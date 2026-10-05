"""One process owns a deployment's sensors; any other is read-only.

The honeypots run *inside* this process, and MCP clients launch one server process per
chat. Two agent sessions open at once therefore meant two servers sharing one database
and one set of ports, and the second one's startup "re-established" the first one's
honeypots, failed to bind their ports, and wrote a CRITICAL `honeypot_restart_failed`
alert — a false alarm that pages whoever is subscribed, every time someone opened a
second chat.

The first process now takes an exclusive OS lock keyed to the database. A process that
cannot get it starts read-only: it can query alerts, run analysis, triage and manage
tokens, but it does not touch ports, reconcile sensors or run the delivery and canary
servers, and the tools that would change sensors say who owns them. The OS releases
the lock when the owner dies for any reason, so there is no stale lock to clean up.

What the lock covers: processes on one host sharing a database. Two hosts sharing a
PostgreSQL database are not detected.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from sqlalchemy.engine import make_url

log = logging.getLogger(__name__)

try:  # POSIX
    import fcntl

    def _try_lock(fh: IO[str]) -> bool:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        return True

    def _unlock(fh: IO[str]) -> None:
        with contextlib.suppress(OSError):
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)

except ImportError:  # Windows
    import msvcrt

    def _try_lock(fh: IO[str]) -> bool:
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        except OSError:
            return False
        return True

    def _unlock(fh: IO[str]) -> None:
        with contextlib.suppress(OSError):
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class Holder:
    """Who owns the sensors, as recorded by the owner when it took the lock."""

    pid: int | None = None
    started_at: str | None = None
    transport: str | None = None

    def describe(self) -> str:
        bits = []
        if self.pid:
            bits.append(f"pid {self.pid}")
        if self.transport:
            bits.append(f"{self.transport} transport")
        if self.started_at:
            bits.append(f"started {self.started_at}")
        return ", ".join(bits) or "another process"


class InstanceLock:
    def __init__(self, path: Path, handle: IO[str]) -> None:
        self.path = path
        self._handle: IO[str] | None = handle

    def release(self) -> None:
        if self._handle is not None:
            _unlock(self._handle)
            with contextlib.suppress(OSError):
                self._handle.close()
            self._handle = None


def lock_path_for(database_url: str) -> Path | None:
    """Where the lock for this database lives, or None when it cannot be shared
    (an in-memory database belongs to one process by construction)."""
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        database = url.database
        # Same test database.py uses: `file::memory:?cache=shared` and friends count too.
        if not database or ":memory:" in database_url or "mode=memory" in database_url:
            return None
        path = Path(database).resolve()
        # Beside the database, so two containers sharing the volume see the same lock.
        return path.with_name(path.name + ".owner")
    digest = hashlib.sha256(url.render_as_string(hide_password=True).encode()).hexdigest()[:16]
    # A per-user 0700 directory, never the shared temp dir: a predictable name in a
    # world-writable directory lets another local user hold the lock (forcing every
    # server read-only) or point it at a file the lock then overwrites.
    return Path.home() / ".honeypot-mcp" / f"lock-{digest}.owner"


def read_holder(path: Path) -> Holder:
    try:
        data: dict[str, Any] = json.loads(path.read_text() or "{}")
    except (OSError, ValueError):
        return Holder()
    pid = data.get("pid")
    return Holder(
        pid=pid if isinstance(pid, int) else None,
        started_at=data.get("started_at") if isinstance(data.get("started_at"), str) else None,
        transport=data.get("transport") if isinstance(data.get("transport"), str) else None,
    )


def try_acquire(database_url: str, transport: str) -> tuple[InstanceLock | None, Holder | None]:
    """Try to become the sensor owner.

    Returns ``(lock, None)`` when this process owns the sensors (also for databases
    that cannot be shared), or ``(None, holder)`` when another process already does.
    """
    path = lock_path_for(database_url)
    if path is None:
        return InstanceLock(Path(os.devnull), open(os.devnull, "w")), None  # noqa: SIM115
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # O_NOFOLLOW: never write through a planted symlink. 0600: owner-only.
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        handle = os.fdopen(fd, "r+")  # held for the process lifetime
    except OSError as e:
        # A lock we cannot create is not a reason to refuse to run: say so, own the sensors.
        log.warning("Could not create the instance lock %s (%s); continuing without it.", path, e)
        return InstanceLock(Path(os.devnull), open(os.devnull, "w")), None  # noqa: SIM115
    if not _try_lock(handle):
        handle.close()
        return None, read_holder(path)
    handle.seek(0)
    handle.truncate()
    handle.write(
        json.dumps(
            {
                "pid": os.getpid(),
                "transport": transport,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }
        )
    )
    handle.flush()
    return InstanceLock(path, handle), None


# ── Process-wide state, read by the tools that would change sensors ─────────

_state: dict[str, Any] = {"owned": True, "holder": None}


def set_ownership(owned: bool, holder: Holder | None = None) -> None:
    _state["owned"] = owned
    _state["holder"] = holder


def sensors_owned() -> bool:
    return bool(_state["owned"])


def read_only_error() -> dict[str, Any] | None:
    """The error a sensor-changing tool returns in a read-only process, else None."""
    if _state["owned"]:
        return None
    holder: Holder = _state["holder"] or Holder()
    return {
        "error": (
            "This HoneyPot MCP session is read-only: another process "
            f"({holder.describe()}) owns the sensors for this database, and starting, "
            "stopping or reconfiguring them from a second process would fight it for the "
            "same ports. Alerts, analysis, triage and tokens work normally here."
        ),
        "hint": (
            "Run the server once as a daemon (MCP_TRANSPORT=streamable-http) and point "
            "every agent at it, or close the other session. A read-only session does not "
            "take over if the owner exits; restart it to become the owner."
        ),
        "sensor_owner": {"pid": holder.pid, "transport": holder.transport},
    }
