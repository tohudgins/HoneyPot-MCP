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

Where the lock lives depends on the database:

* SQLite — an ``flock`` file beside the database file (processes on one host or sharing
  a volume).
* PostgreSQL — a session-level *advisory lock* on a dedicated connection, so two servers
  on different hosts pointed at one database are detected too. The server releases it
  when the connection closes, which happens when the owner dies.

A read-only process keeps trying (``owner_check_seconds``) and promotes itself when the
owner goes away: it re-establishes the sensors the old owner left RUNNING, exactly as a
restart would.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

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
    host: str | None = None

    def describe(self) -> str:
        bits = []
        if self.host:
            bits.append(f"host {self.host}")
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

    async def aclose(self) -> None:
        self.release()

    async def alive(self) -> bool:
        """An OS file lock is held by the open descriptor; it cannot be lost silently."""
        return self._handle is not None


# Arbitrary, fixed: advisory locks are per-database, so every HoneyPot MCP server
# pointed at one database contends for the same key.
_PG_LOCK_KEY = 0x484F4E4559504F54  # "HONEYPOT"
_PG_APP_PREFIX = "honeypot-mcp-owner"


class LockError(Exception):
    """The ownership lock could not be consulted (database unreachable, no permission to
    create the file). Distinct from "someone else holds it": a running owner that cannot
    ask the question must not conclude it lost ownership, and a read-only process must not
    conclude the owner is gone."""


# Seconds any single question to the database about the lock may take. A half-open TCP
# connection otherwise blocks for minutes, and with it the loop that checks ownership.
_PG_TIMEOUT = 5.0


class PgAdvisoryLock:
    """Ownership as a PostgreSQL session-level advisory lock on a dedicated connection.

    The lock lives exactly as long as that connection: a crashed owner's connection is
    closed by the server, releasing the lock with no stale state to clean up. Unlike the
    file lock it works between hosts, which is the case the file lock cannot see."""

    def __init__(self, engine: AsyncEngine, connection: AsyncConnection) -> None:
        self._engine: AsyncEngine | None = engine
        self._connection: AsyncConnection | None = connection
        self.path = Path("postgresql-advisory-lock")

    async def alive(self) -> bool:
        """Still connected AND still the holder. A network blip that dropped the
        connection silently released the lock; another process may own the sensors now."""
        if self._connection is None:
            return False
        connection = self._connection
        try:
            held = (
                await asyncio.wait_for(
                    connection.execute(
                        text(
                            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                            "AND granted AND pid = pg_backend_pid()"
                        )
                    ),
                    _PG_TIMEOUT,
                )
            ).scalar_one()
        except Exception:
            return False
        return bool(held)

    async def aclose(self) -> None:
        connection, engine = self._connection, self._engine
        self._connection = self._engine = None
        # Bounded: on a dead connection these would otherwise wait for TCP to give up.
        if connection is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(
                    connection.execute(text("SELECT pg_advisory_unlock_all()")), _PG_TIMEOUT
                )
            with contextlib.suppress(Exception):
                await asyncio.wait_for(connection.close(), _PG_TIMEOUT)
        if engine is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(engine.dispose(), _PG_TIMEOUT)

    def release(self) -> None:  # pragma: no cover - sync callers use the file lock
        raise RuntimeError("PgAdvisoryLock must be released with `await aclose()`")


async def _pg_holder(connection: AsyncConnection) -> Holder:
    row = (
        await connection.execute(
            text(
                "SELECT application_name, host(client_addr) FROM pg_stat_activity "
                "WHERE application_name LIKE :prefix AND pid <> pg_backend_pid() LIMIT 1"
            ),
            {"prefix": f"{_PG_APP_PREFIX}:%"},
        )
    ).first()
    if row is None:
        return Holder()
    _, pid, transport = (row[0].split(":") + [None, None])[:3]
    return Holder(
        pid=int(pid) if pid and pid.isdigit() else None,
        transport=transport,
        host=row[1],
    )


async def _acquire_pg(
    database_url: str, transport: str, fail_open: bool
) -> tuple[InstanceLock | PgAdvisoryLock | None, Holder | None]:
    connect_args: dict[str, Any] = {}
    if "asyncpg" in database_url.split("://", 1)[0]:
        connect_args["command_timeout"] = _PG_TIMEOUT * 2
    engine = create_async_engine(database_url, poolclass=NullPool, connect_args=connect_args)
    connection: AsyncConnection | None = None
    try:
        # AUTOCOMMIT: otherwise the connection sits "idle in transaction" for as long as the
        # lock is held, where `idle_in_transaction_session_timeout` kills it (and the lock),
        # and one failed statement poisons the transaction.
        connection = await asyncio.wait_for(engine.connect(), _PG_TIMEOUT)
        connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
        await asyncio.wait_for(
            connection.execute(
                text("SELECT set_config('application_name', :n, false)"),
                {"n": f"{_PG_APP_PREFIX}:{os.getpid()}:{transport}"[:63]},
            ),
            _PG_TIMEOUT,
        )
        got = (
            await asyncio.wait_for(
                connection.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": _PG_LOCK_KEY}),
                _PG_TIMEOUT,
            )
        ).scalar_one()
        if got:
            return PgAdvisoryLock(engine, connection), None
        holder = await asyncio.wait_for(_pg_holder(connection), _PG_TIMEOUT)
    except Exception as e:
        if connection is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(connection.close(), _PG_TIMEOUT)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(engine.dispose(), _PG_TIMEOUT)
        if not fail_open:
            raise LockError(f"PostgreSQL ownership lock unavailable: {e}") from e
        # At first start, not being able to take a lock must not stop the server serving.
        log.warning("Could not take the PostgreSQL ownership lock (%s); continuing without it.", e)
        return InstanceLock(Path(os.devnull), open(os.devnull, "w")), None  # noqa: SIM115
    with contextlib.suppress(Exception):
        await asyncio.wait_for(connection.close(), _PG_TIMEOUT)
    with contextlib.suppress(Exception):
        await asyncio.wait_for(engine.dispose(), _PG_TIMEOUT)
    return None, holder


async def acquire(
    database_url: str, transport: str, *, fail_open: bool = True
) -> tuple[InstanceLock | PgAdvisoryLock | None, Holder | None]:
    """Try to become the sensor owner, using the lock that fits the database.

    `fail_open` is for process start: if the lock cannot be consulted the server runs as
    owner anyway (a missing lock file is not a reason to refuse to serve). Later checks pass
    `fail_open=False`, and an error then raises `LockError` instead of being read as an
    answer in either direction."""
    if make_url(database_url).get_backend_name() == "postgresql":
        return await _acquire_pg(database_url, transport, fail_open)
    return try_acquire(database_url, transport, fail_open=fail_open)


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
    # Other backends (PostgreSQL has its own advisory lock, see `acquire`) are not shared
    # through a local file: a path in a world-writable directory could be held by another
    # user or pointed at a file the lock then overwrites.
    return None


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
        host=data.get("host") if isinstance(data.get("host"), str) else None,
    )


def try_acquire(
    database_url: str, transport: str, *, fail_open: bool = True
) -> tuple[InstanceLock | None, Holder | None]:
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
        if not fail_open:
            raise LockError(f"cannot open the lock file {path}: {e}") from e
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
                "host": socket.gethostname(),
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
            "every agent at it, or close the other session. This session promotes itself "
            "if the owner exits."
        ),
        "sensor_owner": {
            "pid": holder.pid,
            "transport": holder.transport,
            "host": holder.host,
        },
    }
