"""rsync daemon honeypot — tcp/873, exposed module enumeration.

An rsync daemon left open to the internet is a recurring breach cause: the
protocol has no authentication by default, and a single anonymous command lists
every share on the box and then copies it. Backup servers are the usual victim,
which means the exposure is not a foothold but the archive itself.

The reconnaissance step is also the exploitation step, and that shapes what is
worth recording:

* Sending an empty module name returns the **module list** — the equivalent of
  `rsync rsync://host/`. Doing that is the entire discovery phase, so it is
  logged as enumeration with the modules the attacker learned about.
* Selecting a module that a real daemon exposes without `auth users` gets
  straight to a file transfer. That is data leaving, and it is recorded as
  such rather than as another connection.
* A module configured with `auth users` challenges, and the response is a
  base64 MD5 of the password against a server-chosen salt — capturable, and
  crackable offline, exactly like the SIP digest.

The advertised modules are named to be worth taking: backups, database dumps,
configuration. A daemon exposing nothing interesting is not one an attacker
spends time on.

Wire format: the rsync daemon protocol — a `@RSYNCD:` version handshake, then
newline-delimited text until a module is selected.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import secrets
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# Protocol 31 is what rsync 3.1–3.2 speak; the client refuses versions it does
# not recognise, so this has to be a real one.
_RSYNC_VERSION = "31.0"

# Modules an attacker would want, with the mix a real backup host has: some
# open, one protected. `MOTD` is what a daemon prints before the list.
_MOTD = "backup01 rsync service - authorised use only"
_MODULES: tuple[tuple[str, str, bool], ...] = (
    # (name, comment, requires_auth)
    ("backups", "Nightly system backups", False),
    ("db-dumps", "PostgreSQL nightly dumps", False),
    ("etc", "Configuration archive", True),
    ("home", "User home directories", True),
    ("public", "Public read-only mirror", False),
)
_AUTH_MODULES = {name for name, _c, needs_auth in _MODULES if needs_auth}
_OPEN_MODULES = {name for name, _c, needs_auth in _MODULES if not needs_auth}

_MAX_LINE = 4096

_STATE_HANDSHAKE = 0
_STATE_MODULE = 1
_STATE_AUTH = 2
_STATE_TRANSFER = 3


class _RsyncProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._state = _STATE_HANDSHAKE
        self._module = ""
        self._challenge = ""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._send(f"@RSYNCD: {_RSYNC_VERSION}\n")
        asyncio.create_task(self._record("rsync_connection", AlertSeverity.LOW, {}))

    def _send(self, text: str) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(text.encode("utf-8", errors="replace"))

    def _close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_LINE * 8:
            self._buf = b""
            self._send("@ERROR: protocol error\n")
            self._close()
            return
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            asyncio.create_task(self._handle(raw.decode("utf-8", errors="replace").strip()))

    async def _handle(self, line: str) -> None:
        if self._state == _STATE_HANDSHAKE:
            # Client echoes `@RSYNCD: <version>`; anything else is a scanner
            # poking the port rather than speaking rsync.
            if not line.startswith("@RSYNCD:"):
                await self._record("rsync_invalid_probe", AlertSeverity.LOW, {"data": line[:120]})
                self._send("@ERROR: protocol version mismatch\n")
                self._close()
                return
            self._state = _STATE_MODULE
            return

        if self._state == _STATE_MODULE:
            if line == "" or line == "#list":
                # The discovery step. This single exchange is what tells an
                # attacker the box is worth returning to.
                listing = f"{_MOTD}\n" + "".join(
                    f"{name}\t{comment}\n" for name, comment, _a in _MODULES
                )
                self._send(listing + "@RSYNCD: EXIT\n")
                await self._record(
                    "rsync_module_enumeration",
                    AlertSeverity.HIGH,
                    {
                        "modules_disclosed": [n for n, _c, _a in _MODULES],
                        "note": "listed every share — the whole discovery phase in one command",
                    },
                )
                self._close()
                return

            self._module = line.split(" ", 1)[0]
            if self._module in _AUTH_MODULES:
                self._challenge = base64.b64encode(secrets.token_bytes(16)).decode().rstrip("=")
                self._send(f"@RSYNCD: AUTHREQD {self._challenge}\n")
                self._state = _STATE_AUTH
                await self._record(
                    "rsync_module_access",
                    AlertSeverity.HIGH,
                    {"module": self._module[:64], "auth_required": True},
                )
                return

            if self._module in _OPEN_MODULES:
                # No auth on this module, so the next thing the client does is
                # copy files. That is the breach, not a probe.
                self._send("@RSYNCD: OK\n")
                self._state = _STATE_TRANSFER
                await self._record(
                    "rsync_anonymous_access",
                    AlertSeverity.CRITICAL,
                    {
                        "module": self._module[:64],
                        "note": (
                            "unauthenticated access to an exposed rsync module — "
                            "the next step is bulk file copy"
                        ),
                    },
                )
                return

            self._send(f"@ERROR: Unknown module '{self._module}'\n")
            await self._record(
                "rsync_unknown_module", AlertSeverity.MEDIUM, {"module": self._module[:64]}
            )
            self._close()
            return

        if self._state == _STATE_AUTH:
            # `<user> <base64 md5 response>` — the response is a digest over
            # our salt, so it is crackable with the salt we just recorded.
            parts = line.split(" ", 1)
            username = parts[0] if parts else ""
            response = parts[1] if len(parts) > 1 else ""
            await self._record(
                "rsync_auth_attempt",
                AlertSeverity.HIGH,
                {
                    "module": self._module[:64],
                    "username": username[:128],
                    "challenge": self._challenge,
                    "digest_response": response[:128],
                    "service": "rsync",
                },
            )
            await asyncio.sleep(0.8)
            self._send("@ERROR: auth failed on module " + self._module + "\n")
            self._close()
            return

        # Post-OK: the client sends its option list, then the file request.
        if line.startswith("-") or line == ".":
            await self._record(
                "rsync_transfer_options", AlertSeverity.MEDIUM, {"options": line[:200]}
            )
            return
        await self._record(
            "rsync_file_request",
            AlertSeverity.CRITICAL,
            {"module": self._module[:64], "path": line[:200], "note": "attempted bulk file read"},
        )

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        self._buf = b""


class RsyncEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _RsyncProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"rsync-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("rsync honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_rsync"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["rsync honeypot is in-process — events are stored directly in the database."]


def _md5_response(password: str, challenge: str) -> str:
    """Reference implementation of rsync's auth digest, for tests.

    rsync hashes a zero-filled 4-byte prefix, the password, then the challenge,
    and base64-encodes the digest with padding stripped.
    """
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(b"\x00\x00\x00\x00")
    digest.update(password.encode())
    digest.update(challenge.encode())
    return base64.b64encode(digest.digest()).decode().rstrip("=")
