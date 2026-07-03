"""PostgreSQL honeypot engine — captures startup params + login credentials.

Exposed PostgreSQL (5432) is a routine credential-brute-force target. The
high-value signal is the login attempt: the client's StartupMessage leaks the
username and target database in the clear, and by requesting cleartext
authentication we capture the password too.

Flow (PostgreSQL frontend/backend protocol, v3.0):
  1. Client may first send an SSLRequest — we reply 'N' (no SSL) so it proceeds
     in cleartext, which is exactly what lets us capture the password.
  2. Client sends StartupMessage with user/database key-value pairs.
  3. We reply AuthenticationCleartextPassword.
  4. Client sends the PasswordMessage — we capture it and reply with a
     believable `28P01 invalid_password` ErrorResponse.

The captured (user, database, password) tuple is fed through
`credential_match` via the event buffer, so a planted CREDENTIAL honeytoken
tried against Postgres escalates to CRITICAL just like SSH/FTP/Redis.

We do NOT implement the query protocol — auth always fails, so no session is
ever established. That keeps this a credential trap, not a real database.

Wire reference: PostgreSQL protocol v3
https://www.postgresql.org/docs/current/protocol-message-formats.html
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import struct
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_SSL_REQUEST_CODE = 80877103
_PROTOCOL_V3 = 196608
_GSSENC_REQUEST_CODE = 80877104


def _parse_startup_params(body: bytes) -> dict[str, str]:
    """StartupMessage payload after the Int32 protocol version: a run of
    null-terminated key\\0value\\0 pairs, terminated by an empty key."""
    params: dict[str, str] = {}
    parts = body.split(b"\x00")
    # Drop trailing empties from the terminator.
    tokens = [p.decode("utf-8", errors="replace") for p in parts if p != b""]
    for i in range(0, len(tokens) - 1, 2):
        params[tokens[i]] = tokens[i + 1]
    return params


def _auth_cleartext_request() -> bytes:
    # 'R' + Int32 length(8) + Int32 3 (AuthenticationCleartextPassword)
    return b"R" + struct.pack("!II", 8, 3)


def _error_response(severity: str, code: str, message: str) -> bytes:
    # 'E' + Int32 len + [field-type byte + string\0]... + \0
    fields = (
        b"S" + severity.encode() + b"\x00"
        + b"C" + code.encode() + b"\x00"
        + b"M" + message.encode() + b"\x00"
        + b"\x00"
    )
    return b"E" + struct.pack("!I", len(fields) + 4) + fields


class _PGProtocol(asyncio.Protocol):
    def __init__(self, honeypot_id: int | None) -> None:
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._startup_done = False
        self._params: dict[str, str] = {}

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("postgresql_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        # First, handle the un-typed startup/SSL packets (Int32 length prefix,
        # no type byte). After startup, messages are type-tagged.
        while True:
            if not self._startup_done:
                if len(self._buf) < 4:
                    return
                length = struct.unpack("!I", self._buf[:4])[0]
                if length < 8 or length > 65535:
                    self._close()
                    return
                if len(self._buf) < length:
                    return
                payload = self._buf[4:length]
                self._buf = self._buf[length:]
                self._handle_startup_packet(payload)
            else:
                # Typed message: 1 byte type + Int32 length.
                if len(self._buf) < 5:
                    return
                msg_type = self._buf[0:1]
                length = struct.unpack("!I", self._buf[1:5])[0]
                if len(self._buf) < 1 + length:
                    return
                payload = self._buf[5 : 1 + length]
                self._buf = self._buf[1 + length :]
                self._handle_message(msg_type, payload)

    def _handle_startup_packet(self, payload: bytes) -> None:
        t = self._transport
        if t is None or len(payload) < 4:
            self._close()
            return
        code = struct.unpack("!I", payload[:4])[0]
        if code in (_SSL_REQUEST_CODE, _GSSENC_REQUEST_CODE):
            # Decline encryption so the client falls back to cleartext.
            t.write(b"N")
            return
        if code == _PROTOCOL_V3:
            self._params = _parse_startup_params(payload[4:])
            self._startup_done = True
            asyncio.create_task(
                self._record(
                    "postgresql_startup",
                    AlertSeverity.MEDIUM,
                    {
                        "user": self._params.get("user", ""),
                        "database": self._params.get("database", ""),
                        "params": self._params,
                    },
                )
            )
            t.write(_auth_cleartext_request())
            return
        # Unknown startup code — reject.
        self._close()

    def _handle_message(self, msg_type: bytes, payload: bytes) -> None:
        t = self._transport
        if t is None:
            return
        if msg_type == b"p":
            # PasswordMessage: password is a null-terminated string.
            password = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            user = self._params.get("user", "")
            asyncio.create_task(self._record_login(user, password))
            t.write(
                _error_response(
                    "FATAL",
                    "28P01",
                    f'password authentication failed for user "{user}"',
                )
            )
            self._close()
            return
        # Any other post-startup message before auth — terminate.
        self._close()

    def _close(self) -> None:
        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()

    async def _record_login(self, user: str, password: str) -> None:
        # service="postgresql" so credential_match can cross-reference planted
        # CREDENTIAL honeytokens.
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type="postgresql_login_attempt",
                payload={
                    "username": user,
                    "password": password,
                    "database": self._params.get("database", ""),
                    "service": "postgresql",
                },
                severity=AlertSeverity.HIGH,
            )
        )

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class PostgreSQLEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _PGProtocol(hp_id), host="0.0.0.0", port=port
        )
        cid = f"postgresql-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("PostgreSQL honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_postgresql"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["PostgreSQL honeypot is in-process — events are stored directly in the database."]
