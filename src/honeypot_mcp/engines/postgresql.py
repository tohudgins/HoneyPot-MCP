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

We then ACCEPT the login and open the simple-query phase (AuthenticationOk +
ParameterStatus + ReadyForQuery). A fake datastore with no real data loses
nothing by granting access, and the post-auth SQL is where intent shows:
`COPY … FROM/TO PROGRAM '<cmd>'` (direct superuser RCE), `CREATE FUNCTION …
LANGUAGE C` UDF loads, `pg_read_file`/`lo_export` file access, and credential-
table dumps (`pg_shadow`, `pg_authid`) — flagged HIGH/CRITICAL by
`_classify_pg_query`. `version()`/`current_user` get believable result sets so
a tool that reads results runs its whole playbook. No real table data is ever
stored or returned.

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

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory
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
    """Build an ErrorResponse in modern PostgreSQL's field order.

    'E' + Int32 len + [field-type byte + string\\0]... + \\0. Real servers since
    9.6 send both S (localised severity) and V (non-localised) before the
    SQLSTATE and message; the pair is what identifies a genuine PostgreSQL
    error frame to a scanner.
    """
    fields = (
        b"S"
        + severity.encode()
        + b"\x00"
        + b"V"
        + severity.encode()
        + b"\x00"
        + b"C"
        + code.encode()
        + b"\x00"
        + b"M"
        + message.encode()
        + b"\x00"
        + b"\x00"
    )
    return b"E" + struct.pack("!I", len(fields) + 4) + fields


def _msg(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack("!I", len(payload) + 4) + payload


def _auth_ok() -> bytes:
    return b"R" + struct.pack("!II", 8, 0)  # AuthenticationOk


def _ready_for_query() -> bytes:
    return b"Z" + struct.pack("!I", 5) + b"I"  # status 'I' = idle


def _post_auth_preamble() -> bytes:
    """What a real server sends after AuthenticationOk: a few ParameterStatus
    messages, BackendKeyData, then ReadyForQuery. Enough for psql/libpq and
    exploit tools to consider themselves connected and start issuing queries."""
    params = {
        "server_version": "14.10 (Debian 14.10-1.pgdg120+1)",
        "server_encoding": "UTF8",
        "client_encoding": "UTF8",
        "DateStyle": "ISO, MDY",
        "integer_datetimes": "on",
        "standard_conforming_strings": "on",
    }
    out = _auth_ok()
    for k, v in params.items():
        out += _msg(b"S", k.encode() + b"\x00" + v.encode() + b"\x00")
    out += _msg(b"K", struct.pack("!II", 12345, 67890))  # BackendKeyData
    out += _ready_for_query()
    return out


def _single_value_result(col: str, value: str) -> bytes:
    """RowDescription + one DataRow + CommandComplete for a 1-col/1-row SELECT
    (e.g. version()), so a tool that reads results stays engaged."""
    # RowDescription 'T': field count(2) + [name\0 + tableOID(4) + colAttr(2) +
    # typeOID(4) + typeLen(2) + typeMod(4) + format(2)]
    # tableOID(I) colAttr(H) typeOID(I) typeSize(h, signed) typeMod(i, signed) format(H)
    col_desc = (
        col.encode() + b"\x00" + struct.pack("!IHIhiH", 0, 0, 25, -1, -1, 0)  # typeOID 25 = text
    )
    t_msg = _msg(b"T", struct.pack("!H", 1) + col_desc)
    vb = value.encode()
    d_msg = _msg(b"D", struct.pack("!HI", 1, len(vb)) + vb)  # 1 col, len-prefixed
    c_msg = _msg(b"C", b"SELECT 1\x00")
    return t_msg + d_msg + c_msg + _ready_for_query()


def _classify_pg_query(sql: str) -> tuple[str, AlertSeverity]:
    """Map a captured SQL string to (event_type, severity). Recognises the
    file/command patterns that turn a Postgres login into RCE or file access."""
    s = sql.lower()
    if "from program" in s or "to program" in s:
        # COPY ... FROM/TO PROGRAM '<cmd>' — direct superuser command execution.
        return "postgresql_copy_program_rce", AlertSeverity.CRITICAL
    if "create function" in s and ("language c" in s or "as '" in s):
        return "postgresql_udf_rce", AlertSeverity.CRITICAL
    if "lo_import" in s or "lo_export" in s or "pg_read_file" in s or "pg_ls_dir" in s:
        return "postgresql_file_access", AlertSeverity.HIGH
    if s.strip().startswith("copy "):
        return "postgresql_copy", AlertSeverity.HIGH
    if any(
        tok in s
        for tok in (
            "pg_stat",
            "version()",
            "current_user",
            "pg_shadow",
            "pg_authid",
            "information_schema",
            "pg_database",
            "current_setting",
            "pg_ls",
        )
    ):
        return "postgresql_recon_query", AlertSeverity.MEDIUM
    return "postgresql_query", AlertSeverity.MEDIUM


class _PGProtocol(asyncio.Protocol):
    def __init__(self, honeypot_id: int | None) -> None:
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._startup_done = False
        self._authed = False
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
                    # Real PostgreSQL answers a malformed startup packet with a
                    # FATAL ErrorResponse rather than hanging up silently, and
                    # that reply is precisely how scanners identify the service
                    # — an HTTP probe's "GET " reads as a 1.2-billion-byte
                    # length and lands here. Closing mutely left the port
                    # unidentifiable, which is itself conspicuous.
                    if self._transport is not None:
                        self._transport.write(
                            _error_response("FATAL", "08P01", "invalid length of startup packet")
                        )
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
        # Unknown startup code — real PostgreSQL names the version it got and
        # the range it supports before closing.
        major, minor = code >> 16, code & 0xFFFF
        t.write(
            _error_response(
                "FATAL",
                "0A000",
                f"unsupported frontend protocol {major}.{minor}: server supports 3.0 to 3.0",
            )
        )
        self._close()

    def _handle_message(self, msg_type: bytes, payload: bytes) -> None:
        t = self._transport
        if t is None:
            return
        if msg_type == b"p" and not self._authed:
            # PasswordMessage: password is a null-terminated string.
            password = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            user = self._params.get("user", "")
            asyncio.create_task(self._record_login(user, password))
            # Accept the login and open the query phase — a fake datastore with
            # no real data loses nothing by granting access, and the post-auth
            # SQL is where the objective shows (COPY ... FROM PROGRAM RCE,
            # pg_read_file, credential-table dumps).
            self._authed = True
            t.write(_post_auth_preamble())
            return
        if self._authed and msg_type == b"Q":
            sql = payload.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            event_type, severity = _classify_pg_query(sql)
            asyncio.create_task(
                self._record(event_type, severity, {"query": sql[:4096], "service": "postgresql"})
            )
            self._respond_to_query(sql)
            return
        if msg_type == b"X":  # Terminate
            self._close()
            return
        if self._authed:
            # Unmodelled post-auth message (Parse/Bind/etc.) — stay ready.
            t.write(_ready_for_query())
            return
        self._close()

    def _respond_to_query(self, sql: str) -> None:
        t = self._transport
        if t is None:
            return
        s = sql.lower()
        if "version()" in s:
            t.write(_single_value_result("version", "PostgreSQL 14.10 on x86_64-pc-linux-gnu"))
        elif "current_user" in s or s.strip().rstrip(";") == "user":
            t.write(_single_value_result("current_user", "postgres"))
        elif s.strip().startswith("select"):
            t.write(_single_value_result("?column?", ""))
        else:
            # DDL/DML/COPY/SET — CommandComplete + ready.
            t.write(_msg(b"C", b"OK\x00") + _ready_for_query())

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
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _PGProtocol(hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
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
