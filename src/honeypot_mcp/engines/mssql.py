"""MSSQL honeypot engine — TDS pre-login + Login7 credential capture.

Microsoft SQL Server (tcp/1433) is a heavy brute-force and ransomware target
(the `xp_cmdshell` path to RCE is well-trodden). The high-value signal is the
login: the client's TDS Login7 packet carries the username and a trivially
obfuscated password in the clear once we decline encryption.

Flow (TDS, MS-TDS):
  1. Client sends a PRELOGIN (0x12) packet negotiating version/encryption.
  2. We reply with ENCRYPT_NOT_SUP so the client sends Login7 without TLS —
     exactly what lets us read the password.
  3. Client sends LOGIN7 (0x10). We parse the variable-length data table to
     extract hostname, username, password (de-obfuscated), app name, server
     name, and database.
  4. We return an ERROR token (18456 "Login failed for user") + DONE and close.

The captured (user, password) is fed through `credential_match` via the event
buffer with `service="mssql"`, so a planted CREDENTIAL honeytoken tried against
MSSQL escalates to CRITICAL like the other services.

We do NOT implement the query/RPC phase — auth always fails, so no session is
established. Credential trap, not a real database.

Wire reference:
* MS-TDS §2.2.6.5 (PRELOGIN), §2.2.6.4 (LOGIN7), §2.2.7.10 (ERROR token)
  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
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

# TDS packet types.
_TDS_PRELOGIN = 0x12
_TDS_LOGIN7 = 0x10
_TDS_RESPONSE = 0x04

# PRELOGIN option tokens.
_PL_VERSION = 0x00
_PL_ENCRYPTION = 0x01
_PL_TERMINATOR = 0xFF
_ENCRYPT_NOT_SUP = 0x02


def _tds_packet(pkt_type: int, payload: bytes) -> bytes:
    """Wrap a payload in an 8-byte TDS header (single, EOM packet)."""
    length = 8 + len(payload)
    # type, status(EOM=1), length(BE), SPID(0), PacketID(1), Window(0)
    return struct.pack(">BBHHBB", pkt_type, 0x01, length, 0, 1, 0) + payload


def _build_prelogin_response() -> bytes:
    """PRELOGIN response advertising a version and ENCRYPT_NOT_SUP, so the
    client proceeds to send Login7 in the clear."""
    version_data = struct.pack(">BBHH", 15, 0, 2000, 0)  # SQL Server 2019-ish
    enc_data = bytes([_ENCRYPT_NOT_SUP])
    # Option headers: token(1) + offset(2 BE) + length(2 BE), then terminator.
    headers_len = 5 + 5 + 1  # VERSION + ENCRYPTION + TERMINATOR
    version_off = headers_len
    enc_off = version_off + len(version_data)
    headers = (
        struct.pack(">BHH", _PL_VERSION, version_off, len(version_data))
        + struct.pack(">BHH", _PL_ENCRYPTION, enc_off, len(enc_data))
        + bytes([_PL_TERMINATOR])
    )
    return _tds_packet(_TDS_RESPONSE, headers + version_data + enc_data)


def _decode_tds_password(raw: bytes) -> str:
    """De-obfuscate a TDS Login7 password: XOR each byte with 0xA5, then swap
    the high and low nibbles; the result is UTF-16LE."""
    out = bytearray()
    for b in raw:
        x = b ^ 0xA5
        out.append(((x & 0x0F) << 4) | ((x & 0xF0) >> 4))
    return bytes(out).decode("utf-16-le", errors="replace")


def _parse_login7(body: bytes) -> dict[str, str]:
    """Parse a LOGIN7 record (the bytes after the TDS header). Returns the
    string fields we capture. Robust to malformed input — never raises.

    The fixed header is 36 bytes; the variable-data offset table follows, with
    each entry a 2-byte offset + 2-byte length-in-characters, offsets relative
    to the start of this record.
    """
    out: dict[str, str] = {}
    if len(body) < 36 + 4 * 9:
        return out

    def _field(table_index: int, deobfuscate: bool = False) -> str:
        pos = 36 + table_index * 4
        ib, cch = struct.unpack_from("<HH", body, pos)
        nbytes = cch * 2
        if ib == 0 or nbytes == 0 or ib + nbytes > len(body):
            return ""
        chunk = body[ib : ib + nbytes]
        if deobfuscate:
            return _decode_tds_password(chunk)
        return chunk.decode("utf-16-le", errors="replace")

    # Table order: HostName, UserName, Password, AppName, ServerName, ...
    out["hostname"] = _field(0)
    out["username"] = _field(1)
    out["password"] = _field(2, deobfuscate=True)
    out["app_name"] = _field(3)
    out["server_name"] = _field(4)
    # index 5 = extension, 6 = CltIntName, 7 = Language, 8 = Database
    out["database"] = _field(8)
    return out


def _build_login_error() -> bytes:
    """ERROR token (18456 Login failed) + DONE token, wrapped as a TDS response."""
    msg = "Login failed for user.".encode("utf-16-le")
    err_body = (
        struct.pack("<I", 18456)  # error number
        + bytes([1])  # state
        + bytes([14])  # class (severity)
        + struct.pack("<H", len(msg) // 2)  # message length in chars
        + msg
        + bytes([0])  # server name length (chars)
        + bytes([0])  # proc name length (chars)
        + struct.pack("<I", 1)  # line number
    )
    error_token = bytes([0xAA]) + struct.pack("<H", len(err_body)) + err_body
    # DONE token: status(2, error=0x0002) + curcmd(2) + rowcount(8).
    done_token = bytes([0xFD]) + struct.pack("<HHQ", 0x0002, 0, 0)
    return _tds_packet(_TDS_RESPONSE, error_token + done_token)


class _MSSQLProtocol(asyncio.Protocol):
    def __init__(self, honeypot_id: int | None) -> None:
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("mssql_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        # Drain complete TDS packets (8-byte header, length is bytes 2-3 BE).
        while len(self._buf) >= 8:
            length = struct.unpack_from(">H", self._buf, 2)[0]
            if length < 8 or length > 65535:
                self._close()
                return
            if len(self._buf) < length:
                return
            pkt_type = self._buf[0]
            body = self._buf[8:length]
            self._buf = self._buf[length:]
            self._handle_packet(pkt_type, body)

    def _handle_packet(self, pkt_type: int, body: bytes) -> None:
        t = self._transport
        if t is None:
            return
        if pkt_type == _TDS_PRELOGIN:
            t.write(_build_prelogin_response())
            return
        if pkt_type == _TDS_LOGIN7:
            fields = _parse_login7(body)
            asyncio.create_task(self._record_login(fields))
            with contextlib.suppress(Exception):
                t.write(_build_login_error())
            self._close()
            return
        # Anything else pre-auth — reject.
        self._close()

    def _close(self) -> None:
        if self._transport is not None:
            with contextlib.suppress(Exception):
                self._transport.close()

    async def _record_login(self, fields: dict[str, str]) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type="mssql_login_attempt",
                payload={
                    "username": fields.get("username", ""),
                    "password": fields.get("password", ""),
                    "database": fields.get("database", ""),
                    "hostname": fields.get("hostname", ""),
                    "app_name": fields.get("app_name", ""),
                    "service": "mssql",
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


class MSSQLEngine(HoneypotEngine):
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
            limited_factory(lambda: _MSSQLProtocol(hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"mssql-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("MSSQL honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_mssql"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["MSSQL honeypot is in-process — events are stored directly in the database."]
