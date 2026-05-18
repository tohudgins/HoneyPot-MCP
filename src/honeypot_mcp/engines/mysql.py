"""MySQL banner honeypot — handshake exchange + access-denied response.

MySQL on port 3306 is a constant brute-force target on the internet:
default-credential sweepers, exposed-DB scrapers, ransomware actors.
We don't implement the full protocol (no query execution, no SSL upgrade,
no auth_plugin negotiation beyond the default) — but we do the Initial
Handshake + HandshakeResponse41 + Error Packet exchange faithfully enough
that scanners harvest a believable username + password attempt before we
close the connection.

Wire format reference:
* https://dev.mysql.com/doc/internals/en/connection-phase.html
* https://dev.mysql.com/doc/internals/en/protocol-handshake.html

Captured per connection:
* Client's CapabilityFlags (identifies the client library / MySQL version).
* Client's max_packet_size, charset, username, auth_response, database name
  (if `CONNECT_WITH_DB` was negotiated).
* The auth_response itself is the `mysql_native_password` SHA1-of-SHA1
  scramble — equivalent to a hash-cracking target like John or Hashcat.

Login attempts are also fed to `credential_match` with `service="mysql"`,
so planted CREDENTIAL honeytokens fire across MySQL just like the other
services.
"""

from __future__ import annotations

import asyncio
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


# Server version advertised in the Initial Handshake Packet. Tracking
# distinct minor versions matters for some clients' capability negotiation —
# 8.0.36-0ubuntu0.22.04.1 is a current stock Ubuntu install fingerprint.
_SERVER_VERSION = b"8.0.36-0ubuntu0.22.04.1"

# CapabilityFlags bitmask we advertise. A superset of what real MySQL 8.0
# emits with mysql_native_password + caching_sha2_password disabled.
# Bits: CLIENT_LONG_PASSWORD | CLIENT_FOUND_ROWS | CLIENT_LONG_FLAG |
# CLIENT_CONNECT_WITH_DB | CLIENT_NO_SCHEMA | CLIENT_COMPRESS |
# CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION |
# CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS | CLIENT_PS_MULTI_RESULTS |
# CLIENT_PLUGIN_AUTH | CLIENT_CONNECT_ATTRS | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
_CAPABILITY_FLAGS = 0x807FE7FF

# Status flags. SERVER_STATUS_AUTOCOMMIT (0x0002).
_STATUS_FLAGS = 0x0002

# Character set: utf8mb4_general_ci (0xff is wrong; 0x2D is utf8mb4_general_ci).
_CHARSET = 0x2D


def _build_handshake_packet(salt_1: bytes, salt_2: bytes) -> bytes:
    """Build the MySQL 4.1+ Initial Handshake Packet.

    Layout (after the standard MySQL packet header):
        protocol_version (1)         = 10
        server_version (null-term)
        thread_id (4 LE)
        auth_plugin_data_part_1 (8)  — first 8 bytes of the 20-byte scramble
        filler (1)                   = 0
        capability_flags_lower (2)
        charset (1)
        status_flags (2)
        capability_flags_upper (2)
        auth_plugin_data_length (1)  = 21 (20 scramble + null term)
        reserved (10)                = zeros
        auth_plugin_data_part_2 (12) — remaining 12 bytes of the scramble
        auth_plugin_name (null-term) = 'mysql_native_password'
    """
    cap_lower = _CAPABILITY_FLAGS & 0xFFFF
    cap_upper = (_CAPABILITY_FLAGS >> 16) & 0xFFFF
    payload = b"".join(
        [
            bytes([10]),
            _SERVER_VERSION,
            b"\x00",
            struct.pack("<I", 12345),  # thread_id
            salt_1,
            b"\x00",  # filler
            struct.pack("<H", cap_lower),
            bytes([_CHARSET]),
            struct.pack("<H", _STATUS_FLAGS),
            struct.pack("<H", cap_upper),
            bytes([21]),  # auth_plugin_data_length (20+null)
            b"\x00" * 10,  # reserved
            salt_2,
            b"mysql_native_password\x00",
        ]
    )
    # MySQL packet header: 3-byte LE length + 1-byte sequence id (= 0 for first).
    header = struct.pack("<I", len(payload))[:3] + bytes([0])
    return header + payload


def _build_error_packet(seq: int, errno: int, sqlstate: str, message: str) -> bytes:
    """ERR_Packet — MySQL 4.1+ format.

    Layout:
        header (1)              = 0xff
        error_code (2 LE)
        '#' marker (1)
        sql_state (5 ASCII)
        error_message (rest of packet, no terminator)
    """
    payload = (
        bytes([0xFF])
        + struct.pack("<H", errno)
        + b"#"
        + sqlstate.encode("ascii")
        + message.encode("utf-8")
    )
    header = struct.pack("<I", len(payload))[:3] + bytes([seq])
    return header + payload


def _parse_handshake_response(payload: bytes) -> dict[str, Any]:
    """Parse HandshakeResponse41 enough to extract username + auth_response.

    Layout (after the packet header has already been consumed):
        client_flag (4 LE)
        max_packet_size (4 LE)
        charset (1)
        reserved (23 zeros)
        username (null-term string)
        auth_response_length (length-encoded int)
        auth_response (auth_response_length bytes)
        — followed by database name + plugin name if the matching capability
          flags were negotiated. We don't need them for logging.

    Returns `{}` if the packet doesn't parse — robust against scanner garbage.
    """
    out: dict[str, Any] = {}
    if len(payload) < 32:
        return out

    try:
        client_flag = struct.unpack("<I", payload[0:4])[0]
        max_packet_size = struct.unpack("<I", payload[4:8])[0]
        charset = payload[8]
    except (struct.error, IndexError):
        return out

    out["client_flag"] = client_flag
    out["max_packet_size"] = max_packet_size
    out["charset"] = charset

    pos = 32  # skip reserved bytes
    # Username — null-terminated string
    null_idx = payload.find(b"\x00", pos)
    if null_idx == -1:
        return out
    out["username"] = payload[pos:null_idx].decode("utf-8", errors="replace")
    pos = null_idx + 1

    # auth_response_length — length-encoded int. For our simple case the
    # `mysql_native_password` plugin produces a 20-byte scramble so the
    # length byte is just 20. Handle the common 1-byte path.
    if pos >= len(payload):
        return out
    auth_len = payload[pos]
    pos += 1
    if pos + auth_len > len(payload):
        return out
    auth_response = payload[pos : pos + auth_len]
    out["auth_response_hex"] = auth_response.hex()
    pos += auth_len

    # Optional database name (null-term)
    if pos < len(payload):
        next_null = payload.find(b"\x00", pos)
        if next_null != -1:
            out["database"] = payload[pos:next_null].decode("utf-8", errors="replace")

    return out


class _MySQLProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._sent_handshake = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)

        # Send the Initial Handshake Packet immediately. Real MySQL sends
        # this on connection — the client doesn't write first.
        salt_1 = secrets.token_bytes(8)
        salt_2 = secrets.token_bytes(12)
        transport.write(_build_handshake_packet(salt_1, salt_2))
        self._sent_handshake = True

        asyncio.create_task(self._record("mysql_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        # Read one packet: 3-byte LE length + 1-byte sequence id + payload.
        if len(self._buf) < 4:
            return
        payload_len = int.from_bytes(self._buf[0:3], "little")
        seq = self._buf[3]
        if len(self._buf) < 4 + payload_len:
            return
        payload = self._buf[4 : 4 + payload_len]
        self._buf = self._buf[4 + payload_len :]

        parsed = _parse_handshake_response(payload)
        username = parsed.get("username", "")

        # Reply with ER_ACCESS_DENIED_ERROR (1045) — the universal "wrong
        # creds" response. SQLSTATE 28000 is the matching standard code.
        host_str = f"{self._peer[0]}:{self._peer[1]}"
        err = _build_error_packet(
            seq=seq + 1,
            errno=1045,
            sqlstate="28000",
            message=f"Access denied for user '{username}'@'{host_str}' (using password: YES)",
        )
        if self._transport is not None:
            self._transport.write(err)
            self._transport.close()

        asyncio.create_task(
            self._record(
                "mysql_login_attempt",
                AlertSeverity.HIGH,
                {**parsed, "service": "mysql"},
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


class MySQLEngine(HoneypotEngine):
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
            lambda: _MySQLProtocol(name, hp_id),
            host="0.0.0.0",
            port=port,
        )
        cid = f"mysql-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("MySQL honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_mysql"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["MySQL honeypot is in-process — events are stored directly in the database."]
