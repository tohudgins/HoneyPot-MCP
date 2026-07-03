"""MySQL honeypot — handshake, credential capture, and post-auth query capture.

MySQL on port 3306 is a constant brute-force target on the internet:
default-credential sweepers, exposed-DB scrapers, ransomware actors.
We do the Initial Handshake + HandshakeResponse41 faithfully to harvest a
believable username + password attempt, then ACCEPT the login and enter the
command phase — because a fake datastore with no real data loses nothing by
granting access, and the post-auth SQL is where the attacker's real objective
shows: recon (`@@version`, `information_schema`, `SHOW DATABASES`), file read
(`LOAD_FILE`, `LOAD DATA`), and the RCE patterns that matter most —
`INTO OUTFILE`/`INTO DUMPFILE` webshell drops and `CREATE FUNCTION … SONAME`
UDF loads. Those are flagged HIGH/CRITICAL via `_classify_query`.

We reply to `SELECT @@version` / `user()` / `@@datadir` with believable
single-value result sets and OK-packet everything else — enough to keep a
scanner running its whole playbook so we capture it, without implementing a
real query engine (no data is ever stored or returned from a real table).

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


def _lenenc_int(n: int) -> bytes:
    if n < 251:
        return bytes([n])
    if n < 65536:
        return b"\xfc" + struct.pack("<H", n)
    if n < 16777216:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def _lenenc_str(s: str) -> bytes:
    b = s.encode("utf-8", errors="replace")
    return _lenenc_int(len(b)) + b


def _packet(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _ok_packet(seq: int) -> bytes:
    payload = bytes([0x00]) + b"\x00" + b"\x00" + struct.pack("<HH", _STATUS_FLAGS, 0)
    return _packet(seq, payload)


def _eof_packet(seq: int) -> bytes:
    return _packet(seq, bytes([0xFE]) + struct.pack("<HH", 0, _STATUS_FLAGS))


def _column_def(seq: int, name: str) -> bytes:
    payload = (
        _lenenc_str("def")  # catalog
        + _lenenc_str("")  # schema
        + _lenenc_str("")  # table
        + _lenenc_str("")  # org_table
        + _lenenc_str(name)  # name
        + _lenenc_str(name)  # org_name
        + bytes([0x0C])  # length of fixed fields
        + struct.pack("<H", 0x21)  # charset utf8_general_ci
        + struct.pack("<I", 255)  # column length
        + bytes([0xFD])  # type = VAR_STRING
        + struct.pack("<H", 0)  # flags
        + bytes([0x00])  # decimals
        + b"\x00\x00"  # filler
    )
    return _packet(seq, payload)


def _single_value_resultset(column_name: str, value: str) -> bytes:
    """A one-column, one-row text result set — enough for `SELECT @@version`
    and friends so a scanner that reads results stays engaged."""
    out = _packet(1, _lenenc_int(1))  # column count = 1
    out += _column_def(2, column_name)
    out += _eof_packet(3)
    out += _packet(4, _lenenc_str(value))  # one row, one value
    out += _eof_packet(5)
    return out


def _classify_query(sql: str) -> tuple[str, AlertSeverity]:
    """Map a captured SQL string to (event_type, severity). Recognises the
    file-write/read and UDF patterns that turn a MySQL login into RCE."""
    s = sql.lower()
    if "into outfile" in s or "into dumpfile" in s:
        return "mysql_outfile_write", AlertSeverity.CRITICAL
    if "create function" in s and "soname" in s:
        return "mysql_udf_rce", AlertSeverity.CRITICAL
    if "sys_exec" in s or "sys_eval" in s:
        return "mysql_udf_rce", AlertSeverity.CRITICAL
    if "load_file" in s or "load data" in s:
        return "mysql_file_read", AlertSeverity.HIGH
    if any(
        tok in s
        for tok in (
            "information_schema",
            "show databases",
            "show tables",
            "@@version",
            "user()",
            "current_user",
            "@@datadir",
            "@@version_compile_os",
        )
    ):
        return "mysql_recon_query", AlertSeverity.MEDIUM
    return "mysql_query", AlertSeverity.MEDIUM


class _MySQLProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._sent_handshake = False
        self._authed = False

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
        # Drain all complete packets: 3-byte LE length + 1-byte seq + payload.
        while len(self._buf) >= 4:
            payload_len = int.from_bytes(self._buf[0:3], "little")
            seq = self._buf[3]
            if len(self._buf) < 4 + payload_len:
                return
            payload = self._buf[4 : 4 + payload_len]
            self._buf = self._buf[4 + payload_len :]
            if not self._authed:
                self._handle_login(seq, payload)
            else:
                self._handle_command(seq, payload)

    def _handle_login(self, seq: int, payload: bytes) -> None:
        parsed = _parse_handshake_response(payload)
        asyncio.create_task(
            self._record("mysql_login_attempt", AlertSeverity.HIGH, {**parsed, "service": "mysql"})
        )
        # Accept the login and enter the command phase. This is a fake datastore
        # with no real data, so granting "access" is safe — and it's what lets
        # us capture the post-auth SQL (recon, INTO OUTFILE / UDF RCE attempts)
        # that reveals the attacker's actual objective, not just their creds.
        if self._transport is not None:
            self._transport.write(_ok_packet(seq + 1))
        self._authed = True

    def _handle_command(self, seq: int, payload: bytes) -> None:
        t = self._transport
        if t is None or not payload:
            return
        command = payload[0]
        # COM_QUERY = 0x03, COM_QUIT = 0x01, COM_INIT_DB = 0x02, COM_PING = 0x0e,
        # COM_FIELD_LIST = 0x04.
        if command == 0x01:  # COM_QUIT
            t.close()
            return
        if command == 0x03:  # COM_QUERY
            sql = payload[1:].decode("utf-8", errors="replace")
            event_type, severity = _classify_query(sql)
            asyncio.create_task(
                self._record(event_type, severity, {"query": sql[:4096], "service": "mysql"})
            )
            self._respond_to_query(sql)
            return
        if command in (0x02, 0x0E):  # COM_INIT_DB / COM_PING
            t.write(_ok_packet(seq + 1))
            return
        # Anything else — generic OK keeps the client talking.
        t.write(_ok_packet(seq + 1))

    def _respond_to_query(self, sql: str) -> None:
        t = self._transport
        if t is None:
            return
        s = sql.lower().strip()
        if "@@version" in s or "version()" in s:
            t.write(_single_value_resultset("@@version", _SERVER_VERSION.decode()))
        elif "user()" in s or "current_user" in s:
            t.write(_single_value_resultset("user()", "root@localhost"))
        elif "@@datadir" in s:
            t.write(_single_value_resultset("@@datadir", "/var/lib/mysql/"))
        elif s.startswith("select"):
            # Empty single-column result — believable "no rows" for arbitrary
            # SELECTs without implementing a real query engine.
            t.write(_single_value_resultset("result", ""))
        else:
            # DDL/DML/SET/USE — reply OK (0 rows affected).
            t.write(_ok_packet(1))

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
