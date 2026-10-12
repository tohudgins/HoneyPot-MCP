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

TLS: the greeting advertises CLIENT_SSL. A TLS-capable client answers with a
32-byte SSLRequest and starts its handshake on the same connection without waiting
for us, then sends the real HandshakeResponse41 inside TLS (`_TLSTransport`). The
login event carries `tls: true` when that happened.

Login attempts are also fed to `credential_match` with `service="mysql"`,
so planted CREDENTIAL honeytokens fire across MySQL just like the other
services.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
import re
import secrets
import ssl
import struct
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._bounds import write_backlogged
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory, shutdown_server
from honeypot_mcp.engines.tls import CertProfile, build_server_ssl_context_async
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


# Server version advertised in the Initial Handshake Packet. Tracking
# distinct minor versions matters for some clients' capability negotiation —
# 8.0.36-0ubuntu0.22.04.1 is a current stock Ubuntu install fingerprint.
_SERVER_VERSION = b"8.0.36-0ubuntu0.22.04.1"

# CapabilityFlags the greeting advertises, named so each bit is auditable. A
# superset of what real MySQL 8.0 emits with mysql_native_password.
_CLIENT_LONG_PASSWORD = 0x00000001
_CLIENT_FOUND_ROWS = 0x00000002
_CLIENT_LONG_FLAG = 0x00000004
_CLIENT_CONNECT_WITH_DB = 0x00000008
_CLIENT_NO_SCHEMA = 0x00000010
_CLIENT_COMPRESS = 0x00000020
_CLIENT_ODBC = 0x00000040
_CLIENT_LOCAL_FILES = 0x00000080
_CLIENT_IGNORE_SPACE = 0x00000100
_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_INTERACTIVE = 0x00000400
_CLIENT_SSL = 0x00000800
_CLIENT_IGNORE_SIGPIPE = 0x00001000
_CLIENT_TRANSACTIONS = 0x00002000
_CLIENT_RESERVED = 0x00004000
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_MULTI_STATEMENTS = 0x00010000
_CLIENT_MULTI_RESULTS = 0x00020000
_CLIENT_PS_MULTI_RESULTS = 0x00040000
_CLIENT_PLUGIN_AUTH = 0x00080000
_CLIENT_CONNECT_ATTRS = 0x00100000
_CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
_CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
_CLIENT_REMEMBER_OPTIONS = 0x80000000

# Everything the engine has always advertised (0x807FE7FF), plus CLIENT_IGNORE_SIGPIPE: a
# client-side no-op that real MySQL 8 sets, so nmap's `Capabilities flags` reads 65535.
_BASE_CAPABILITY_FLAGS = (
    _CLIENT_LONG_PASSWORD
    | _CLIENT_FOUND_ROWS
    | _CLIENT_LONG_FLAG
    | _CLIENT_CONNECT_WITH_DB
    | _CLIENT_NO_SCHEMA
    | _CLIENT_COMPRESS
    | _CLIENT_ODBC
    | _CLIENT_LOCAL_FILES
    | _CLIENT_IGNORE_SPACE
    | _CLIENT_PROTOCOL_41
    | _CLIENT_INTERACTIVE
    | _CLIENT_IGNORE_SIGPIPE
    | _CLIENT_TRANSACTIONS
    | _CLIENT_RESERVED
    | _CLIENT_SECURE_CONNECTION
    | _CLIENT_MULTI_STATEMENTS
    | _CLIENT_MULTI_RESULTS
    | _CLIENT_PS_MULTI_RESULTS
    | _CLIENT_PLUGIN_AUTH
    | _CLIENT_CONNECT_ATTRS
    | _CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
    | _CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS
    | _CLIENT_REMEMBER_OPTIONS
)
# Real MySQL 8 offers TLS with an auto-generated certificate, and mariadb-client
# >= 11.4 refuses a server that does not. The engine always holds a certificate
# (`MySQLEngine.start` builds it), so CLIENT_SSL is always truthful.
_CAPABILITY_FLAGS = _BASE_CAPABILITY_FLAGS | _CLIENT_SSL

# Status flags. SERVER_STATUS_AUTOCOMMIT (0x0002).
_STATUS_FLAGS = 0x0002

# The certificate MySQL 8 generates at first start: a leaf `..._Auto_Generated_Server_Certificate`
# issued by a `..._Auto_Generated_CA_Certificate`, valid ten years, no SAN, no key usage.
_CERT_PROFILE = CertProfile(
    common_name="MySQL_Server_8.0.36_Auto_Generated_Server_Certificate",
    issuer_common_name="MySQL_Server_8.0.36_Auto_Generated_CA_Certificate",
    days=3650,
    dns_names=(),
)

# A client sends the 32-byte SSLRequest and then a ClientHello, with no reply
# awaited in between; a peer that goes quiet after the SSLRequest is cut off
# after this long (MySQL's own connect_timeout is 10s).
_TLS_HANDSHAKE_TIMEOUT = 10.0
_TLS_READ_CHUNK = 16 * 1024


# Character set: utf8mb4_general_ci (0xff is wrong; 0x2D is utf8mb4_general_ci).
_CHARSET = 0x2D

# What `SHOW DATABASES` lists on a fresh MySQL 8 install.
_DATABASES = ("information_schema", "mysql", "performance_schema", "sys")

# Per-connection bounds. The wire format allows 16 MiB packets; nothing a
# honeypot needs to capture is that large, and buffering them is the exposure.
_MAX_PACKET_BYTES = 1024 * 1024
_MAX_PACKETS_PER_CONN = 1024
_MAX_WRITE_BUFFER = 256 * 1024


# A MySQL connection id is a per-server counter, so every connection sees a higher one than the
# last. The greeting used the constant 12345, which nmap's `mysql-info` prints ("Thread ID: 12345")
# on every scan: a decoy tell. Start somewhere a busy server plausibly is.
_CONNECTION_IDS = itertools.count(secrets.randbelow(4000) + 800)


def _build_handshake_packet(salt_1: bytes, salt_2: bytes, thread_id: int) -> bytes:
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
            struct.pack("<I", thread_id),  # connection id
            salt_1,
            b"\x00",  # filler
            struct.pack("<H", cap_lower),
            bytes([_CHARSET]),
            struct.pack("<H", _STATUS_FLAGS),
            struct.pack("<H", cap_upper),
            bytes([21]),  # auth_plugin_data_length (20+null)
            b"\x00" * 10,  # reserved
            salt_2,
            b"\x00",  # auth_plugin_data_part_2 is 13 bytes: the 12 of scramble and a NUL
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
    out["username"] = payload[pos : min(null_idx, pos + 2048)].decode("utf-8", errors="replace")
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

    # Optional database name (CLIENT_CONNECT_WITH_DB) and plugin name (CLIENT_PLUGIN_AUTH),
    # both null-terminated and each present only if its capability flag was sent. Reading them
    # without the flags files the plugin name as the database.
    if client_flag & _CLIENT_CONNECT_WITH_DB and pos < len(payload):
        next_null = payload.find(b"\x00", pos)
        if next_null != -1:
            out["database"] = payload[pos : min(next_null, pos + 2048)].decode(
                "utf-8", errors="replace"
            )
            pos = next_null + 1
    if client_flag & _CLIENT_PLUGIN_AUTH and pos < len(payload):
        next_null = payload.find(b"\x00", pos)
        if next_null != -1:
            out["auth_plugin"] = payload[pos : min(next_null, pos + 128)].decode(
                "utf-8", errors="replace"
            )

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


def _resultset(column_name: str, values: list[str]) -> bytes:
    """A one-column text result set, one row per value."""
    out = _packet(1, _lenenc_int(1))  # column count = 1
    out += _column_def(2, column_name)
    out += _eof_packet(3)
    seq = 4
    for value in values:
        out += _packet(seq, _lenenc_str(value))
        seq += 1
    out += _eof_packet(seq)
    return out


def _single_value_resultset(column_name: str, value: str) -> bytes:
    """A one-column, one-row text result set — enough for `SELECT @@version`
    and friends so a scanner that reads results stays engaged."""
    return _resultset(column_name, [value])


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


class _TLSTransport(asyncio.Transport):
    """The decrypted side of a TLS session riding on `raw`, shaped like a transport.

    `loop.start_tls` cannot be used here: the client sends its ClientHello straight
    after the SSLRequest without waiting for us, so the read that delivered the
    SSLRequest may already hold the first bytes of the handshake, and bytes already
    handed to the protocol cannot be replayed into a new SSL transport. Driving the
    session through memory BIOs lets the protocol feed those leftover bytes in itself.

    The raw transport stays the one the connection limiter tracks, so the idle and
    lifetime timers, the per-IP cap and `close_all` keep working unchanged; the write
    backlog is the raw transport's, so `write_backlogged` sees what is really unsent.
    """

    def __init__(
        self,
        raw: asyncio.Transport,
        sslobj: ssl.SSLObject,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
    ) -> None:
        super().__init__()
        self._raw = raw
        self._ssl = sslobj
        self._incoming = incoming
        self._outgoing = outgoing
        self._closing = False
        self.handshaken = False

    def feed(self, data: bytes) -> None:
        self._incoming.write(data)

    def do_handshake(self) -> None:
        self._ssl.do_handshake()
        self.handshaken = True

    def read(self, n: int) -> bytes:
        return self._ssl.read(n)

    def flush(self) -> None:
        """Send whatever the TLS layer has queued (handshake records, alerts, tickets)."""
        data = self._outgoing.read()
        if data and not self._raw.is_closing():
            self._raw.write(data)

    def write(self, data: bytes | bytearray | memoryview) -> None:
        if self.is_closing():
            return
        try:
            self._ssl.write(bytes(data))
        except ssl.SSLError:
            self.abort()
            return
        self.flush()

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self.handshaken:
            with contextlib.suppress(ssl.SSLError):
                self._ssl.unwrap()  # queues our close_notify
        self.flush()
        self._raw.close()

    def abort(self) -> None:
        self._closing = True
        self._raw.abort()

    def is_closing(self) -> bool:
        return self._closing or self._raw.is_closing()

    def get_write_buffer_size(self) -> int:
        return self._raw.get_write_buffer_size()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "ssl_object":
            return self._ssl
        if name == "cipher":
            return self._ssl.cipher()
        return self._raw.get_extra_info(name, default)


class _MySQLProtocol(asyncio.Protocol):
    def __init__(
        self, honeypot_name: str, honeypot_id: int | None, ssl_ctx: ssl.SSLContext
    ) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._ssl_ctx = ssl_ctx
        # `_transport` is what replies are written to: the raw transport until the
        # client upgrades, then the TLS view of it.
        self._transport: asyncio.Transport | None = None
        self._raw: asyncio.Transport | None = None
        self._tls: _TLSTransport | None = None
        self._handshake_timer: asyncio.TimerHandle | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = bytearray()
        self._packets = 0
        self._sent_handshake = False
        self._authed = False
        # A handshake response awaiting the client's reply to our AuthSwitchRequest.
        self._pending_login: dict[str, Any] | None = None
        # Full 20-byte scramble we advertised — needed to verify the client's
        # mysql_native_password response against a planted honeytoken password.
        self._salt = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = self._raw = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)

        # Send the Initial Handshake Packet immediately. Real MySQL sends
        # this on connection — the client doesn't write first.
        salt_1 = secrets.token_bytes(8)
        salt_2 = secrets.token_bytes(12)
        self._salt = salt_1 + salt_2
        transport.write(_build_handshake_packet(salt_1, salt_2, next(_CONNECTION_IDS)))
        self._sent_handshake = True

        spawn(self._record("mysql_connection", AlertSeverity.LOW, {}), name="mysql-event")

    def _close(self) -> None:
        self._buf.clear()
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()
        elif self._raw is not None and not self._raw.is_closing():
            self._raw.close()

    def data_received(self, data: bytes) -> None:
        t = self._transport
        if t is None or t.is_closing():
            return
        if self._tls is not None:
            self._receive_tls(data)
        else:
            self._receive_plain(data)

    def _is_ssl_request(self, payload: bytes) -> bool:
        """The 32-byte SSLRequest: a HandshakeResponse41 header with CLIENT_SSL set and
        no username, sent before the client's TLS handshake."""
        return (
            self._tls is None
            and self._pending_login is None
            and len(payload) == 32
            and struct.unpack_from("<I", payload)[0] & _CLIENT_SSL != 0
        )

    def _start_tls(self) -> None:
        assert self._raw is not None
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        sslobj = self._ssl_ctx.wrap_bio(incoming, outgoing, server_side=True)
        self._tls = _TLSTransport(self._raw, sslobj, incoming, outgoing)
        self._transport = self._tls
        self._handshake_timer = asyncio.get_running_loop().call_later(
            _TLS_HANDSHAKE_TIMEOUT, self._handshake_expired
        )

    def _handshake_expired(self) -> None:
        self._handshake_timer = None
        if self._tls is not None and not self._tls.handshaken and self._raw is not None:
            self._raw.abort()

    def _receive_tls(self, data: bytes) -> None:
        """Feed raw bytes to the TLS session and run whatever plaintext comes out
        through the MySQL packet handler."""
        tls = self._tls
        assert tls is not None
        tls.feed(data)
        if not tls.handshaken:
            try:
                tls.do_handshake()
            except ssl.SSLWantReadError:
                tls.flush()
                return
            except (ssl.SSLError, OSError):
                tls.flush()  # OpenSSL has queued the alert a real server would send
                self._close()
                return
            if self._handshake_timer is not None:
                self._handshake_timer.cancel()
                self._handshake_timer = None
        while not tls.is_closing():
            try:
                chunk = tls.read(_TLS_READ_CHUNK)
            except ssl.SSLWantReadError:
                break
            except ssl.SSLError:  # includes the peer's close_notify and a truncated stream
                self._close()
                return
            if not chunk:
                break
            self._receive_plain(chunk)
        tls.flush()

    def _receive_plain(self, data: bytes) -> None:
        t = self._transport
        if t is None or t.is_closing():
            return
        self._buf += data
        buf = self._buf
        pos = 0
        try:
            # Drain all complete packets: 3-byte LE length + 1-byte seq + payload.
            while len(buf) - pos >= 4 and not t.is_closing():
                if write_backlogged(t, _MAX_WRITE_BUFFER):
                    self._close()  # peer is not reading its replies
                    return
                payload_len = int.from_bytes(buf[pos : pos + 3], "little")
                if payload_len > _MAX_PACKET_BYTES:
                    self._close()
                    return
                seq = buf[pos + 3]
                if len(buf) - pos < 4 + payload_len:
                    break
                self._packets += 1
                if self._packets > _MAX_PACKETS_PER_CONN:
                    self._close()
                    return
                payload = bytes(buf[pos + 4 : pos + 4 + payload_len])
                pos += 4 + payload_len
                if not self._authed:
                    if self._is_ssl_request(payload):
                        # Everything after this packet is the start of the TLS handshake,
                        # not MySQL: the client does not wait for us between the SSLRequest
                        # and its ClientHello, so the same read can carry both.
                        leftover = bytes(buf[pos:])
                        buf.clear()
                        self._start_tls()
                        if leftover:
                            self._receive_tls(leftover)
                        return
                    self._handle_login(seq, payload)
                else:
                    self._handle_command(seq, payload)
        except Exception:
            log.exception("mysql protocol error")
            self._close()
            return
        del buf[:pos]

    def _handle_login(self, seq: int, payload: bytes) -> None:
        if self._pending_login is not None:
            # The reply to our AuthSwitchRequest: the bare 20-byte scramble response, no
            # length prefix. It is what the first packet lacked.
            parsed, self._pending_login = self._pending_login, None
            parsed["auth_response_hex"] = payload[:512].hex()
            self._finish_login(seq, parsed)
            return
        parsed = _parse_handshake_response(payload)
        plugin = parsed.get("auth_plugin")
        if plugin and plugin != "mysql_native_password" and self._transport is not None:
            # A client that does not already speak the server's plugin (libmariadb names its
            # placeholder `dummy_fallback_auth`) sends no password with its first packet and
            # waits for the server to say which plugin to use, as MySQL 8 does. Without this
            # the client treated the immediate OK as a protocol error and the password was
            # never captured.
            self._pending_login = parsed
            switch = b"\xfemysql_native_password\x00" + self._salt + b"\x00"
            self._transport.write(_packet(seq + 1, switch))
            return
        self._finish_login(seq, parsed)

    def _finish_login(self, seq: int, parsed: dict[str, Any]) -> None:
        payload = {**parsed, "service": "mysql", "salt_hex": self._salt.hex()}
        if self._tls is not None:
            payload["tls"] = True
        spawn(self._record("mysql_login_attempt", AlertSeverity.HIGH, payload), name="mysql-event")
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
            spawn(
                self._record(event_type, severity, {"query": sql[:4096], "service": "mysql"}),
                name="mysql-event",
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
            column = "@@version" if "@@version" in s else "version()"
            t.write(_single_value_resultset(column, _SERVER_VERSION.decode()))
        elif "user()" in s or "current_user" in s:
            t.write(_single_value_resultset("user()", "root@localhost"))
        elif "@@datadir" in s:
            t.write(_single_value_resultset("@@datadir", "/var/lib/mysql/"))
        elif re.fullmatch(r"show\s+(databases|schemas)\s*;?", s):
            t.write(_resultset("Database", list(_DATABASES)))
        elif m := re.fullmatch(r"select\s+(\d{1,9})\s*;?", s):
            t.write(_single_value_resultset(m.group(1), m.group(1)))
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
        self._buf.clear()
        if self._handshake_timer is not None:
            self._handshake_timer.cancel()
            self._handshake_timer = None


class MySQLEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        # Real MySQL 8 offers TLS with a self-generated certificate, and clients that
        # require TLS (mariadb-client >= 11.4 by default) refuse a server that does not.
        ssl_ctx = await build_server_ssl_context_async(name, profile=_CERT_PROFILE)
        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _MySQLProtocol(name, hp_id, ssl_ctx), self._limiter),
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
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_mysql"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["MySQL honeypot is in-process — events are stored directly in the database."]
