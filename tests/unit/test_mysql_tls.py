"""MySQL honeypot TLS: the SSLRequest upgrade, driven by a TLS client we did not write.

mariadb-client >= 11.4 requires TLS by default, so an engine that does not offer it is refused
before any credential is sent (`SSL is required, but the server does not support it`). Offering it
is not just a flag: the client sends a 32-byte SSLRequest and then its ClientHello *without waiting
for the server*, so one `data_received` call can carry both, and `loop.start_tls` cannot replay
bytes the protocol has already been handed. The coalescing tests are the ones that would have
failed intermittently against a naive upgrade.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import ssl
import struct
import time

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

CLIENT_SSL = 0x0800
# PROTOCOL_41 | TRANSACTIONS | SECURE_CONNECTION | PLUGIN_AUTH | CONNECT_ATTRS
_CLIENT_FLAGS = 0x00000200 | 0x00002000 | 0x00008000 | 0x00080000 | 0x00100000


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match, suppression
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    suppression.invalidate_rule_cache()
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()


@pytest.fixture
async def server():
    from honeypot_mcp.engines.mysql import MySQLEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(
            Honeypot(
                name="mysql-tls",
                type=HoneypotType.MYSQL,
                port=port,
                status=HoneypotStatus.RUNNING,
                container_id=None,
                config={},
            )
        )
    engine = MySQLEngine()
    cid = await engine.start("mysql-tls", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


async def _events(event_type: str, *, count: int = 1, wait: float = 5.0) -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    deadline = asyncio.get_running_loop().time() + wait
    while True:
        async with get_session() as session:
            rows = (
                (
                    await session.execute(
                        select(Alert).where(Alert.event_type == event_type).order_by(Alert.id)
                    )
                )
                .scalars()
                .all()
            )
        if len(rows) >= count or asyncio.get_running_loop().time() > deadline:
            return list(rows)
        await asyncio.sleep(0.05)


def _packet(seq: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _ssl_request() -> bytes:
    return _packet(1, struct.pack("<IIB", _CLIENT_FLAGS | CLIENT_SSL, 1 << 24, 45) + b"\x00" * 23)


def _login(seq: int, username: bytes, scramble: bytes, *, flags: int) -> bytes:
    body = (
        struct.pack("<IIB", flags, 1 << 24, 45)
        + b"\x00" * 23
        + username
        + b"\x00"
        + bytes([len(scramble)])
        + scramble
        + b"mysql_native_password\x00"
    )
    return _packet(seq, body)


def _query(sql: str) -> bytes:
    return _packet(0, b"\x03" + sql.encode())


async def _plain_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
    n = int.from_bytes(header[:3], "little")
    return header[3], await asyncio.wait_for(reader.readexactly(n), timeout=5.0)


class _TLSClient:
    """A MySQL client's TLS half: an `ssl.SSLObject` over memory BIOs, so a test chooses exactly
    which bytes go on the wire in which write and cannot be helped by a library doing the upgrade."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        version: ssl.TLSVersion | None = None,
    ) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if version is not None:
            ctx.minimum_version = ctx.maximum_version = version
        self.reader, self.writer = reader, writer
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.ssl = ctx.wrap_bio(self._in, self._out, server_hostname=None)
        self._plain = bytearray()

    def client_hello(self) -> bytes:
        with pytest.raises(ssl.SSLWantReadError):
            self.ssl.do_handshake()
        return self._out.read()

    async def _pull(self) -> None:
        data = await asyncio.wait_for(self.reader.read(65536), timeout=5.0)
        if not data:
            raise ConnectionError("server closed the connection")
        self._in.write(data)

    async def _push(self) -> None:
        out = self._out.read()
        if out:
            self.writer.write(out)
            await self.writer.drain()

    async def finish_handshake(self) -> None:
        while True:
            try:
                self.ssl.do_handshake()
                await self._push()
                return
            except ssl.SSLWantReadError:
                await self._push()
                await self._pull()

    async def send(self, data: bytes) -> None:
        self.ssl.write(data)
        await self._push()

    async def packet(self) -> tuple[int, bytes]:
        while True:
            if len(self._plain) >= 4:
                n = int.from_bytes(self._plain[:3], "little")
                if len(self._plain) >= 4 + n:
                    seq, body = self._plain[3], bytes(self._plain[4 : 4 + n])
                    del self._plain[: 4 + n]
                    return seq, body
            try:
                chunk = self.ssl.read(65536)
            except ssl.SSLWantReadError:
                await self._pull()
                continue
            if not chunk:
                raise ConnectionError("TLS stream ended")
            self._plain += chunk

    async def result_rows(self, sql: str) -> list[str]:
        """Run a one-column query and return the rows' text."""
        await self.send(_query(sql))
        packets: list[bytes] = []
        eofs = 0
        while eofs < 2:
            _, body = await self.packet()
            packets.append(body)
            eofs += body[:1] == b"\xfe" and len(body) < 9
        # column count, column definition, EOF, rows..., EOF
        return [p[1 : 1 + p[0]].decode() for p in packets[3:-1]]

    async def login(self, username: bytes = b"root", password: bytes = b"Root123") -> bytes:
        from honeypot_mcp.credential_verify import mysql_native_token

        self._salt = self._salt_from_greeting
        scramble = mysql_native_token(password, self._salt)
        await self.send(_login(2, username, scramble, flags=_CLIENT_FLAGS | CLIENT_SSL))
        _, ok = await self.packet()
        return ok

    _salt_from_greeting = b""

    def close(self) -> None:
        self.writer.close()


def _salt_of(greeting: bytes) -> bytes:
    nul = greeting.index(b"\x00", 1)
    pos = nul + 1 + 4
    part1 = greeting[pos : pos + 8]
    pos += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
    return part1 + greeting[pos : pos + 12]


async def _connect(
    port: int, version: ssl.TLSVersion | None = None
) -> tuple[_TLSClient, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    seq, greeting = await _plain_packet(reader)
    assert seq == 0
    client = _TLSClient(reader, writer, version)
    client._salt_from_greeting = _salt_of(greeting)
    return client, reader, writer


# ── the greeting ─────────────────────────────────────────────────────────────────────────────


async def test_greeting_offers_tls_and_keeps_every_other_capability(server):
    """CLIENT_SSL is what mariadb >= 11.4 and nmap's mysql-info read; the bits the engine already
    claimed must not move."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server)
    try:
        _, greeting = await _plain_packet(reader)
    finally:
        writer.close()
    nul = greeting.index(b"\x00", 1)
    pos = nul + 1 + 4 + 8 + 1
    (lower,) = struct.unpack_from("<H", greeting, pos)
    (upper,) = struct.unpack_from("<H", greeting, pos + 2 + 1 + 2)
    flags = lower | upper << 16
    assert flags & CLIENT_SSL
    assert flags == 0x807FE7FF | CLIENT_SSL | 0x1000  # 0x1000: IGNORE_SIGPIPE, as real MySQL 8


# ── a TLS client completes the login and the command phase ──────────────────────────────────


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
async def test_tls_client_logs_in_and_gets_show_databases_rows(server, version):
    client, _reader, _writer = await _connect(server, version)
    try:
        _, writer = client.reader, client.writer
        writer.write(_ssl_request())
        await writer.drain()
        await asyncio.sleep(0.05)  # the server must not need anything from us in between
        writer.write(client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        assert client.ssl.version() == (
            "TLSv1.2" if version is ssl.TLSVersion.TLSv1_2 else "TLSv1.3"
        )

        ok = await client.login()
        assert ok[0] == 0x00
        assert await client.result_rows("show databases") == [
            "information_schema",
            "mysql",
            "performance_schema",
            "sys",
        ]
        assert await client.result_rows("select 1") == ["1"]
    finally:
        client.close()


async def test_server_certificate_is_the_one_mysql_8_generates(server):
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        der = client.ssl.getpeercert(binary_form=True)
    finally:
        client.close()
    assert der is not None
    cert = x509.load_der_x509_certificate(der)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "MySQL_Server_8.0.36_Auto_Generated_Server_Certificate"


async def test_auth_switch_flow_works_inside_tls_and_a_planted_password_fires(server):
    """libmariadb names `dummy_fallback_auth`, sends no password, and waits for the server's
    AuthSwitchRequest — all of it now inside TLS. The token must still resolve against the salt."""
    from honeypot_mcp import credential_match
    from honeypot_mcp.credential_verify import mysql_native_token
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label="tls",
            token_value="cred:test:tls",
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                "service": "mysql",
                "credentials": [{"username": "root", "password": "Tr1cky!Pass"}],
                "count": 1,
            },
        )
        session.add(token)
        await session.flush()
        token_id = token.id
    credential_match.invalidate_cache()

    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        first = (
            struct.pack("<IIB", _CLIENT_FLAGS | CLIENT_SSL, 1 << 24, 45)
            + b"\x00" * 23
            + b"root\x00\x00dummy_fallback_auth\x00"
        )
        await client.send(_packet(2, first))
        seq, switch = await client.packet()
        assert seq == 3 and switch[0] == 0xFE
        salt = switch[1 + len(b"mysql_native_password\x00") : -1]
        assert salt == client._salt_from_greeting
        await client.send(_packet(4, mysql_native_token(b"Tr1cky!Pass", salt)))
        seq, ok = await client.packet()
        assert seq == 5 and ok[0] == 0x00
    finally:
        client.close()

    fired = await _events("honeytoken_triggered_credential_via_mysql_login_attempt")
    assert len(fired) == 1
    async with get_session() as session:
        assert (await session.get(Honeytoken, token_id)).status == HoneytokenStatus.TRIGGERED
    assert fired[0].payload["tls"] is True
    assert fired[0].payload["salt_hex"] == salt.hex()


# ── the race: SSLRequest and ClientHello arrive together ────────────────────────────────────


async def test_sslrequest_and_clienthello_in_one_write_never_hangs(server, monkeypatch):
    """The client does not wait for the server between the two, so they routinely share one TCP
    segment and one `data_received`. Fifty in a row, each with a full login and a query."""
    from honeypot_mcp.engines import mysql

    first_chunks: list[int] = []
    original = mysql._MySQLProtocol._receive_plain

    def spy(self, data):
        if not self._buf and not self._authed and self._tls is None:
            first_chunks.append(len(data))
        return original(self, data)

    monkeypatch.setattr(mysql._MySQLProtocol, "_receive_plain", spy)

    for i in range(50):
        client, _r, writer = await _connect(server)
        try:
            writer.write(_ssl_request() + client.client_hello())  # one write(), one segment
            await writer.drain()
            await asyncio.wait_for(client.finish_handshake(), timeout=5.0)
            ok = await client.login()
            assert ok[0] == 0x00, f"connection {i}"
            assert await client.result_rows("select 1") == ["1"]
        finally:
            client.close()

    # The SSLRequest alone is 36 bytes on the wire: anything longer is the SSLRequest and the
    # start of the ClientHello arriving in the same read — the case this test exists to hit.
    coalesced = sum(1 for n in first_chunks if n > 36)
    assert coalesced >= 25, f"only {coalesced}/50 reads carried both; the race was not exercised"


async def test_sslrequest_and_clienthello_in_separate_writes(server):
    for i in range(10):
        client, _r, writer = await _connect(server)
        try:
            writer.write(_ssl_request())
            await writer.drain()
            await asyncio.sleep(0.02)
            writer.write(client.client_hello())
            await writer.drain()
            await asyncio.wait_for(client.finish_handshake(), timeout=5.0)
            assert (await client.login())[0] == 0x00, f"connection {i}"
        finally:
            client.close()


async def test_clienthello_dribbled_a_few_bytes_at_a_time(server):
    """Partial TLS records must be buffered by the TLS layer, not mistaken for a failed handshake."""
    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request())
        await writer.drain()
        hello = client.client_hello()
        for start in range(0, len(hello), 37):
            writer.write(hello[start : start + 37])
            await writer.drain()
            await asyncio.sleep(0.005)
        await asyncio.wait_for(client.finish_handshake(), timeout=5.0)
        assert (await client.login())[0] == 0x00
    finally:
        client.close()


# ── bounds survive the upgrade ──────────────────────────────────────────────────────────────


async def test_client_that_stalls_after_the_sslrequest_is_cut_off(server, monkeypatch):
    from honeypot_mcp.engines import mysql

    monkeypatch.setattr(mysql, "_TLS_HANDSHAKE_TIMEOUT", 0.3)
    _client, reader, writer = await _connect(server)
    try:
        writer.write(_ssl_request())
        await writer.drain()
        started = time.monotonic()
        with contextlib.suppress(ConnectionError):
            data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            assert data == b"", "server sent something to a client that never started TLS"
        assert time.monotonic() - started < 3.0
    finally:
        writer.close()


async def test_handshake_deadline_does_not_kill_a_connection_that_completed_it(server, monkeypatch):
    from honeypot_mcp.engines import mysql

    monkeypatch.setattr(mysql, "_TLS_HANDSHAKE_TIMEOUT", 0.3)
    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        await asyncio.sleep(0.7)  # well past the deadline
        assert (await client.login())[0] == 0x00
        assert await client.result_rows("select 1") == ["1"]
    finally:
        client.close()


async def test_oversized_packet_inside_tls_closes_the_connection(server):
    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        assert (await client.login())[0] == 0x00
        # A header promising 4 MiB, over `_MAX_PACKET_BYTES`: nothing legitimate is that large.
        await client.send(struct.pack("<I", 4 * 1024 * 1024)[:3] + b"\x00" + b"x" * 64)
        with pytest.raises(ConnectionError):
            await client.packet()
    finally:
        client.close()


async def test_garbage_after_the_sslrequest_closes_without_a_login(server):
    _client, reader, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        with contextlib.suppress(ConnectionError):
            while await asyncio.wait_for(reader.read(4096), timeout=5.0):
                pass  # any TLS alert the server sends, then EOF
    finally:
        writer.close()
    await asyncio.sleep(0.3)
    assert await _events("mysql_login_attempt", wait=0.5) == []


# ── the login event ─────────────────────────────────────────────────────────────────────────


async def test_login_event_over_tls_carries_tls_true_and_the_auth_fields(server):
    from honeypot_mcp.credential_verify import mysql_native_token

    client, _r, writer = await _connect(server)
    try:
        writer.write(_ssl_request() + client.client_hello())
        await writer.drain()
        await client.finish_handshake()
        await client.login(b"admin", b"hunter2")
    finally:
        client.close()
    (event,) = await _events("mysql_login_attempt")
    p = event.payload
    assert p["tls"] is True
    assert p["username"] == "admin"
    assert p["service"] == "mysql"
    assert p["salt_hex"] == client._salt_from_greeting.hex()
    assert (
        p["auth_response_hex"] == mysql_native_token(b"hunter2", client._salt_from_greeting).hex()
    )


async def test_plain_login_still_works_and_carries_no_tls_flag(server):
    """A client that skips TLS (`--skip-ssl`, hydra, most scanners) is the bulk of real traffic."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server)
    try:
        await _plain_packet(reader)
        writer.write(_login(1, b"root", b"\xaa" * 20, flags=_CLIENT_FLAGS))
        await writer.drain()
        _, ok = await _plain_packet(reader)
        assert ok[0] == 0x00
        writer.write(_query("select 1"))
        await writer.drain()
        _, count = await _plain_packet(reader)
        assert count == b"\x01"
    finally:
        writer.close()
    (event,) = await _events("mysql_login_attempt")
    assert "tls" not in event.payload
    assert event.payload["username"] == "root"


async def test_full_login_that_merely_sets_client_ssl_is_not_mistaken_for_an_sslrequest(server):
    """Only the bare 32-byte packet is an SSLRequest. A client that sets the flag but sends its
    credentials in the clear must still be captured, not left waiting for a handshake."""
    reader, writer = await asyncio.open_connection("127.0.0.1", server)
    try:
        await _plain_packet(reader)
        writer.write(_login(1, b"root", b"\xbb" * 20, flags=_CLIENT_FLAGS | CLIENT_SSL))
        await writer.drain()
        _, ok = await _plain_packet(reader)
        assert ok[0] == 0x00
    finally:
        writer.close()
    (event,) = await _events("mysql_login_attempt")
    assert "tls" not in event.payload
    assert event.payload["auth_response_hex"] == "bb" * 20
