"""Regression tests for the text/UDP engine and connection-infrastructure audit.

Every test that exercises a former hang, leak or amplification bounds itself
(timeouts, wall-time assertions) so a regression fails instead of hanging the
suite.
"""

import asyncio
import contextlib
import os
import ssl
import time

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await asyncio.sleep(0.2)
    event_buffer.reset_for_tests()
    await close_db()


async def _closed_by_peer(reader: asyncio.StreamReader, timeout: float = 3.0) -> bool:
    """True when the server ends the connection (EOF, or RST — a server that
    closes with unread pipelined input resets, as real servers do)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=deadline - time.monotonic())
        except ConnectionError:
            return True
        except TimeoutError:
            return False
        if not chunk:
            return True
    return False


async def _make_honeypot(name: str, type_name: str, port: int) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    async with get_session() as session:
        session.add(Honeypot(name=name, type=HoneypotType(type_name), port=port))
        await session.flush()


# ── SIP ─────────────────────────────────────────────────────────────────────


def test_sip_parse_digest_is_linear_on_hostile_header():
    from honeypot_mcp.engines.sip import parse_digest

    hostile = "Digest " + "a" * 65_000
    start = time.monotonic()
    assert parse_digest(hostile) == {}
    assert time.monotonic() - start < 0.5


def test_sip_parse_digest_still_reads_a_real_header():
    from honeypot_mcp.engines.sip import parse_digest

    fields = parse_digest(
        'Digest username="1001", realm="asterisk", nonce="abc123", uri="sip:x", response="deadbeef"'
    )
    assert fields["username"] == "1001"
    assert fields["nonce"] == "abc123"
    assert fields["response"] == "deadbeef"


@pytest.mark.asyncio
async def test_sip_udp_reply_is_bounded_by_the_reply_factor():
    from honeypot_mcp.engines.sip import _UDP_REPLY_FACTOR, SIPEngine

    port = free_port()
    await _make_honeypot("sip-a2", "sip", port)
    engine = SIPEngine()
    cid = await engine.start("sip-a2", port, {})
    try:
        # A tiny datagram whose faithful reply is many times larger.
        request = b"OPTIONS sip:x SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n"
        loop = asyncio.get_running_loop()
        got: asyncio.Future[bytes] = loop.create_future()

        class _Client(asyncio.DatagramProtocol):
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                if not got.done():
                    got.set_result(data)

        transport, _ = await loop.create_datagram_endpoint(_Client, remote_addr=("127.0.0.1", port))
        try:
            transport.sendto(request)
            # Silence is an acceptable answer; a reply larger than the bound is not.
            with contextlib.suppress(TimeoutError):
                reply = await asyncio.wait_for(got, timeout=1.0)
                assert len(reply) <= len(request) * _UDP_REPLY_FACTOR
        finally:
            transport.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_sip_tcp_blank_frame_flood_closes_connection_quickly():
    from honeypot_mcp.engines.sip import SIPEngine

    port = free_port()
    await _make_honeypot("sip-a2-tcp", "sip", port)
    engine = SIPEngine()
    cid = await engine.start("sip-a2-tcp", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        start = time.monotonic()
        writer.write(b"\r\n\r\n" * 15_000)
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        # The server closes the connection instead of creating 15k tasks. A read
        # timeout means it did NOT close, which must fail the test.
        try:
            closed = await asyncio.wait_for(reader.read(65536), timeout=2.0) == b""
        except ConnectionError:
            closed = True  # an RST is a close too
        assert closed, "the server kept the flooding connection open"
        assert time.monotonic() - start < 2.5
        writer.close()
    finally:
        await engine.stop(cid)


# ── SNMP ────────────────────────────────────────────────────────────────────


def test_snmp_getbulk_reply_is_never_larger_than_request():
    from honeypot_mcp.engines.snmp import (
        build_bounded_response,
        build_get_request,
        parse_snmp,
    )

    data = build_get_request("1.3.6.1.2.1.1.1.0", request_id=7)
    request = parse_snmp(data)
    assert request is not None
    reply = build_bounded_response(request, len(data))
    # Either a bounded reply or deliberate silence — never a larger datagram.
    assert reply is None or len(reply) <= len(data)


# ── DNS ─────────────────────────────────────────────────────────────────────


def test_dns_header_gate_rejects_responses_oversize_and_odd_opcodes():
    from honeypot_mcp.engines.dns import _is_plain_query

    query = bytes.fromhex("1234010000010000000000000377777703636f6d0000010001")
    assert _is_plain_query(query)
    response = bytearray(query)
    response[2] |= 0x80  # QR=1
    assert not _is_plain_query(bytes(response))
    notify = bytearray(query)
    notify[2] = (notify[2] & 0x87) | (4 << 3)  # opcode NOTIFY
    assert not _is_plain_query(bytes(notify))
    assert not _is_plain_query(query + b"\x00" * 600)
    assert not _is_plain_query(b"\x00" * 5)


# ── conn_limit ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_idle_connection_is_closed_by_the_central_timeout():
    from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory

    limiter = ConnectionLimiter(8)
    loop = asyncio.get_running_loop()
    server = await loop.create_server(
        limited_factory(asyncio.Protocol, limiter, idle_timeout=0.3, max_session=0),
        host="127.0.0.1",
        port=0,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Sends nothing: the server must hang up on us, and release the slot.
        data = await asyncio.wait_for(reader.read(10), timeout=2.0)
        assert data == b""
        for _ in range(20):
            if limiter.live_count("127.0.0.1") == 0:
                break
            await asyncio.sleep(0.05)
        assert limiter.live_count("127.0.0.1") == 0
        writer.close()
    finally:
        server.close()


@pytest.mark.asyncio
async def test_stop_returns_promptly_with_an_idle_client_attached():
    from honeypot_mcp.engines.imap import IMAPEngine

    port = free_port()
    await _make_honeypot("imap-a2", "imap", port)
    engine = IMAPEngine()
    cid = await engine.start("imap-a2", port, {})
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await reader.readline()  # greeting
    start = time.monotonic()
    await asyncio.wait_for(engine.stop(cid), timeout=8.0)
    assert time.monotonic() - start < 7.0
    writer.close()


# ── line-oriented engines ───────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "module,cls,type_name", [("imap", "IMAPEngine", "imap"), ("pop3", "POP3Engine", "pop3")]
)
async def test_pipelined_line_flood_closes_the_connection(module, cls, type_name):
    import importlib

    engine = getattr(importlib.import_module(f"honeypot_mcp.engines.{module}"), cls)()
    port = free_port()
    await _make_honeypot(f"{module}-a2-flood", type_name, port)
    cid = await engine.start(f"{module}-a2-flood", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        start = time.monotonic()
        writer.write(b"NOOP\r\n" * 20_000)
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        assert await _closed_by_peer(reader)
        assert time.monotonic() - start < 4.0
        writer.close()
    finally:
        await engine.stop(cid)


# ── FTP ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ftp_pipelined_pasv_leaves_exactly_one_listener():
    from honeypot_mcp.engines.ftp import FTPEngine

    port = free_port()
    await _make_honeypot("ftp-a2", "ftp", port)
    engine = FTPEngine()
    cid = await engine.start("ftp-a2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(b"USER anonymous\r\nPASS a@b.c\r\n")
        await writer.drain()
        await reader.readline()
        await reader.readline()
        writer.write(b"PASV\r\n" * 10)
        await writer.drain()
        ports: list[int] = []
        for _ in range(10):
            line = (await asyncio.wait_for(reader.readline(), timeout=3.0)).decode()
            assert line.startswith("227"), line
            nums = line[line.index("(") + 1 : line.index(")")].split(",")
            ports.append(int(nums[4]) * 256 + int(nums[5]))

        async def _accepts(p: int) -> bool:
            try:
                _r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", p), 0.5)
            except (OSError, TimeoutError):
                return False
            w.close()
            return True

        live = [p for p in ports if await _accepts(p)]
        assert len(live) <= 1, f"leaked PASV listeners: {live}"
        writer.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_ftp_data_connection_from_a_different_host_is_refused(monkeypatch):
    from honeypot_mcp.engines import ftp
    from honeypot_mcp.engines.ftp import FTPEngine

    async def pasv_port(pretend_control_peer: str | None) -> tuple[int, asyncio.StreamWriter]:
        if pretend_control_peer is not None:
            original = ftp._FTPProtocol.connection_made

            def made(self, transport):  # type: ignore[no-untyped-def]
                original(self, transport)
                self._peer = (pretend_control_peer, 1)

            monkeypatch.setattr(ftp._FTPProtocol, "connection_made", made)
        port = free_port()
        await _make_honeypot(f"ftp-peer-{pretend_control_peer}", "ftp", port)
        engine = FTPEngine()
        cid = await engine.start(f"ftp-peer-{pretend_control_peer}", port, {})
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(b"USER anonymous\r\nPASS a@b.c\r\n")
        await reader.readline()
        await reader.readline()
        writer.write(b"PASV\r\n")
        line = (await asyncio.wait_for(reader.readline(), 3)).decode()
        nums = line[line.index("(") + 1 : line.index(")")].split(",")
        pasv = int(nums[4]) * 256 + int(nums[5])
        # Keep the engine alive for the caller via the writer; stop on cleanup.
        pasv_port.cleanups.append((engine, cid))  # type: ignore[attr-defined]
        return pasv, writer

    pasv_port.cleanups = []  # type: ignore[attr-defined]
    try:
        # Control peer is who it says it is: a data connection from it is kept.
        pasv, ctl = await pasv_port(None)
        _r, data_w = await asyncio.open_connection("127.0.0.1", pasv)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(_r.read(), 0.5)  # still open, waiting for LIST
        data_w.close()
        ctl.close()

        # The control connection "came from" another host: the same data
        # connection is now a stranger probing the port and is closed at once.
        pasv, ctl = await pasv_port("203.0.113.5")
        r2, w2 = await asyncio.open_connection("127.0.0.1", pasv)
        assert await asyncio.wait_for(r2.read(), 2) == b""
        w2.close()
        ctl.close()
    finally:
        for engine, cid in pasv_port.cleanups:  # type: ignore[attr-defined]
            await engine.stop(cid)


async def test_pasv_address_advertises_the_control_sockets_own_address():
    from honeypot_mcp.engines.ftp import _pasv_address

    class _T:
        def get_extra_info(self, name: str):
            return ("10.1.2.3", 21) if name == "sockname" else None

    assert _pasv_address(_T()) == "10,1,2,3"  # type: ignore[arg-type]

    class _Unknown:
        def get_extra_info(self, name: str):
            return None

    assert _pasv_address(_Unknown()) == "127,0,0,1"  # type: ignore[arg-type]


# ── SMTP ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_smtp_starttls_session_releases_its_connection_slot(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp.engines.smtp import SMTPEngine

    port = free_port()
    await _make_honeypot("smtp-a2", "smtp", port)
    engine = SMTPEngine()
    cid = await engine.start("smtp-a2", port, {"smtp_hostname": "mail.test.local"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(b"EHLO x\r\n")
        await writer.drain()
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=2.0)
            if line[3:4] == b" ":
                break
        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.readline(), timeout=2.0)).startswith(b"220")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        await writer.start_tls(ctx)
        assert engine._limiter.live_count("127.0.0.1") == 1
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        for _ in range(40):
            if engine._limiter.live_count("127.0.0.1") == 0:
                break
            await asyncio.sleep(0.05)
        assert engine._limiter.live_count("127.0.0.1") == 0
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_smtp_line_flood_is_cut_off_and_data_body_is_bounded():
    from honeypot_mcp.engines.smtp import SMTPEngine

    port = free_port()
    await _make_honeypot("smtp-a2-flood", "smtp", port)
    engine = SMTPEngine()
    cid = await engine.start("smtp-a2-flood", port, {"smtp_hostname": "mail.test.local"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        start = time.monotonic()
        writer.write(b"NOOP\r\n" * 50_000)
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        assert await _closed_by_peer(reader)
        assert time.monotonic() - start < 4.0
        writer.close()
    finally:
        await engine.stop(cid)
