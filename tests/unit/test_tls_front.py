"""`TLSFrontSite`: what a TLS port says when the handshake never starts.

A stock `web.TCPSite(ssl_context=...)` closes the socket without a byte when the first record is
not an acceptable ClientHello. Real Go / OpenSSL servers send a `protocol_version` alert for an
old-versioned hello and (Go's net/http) a one-line 400 for plaintext HTTP; `nmap -sV` identifies a
port as `ssl/http` from exactly those answers. These tests drive the listener with raw sockets and
with Python's own TLS client, which we did not write and which does not share our expectations.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import ssl
import struct
import time
from collections.abc import AsyncIterator

import pytest
from aiohttp import web

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.engines import _tasks  # noqa: E402
from honeypot_mcp.engines.tls import build_server_ssl_context  # noqa: E402
from honeypot_mcp.engines.tls_front import (  # noqa: E402
    GO_PLAINTEXT_HTTP_REPLY,
    PROTOCOL_VERSION_ALERT,
    TLSFrontSite,
    _Kind,
    classify_first_bytes,
    start_tls_site,
)

pytestmark = pytest.mark.asyncio

GO_400 = b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _client_hello(version: int, record_version: int | None = None) -> bytes:
    """A syntactically valid ClientHello record with the given legacy_version."""
    body = (
        struct.pack(">H", version)
        + os.urandom(32)
        + b"\x00"  # session id
        + struct.pack(">H", 2)
        + b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01\x00"  # null compression
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return (
        b"\x16"
        + struct.pack(">H", record_version if record_version is not None else version)
        + struct.pack(">H", len(handshake))
        + handshake
    )


async def _read_to_close(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """Everything the server sends until it closes; a reset ends the read like a FIN does."""
    out = b""
    try:
        async with asyncio.timeout(timeout):
            while chunk := await reader.read(4096):
                out += chunk
    except ConnectionError:
        pass
    return out


async def _wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        if asyncio.get_running_loop().time() > deadline:
            return False
        await asyncio.sleep(0.02)
    return True


class _Front:
    def __init__(self, runner: web.AppRunner, site: TLSFrontSite, ctx: ssl.SSLContext) -> None:
        self.runner, self.site, self.ctx = runner, site, ctx
        self.port = site.port
        self.peers: list[tuple[str, int]] = []


@contextlib.asynccontextmanager
async def _front(tmp_name: str, **options) -> AsyncIterator[_Front]:
    peers: list[tuple[str, int]] = []

    async def handler(request: web.Request) -> web.Response:
        peers.append(request.transport.get_extra_info("peername")[:2])
        return web.Response(text=f"{request.remote}")

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    ctx = build_server_ssl_context(tmp_name)
    site = await start_tls_site(runner, "127.0.0.1", 0, ctx, **options)
    assert isinstance(site, TLSFrontSite)
    front = _Front(runner, site, ctx)
    front.peers = peers
    try:
        yield front
    finally:
        await runner.cleanup()


def _client_ctx(*, max_version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if max_version is not None:
        ctx.maximum_version = max_version
    return ctx


# ── what a real server answers ──────────────────────────────────────────────────────────────


async def test_reply_constants_match_what_go_and_nmap_expect():
    assert GO_PLAINTEXT_HTTP_REPLY == GO_400
    # nmap-service-probes: `match ssl m|^\x15\x03[\x00-\x04]\0\x02\x02[F\x28]|`
    assert PROTOCOL_VERSION_ALERT[:2] == b"\x15\x03"
    assert PROTOCOL_VERSION_ALERT[2] <= 4
    assert PROTOCOL_VERSION_ALERT[3:6] == b"\x00\x02\x02"
    assert PROTOCOL_VERSION_ALERT[6] in (0x46, 0x28)


@pytest.mark.parametrize("request_bytes", [b"GET / HTTP/1.0\r\n\r\n", b"POST /x HTTP/1.1\r\n\r\n"])
async def test_plaintext_http_gets_go_400_and_a_close(request_bytes):
    async with _front("front-http") as f:
        reader, writer = await asyncio.open_connection("127.0.0.1", f.port)
        writer.write(request_bytes)
        await writer.drain()
        assert await _read_to_close(reader) == GO_400
        writer.close()
    assert f.peers == []


@pytest.mark.parametrize(
    ("version", "record_version"),
    [(0x0300, 0x0300), (0x0301, 0x0301), (0x0302, 0x0301)],
    ids=["sslv3-like-nmap-SSLSessionReq", "tls1.0", "tls1.1"],
)
async def test_pre_tls12_client_hello_gets_exactly_the_protocol_version_alert(
    version, record_version
):
    async with _front("front-old") as f:
        reader, writer = await asyncio.open_connection("127.0.0.1", f.port)
        writer.write(_client_hello(version, record_version))
        await writer.drain()
        assert (
            await _read_to_close(reader)
            == PROTOCOL_VERSION_ALERT
            == b"\x15\x03\x01\x00\x02\x02\x46"
        )
        writer.close()


@pytest.mark.parametrize("max_version", [ssl.TLSVersion.TLSv1_2, None], ids=["tls1.2", "tls1.3"])
async def test_tls12_and_tls13_clients_complete_and_the_handler_sees_the_real_peer(max_version):
    async with _front("front-tls") as f:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", f.port, ssl=_client_ctx(max_version=max_version)
        )
        tls = writer.get_extra_info("ssl_object")
        assert tls.version() == ("TLSv1.2" if max_version else "TLSv1.3")
        client_addr = writer.get_extra_info("sockname")[:2]
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        body = await _read_to_close(reader)
        writer.close()
    assert b"200 OK" in body.split(b"\r\n", 1)[0]
    # The peername is the connecting socket, not the listener or a proxy hop: same ip *and*
    # the client's ephemeral port.
    assert f.peers == [client_addr]
    assert body.endswith(client_addr[0].encode())


async def test_openssl_tls_alert_survives_the_front_for_a_real_tls10_client():
    """A real TLS-1.0-only client (ssl module, not our hand-built bytes) is refused with an alert
    rather than a bare close: the client's error must be a protocol error, not an EOF."""
    async with _front("front-real-old") as f:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ssl.SSLError, ValueError):
            pytest.skip("this OpenSSL build cannot offer TLS 1.0")
        with pytest.raises(ssl.SSLError) as exc:
            await asyncio.open_connection("127.0.0.1", f.port, ssl=ctx)
        assert "PROTOCOL_VERSION" in str(exc.value).upper() or "ALERT" in str(exc.value).upper()


# ── hostile peers ───────────────────────────────────────────────────────────────────────────


async def test_silent_and_stalled_connections_are_closed_by_the_deadline_and_leak_nothing():
    baseline = _tasks.live_count()
    async with _front("front-stall", sniff_timeout=0.3) as f:
        silent_r, silent_w = await asyncio.open_connection("127.0.0.1", f.port)
        one_r, one_w = await asyncio.open_connection("127.0.0.1", f.port)
        one_w.write(b"\x16")  # a TLS record's first byte, then nothing
        await one_w.drain()
        drip_r, drip_w = await asyncio.open_connection("127.0.0.1", f.port)
        drip_w.write(b"GE")  # a prefix of GET, then nothing

        started = asyncio.get_running_loop().time()
        assert await _read_to_close(silent_r, 3) == b""
        assert await _read_to_close(one_r, 3) == b""
        assert await _read_to_close(drip_r, 3) == b""
        assert asyncio.get_running_loop().time() - started < 2.0, "deadline not honoured"
        for w in (silent_w, one_w, drip_w):
            w.close()

        assert await _wait_until(lambda: f.site.pending == 0)
        assert await _wait_until(lambda: _tasks.live_count() <= baseline + 1)  # the accept task

        # The port still serves a normal client afterwards.
        reader, writer = await asyncio.open_connection("127.0.0.1", f.port, ssl=_client_ctx())
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        assert b" 200 " in await _read_to_close(reader)
        writer.close()


async def test_record_header_declaring_a_huge_length_is_closed_without_waiting():
    async with _front("front-huge", sniff_timeout=30.0) as f:
        reader, writer = await asyncio.open_connection("127.0.0.1", f.port)
        # handshake record, TLS 1.2, length 0xFFFF, then a ClientHello type byte
        writer.write(b"\x16\x03\x03\xff\xff\x01")
        await writer.drain()
        started = asyncio.get_running_loop().time()
        assert await _read_to_close(reader, 3) == b""
        assert asyncio.get_running_loop().time() - started < 1.0, "waited out the 30s deadline"
        writer.close()
        assert await _wait_until(lambda: f.site.pending == 0)


async def test_one_source_cannot_exhaust_the_unclassified_connection_budget():
    async with _front("front-cap", sniff_timeout=30.0, max_pending_per_ip=2) as f:
        held = [await asyncio.open_connection("127.0.0.1", f.port) for _ in range(2)]
        assert await _wait_until(lambda: f.site.pending == 2)
        extra_r, extra_w = await asyncio.open_connection("127.0.0.1", f.port)
        assert await _read_to_close(extra_r, 3) == b"", "third connection from the IP was admitted"
        assert f.site.pending == 2
        extra_w.close()
        for _, w in held:
            w.close()
        assert await _wait_until(lambda: f.site.pending == 0)
        # Slots are returned: a fresh connection is admitted again.
        reader, writer = await asyncio.open_connection("127.0.0.1", f.port, ssl=_client_ctx())
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        assert b" 200 " in await _read_to_close(reader)
        writer.close()


# ── lifecycle ───────────────────────────────────────────────────────────────────────────────


async def test_runner_cleanup_releases_the_port_and_cancels_pending_connections():
    baseline = _tasks.live_count()
    port = _free_port()
    app = web.Application()
    runner = web.AppRunner(app)
    await runner.setup()
    ctx = build_server_ssl_context("front-stop")
    await start_tls_site(runner, "127.0.0.1", port, ctx, sniff_timeout=30.0)

    reader, writer = await asyncio.open_connection("127.0.0.1", port)  # held un-sniffed
    await asyncio.sleep(0.1)
    await runner.cleanup()

    assert await _read_to_close(reader, 3) == b"", "pending connection survived cleanup"
    writer.close()
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection("127.0.0.1", port)
    rebound = socket.socket()
    # SO_REUSEADDR tolerates TIME_WAIT from our own closed client sockets but still fails
    # (EADDRINUSE) while any socket is listening on the port.
    rebound.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rebound.bind(("127.0.0.1", port))
        rebound.listen(1)
    finally:
        rebound.close()
    assert await _wait_until(lambda: _tasks.live_count() <= baseline)


async def test_a_bind_failure_raises_and_leaves_no_site_registered():
    holder = socket.socket()
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    port = holder.getsockname()[1]
    runner = web.AppRunner(web.Application())
    await runner.setup()
    try:
        with pytest.raises(OSError):
            await start_tls_site(runner, "127.0.0.1", port, build_server_ssl_context("front-bind"))
        assert list(runner.sites) == []
    finally:
        holder.close()
        await runner.cleanup()


# ── classifier boundaries ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", _Kind.NEED_MORE),
        (b"\x16", _Kind.NEED_MORE),
        (b"\x16\x03\x01\x00\xc8\x01\x00\x00", _Kind.NEED_MORE),
        (b"GE", _Kind.NEED_MORE),
        (b"GET ", _Kind.HTTP),
        (b"OPTIONS * ", _Kind.HTTP),
        (b"GETX", _Kind.OTHER),
        (b"SSH-2.0-x", _Kind.OTHER),
        (b"\x80\x2e\x01\x03\x01", _Kind.OTHER),  # SSLv2-style hello
        (b"\x16\x04\x01\x00\xc8\x01", _Kind.OTHER),  # major version 4
        (b"\x16\x03\x03\x00\xc8\x02", _Kind.OTHER),  # ServerHello where a ClientHello belongs
        (b"\x16\x03\x03\x00\x00\x01", _Kind.OTHER),  # zero-length record
        (b"\x16\x03\x03\x40\x01\x01", _Kind.OTHER),  # 16385: over the record limit
        (b"\x16\x03\x03\x40\x00\x01\x00\x01\x00\x03\x03", _Kind.TLS),  # 16384 is allowed
        (b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x02", _Kind.OLD_TLS),
        (b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03", _Kind.TLS),
        (b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x02\x00", _Kind.OTHER),
    ],
)
async def test_classify_first_bytes(data, expected):
    assert classify_first_bytes(data) is expected


# ── wired into the HTTP engine ──────────────────────────────────────────────────────────────


@pytest.fixture
async def _db():
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


async def _plain_http(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(request)
    await writer.drain()
    try:
        return await _read_to_close(reader)
    finally:
        writer.close()


async def test_https_honeypot_serves_the_persona_over_tls_and_frees_the_port_on_stop(_db):
    from honeypot_mcp.engines.http import HTTPEngine

    port = _free_port()
    engine = HTTPEngine()
    cid = await engine.start("front-engine", port, {"tls": True, "persona": "apache_ubuntu"})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=_client_ctx())
        writer.write(b"GET /robots.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await writer.drain()
        reply = await _read_to_close(reader)
        writer.close()
        assert reply.startswith(b"HTTP/1.1 200")
    finally:
        await engine.stop(cid)
    with pytest.raises(ConnectionRefusedError):
        await asyncio.open_connection("127.0.0.1", port)


async def test_apache_persona_explains_plain_http_on_its_tls_port_the_way_apache_does(_db):
    """The Go one-liner on an Apache port is a tell: Apache 2.4 answers with a page naming the
    host and port, with Content-Length matching the body and a current Date."""
    from email.utils import parsedate_to_datetime

    from honeypot_mcp.engines.http import HTTPEngine

    port = _free_port()
    engine = HTTPEngine()
    cid = await engine.start("front-apache", port, {"tls": True, "persona": "apache_ubuntu"})
    try:
        raw = await _plain_http(port, b"GET / HTTP/1.1\r\nHost: shop.example.com:8443\r\n\r\n")
    finally:
        await engine.stop(cid)
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    headers = dict(line.split(": ", 1) for line in lines[1:])
    assert lines[0] == "HTTP/1.1 400 Bad Request"
    assert list(headers) == ["Date", "Server", "Content-Length", "Connection", "Content-Type"]
    assert headers["Server"] == "Apache/2.4.41 (Ubuntu)"
    assert int(headers["Content-Length"]) == len(body)
    age = abs(parsedate_to_datetime(headers["Date"]).timestamp() - time.time())
    assert age < 5, "a static Date header is itself a tell"
    assert b"You're speaking plain HTTP to an SSL-enabled server port." in body
    assert f"Apache/2.4.41 (Ubuntu) Server at shop.example.com Port {port}".encode() in body


async def test_nginx_persona_sends_nginxs_own_400_for_plain_http_on_tls(_db):
    from honeypot_mcp.engines.http import HTTPEngine

    port = _free_port()
    engine = HTTPEngine()
    cid = await engine.start("front-nginx", port, {"tls": True, "persona": "nginx_stable"})
    try:
        raw = await _plain_http(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    finally:
        await engine.stop(cid)
    head, _, body = raw.partition(b"\r\n\r\n")
    headers = dict(line.split(": ", 1) for line in head.decode().split("\r\n")[1:])
    assert head.startswith(b"HTTP/1.1 400 Bad Request")
    assert headers["Server"] == "nginx/1.18.0"
    assert int(headers["Content-Length"]) == len(body)
    assert b"400 The plain HTTP request was sent to HTTPS port" in body
    assert body.endswith(b"<hr><center>nginx/1.18.0</center>\r\n</body>\r\n</html>\r\n")


async def test_iis_persona_sends_nothing_to_plain_http_on_a_tls_binding(_db):
    """HTTP.sys drops plaintext on a TLS binding without writing a byte."""
    from honeypot_mcp.engines.http import HTTPEngine

    port = _free_port()
    engine = HTTPEngine()
    cid = await engine.start("front-iis", port, {"tls": True, "persona": "iis_windows"})
    try:
        assert await _plain_http(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == b""
    finally:
        await engine.stop(cid)


async def test_plaintext_reply_may_be_a_callable_and_none_closes_silently():
    async with _front("callable", plaintext_reply=lambda host: f"hello {host}".encode()) as front:
        assert await _plain_http(front.port, b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n") == b"hello a.b"
    async with _front("none", plaintext_reply=None) as front:
        assert await _plain_http(front.port, b"GET / HTTP/1.1\r\nHost: a.b\r\n\r\n") == b""
