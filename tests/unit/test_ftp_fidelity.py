"""FTP engine fidelity checks.

Verifies the ProFTPD-flavoured anonymous-login flow, FEAT response, PASV/PORT
handling, and post-login verb support added to defeat first-probe
fingerprinting.
"""

import asyncio
import contextlib
import os
import re
import socket

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
async def ftp_server():
    from honeypot_mcp.engines.ftp import FTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="ftp-fidelity-test", type=HoneypotType.FTP, port=port)
        session.add(hp)
        await session.flush()

    engine = FTPEngine()
    container_id = await engine.start("ftp-fidelity-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(container_id)


async def _read_line(reader: asyncio.StreamReader) -> bytes:
    return await asyncio.wait_for(reader.readline(), timeout=2.0)


async def _drain_multiline(reader: asyncio.StreamReader, code: bytes) -> list[bytes]:
    """Read FTP multi-line response until a line starting with `<code> ` (space
    after the code, signalling end-of-response)."""
    out = []
    while True:
        line = await _read_line(reader)
        out.append(line)
        if line.startswith(code + b" "):
            break
    return out


@pytest.mark.asyncio
async def test_anonymous_login_flow(ftp_server):
    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # 220 banner

        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp = await _read_line(reader)
        assert resp.startswith(b"331")

        writer.write(b"PASS user@example.com\r\n")
        await writer.drain()
        resp = await _read_line(reader)
        assert resp.startswith(b"230")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_pasv_returns_parseable_tuple(ftp_server):
    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # banner
        writer.write(b"USER anonymous\r\nPASS x@y.com\r\n")
        await writer.drain()
        await _read_line(reader)  # 331
        await _read_line(reader)  # 230

        writer.write(b"PASV\r\n")
        await writer.drain()
        resp = await _read_line(reader)
        # `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).`
        m = re.search(rb"227 Entering Passive Mode \((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", resp)
        assert m is not None, f"PASV response not parseable: {resp!r}"
        h1, h2, h3, h4, p1, p2 = (int(x) for x in m.groups())
        # Host should be 127.0.0.1.
        assert (h1, h2, h3, h4) == (127, 0, 0, 1)
        # Port should be >= 1024 (we pick a high port).
        port_val = p1 * 256 + p2
        assert port_val >= 1024
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_feat_lists_realistic_features(ftp_server):
    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # banner
        writer.write(b"FEAT\r\n")
        await writer.drain()
        lines = await _drain_multiline(reader, b"211")
        body = b"".join(lines)
        for feat in (b"PASV", b"EPSV", b"SIZE", b"MDTM", b"REST STREAM", b"UTF8"):
            assert feat in body, f"FEAT response missing {feat!r}: {body!r}"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_stor_after_anonymous_login_blocked(ftp_server):
    """Anonymous shouldn't be writing. 550 + an ftp_file_op_blocked event."""
    import asyncio as _asyncio

    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = ftp_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await _asyncio.open_connection("127.0.0.1", port)
        try:
            await _read_line(reader)  # banner
            writer.write(b"USER anonymous\r\nPASS x@y.com\r\n")
            await writer.drain()
            await _read_line(reader)  # 331
            await _read_line(reader)  # 230

            writer.write(b"STOR /etc/passwd\r\n")
            await writer.drain()
            resp = await _read_line(reader)
            assert resp.startswith(b"550")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await _asyncio.sleep(1.0)  # let the flusher drain
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "ftp_file_op_blocked")
        )
        alerts = list(result.scalars().all())
    assert len(alerts) >= 1
    assert alerts[0].payload.get("verb") == "STOR"


@pytest.mark.asyncio
async def test_pwd_requires_auth(ftp_server):
    """Unauthenticated PWD should get 530."""
    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # banner
        writer.write(b"PWD\r\n")
        await writer.drain()
        resp = await _read_line(reader)
        assert resp.startswith(b"530")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
