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
async def test_stor_captures_uploaded_webshell(ftp_server):
    """A STOR upload over PASV is now accepted and captured — the dropped
    artefact (here a PHP webshell) lands as a CRITICAL ftp_file_upload with the
    payload classified and hashed."""
    import asyncio as _asyncio
    import re as _re

    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = ftp_server
    buf = event_buffer.get_buffer()
    await buf.start()
    payload = b"<?php system($_GET['c']); ?>\n"
    try:
        reader, writer = await _asyncio.open_connection("127.0.0.1", port)
        try:
            await _read_line(reader)  # banner
            writer.write(b"USER anonymous\r\nPASS x@y.com\r\n")
            await writer.drain()
            await _read_line(reader)  # 331
            await _read_line(reader)  # 230

            # PASV to open the data channel.
            writer.write(b"PASV\r\n")
            await writer.drain()
            pasv = await _read_line(reader)
            m = _re.search(rb"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv)
            assert m, pasv
            data_port = int(m.group(5)) * 256 + int(m.group(6))

            # STOR, connect the data socket, send the webshell.
            writer.write(b"STOR shell.php\r\n")
            await writer.drain()
            resp150 = await _read_line(reader)
            assert resp150.startswith(b"150"), resp150
            dr, dw = await _asyncio.open_connection("127.0.0.1", data_port)
            dw.write(payload)
            await dw.drain()
            dw.close()
            with contextlib.suppress(Exception):
                await dw.wait_closed()
            resp226 = await _read_line(reader)
            assert resp226.startswith(b"226"), resp226
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await _asyncio.sleep(1.2)  # let the flusher drain
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "ftp_file_upload"))
        alerts = list(result.scalars().all())
    assert len(alerts) == 1
    p = alerts[0].payload
    assert p["filename"] == "shell.php"
    assert p["size_bytes"] == len(payload)
    assert p["payload_kind"] == "php_webshell"
    assert alerts[0].severity.value == "critical"
    assert len(p["sha256"]) == 64


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


@pytest.mark.asyncio
async def test_list_serves_fake_directory_over_pasv(ftp_server):
    """PASV + LIST must actually open a real data socket, accept the
    client's data connection, and serve a ProFTPD-flavoured `ls -l`. The
    previous engine returned `425 Use PORT or PASV first.` regardless of
    PASV state, which a single LIST probe confirmed as a honeypot tell.

    End-to-end:
      USER anonymous → PASS x → PASV → connect to advertised port → LIST
      → expect 150 (data starting) → read bytes → expect 226 (done).
    """
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
        pasv_resp = await _read_line(reader)
        m = re.search(rb"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_resp)
        assert m, f"PASV response not parseable: {pasv_resp!r}"
        p1, p2 = int(m.group(5)), int(m.group(6))
        data_port = p1 * 256 + p2

        # Connect the data channel BEFORE issuing LIST — real ftp clients
        # establish the data connection then send LIST on the control channel.
        data_reader, data_writer = await asyncio.open_connection("127.0.0.1", data_port)

        writer.write(b"LIST\r\n")
        await writer.drain()

        # 150 Opening data connection
        opening = await _read_line(reader)
        assert opening.startswith(b"150"), f"expected 150 marker, got {opening!r}"

        # Read the directory listing off the data channel until close.
        listing = await asyncio.wait_for(data_reader.read(), timeout=2.0)
        data_writer.close()
        with contextlib.suppress(Exception):
            await data_writer.wait_closed()

        # Realistic ls -l output: at least one entry, file mode column, and
        # the names baked into _FAKE_LISTING.
        assert b"-rw-r--r--" in listing or b"drwxr-xr-x" in listing
        assert b"backup.tar.gz" in listing or b"passwords.txt" in listing

        # 226 Transfer complete on the control channel.
        done = await _read_line(reader)
        assert done.startswith(b"226"), f"expected 226 transfer-complete, got {done!r}"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_list_without_pasv_returns_425(ftp_server):
    """A LIST issued without a preceding PASV must still return 425 — the
    new fake-listing behaviour kicks in only when PASV established a data
    listener. This is the regression check for the old fallback path."""
    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # banner
        writer.write(b"USER anonymous\r\nPASS x@y.com\r\nLIST\r\n")
        await writer.drain()
        await _read_line(reader)  # 331
        await _read_line(reader)  # 230
        resp = await _read_line(reader)
        assert resp.startswith(b"425")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_data_received_caps_unbounded_buffer_growth(ftp_server):
    """A client that never sends a bare CRLF on the control channel must not
    be able to grow `self._buf` without bound — one connection, zero further
    syscalls, a memory-exhaustion DoS against the whole process. The control
    channel has no cap of its own (unlike the upload path's
    `_MAX_UPLOAD_BYTES`), so the engine should refuse and close once the
    buffer passes a sane line-length ceiling."""
    from honeypot_mcp.engines.ftp import _MAX_LINE_BYTES

    port = ftp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_line(reader)  # banner
        writer.write(b"A" * (_MAX_LINE_BYTES + 1))  # no CRLF, ever
        await writer.drain()
        reply = await _read_line(reader)
        assert reply.startswith(b"500"), reply
        eof = await asyncio.wait_for(reader.read(1), timeout=2.0)
        assert eof == b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
