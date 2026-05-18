"""SMTP STARTTLS upgrade test.

Verifies the engine actually completes a TLS handshake when the client issues
STARTTLS, rather than the previous behaviour of announcing TLS and dropping
on the ClientHello. A real Postfix completes the handshake; the previous
drop was itself a fingerprint.

We use `StreamWriter.start_tls()` (Python 3.11+) on the client side because
we require Python 3.11+ for the project.
"""

import asyncio
import contextlib
import os
import socket
import ssl

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
    # The TLS-upgrade path spawns a background task that calls submit_event()
    # after the handshake completes. If we close the DB before that task lands
    # its `smtp_starttls_handshake` event, credential_match queries a closed
    # connection. Brief settle window keeps the test deterministic without
    # complicating engine.stop() with task-awaiting logic that only matters
    # under in-process test conditions.
    await asyncio.sleep(0.3)
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
async def smtp_server(tmp_path, monkeypatch):
    """SMTP honeypot in a temp dir so the self-signed cert lives under
    `<tmpdir>/tls/...` and gets cleaned up at the end of the test."""
    monkeypatch.chdir(tmp_path)

    from honeypot_mcp.engines.smtp import SMTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="smtp-starttls-test", type=HoneypotType.SMTP, port=port)
        session.add(hp)
        await session.flush()

    engine = SMTPEngine()
    cid = await engine.start("smtp-starttls-test", port, {"smtp_hostname": "mail.test.local"})
    try:
        yield port
    finally:
        await engine.stop(cid)


async def _read_until_terminator(reader: asyncio.StreamReader) -> str:
    """Drain a multi-line SMTP response until a `<code> ` (space) terminator."""
    out: list[str] = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        if not line:
            break
        decoded = line.decode("utf-8", errors="replace")
        out.append(decoded)
        if len(decoded) >= 4 and decoded[3] == " ":
            break
    return "".join(out)


@pytest.mark.asyncio
async def test_starttls_handshake_completes(smtp_server):
    """End-to-end: EHLO → STARTTLS → real TLS handshake.

    A successful `writer.start_tls(ctx)` return is the proof point — Python's
    StreamWriter.start_tls() awaits the full handshake and raises on failure.
    Post-TLS application dialogue is not asserted here because the SSL
    shutdown sequence after closing a self-signed-cert connection can surface
    benign `WRONG_VERSION_NUMBER` warnings during asyncio teardown that
    aren't catchable via the normal suppress patterns — that's an asyncio
    SSL transport quirk, not a STARTTLS correctness issue."""
    port = smtp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert banner.startswith(b"220 mail.test.local")

        writer.write(b"EHLO probe.test\r\n")
        await writer.drain()
        ehlo_resp = await _read_until_terminator(reader)
        assert "STARTTLS" in ehlo_resp

        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        starttls_resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert starttls_resp.startswith(b"220")

        # Client-side TLS upgrade. The cert is self-signed — disable verification.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # If this returns without raising, the handshake completed on both
        # sides — that's the whole assertion of this test.
        await writer.start_tls(ctx)
    finally:
        with contextlib.suppress(Exception):
            writer.close()


@pytest.mark.asyncio
async def test_starttls_allows_post_tls_ehlo(smtp_server):
    """After STARTTLS completes, the engine must keep speaking SMTP over the
    upgraded TLS transport. Real Postfix requires a fresh EHLO per RFC 3207
    and serves the same extension list; closing the connection right after
    the handshake is itself a fingerprint.

    The previous test (`test_starttls_handshake_completes`) only asserts the
    handshake completes — this one drives the protocol forward over TLS so
    we catch regressions where the engine drops the connection or fails to
    reattach the protocol on the new transport.
    """
    port = smtp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert banner.startswith(b"220 mail.test.local")

        writer.write(b"EHLO probe.test\r\n")
        await writer.drain()
        await _read_until_terminator(reader)

        writer.write(b"STARTTLS\r\n")
        await writer.drain()
        starttls_resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert starttls_resp.startswith(b"220")

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        await writer.start_tls(ctx)
        # writer.start_tls() returns once the CLIENT-side handshake completes;
        # the server may still be assigning the new transport on its end. A
        # short settle prevents a race where our EHLO write hits the wire
        # before the server's post-handshake protocol state is bound.
        await asyncio.sleep(0.2)

        # Fresh EHLO over the upgraded TLS connection — this is the proof
        # point. If the engine closed after the handshake (the old broken
        # behaviour), this write fails or the read returns empty.
        writer.write(b"EHLO probe-over-tls.test\r\n")
        await writer.drain()
        post_tls_resp = await _read_until_terminator(reader)
        # Multi-line 250- ... 250 <last>, terminator on the last line.
        assert "250" in post_tls_resp, f"no 250 after post-TLS EHLO: {post_tls_resp!r}"
        # Should advertise the same extensions as plaintext EHLO did.
        assert "PIPELINING" in post_tls_resp
        assert "AUTH" in post_tls_resp

        # And the engine should accept QUIT over TLS too — verifies the
        # dispatcher is fully functional.
        writer.write(b"QUIT\r\n")
        await writer.drain()
        bye = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert bye.startswith(b"221")
    finally:
        with contextlib.suppress(Exception):
            writer.close()


@pytest.mark.asyncio
async def test_starttls_handshake_logged_as_event(smtp_server):
    """A successful TLS upgrade should emit an `smtp_starttls_handshake`
    event in the alert stream — useful for distinguishing "scanner that did
    TLS" from "scanner that didn't"."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = smtp_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(reader.readline(), timeout=2.0)  # banner
            writer.write(b"EHLO probe.test\r\n")
            await writer.drain()
            await _read_until_terminator(reader)
            writer.write(b"STARTTLS\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            await writer.start_tls(ctx)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "smtp_starttls_handshake")
        )
        events = list(result.scalars().all())

    assert len(events) == 1
    # The cipher info from get_extra_info("cipher") should be present
    assert events[0].payload.get("cipher") is not None
