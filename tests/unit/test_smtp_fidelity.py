"""SMTP engine fidelity checks.

Verifies the Postfix-flavoured EHLO/HELO/STARTTLS/DATA/VRFY behaviour added
to defeat first-probe fingerprinting. Connects to a started SMTPEngine on a
free local port and asserts the wire response shape.
"""

import asyncio
import contextlib
import os
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


async def _read_until_terminator(reader: asyncio.StreamReader, timeout: float = 2.0) -> str:
    """Read multi-line SMTP response until we see a line whose 4th char is a
    space (the SMTP continuation terminator)."""
    chunks: list[str] = []
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
        if not line:
            break
        decoded = line.decode("utf-8", errors="replace")
        chunks.append(decoded)
        # SMTP multi-line: `250-EXT` continues, `250 EXT` terminates.
        if len(decoded) >= 4 and decoded[3] == " ":
            break
    return "".join(chunks)


@pytest.fixture
async def smtp_server():
    """Boot an SMTPEngine on a free port. Yields (port,). Cleans up after."""
    from honeypot_mcp.engines.smtp import SMTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    # Seed a honeypot row so SMTPEngine.start() can resolve honeypot_id.
    async with get_session() as session:
        hp = Honeypot(name="smtp-fidelity-test", type=HoneypotType.SMTP, port=port)
        session.add(hp)
        await session.flush()

    engine = SMTPEngine()
    container_id = await engine.start(
        "smtp-fidelity-test", port, {"smtp_hostname": "mail.test.local"}
    )
    try:
        yield port
    finally:
        await engine.stop(container_id)


@pytest.mark.asyncio
async def test_ehlo_returns_postfix_realistic_extensions(smtp_server):
    port = smtp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert banner.startswith(b"220 mail.test.local ESMTP")

        writer.write(b"EHLO probe.test\r\n")
        await writer.drain()
        resp = await _read_until_terminator(reader)

        # All required Postfix extensions present.
        for ext in (
            "PIPELINING",
            "SIZE",
            "VRFY",
            "ETRN",
            "STARTTLS",
            "AUTH PLAIN LOGIN",
            "ENHANCEDSTATUSCODES",
            "8BITMIME",
            "DSN",
            "SMTPUTF8",
        ):
            assert ext in resp, f"EHLO response missing {ext}: {resp!r}"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_helo_is_single_line_no_extensions(smtp_server):
    """Real Postfix: HELO (legacy) returns one `250 hostname` line. The
    asymmetry vs EHLO is itself a realism signal."""
    port = smtp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=2.0)  # banner

        writer.write(b"HELO probe.test\r\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert line.startswith(b"250 ")
        assert b"PIPELINING" not in line
        assert b"STARTTLS" not in line
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_vrfy_returns_252(smtp_server):
    """Postfix default: VRFY answers 252 'neither confirm nor deny'."""
    port = smtp_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=2.0)  # banner
        writer.write(b"EHLO probe.test\r\n")
        await writer.drain()
        await _read_until_terminator(reader)

        writer.write(b"VRFY root\r\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert line.startswith(b"252")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# STARTTLS handshake-completion behaviour moved to test_smtp_starttls.py
# now that we actually perform the TLS handshake instead of closing on the
# ClientHello.


@pytest.mark.asyncio
async def test_smtp_auth_login_decodes_credentials(smtp_server):
    """AUTH LOGIN's base64 username/password challenge exchange must be decoded
    and captured with service=smtp for credential cross-referencing."""
    import base64

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
            writer.write(b"EHLO x\r\n")
            await writer.drain()
            await _read_until_terminator(reader)
            writer.write(b"AUTH LOGIN\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)  # 334 Username:
            writer.write(base64.b64encode(b"admin@corp") + b"\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)  # 334 Password:
            writer.write(base64.b64encode(b"Hunter2!") + b"\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)  # 535 fail
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "smtp_auth_attempt")
        )
        alerts = list(result.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].payload["username"] == "admin@corp"
    assert alerts[0].payload["password"] == "Hunter2!"
    assert alerts[0].payload["service"] == "smtp"


@pytest.mark.asyncio
async def test_smtp_open_relay_detected(smtp_server):
    """External sender + external recipient = open-relay probe → HIGH."""
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
            writer.write(b"MAIL FROM:<spammer@gmail.com>\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)
            writer.write(b"RCPT TO:<victim@yahoo.com>\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "smtp_open_relay")
        )
        alerts = list(result.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].severity.value == "high"
    assert alerts[0].payload["mail_from"] == "spammer@gmail.com"
    assert alerts[0].payload["rcpt_to"] == "victim@yahoo.com"
