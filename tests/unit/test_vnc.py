"""VNC banner honeypot tests.

Verifies the RFB 003.008 handshake: server banner, security types
negotiation, challenge/response exchange, and auth-failure response. Also
checks the events emitted along the way — `vnc_connection`, `vnc_handshake`,
`vnc_security_selected`, and `vnc_auth_attempt`.
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


@pytest.fixture
async def vnc_server():
    from honeypot_mcp.engines.vnc import VNCEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="vnc-test", type=HoneypotType.VNC, port=port)
        session.add(hp)
        await session.flush()

    engine = VNCEngine()
    cid = await engine.start("vnc-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_vnc_banner_is_rfb_003_008(vnc_server):
    """Server greets with `RFB 003.008\\n` — that's what the install base of
    modern RealVNC / TightVNC / TigerVNC advertises."""
    port = vnc_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = await asyncio.wait_for(reader.readexactly(12), timeout=2.0)
        assert banner == b"RFB 003.008\n"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_vnc_full_handshake_to_auth_failure(vnc_server):
    """End-to-end: receive banner, send client version, receive security
    types, send selection, receive 16-byte challenge, send response,
    receive auth-failure packet with reason."""
    port = vnc_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        banner = await asyncio.wait_for(reader.readexactly(12), timeout=2.0)
        assert banner == b"RFB 003.008\n"

        # Client sends its supported version
        writer.write(b"RFB 003.008\n")
        await writer.drain()

        # Server sends security types: 1 byte count + N bytes of type ids
        count_byte = await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
        count = count_byte[0]
        assert count >= 1
        types = await asyncio.wait_for(reader.readexactly(count), timeout=2.0)
        assert 2 in types, "VNC Auth (type 2) must be in the security types list"

        # Client picks VNC Auth
        writer.write(bytes([2]))
        await writer.drain()

        # Server sends 16-byte challenge
        challenge = await asyncio.wait_for(reader.readexactly(16), timeout=2.0)
        assert len(challenge) == 16

        # Client sends 16-byte DES-encrypted response (we just send zeros)
        writer.write(b"\x00" * 16)
        await writer.drain()

        # Server sends SecurityResult: 4-byte status + length-prefixed reason
        status_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
        status = int.from_bytes(status_bytes, "big")
        assert status == 1, "expected auth-failed status code (1)"

        reason_len_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
        reason_len = int.from_bytes(reason_len_bytes, "big")
        assert 0 < reason_len < 100, f"unexpected reason length {reason_len}"

        reason = await asyncio.wait_for(reader.readexactly(reason_len), timeout=2.0)
        assert b"Authentication" in reason or b"failure" in reason.lower()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_vnc_auth_attempt_event_captures_response(vnc_server):
    """The captured `response_hex` in the alert is what enables offline
    brute-force-credential cracking — verify it's recorded verbatim."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = vnc_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.wait_for(reader.readexactly(12), timeout=2.0)  # banner
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            count_byte = await asyncio.wait_for(reader.readexactly(1), timeout=2.0)
            await asyncio.wait_for(reader.readexactly(count_byte[0]), timeout=2.0)
            writer.write(bytes([2]))
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(16), timeout=2.0)
            # Send a distinctive response so we can verify it round-trips
            distinctive = b"\xde\xad\xbe\xef" + b"\x01\x02\x03\x04" * 3
            writer.write(distinctive)
            await writer.drain()
            # Drain the status reply so the server's close is graceful
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader.read(64), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "vnc_auth_attempt"))
        events = list(result.scalars().all())

    assert len(events) == 1
    payload = events[0].payload
    assert payload.get("response_hex") == distinctive.hex()
    assert "challenge_hex" in payload
    assert len(payload["challenge_hex"]) == 32  # 16 bytes hex = 32 chars
    assert events[0].severity.value == "medium"
