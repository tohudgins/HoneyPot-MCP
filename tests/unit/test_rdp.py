"""RDP banner honeypot — X.224 Connection Request parsing + handshake.

Verifies the wire-format parser extracts `Cookie: mstshash=user@DOMAIN`,
identifies the requested security protocols, and that the engine responds
with a TPKT + X.224 Connection Confirm carrying a believable negotiation
failure code.
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


def _build_x224_cr(
    cookie_user: str | None = "admin@CORP", requested_protocols: int = 0x01
) -> bytes:
    """Build a TPKT + X.224 Connection Request that a real RDP client (mstsc,
    Hydra, NLBrute, etc.) would send. Matches MS-RDPBCGR §2.2.1.1."""
    var = b""
    if cookie_user is not None:
        var += f"Cookie: mstshash={cookie_user}\r\n".encode()
    # RDP Negotiation Request: type=0x01, flags=0, length=8, requestedProtocols
    var += (
        bytes([0x01, 0x00]) + (8).to_bytes(2, "little") + requested_protocols.to_bytes(4, "little")
    )

    x224_len = 6 + len(var)  # header bytes after the length byte itself
    x224 = bytes([x224_len, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + var
    tpkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big")
    return tpkt + x224


@pytest.fixture
async def rdp_server():
    from honeypot_mcp.engines.rdp import RDPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="rdp-test", type=HoneypotType.RDP, port=port)
        session.add(hp)
        await session.flush()

    engine = RDPEngine()
    cid = await engine.start("rdp-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


def test_parser_extracts_cookie_user_and_domain():
    from honeypot_mcp.engines.rdp import _parse_x224_cr

    data = _build_x224_cr(cookie_user="bob@CONTOSO", requested_protocols=0x03)
    parsed = _parse_x224_cr(data)
    assert parsed["x224_code"] == "ConnectionRequest"
    assert parsed["mstshash"] == "bob@CONTOSO"
    assert parsed["username"] == "bob"
    assert parsed["domain"] == "CONTOSO"
    # 0x03 = SSL | HYBRID_CredSSP
    assert "SSL" in parsed["requested_protocols_names"]
    assert "HYBRID_CredSSP" in parsed["requested_protocols_names"]


def test_parser_handles_user_without_domain():
    from honeypot_mcp.engines.rdp import _parse_x224_cr

    parsed = _parse_x224_cr(_build_x224_cr(cookie_user="administrator"))
    assert parsed["username"] == "administrator"
    assert "domain" not in parsed


def test_parser_handles_missing_cookie():
    """Some RDP scanners skip the cookie. We should still parse the neg request."""
    from honeypot_mcp.engines.rdp import _parse_x224_cr

    parsed = _parse_x224_cr(_build_x224_cr(cookie_user=None, requested_protocols=0x00))
    assert parsed["x224_code"] == "ConnectionRequest"
    assert "mstshash" not in parsed
    assert "STANDARD_RDP" in parsed["requested_protocols_names"]


def test_parser_rejects_garbage():
    from honeypot_mcp.engines.rdp import _parse_x224_cr

    # Random bytes, non-TPKT
    assert _parse_x224_cr(b"GET / HTTP/1.1\r\n") == {}
    # Too short to be a valid TPKT
    assert _parse_x224_cr(b"\x03\x00") == {}


@pytest.mark.asyncio
async def test_engine_responds_with_negotiation_failure(rdp_server):
    """End-to-end: send a real X.224 CR, get back a parseable TPKT + X.224 CC
    with a negotiation-failure response. Captures the mstshash event."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = rdp_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_build_x224_cr(cookie_user="evil@TARGET"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        # TPKT header
        assert resp[:1] == b"\x03"
        # X.224 code 0xD0 = Connection Confirm
        assert resp[5] == 0xD0
        # RDP negotiation failure starts at offset 11
        assert resp[11] == 0x03  # _RDP_NEG_FAILURE

        await asyncio.sleep(1.0)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    handshake_alerts = [a for a in alerts if a.event_type == "rdp_handshake"]
    assert len(handshake_alerts) == 1
    assert handshake_alerts[0].payload["username"] == "evil"
    assert handshake_alerts[0].payload["domain"] == "TARGET"


@pytest.mark.asyncio
async def test_engine_records_invalid_probe_at_low_severity(rdp_server):
    """Port-scan garbage that doesn't parse as X.224 should still log a probe
    event, but at LOW severity so it doesn't trigger CRITICAL pipelines."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    port = rdp_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"GET / HTTP/1.1\r\n\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(64), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.0)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "rdp_invalid_probe"))
        alerts = list(result.scalars().all())

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.LOW
