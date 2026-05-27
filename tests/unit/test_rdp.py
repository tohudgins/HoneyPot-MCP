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
async def test_engine_responds_with_negotiation_failure_for_standard_rdp(rdp_server):
    """End-to-end: a client that asks for Standard RDP only (no SSL/HYBRID)
    gets a NegFailure response. Captures the mstshash event."""
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
            # requested_protocols=0x00 → Standard RDP only → NegFailure path
            writer.write(_build_x224_cr(cookie_user="evil@TARGET", requested_protocols=0x00))
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


def test_mcs_parser_handles_truncated_pdu():
    """A short / empty / garbage PDU returns `{}` rather than raising."""
    from honeypot_mcp.engines.rdp import _parse_mcs_connect_initial

    assert _parse_mcs_connect_initial(b"") == {}
    assert _parse_mcs_connect_initial(b"\x00") == {}
    assert _parse_mcs_connect_initial(b"\x03\x00\x00\x10") == {}
    # No GCC magic anywhere in the payload → empty result.
    assert _parse_mcs_connect_initial(b"completely unrelated bytes here") == {}


def _build_minimal_mcs_pdu(
    *,
    client_name: str = "DESKTOP-ATTACKER",
    client_build: int = 0x00001DB1,
    keyboard_layout: int = 0x00000409,
    desktop_width: int = 1920,
    desktop_height: int = 1080,
    color_depth: int = 0xCA01,
    encryption_methods: int = 0x0000001B,
    ext_encryption_methods: int = 0,
) -> bytes:
    """Synthesise an MCS Connect Initial PDU with just enough structure for
    our `_parse_mcs_connect_initial` (magic-prefix-driven) to extract the
    fields. We don't need to produce a wire-format-valid BER wrapper because
    the parser locates the GCC userData by magic prefix and never walks the
    outer ASN.1 framing."""
    # TS_UD_CS_CORE body (MS-RDPBCGR §2.2.1.3.2):
    # version(4) + width(2) + height(2) + colorDepth(2) + sasSeq(2)
    # + keyboardLayout(4) + clientBuild(4) + clientName(32 UTF-16LE)
    # + keyboardType(4) + keyboardSubType(4) + keyboardFunctionKey(4)
    # + imeFileName(64) + ... we cap here at clientDigProductId (192 bytes).
    name_utf16 = client_name.encode("utf-16-le").ljust(32, b"\x00")[:32]
    core_body = (
        (0x00080001).to_bytes(4, "little")            # version
        + desktop_width.to_bytes(2, "little")
        + desktop_height.to_bytes(2, "little")
        + color_depth.to_bytes(2, "little")
        + (0xAA03).to_bytes(2, "little")              # SASSequence
        + keyboard_layout.to_bytes(4, "little")
        + client_build.to_bytes(4, "little")
        + name_utf16
        + (0x00000004).to_bytes(4, "little")          # keyboardType
        + (0).to_bytes(4, "little")                   # keyboardSubType
        + (12).to_bytes(4, "little")                  # keyboardFunctionKey
        + b"\x00" * 64                                # imeFileName
        + b"\x00" * 64                                # clientDigProductId
    )
    core_len = 4 + len(core_body)
    core_block = (
        b"\x01\xc0"
        + core_len.to_bytes(2, "little")
        + core_body
    )

    # TS_UD_CS_SEC body: encryptionMethods(4) + extEncryptionMethods(4).
    sec_body = (
        encryption_methods.to_bytes(4, "little")
        + ext_encryption_methods.to_bytes(4, "little")
    )
    sec_len = 4 + len(sec_body)
    sec_block = b"\x02\xc0" + sec_len.to_bytes(2, "little") + sec_body

    # Frame: anything → GCC magic → core+sec blocks.
    # The parser only needs the magic prefix to anchor — outer BER framing
    # is irrelevant.
    return b"\x7f\x65\x82\x01\x00" + b"\x00" * 80 + b"\x00\x05\x00\x14\x7c\x00\x01" + core_block + sec_block


def test_mcs_parser_extracts_core_and_sec_fields():
    """Parser pulls clientName, clientBuild, screen res, keyboard layout, and
    encryption methods from a synthesised PDU."""
    from honeypot_mcp.engines.rdp import _parse_mcs_connect_initial

    pdu = _build_minimal_mcs_pdu(
        client_name="LAB-WIN11",
        client_build=0x00001DB1,
        keyboard_layout=0x00000409,  # en-US
        desktop_width=2560,
        desktop_height=1440,
        encryption_methods=0x0000001F,
    )
    parsed = _parse_mcs_connect_initial(pdu)
    assert parsed.get("client_name") == "LAB-WIN11"
    assert parsed.get("client_build") == 0x00001DB1
    assert parsed.get("keyboard_layout") == 0x00000409
    assert parsed.get("desktop_width") == 2560
    assert parsed.get("desktop_height") == 1440
    assert parsed.get("encryption_methods") == 0x0000001F


@pytest.mark.asyncio
async def test_engine_upgrades_to_tls_and_captures_mcs(rdp_server):
    """End-to-end: when the client requests SSL, the engine sends a NegRSP
    success, completes the TLS handshake, then captures the MCS Connect
    Initial PDU sent inside the encrypted tunnel."""
    import ssl as ssl_mod

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
            # requested_protocols=0x01 → SSL → engine should accept & upgrade
            writer.write(_build_x224_cr(cookie_user="attacker@LAB", requested_protocols=0x01))
            await writer.drain()
            cc_resp = await asyncio.wait_for(reader.read(64), timeout=2.0)

            # Should be a NegRSP success (type 0x02), not NegFailure (0x03).
            assert cc_resp[5] == 0xD0  # X.224 Connection Confirm
            assert cc_resp[11] == 0x02  # _RDP_NEG_RSP success

            # Upgrade our side to TLS — accept the honeypot's self-signed cert.
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            await writer.start_tls(ctx, server_hostname="localhost")

            # Send the MCS Connect Initial inside TLS.
            pdu = _build_minimal_mcs_pdu(client_name="LAB-WIN11", client_build=0x00001DB1)
            writer.write(pdu)
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        # Give the flusher time to write
        await asyncio.sleep(1.0)
    finally:
        await buf.stop()

    async with get_session() as session:
        rows = list(
            (await session.execute(select(Alert).where(Alert.event_type == "rdp_mcs_handshake")))
            .scalars()
            .all()
        )

    assert len(rows) == 1, "expected exactly one rdp_mcs_handshake event"
    payload = rows[0].payload
    assert payload["tls_negotiated"] is True
    assert payload["client_name"] == "LAB-WIN11"
    assert payload["client_build"] == 0x00001DB1
    assert payload["selected_protocol"] == 0x01


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
