"""MySQL banner honeypot tests.

Verifies the Initial Handshake Packet emission, HandshakeResponse41 parsing
(username + auth_response capture), and the ER_ACCESS_DENIED_ERROR reply.
"""

import asyncio
import contextlib
import os
import socket
import struct

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
async def mysql_server():
    from honeypot_mcp.engines.mysql import MySQLEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="mysql-test", type=HoneypotType.MYSQL, port=port)
        session.add(hp)
        await session.flush()

    engine = MySQLEngine()
    cid = await engine.start("mysql-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


async def _read_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    """Read one MySQL packet: 3-byte LE length + 1-byte seq + payload."""
    header = await asyncio.wait_for(reader.readexactly(4), timeout=2.0)
    payload_len = int.from_bytes(header[0:3], "little")
    seq = header[3]
    payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=2.0)
    return seq, payload


@pytest.mark.asyncio
async def test_mysql_initial_handshake_packet(mysql_server):
    """Server sends Initial Handshake Packet immediately on connect.

    Layout: protocol_version=10 + server_version (null-term) + thread_id +
    salt + capability flags + ... + auth_plugin_name (null-term).
    """
    port = mysql_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        seq, payload = await _read_packet(reader)
        assert seq == 0
        # First byte: protocol version (10 for MySQL 4.1+)
        assert payload[0] == 10
        # Server version is a null-terminated string starting at byte 1
        null_idx = payload.find(b"\x00", 1)
        assert null_idx > 1
        version = payload[1:null_idx].decode()
        assert version.startswith("8.0"), f"unexpected server version: {version!r}"
        # Auth plugin name must be present at the end as null-term string
        assert b"mysql_native_password" in payload
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_mysql_handshake_response_then_access_denied(mysql_server):
    """Send a believable HandshakeResponse41 with username `root`, expect
    ER_ACCESS_DENIED_ERROR (1045) back."""
    port = mysql_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        # Drain the server greeting
        await _read_packet(reader)

        # Build a HandshakeResponse41 packet
        client_flag = 0x807FE7FF  # advertise the same flags the server did
        max_packet_size = 16 * 1024 * 1024
        charset = 0x2D
        reserved = b"\x00" * 23
        username = b"root\x00"
        auth_response_len = 20
        auth_response = b"\xaa" * auth_response_len  # fake scramble
        response_payload = (
            struct.pack("<I", client_flag)
            + struct.pack("<I", max_packet_size)
            + bytes([charset])
            + reserved
            + username
            + bytes([auth_response_len])
            + auth_response
        )
        header = struct.pack("<I", len(response_payload))[:3] + bytes([1])
        writer.write(header + response_payload)
        await writer.drain()

        # Read the response — should be an ERR_Packet (0xff header)
        seq, payload = await _read_packet(reader)
        assert payload[0] == 0xFF, f"expected ERR_Packet, got header byte {payload[0]:#x}"
        errno = struct.unpack("<H", payload[1:3])[0]
        assert errno == 1045
        assert payload[3:4] == b"#"
        assert payload[4:9] == b"28000"
        message = payload[9:].decode("utf-8", errors="replace")
        assert "Access denied" in message
        assert "'root'" in message
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_mysql_login_attempt_event_captures_username(mysql_server):
    """The captured `username` + `auth_response_hex` payload is what makes
    this useful for SOC analysis."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = mysql_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await _read_packet(reader)  # greeting
            username = b"admin\x00"
            response_payload = (
                struct.pack("<I", 0x807FE7FF)
                + struct.pack("<I", 16 * 1024 * 1024)
                + bytes([0x2D])
                + b"\x00" * 23
                + username
                + bytes([20])
                + b"\xab" * 20
            )
            header = struct.pack("<I", len(response_payload))[:3] + bytes([1])
            writer.write(header + response_payload)
            await writer.drain()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader.read(256), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "mysql_login_attempt")
        )
        events = list(result.scalars().all())
    assert len(events) == 1
    assert events[0].payload["username"] == "admin"
    assert events[0].payload["auth_response_hex"] == "ab" * 20
    assert events[0].payload["service"] == "mysql"
    assert events[0].severity.value == "high"
