"""MySQL honeypot tests.

Verifies the Initial Handshake Packet emission, HandshakeResponse41 parsing
(username + auth_response capture), login acceptance into the command phase,
and post-auth query capture (recon result sets + INTO OUTFILE RCE flagging).
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


def _handshake_response(username: bytes = b"root\x00") -> bytes:
    client_flag = 0x807FE7FF
    max_packet_size = 16 * 1024 * 1024
    charset = 0x2D
    reserved = b"\x00" * 23
    auth_response = b"\xaa" * 20
    payload = (
        struct.pack("<I", client_flag)
        + struct.pack("<I", max_packet_size)
        + bytes([charset])
        + reserved
        + username
        + bytes([20])
        + auth_response
    )
    return struct.pack("<I", len(payload))[:3] + bytes([1]) + payload


def _com_query(sql: str, seq: int = 0) -> bytes:
    payload = bytes([0x03]) + sql.encode()
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


@pytest.mark.asyncio
async def test_mysql_login_accepted_then_query_phase(mysql_server):
    """Login is now accepted (OK packet) so the command phase opens, and a
    post-auth `SELECT @@version` returns a believable version result set."""
    port = mysql_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await _read_packet(reader)  # greeting
        writer.write(_handshake_response())
        await writer.drain()

        # Auth response is now an OK_Packet (0x00 header), not ERR (0xff).
        _seq, payload = await _read_packet(reader)
        assert payload[0] == 0x00, f"expected OK packet, got {payload[0]:#x}"

        # Run a version query — expect a result set carrying the server version.
        writer.write(_com_query("SELECT @@version"))
        await writer.drain()
        # Column-count packet, then column def, EOF, row, EOF. The row carries
        # the version string somewhere in the byte stream.
        blob = b""
        for _ in range(5):
            _s, p = await _read_packet(reader)
            blob += p
        assert b"8.0" in blob
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_mysql_into_outfile_flagged_critical(mysql_server):
    """`SELECT ... INTO OUTFILE` (webshell drop RCE) must be captured CRITICAL."""
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
            writer.write(_handshake_response())
            await writer.drain()
            await _read_packet(reader)  # OK
            writer.write(
                _com_query("SELECT '<?php system($_GET[c]); ?>' INTO OUTFILE '/var/www/x.php'")
            )
            await writer.drain()
            await asyncio.sleep(0.3)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "mysql_outfile_write")
        )
        events = list(result.scalars().all())
    assert len(events) == 1
    assert events[0].severity.value == "critical"
    assert "outfile" in events[0].payload["query"].lower()


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
