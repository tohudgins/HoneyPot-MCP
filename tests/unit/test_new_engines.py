"""High-value capture tests for the SMB / PostgreSQL / MongoDB honeypots.

Beyond the generic self-test (probe → alert), these exercise the attack
scenarios that make each engine worth deploying: EternalBlue/DoublePulsar
detection, credential capture, and Mongo ransom-note detection.
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
    buf = event_buffer.get_buffer()
    await buf.start()
    yield
    await buf.stop()
    event_buffer.reset_for_tests()
    await close_db()


async def _register(name, hp_type):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = _free_port()
    async with get_session() as session:
        session.add(Honeypot(name=name, type=hp_type, port=port, status=HoneypotStatus.RUNNING))
        await session.flush()
    return port


async def _alerts_of_type(event_type):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == event_type))
        return list(result.scalars().all())


# ── SMB ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_smb_detects_doublepulsar_ping():
    """An SMB1 Trans2 SESSION_SETUP (0x000e) after negotiate is the DoublePulsar
    backdoor check — must flag CRITICAL smb_exploit_attempt."""
    from honeypot_mcp.engines.smb import SMBEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("smb-eb", HoneypotType.SMB)
    engine = SMBEngine()
    cid = await engine.start("smb-eb", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            # Negotiate (SMB1).
            neg = b"\xffSMB" + bytes([0x72]) + b"\x00" * 27 + b"\x00\x0c\x00\x02NT LM 0.12\x00"
            writer.write(b"\x00" + len(neg).to_bytes(3, "big") + neg)
            await writer.drain()
            await asyncio.wait_for(reader.read(256), timeout=3.0)
            # Trans2 (command 0x32) carrying subcommand 0x000e.
            trans2 = b"\xffSMB" + bytes([0x32]) + b"\x00" * 27 + struct.pack("<H", 0x000E) + b"\x00" * 8
            writer.write(b"\x00" + len(trans2).to_bytes(3, "big") + trans2)
            await writer.drain()
            await asyncio.sleep(0.3)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await engine.stop(cid)

    events = await _alerts_of_type("smb_exploit_attempt")
    assert len(events) == 1
    assert events[0].severity.value == "critical"
    assert "doublepulsar" in events[0].payload["ioc"].lower()


# ── PostgreSQL ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_postgresql_captures_password():
    """The full startup → cleartext-auth → password flow must capture the
    username, database, and password."""
    from honeypot_mcp.engines.postgresql import PostgreSQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pg-cred", HoneypotType.POSTGRESQL)
    engine = PostgreSQLEngine()
    cid = await engine.start("pg-cred", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            params = b"user\x00admin\x00database\x00prod\x00\x00"
            body = struct.pack("!I", 196608) + params
            writer.write(struct.pack("!I", len(body) + 4) + body)
            await writer.drain()
            # Expect an AuthenticationCleartextPassword ('R').
            resp = await asyncio.wait_for(reader.read(64), timeout=3.0)
            assert resp[:1] == b"R", resp
            # Send PasswordMessage 'p'.
            pw = b"S3cr3tP@ss\x00"
            writer.write(b"p" + struct.pack("!I", len(pw) + 4) + pw)
            await writer.drain()
            await asyncio.sleep(0.3)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await engine.stop(cid)

    events = await _alerts_of_type("postgresql_login_attempt")
    assert len(events) == 1
    p = events[0].payload
    assert p["username"] == "admin"
    assert p["database"] == "prod"
    assert p["password"] == "S3cr3tP@ss"
    assert p["service"] == "postgresql"


# ── MongoDB ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mongodb_flags_ransom_note():
    """An insert carrying a ransom note (bitcoin/recover language) must flag
    CRITICAL mongodb_ransom_note with the note text captured."""
    from honeypot_mcp.engines.mongodb import MongoDBEngine, _bson_encode
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mongo-ransom", HoneypotType.MONGODB)
    engine = MongoDBEngine()
    cid = await engine.start("mongo-ransom", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            note = "All your databases are backed up. Send 0.5 bitcoin to recover: 1A2b3C wallet"
            doc = _bson_encode({"insert": "READ_ME", "documents": [{"msg": note}]})
            body = struct.pack("<I", 0) + b"\x00" + doc  # OP_MSG flagBits + section 0
            header = struct.pack("<iiii", 16 + len(body), 1, 0, 2013)
            writer.write(header + body)
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=3.0)
            await asyncio.sleep(0.3)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await engine.stop(cid)

    events = await _alerts_of_type("mongodb_ransom_note")
    assert len(events) == 1
    assert events[0].severity.value == "critical"
    joined = " ".join(events[0].payload["strings"]).lower()
    assert "bitcoin" in joined


@pytest.mark.asyncio
async def test_mongodb_answers_ismaster():
    """isMaster must get a believable reply (ismaster:true) so the scanner
    proceeds — otherwise we capture nothing past the handshake."""
    from honeypot_mcp.engines.mongodb import MongoDBEngine, _bson_encode
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mongo-hello", HoneypotType.MONGODB)
    engine = MongoDBEngine()
    cid = await engine.start("mongo-hello", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            doc = _bson_encode({"isMaster": 1})
            body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + doc
            header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)
            writer.write(header + body)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=3.0)
            # The reply BSON should contain the "ismaster" field name.
            assert b"ismaster" in resp
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await engine.stop(cid)
