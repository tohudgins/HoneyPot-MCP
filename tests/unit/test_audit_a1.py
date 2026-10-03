"""Audit slice A1 — hostile input to the binary-protocol engines.

Every test here crafts the packet that used to hang the shared event loop,
balloon memory, or fan out unbounded work, and asserts the engine stays
responsive and still records something sensible. Parser-level tests run in a
daemon thread with a join timeout: a regression into an infinite loop would
otherwise freeze the event loop (and with it any asyncio-level timeout).
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _register(name: str, hp_type) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = _free_port()
    async with get_session() as session:
        session.add(
            Honeypot(
                name=name,
                type=hp_type,
                port=port,
                status=HoneypotStatus.RUNNING,
                container_id=None,
                config={},
            )
        )
    return port


async def _alerts() -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return list((await session.execute(select(Alert))).scalars().all())


def _returns_within(fn: Callable[..., Any], *args: Any, timeout: float = 3.0) -> Any:
    """Run `fn` in a daemon thread; fail the test (rather than hang it) if it spins."""
    box: dict[str, Any] = {}

    def _run() -> None:
        box["value"] = fn(*args)

    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(timeout)
    assert not th.is_alive(), f"{fn.__name__} did not return within {timeout}s (infinite loop?)"
    return box["value"]


async def _read_until_eof(reader: asyncio.StreamReader, timeout: float = 2.0) -> bytes:
    """Drain until the peer closes. Fails if the server keeps the socket open."""
    out = b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=deadline - time.monotonic())
        if not chunk:
            return out
        out += chunk
    raise AssertionError("server did not close the connection")


# ── MongoDB ─────────────────────────────────────────────────────────────────


def _op_msg(doc: bytes, request_id: int = 1) -> bytes:
    payload = struct.pack("<I", 0) + b"\x00" + doc
    return struct.pack("<iiii", 16 + len(payload), request_id, 0, 2013) + payload


def _hostile_bson(embedded_len: int) -> bytes:
    """Outer doc whose first element is an embedded document claiming a bogus length."""
    return struct.pack("<i", 20) + b"\x03a\x00" + struct.pack("<i", embedded_len) + b"\x00" * 3


@pytest.mark.parametrize("bad_len", [-1, -100, 0, 1, 4, 2**31 - 1])
async def test_bson_walk_terminates_on_bogus_embedded_length(bad_len):
    from honeypot_mcp.engines.mongodb import _bson_collect_strings

    assert _returns_within(_bson_collect_strings, _hostile_bson(bad_len)) == []


async def test_bson_walk_terminates_on_bogus_string_length():
    from honeypot_mcp.engines.mongodb import _bson_collect_strings

    for slen in (-5, 0, 2**31 - 1):
        doc = struct.pack("<i", 20) + b"\x02a\x00" + struct.pack("<i", slen) + b"\x00" * 4
        assert _returns_within(_bson_collect_strings, doc) == []


async def test_bson_walk_depth_is_capped():
    from honeypot_mcp.engines.mongodb import _bson_collect_strings, _bson_encode

    doc: dict[str, Any] = {"deep": "found"}
    for _ in range(200):
        doc = {"n": doc}
    assert _returns_within(_bson_collect_strings, _bson_encode(doc)) == []


async def test_mongodb_survives_the_33_byte_negative_length_op_msg():
    from honeypot_mcp.engines.mongodb import MongoDBEngine, _bson_encode
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mongo-audit", HoneypotType.MONGODB)
    engine = MongoDBEngine()
    cid = await engine.start("mongo-audit", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        crafted = _op_msg(struct.pack("<i", 12) + b"\x03a\x00" + struct.pack("<i", -1) + b"\x00")
        assert len(crafted) == 33
        writer.write(crafted)
        writer.write(_op_msg(_bson_encode({"isMaster": 1}), request_id=2))
        await writer.drain()
        # Both are answered, and the loop stayed responsive to do so.
        replies = b""
        deadline = time.monotonic() + 1.0
        while replies.count(b"maxWireVersion") < 1 and time.monotonic() < deadline:
            replies += await asyncio.wait_for(reader.read(65536), timeout=1.0)
        assert b"maxWireVersion" in replies
        writer.close()
    finally:
        await engine.stop(cid)


async def test_mongodb_closes_on_oversized_wire_message_but_keeps_ransom_capture():
    from honeypot_mcp.engines.mongodb import MongoDBEngine, _bson_encode
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mongo-audit2", HoneypotType.MONGODB)
    engine = MongoDBEngine()
    cid = await engine.start("mongo-audit2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(struct.pack("<iiii", 48_000_000, 1, 0, 2013))
        await writer.drain()
        await _read_until_eof(reader)
        writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        note = {
            "insert": "README",
            "documents": [{"msg": "send bitcoin to recover your data"}],
        }
        writer.write(_op_msg(_bson_encode(note)))
        await writer.drain()
        await asyncio.wait_for(reader.read(4096), timeout=1.0)
        await asyncio.sleep(0.4)
        writer.close()
    finally:
        await engine.stop(cid)
    ransom = [a for a in await _alerts() if a.event_type == "mongodb_ransom_note"]
    assert ransom
    assert any("bitcoin" in s for s in ransom[0].payload["strings"])


# ── Redis ───────────────────────────────────────────────────────────────────


async def test_resp_parser_rejects_negative_bulk_length_without_spinning():
    from honeypot_mcp.engines.redis import _ProtocolError, _RESPParser

    def _parse(buf: bytes) -> str:
        try:
            _RESPParser.parse(buf, 0)
        except _ProtocolError:
            return "error"
        return "ok"

    assert _returns_within(_parse, b"*1\r\n$-7\r\n") == "error"
    assert _returns_within(_parse, b"*1\r\n$-1\r\n") == "error"
    assert _returns_within(_parse, b"*99999999\r\n") == "error"
    assert _returns_within(_parse, b"*1\r\n$99999999\r\n") == "error"


async def test_resp_parser_consumes_at_least_one_byte_per_command():
    from honeypot_mcp.engines.redis import _RESPParser

    for buf in (b"\r\n", b"*0\r\n", b"*-1\r\n", b"*x\r\n", b"PING\r\n"):
        args, consumed, _need = _RESPParser.parse(buf, 0)
        assert args is not None and consumed > 0


async def test_redis_closes_with_protocol_error_and_stays_up():
    from honeypot_mcp.engines.redis import RedisEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("redis-audit", HoneypotType.REDIS)
    engine = RedisEngine()
    cid = await engine.start("redis-audit", port, {})
    try:
        for hostile in (b"*1\r\n$-7\r\n", b"*2000000000\r\n", b"A" * (200 * 1024)):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(hostile)
            await writer.drain()
            data = await _read_until_eof(reader)
            assert data.startswith(b"-ERR Protocol error")
            writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"*1\r\n$4\r\nPING\r\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.readline(), timeout=1.0) == b"+PONG\r\n"
        writer.close()
    finally:
        await engine.stop(cid)


async def test_redis_large_bulk_trickled_in_is_parsed_once_complete():
    from honeypot_mcp.engines.redis import RedisEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("redis-audit2", HoneypotType.REDIS)
    engine = RedisEngine()
    cid = await engine.start("redis-audit2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        value = b"v" * 30_000
        cmd = b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$30000\r\n" + value + b"\r\n"
        for i in range(0, len(cmd), 4000):
            writer.write(cmd[i : i + 4000])
            await writer.drain()
            await asyncio.sleep(0.01)
        assert await asyncio.wait_for(reader.readline(), timeout=1.0) == b"+OK\r\n"
        writer.write(b"*2\r\n$6\r\nSTRLEN\r\n$1\r\nk\r\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.readline(), timeout=1.0) == b":30000\r\n"
        writer.close()
    finally:
        await engine.stop(cid)


# ── Memcached ───────────────────────────────────────────────────────────────


async def test_memcached_duplicate_keys_do_not_amplify_but_factor_is_still_measured():
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-audit", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-audit", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"set a 0 0 8192\r\n" + b"A" * 8192 + b"\r\n")
        await writer.drain()
        assert await asyncio.wait_for(reader.readline(), timeout=1.0) == b"STORED\r\n"
        line = b"get " + b"a " * 3000 + b"\r\n"
        assert len(line) < 8192
        writer.write(line)
        await writer.drain()
        await asyncio.sleep(0.4)
        reply = b""
        while not reply.endswith(b"END\r\n"):
            reply += await asyncio.wait_for(reader.read(65536), timeout=1.0)
        writer.close()
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert reply.count(b"VALUE a ") == 1
    assert len(reply) < 16 * 1024, "the reply must not scale with the number of duplicate keys"
    amp = [a for a in await _alerts() if a.event_type == "memcached_amplification_attempt"]
    assert amp, "stage-then-fetch must still be detected"
    # 3000 occurrences of an 8192-byte value over a ~6 KB request line.
    assert amp[0].payload["staged_bytes"] == 8192 * 3000
    assert amp[0].payload["amplification_factor"] > 3000


async def test_memcached_blank_line_flood_is_cheap():
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-audit2", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-audit2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        started = time.monotonic()
        writer.write(b"\r\n" * 30_000 + b"version\r\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert line.startswith(b"VERSION ")
        assert time.monotonic() - started < 2.0
        writer.close()
    finally:
        await engine.stop(cid)


# ── PostgreSQL ──────────────────────────────────────────────────────────────


def _pg_startup(user: str = "tester") -> bytes:
    body = struct.pack("!I", 196608) + b"user\x00" + user.encode() + b"\x00\x00"
    return struct.pack("!I", len(body) + 4) + body


def _pg_msg(tag: bytes, payload: bytes) -> bytes:
    return tag + struct.pack("!I", len(payload) + 4) + payload


async def _pg_login(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(_pg_startup())
    await writer.drain()
    assert (await asyncio.wait_for(reader.readexactly(9), timeout=1.0))[0:1] == b"R"
    writer.write(_pg_msg(b"p", b"hunter2\x00"))
    await writer.drain()
    await asyncio.sleep(0.2)
    await asyncio.wait_for(reader.read(65536), timeout=1.0)  # post-auth preamble
    return reader, writer


async def test_postgresql_huge_typed_length_closes_instead_of_buffering():
    from honeypot_mcp.engines.postgresql import PostgreSQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pg-audit", HoneypotType.POSTGRESQL)
    engine = PostgreSQLEngine()
    cid = await engine.start("pg-audit", port, {})
    try:
        for length in (0xFFFFFFFF, 2 * 1024 * 1024, 0, 3):
            reader, writer = await _pg_login(port)
            writer.write(b"Q" + struct.pack("!I", length))
            await writer.drain()
            await _read_until_eof(reader)
            writer.close()
    finally:
        await engine.stop(cid)


async def test_postgresql_normal_query_still_classified_and_pipeline_stops_after_terminate():
    from honeypot_mcp.engines.postgresql import PostgreSQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pg-audit2", HoneypotType.POSTGRESQL)
    engine = PostgreSQLEngine()
    cid = await engine.start("pg-audit2", port, {})
    try:
        reader, writer = await _pg_login(port)
        writer.write(_pg_msg(b"Q", b"COPY t FROM PROGRAM 'id';\x00"))
        await writer.drain()
        await asyncio.wait_for(reader.read(65536), timeout=1.0)
        # Terminate followed by a pipelined query: the query must never be recorded.
        writer.write(_pg_msg(b"X", b"") + _pg_msg(b"Q", b"SELECT 'after-terminate';\x00"))
        await writer.drain()
        await _read_until_eof(reader)
        await asyncio.sleep(0.4)
        writer.close()
    finally:
        await engine.stop(cid)
    queries = [a.payload.get("query", "") for a in await _alerts() if a.payload.get("query")]
    assert any("PROGRAM" in q for q in queries)
    assert not any("after-terminate" in q for q in queries)
    critical = [a for a in await _alerts() if a.severity.value == "critical"]
    assert critical, "COPY ... PROGRAM must stay CRITICAL"


# ── NFS ─────────────────────────────────────────────────────────────────────


def _rpc_call(program: int, procedure: int, version: int = 3) -> bytes:
    body = struct.pack(">IIIIII", 0x1234, 0, 2, program, version, procedure)
    body += struct.pack(">IIII", 0, 0, 0, 0)  # AUTH_NONE cred + verf
    return struct.pack(">I", 0x80000000 | len(body)) + body


async def test_nfs_zero_length_record_flood_closes_after_a_few_probes():
    from honeypot_mcp.engines.nfs import NFSEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("nfs-audit", HoneypotType.NFS)
    engine = NFSEngine()
    cid = await engine.start("nfs-audit", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(struct.pack(">I", 0x80000000) * 5000)
        await writer.drain()
        await _read_until_eof(reader)
        writer.close()
        await asyncio.sleep(0.5)
    finally:
        await engine.stop(cid)
    invalid = [a for a in await _alerts() if a.event_type == "nfs_invalid_probe"]
    assert 1 <= len(invalid) <= 6


async def test_nfs_showmount_still_answers_inline():
    from honeypot_mcp.engines.nfs import NFSEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("nfs-audit2", HoneypotType.NFS)
    engine = NFSEngine()
    cid = await engine.start("nfs-audit2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_rpc_call(100005, 5))
        await writer.drain()
        header = await asyncio.wait_for(reader.readexactly(4), timeout=1.0)
        length = struct.unpack(">I", header)[0] & 0x7FFFFFFF
        body = await asyncio.wait_for(reader.readexactly(length), timeout=1.0)
        assert struct.unpack(">I", body[:4])[0] == 0x1234
        writer.close()
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)
    assert "nfs_export_enumeration" in [a.event_type for a in await _alerts()]


# ── MSSQL ───────────────────────────────────────────────────────────────────


def _tds(pkt_type: int, payload: bytes) -> bytes:
    return struct.pack(">BBHHBB", pkt_type, 1, 8 + len(payload), 0, 1, 0) + payload


async def test_mssql_pipelined_login7_yields_one_event_and_second_prelogin_is_rejected():
    from honeypot_mcp.engines.mssql import MSSQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mssql-audit", HoneypotType.MSSQL)
    engine = MSSQLEngine()
    cid = await engine.start("mssql-audit", port, {})
    try:
        login = _tds(0x10, b"\x00" * 120)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_tds(0x12, b"\x00" * 8) + login * 50)
        await writer.drain()
        await _read_until_eof(reader)
        writer.close()

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(_tds(0x12, b"\x00" * 8) * 100)
        await writer.drain()
        data = await _read_until_eof(reader)
        writer.close()
        # One PRELOGIN response only; the repeats close the connection.
        assert data.count(b"\x04\x01") <= 2
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)
    logins = [a for a in await _alerts() if a.event_type == "mssql_login_attempt"]
    assert len(logins) == 1
