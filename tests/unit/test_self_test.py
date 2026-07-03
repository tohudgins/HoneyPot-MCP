"""Tests for honeypot_self_test.

Hard to fake the entire engine pipeline in unit tests, so we test the parts
that have the most logic risk:
- The matcher (marker-in-payload detection) finds a real alert
- A non-existent honeypot returns a clean error
- A stopped honeypot returns a clean error
- The HTTP probe end-to-end against a real in-process HTTP engine
"""

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.suppression import _rate_state, invalidate_rule_cache

    event_buffer.reset_for_tests()
    await init_db()
    invalidate_rule_cache()
    _rate_state.clear()
    buf = event_buffer.get_buffer()
    await buf.start()
    yield
    await buf.stop()
    event_buffer.reset_for_tests()
    await close_db()


@pytest.mark.asyncio
async def test_self_test_unknown_honeypot_returns_error():
    from honeypot_mcp.tools.honeypot import honeypot_self_test

    result = await honeypot_self_test("does-not-exist")
    assert "error" in result


@pytest.mark.asyncio
async def test_self_test_stopped_honeypot_returns_error():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_self_test

    async with get_session() as session:
        session.add(
            Honeypot(
                name="stopped-hp",
                type=HoneypotType.HTTP,
                port=18099,
                status=HoneypotStatus.STOPPED,
            )
        )

    result = await honeypot_self_test("stopped-hp")
    assert "error" in result
    assert "not running" in result["error"]


@pytest.mark.asyncio
async def test_self_test_http_end_to_end():
    """Spin up a real HTTP engine, probe it, confirm the alert with our marker
    is found. This exercises the FULL pipeline: probe → engine → buffer → DB."""
    # Find a free local port
    import socket

    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_self_test

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    # Register the honeypot in DB
    async with get_session() as session:
        hp = Honeypot(
            name="test-http",
            type=HoneypotType.HTTP,
            port=port,
            status=HoneypotStatus.RUNNING,
        )
        session.add(hp)
        await session.flush()

    # Start the actual HTTP engine on the port
    engine = HTTPEngine()
    try:
        container_id = await engine.start("test-http", port, {})
        async with get_session() as session:
            from sqlalchemy import update

            await session.execute(
                update(Honeypot)
                .where(Honeypot.name == "test-http")
                .values(container_id=container_id)
            )

        # Run the self-test — should find its own probe
        result = await honeypot_self_test("test-http", timeout_seconds=10)

        assert result.get("probe_sent") is True, result
        assert result.get("alert_received") is True, result
        assert result["probe_marker"] in result.get("alert_event_type", "") or result.get(
            "alert_id"
        )
    finally:
        # Clean up the engine
        for cid in list(engine._runners.keys()):
            await engine.stop(cid)


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.parametrize(
    ("engine_path", "engine_cls", "hp_type_name"),
    [
        ("honeypot_mcp.engines.redis", "RedisEngine", "REDIS"),
        ("honeypot_mcp.engines.mysql", "MySQLEngine", "MYSQL"),
        ("honeypot_mcp.engines.rdp", "RDPEngine", "RDP"),
        ("honeypot_mcp.engines.vnc", "VNCEngine", "VNC"),
        ("honeypot_mcp.engines.elasticsearch", "ElasticsearchEngine", "ELASTICSEARCH"),
        ("honeypot_mcp.engines.smb", "SMBEngine", "SMB"),
        ("honeypot_mcp.engines.postgresql", "PostgreSQLEngine", "POSTGRESQL"),
        ("honeypot_mcp.engines.mongodb", "MongoDBEngine", "MONGODB"),
        ("honeypot_mcp.engines.mssql", "MSSQLEngine", "MSSQL"),
    ],
)
@pytest.mark.asyncio
async def test_self_test_in_process_engines_end_to_end(engine_path, engine_cls, hp_type_name):
    """Every in-process engine must have a working self-test probe: start the
    real engine, probe it, confirm the marker-bearing alert lands. Guards
    against a new engine shipping without a matching probe."""
    import importlib

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_self_test

    engine = getattr(importlib.import_module(engine_path), engine_cls)()
    hp_type = getattr(HoneypotType, hp_type_name)
    port = _free_port()
    name = f"selftest-{hp_type_name.lower()}"

    async with get_session() as session:
        hp = Honeypot(name=name, type=hp_type, port=port, status=HoneypotStatus.RUNNING)
        session.add(hp)
        await session.flush()

    container_id = await engine.start(name, port, {})
    try:
        async with get_session() as session:
            from sqlalchemy import update

            await session.execute(
                update(Honeypot).where(Honeypot.name == name).values(container_id=container_id)
            )

        result = await honeypot_self_test(name, timeout_seconds=10)
        assert result.get("probe_sent") is True, result
        assert result.get("alert_received") is True, result
    finally:
        await engine.stop(container_id)
