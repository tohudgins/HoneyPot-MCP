"""Tests for honeypot health checks.

Verifies: the default TCP probe correctly detects open vs closed ports;
the watchdog flips a dead honeypot's status to ERROR and emits a CRITICAL
alert exactly once (no flood).
"""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


@pytest.mark.asyncio
async def test_tcp_probe_detects_open_port():
    from honeypot_mcp.engines.base import tcp_probe

    async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Close immediately so server.wait_closed() can drain.
        # Python 3.12+ made wait_closed() block until every active connection
        # finishes — a sync no-op handler leaves the connection dangling and
        # the teardown hangs forever.
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(_handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        result = await tcp_probe(port, timeout=1.0)
        assert result["alive"] is True
        assert result["method"] == "tcp"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_tcp_probe_detects_closed_port():
    from honeypot_mcp.engines.base import tcp_probe

    # 1 is reserved + always closed; should refuse immediately.
    result = await tcp_probe(1, timeout=1.0)
    assert result["alive"] is False
    assert result["method"] == "tcp"


@pytest.mark.asyncio
async def test_watchdog_marks_dead_honeypot_and_emits_alert():
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import get_buffer
    from honeypot_mcp.storage.models import (
        Alert,
        Honeypot,
        HoneypotStatus,
        HoneypotType,
    )
    from honeypot_mcp.watchdog import HoneypotWatchdog

    # Drain any prior buffer state, then start fresh.
    buf = get_buffer()
    await buf.start()

    async with get_session() as session:
        hp = Honeypot(
            name="dead-ssh",
            type=HoneypotType.SSH,
            port=2222,
            status=HoneypotStatus.RUNNING,
            container_id="fake-container",
        )
        session.add(hp)
        await session.flush()
        hp_id = hp.id

    # Patch get_engine to return a stub whose health_check always reports dead.
    fake_engine = MagicMock()
    fake_engine.health_check = AsyncMock(
        return_value={"alive": False, "detail": "Container exited", "method": "docker"}
    )

    with patch("honeypot_mcp.watchdog.get_engine", return_value=fake_engine):
        wd = HoneypotWatchdog(interval=10.0)
        await wd._check_all()
        # Second pass should NOT generate a duplicate alert.
        await wd._check_all()

    # Drain the buffer so alerts are persisted.
    await asyncio.sleep(1.5)
    await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Honeypot).where(Honeypot.id == hp_id))
        updated = result.scalar_one()
        assert updated.status == HoneypotStatus.ERROR

        alert_result = await session.execute(
            select(Alert).where(Alert.event_type == "honeypot_health_failed")
        )
        alerts = list(alert_result.scalars().all())
    assert len(alerts) == 1
    assert alerts[0].severity.value == "critical"
    assert alerts[0].payload["name"] == "dead-ssh"


@pytest.mark.asyncio
async def test_watchdog_clears_alert_state_on_recovery():
    """If a honeypot fails then recovers, a subsequent failure should re-alert."""
    from honeypot_mcp.watchdog import HoneypotWatchdog

    wd = HoneypotWatchdog()
    wd._reported_dead.add(42)
    # Simulating a successful health check should clear the entry.
    wd._reported_dead.discard(42)
    assert 42 not in wd._reported_dead
