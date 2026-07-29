"""Losing captured events must never be quiet.

The ingest queue is unbounded, so nothing is dropped on the way in. There is
exactly one way a captured event disappears: shutdown drains for a bounded
time, and whatever is still queued when that expires is discarded.

A load test found that path the hard way — 50,000 events queued, 40,850
silently discarded, and the only clue was "Event buffer flusher did not exit
cleanly", which names neither the loss nor its size. Deleted evidence with no
record of the deletion is the worst failure mode this system has, so the count
is now an ERROR and the backlog is exposed as a metric that moves before a
restart turns it into loss.

Measured for reference: ~1,550 events/sec committed against SQLite, so the
5-second default drains any backlog a real honeypot builds. The case that needs
a longer timeout is a slow or remote database.
"""

from __future__ import annotations

import asyncio
import logging
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()


def _event(i: int):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=None,
        source_ip="192.0.2.10",
        source_port=i % 65535,
        event_type="ssh_login_failed",
        payload={"seq": i},
        severity=AlertSeverity.MEDIUM,
    )


async def _stored() -> int:
    from sqlalchemy import func, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return (await session.execute(select(func.count(Alert.id)))).scalar() or 0


async def test_a_normal_backlog_is_drained_without_loss():
    """Shutdown is not allowed to throw away work it had time to finish."""
    from honeypot_mcp.storage import event_buffer

    buffer = event_buffer.get_buffer()
    await buffer.start()
    for i in range(500):
        await buffer.submit(_event(i))
    await buffer.stop()

    assert await _stored() == 500


async def test_abandoned_events_are_reported_with_a_count(monkeypatch, caplog):
    """The whole point: an operator must be told how much was thrown away.

    The drain timeout is squeezed to zero so the abandon path is taken
    deterministically, rather than by racing a real backlog.
    """
    from honeypot_mcp import config
    from honeypot_mcp.storage import event_buffer

    monkeypatch.setattr(
        config, "get_settings", lambda: _settings_with(config, shutdown_drain_seconds=0.01)
    )

    buffer = event_buffer.get_buffer()

    async def _never_finishes() -> None:
        await asyncio.sleep(60)

    buffer._task = asyncio.create_task(_never_finishes())
    for i in range(1234):
        await buffer.submit(_event(i))

    with caplog.at_level(logging.ERROR, logger="honeypot_mcp.storage.event_buffer"):
        await buffer.stop()

    messages = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert messages, "abandoning captured events must log at ERROR, not WARNING or below"
    combined = " ".join(messages)
    assert "1234" in combined, f"the number of discarded events must appear: {combined}"
    assert "DISCARDED" in combined
    assert "shutdown_drain_seconds" in combined, "say which knob fixes it"


def _settings_with(config_module, **overrides):
    real = config_module.Settings()
    for key, value in overrides.items():
        object.__setattr__(real, key, value)
    return real


async def test_drain_timeout_is_configurable():
    """A remote database needs longer than a local one; that must be tunable."""
    from honeypot_mcp.config import Settings

    assert Settings().shutdown_drain_seconds == 5.0
    assert Settings(shutdown_drain_seconds=30.0).shutdown_drain_seconds == 30.0


async def test_queue_depth_is_exposed_as_a_metric():
    """Depth is the leading indicator — it moves before anything is lost."""
    from honeypot_mcp.metrics import _gather_metrics
    from honeypot_mcp.storage import event_buffer

    buffer = event_buffer.get_buffer()
    for i in range(7):
        await buffer.submit(_event(i))  # never started, so nothing drains

    body = await _gather_metrics()
    assert "honeypot_event_queue_depth" in body
    assert "# TYPE honeypot_event_queue_depth gauge" in body
    line = next(ln for ln in body.splitlines() if ln.startswith("honeypot_event_queue_depth "))
    assert line.split()[-1] == "7"
