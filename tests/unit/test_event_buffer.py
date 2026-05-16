"""Tests for the asyncio event buffer.

Verifies: events submitted are flushed to the DB; chronological order is
preserved across a batch; stop() drains pending events instead of losing them.
"""

import asyncio
import os
from datetime import UTC

import pytest

# In-memory DB; must be set before any honeypot_mcp imports
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
async def test_buffer_flushes_submitted_events():
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import EventBuffer, PendingEvent
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    buf = EventBuffer(batch_size=10, flush_interval=0.1)
    await buf.start()
    try:
        for i in range(5):
            await buf.submit(
                PendingEvent(
                    honeypot_id=None,
                    source_ip=f"10.0.0.{i}",
                    event_type="ssh_login_failed",
                    payload={"username": "root", "attempt": i},
                    severity=AlertSeverity.HIGH,
                )
            )
        # Wait long enough for the flusher to drain
        await asyncio.sleep(0.5)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).order_by(Alert.id))
        alerts = list(result.scalars().all())
    assert len(alerts) == 5
    assert {a.source_ip for a in alerts} == {f"10.0.0.{i}" for i in range(5)}


@pytest.mark.asyncio
async def test_buffer_preserves_event_timestamps():
    """Each PendingEvent carries its own timestamp, so a batched flush keeps
    chronological order even when many events share one transaction."""
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import EventBuffer, PendingEvent
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    base = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
    buf = EventBuffer(batch_size=20, flush_interval=0.1)
    await buf.start()
    try:
        for i in range(5):
            await buf.submit(
                PendingEvent(
                    honeypot_id=None,
                    source_ip="1.2.3.4",
                    event_type=f"step_{i}",
                    payload={},
                    severity=AlertSeverity.LOW,
                    timestamp=base + timedelta(seconds=i),
                )
            )
        await asyncio.sleep(0.5)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).order_by(Alert.timestamp))
        alerts = list(result.scalars().all())
    assert [a.event_type for a in alerts] == [f"step_{i}" for i in range(5)]


@pytest.mark.asyncio
async def test_buffer_stop_drains_queue():
    """stop() must flush any pending events rather than dropping them on the floor."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import EventBuffer, PendingEvent
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    # Long flush_interval so we know the drain happens because of stop(), not the timer.
    buf = EventBuffer(batch_size=10, flush_interval=5.0)
    await buf.start()
    for i in range(3):
        await buf.submit(
            PendingEvent(
                honeypot_id=None,
                source_ip="9.9.9.9",
                event_type=f"drain_{i}",
                payload={},
                severity=AlertSeverity.MEDIUM,
            )
        )
    await buf.stop()  # Should drain before returning

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.source_ip == "9.9.9.9"))
        alerts = list(result.scalars().all())
    assert len(alerts) == 3
