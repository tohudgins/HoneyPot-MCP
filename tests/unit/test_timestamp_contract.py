"""Every timestamp this platform emits must be unambiguous.

An offset-less ISO-8601 string is not merely ambiguous — consumers actively
disagree about it. JavaScript's `new Date()` reads a date-time with no offset
as *local* time per the ES spec, so the operations console rendered its header
clock (from an aware timestamp) and its event feed (from naive ones) four hours
apart on a UTC-4 host, with the newest event displayed in the future.

Root cause was a dialect split: the columns are declared `timezone=True`, which
PostgreSQL honours via TIMESTAMPTZ while SQLite — the default backend — has no
timezone storage and hands back naive datetimes. `UTCDateTime` closes it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

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


async def _one_alert(**overrides):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    fields = dict(
        source_ip="203.0.113.9",
        event_type="ssh_login_attempt",
        payload={"username": "root"},
        severity=AlertSeverity.HIGH,
        timestamp=datetime.now(UTC) - timedelta(minutes=5),
    )
    fields.update(overrides)
    async with get_session() as session:
        alert = Alert(**fields)
        session.add(alert)
        await session.flush()
        return alert.id


async def test_alert_timestamps_come_back_timezone_aware():
    """The core of it: SQLite used to drop the tzinfo silently."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    await _one_alert()
    async with get_session() as session:
        alert = (await session.execute(select(Alert))).scalars().first()

    assert alert is not None
    assert alert.timestamp.tzinfo is not None, "naive datetime escaped the ORM layer"
    assert alert.timestamp.utcoffset() == timedelta(0)


async def test_isoformat_carries_an_offset():
    """This exact string is what reaches a browser, a SIEM and an MCP client."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    await _one_alert()
    async with get_session() as session:
        alert = (await session.execute(select(Alert))).scalars().first()

    rendered = alert.timestamp.isoformat()
    assert rendered.endswith("+00:00"), f"offset-less timestamp would be read as local: {rendered}"


async def test_console_feed_and_header_share_one_timescale():
    """The visible bug: header clock aware, feed naive, four hours apart. Both
    must now be offset-bearing so a browser puts them on the same timeline."""
    from honeypot_mcp.console.server import _overview

    await _one_alert()
    overview = await _overview(24.0)

    assert overview["generated_at"].endswith("+00:00")
    assert overview["feed"], "expected the seeded alert in the feed"
    for row in overview["feed"]:
        assert row["t"].endswith("+00:00"), f"naive feed timestamp: {row['t']}"
    for point in overview["series"]["points"]:
        assert point["t"].endswith("+00:00")

    # And the ordering a human would sanity-check: nothing in the feed may be
    # newer than the moment the payload was generated.
    generated = datetime.fromisoformat(overview["generated_at"])
    newest = max(datetime.fromisoformat(r["t"]) for r in overview["feed"])
    assert newest <= generated, "an event dated after 'now' means the timescales disagree"


async def test_naive_input_is_stored_as_utc_not_reinterpreted():
    """Defensive: anything that still hands us a naive datetime is taken as UTC
    rather than silently shifted by the server's local offset."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    naive = datetime(2026, 5, 20, 12, 0, 0)
    await _one_alert(timestamp=naive)
    async with get_session() as session:
        alert = (await session.execute(select(Alert))).scalars().first()

    assert alert.timestamp == datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC)
