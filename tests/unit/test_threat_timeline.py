"""Tests for `threat_timeline`.

Pins two things: the wrapped `{count, events, note}` shape (matching
`alerts_recent`'s convention — a caller must never read a capped list as the
complete picture), and that truncation keeps the most recent events rather
than the oldest. The tool queried `ORDER BY timestamp ASC LIMIT n`, which
silently returned the *oldest* matching events whenever a window held more
than `limit` — the opposite of what "the last N hours" implies.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


async def _add_alert(ip, minutes_ago, event_type="ssh_login_failed"):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ts = datetime.now(UTC) - timedelta(minutes=minutes_ago)
    async with get_session() as session:
        session.add(
            Alert(
                honeypot_id=None,
                source_ip=ip,
                source_port=None,
                event_type=event_type,
                payload={},
                severity=AlertSeverity.HIGH,
                timestamp=ts,
            )
        )


@pytest.mark.asyncio
async def test_timeline_wraps_results_with_count_and_window():
    from honeypot_mcp.tools.analysis import threat_timeline

    await _add_alert("1.2.3.4", minutes_ago=5)
    await _add_alert("1.2.3.4", minutes_ago=10)

    out = await threat_timeline(ip="1.2.3.4", hours=24)
    assert out["count"] == 2
    assert len(out["events"]) == 2
    assert out["window"] == "last 24h"
    assert "note" not in out


@pytest.mark.asyncio
async def test_timeline_truncation_keeps_the_most_recent_events():
    from honeypot_mcp.tools.analysis import threat_timeline

    ip = "9.9.9.9"
    # 30 events spread over the window; cap at 10 should keep the 10 most
    # recent (minutes_ago 0..9), not the 10 oldest (minutes_ago 20..29).
    for minutes_ago in range(30):
        await _add_alert(ip, minutes_ago=minutes_ago)

    out = await threat_timeline(ip=ip, hours=24, limit=10)
    assert out["count"] == 10
    assert "note" in out

    timestamps = [e["timestamp"] for e in out["events"]]
    assert timestamps == sorted(timestamps), "events must be in chronological order"

    newest_kept = datetime.now(UTC) - timedelta(minutes=9)
    oldest_dropped = datetime.now(UTC) - timedelta(minutes=10)
    kept_range_start = datetime.fromisoformat(out["events"][0]["timestamp"])
    assert kept_range_start >= newest_kept - timedelta(seconds=5), (
        "the oldest kept event should still be recent — truncation dropped the "
        f"newest events instead of the oldest ({out['events'][0]})"
    )
    assert kept_range_start > oldest_dropped - timedelta(seconds=5)
