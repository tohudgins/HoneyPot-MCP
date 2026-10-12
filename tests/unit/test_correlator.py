"""Unit tests for the attack campaign correlator."""

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.analysis.correlator import detect_campaigns  # noqa: E402


def _make_alert(ip: str, event_type: str, minutes_offset: int) -> MagicMock:
    a = MagicMock()
    a.source_ip = ip
    a.event_type = event_type
    a.honeypot_id = 1
    a.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC) + timedelta(minutes=minutes_offset)
    return a


@pytest.mark.asyncio
async def test_detects_campaign_with_multiple_ips():
    alerts = [
        _make_alert("1.1.1.1", "ssh_brute_force", 0),
        _make_alert("2.2.2.2", "ssh_brute_force", 5),
        _make_alert("3.3.3.3", "ssh_brute_force", 10),
        _make_alert("4.4.4.4", "ssh_brute_force", 15),
    ]
    campaigns = await detect_campaigns(alerts, window_minutes=60, min_sources=3)
    assert len(campaigns) >= 1
    assert campaigns[0]["unique_source_ips"] >= 3
    assert campaigns[0]["event_type"] == "ssh_brute_force"


@pytest.mark.asyncio
async def test_no_campaign_below_min_sources():
    alerts = [
        _make_alert("1.1.1.1", "ssh_brute_force", 0),
        _make_alert("2.2.2.2", "ssh_brute_force", 5),
    ]
    campaigns = await detect_campaigns(alerts, window_minutes=60, min_sources=3)
    assert len(campaigns) == 0


@pytest.mark.asyncio
async def test_separate_event_types_are_separate_campaigns():
    alerts = [
        _make_alert("1.1.1.1", "ssh_brute_force", 0),
        _make_alert("2.2.2.2", "ssh_brute_force", 5),
        _make_alert("3.3.3.3", "ssh_brute_force", 10),
        _make_alert("4.4.4.4", "http_probe", 0),
        _make_alert("5.5.5.5", "http_probe", 5),
        _make_alert("6.6.6.6", "http_probe", 10),
    ]
    campaigns = await detect_campaigns(alerts, window_minutes=60, min_sources=3)
    event_types = {c["event_type"] for c in campaigns}
    assert "ssh_brute_force" in event_types
    assert "http_probe" in event_types


@pytest.mark.asyncio
async def test_empty_alerts_returns_empty():
    campaigns = await detect_campaigns([], window_minutes=60, min_sources=3)
    assert campaigns == []


@pytest.mark.asyncio
async def test_earlier_smaller_window_deduplicated_against_later_superset():
    """Windows for one event_type are produced in chronological order, not
    size order — an attacker who reappears later shows up in a second,
    larger window whose IP set is a strict superset of the first. The
    smaller, earlier window must not survive dedup just because it was
    discovered first; only the largest (here, the later) window should be
    reported, per the module's own "keep the largest" contract."""
    alerts = [
        # Window 1 (t=0..10): 1.1.1.1, 2.2.2.2, 3.3.3.3
        _make_alert("1.1.1.1", "ssh_brute_force", 0),
        _make_alert("2.2.2.2", "ssh_brute_force", 5),
        _make_alert("3.3.3.3", "ssh_brute_force", 10),
        # Window 2 (t=70..85): the same three IPs return, plus a new one —
        # a strict superset of window 1's IP set.
        _make_alert("1.1.1.1", "ssh_brute_force", 70),
        _make_alert("2.2.2.2", "ssh_brute_force", 75),
        _make_alert("3.3.3.3", "ssh_brute_force", 80),
        _make_alert("4.4.4.4", "ssh_brute_force", 85),
    ]
    campaigns = await detect_campaigns(alerts, window_minutes=60, min_sources=3)

    ssh_campaigns = [c for c in campaigns if c["event_type"] == "ssh_brute_force"]
    assert len(ssh_campaigns) == 1, (
        f"expected only the larger superset window to survive dedup, got {ssh_campaigns}"
    )
    assert ssh_campaigns[0]["unique_source_ips"] == 4
    assert set(ssh_campaigns[0]["source_ips"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}


# ── analyze_campaign reads the whole run, not the latest alerts ──────────────


@pytest.fixture
async def db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(rows: list[tuple[str, str, datetime, int]]) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for ip, event_type, at, count in rows:
            for i in range(count):
                session.add(
                    Alert(
                        source_ip=ip,
                        event_type=event_type,
                        severity=AlertSeverity.MEDIUM,
                        timestamp=at + timedelta(seconds=i % 3000),
                        payload={},
                        honeypot_id=None,
                    )
                )


def _hours_ago(n: int) -> datetime:
    return datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=n)


async def test_a_campaign_is_found_even_after_a_flood_buries_it_in_the_latest_alerts(db):
    """It used to correlate only the newest 5,000 alerts. On the real run one source's flood filled
    that, so the only 'campaigns' reported were from the last few minutes of a day-long run."""
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = [(f"203.0.113.{n}", "redis_config_set", _hours_ago(6), 2) for n in range(1, 5)]
    rows.append(("198.51.100.9", "sip_request", _hours_ago(1), 6000))  # the flood, newest
    await _seed(rows)

    out = await analyze_campaign()

    redis = [c for c in out["campaigns"] if c["event_type"] == "redis_config_set"]
    assert len(redis) == 1
    assert redis[0]["unique_source_ips"] == 4 and redis[0]["total_events"] == 8
    assert redis[0]["source_ips"] == [f"203.0.113.{n}" for n in range(1, 5)]
    assert out["window"] == "whole run" and "hourly" in out["resolution"]


async def test_the_window_spans_whole_hours_and_since_hours_narrows_the_run(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = [
        ("203.0.113.1", "ssh_login_failed", _hours_ago(6), 3),
        ("203.0.113.2", "ssh_login_failed", _hours_ago(6), 3),
        ("203.0.113.3", "ssh_login_failed", _hours_ago(5), 3),
        ("203.0.113.4", "ssh_login_failed", _hours_ago(5), 3),
    ]
    await _seed(rows)

    one_hour = await analyze_campaign(window_minutes=60, min_sources=3)
    two_hours = await analyze_campaign(window_minutes=120, min_sources=3)
    recent = await analyze_campaign(window_minutes=120, min_sources=3, since_hours=3)

    assert one_hour["campaigns_total"] == 0, "two sources an hour is not a campaign at min 3"
    assert two_hours["campaigns_total"] == 1 and two_hours["campaigns"][0]["unique_source_ips"] == 4
    assert two_hours["campaigns"][0]["total_events"] == 12
    assert recent["campaigns_total"] == 0, "the campaign is older than the window"


async def test_the_result_says_when_it_returns_fewer_campaigns_than_exist(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = []
    for n in range(4):
        for ip in range(3):
            rows.append((f"203.0.113.{ip + 1}", f"event_{n}", _hours_ago(3), 1))
    await _seed(rows)

    out = await analyze_campaign(limit=2)

    assert out["campaigns_total"] == 4 and out["count"] == 2 and len(out["campaigns"]) == 2
    assert "error" in await analyze_campaign(since_hours=0)
