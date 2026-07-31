"""Unit tests for the attack campaign correlator."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from honeypot_mcp.analysis.correlator import detect_campaigns


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
