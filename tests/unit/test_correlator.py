"""Unit tests for the attack campaign correlator."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from honeypot_mcp.analysis.correlator import detect_campaigns
from honeypot_mcp.storage.models import AlertSeverity


def _make_alert(ip: str, event_type: str, minutes_offset: int) -> MagicMock:
    a = MagicMock()
    a.source_ip = ip
    a.event_type = event_type
    a.honeypot_id = 1
    a.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes_offset)
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
