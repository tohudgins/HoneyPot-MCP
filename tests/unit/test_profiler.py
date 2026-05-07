"""Unit tests for the attacker profiler."""

import pytest
from unittest.mock import MagicMock
from datetime import datetime, timezone

from honeypot_mcp.analysis.profiler import build_profile, _calculate_risk, _risk_level


def _alert(ip, event_type, severity="medium"):
    a = MagicMock()
    a.source_ip = ip
    a.event_type = event_type
    a.severity = MagicMock()
    a.severity.value = severity
    a.payload = {}
    a.timestamp = datetime(2024, 1, 1, tzinfo=timezone.utc)
    return a


@pytest.mark.asyncio
async def test_profile_contains_required_fields():
    alerts = [_alert("1.2.3.4", "ssh_login_failed", "high")]
    profile = await build_profile(
        ip="1.2.3.4",
        alerts=alerts,
        events=[],
        geoip={"country": "Russia", "country_code": "RU"},
        vt={"available": False},
        abuse={"available": False},
    )
    assert profile["ip"] == "1.2.3.4"
    assert "risk_score" in profile
    assert "risk_level" in profile
    assert "mitre_techniques" in profile
    assert "recommendations" in profile
    assert "abuseipdb" in profile
    assert profile["total_events"] == 1


@pytest.mark.asyncio
async def test_high_abuse_score_increases_risk():
    score_low = _calculate_risk(
        vt={"available": True, "reputation": 0, "malicious_votes": 0},
        abuse={"available": True, "abuse_confidence_score": 0},
        ttps=[],
        sev={},
        event_count=1,
    )
    score_high = _calculate_risk(
        vt={"available": True, "reputation": -50, "malicious_votes": 10},
        abuse={"available": True, "abuse_confidence_score": 95},
        ttps=[{"tactic": "Initial Access"}] * 5,
        sev={"critical": 3},
        event_count=100,
    )
    assert score_high > score_low


def test_risk_level_boundaries():
    assert _risk_level(0) == "LOW"
    assert _risk_level(24) == "LOW"
    assert _risk_level(25) == "MEDIUM"
    assert _risk_level(50) == "HIGH"
    assert _risk_level(75) == "CRITICAL"
    assert _risk_level(100) == "CRITICAL"
