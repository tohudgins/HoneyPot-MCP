"""Unit tests for the attacker profiler."""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from honeypot_mcp.analysis.profiler import _calculate_risk, _risk_level, build_profile


def _alert(ip, event_type, severity="medium"):
    a = MagicMock()
    a.source_ip = ip
    a.event_type = event_type
    a.severity = MagicMock()
    a.severity.value = severity
    a.payload = {}
    a.timestamp = datetime(2024, 1, 1, tzinfo=UTC)
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


# ── Risk-score calibration ───────────────────────────────────────────────────
#
# These pin the two properties the scoring has to hold for a deception
# platform. They are written as relative/threshold assertions rather than exact
# numbers so the weights can be retuned without churn — what must not change is
# the ordering and the reachability of each band.


def _alerts(n, severity, event_type):
    from datetime import UTC, datetime, timedelta

    from honeypot_mcp.storage.models import Alert, AlertSeverity

    return [
        Alert(
            source_ip="1.2.3.4",
            event_type=event_type,
            payload={},
            severity=AlertSeverity(severity),
            timestamp=datetime.now(UTC) - timedelta(minutes=i),
        )
        for i in range(n)
    ]


async def _score(alerts, vt=None, abuse=None):
    from honeypot_mcp.analysis.profiler import build_profile

    profile = await build_profile(
        ip="1.2.3.4", alerts=alerts, events=[], geoip={}, vt=vt or {}, abuse=abuse or {}
    )
    return profile["risk_score"], profile["risk_level"]


@pytest.mark.asyncio
async def test_hands_on_attack_reaches_high_without_any_api_keys():
    """VirusTotal and AbuseIPDB are optional. An attacker who ran an RCE chain
    against a decoy must not be capped at MEDIUM just because no key is set —
    our own capture is stronger evidence than a reputation lookup."""
    score, level = await _score(_alerts(4, "critical", "redis_rce_dropper"))
    assert score >= 50, f"hands-on RCE scored only {score} with no external intel"
    assert level in ("HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_ransom_note_reaches_high_without_api_keys():
    score, level = await _score(_alerts(2, "critical", "mongodb_ransom_note"))
    assert level in ("HIGH", "CRITICAL"), f"ransom note rated {level} ({score})"


@pytest.mark.asyncio
async def test_triggered_honeytoken_dominates_the_score():
    """A planted secret being replayed is the highest-fidelity signal the
    platform produces; it must outrank a large brute-force campaign."""
    token, token_level = await _score(
        _alerts(1, "critical", "honeytoken_triggered_credential_via_ssh")
    )
    brute, _ = await _score(_alerts(50, "high", "ssh_login_failed"))
    assert token > brute
    assert token_level in ("HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_background_noise_stays_low():
    """A loud scanner must not climb the scale on volume alone — otherwise the
    ranking is dominated by whoever is noisiest rather than most dangerous."""
    _score_noise, level = await _score(_alerts(200, "low", "http_probe"))
    assert level == "LOW"


@pytest.mark.asyncio
async def test_external_intel_corroborates_but_does_not_dominate():
    """Perfect-confidence external reports on a mere brute-forcer should raise
    the score without reaching the band reserved for observed compromise."""
    plain, _ = await _score(_alerts(50, "high", "ssh_login_failed"))
    enriched, level = await _score(
        _alerts(50, "high", "ssh_login_failed"),
        vt={"malicious_votes": 40, "reputation": -60, "available": True},
        abuse={"abuse_confidence_score": 100, "available": True},
    )
    assert enriched > plain
    assert level != "CRITICAL"


@pytest.mark.asyncio
async def test_compromise_plus_token_is_critical():
    alerts = _alerts(2, "critical", "honeytoken_triggered_credential_via_ssh") + _alerts(
        3, "critical", "redis_rce_dropper"
    )
    _s, level = await _score(alerts)
    assert level == "CRITICAL"
