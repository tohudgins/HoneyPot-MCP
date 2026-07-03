"""Reporter rendering — security-focused tests.

Attacker-controlled fields (IPs, event types, payload values) flow into the
report unchanged. These tests confirm the renderer can never let those fields
escape into executable HTML or break the surrounding Markdown table.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from honeypot_mcp.analysis.reporter import generate


def _alert(ip: str, event_type: str, severity: str = "high", payload: dict | None = None):
    a = MagicMock()
    a.source_ip = ip
    a.event_type = event_type
    a.severity = MagicMock()
    a.severity.value = severity
    a.payload = payload or {}
    a.timestamp = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
    return a


@pytest.mark.asyncio
async def test_html_report_escapes_malicious_ip():
    malicious_ip = "<script>alert('xss')</script>"
    alerts = [_alert(malicious_ip, "ssh_login_failed")]
    html = await generate(
        title="Test Report",
        alerts=alerts,
        stats={},
        target_ip=None,
        format="html",
    )
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


@pytest.mark.asyncio
async def test_html_report_escapes_malicious_event_type():
    # The dangerous payload — `<img onerror=...>` — would execute JS if rendered raw.
    # Once `<` is escaped to `&lt;`, the browser treats it as inert text.
    alerts = [_alert("1.2.3.4", '"><img src=x onerror=alert(1)>')]
    html = await generate(title="Test", alerts=alerts, stats={}, target_ip=None, format="html")
    # The unescaped tag must not survive into the document.
    assert "<img src=x" not in html
    # And the escaped form must be present.
    assert "&lt;img src=x" in html


@pytest.mark.asyncio
async def test_markdown_report_escapes_pipes_in_cells():
    # Pipe in event_type would otherwise break the table layout
    alerts = [_alert("1.2.3.4", "evt|injected|extra_col")]
    md = await generate(title="Test", alerts=alerts, stats={}, target_ip=None, format="markdown")
    assert "evt\\|injected\\|extra_col" in md


@pytest.mark.asyncio
async def test_html_report_with_no_alerts_renders():
    html = await generate(title="Empty Report", alerts=[], stats={}, target_ip=None, format="html")
    assert "Empty Report" in html
    assert "Total Alerts" in html


@pytest.mark.asyncio
async def test_report_renders_ip_intelligence_section():
    """An IP-scoped report with an intel block must surface geo/ASN/reputation/
    risk and recommendations in both HTML and Markdown."""
    intel = {
        "risk_score": 82,
        "risk_level": "CRITICAL",
        "geoip": {
            "available": True,
            "country": "Germany",
            "city": "Nuremberg",
            "asn": 24940,
            "as_org": "Hetzner Online GmbH",
            "reverse_dns": "static.example.your-server.de",
        },
        "virustotal": {"reputation": -34, "malicious_votes": 8, "detection_ratio": "8/89"},
        "abuseipdb": {
            "abuse_confidence_score": 100,
            "total_reports": 421,
            "isp": "Hetzner Online GmbH",
            "usage_type": "Data Center/Web Hosting/Transit",
        },
        "recommendations": ["Block this IP at the perimeter firewall immediately."],
    }
    alerts = [_alert("1.2.3.4", "ssh_login_failed")]
    for fmt in ("html", "markdown"):
        out = await generate(
            title="Attacker 1.2.3.4",
            alerts=alerts,
            stats={},
            target_ip="1.2.3.4",
            format=fmt,
            intel=intel,
        )
        assert "IP Intelligence" in out
        assert "AS24940" in out
        assert "Hetzner" in out
        assert "8/89" in out
        assert "100" in out  # abuse confidence
        assert "static.example.your-server.de" in out
        assert "Block this IP at the perimeter" in out


@pytest.mark.asyncio
async def test_report_without_intel_has_no_intel_section():
    """Reports with no intel block (unscoped, or enrichment unavailable) must
    not render an empty IP Intelligence section."""
    alerts = [_alert("1.2.3.4", "ssh_login_failed")]
    html = await generate(title="T", alerts=alerts, stats={}, target_ip=None, format="html")
    assert "IP Intelligence" not in html


@pytest.mark.asyncio
async def test_report_intel_reverse_dns_is_escaped():
    """Reverse-DNS is attacker-influenced (they can set their own PTR), so it
    must be escaped in HTML like every other untrusted field."""
    intel = {
        "risk_score": 10,
        "risk_level": "LOW",
        "geoip": {"available": True, "reverse_dns": "<script>alert(1)</script>.evil"},
        "virustotal": {"available": False},
        "abuseipdb": {"available": False},
        "recommendations": [],
    }
    html = await generate(
        title="T",
        alerts=[_alert("1.2.3.4", "x")],
        stats={},
        target_ip="1.2.3.4",
        format="html",
        intel=intel,
    )
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)" in html
