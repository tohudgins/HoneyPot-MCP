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
