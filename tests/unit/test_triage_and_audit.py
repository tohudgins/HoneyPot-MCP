"""Tests for the SOC triage workflow and the control-plane audit trail.

Both exist because of how this server is actually operated: alerts arrive in
bursts (a single scanner sweep is hundreds of rows), and every state-changing
action is taken by a language model rather than a human clicking a button.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    """Point the artifact directory at a temp dir.

    Export tools confine writes to `reports_dir` (a security boundary — see
    tests/unit/test_security_boundaries.py), so tests move the directory rather
    than writing outside it.
    """
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path, raising=False)
    return tmp_path


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


async def _seed(
    ip: str = "203.0.113.7",
    count: int = 1,
    event_type: str = "http_probe",
    severity: str = "low",
    hours_ago: float = 0.1,
) -> list[int]:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ids = []
    async with get_session() as session:
        for _ in range(count):
            a = Alert(
                source_ip=ip,
                event_type=event_type,
                payload={},
                severity=AlertSeverity(severity),
                timestamp=datetime.now(UTC) - timedelta(hours=hours_ago),
            )
            session.add(a)
            await session.flush()
            ids.append(a.id)
    return ids


# ── Bulk triage ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bulk_triage_by_filter_clears_a_scanner_sweep():
    """The case that motivated this: one scanner produces hundreds of alerts,
    and acknowledging them one call at a time is not a workflow."""
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    await _seed(ip="185.220.101.5", count=150)
    await _seed(ip="198.51.100.9", count=5)

    result = await alerts_acknowledge(
        source_ip="185.220.101.5",
        disposition="benign",
        note="known Tor exit node",
        analyst="tyler",
    )
    assert result["acknowledged"] == 150
    assert result["disposition"] == "benign"
    assert result["analyst"] == "tyler"

    # The other IP is untouched.
    from honeypot_mcp.tools.alerts import alerts_recent

    others = await alerts_recent(source_ip="198.51.100.9")
    assert all("acknowledged" not in a for a in others["alerts"])


@pytest.mark.asyncio
async def test_triage_by_explicit_ids():
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    ids = await _seed(count=4)
    result = await alerts_acknowledge(alert_ids=ids[:2], disposition="true_positive")
    assert result["acknowledged"] == 2


@pytest.mark.asyncio
async def test_triage_requires_a_selection():
    """An unfiltered call must not clear the board."""
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    await _seed(count=10)
    result = await alerts_acknowledge(disposition="benign")
    assert "error" in result


@pytest.mark.asyncio
async def test_triage_caps_and_says_so():
    """An over-broad filter is capped, and the caller is told there is more —
    silently triaging thousands of alerts is not a recoverable mistake."""
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    await _seed(ip="192.0.2.50", count=25)
    result = await alerts_acknowledge(source_ip="192.0.2.50", max_alerts=10)
    assert result["acknowledged"] == 10
    assert result["capped"] is True
    assert "note" in result


@pytest.mark.asyncio
async def test_triage_records_who_what_and_why():
    from honeypot_mcp.tools.alerts import alerts_acknowledge, alerts_get

    ids = await _seed(count=1)
    await alerts_acknowledge(
        alert_ids=ids,
        disposition="false_positive",
        note="our own vuln scanner",
        analyst="alice",
    )

    detail = await alerts_get(ids[0])
    assert detail["acknowledged"] is True
    assert detail["disposition"] == "false_positive"
    assert detail["triage_note"] == "our own vuln scanner"
    assert detail["triaged_by"] == "alice"
    assert detail["triaged_at"] is not None


@pytest.mark.asyncio
async def test_disposition_visible_in_triage_list():
    """A shift must be able to see what the previous one already resolved."""
    from honeypot_mcp.tools.alerts import alerts_acknowledge, alerts_recent

    ids = await _seed(count=1)
    await alerts_acknowledge(alert_ids=ids, disposition="benign")

    row = (await alerts_recent())["alerts"][0]
    assert row["acknowledged"] is True
    assert row["disposition"] == "benign"


@pytest.mark.asyncio
async def test_triage_window_and_severity_filters():
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    await _seed(count=3, severity="critical", hours_ago=0.5)
    await _seed(count=4, severity="low", hours_ago=0.5)
    await _seed(count=5, severity="critical", hours_ago=100)

    result = await alerts_acknowledge(severity="critical", since_hours=1, disposition="benign")
    assert result["acknowledged"] == 3


@pytest.mark.asyncio
async def test_triage_rejects_bad_window():
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    assert "error" in await alerts_acknowledge(source_ip="1.1.1.1", since_hours=0)


# ── Audit trail ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_destructive_actions_are_audited():
    """alerts_prune can delete months of evidence; it must leave a trace."""
    from honeypot_mcp.tools.alerts import alerts_prune, audit_log_search

    await _seed(count=3, hours_ago=24 * 200)
    await alerts_prune(older_than_days=30)

    log = await audit_log_search(tool="alerts_prune")
    assert log["count"] == 1
    entry = log["actions"][0]
    assert "deleted" in entry["summary"]
    assert entry["outcome"] == "ok"
    assert entry["arguments"]["older_than_days"] == 30


@pytest.mark.asyncio
async def test_audit_log_filters_by_tool_and_window():
    from honeypot_mcp.tools.alerts import alerts_acknowledge, audit_log_search

    await _seed(ip="203.0.113.99", count=2)
    await alerts_acknowledge(source_ip="203.0.113.99", disposition="benign")

    assert (await audit_log_search(tool="alerts_acknowledge"))["count"] == 1
    assert (await audit_log_search(tool="honeypot_deploy"))["count"] == 0
    assert (await audit_log_search(since_hours=1))["count"] >= 1
    assert (await audit_log_search(target="203.0.113.99"))["count"] == 1


@pytest.mark.asyncio
async def test_audit_log_empty_result_explains_itself():
    from honeypot_mcp.tools.alerts import audit_log_search

    result = await audit_log_search()
    assert result["count"] == 0
    assert "state-changing" in result["note"]


@pytest.mark.asyncio
async def test_audit_never_records_secrets():
    """Arguments are logged so an operator can see what was requested, which
    means anything credential-shaped has to be redacted on the way in."""
    from honeypot_mcp.tools._audit import redact_arguments

    redacted = redact_arguments(
        {
            "url": "https://splunk.example.com",
            "hmac_secret": "super-secret-value",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "password": "hunter2",
            "nested": {"auth_token": "abc123", "label": "prod"},
            "count": 5,
        }
    )
    assert redacted["url"] == "https://splunk.example.com"
    assert redacted["count"] == 5
    assert redacted["nested"]["label"] == "prod"
    for hidden in ("hmac_secret", "api_key", "password"):
        assert redacted[hidden] == "[redacted]"
    assert redacted["nested"]["auth_token"] == "[redacted]"
    assert "super-secret-value" not in str(redacted)
    assert "hunter2" not in str(redacted)


@pytest.mark.asyncio
async def test_audit_failure_never_breaks_the_action(monkeypatch):
    """An unwritable audit table must not stop an operator from acting."""
    from honeypot_mcp.tools import _audit

    def _explode(*_args, **_kwargs):
        raise RuntimeError("audit table unavailable")

    monkeypatch.setattr(_audit, "get_session", _explode, raising=False)
    # Must not raise.
    await _audit.record_action("honeypot_stop", "stopped something")


@pytest.mark.asyncio
async def test_audit_records_failed_actions_too():
    from honeypot_mcp.tools._audit import record_action
    from honeypot_mcp.tools.alerts import audit_log_search

    await record_action(
        "honeypot_deploy",
        "failed to deploy ssh honeypot 'web-01'",
        target="web-01",
        outcome="error",
        error="port already in use",
    )
    entry = (await audit_log_search(outcome="error"))["actions"][0]
    assert entry["outcome"] == "error"
    assert "port already in use" in entry["error"]


# ── Report artifact ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_report_writes_a_file_with_headline_figures(reports_dir):
    from honeypot_mcp.tools.analysis import generate_report

    await _seed(count=5, severity="high")
    dest = reports_dir / "r.md"
    result = await generate_report(format="markdown", output_path="r.md")

    assert result["path"] == str(dest)
    assert result["alerts_analysed"] == 5
    assert result["by_severity"] == {"high": 5}
    assert dest.exists()
    assert "html" not in dest.read_text()[:200].lower()


@pytest.mark.asyncio
async def test_generate_report_validates_ip_and_window():
    from honeypot_mcp.tools.analysis import generate_report

    assert "error" in await generate_report(ip="not-an-ip")
    assert "error" in await generate_report(since_hours=-1)
