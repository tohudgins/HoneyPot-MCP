"""The Grafana ATT&CK dashboard must not drift from the ATT&CK mapper.

SQL cannot call Python, so the dashboard needs its own event-type → tactic
mapping — and a hand-maintained second copy drifted exactly the way duplicated
tables always do. It filed SSH/FTP/RDP brute force under Initial Access when
T1110 is Credential Access, and `ssh_file_download` under Exfiltration when
Cowrie means ingress (T1105). Both were bugs `intel/mitre.py` had already
fixed, so the platform disagreed with itself, and the wrong answer was the one
on the wall display.

The SQL is generated now. This test regenerates and compares, so drift fails
CI rather than quietly misinforming an analyst who knows ATT&CK.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "docker" / "grafana" / "dashboards" / "03-mitre-coverage.json"


def _generator():
    sys.path.insert(0, str(ROOT / "scripts"))
    import generate_mitre_dashboard

    return generate_mitre_dashboard


def test_dashboard_matches_the_generator():
    """`uv run python scripts/generate_mitre_dashboard.py` to fix a failure."""
    expected = asyncio.run(_generator().render())
    actual = json.loads(DASHBOARD.read_text())
    assert actual == expected, (
        "03-mitre-coverage.json is out of date with intel/mitre.py — "
        "run scripts/generate_mitre_dashboard.py"
    )


def test_brute_force_is_credential_access_not_initial_access():
    """The specific regression. T1110 is Credential Access; the hand-written
    SQL had `ssh_login%` → Initial Access (it matched ssh_login_failed too)."""
    by_tactic = asyncio.run(_generator().tactic_event_types())
    assert "ssh_login_failed" in by_tactic["Credential Access"]
    assert "ssh_login_failed" not in by_tactic.get("Initial Access", [])


def test_cowrie_file_download_is_ingress_not_exfiltration():
    """Cowrie's `file_download` is the attacker pulling a payload *in* (T1105,
    Command and Control), not data leaving."""
    by_tactic = asyncio.run(_generator().tactic_event_types())
    assert "ssh_file_download" in by_tactic["Command and Control"]
    assert "ssh_file_download" not in by_tactic.get("Exfiltration", [])


def test_coverage_spans_the_catalogue_not_just_the_original_engines():
    """The hand-written CASE predated most of the 25 engines, so newer
    high-value captures fell through to 'Uncategorised' — invisible on a
    dashboard whose entire job is showing what you can detect."""
    by_tactic = asyncio.run(_generator().tactic_event_types())
    covered = {e for events in by_tactic.values() for e in events}
    for event_type in (
        "smb_exploit_attempt",
        "docker_api_container_escape",
        "kubernetes_secret_access",
        "sip_toll_fraud_attempt",
        "memcached_amplification_attempt",
        "mongodb_ransom_note",
    ):
        assert event_type in covered, f"{event_type} is not on the ATT&CK dashboard"
    assert len(by_tactic) >= 10, "a 25-protocol platform should light up most of the kill chain"


@pytest.mark.parametrize("panel", ["Observed tactics (ATT&CK)", "Tactic timeline"])
def test_generated_sql_is_present_and_windowed(panel: str):
    """Every panel must respect the dashboard's own time range, or the numbers
    silently describe a different window than the one on screen."""
    dashboard = json.loads(DASHBOARD.read_text())
    found = [p for p in dashboard["panels"] if p.get("title") == panel]
    assert found, f"panel missing: {panel}"
    for target in found[0]["targets"]:
        sql = target.get("rawQueryText") or target.get("rawSql") or ""
        assert "$__from" in sql and "$__to" in sql


def test_tactic_ids_are_correct():
    """These render on screen next to the tactic name; a wrong TA id is the
    kind of detail that costs an analyst's trust in everything else."""
    from honeypot_mcp.intel.mitre import TACTIC_IDS

    assert TACTIC_IDS["Credential Access"] == "TA0006"
    assert TACTIC_IDS["Initial Access"] == "TA0001"
    assert TACTIC_IDS["Command and Control"] == "TA0011"
    assert TACTIC_IDS["Exfiltration"] == "TA0010"
    assert TACTIC_IDS["Impact"] == "TA0040"
    assert TACTIC_IDS["Reconnaissance"] == "TA0043"


def test_every_declared_signature_event_exists_in_an_engine():
    """`signature_events` drives the coverage map and this dashboard, so a
    typo'd or retired entry makes the platform claim detection it does not
    have — the one thing a coverage view must never do.

    Substring search over the engines package, because event types are often
    built conditionally (`"docker_api_container_escape" if reasons else ...`)
    or retagged at runtime (Telnet rewrites Cowrie's `ssh_*` prefixes), so
    matching on an `event_type=` assignment alone gives false alarms.
    """
    from honeypot_mcp.deception.capabilities import _CAPABILITIES

    engines = ROOT / "src" / "honeypot_mcp" / "engines"
    source = "\n".join(p.read_text() for p in engines.glob("*.py"))
    declared = sorted({e for cap in _CAPABILITIES for e in cap.signature_events})

    def emitted(event: str) -> bool:
        if f'"{event}"' in source:
            return True
        # Telnet shares Cowrie with SSH and rewrites the prefix at ingest
        # (`ssh.py:_retag_for_protocol`), so `telnet_login_failed` is real even
        # though only `ssh_login_failed` appears as a literal.
        if event.startswith("telnet_"):
            return f'"ssh_{event.removeprefix("telnet_")}"' in source
        return False

    orphans = [event for event in declared if not emitted(event)]
    assert not orphans, f"declared but never emitted by any engine: {orphans}"


@pytest.mark.parametrize(
    "dashboard_file",
    sorted(p.name for p in (ROOT / "docker" / "grafana" / "dashboards").glob("*.json")),
)
def test_dashboard_query_fields_agree(dashboard_file: str):
    """`queryText` is what frser-sqlite-datasource executes; `rawQueryText` is
    the editor buffer. If they diverge, the panel runs one query while the JSON
    (and anyone reviewing it) shows another.

    This is not hypothetical: the first pass of the ATT&CK generator wrote only
    `rawQueryText`, so the corrected tactic mapping would have shipped while the
    dashboard kept executing the buggy one — a fix that reads as applied and
    isn't.
    """
    dashboard = json.loads(
        (ROOT / "docker" / "grafana" / "dashboards" / dashboard_file).read_text()
    )
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            present = {f: target[f] for f in ("queryText", "rawQueryText", "rawSql") if f in target}
            if len(present) < 2:
                continue
            assert len(set(present.values())) == 1, (
                f"{dashboard_file} / {panel.get('title')}: query fields disagree "
                f"({sorted(present)}) — the executed query is not the one shown"
            )


# ── Time bucketing scales with the selected window ─────────────────────────


def _timeseries_queries() -> list[tuple[str, str, str]]:
    """(dashboard, panel title, SQL) for every timeseries panel."""
    found = []
    for name in ("01-overview.json", "02-threat-map.json", "03-mitre-coverage.json"):
        dashboard = json.loads((ROOT / "docker" / "grafana" / "dashboards" / name).read_text())
        for panel in dashboard.get("panels", []):
            if panel.get("type") != "timeseries":
                continue
            for target in panel.get("targets", []):
                sql = target.get("queryText") or target.get("rawQueryText") or ""
                if sql:
                    found.append((name, panel.get("title", "?"), sql))
    return found


def test_timeseries_panels_bucket_relative_to_the_window():
    """A hardcoded bucket width is wrong in both directions.

    The severity panel grouped by `strftime('%Y-%m-%dT%H:%M')` — a fixed minute
    — regardless of the range the viewer selected. Over 24h that is up to 1,440
    points per series, which renders; over 30 days it is 43,200 per series
    across four series, which does not. The opposite failure is just as real: an
    hourly bucket over a five-minute window is a single column.

    The bucket must therefore be derived from $__from/$__to, not written into
    the query. The console already sizes buckets this way (`_bucket_size`).
    """
    offenders = []
    for dashboard, title, sql in _timeseries_queries():
        derives_bucket = "$__to" in sql and "$__from" in sql and "240000" in sql
        # A GROUP BY on a literal strftime pattern is the fixed-width form.
        fixed_width = re.search(r"GROUP BY strftime\('%[^']*'", sql) is not None
        if fixed_width or not derives_bucket:
            offenders.append(f"{dashboard} / {title}")
    assert not offenders, "timeseries panels with a hardcoded bucket width: " + ", ".join(offenders)


def test_timeseries_panels_emit_utc_marked_timestamps():
    """An offset-less date-time is read as *local* by JavaScript, which is what
    put the console's feed four hours ahead of its own clock. Grafana is no
    different, so every time column ships an explicit Z."""
    for dashboard, title, sql in _timeseries_queries():
        assert "Z'" in sql, f"{dashboard} / {title}: time column is not UTC-marked"


def test_table_panels_format_timestamps_rather_than_returning_raw_columns():
    """`MAX(timestamp) AS last_seen` returns SQLite's raw storage string —
    `2026-07-30 20:22:10.632767`: no T, no offset, microsecond noise. It renders
    as an ambiguous string in a table whose every other time is formatted, and
    cannot be shown in the viewer's timezone."""
    dashboard = json.loads(
        (ROOT / "docker" / "grafana" / "dashboards" / "01-overview.json").read_text()
    )
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            sql = target.get("queryText") or ""
            assert not re.search(
                r"(?<!strftime\(')(?:MAX|MIN)\(\s*timestamp\s*\)\s+AS", sql, re.I
            ), f"{panel.get('title')}: selects a raw timestamp column"
