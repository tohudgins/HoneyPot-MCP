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
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DASHBOARDS = ROOT / "src" / "honeypot_mcp" / "grafana_assets" / "dashboards"
DASHBOARD = DASHBOARDS / "03-mitre-coverage.json"


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
    sorted(p.name for p in (DASHBOARDS).glob("*.json")),
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
    dashboard = json.loads((DASHBOARDS / dashboard_file).read_text())
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
        dashboard = json.loads((DASHBOARDS / name).read_text())
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
    dashboard = json.loads((DASHBOARDS / "01-overview.json").read_text())
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            sql = target.get("queryText") or ""
            assert not re.search(
                r"(?<!strftime\(')(?:MAX|MIN)\(\s*timestamp\s*\)\s+AS", sql, re.I
            ), f"{panel.get('title')}: selects a raw timestamp column"


# ── Tactic timeline: every tactic gets its own distinguishable color ────────
#
# Grafana's auto-palette repeats/shades hues past ~8 series, which is exactly
# the range this panel needs (up to 14 tactics) — the original symptom was a
# handful of kill-chain-adjacent tactics rendering as indistinguishable
# shades of blue/purple in a filled, stacked chart. Fixed per-tactic colors
# replace the auto-palette; these tests hold that fix in place rather than
# letting a future edit quietly drop back to Grafana's default assignment.


def test_every_tactic_has_a_fixed_color_override():
    from honeypot_mcp.intel.mitre import TACTIC_ORDER

    dashboard = json.loads(DASHBOARD.read_text())
    panel = next(p for p in dashboard["panels"] if p["title"] == "Tactic timeline")
    overridden = {
        o["matcher"]["options"]
        for o in panel["fieldConfig"]["overrides"]
        if o["matcher"]["id"] == "byName"
    }
    missing = set(TACTIC_ORDER) - overridden
    assert not missing, f"tactic(s) with no fixed color override: {missing}"


def test_tactic_colors_are_unique():
    dashboard = json.loads(DASHBOARD.read_text())
    panel = next(p for p in dashboard["panels"] if p["title"] == "Tactic timeline")
    colors = [
        prop["value"]["fixedColor"]
        for o in panel["fieldConfig"]["overrides"]
        for prop in o["properties"]
        if prop["id"] == "color"
    ]
    assert len(colors) == len(set(colors)), f"two tactics share a color: {colors}"


def test_tactic_timeline_is_not_stacked():
    """A filled, stacked area chart blends overlapping bands into a muddy
    blob — the panel's actual question ('when did which tactic spike') is
    better served by overlaid lines than a cumulative stacked view, and it
    also happens to be far easier to color-distinguish."""
    dashboard = json.loads(DASHBOARD.read_text())
    panel = next(p for p in dashboard["panels"] if p["title"] == "Tactic timeline")
    assert panel["fieldConfig"]["defaults"]["custom"]["stacking"]["mode"] == "none"


# ── Threat map: basemap must need no API key and render no place labels ─────


def test_threat_map_basemap_needs_no_api_key_and_has_no_labels():
    """Two failures of the same panel, found by opening the dashboard on a real backup.

    The first: Grafana's `default` basemap resolves to CARTO's free raster endpoint, which renders
    place names in each region's local language, so labels were turned off. The second, later: that
    endpoint began stamping "API KEY REQUIRED" across every tile while still answering HTTP 200,
    so nothing looked broken until a person opened the map. The basemap is now an explicit,
    keyless, label-free layer (Esri's Dark Gray *Base*; the labels are a separate layer we do not
    add). The 'Top countries' table beside it carries the place names."""
    path = DASHBOARDS / "02-threat-map.json"
    dashboard = json.loads(path.read_text())
    geomap_panels = [p for p in dashboard["panels"] if p.get("type") == "geomap"]
    assert geomap_panels, "no geomap panel found in the threat map dashboard"
    for panel in geomap_panels:
        basemap = panel["options"]["basemap"]
        assert basemap["type"] == "xyz", "`default` is CARTO, which now demands an API key"
        url = basemap["config"]["url"]
        assert "cartocdn" not in url and "{apikey}" not in url.lower() and "key=" not in url
        assert "World_Dark_Gray_Base" in url, "a base layer carries no place labels"


def test_dashboards_need_nothing_but_the_database():
    """The dashboards are read from a downloaded backup on a laptop as often as from the live
    stack. A panel on the Prometheus datasource ('Active honeypots') showed 'No data' there, because
    there is no Prometheus; the honeypots table is the source of truth and is always present."""
    for name in ("01-overview.json", "02-threat-map.json", "03-mitre-coverage.json"):
        dashboard = json.loads((DASHBOARDS / name).read_text())

        def walk(panels):
            for panel in panels:
                yield panel
                yield from walk(panel.get("panels", []))

        for panel in walk(dashboard["panels"]):
            uids = {
                t.get("datasource", panel.get("datasource", {})).get("uid")
                for t in panel.get("targets", [])
            }
            assert uids <= {"honeypot-db"}, (name, panel.get("title"), uids)


# ── Nothing the mapper counts may be missing from the dashboard ────────────

# Event-type NAMES (no data) seen on a real 116-hour, 17.7M-alert run that
# `intel.mitre` maps to a technique. `attack_summary` counts every one of them;
# the dashboard counted only what some engine listed in `signature_events`, so
# 39 types (about 109k alerts, 0.6%) were missing: Discovery read 8,737,549 on
# the wall and 8,844,809 in the tool, with nothing to say which was right.
_SEEN_BUT_ONCE_MISSING = (
    "sip_request",
    "sip_invite",
    "sip_options_probe",
    "sip_invalid_probe",
    "nfs_unknown_program",
    "nfs_portmap_probe",
    "nfs_mount_probe",
    "docker_api_probe",
    "docker_api_recon",
    "docker_api_container_start",
    "docker_api_container_create",
    "docker_api_exec_start",
    "elasticsearch_recon_probe",
    "elasticsearch_health_probe",
    "ssh_port_forward_ja4h",
    "ssh_port_forward_data",
    "kubernetes_probe",
    "kubernetes_recon",
    "rdp_invalid_probe",
    "rdp_nla_probe",
    "rdp_mcs_handshake",
    "mysql_recon_query",
    "http_recon_probe",
    "ldap_invalid_probe",
    "redis_info_probe",
    "redis_config_get",
    "redis_key_set",
    "redis_rogue_replica",
    "redis_rce_dropper",
    "postgresql_recon_query",
    "snmp_invalid_probe",
    "rsync_module_access",
    "rsync_invalid_probe",
    "rsync_unknown_module",
    "memcached_version_probe",
    "memcached_large_set",
)
# Planted-credential and canary trips: named after the token type and the event they re-tagged.
_SEEN_HONEYTOKEN_TRIPS = (
    "honeytoken_triggered_canary_url",
    "honeytoken_triggered_credential_via_mysql_login_attempt",
    "honeytoken_triggered_credential_via_ssh_login_success",
)
# The highest-volume mapped types, which were always on the dashboard and must stay there.
_SEEN_AND_ALWAYS_COVERED = (
    "sip_extension_probe",
    "sip_register_attempt",
    "sip_toll_fraud_attempt",
    "sip_scan",
    "telnet_command_input",
    "telnet_login_success",
    "telnet_login_failed",
    "ssh_command_input",
    "ssh_login_success",
    "ssh_file_download",
    "ssh_port_forward",
    "vnc_auth_attempt",
    "smb_negotiate",
    "smb_ntlm_auth",
    "smb_session_setup",
    "mssql_login_attempt",
    "mysql_login_attempt",
    "rdp_connection",
    "rdp_handshake",
    "rdp_nla_auth",
    "http_active_recon",
    "http_probe",
    "http_exploit_attempt",
)
_PINNED = _SEEN_BUT_ONCE_MISSING + _SEEN_HONEYTOKEN_TRIPS + _SEEN_AND_ALWAYS_COVERED

_FROM_MS, _TO_MS = 0, 4_102_444_800_000  # 1970 .. 2100; every row below falls inside


def _panel_query(panel: str) -> str:
    dashboard = json.loads(DASHBOARD.read_text())
    found = next(p for p in dashboard["panels"] if p.get("title") == panel)
    return (
        found["targets"][0]["queryText"]
        .replace("$__from", str(_FROM_MS))
        .replace("$__to", str(_TO_MS))
    )


def _expected_tactic_counts(event_types) -> dict[str, int]:
    """{tactic: alerts} as `attack_summary` would total them, one alert per name."""
    from honeypot_mcp.intel.mitre import map_to_attack

    async def tactics_of(name: str) -> set[str]:
        return {t["tactic"] for t in await map_to_attack([name])}

    async def gather() -> dict[str, set[str]]:
        return {name: await tactics_of(name) for name in event_types}

    expected: dict[str, int] = {}
    for name, tactics in asyncio.run(gather()).items():
        assert tactics, f"{name} no longer maps to any technique; drop it from the pinned list"
        for tactic in tactics:
            expected[tactic] = expected.get(tactic, 0) + 1
    return expected


def _one_alert_per(event_types) -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE alerts (event_type TEXT, timestamp TEXT)")
    con.executemany(
        "INSERT INTO alerts VALUES (?, '2026-10-16 12:00:00.000000')", [(n,) for n in event_types]
    )
    return con


def test_every_event_type_seen_on_a_real_run_is_counted_under_its_tactics():
    """Runs the shipped SQL, so a name missing from a tactic, listed under a wrong one, or a
    syntax slip in the honeytoken prefix match all fail here.

    One alert per pinned name, no other rows: every tactic's total must equal the number of
    pinned names the mapper files under it, in both panels.
    """
    from honeypot_mcp.intel.mitre import tactic_label

    expected = _expected_tactic_counts(_PINNED)
    con = _one_alert_per(_PINNED)

    observed = dict(con.execute(_panel_query("Observed tactics (ATT&CK)")).fetchall())
    assert {t: n for t, n in observed.items() if n} == {
        tactic_label(t): n for t, n in expected.items()
    }

    timeline = con.execute(_panel_query("Tactic timeline"))
    columns = [d[0] for d in timeline.description][1:]
    rows = timeline.fetchall()
    summed = {c: sum(row[i + 1] for row in rows) for i, c in enumerate(columns)}
    assert {t: n for t, n in summed.items() if n} == expected


def test_pinned_names_are_real_event_types():
    """The pinned names must be ones an engine can emit, so the list cannot rot into a set of
    names that no longer exist (which the SQL test above would still happily pass, since the
    mapper decides what it expects). Honeytoken trips are built at run time, so only their
    shape is checked."""
    engines = ROOT / "src" / "honeypot_mcp" / "engines"
    source = "\n".join(p.read_text() for p in engines.glob("*.py"))
    for name in _SEEN_BUT_ONCE_MISSING + _SEEN_AND_ALWAYS_COVERED:
        retagged = name.startswith("telnet_") and f'"ssh_{name.removeprefix("telnet_")}"' in source
        assert f'"{name}"' in source or retagged, f"no engine emits {name}"
    for name in _SEEN_HONEYTOKEN_TRIPS:
        assert name.startswith("honeytoken_triggered_")


# Strings that look like an event type and map to a technique but are not one: each says what it is.
_NOT_EVENT_TYPES = {
    "smb_version": "payload key naming the dialect (SMB1/SMB2), never an event_type",
    "ssh_authorized_key": "label `redis._classify_payload` puts in a payload, not an event_type",
    "mysql_native_password": "the auth plugin name in the MySQL handshake",
}


def _engine_event_type_literals() -> dict[str, set[str]]:
    """{string literal: {engine files}} for every literal that is, or looks like, an event type.

    Engines rarely write `event_type="..."` at the call: most return a name from a classifier
    (`return "sip_invite", severity, extra`) or pass it positionally to a `_record` helper, so a
    scan of only that keyword finds a handful of the ~300 names. So this takes every string
    constant, found with `ast` (comments and docstrings are not constants of this shape), that is
    `<engine type>_<words>`, plus every literal given as `event_type=`. F-strings are skipped:
    a name built at run time (`honeytoken_triggered_{match}_via_...`) is covered by
    `CROSS_ENGINE_EVENT_PREFIXES` instead.
    """
    import ast

    from honeypot_mcp.deception.capabilities import _CAPABILITIES

    prefixes = "|".join(sorted({c.type for c in _CAPABILITIES} | {"telnet"}))
    looks_like_event = re.compile(rf"^(?:{prefixes})_[a-z0-9_]+$")
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "src" / "honeypot_mcp" / "engines").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.keyword) and node.arg == "event_type":
                value = node.value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    found.setdefault(value.value, set()).add(path.name)
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and looks_like_event.match(node.value)
            ):
                found.setdefault(node.value, set()).add(path.name)
    return found


def test_the_literal_scan_actually_finds_the_engines_event_types():
    """A scanner that matches nothing would make the next test pass forever."""
    found = _engine_event_type_literals()
    assert len(found) > 200
    for name in ("sip_invite", "redis_key_set", "ssh_port_forward_data", "mssql_login_attempt"):
        assert name in found, name


def test_every_mapped_engine_event_type_is_on_the_dashboard():
    """A new engine event that maps to a technique but is not in `signature_events` is counted
    by `attack_summary` and absent from the dashboard, silently: the 39-type gap this closes.

    Add it to the owning engine's `signature_events`, or, if it is not an event type, to
    `_NOT_EVENT_TYPES` with the reason.
    """
    from honeypot_mcp.deception.capabilities import _CAPABILITIES, CROSS_ENGINE_EVENT_PREFIXES
    from honeypot_mcp.intel.mitre import map_to_attack

    declared = {e for cap in _CAPABILITIES for e in cap.signature_events}

    async def mapped(names):
        return {n for n in names if await map_to_attack([n])}

    candidates = _engine_event_type_literals()
    missing = sorted(
        name
        for name in asyncio.run(mapped(candidates))
        if name not in declared
        and name not in _NOT_EVENT_TYPES
        and not name.startswith(CROSS_ENGINE_EVENT_PREFIXES)
    )
    assert not missing, "event types that map to ATT&CK but are on no dashboard list: " + ", ".join(
        f"{n} ({'/'.join(sorted(candidates[n]))})" for n in missing
    )


def test_not_event_type_exceptions_are_still_needed():
    """An allow-list entry that no longer matches anything hides the next real gap."""
    found = _engine_event_type_literals()
    from honeypot_mcp.deception.capabilities import _CAPABILITIES

    declared = {e for cap in _CAPABILITIES for e in cap.signature_events}
    for name in _NOT_EVENT_TYPES:
        assert name in found, f"{name} is no longer in any engine; remove the exception"
        assert name not in declared, f"{name} is declared; remove the exception"


def test_honeytoken_trips_are_counted_by_prefix_without_inflating_sensor_coverage():
    """Trips re-tag an event from any sensor, so no engine's `signature_events` may list one:
    `deception_coverage` would then credit that sensor with detecting 'valid accounts'."""
    from honeypot_mcp.deception.capabilities import _CAPABILITIES, CROSS_ENGINE_EVENT_PREFIXES

    assert "honeytoken_triggered_" in CROSS_ENGINE_EVENT_PREFIXES
    for cap in _CAPABILITIES:
        leaked = [e for e in cap.signature_events if e.startswith(CROSS_ENGINE_EVENT_PREFIXES)]
        assert not leaked, f"{cap.type} lists a cross-engine event type: {leaked}"
    prefixes = asyncio.run(_generator().tactic_event_prefixes())
    assert "honeytoken_triggered_" in prefixes["Initial Access"]
