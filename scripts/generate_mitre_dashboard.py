"""Regenerate the MITRE ATT&CK dashboard's SQL from `intel/mitre.py`.

    uv run python scripts/generate_mitre_dashboard.py

Why this is generated rather than hand-written:

The dashboard needs event-type → tactic mapping, and SQL cannot call Python, so
someone wrote the mapping a second time as a CASE expression. It then drifted
from the real mapper in exactly the ways a duplicated table always does — it
filed SSH/FTP/RDP brute force under Initial Access when T1110 is Credential
Access, and `ssh_file_download` under Exfiltration when Cowrie means ingress
(T1105). Both were bugs `intel/mitre.py` had already fixed. It also left most
of a 25-protocol catalogue in "Uncategorised", because it was written when the
platform had far fewer engines and nothing failed when new ones shipped.

So the mapping is computed here from the authoritative mapper and written into
the dashboard as an explicit event-type list per tactic. `test_mitre_dashboard`
regenerates and compares, so a drifted dashboard fails CI instead of quietly
misinforming an analyst who knows ATT&CK well enough to notice.

Multi-tactic events (ATT&CK techniques legitimately span tactics — an SMB
exploit is both Initial Access and Lateral Movement) are counted under *every*
tactic they map to. That is the honest reading for a coverage view, and it is
why the bar gauge is a UNION ALL rather than a CASE: a CASE can only put each
row in one bucket and would silently under-report the later tactic.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

DASHBOARD = ROOT / "docker" / "grafana" / "dashboards" / "03-mitre-coverage.json"

_WINDOW = (
    "timestamp BETWEEN datetime($__from / 1000, 'unixepoch') "
    "AND datetime($__to / 1000, 'unixepoch')"
)


async def tactic_event_types() -> dict[str, list[str]]:
    """{tactic name: [event_type, ...]} built from the real mapper."""
    from honeypot_mcp.deception.capabilities import _CAPABILITIES
    from honeypot_mcp.intel.mitre import TACTIC_ORDER, map_to_attack

    event_types = sorted({e for cap in _CAPABILITIES for e in cap.signature_events})
    by_tactic: dict[str, list[str]] = {}
    for event_type in event_types:
        for technique in await map_to_attack([event_type]):
            by_tactic.setdefault(technique["tactic"], []).append(event_type)

    # Kill-chain order, and de-duplicated: one event type can match several
    # techniques inside the same tactic.
    return {
        tactic: sorted(set(by_tactic[tactic])) for tactic in TACTIC_ORDER if tactic in by_tactic
    }


def _in_list(event_types: list[str]) -> str:
    return ", ".join(f"'{e}'" for e in event_types)


def build_observed_tactics_sql(by_tactic: dict[str, list[str]]) -> str:
    """Bar gauge: one row per tactic, counted over the dashboard window."""
    from honeypot_mcp.intel.mitre import tactic_label

    selects = [
        f"SELECT '{tactic_label(tactic)}' AS tactic, COUNT(*) AS count "
        f"FROM alerts WHERE event_type IN ({_in_list(events)}) AND {_WINDOW}"
        for tactic, events in by_tactic.items()
    ]
    return "\n  UNION ALL\n".join(selects) + "\n  ORDER BY count DESC"


# ~240 buckets across whatever window the viewer selected, floored at 60s.
# Derived from $__from/$__to (epoch milliseconds) rather than $__interval_ms so
# it depends only on the macros these dashboards already prove are interpolated.
# A fixed bucket width is wrong in both directions: hourly over a year is 8,760
# points per series, and hourly over a five-minute window is a single column.
_BUCKET = "MAX((($__to) - ($__from)) / 240000, 60)"


def build_tactic_timeline_sql(by_tactic: dict[str, list[str]]) -> str:
    """Timeseries: one column per tactic, bucketed to fit the selected window."""
    columns = [
        f'SUM(CASE WHEN event_type IN ({_in_list(events)}) THEN 1 ELSE 0 END) AS "{tactic}"'
        for tactic, events in by_tactic.items()
    ]
    bucket = f"CAST(strftime('%s', timestamp) / ({_BUCKET}) AS INTEGER)"
    return (
        f"SELECT strftime('%Y-%m-%dT%H:%M:%SZ', datetime({bucket} * ({_BUCKET}), "
        "'unixepoch')) AS time,\n  "
        + ",\n  ".join(columns)
        + f"\nFROM alerts WHERE {_WINDOW}"
        + f"\nGROUP BY {bucket} ORDER BY time"
    )


# frser-sqlite-datasource carries the query twice: `rawQueryText` is the editor
# buffer, `queryText` is what the backend actually runs. Writing only the former
# leaves the panel *executing* the old SQL while the editor shows the new — the
# fix silently does nothing, and reading the JSON suggests it worked. Every
# hand-written panel in these dashboards keeps the two identical;
# `test_dashboard_query_fields_agree` holds that invariant.
_SQL_FIELDS = ("queryText", "rawQueryText", "rawSql")


def _set_panel_sql(dashboard: dict, title: str, sql: str) -> bool:
    for panel in dashboard.get("panels", []):
        if panel.get("title") != title:
            continue
        for target in panel.get("targets", []):
            for field in _SQL_FIELDS:
                if field in target:
                    target[field] = sql
        return True
    return False


async def render() -> dict:
    """The dashboard JSON as it should be on disk."""
    dashboard = json.loads(DASHBOARD.read_text())
    by_tactic = await tactic_event_types()
    missing = [
        title
        for title, sql in (
            ("Observed tactics (ATT&CK)", build_observed_tactics_sql(by_tactic)),
            ("Tactic timeline", build_tactic_timeline_sql(by_tactic)),
        )
        if not _set_panel_sql(dashboard, title, sql)
    ]
    if missing:
        raise SystemExit(f"panel(s) not found in {DASHBOARD.name}: {missing}")
    return dashboard


async def main() -> None:
    dashboard = await render()
    DASHBOARD.write_text(json.dumps(dashboard, indent=2) + "\n")
    by_tactic = await tactic_event_types()
    print(f"Wrote {DASHBOARD.relative_to(ROOT)}")
    for tactic, events in by_tactic.items():
        print(f"  {tactic:22s} {len(events):3d} event types")


if __name__ == "__main__":
    asyncio.run(main())
