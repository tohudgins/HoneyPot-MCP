#!/usr/bin/env python3
"""Point the dashboards' window-aggregate panels at the hourly rollups.

    python scripts/dashboard_rollups.py          # rewrites docker/grafana/dashboards/*.json in place

The panels used to scan the raw `alerts` table, so their cost grew with the whole run (13 queries took
17.8 s on 4.9M alerts). They now read the same pieces `storage/rollups.py` does:

  * whole hours inside the Grafana window come from `alert_rollups` (thousands of rows, not millions);
  * the partial hour at the start and the hour containing the end come from `alerts` by timestamp, using
    the timestamp index, so the window is exact to the second at both edges;
  * a window inside one hour is answered from `alerts` alone.

That is the definition `alerts_stats` uses, so a dashboard total equals the tool's. Panels that need
sub-hour resolution (time series) or a payload field the rollups do not hold (geo country) are left on
`alerts`. `tests/unit/test_dashboard_rollups.py` checks each rewritten panel against a plain GROUP BY over
the raw table for windows that start mid-hour, on the hour, and inside one hour.
"""

from __future__ import annotations

import json
from pathlib import Path

DASHBOARDS = Path(__file__).resolve().parent.parent / "docker" / "grafana" / "dashboards"

# `w`: (severity, event_type, source_ip, honeypot_id, n, ts) covering [from, to] exactly.
WINDOW = (
    "WITH b AS (SELECT $__from / 1000 AS f, $__to / 1000 AS t, "
    "($__from / 1000 + 3599) / 3600 * 3600 AS lo, $__to / 1000 / 3600 * 3600 AS hi), "
    "w AS ("
    "SELECT severity, event_type, source_ip, COALESCE(honeypot_id, 0) AS honeypot_id, count AS n, bucket AS ts "
    "FROM alert_rollups, b WHERE lo < hi AND bucket >= datetime(lo, 'unixepoch') AND bucket < datetime(hi, 'unixepoch') "
    "UNION ALL "
    "SELECT severity, event_type, source_ip, COALESCE(honeypot_id, 0), 1, timestamp "
    "FROM alerts, b WHERE timestamp >= datetime(f, 'unixepoch') AND "
    "((lo < hi AND timestamp < datetime(lo, 'unixepoch')) OR (lo >= hi AND timestamp <= datetime(t, 'unixepoch'))) "
    "UNION ALL "
    "SELECT severity, event_type, source_ip, COALESCE(honeypot_id, 0), 1, timestamp "
    "FROM alerts, b WHERE lo < hi AND timestamp >= datetime(hi, 'unixepoch') AND timestamp <= datetime(t, 'unixepoch')"
    ") "
)

PANELS: dict[tuple[str, str], str] = {
    ("01-overview.json", "Alerts (window)"): "SELECT COALESCE(SUM(n), 0) AS value FROM w",
    ("01-overview.json", "Unique attacker IPs"): "SELECT COUNT(DISTINCT source_ip) AS value FROM w",
    ("01-overview.json", "CRITICAL alerts (window)"): (
        "SELECT COALESCE(SUM(n), 0) AS value FROM w WHERE severity = 'critical'"
    ),
    ("01-overview.json", "Alerts by honeypot engine"): (
        "SELECT COALESCE(h.type, '(removed sensors)') AS engine, SUM(w.n) AS count FROM w "
        "LEFT JOIN honeypots h ON w.honeypot_id = h.id "
        "GROUP BY h.type ORDER BY count DESC"
    ),
    ("01-overview.json", "Top 10 attackers (window)"): (
        "SELECT source_ip AS ip, SUM(n) AS hits, COUNT(DISTINCT event_type) AS event_types, "
        "SUM(CASE WHEN severity = 'critical' THEN n ELSE 0 END) AS critical_hits, "
        "strftime('%Y-%m-%dT%H:00:00Z', MAX(ts)) AS last_seen_hour FROM w GROUP BY source_ip ORDER BY hits DESC LIMIT 10"
    ),
    ("03-mitre-coverage.json", "Top event types (raw)"): (
        "SELECT event_type, SUM(n) AS hits, COUNT(DISTINCT source_ip) AS unique_ips, "
        "SUM(CASE WHEN severity = 'critical' THEN n ELSE 0 END) AS critical FROM w "
        "GROUP BY event_type ORDER BY hits DESC LIMIT 20"
    ),
}
RENAMES = {("01-overview.json", "Top 10 attackers (window)"): ("last_seen", "last_seen_hour")}


def _walk(panels: list[dict]):
    for panel in panels:
        yield panel
        yield from _walk(panel.get("panels", []))


def main() -> int:
    changed = 0
    for name in sorted({file for file, _ in PANELS}):
        path = DASHBOARDS / name
        dashboard = json.loads(path.read_text())
        for panel in _walk(dashboard["panels"]):
            key = (name, panel.get("title", ""))
            if key not in PANELS:
                continue
            sql = WINDOW + PANELS[key]
            for target in panel["targets"]:
                target["queryText"] = target["rawQueryText"] = sql
                if key in RENAMES:
                    old, new = RENAMES[key]
                    target["timeColumns"] = [
                        new if c == old else c for c in target.get("timeColumns", [])
                    ]
            changed += 1
        path.write_text(json.dumps(dashboard, indent=2) + "\n")
    print(f"rewrote {changed} panels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
