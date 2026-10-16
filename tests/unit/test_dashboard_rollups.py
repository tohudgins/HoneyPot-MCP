"""The dashboards' window-aggregate panels read hourly rollups plus raw edges; they must equal the raw answer.

The panel SQL is taken from the dashboard JSON itself, so what ships is what is tested. Windows start
mid-hour, on the hour, and sit inside one hour, because those are where a rollup-backed total goes wrong.
"""

from __future__ import annotations

import json
import random
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

DASHBOARDS = (
    Path(__file__).resolve().parents[2] / "src" / "honeypot_mcp" / "grafana_assets" / "dashboards"
)
BASE = datetime(2026, 1, 5, 0, 0, 0, tzinfo=UTC)
SEVERITIES = ["low", "medium", "high", "critical"]
TYPES = ["ssh_login_failed", "telnet_command_input", "sip_register_attempt", "http_probe"]
IPS = [f"91.121.7.{i}" for i in range(1, 9)]


def _panel_sql(dashboard: str, title: str) -> str:
    data = json.loads((DASHBOARDS / dashboard).read_text())

    def walk(panels):
        for panel in panels:
            yield panel
            yield from walk(panel.get("panels", []))

    panel = next(p for p in walk(data["panels"]) if p.get("title") == title)
    return panel["targets"][0]["queryText"]


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")


@pytest.fixture(scope="module")
def db():
    rng = random.Random(7)
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE honeypots (id INTEGER PRIMARY KEY, type TEXT);
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, honeypot_id INTEGER, source_ip TEXT, event_type TEXT,
                             severity TEXT, timestamp TEXT);
        CREATE TABLE alert_rollups (bucket TEXT, severity TEXT, event_type TEXT, source_ip TEXT,
                                    honeypot_id INTEGER, count INTEGER);
        INSERT INTO honeypots VALUES (1, 'ssh'), (2, 'sip'), (3, 'http');
        """
    )
    rows, rollups = [], {}
    for _ in range(1500):
        at = BASE + timedelta(
            seconds=rng.randrange(0, 6 * 3600), microseconds=rng.randrange(1_000_000)
        )
        honeypot = rng.choice([1, 2, 3, None])
        row = (honeypot, rng.choice(IPS), rng.choice(TYPES), rng.choice(SEVERITIES), _stamp(at))
        rows.append(row)
        key = (
            _stamp(at.replace(minute=0, second=0, microsecond=0)),
            row[3],
            row[2],
            row[1],
            honeypot or 0,
        )
        rollups[key] = rollups.get(key, 0) + 1
    con.executemany(
        "INSERT INTO alerts (honeypot_id, source_ip, event_type, severity, timestamp) VALUES (?,?,?,?,?)",
        rows,
    )
    con.executemany(
        "INSERT INTO alert_rollups VALUES (?,?,?,?,?,?)", [(*k, n) for k, n in rollups.items()]
    )
    return con, rows


WINDOWS = {
    "mid-hour start and end": (
        BASE + timedelta(hours=1, minutes=17, seconds=41),
        BASE + timedelta(hours=4, minutes=43, seconds=9),
    ),
    "on the hour": (BASE + timedelta(hours=2), BASE + timedelta(hours=4)),
    "inside one hour": (
        BASE + timedelta(hours=3, minutes=10),
        BASE + timedelta(hours=3, minutes=50),
    ),
    "the whole data set": (BASE - timedelta(hours=1), BASE + timedelta(hours=7)),
    "ends mid-hour, starts on the hour": (
        BASE + timedelta(hours=1),
        BASE + timedelta(hours=3, minutes=30),
    ),
    "after all data": (BASE + timedelta(hours=8), BASE + timedelta(hours=9)),
}


def _run(con, sql: str, window) -> list[tuple]:
    start, end = window
    sql = sql.replace("$__from", str(int(start.timestamp() * 1000))).replace(
        "$__to", str(int(end.timestamp() * 1000))
    )
    return con.execute(sql).fetchall()


@pytest.mark.parametrize("name", WINDOWS)
def test_window_totals_equal_the_raw_table(db, name):
    con, rows = db
    window = WINDOWS[name]
    mine = [
        r
        for r in rows
        if _stamp(window[0]).split(".")[0] <= r[4] <= _stamp(window[1]).split(".")[0]
    ]

    total = _run(con, _panel_sql("01-overview.json", "Alerts (window)"), window)[0][0]
    critical = _run(con, _panel_sql("01-overview.json", "CRITICAL alerts (window)"), window)[0][0]
    unique = _run(con, _panel_sql("01-overview.json", "Unique attacker IPs"), window)[0][0]

    assert total == len(mine), name
    assert critical == sum(1 for r in mine if r[3] == "critical"), name
    assert unique == len({r[1] for r in mine}), name


@pytest.mark.parametrize("name", WINDOWS)
def test_top_attackers_event_types_and_engines_equal_the_raw_table(db, name):
    con, rows = db
    window = WINDOWS[name]
    mine = [
        r
        for r in rows
        if _stamp(window[0]).split(".")[0] <= r[4] <= _stamp(window[1]).split(".")[0]
    ]

    attackers = _run(con, _panel_sql("01-overview.json", "Top 10 attackers (window)"), window)
    want: dict[str, list[int]] = {}
    for _hp, ip, et, sev, _ts in mine:
        entry = want.setdefault(ip, [0, set(), 0])
        entry[0] += 1
        entry[1].add(et)
        entry[2] += sev == "critical"
    expected = sorted(
        ((ip, v[0], len(v[1]), v[2]) for ip, v in want.items()), key=lambda r: (-r[1], r[0])
    )[:10]
    got = sorted(((r[0], r[1], r[2], r[3]) for r in attackers), key=lambda r: (-r[1], r[0]))
    assert got == expected, name

    types = {
        r[0]: (r[1], r[2], r[3])
        for r in _run(con, _panel_sql("03-mitre-coverage.json", "Top event types (raw)"), window)
    }
    for et in {r[2] for r in mine}:
        rows_for = [r for r in mine if r[2] == et]
        assert types[et] == (
            len(rows_for),
            len({r[1] for r in rows_for}),
            sum(r[3] == "critical" for r in rows_for),
        ), (name, et)

    engines = {
        r[0]: r[1]
        for r in _run(con, _panel_sql("01-overview.json", "Alerts by honeypot engine"), window)
    }
    names = {1: "ssh", 2: "sip", 3: "http", None: "(removed sensors)", 0: "(removed sensors)"}
    expected_engines: dict[str | None, int] = {}
    for r in mine:
        key = names[r[0]]
        expected_engines[key] = expected_engines.get(key, 0) + 1
    assert engines == expected_engines, name


def test_a_panel_that_ignored_the_partial_hours_would_be_caught(db):
    """The mid-hour window cuts hours 1 and 4 in half: whole-hour rollups alone cannot be exact."""
    con, rows = db
    window = WINDOWS["mid-hour start and end"]
    whole_hours_only = con.execute(
        "SELECT SUM(count) FROM alert_rollups WHERE bucket >= ? AND bucket < ?",
        (_stamp(BASE + timedelta(hours=2)), _stamp(BASE + timedelta(hours=4))),
    ).fetchone()[0]
    exact = _run(con, _panel_sql("01-overview.json", "Alerts (window)"), window)[0][0]
    assert exact > whole_hours_only, "the edges hold alerts, which is why they are read raw"
