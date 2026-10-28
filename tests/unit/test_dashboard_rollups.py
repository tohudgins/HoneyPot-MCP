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


def _build(hours: int, count: int, seed: int):
    """A database whose rollups are what the server would have written for its alerts."""
    rng = random.Random(seed)
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
    for _ in range(count):
        at = BASE + timedelta(
            seconds=rng.randrange(0, hours * 3600), microseconds=rng.randrange(1_000_000)
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


@pytest.fixture(scope="module")
def db():
    return _build(6, 1500, 7)


@pytest.fixture(scope="module")
def db_long():
    """Twelve hours, so a window can be longer than the six hours below which panels read raw rows."""
    return _build(12, 3000, 11)


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


def _bind(sql: str, window) -> tuple[str]:
    """`con.execute(*_bind(sql, window))`: the panel SQL with the dashboard's time range filled in."""
    return (
        sql.replace("$__from", str(int(window[0].timestamp() * 1000))).replace(
            "$__to", str(int(window[1].timestamp() * 1000))
        ),
    )


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


# ── the time-series panels ────────────────────────────────────────────────────────────────────
# They read the hourly rollups (raw rows only at a window's edges, and for a window under six hours
# where little is rolled up). Before, they scanned the whole alerts table: minutes on 17.7M rows.

SERIES_WINDOWS = {
    "long, mid-hour edges inside the data": (
        BASE + timedelta(minutes=17, seconds=41),
        BASE + timedelta(hours=9, minutes=43, seconds=9),
    ),
    "long, on the hour": (BASE + timedelta(hours=1), BASE + timedelta(hours=9)),
    "all of it and more": (BASE - timedelta(hours=2), BASE + timedelta(hours=14)),
    "short, mid-hour": (
        BASE + timedelta(hours=3, minutes=7),
        BASE + timedelta(hours=4, minutes=21),
    ),
    "five minutes": (BASE + timedelta(hours=2, minutes=3), BASE + timedelta(hours=2, minutes=8)),
}


def _bucket_seconds(window) -> int:
    seconds = int((window[1] - window[0]).total_seconds() * 1000) // 240000
    if (window[1] - window[0]) < timedelta(hours=6):
        return max(seconds, 60)
    return (max(seconds, 3600) + 3599) // 3600 * 3600


def _raw_in(rows, window):
    lo, hi = _stamp(window[0]), _stamp(window[1])
    return [r for r in rows if lo <= r[4] <= hi]


def _bucket_of(stamp: str, width: int) -> str:
    moment = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)
    start = int(moment.timestamp()) // width * width
    return datetime.fromtimestamp(start, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.mark.parametrize("name", SERIES_WINDOWS)
def test_the_severity_series_equals_the_raw_table_bucket_by_bucket(db_long, name):
    con, rows = db_long
    window = SERIES_WINDOWS[name]
    sql = _panel_sql("01-overview.json", "Alerts over time by severity")
    cursor = con.execute(*_bind(sql, window))
    series = {r[0]: r[1:] for r in cursor.fetchall()}

    width, expected = _bucket_seconds(window), {}
    for _hp, _ip, _type, severity, stamp in _raw_in(rows, window):
        counts = expected.setdefault(_bucket_of(stamp, width), [0, 0, 0, 0])
        counts[SEVERITIES.index(severity)] += 1

    assert series == {k: tuple(v) for k, v in expected.items()}, name


@pytest.mark.parametrize("name", SERIES_WINDOWS)
def test_the_unique_source_series_equals_the_raw_table_bucket_by_bucket(db_long, name):
    con, rows = db_long
    window = SERIES_WINDOWS[name]
    sql = _panel_sql("02-threat-map.json", "Unique attacker IPs over time")
    series = dict(con.execute(*_bind(sql, window)).fetchall())

    width, seen = _bucket_seconds(window), {}
    for _hp, ip, _type, _sev, stamp in _raw_in(rows, window):
        seen.setdefault(_bucket_of(stamp, width), set()).add(ip)

    assert series == {k: len(v) for k, v in seen.items()}, name


def test_a_long_window_is_hourly_and_a_short_one_keeps_its_detail(db_long):
    con, _ = db_long
    sql = _panel_sql("01-overview.json", "Alerts over time by severity")

    long_times = [r[0] for r in con.execute(*_bind(sql, SERIES_WINDOWS["long, on the hour"]))]
    short_times = [r[0] for r in con.execute(*_bind(sql, SERIES_WINDOWS["short, mid-hour"]))]

    assert all(
        t.endswith(":00:00Z") for t in long_times
    )  # whole hours, never a sawtooth of half-hours
    assert any(
        not t.endswith(":00:00Z") for t in short_times
    )  # a 74-minute window is not one column


def test_every_series_panel_carries_the_same_source_sql():
    """The tactic panels and the overview series are one query shape; a copy that drifted would
    count differently from the panel beside it."""
    import re

    def cte(dashboard: str, title: str) -> str:
        sql = _panel_sql(dashboard, title)
        return re.match(r"^(WITH b AS .*?\))\s+SELECT ", sql, re.S).group(1)

    reference = cte("01-overview.json", "Alerts over time by severity")
    for dashboard, title in (
        ("02-threat-map.json", "Unique attacker IPs over time"),
        ("03-mitre-coverage.json", "Observed tactics (ATT&CK)"),
        ("03-mitre-coverage.json", "Tactic timeline"),
    ):
        assert cte(dashboard, title) == reference, f"{dashboard} / {title}"


def test_the_map_panels_read_only_the_critical_rows_through_the_urgent_index():
    """GeoIP enrichment is only ever written onto CRITICAL alerts (test_auto_enrich: a non-critical
    alert skips it), so those are the only rows these panels can count. The query names the partial
    index's own predicate as well, because SQLite only uses a partial index it can see the query implies;
    without it the planner scanned every alert and ran json_extract on each."""
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, honeypot_id INTEGER, source_ip TEXT, event_type TEXT,
                             severity TEXT, acknowledged INTEGER DEFAULT 0, timestamp TEXT, payload TEXT);
        CREATE INDEX ix_alerts_urgent ON alerts (severity, acknowledged, timestamp)
            WHERE severity IN ('critical', 'high');
        """
    )
    geo = '{"enrichment": {"geoip": {"latitude": 1.5, "longitude": 2.5, "country": "Chile"}}}'
    stamp = _stamp(BASE + timedelta(hours=1))
    con.executemany(
        "INSERT INTO alerts (source_ip, event_type, severity, timestamp, payload) VALUES (?,?,?,?,?)",
        [("203.0.113.1", "x", "critical", stamp, geo)] * 3
        + [("203.0.113.2", "x", "critical", stamp, "{}")]
        + [("203.0.113.3", "x", "low", stamp, "{}")] * 50,
    )
    window = (BASE, BASE + timedelta(hours=2))
    for title in ("Attacker origins", "Top countries (window)"):
        sql = _panel_sql("02-threat-map.json", title)
        plan = " ".join(
            str(r) for r in con.execute("EXPLAIN QUERY PLAN " + _bind(sql, window)[0]).fetchall()
        )
        assert "ix_alerts_urgent" in plan, plan
    countries = con.execute(
        *_bind(_panel_sql("02-threat-map.json", "Top countries (window)"), window)
    ).fetchall()
    assert countries == [("Chile", 3, 1)]


# ── the alert browser ─────────────────────────────────────────────────────────────────────────
# "Newest 200 in the window" used to sort every alert in the window (46 s over 17.7M rows) because
# SQLite chose the timestamp index and then ordered by id. Alert ids are chronological (the event buffer
# keeps rows in order), so the window becomes an id range by two index seeks and the newest rows come
# straight off the primary key.

_STRAIGHT_ALERTS = (
    "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', a.timestamp) AS time, a.severity, COALESCE(h.name, '-') AS sensor, "
    "a.source_ip, a.event_type, substr(a.payload, 1, 400) AS payload, a.id FROM alerts a "
    "LEFT JOIN honeypots h ON a.honeypot_id = h.id WHERE a.timestamp BETWEEN datetime($__from / 1000, 'unixepoch') "
    "AND datetime($__to / 1000, 'unixepoch') AND ('${ip}' = '' OR a.source_ip = '${ip}') "
    "AND ('${etype}' = '' OR a.event_type LIKE '%${etype}%') AND a.severity IN (${severity:sqlstring}) "
    "AND ('${sensor}' = 'All' OR h.name = '${sensor}') AND ('${text}' = '' OR a.payload LIKE '%${text}%') "
    "ORDER BY a.id DESC LIMIT ${limit}"
)


def _alert_browser(
    sql: str,
    window,
    *,
    ip="",
    etype="",
    severity="'critical','high','medium','low'",
    text="",
    limit=25,
):
    start, end = window
    bound = (
        sql.replace("$__from", str(int(start.timestamp() * 1000)))
        .replace("$__to", str(int(end.timestamp() * 1000)))
        .replace("${ip}", ip)
        .replace("${etype}", etype)
        .replace("${sensor}", "All")
        .replace("${text}", text)
        .replace("${limit}", str(limit))
        .replace("${severity:sqlstring}", severity)
    )
    return bound


@pytest.fixture(scope="module")
def alert_db():
    rng = random.Random(3)
    con = sqlite3.connect(":memory:")
    con.executescript(
        """
        CREATE TABLE honeypots (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO honeypots VALUES (1, 'hp-ssh'), (2, 'hp-sip');
        CREATE TABLE alerts (id INTEGER PRIMARY KEY, honeypot_id INTEGER, source_ip TEXT, event_type TEXT,
                             severity TEXT, timestamp TEXT, payload TEXT);
        CREATE INDEX ix_alerts_timestamp ON alerts (timestamp);
        """
    )
    # ids rise with time, as they do on a server; several rows share a timestamp
    moments = sorted(BASE + timedelta(seconds=rng.randrange(0, 12 * 3600)) for _ in range(2500))
    con.executemany(
        "INSERT INTO alerts (honeypot_id, source_ip, event_type, severity, timestamp, payload) VALUES (?,?,?,?,?,?)",
        [
            (
                rng.choice([1, 2, None]),
                rng.choice(IPS),
                rng.choice(TYPES),
                rng.choice(SEVERITIES),
                _stamp(m.replace(microsecond=0)),
                f'{{"n": {i}, "note": "{rng.choice(["wget", "curl", "none"])}"}}',
            )
            for i, m in enumerate(moments)
        ],
    )
    return con


ALERT_WINDOWS = {
    "mid-hour edges": (
        BASE + timedelta(hours=1, minutes=17, seconds=41),
        BASE + timedelta(hours=6, minutes=43, seconds=9),
    ),
    "the whole run": (BASE - timedelta(hours=1), BASE + timedelta(hours=13)),
    "ends before the data": (BASE - timedelta(hours=5), BASE - timedelta(hours=2)),
    "starts after the data": (BASE + timedelta(hours=14), BASE + timedelta(hours=16)),
    "one minute": (BASE + timedelta(hours=3, minutes=10), BASE + timedelta(hours=3, minutes=11)),
}
ALERT_FILTERS = {
    "none": {},
    "critical only": {"severity": "'critical'"},
    "one address": {"ip": IPS[2]},
    "event type words": {"etype": "sip"},
    "payload text": {"text": "wget"},
}


@pytest.mark.parametrize("filters", ALERT_FILTERS)
@pytest.mark.parametrize("name", ALERT_WINDOWS)
def test_the_alert_browser_returns_the_same_rows_as_the_straightforward_query(
    alert_db, name, filters
):
    shipped = _panel_sql("05-alerts.json", "Alerts")
    window, kw = ALERT_WINDOWS[name], ALERT_FILTERS[filters]

    got = alert_db.execute(_alert_browser(shipped, window, **kw)).fetchall()
    want = alert_db.execute(_alert_browser(_STRAIGHT_ALERTS, window, **kw)).fetchall()

    assert got == want, (name, filters)


def test_the_alert_browser_walks_the_primary_key_instead_of_sorting_the_window(alert_db):
    shipped = _alert_browser(_panel_sql("05-alerts.json", "Alerts"), ALERT_WINDOWS["the whole run"])
    straight = _alert_browser(_STRAIGHT_ALERTS, ALERT_WINDOWS["the whole run"])

    plan = " | ".join(str(r[3]) for r in alert_db.execute("EXPLAIN QUERY PLAN " + shipped))
    assert "USE TEMP B-TREE FOR ORDER BY" not in plan and "PRIMARY KEY (rowid>" in plan, plan
    # and the thing it replaced did sort, which is what made it take 46 s on 17.7M rows
    old = " | ".join(str(r[3]) for r in alert_db.execute("EXPLAIN QUERY PLAN " + straight))
    assert "USE TEMP B-TREE FOR ORDER BY" in old, old
