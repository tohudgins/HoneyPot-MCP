"""The console overview reads the hourly rollups; it must say what the raw alerts say, fast.

On 17.5M real alerts the first version did not return in 100 s for any window, because every poll
re-aggregated the raw table ten times over. These tests pin the two properties that fixed it: the
numbers equal a plain computation (so the rollups and raw edge hours are combined exactly), and the
one query that is not served by a rollup, the CRITICAL geography lookup, seeks a partial index instead
of reading every row in the window.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


# (hours ago, source, severity, sensor index, acknowledged, country). The ages sit at least 6 minutes
# from every window edge used below, so the test cannot straddle a boundary while it runs.
ALERTS = [
    (0.30, "91.121.7.1", "low", 0, False, None),
    (0.40, "91.121.7.1", "medium", 0, False, None),
    (0.50, "91.121.7.2", "critical", 1, False, "France"),
    (2.60, "91.121.7.2", "high", 1, True, None),
    (2.70, "91.121.7.3", "low", 0, False, None),
    (5.50, "91.121.7.1", "critical", 0, False, "France"),
    (5.60, "91.121.7.4", "low", 1, False, None),
    (11.9, "91.121.7.4", "medium", 1, False, None),
    (30.2, "91.121.7.5", "critical", 0, True, "Brazil"),
    (30.4, "91.121.7.1", "low", 1, False, None),
    (47.9, "91.121.7.6", "high", 0, False, None),
    (48.1, "91.121.7.7", "low", 0, False, None),  # just outside a 48 h window
    (80.7, "91.121.7.8", "medium", 1, False, None),
    (160.0, "91.121.7.9", "low", 0, False, None),
    (200.0, "91.121.7.10", "low", 1, False, None),  # outside a 7-day window
]


async def _seed() -> list[int]:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeypot,
        HoneypotStatus,
        HoneypotType,
    )

    now = datetime.now(UTC)
    async with get_session() as session:
        sensors = []
        for n, kind in enumerate((HoneypotType.SSH, HoneypotType.HTTP)):
            hp = Honeypot(
                name=f"hp-{kind.value}",
                type=kind,
                port=2000 + n,
                status=HoneypotStatus.RUNNING,
                config={},
            )
            session.add(hp)
            sensors.append(hp)
        await session.flush()
        ids = [hp.id for hp in sensors]
        for ago, ip, severity, sensor, acked, country in ALERTS:
            payload = {"enrichment": {"geoip": {"country": country}}} if country else {}
            session.add(
                Alert(
                    source_ip=ip,
                    event_type="probe",
                    severity=AlertSeverity(severity),
                    honeypot_id=ids[sensor],
                    acknowledged=acked,
                    payload=payload,
                    timestamp=now - timedelta(hours=ago),
                )
            )
    return ids


@pytest.mark.parametrize("hours", [1, 6, 24, 48, 168])
async def test_every_number_equals_a_plain_computation_over_the_raw_alerts(hours):
    from honeypot_mcp.console.server import _overview

    ids = await _seed()
    inside = [a for a in ALERTS if a[0] < hours]

    data = await _overview(hours)
    stats = data["stats"]

    assert stats["events"] == len(inside)
    assert stats["unique_ips"] == len({a[1] for a in inside})
    for severity in ("critical", "high", "medium", "low"):
        assert stats[severity] == sum(1 for a in inside if a[2] == severity), severity
    assert stats["untriaged"] == sum(1 for a in inside if not a[4])

    by_ip: dict[str, int] = {}
    for a in inside:
        by_ip[a[1]] = by_ip.get(a[1], 0) + 1
    want_top = sorted(by_ip.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    assert [(t["ip"], t["hits"]) for t in data["top_attackers"]] == want_top

    hits = {h["name"]: h["hits"] for h in data["honeypots"]}
    assert hits == {
        "hp-ssh": sum(1 for a in inside if ids[a[3]] == ids[0]),
        "hp-http": sum(1 for a in inside if ids[a[3]] == ids[1]),
    }

    points = data["series"]["points"]
    assert sum(p["routine"] + p["serious"] for p in points) == len(inside), "chart total = headline"
    assert sum(p["serious"] for p in points) == sum(
        1 for a in inside if a[2] in ("high", "critical")
    )
    assert 5 <= len(points) <= 60

    countries: dict[str, int] = {}
    for a in inside:
        if a[2] == "critical" and a[5]:
            countries[a[5]] = countries.get(a[5], 0) + 1
    assert {c["country"]: c["hits"] for c in data["top_countries"]} == countries


async def test_chart_columns_are_clock_aligned_so_they_do_not_move_between_polls():
    """Hour-and-longer buckets are whole hours (or 6-hour blocks): sums of whole rollup rows."""
    from honeypot_mcp.console.server import _overview

    await _seed()
    for hours, step in ((24, 1), (168, 6)):
        stamps = [
            datetime.fromisoformat(p["t"]) for p in (await _overview(hours))["series"]["points"]
        ]
        assert all(s.minute == 0 and s.second == 0 and s.hour % step == 0 for s in stamps), hours
        assert all(b - a == timedelta(hours=step) for a, b in zip(stamps, stamps[1:], strict=False))


async def test_the_critical_geography_lookup_seeks_the_partial_index():
    """SQLite only uses `ix_alerts_urgent` when the query states its predicate as literal text; with a
    bound parameter the planner reads every row in the window to test its severity (12.7 s against
    0.47 s for 7 days of 17.5M alerts). The plan is read from the statement the app really executes."""
    from sqlalchemy import event, func, select

    from honeypot_mcp.console.server import _critical_rows
    from honeypot_mcp.storage.database import get_session

    async with get_session() as session:
        connection = await session.connection()
        if connection.dialect.name != "sqlite":
            pytest.skip("partial-index matching is a SQLite planner behaviour")
        seen: dict[str, object] = {}

        def grab(_conn, _cursor, statement, parameters, _context, _many):  # noqa: ANN001
            seen["sql"], seen["params"] = statement, parameters

        sync_engine = session.bind.sync_engine  # type: ignore[union-attr]
        event.listen(sync_engine, "before_cursor_execute", grab)
        try:
            rows = _critical_rows(datetime.now(UTC) - timedelta(days=7))
            await session.execute(select(func.count()).select_from(rows))
        finally:
            event.remove(sync_engine, "before_cursor_execute", grab)
        plan = (
            await connection.exec_driver_sql(
                "EXPLAIN QUERY PLAN " + str(seen["sql"]), seen["params"]
            )
        ).fetchall()

    detail = " | ".join(str(row[-1]) for row in plan)
    assert "ix_alerts_urgent" in detail, f"the CRITICAL lookup lost its index: {detail}"


async def _seed_a_run_that_ended_long_ago(days_ago: int = 30) -> datetime:
    """Alerts only in the last two days of a run that finished `days_ago` days ago, as a restored backup."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    end = (datetime.now(UTC) - timedelta(days=days_ago)).replace(microsecond=0)
    async with get_session() as session:
        # Oldest first: alert ids are chronological on a real server, and the window's end is read from the
        # highest id (an index seek) rather than by scanning for the largest timestamp.
        for hours_back, severity in (
            (40.0, "low"),
            (20.0, "medium"),
            (3.0, "low"),
            (0.2, "critical"),
        ):
            session.add(
                Alert(
                    source_ip="203.0.113.9",
                    event_type="probe",
                    severity=AlertSeverity(severity),
                    timestamp=end - timedelta(hours=hours_back),
                    payload={},
                )
            )
    return end - timedelta(hours=0.2)


async def test_a_saved_run_is_shown_up_to_its_newest_alert_not_up_to_the_wall_clock(monkeypatch):
    """A restored backup opened a month later: "the last 24 hours" ended now and held nothing, so the
    console showed a blank page for a run with data. In analysis mode the window ends at the newest alert."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.console.server import _overview
    from honeypot_mcp.tools import _window

    newest = await _seed_a_run_that_ended_long_ago()

    monkeypatch.setattr(get_settings(), "analysis_mode", False)
    _window.reset_for_tests()
    live = await _overview(24)
    assert live["stats"]["events"] == 0 and live["saved_run"] is False and live["data_ends"] is None

    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    _window.reset_for_tests()
    saved = await _overview(24)
    # the three alerts inside 24 h of the newest one (the one 40 h back is outside), split by severity
    assert saved["stats"]["events"] == 3
    assert (saved["stats"]["critical"], saved["stats"]["medium"], saved["stats"]["low"]) == (
        1,
        1,
        1,
    )
    assert saved["saved_run"] is True and saved["data_ends"] == newest.isoformat()
    assert (
        sum(p["routine"] + p["serious"] for p in saved["series"]["points"]) == 3
    )  # the chart agrees
    _window.reset_for_tests()


async def test_the_page_calls_a_saved_run_a_saved_run():
    """ "live · 10:25:58" on a month-old backup is a lie; the page switches on the server's flag."""
    from honeypot_mcp.console import server as console

    page = (console.Path(console.__file__).parent / "static" / "index.html").read_text(
        encoding="utf-8"
    )

    assert "d.saved_run" in page and "saved run · data ends" in page and '"live · "' in page


def _page() -> str:
    from honeypot_mcp.console import server as console

    return (console.Path(console.__file__).parent / "static" / "index.html").read_text(
        encoding="utf-8"
    )


def test_the_chart_labels_are_selected_by_a_rule_that_matches_them():
    """The labels are `<text class="axis">`; the rule was `.axis text` (a `text` INSIDE `.axis`), which
    matches nothing, so every axis label rendered black on the dark surface (found in a screenshot)."""
    import re

    page = _page()

    assert re.search(r"text\.axis\s*\{[^}]*fill:\s*var\(--muted\)", page)
    assert not re.search(r"(^|\n)\.axis text\s*\{", page)
    assert '<text class="axis"' in page  # the element the rule has to match


def test_a_chart_longer_than_a_day_names_the_day_and_a_saved_run_says_latest():
    """Over 7 days with 6-hour bars the labels read "08:00 ... 08:00" with no way to tell the days apart."""
    page = _page()

    assert "toLocaleDateString" in page and "multiDay" in page
    assert "Latest activity" in page and "Live activity" in page and "feed-title" in page


def test_a_six_digit_axis_number_is_shortened_and_the_last_label_stays_inside_the_chart():
    """`356610` is wider than the chart's 40px left margin and the last date label ran off the right edge:
    both were cut off in a screenshot of a 17.7M-alert run."""
    page = _page()

    assert "const short = (n)" in page and "${short(t)}" in page
    assert 'x > W - 52 ? "end" : "middle"' in page
