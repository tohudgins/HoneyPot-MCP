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
