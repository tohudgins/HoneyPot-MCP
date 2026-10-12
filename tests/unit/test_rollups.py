"""The hourly rollups must give exactly the answers a scan of the alert table would.

Every windowed statistic here is checked against a brute-force count over the raw rows, for windows
that start on an hour, mid-hour, inside the current hour, and before any data. The cost of a
statistic must depend on the size of the answer, but never at the price of a different answer.
"""

from __future__ import annotations

import asyncio
import importlib.util
import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, text


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    """A file-backed SQLite, so every session has its own connection as in production."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(
        get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path}/rollups.db", raising=False
    )
    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _ingest(n: int, seed: int = 7, hours_back: int = 30) -> datetime:
    """Push `n` random events through the real buffer and return the reference time."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    rng = random.Random(seed)
    now = datetime.now(UTC)
    ips = [f"203.0.113.{i}" for i in range(1, 15)]
    types = ["ssh_login_failed", "http_probe", "sip_scan", "redis_config_set"]
    buf = event_buffer.get_buffer()
    await buf.start()
    for _ in range(n):
        await buf.submit(
            PendingEvent(
                honeypot_id=rng.choice([1, 2, 3, None]),
                source_ip=rng.choice(ips),
                source_port=1000,
                event_type=rng.choice(types),
                payload={},
                severity=rng.choice(list(AlertSeverity)),
                timestamp=now - timedelta(minutes=rng.randint(0, hours_back * 60)),
            )
        )
    await asyncio.sleep(1.5)
    await buf.stop()
    return now


async def _brute(since: datetime | None, ip: str | None = None):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        q = select(Alert.severity, Alert.event_type, Alert.source_ip, Alert.honeypot_id)
        if since is not None:
            q = q.where(Alert.timestamp >= since)
        if ip is not None:
            q = q.where(Alert.source_ip == ip)
        rows = (await session.execute(q)).all()
    return rows


def _expected(rows):
    return {
        "total_alerts": len(rows),
        "unique_source_ips": len({r[2] for r in rows}),
        "by_severity": dict(Counter(r[0].value for r in rows)),
        "ips": Counter(r[2] for r in rows),
        "types": Counter(r[1] for r in rows),
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offset",
    [
        None,
        timedelta(minutes=20),  # inside the current hour
        timedelta(minutes=95),  # starts mid-hour, spans a whole hour
        timedelta(hours=5, minutes=17),
        timedelta(hours=26, minutes=41),
        timedelta(hours=200),  # before any data
    ],
)
async def test_windowed_stats_equal_a_scan_of_the_alert_table(offset):
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    now = await _ingest(900)
    since = None if offset is None else now - offset
    async with get_session() as session:
        got = await rollups.stats(session, since, top=50)
    want = _expected(await _brute(since))
    assert got["total_alerts"] == want["total_alerts"]
    assert got["unique_source_ips"] == want["unique_source_ips"]
    assert got["by_severity"] == want["by_severity"]
    assert {r["ip"]: r["count"] for r in got["top_source_ips"]} == dict(want["ips"])
    assert {r["type"]: r["count"] for r in got["top_event_types"]} == dict(want["types"])
    counts = [r["count"] for r in got["top_source_ips"]]
    assert counts == sorted(counts, reverse=True), "top sources come back largest first"


@pytest.mark.asyncio
async def test_per_source_stats_and_sensor_lists_equal_a_scan():
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    now = await _ingest(600, seed=11)
    ip = "203.0.113.4"
    since = now - timedelta(hours=7, minutes=30)
    async with get_session() as session:
        got = await rollups.stats(session, since, ip=ip, top=50)
        sensors = await rollups.honeypot_ids(session, since, ip)
    rows = await _brute(since, ip)
    assert got["total_alerts"] == len(rows)
    assert {r["type"]: r["count"] for r in got["top_event_types"]} == dict(
        Counter(r[1] for r in rows)
    )
    assert sensors == {r[3] for r in rows if r[3] is not None}


@pytest.mark.asyncio
async def test_hit_counts_equal_a_group_by_and_ignore_events_with_no_sensor():
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    await _ingest(500, seed=3)
    async with get_session() as session:
        got = await rollups.hit_counts(session)
    want = Counter(r[3] for r in await _brute(None) if r[3] is not None)
    assert got == dict(want)


@pytest.mark.asyncio
async def test_any_writer_is_counted_not_only_the_flusher_and_a_rollback_undoes_the_count():
    """The watchdog's disk-full alert, `create_alert` and every future writer write Alert rows
    without the flusher. Counting is hooked into the flush, so none of them can be forgotten, and
    a failed transaction takes its counts with it."""
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertRollup, AlertSeverity

    async with get_session() as session:
        await queries.create_alert(
            session,
            honeypot_id=None,
            source_ip="198.51.100.9",
            event_type="watchdog_x",
            payload={},
            severity=AlertSeverity.CRITICAL,
        )
    async with get_session() as session:
        assert (await session.execute(select(func.sum(AlertRollup.count)))).scalar_one() == 1

    with pytest.raises(RuntimeError):
        async with get_session() as session:
            session.add(
                Alert(
                    source_ip="198.51.100.10",
                    event_type="x",
                    payload={},
                    severity=AlertSeverity.LOW,
                )
            )
            await session.flush()
            raise RuntimeError("the transaction fails after the flush")
    async with get_session() as session:
        assert (await session.execute(select(func.sum(AlertRollup.count)))).scalar_one() == 1
        assert (await session.execute(select(func.count()).select_from(Alert))).scalar_one() == 1


@pytest.mark.asyncio
async def test_lifetime_figures_survive_pruning_the_raw_alerts():
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    now = await _ingest(700, seed=5)
    async with get_session() as session:
        before = await rollups.stats(session, None, top=50)
        recent_before = await rollups.stats(session, now - timedelta(hours=2), top=50)
        await session.execute(
            text("DELETE FROM alerts WHERE timestamp < :cut"),
            {"cut": (now - timedelta(hours=10)).strftime("%Y-%m-%d %H:%M:%S.%f")},
        )
    async with get_session() as session:
        after = await rollups.stats(session, None, top=50)
        recent_after = await rollups.stats(session, now - timedelta(hours=2), top=50)
    assert after == before, "pruning raw rows must not change lifetime statistics"
    assert recent_after == recent_before


@pytest.mark.asyncio
async def test_only_a_honeytoken_event_is_copied_into_attacker_events():
    """Every event used to be copied there in full (payload included), doubling the table."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import (
        AlertSeverity,
        AttackerEvent,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label="t",
            token_value="cred:x",
            status=HoneytokenStatus.ACTIVE,
            token_meta={},
        )
        session.add(token)
        await session.flush()
        token_id = token.id

    buf = event_buffer.get_buffer()
    await buf.start()
    now = datetime.now(UTC)
    for i in range(5):
        await buf.submit(
            PendingEvent(
                honeypot_id=1,
                source_ip="203.0.113.77",
                source_port=1,
                event_type="http_probe",
                payload={"i": i},
                severity=AlertSeverity.LOW,
                timestamp=now,
            )
        )
    await buf.submit(
        PendingEvent(
            honeypot_id=1,
            source_ip="203.0.113.77",
            source_port=1,
            event_type="honeytoken_triggered_credential_via_ssh_login",
            payload={},
            severity=AlertSeverity.CRITICAL,
            timestamp=now,
            honeytoken_id=token_id,
        )
    )
    await asyncio.sleep(1.5)
    await buf.stop()
    async with get_session() as session:
        rows = (await session.execute(select(AttackerEvent))).scalars().all()
    assert [r.honeytoken_id for r in rows] == [token_id], "five plain events, one token trail"


def _load_migration():
    path = (
        Path(__file__).resolve().parents[2]
        / "src/honeypot_mcp/migrations/versions/0017_alert_rollups.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0017", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_the_migration_backfills_exactly_what_a_group_by_of_the_existing_alerts_gives():
    """A database that already holds alerts when it upgrades (the live droplet: 4.9M rows) must get
    rollups equal to those alerts, not an empty table that makes every statistic read zero."""
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import create_engine

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.database import get_session

    await _ingest(400, seed=21)
    async with get_session() as session:
        want = {
            tuple(r)
            for r in (
                await session.execute(
                    text(
                        "SELECT bucket, severity, event_type, source_ip, honeypot_id, count "
                        "FROM alert_rollups"
                    )
                )
            ).all()
        }
        await session.execute(text("DROP TABLE alert_rollups"))
    assert want

    engine = create_engine(get_settings().database_url.replace("+aiosqlite", ""))
    try:
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                _load_migration().upgrade()
            got = {
                tuple(r)
                for r in conn.execute(
                    text(
                        "SELECT bucket, severity, event_type, source_ip, honeypot_id, count "
                        "FROM alert_rollups"
                    )
                ).all()
            }
    finally:
        engine.dispose()
    assert got == want


def test_the_sensor_expression_renders_identically_in_select_and_group_by_on_postgresql():
    """PostgreSQL rejects `coalesce(x, $3)` in the SELECT list with `coalesce(x, $5)` in GROUP BY
    (two different bound parameters are two different expressions); SQLite accepts it, so only a
    run against PostgreSQL found it. The tests run on SQLite by default, so the rendered SQL is
    checked directly: the same literal on both sides, and no bound parameter standing in for it."""
    from sqlalchemy.dialects import postgresql

    from honeypot_mcp.storage import rollups

    sql = str(rollups._raw(None, None, None).compile(dialect=postgresql.dialect()))
    assert sql.count("coalesce(alerts.honeypot_id, 0)") == 2, sql
    assert "coalesce(alerts.honeypot_id, %" not in sql and "$" not in sql.split("GROUP BY")[1], sql
