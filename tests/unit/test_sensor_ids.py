"""A removed sensor's id is never handed to a new one, and removal keeps the rollups honest.

Found on the live droplet: removing the newest sensor and deploying another gave the new one the old
id (SQLite reuses the highest rowid), so the old sensor's history was attributed to it. And removal
NULLed the sensor on raw alerts but left the rollups pointing at the old id, so the rollups stopped
agreeing with the alerts.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select, text

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(
        get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path}/ids.db", raising=False
    )
    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _sensor(name: str):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        hp = Honeypot(
            name=name, type=HoneypotType.HTTP, port=8000, status=HoneypotStatus.STOPPED, config={}
        )
        session.add(hp)
        await session.flush()
        return hp.id


async def _alerts(honeypot_id: int | None, n: int, ip: str = "203.0.113.5") -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        session.add_all(
            Alert(
                honeypot_id=honeypot_id,
                source_ip=ip,
                event_type="x",
                payload={},
                severity=AlertSeverity.LOW,
                timestamp=datetime.now(UTC) - timedelta(minutes=i),
            )
            for i in range(n)
        )


@pytest.mark.asyncio
async def test_a_sensor_created_after_removing_the_newest_gets_a_new_id():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    first, second = await _sensor("a"), await _sensor("b")
    await honeypot_stop(name="b", remove=True)
    third = await _sensor("c")
    assert third not in (first, second) and third > second


@pytest.mark.asyncio
async def test_removal_refiles_the_rollups_so_they_still_equal_the_alerts():
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.tools.honeypot import honeypot_stop

    keep, gone = await _sensor("keep"), await _sensor("gone")
    await _alerts(keep, 4)
    await _alerts(gone, 6)
    await _alerts(None, 3)  # events that never had a sensor: the id-0 rows already exist
    await _alerts(gone, 2, ip="198.51.100.9")

    await honeypot_stop(name="gone", remove=True)

    async with get_session() as session:
        per_sensor = await rollups.hit_counts(session)
        total = await rollups.stats(session, None)
        raw = dict(
            (
                await session.execute(
                    select(Alert.honeypot_id, func.count()).group_by(Alert.honeypot_id)
                )
            ).all()
        )
        ids_left = {
            r[0]
            for r in (
                await session.execute(text("SELECT DISTINCT honeypot_id FROM alert_rollups"))
            ).all()
        }
    assert per_sensor == {keep: 4}, "the removed sensor no longer has hits of its own"
    assert raw == {keep: 4, None: 11}, "raw alerts: the removed sensor's 8 joined the 3 with none"
    assert total["total_alerts"] == 15, "and nothing was lost"
    assert gone not in ids_left


@pytest.mark.asyncio
async def test_the_migration_seeds_the_counter_past_every_id_ever_referenced(tmp_path):
    """An old SQLite database (no AUTOINCREMENT) whose newest sensors were removed: their ids
    survive in alerts and rollups, and the new counter must start beyond them."""
    import importlib.util
    from pathlib import Path

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = (
        Path(__file__).resolve().parents[2]
        / "src/honeypot_mcp/migrations/versions/0019_honeypot_autoinc.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0019", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    engine = sa.create_engine(f"sqlite:///{tmp_path}/old.db")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE honeypots (id INTEGER NOT NULL PRIMARY KEY, name VARCHAR(128) NOT NULL UNIQUE, port INTEGER)"
            )
        )
        conn.execute(text("CREATE TABLE alerts (id INTEGER PRIMARY KEY, honeypot_id INTEGER)"))
        conn.execute(text("CREATE TABLE alert_rollups (honeypot_id INTEGER NOT NULL)"))
        conn.execute(text("INSERT INTO honeypots (id, name, port) VALUES (1, 'a', 1), (2, 'b', 2)"))
        conn.execute(
            text("INSERT INTO alerts (honeypot_id) VALUES (2), (9)")
        )  # 9: a removed sensor
        conn.execute(text("INSERT INTO alert_rollups (honeypot_id) VALUES (12)"))  # 12: another
        with Operations.context(MigrationContext.configure(conn)):
            migration.upgrade()
            migration.upgrade()  # idempotent
        sql = conn.execute(text("SELECT sql FROM sqlite_master WHERE name = 'honeypots'")).scalar()
        assert "AUTOINCREMENT" in sql.upper()
        assert (
            conn.execute(text("SELECT seq FROM sqlite_sequence WHERE name = 'honeypots'")).scalar()
            == 12
        )
        conn.execute(text("INSERT INTO honeypots (name, port) VALUES ('new', 3)"))
        assert conn.execute(text("SELECT id FROM honeypots WHERE name = 'new'")).scalar() == 13
        assert conn.execute(text("SELECT count(*) FROM honeypots")).scalar() == 3
    engine.dispose()
