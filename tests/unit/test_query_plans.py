"""Queries that run on every `honeypot_list` must not scan the alerts table.

Found on the live droplet: with 4.9M alerts `honeypot_list` took 51 s, because the per-sensor hit
count (`GROUP BY honeypot_id`) had no index and read every row. The alert table grows by gigabytes a
day on a public host, so a plan regression is invisible in a small test database and fatal in
production; the plan itself is what is pinned here.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


@pytest.mark.asyncio
async def test_the_per_sensor_hit_count_is_answered_from_an_index_not_a_table_scan():
    from honeypot_mcp.storage.database import get_session

    async with get_session() as session:
        bind = session.bind.dialect.name
        if bind != "sqlite":
            pytest.skip("EXPLAIN QUERY PLAN is the SQLite form; the index is asserted below")
        plan = (
            await session.execute(
                text(
                    "EXPLAIN QUERY PLAN SELECT honeypot_id, count(*) FROM alerts "
                    "WHERE honeypot_id IS NOT NULL GROUP BY honeypot_id"
                )
            )
        ).all()
    detail = " ".join(str(row[-1]) for row in plan)
    assert "ix_alerts_honeypot_id" in detail, f"full scan of alerts: {detail}"
    assert "SCAN alerts" not in detail.replace("COVERING INDEX", "")


@pytest.mark.asyncio
async def test_the_alert_table_declares_the_honeypot_index():
    """On PostgreSQL there is no EXPLAIN QUERY PLAN to read, so assert the index exists."""
    from sqlalchemy import inspect

    from honeypot_mcp.storage.database import get_session

    async with get_session() as session:
        conn = await session.connection()
        names = await conn.run_sync(
            lambda sync_conn: {ix["name"] for ix in inspect(sync_conn).get_indexes("alerts")}
        )
    assert "ix_alerts_honeypot_id" in names
