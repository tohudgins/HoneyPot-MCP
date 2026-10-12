"""Archive-then-delete must scale with chunks, not with the table.

Found by running `alerts_prune` against a copy of the live 4.9M-row database: the manual tool built
the whole archive as one string (1.35 GB of peak memory for 1M rows, so ~6.6 GB for the real table
on a 4 GB host) while the unattended sweep already streamed. They now share one implementation
(`retention.py`); the streamed run archived 4M rows in 54 s at 181 MB peak. These tests pin the
properties that make that true, with a small chunk size so a handful of rows crosses many chunks.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(
        get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path}/ret.db", raising=False
    )
    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(n: int, age_days: float) -> list[int]:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    stamp = datetime.now(UTC) - timedelta(days=age_days)
    async with get_session() as session:
        rows = [
            Alert(
                source_ip=f"203.0.113.{i % 200}",
                event_type="x",
                payload={"i": i},
                severity=AlertSeverity.LOW,
                timestamp=stamp + timedelta(seconds=i),
            )
            for i in range(n)
        ]
        session.add_all(rows)
        await session.flush()
        return [r.id for r in rows]


async def _count() -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return (await session.execute(select(func.count()).select_from(Alert))).scalar_one()


@pytest.fixture
def small_chunks(monkeypatch):
    """Force chunking: the real chunk is thousands of rows."""
    from honeypot_mcp.storage import queries

    real_iter, real_delete = queries.iter_alert_archive_chunks, queries.delete_alerts_chunk
    seen = {"archive_chunks": 0, "delete_calls": 0}

    async def iterate(session, cutoff):
        async for item in real_iter(session, cutoff, chunk_rows=40):
            seen["archive_chunks"] += 1
            yield item

    async def delete(session, cutoff, *, limit=0, max_id=None):
        seen["delete_calls"] += 1
        return await real_delete(session, cutoff, limit=40, max_id=max_id)

    monkeypatch.setattr(queries, "iter_alert_archive_chunks", iterate)
    monkeypatch.setattr(queries, "delete_alerts_chunk", delete)
    return seen


@pytest.mark.asyncio
async def test_the_archive_is_streamed_complete_ordered_and_leaves_no_partial_file(small_chunks):
    import json
    from pathlib import Path

    from honeypot_mcp import retention
    from honeypot_mcp.config import get_settings

    ids = await _seed(230, age_days=200)
    cutoff = datetime.now(UTC) - timedelta(days=90)
    last_id, info = await retention.archive_alerts(cutoff, prefix="stream-test")

    assert small_chunks["archive_chunks"] == 6, "230 rows in chunks of 40"
    assert last_id == max(ids)
    assert info["lines"] == 230
    lines = Path(info["path"]).read_text().splitlines()
    assert [json.loads(x)["id"] for x in lines] == sorted(ids), "every row, in id order"
    assert info["bytes"] == os.path.getsize(info["path"])
    assert not list(get_settings().reports_dir.glob("*.partial")), "renamed into place when done"


@pytest.mark.asyncio
async def test_deletion_runs_in_bounded_chunks_and_never_past_what_was_archived(small_chunks):
    from honeypot_mcp import retention

    await _seed(230, age_days=200)
    cutoff = datetime.now(UTC) - timedelta(days=90)
    max_id, _info = await retention.archive_alerts(cutoff, prefix="confine-test")
    late = await _seed(5, age_days=200)  # older than the cutoff but written AFTER the archive ran
    assert min(late) > max_id

    alerts_deleted, _events = await retention.delete_before(cutoff, max_id)

    assert alerts_deleted == 230
    assert small_chunks["delete_calls"] >= 6, "one transaction per chunk, not one huge DELETE"
    assert await _count() == 5, "a row that is not in the archive must not be deleted"


@pytest.mark.asyncio
async def test_a_failure_part_way_leaves_no_archive_and_deletes_nothing(monkeypatch, small_chunks):
    from honeypot_mcp import retention
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import queries

    await _seed(100, age_days=200)
    cutoff = datetime.now(UTC) - timedelta(days=90)
    real = queries.iter_alert_archive_chunks

    async def fail_on_the_second_chunk(session, cutoff):
        n = 0
        async for item in real(session, cutoff):
            n += 1
            if n == 2:
                raise OSError("disk full")
            yield item

    monkeypatch.setattr(queries, "iter_alert_archive_chunks", fail_on_the_second_chunk)
    with pytest.raises(OSError, match="disk full"):
        await retention.archive_alerts(cutoff, prefix="fail-test")

    assert not list(get_settings().reports_dir.glob("fail-test*")), "no half-written archive"
    assert await _count() == 100


@pytest.mark.asyncio
async def test_nothing_old_enough_writes_no_file_and_makes_nothing_deletable():
    from honeypot_mcp import retention
    from honeypot_mcp.config import get_settings

    await _seed(10, age_days=1)
    last_id, info = await retention.archive_alerts(
        datetime.now(UTC) - timedelta(days=90), prefix="empty-test"
    )
    assert (last_id, info) == (None, None)
    assert not list(get_settings().reports_dir.glob("empty-test*"))
    assert await retention.delete_before(datetime.now(UTC) - timedelta(days=90), 0) == (0, 0)
    assert await _count() == 10


@pytest.mark.asyncio
async def test_lifetime_rollups_survive_a_prune():
    """The statistics read the rollups, so deleting raw rows must not change them."""
    from honeypot_mcp import retention
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    await _seed(120, age_days=200)
    async with get_session() as session:
        before = await rollups.stats(session, None)
    cutoff = datetime.now(UTC) - timedelta(days=90)
    max_id, _ = await retention.archive_alerts(cutoff, prefix="rollup-test")
    await retention.delete_before(cutoff, max_id)
    assert await _count() == 0
    async with get_session() as session:
        assert await rollups.stats(session, None) == before
