"""Tests for Alembic-driven schema management.

Verifies: a fresh persistent (file-backed) DB gets the full schema applied via
Alembic; the alembic_version row is populated; running init_db a second time
is a no-op (idempotent); a pre-existing DB without alembic_version still ends
up with the right schema (the baseline migration is idempotent via create_all).
"""

import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect


@pytest.fixture
def tmp_db_url(tmp_path: Path):
    """File-backed sqlite path for one test, cleaned up after."""
    db_path = tmp_path / "test.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    sync_url = f"sqlite:///{db_path}"
    # The settings singleton caches; force a fresh load by mutating env + clearing.
    prev = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = url
    import honeypot_mcp.config as cfg_mod

    cfg_mod._settings = None
    yield url, sync_url
    if prev is None:
        del os.environ["DATABASE_URL"]
    else:
        os.environ["DATABASE_URL"] = prev
    cfg_mod._settings = None


@pytest.mark.asyncio
async def test_init_db_runs_alembic_on_fresh_persistent_db(tmp_db_url):
    url, sync_url = tmp_db_url
    from honeypot_mcp.storage import database

    # Reset module-level engine cache so it picks up the tmp URL
    database._engine = None
    database._session_factory = None

    await database.init_db()
    await database.close_db()

    engine = create_engine(sync_url)
    try:
        tables = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    # Schema is in place
    assert "honeypots" in tables
    assert "alerts" in tables
    assert "subscriptions" in tables  # Round 3 table
    assert "suppression_rules" in tables  # Round 3 table
    # Alembic took ownership of versioning
    assert "alembic_version" in tables


@pytest.mark.asyncio
async def test_init_db_is_idempotent(tmp_db_url):
    url, sync_url = tmp_db_url
    from honeypot_mcp.storage import database

    database._engine = None
    database._session_factory = None

    await database.init_db()
    await database.close_db()
    database._engine = None
    database._session_factory = None
    # Second invocation should be a clean no-op (Alembic sees head already current)
    await database.init_db()
    await database.close_db()

    engine = create_engine(sync_url)
    try:
        tables = inspect(engine).get_table_names()
    finally:
        engine.dispose()
    assert "alembic_version" in tables


@pytest.mark.asyncio
async def test_baseline_migration_is_idempotent_against_pre_alembic_db(tmp_path):
    """An existing dev DB created with the old `create_all`-only init_db has all
    the tables but no alembic_version row. The baseline migration uses
    create_all under the hood, so it must succeed and just stamp the version
    row — not crash on duplicate-table errors."""
    db_path = tmp_path / "preexisting.db"
    sync_url = f"sqlite:///{db_path}"
    async_url = f"sqlite+aiosqlite:///{db_path}"

    # Simulate the pre-Alembic state: tables exist, no alembic_version.
    from honeypot_mcp.storage.models import Base

    sync_engine = create_engine(sync_url)
    Base.metadata.create_all(sync_engine)
    pre_tables = set(inspect(sync_engine).get_table_names())
    sync_engine.dispose()
    assert "honeypots" in pre_tables
    assert "alembic_version" not in pre_tables

    # Now point the app at this DB and call init_db.
    prev = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = async_url
    import honeypot_mcp.config as cfg_mod

    cfg_mod._settings = None
    from honeypot_mcp.storage import database

    database._engine = None
    database._session_factory = None
    try:
        await database.init_db()
        await database.close_db()
    finally:
        if prev is None:
            del os.environ["DATABASE_URL"]
        else:
            os.environ["DATABASE_URL"] = prev
        cfg_mod._settings = None
        database._engine = None
        database._session_factory = None

    sync_engine = create_engine(sync_url)
    try:
        post_tables = set(inspect(sync_engine).get_table_names())
    finally:
        sync_engine.dispose()
    # alembic_version is now present — Alembic adopted the existing DB.
    assert "alembic_version" in post_tables
    assert "honeypots" in post_tables
