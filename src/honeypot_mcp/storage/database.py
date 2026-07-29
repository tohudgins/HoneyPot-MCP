from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.models import Base

log = logging.getLogger(__name__)

_engine = None
_session_factory = None

# Sessions currently open. `close_db` waits on this so a fire-and-forget write
# is not cut off mid-statement by `dispose()`.
_active_sessions = 0
# Bounded so a leaked session can never hang shutdown.
_CLOSE_GRACE_SECONDS = 2.0


def _get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            future=True,
        )
        _apply_sqlite_pragmas(_engine, settings.database_url)
    return _engine


def _apply_sqlite_pragmas(engine, url: str) -> None:
    """Enable WAL mode + sane defaults for file-backed SQLite.

    WAL is what lets Grafana (and any other observer) read the alerts table
    concurrently with the MCP writer. Without it, SQLite's default `delete`
    journal-mode serialises readers behind writers, and a dashboard refresh
    can briefly stall event ingestion. WAL also dramatically improves write
    throughput under burst load.

    In-memory and Postgres URLs short-circuit. SQLite-only PRAGMAs would error
    against other backends, so we feature-detect by URL scheme.
    """
    if not url.startswith("sqlite") or ":memory:" in url:
        return

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _conn_record) -> None:  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        # WAL: readers don't block writers and vice versa.
        cursor.execute("PRAGMA journal_mode=WAL")
        # NORMAL: durability slightly relaxed vs FULL, ~2x write speed, still
        # crash-safe for our use case (lost transactions on power loss are
        # acceptable for honeypot telemetry).
        cursor.execute("PRAGMA synchronous=NORMAL")
        # 5s busy timeout — if a concurrent reader is mid-checkpoint, wait
        # instead of immediately erroring with SQLITE_BUSY.
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def _get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=_get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
        )
    return _session_factory


async def init_db() -> None:
    """Bring the schema up to date.

    For persistent DBs (file-backed SQLite, Postgres, etc.) we run Alembic
    migrations so users keep their data across upgrades. For in-memory test
    DBs, Alembic is overkill — we just `create_all` and move on.

    If Alembic fails for any reason, we fall back to `create_all` so the
    server still starts. This keeps dev experience smooth: a misconfigured
    migration shouldn't crash the whole MCP."""
    settings = get_settings()
    if ":memory:" in settings.database_url:
        engine = _get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(None, _run_alembic_upgrade)
    except Exception as e:
        log.warning("Alembic upgrade failed (%s) — falling back to create_all.", e)
        engine = _get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)


# Revision ids that were renamed after the fact. Alembic's `alembic_version`
# column is VARCHAR(32); anything longer is silently accepted by SQLite and
# rejected by PostgreSQL, so `0007_drop_attacker_profile_shodan_data` (38 chars)
# had to be shortened. A database stamped with the old id before that change
# would otherwise fail with "Can't locate revision", so rewrite it in place.
_RENAMED_REVISIONS = {
    "0007_drop_attacker_profile_shodan_data": "0007_drop_profile_shodan",
}


def _rewrite_renamed_revisions(sync_url: str) -> None:
    """Update any stamp that refers to a revision id we have since renamed."""
    from sqlalchemy import create_engine, text

    try:
        engine = create_engine(sync_url)
        with engine.begin() as conn:
            if not engine.dialect.has_table(conn, "alembic_version"):
                return
            for old, new in _RENAMED_REVISIONS.items():
                result = conn.execute(
                    text("UPDATE alembic_version SET version_num = :new WHERE version_num = :old"),
                    {"new": new, "old": old},
                )
                if result.rowcount:
                    log.info("Rewrote migration stamp %s → %s", old, new)
        engine.dispose()
    except Exception as e:  # noqa: BLE001 — best effort; upgrade reports real errors
        log.debug("Could not check for renamed revisions: %s", e)


def _run_alembic_upgrade() -> None:
    """Synchronous Alembic invocation. Imported here so test suites that use
    in-memory DBs never load Alembic at all."""
    from importlib.resources import files

    from alembic import command
    from alembic.config import Config

    url = get_settings().database_url
    # The rewrite needs a sync driver; strip the async dialect suffix.
    sync_url = url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2")
    if "+psycopg2" not in sync_url or _has_psycopg2():
        _rewrite_renamed_revisions(sync_url)

    package_root = files("honeypot_mcp")
    cfg = Config()
    cfg.set_main_option("script_location", str(package_root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


def _has_psycopg2() -> bool:
    try:
        import psycopg2  # noqa: F401

        return True
    except ImportError:
        return False


async def close_db() -> None:
    """Dispose the engine, waiting for in-flight sessions to finish first.

    Plenty of writes here are fire-and-forget: every engine's `_record` call,
    `_enrich_alert_async`, `record_action`. Disposing while one of those is
    mid-statement kills its connection underneath it, and the write is lost —
    an audit entry or an enrichment merge, gone, reported only as a stray
    "Cannot operate on a closed database" traceback from a task nobody is
    awaiting. It also made CI intermittently red with a `KeyError: 'connection'`
    raised out of `dispose()` itself.

    Waiting on the *session count* rather than on pending tasks is deliberate.
    An earlier attempt drained every outstanding asyncio task, which under
    in-memory SQLite's StaticPool made abandoned writes resume and overlap on
    the single shared connection ("cannot commit transaction - SQL statements
    in progress"). This waits only for sessions already open, and never lets a
    new one start something.
    """
    global _engine, _session_factory
    if _engine is None:
        _session_factory = None
        return

    # Yield first. A fire-and-forget write is *scheduled*, not running, so at
    # this instant its session does not exist yet and the counter below would
    # read zero and dispose straight through it. A couple of loop turns let
    # every already-created task reach its `get_session()` and register.
    for _ in range(3):
        await asyncio.sleep(0)

    deadline = asyncio.get_event_loop().time() + _CLOSE_GRACE_SECONDS
    while _active_sessions > 0 and asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.01)
    if _active_sessions > 0:
        log.warning(
            "Closing the database with %d session(s) still open after %.1fs — "
            "their writes may be lost.",
            _active_sessions,
            _CLOSE_GRACE_SECONDS,
        )

    await _engine.dispose()
    _engine = None
    _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    global _active_sessions
    factory = _get_session_factory()
    _active_sessions += 1
    try:
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    finally:
        _active_sessions -= 1
