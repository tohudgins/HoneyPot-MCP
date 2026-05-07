from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.models import Base

log = logging.getLogger(__name__)

_engine = None
_session_factory = None


def _get_engine():
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            future=True,
        )
    return _engine


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


def _run_alembic_upgrade() -> None:
    """Synchronous Alembic invocation. Imported here so test suites that use
    in-memory DBs never load Alembic at all."""
    from importlib.resources import files

    from alembic import command
    from alembic.config import Config

    package_root = files("honeypot_mcp")
    cfg = Config()
    cfg.set_main_option("script_location", str(package_root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    command.upgrade(cfg, "head")


async def close_db() -> None:
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
    _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    factory = _get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
