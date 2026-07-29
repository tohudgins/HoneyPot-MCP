"""Alembic environment for HoneyPot MCP.

Async-compatible: Alembic itself is sync, so we run migrations through a
sync-bridge over the async engine. Pulls the connection URL from
honeypot_mcp.config so it stays in sync with the rest of the app.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Always honour the runtime DATABASE_URL — alembic.ini's value is just a fallback.
config.set_main_option("sqlalchemy.url", get_settings().database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
        # SQLAlchemy 2.0's `connect()` does not autocommit, so without this the
        # version stamp is discarded. SQLite's driver commits DDL implicitly and
        # hid the bug; PostgreSQL has transactional DDL and rolled `alembic_version`
        # back on every run, so a Postgres deployment re-executed the entire
        # migration chain at every startup — surviving only because these
        # migrations happen to be idempotent, and one non-idempotent revision
        # away from corrupting a production database.
        await connection.commit()
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
