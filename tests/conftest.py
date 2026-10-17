"""Shared test configuration.

Kept deliberately small: the only thing here is the timing knob that makes
buffer-dependent assertions deterministic.
"""

import os

import pytest

# Every test that drives an engine ends up asserting on rows the event buffer
# wrote. The buffer flushes a partial batch once per `flush_interval`, which
# defaults to 1 second — and the suite is full of `await asyncio.sleep(1.0)`
# followed immediately by a query. That is a coin flip: on an unloaded laptop
# the flush wins, on a loaded CI runner it doesn't, and the failure lands on
# whichever engine test happened to lose that run.
#
# Shortening the interval for tests turns those exact-boundary waits into a
# 20x margin without rewriting 40-odd assertions.
os.environ.setdefault("EVENT_FLUSH_INTERVAL_SECONDS", "0.05")


@pytest.fixture(autouse=True)
def _fast_flush():
    """Guard the setting against a cached Settings singleton built earlier."""
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    if settings.event_flush_interval_seconds > 0.2:
        settings.event_flush_interval_seconds = 0.05
    yield


def _reset_postgres_schema(dsn: str) -> None:
    import asyncio

    import asyncpg

    async def _reset() -> None:
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        finally:
            await conn.close()

    asyncio.run(_reset())


@pytest.fixture(autouse=True)
def _fresh_postgres_schema():
    """Give each test an empty PostgreSQL schema when the suite is pointed at
    one (`TEST_DATABASE_URL=postgresql+asyncpg://...`).

    Test modules default to an in-memory SQLite database, which is born empty
    per test. A shared PostgreSQL database is not, so without this every test
    would see its predecessors' rows. Opt-in, and keyed to a variable the
    modules read themselves, so a stray `DATABASE_URL` in a developer's shell
    can never point the suite at a real database.
    """
    url = os.environ.get("TEST_DATABASE_URL", "")
    if url.startswith("postgresql"):
        import concurrent.futures

        dsn = url.replace("postgresql+asyncpg://", "postgresql://", 1)
        # A separate thread: asyncio.run() would otherwise close and unset the
        # event loop that pytest-asyncio expects to manage.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(_reset_postgres_schema, dsn).result(timeout=60)
    yield


@pytest.fixture(autouse=True)
def _isolated_data_dirs(tmp_path, monkeypatch):
    """Point certificate and generated-artifact directories at the test's tmp dir.

    They are settings now (`tls_dir`, `reports_dir`), anchored to the project root
    rather than the working directory — so a test that used to isolate them with
    `chdir(tmp_path)` would otherwise write real certificates and private keys into
    the repository."""
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "tls_dir", tmp_path / "tls")
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "reports")
    monkeypatch.setattr(settings, "backup_dir", tmp_path / "backups")
    monkeypatch.setattr(settings, "grafana_dir", tmp_path / "grafana")
    monkeypatch.setattr(settings, "samples_dir", tmp_path / "samples")
    monkeypatch.setattr(settings, "yara_rules_dir", tmp_path / "yara-rules")
    monkeypatch.setattr(settings, "detection_rules_dir", tmp_path / "detection-rules")
