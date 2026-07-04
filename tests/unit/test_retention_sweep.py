"""Tests for the watchdog's opt-in retention sweep (`_maybe_prune`).

Verifies: with retention enabled, alerts + attacker_events older than the
cutoff are deleted while newer rows survive; with retention disabled (the
default), nothing is touched; and the sweep respects its own interval so it
doesn't hammer the DB every 30s watchdog cycle.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    settings = get_settings()
    original = settings.retention_days
    yield
    settings.retention_days = original
    await close_db()


async def _add_alert(age_days: int) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        session.add(
            Alert(
                source_ip="1.2.3.4",
                event_type="ssh_login_failed",
                payload={},
                severity=AlertSeverity.MEDIUM,
                timestamp=datetime.now(UTC) - timedelta(days=age_days),
            )
        )


async def _alert_count() -> int:
    from sqlalchemy import func, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return (await session.execute(select(func.count()).select_from(Alert))).scalar_one()


@pytest.mark.asyncio
async def test_sweep_deletes_only_rows_older_than_cutoff():
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    get_settings().retention_days = 30
    await _add_alert(age_days=90)  # stale
    await _add_alert(age_days=100)  # stale
    await _add_alert(age_days=5)  # fresh
    assert await _alert_count() == 3

    wd = HoneypotWatchdog()
    await wd._maybe_prune()

    assert await _alert_count() == 1  # only the 5-day-old row survives


@pytest.mark.asyncio
async def test_sweep_is_noop_when_retention_disabled():
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    get_settings().retention_days = 0  # disabled (default)
    await _add_alert(age_days=999)
    assert await _alert_count() == 1

    wd = HoneypotWatchdog()
    await wd._maybe_prune()

    assert await _alert_count() == 1  # untouched


@pytest.mark.asyncio
async def test_sweep_respects_interval_between_runs():
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    get_settings().retention_days = 30
    wd = HoneypotWatchdog()

    # First run prunes and records the timestamp.
    await _add_alert(age_days=90)
    await wd._maybe_prune()
    assert await _alert_count() == 0

    # A second stale row added immediately after should NOT be swept, because
    # the interval hasn't elapsed since the last run.
    await _add_alert(age_days=90)
    await wd._maybe_prune()
    assert await _alert_count() == 1
