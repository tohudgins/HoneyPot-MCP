"""The server watches itself: free disk, per-sensor state, and what role it plays.

A full disk is the quietest way for a honeypot to stop working. The listeners keep
answering attackers (they never touch the disk) while every event fails to persist, and
nothing used to notice.
"""

import os
from types import SimpleNamespace

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


def _full_disk(monkeypatch, free_mb: int = 10) -> None:
    from honeypot_mcp.storage import disk

    gib = 1024**3
    monkeypatch.setattr(
        disk.shutil,
        "disk_usage",
        lambda _p: SimpleNamespace(total=100 * gib, used=0, free=free_mb * 1024 * 1024),
    )


async def test_readiness_goes_unready_when_the_database_disk_is_nearly_full(monkeypatch, tmp_path):
    import json

    from honeypot_mcp.metrics import _handle_readyz
    from honeypot_mcp.storage import disk

    # The database volume, whatever database the suite is running against.
    monkeypatch.setattr(disk, "watched_paths", lambda: [("database", tmp_path)])
    ok = await _handle_readyz(None)
    assert ok.status == 200 and json.loads(ok.text)["checks"]["disk"] == "ok"

    _full_disk(monkeypatch)
    bad = await _handle_readyz(None)
    body = json.loads(bad.text)
    assert bad.status == 503 and body["status"] == "not ready"
    assert "low on database" in body["checks"]["disk"] and "10 MB free" in body["checks"]["disk"]


async def test_the_disk_check_can_be_switched_off(monkeypatch, tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import disk

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    monkeypatch.setattr(get_settings(), "min_free_disk_mb", 0)
    _full_disk(monkeypatch, free_mb=1)
    assert disk.low_volumes() == []


async def test_free_disk_and_per_sensor_state_are_exported(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.metrics import _gather_metrics
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    async with get_session() as session:
        session.add(
            Honeypot(name="up-one", type=HoneypotType.HTTP, port=1, status=HoneypotStatus.RUNNING)
        )
        session.add(
            Honeypot(name="down-one", type=HoneypotType.SSH, port=2, status=HoneypotStatus.ERROR)
        )
    body = await _gather_metrics()
    assert 'honeypot_sensor_up{name="up-one",type="http"} 1' in body
    assert 'honeypot_sensor_up{name="down-one",type="ssh"} 0' in body
    assert 'honeypot_disk_free_bytes{volume="reports"}' in body


async def test_a_low_disk_raises_one_critical_alert_and_rearms_after_recovery(
    monkeypatch, tmp_path
):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    delivered = []

    async def capture(events):
        delivered.extend(events)

    monkeypatch.setattr(
        "honeypot_mcp.webhooks.get_delivery", lambda: SimpleNamespace(enqueue_batch=capture)
    )
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    watchdog = HoneypotWatchdog()

    _full_disk(monkeypatch)
    await watchdog._check_disk()
    await watchdog._check_disk()  # still low: must not alert again
    assert [e.event_type for e in delivered] == ["disk_space_low"]
    assert delivered[0].severity.value == "critical"
    assert delivered[0].payload["volume"] == "reports" and delivered[0].payload["free_mb"] == 10

    _full_disk(monkeypatch, free_mb=5000)  # recovered
    await watchdog._check_disk()
    _full_disk(monkeypatch)  # and low again
    await watchdog._check_disk()
    assert [e.event_type for e in delivered] == ["disk_space_low", "disk_space_low"]


async def test_the_disk_alert_reaches_subscribers_even_when_the_database_refuses_writes(
    monkeypatch, tmp_path
):
    """The ordinary alert path notifies subscribers only after the row is written, which is
    exactly what a full disk prevents: the alert about the disk was stuck behind the
    failure it reports."""
    from honeypot_mcp import watchdog as watchdog_module
    from honeypot_mcp.config import get_settings

    delivered = []

    async def capture(events):
        delivered.extend(events)

    class BrokenSession:
        async def __aenter__(self):
            raise RuntimeError("database or disk is full")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(
        "honeypot_mcp.webhooks.get_delivery", lambda: SimpleNamespace(enqueue_batch=capture)
    )
    monkeypatch.setattr(watchdog_module, "get_session", BrokenSession)
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    _full_disk(monkeypatch)
    await watchdog_module.HoneypotWatchdog()._check_disk()
    assert [e.event_type for e in delivered] == ["disk_space_low"]


async def test_the_alert_is_also_recorded_when_the_database_works(monkeypatch, tmp_path):
    from sqlalchemy import select

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.watchdog import HoneypotWatchdog

    async def ignore(_events):
        return None

    monkeypatch.setattr(
        "honeypot_mcp.webhooks.get_delivery", lambda: SimpleNamespace(enqueue_batch=ignore)
    )
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    _full_disk(monkeypatch)
    await HoneypotWatchdog()._check_disk()
    async with get_session() as session:
        rows = (
            (await session.execute(select(Alert).where(Alert.event_type == "disk_space_low")))
            .scalars()
            .all()
        )
    assert len(rows) == 1 and rows[0].payload["volume"] == "reports"


async def test_database_size_is_exported(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.metrics import _database_size_bytes

    db = tmp_path / "x.db"
    db.write_bytes(b"0" * 4096)
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{db}")
    assert await _database_size_bytes() == 4096
    monkeypatch.setattr(get_settings(), "database_url", "sqlite+aiosqlite:///:memory:")
    assert await _database_size_bytes() is None


async def test_a_full_reports_volume_alerts_but_does_not_fail_readiness(monkeypatch, tmp_path):
    """Only the database volume stops collection; a full exports directory must not make
    a collecting server look unhealthy (docker-compose restarts on /readyz)."""
    import json

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.metrics import _handle_readyz
    from honeypot_mcp.storage import disk

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)  # in-memory DB: reports only
    _full_disk(monkeypatch)
    assert [v.label for v in disk.low_volumes()] == ["reports"]
    response = await _handle_readyz(None)
    assert response.status == 200 and json.loads(response.text)["checks"]["disk"] == "ok"


async def test_stopped_sensors_do_not_export_a_down_series(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.metrics import _gather_metrics
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    async with get_session() as session:
        session.add(
            Honeypot(name="parked", type=HoneypotType.FTP, port=3, status=HoneypotStatus.STOPPED)
        )
    assert 'name="parked"' not in await _gather_metrics()


async def test_a_volume_hovering_at_the_threshold_does_not_alert_every_cycle(monkeypatch, tmp_path):
    """CRITICAL notifications are exempt from throttling, so free space flapping across the
    threshold raised one every cycle."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    delivered = []

    async def capture(events):
        delivered.extend(events)

    monkeypatch.setattr(
        "honeypot_mcp.webhooks.get_delivery", lambda: SimpleNamespace(enqueue_batch=capture)
    )
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    watchdog = HoneypotWatchdog()
    for free in (499, 501, 499, 502, 498, 505, 499):  # threshold is 500
        _full_disk(monkeypatch, free_mb=free)
        await watchdog._check_disk()
    assert len(delivered) == 1

    _full_disk(monkeypatch, free_mb=800)  # clearly recovered
    await watchdog._check_disk()
    _full_disk(monkeypatch, free_mb=100)
    await watchdog._check_disk()
    assert len(delivered) == 2


async def test_a_failed_notification_is_retried_next_cycle(monkeypatch, tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.watchdog import HoneypotWatchdog

    calls = []

    async def flaky(events):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("queue unavailable")

    monkeypatch.setattr(
        "honeypot_mcp.webhooks.get_delivery", lambda: SimpleNamespace(enqueue_batch=flaky)
    )
    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path)
    watchdog = HoneypotWatchdog()
    _full_disk(monkeypatch)
    await watchdog._check_disk()
    await watchdog._check_disk()
    await watchdog._check_disk()
    assert len(calls) == 2  # once failed, once delivered, then quiet


async def test_database_size_includes_the_write_ahead_log(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.metrics import _database_size_bytes

    db = tmp_path / "x.db"
    db.write_bytes(b"0" * 4096)
    (tmp_path / "x.db-wal").write_bytes(b"0" * 30_000)
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{db}")
    assert await _database_size_bytes() == 34_096
