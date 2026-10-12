"""A honeypot that comes back must stop being marked dead.

The sweep used to select only RUNNING honeypots, which made ERROR a one-way
door: the first failed probe set ERROR, and ERROR rows were then excluded from
every later sweep. Nothing ever re-checked them, so a container restart or a
momentary Docker hiccup permanently retired a working honeypot — it kept
capturing attacks while the dashboard showed it dead and the watchdog ignored
it. Recovery has to be observed, because nothing else in the system will
notice.
"""

from __future__ import annotations

import os

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()


async def _add(name: str, status, container_id: str = "cid"):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    async with get_session() as session:
        hp = Honeypot(
            name=name,
            type=HoneypotType.FTP,
            port=2121,
            status=status,
            container_id=container_id,
            config={},
        )
        session.add(hp)
        await session.flush()
        return hp.id


def _engine_reporting(alive: bool):
    class _Engine:
        async def health_check(self, container_id, port):
            return {"alive": alive, "detail": "stubbed"}

    return _Engine()


async def _status_of(hp_id: int):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot

    async with get_session() as session:
        row = (await session.execute(select(Honeypot).where(Honeypot.id == hp_id))).scalar_one()
        return row.status


async def test_error_honeypot_that_answers_again_returns_to_running(monkeypatch):
    import honeypot_mcp.watchdog as watchdog_mod
    from honeypot_mcp.storage.models import HoneypotStatus

    hp_id = await _add("recovering", HoneypotStatus.ERROR)
    monkeypatch.setattr(watchdog_mod, "get_engine", lambda _t: _engine_reporting(True))

    wd = watchdog_mod.HoneypotWatchdog()
    await wd._check_all()

    assert await _status_of(hp_id) is HoneypotStatus.RUNNING


async def test_error_honeypot_still_down_stays_in_error_without_realerting(monkeypatch):
    """Sweeping ERROR rows must not turn into an alert every 30 seconds."""
    import honeypot_mcp.watchdog as watchdog_mod
    from honeypot_mcp.storage.models import HoneypotStatus

    hp_id = await _add("still-down", HoneypotStatus.ERROR)
    monkeypatch.setattr(watchdog_mod, "get_engine", lambda _t: _engine_reporting(False))

    wd = watchdog_mod.HoneypotWatchdog()
    alerts: list[str] = []

    async def _capture(hp, name, health):
        alerts.append(name)

    monkeypatch.setattr(wd, "_mark_dead", _capture)
    await wd._check_all()
    await wd._check_all()
    await wd._check_all()

    assert await _status_of(hp_id) is HoneypotStatus.ERROR
    assert alerts == ["still-down"], f"re-alerted on an already-dead honeypot: {alerts}"


async def test_one_failed_probe_is_a_blip_and_two_in_a_row_is_an_outage(monkeypatch):
    """A Docker restart takes seconds. Paging CRITICAL for that, every few minutes, trained the
    operator to ignore the channel; an outage that survives into the next sweep still pages."""
    import honeypot_mcp.watchdog as watchdog_mod
    from honeypot_mcp.storage.models import HoneypotStatus

    hp_id = await _add("dying", HoneypotStatus.RUNNING)
    monkeypatch.setattr(watchdog_mod, "get_engine", lambda _t: _engine_reporting(False))
    wd = watchdog_mod.HoneypotWatchdog()
    alerts: list[str] = []

    async def _capture(hp, name, health):
        alerts.append(name)

    monkeypatch.setattr(wd, "_mark_dead", _capture)

    await wd._check_all()
    assert alerts == [], "a single failed probe must not page"
    await wd._check_all()
    assert alerts == ["dying"]
    assert await _status_of(hp_id) is HoneypotStatus.RUNNING  # _mark_dead is stubbed here


async def test_a_failed_probe_that_recovers_never_marks_the_sensor_dead(monkeypatch):
    import honeypot_mcp.watchdog as watchdog_mod
    from honeypot_mcp.storage.models import HoneypotStatus

    hp_id = await _add("blippy", HoneypotStatus.RUNNING)
    answers = iter([False, True, False, True])
    monkeypatch.setattr(watchdog_mod, "get_engine", lambda _t: _engine_reporting(next(answers)))
    wd = watchdog_mod.HoneypotWatchdog()

    for _ in range(4):
        await wd._check_all()

    assert await _status_of(hp_id) is HoneypotStatus.RUNNING
    assert wd._reported_dead == set()


async def test_a_sensor_that_keeps_blipping_raises_one_high_instability_alert(monkeypatch):
    """The restart loop that prompted this was only noticed because it paged. Debouncing must not
    make it silent: three recovered blips in an hour is one HIGH alert, not three CRITICALs."""
    import honeypot_mcp.watchdog as watchdog_mod
    from honeypot_mcp.storage.models import AlertSeverity, HoneypotStatus

    await _add("loopy", HoneypotStatus.RUNNING)
    answers = iter([False, True] * 5)
    monkeypatch.setattr(watchdog_mod, "get_engine", lambda _t: _engine_reporting(next(answers)))
    sent = []

    async def _submit(event):
        sent.append(event)

    monkeypatch.setattr(watchdog_mod, "submit_event", _submit)
    wd = watchdog_mod.HoneypotWatchdog()

    for _ in range(10):
        await wd._check_all()

    assert [(e.event_type, e.severity) for e in sent] == [
        ("honeypot_unstable", AlertSeverity.HIGH)
    ], "exactly one instability alert (cooldown), and no honeypot_health_failed"
    assert sent[0].payload["failed_probes_in_last_hour"] == 3
