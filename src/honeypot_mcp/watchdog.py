"""Honeypot watchdog.

Periodically health-checks every running honeypot. When one stops responding,
flips its status to ERROR and emits a CRITICAL `honeypot_health_failed` alert
through the normal event pipeline (so it lands in the DB, fires webhooks, and
shows up in the alert stream alongside attack events).

Without this, a crashed Cowrie container or a dead in-process server would
just go quiet — the worst failure mode for a honeypot, since you'd have no
way to tell normal-low-traffic from broken.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import update

from honeypot_mcp.engines import get_engine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import AlertSeverity, Honeypot, HoneypotStatus

log = logging.getLogger(__name__)

CHECK_INTERVAL_SECONDS = 30


class HoneypotWatchdog:
    def __init__(self, interval: float = CHECK_INTERVAL_SECONDS) -> None:
        self._interval = interval
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        # Honeypot IDs we've already alerted about — so a single failure doesn't
        # flood the alert stream every interval. Cleared when health recovers.
        self._reported_dead: set[int] = set()

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name="honeypot-watchdog")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("Watchdog did not exit cleanly.")
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._check_all()
            except Exception as e:
                log.warning("Watchdog cycle failed: %s", e)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                continue

    async def _check_all(self) -> None:
        async with get_session() as session:
            honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)

        for hp in honeypots:
            if hp.container_id is None:
                continue
            try:
                engine = get_engine(hp.type)
                health = await engine.health_check(hp.container_id, hp.port)
            except Exception as e:
                log.debug("Health check raised for %s: %s", hp.name, e)
                continue

            if health.get("alive"):
                self._reported_dead.discard(hp.id)
                continue

            if hp.id in self._reported_dead:
                continue
            self._reported_dead.add(hp.id)
            await self._mark_dead(hp.id, hp.name, health)

    async def _mark_dead(self, hp_id: int, hp_name: str, health: dict) -> None:
        log.warning("Honeypot %r flagged unhealthy: %s", hp_name, health.get("detail"))
        async with get_session() as session:
            await session.execute(
                update(Honeypot).where(Honeypot.id == hp_id).values(status=HoneypotStatus.ERROR)
            )
        await submit_event(PendingEvent(
            honeypot_id=hp_id,
            source_ip="0.0.0.0",
            event_type="honeypot_health_failed",
            payload={"name": hp_name, **health},
            severity=AlertSeverity.CRITICAL,
        ))


_watchdog: HoneypotWatchdog | None = None


def get_watchdog() -> HoneypotWatchdog:
    global _watchdog
    if _watchdog is None:
        _watchdog = HoneypotWatchdog()
    return _watchdog
