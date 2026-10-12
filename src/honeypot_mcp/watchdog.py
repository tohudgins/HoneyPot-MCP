"""Honeypot watchdog.

Periodically health-checks every running honeypot. When one stops responding,
flips its status to ERROR and emits a CRITICAL `honeypot_health_failed` alert
through the normal event pipeline (so it lands in the DB, fires webhooks, and
shows up in the alert stream alongside attack events).

Without this, a crashed Cowrie container or a dead in-process server would
just go quiet — the worst failure mode for a honeypot, since you'd have no
way to tell normal-low-traffic from broken.

The watchdog also hosts the retention sweep (opt-in via `retention_days`):
folding it in here reuses the proven periodic loop rather than standing up a
second lifespan-managed task, and DB housekeeping is a natural fit alongside
liveness housekeeping.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from honeypot_mcp import retention
from honeypot_mcp.config import get_settings
from honeypot_mcp.engines import get_engine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
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
        # Monotonic timestamp of the last retention sweep. 0.0 means "never" so
        # the first cycle after startup runs it immediately when enabled.
        self._last_prune_at: float = 0.0
        # Volumes already reported low, so a full disk raises one alert, not one per cycle.
        self._disk_low: set[str] = set()

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name="honeypot-watchdog")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except TimeoutError:
                log.warning("Watchdog did not exit cleanly.")
            self._task = None

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                await self._check_all()
            except Exception as e:
                log.warning("Watchdog cycle failed: %s", e)
            try:
                await self._maybe_prune()
            except Exception as e:
                log.warning("Retention sweep failed: %s", e)
            try:
                await self._check_disk()
            except Exception as e:
                log.warning("Disk check failed: %s", e)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
            except TimeoutError:
                continue

    async def _maybe_prune(self) -> None:
        """Delete alerts + attacker_events older than `retention_days`, at most
        once per `retention_sweep_interval_hours`. No-op unless retention is
        enabled (retention_days > 0)."""
        settings = get_settings()
        days = settings.retention_days
        if days < 1:
            return

        interval = max(settings.retention_sweep_interval_hours, 0.0) * 3600
        now = time.monotonic()
        if self._last_prune_at != 0.0 and now - self._last_prune_at < interval:
            return
        self._last_prune_at = now

        cutoff = datetime.now(UTC) - timedelta(days=days)

        # Archive before deleting, unless the operator opted out. This sweep
        # runs unattended, so it is the path most likely to quietly destroy a
        # months-old campaign nobody had finished investigating — and unlike
        # the manual tool, nobody is watching when it does. A failed archive
        # cancels the prune rather than proceeding without one: no row is
        # deleted unless every row it covers is on disk first.
        max_id: int | None = None
        if settings.retention_archive:
            try:
                max_id, _info = await retention.archive_alerts(
                    cutoff, prefix=f"retention-archive-before-{cutoff.date().isoformat()}"
                )
            except Exception as e:
                log.error(
                    "Retention archive failed (%s) — skipping this sweep rather than "
                    "deleting unarchived alerts. Set RETENTION_ARCHIVE=false to prune "
                    "without archiving.",
                    e,
                )
                return
            if max_id is None:
                max_id = 0  # nothing old enough to archive → no alert is deletable

        # Delete in bounded chunks (see retention.delete_before): a single unbatched DELETE of a
        # year of rows outlasts busy_timeout and stalls ingest.
        alerts_deleted, events_deleted = await retention.delete_before(cutoff, max_id)
        if alerts_deleted or events_deleted:
            log.info(
                "Retention sweep removed %d alerts + %d attacker_events older than %d days.",
                alerts_deleted,
                events_deleted,
                days,
            )

    async def _check_all(self) -> None:
        # ERROR honeypots are swept too, not just RUNNING ones. Watching only
        # RUNNING made the status a one-way door: the first failed probe set
        # ERROR, and ERROR rows were then excluded from every later sweep, so a
        # honeypot that came back stayed marked dead forever and was never
        # health-checked again. Transient failures — a container restart, a
        # daemon hiccup — became permanent.
        async with get_session() as session:
            honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)
            honeypots += await queries.list_honeypots(session, status=HoneypotStatus.ERROR)

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
                if hp.status is HoneypotStatus.ERROR:
                    await self._mark_recovered(hp.id, hp.name)
                continue

            if hp.id in self._reported_dead:
                continue
            self._reported_dead.add(hp.id)
            await self._mark_dead(hp.id, hp.name, health)

    async def _check_disk(self) -> None:
        """Raise one CRITICAL alert when a volume runs low, and clear it on recovery."""
        from honeypot_mcp.storage import disk

        low = {sample.label: sample for sample in disk.low_volumes()}
        for label, sample in low.items():
            if label in self._disk_low:
                continue
            log.error("Low disk space on %s (%s): %d MB free", label, sample.path, sample.free_mb)
            delivered = await _emit_independent_alert(
                PendingEvent(
                    honeypot_id=None,
                    source_ip="0.0.0.0",
                    event_type="disk_space_low",
                    payload={
                        "volume": label,
                        "path": sample.path,
                        "free_mb": sample.free_mb,
                        "threshold_mb": get_settings().min_free_disk_mb,
                    },
                    severity=AlertSeverity.CRITICAL,
                )
            )
            # Only once the notification was queued: a failed one is retried next cycle.
            if delivered:
                self._disk_low.add(label)
        # A volume re-arms only once it is clearly clear (10% above the threshold). Without
        # the margin, free space hovering at the threshold re-alerted every cycle, and
        # CRITICAL is exempt from notification throttling.
        threshold = get_settings().min_free_disk_mb
        samples = {s.label: s for s in disk.sample()}
        for label in list(self._disk_low):
            current = samples.get(label)
            if label not in low and (current is None or current.free_mb >= threshold * 1.1):
                self._disk_low.discard(label)

    async def _mark_recovered(self, hp_id: int, hp_name: str) -> None:
        """Flip a honeypot that is answering again back to RUNNING.

        No alert is emitted: recovery is good news, and a honeypot that flaps
        would otherwise generate an alert on every transition.
        """
        log.info("Honeypot %r is responding again — status restored to RUNNING.", hp_name)
        async with get_session() as session:
            await session.execute(
                update(Honeypot).where(Honeypot.id == hp_id).values(status=HoneypotStatus.RUNNING)
            )

    async def _mark_dead(self, hp_id: int, hp_name: str, health: dict) -> None:
        log.warning("Honeypot %r flagged unhealthy: %s", hp_name, health.get("detail"))
        async with get_session() as session:
            await session.execute(
                update(Honeypot).where(Honeypot.id == hp_id).values(status=HoneypotStatus.ERROR)
            )
        await submit_event(
            PendingEvent(
                honeypot_id=hp_id,
                source_ip="0.0.0.0",
                event_type="honeypot_health_failed",
                payload={"name": hp_name, **health},
                severity=AlertSeverity.CRITICAL,
            )
        )


async def _emit_independent_alert(event: PendingEvent) -> bool:
    """Raise an alert without waiting for the database to accept its row.

    The normal path (`submit_event`) notifies subscribers only AFTER the row is written,
    which is exactly what a full disk prevents: the alert about the disk would be stuck
    behind the failure it reports. So subscribers are notified first, and the row is
    written best-effort afterwards (a refused write is logged, not retried into a flood).
    The subscriber list is cached for 30 seconds; when that cache is stale and the database
    is refusing reads, delivery still fails: the log line is the signal of last resort.
    Returns whether the notification was queued."""
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.webhooks import get_delivery

    queued = True
    try:
        await get_delivery().enqueue_batch([event])
    except Exception as e:
        queued = False
        log.error("Could not queue the %s notification: %s", event.event_type, e)
    try:
        async with get_session() as session:
            session.add(
                Alert(
                    honeypot_id=event.honeypot_id,
                    source_ip=event.source_ip,
                    event_type=event.event_type,
                    payload=event.payload,
                    severity=event.severity,
                    timestamp=event.timestamp,
                )
            )
    except Exception as e:
        log.error("Could not record the %s alert in the database: %s", event.event_type, e)
    return queued


_watchdog: HoneypotWatchdog | None = None


def get_watchdog() -> HoneypotWatchdog:
    global _watchdog
    if _watchdog is None:
        _watchdog = HoneypotWatchdog()
    return _watchdog
