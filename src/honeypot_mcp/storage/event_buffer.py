"""Asyncio-batched event writer.

Engines submit events to a queue; a single background task drains them in
batches and writes one DB transaction per batch. Collapses per-event session
overhead (the dominant cost of high-volume ingestion) into amortised constant
cost and keeps the event loop responsive under DDoS-class load.

Each PendingEvent carries its own `timestamp`, so events written in the same
batch retain chronological order — critical for SOC analysis where the order
of "login_failed → command_input → file_download" is the whole story.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert, AlertSeverity, AttackerEvent

log = logging.getLogger(__name__)


@dataclass
class PendingEvent:
    honeypot_id: int | None
    source_ip: str
    event_type: str
    payload: dict[str, Any]
    severity: AlertSeverity
    source_port: int | None = None
    honeytoken_id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class EventBuffer:
    """Single-consumer asyncio queue + periodic flusher.

    `batch_size`: max events per DB transaction (50 keeps each transaction small
    enough that a flush failure loses bounded work).
    `flush_interval`: max wait (seconds) between flushes when the queue is slow.
    """

    def __init__(self, batch_size: int = 50, flush_interval: float = 1.0) -> None:
        self._queue: asyncio.Queue[PendingEvent] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._stop = asyncio.Event()
        self._on_flush: Callable[[list[PendingEvent]], Awaitable[None]] | None = None
        # Size of the batch currently mid-flush, if any. A batch is pulled off
        # `_queue` (via get()/get_nowait()) before `_flush()` runs, so
        # `_queue.qsize()` no longer reflects it — if the flusher task is
        # cancelled while `_flush()` is awaiting a slow/remote DB write (the
        # exact case shutdown_drain_seconds exists for), those events would
        # otherwise vanish from the shutdown discard count entirely, silently
        # undercounting by up to `batch_size`.
        self._in_flight = 0

    def set_on_flush(self, hook: Callable[[list[PendingEvent]], Awaitable[None]] | None) -> None:
        """Hook invoked AFTER a successful DB flush. Used by webhooks delivery
        to fan out the same batch to subscribed consumers."""
        self._on_flush = hook

    async def submit(self, event: PendingEvent) -> None:
        await self._queue.put(event)

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._run(), name="event-buffer-flusher")

    async def stop(self) -> None:
        """Stop the flusher, draining what is queued.

        The drain is bounded, so a backlog larger than the timeout allows is
        discarded — and that discard is *evidence being deleted*, so it is
        reported with a count rather than as "did not exit cleanly". A load
        test that queued 50,000 events lost 40,850 of them here and said
        nothing about how many; the operator's only clue was a vague warning.

        Measured commit rate is ~1,550 events/sec against SQLite, so the
        default comfortably drains any backlog a real honeypot builds. A slow
        or remote database is the case that needs `shutdown_drain_seconds`
        raised.
        """
        from honeypot_mcp.config import get_settings

        self._stop.set()
        if self._task is not None:
            timeout = get_settings().shutdown_drain_seconds
            try:
                await asyncio.wait_for(self._task, timeout=timeout)
            except TimeoutError:
                abandoned = self._queue.qsize() + self._in_flight
                log.error(
                    "Event buffer did not finish draining within %.1fs — %d captured "
                    "event(s) were DISCARDED. Raise `shutdown_drain_seconds` if the "
                    "database is slow or remote.",
                    timeout,
                    abandoned,
                )
            self._task = None

    def qsize(self) -> int:
        return self._queue.qsize()

    async def _run(self) -> None:
        while True:
            batch: list[PendingEvent] = []
            try:
                first = await asyncio.wait_for(self._queue.get(), timeout=self._flush_interval)
                batch.append(first)
            except TimeoutError:
                if self._stop.is_set() and self._queue.empty():
                    return
                continue

            while len(batch) < self._batch_size:
                try:
                    batch.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            self._in_flight = len(batch)
            try:
                await self._flush(batch)
            except asyncio.CancelledError:
                # stop()'s wait_for timed out while this batch was mid-flush.
                # Leave _in_flight set to len(batch) — that's what makes it
                # visible to stop()'s shutdown-discard count instead of the
                # batch silently vanishing (already off the queue, never
                # committed).
                raise
            except Exception as e:
                log.warning("Event buffer flush failed (%d events lost): %s", len(batch), e)
                self._in_flight = 0
                continue
            self._in_flight = 0

            if self._on_flush is not None:
                try:
                    await self._on_flush(batch)
                except Exception as e:
                    log.warning("Event buffer on_flush hook failed: %s", e)

    async def _flush(self, batch: list[PendingEvent]) -> None:
        # (Alert object, source_ip) for any CRITICAL event we'll auto-enrich
        # after the session commits. We can't gather inside the session because
        # alert.id isn't populated until session.flush(), and we don't want the
        # external API calls inside the DB transaction.
        to_enrich: list[tuple[Alert, str]] = []

        async with get_session() as session:
            for ev in batch:
                alert = Alert(
                    honeypot_id=ev.honeypot_id,
                    source_ip=ev.source_ip,
                    source_port=ev.source_port,
                    event_type=ev.event_type,
                    payload=ev.payload,
                    severity=ev.severity,
                    timestamp=ev.timestamp,
                )
                session.add(alert)
                session.add(
                    AttackerEvent(
                        ip=ev.source_ip,
                        event_type=ev.event_type,
                        extra=ev.payload,
                        honeytoken_id=ev.honeytoken_id,
                        timestamp=ev.timestamp,
                    )
                )
                if ev.severity == AlertSeverity.CRITICAL and _is_enrichable_ip(ev.source_ip):
                    to_enrich.append((alert, ev.source_ip))
                if ev.honeytoken_id is not None and ev.event_type.startswith(
                    "honeytoken_triggered_"
                ):
                    # Lazy import — queries pulls models which is fine, but keeps
                    # the import surface of this module minimal.
                    from honeypot_mcp.storage import queries

                    trigger_meta = {
                        "trigger_ip": ev.source_ip,
                        "trigger_event_type": ev.event_type,
                        "payload": ev.payload,
                    }
                    await queries.mark_honeytoken_triggered(session, ev.honeytoken_id, trigger_meta)
            await session.flush()  # populate alert.id for the enrichment hook
            enrich_targets = [(alert.id, ip) for alert, ip in to_enrich]

        # Outside the session: kick off background enrichment. Failures here
        # must never affect ingest — log and move on.
        for alert_id, ip in enrich_targets:
            asyncio.create_task(_enrich_alert_async(alert_id, ip))


_buffer: EventBuffer | None = None


def get_buffer() -> EventBuffer:
    global _buffer
    if _buffer is None:
        from honeypot_mcp.config import get_settings

        _buffer = EventBuffer(flush_interval=get_settings().event_flush_interval_seconds)
    return _buffer


def reset_for_tests() -> None:
    """Clear the singleton so the next get_buffer() returns a fresh instance.

    Each pytest-asyncio test gets its own event loop. asyncio.Queue is bound to
    the loop it was created in, so a singleton built in test A breaks in test B
    with `Queue is bound to a different event loop`. Tests that use the buffer
    must call this in their setUp.

    The running flusher is cancelled rather than merely dropped. Abandoning it
    leaves a task that may be mid-write when the fixture disposes the
    connection pool a moment later, which surfaces as
    `KeyError: 'connection'` from SQLAlchemy's pool — an intermittent teardown
    failure that lands on whichever engine test loses the race that run.
    """
    global _buffer
    if _buffer is not None and _buffer._task is not None and not _buffer._task.done():
        _buffer._task.cancel()
        _buffer._task = None
    _buffer = None


async def submit_event(event: PendingEvent) -> None:
    """Module-level convenience for engines.

    Suppression rules are evaluated here — events that match an active drop or
    rate-limit rule are dropped before they enter the buffer. Credential
    honeytoken matching runs next: when planted creds appear in a login
    attempt payload, severity is escalated to CRITICAL and the event is tagged
    with `honeytoken_id` so the flusher can mark the token as triggered.

    Imports are lazy to avoid a cycle (event_buffer ⇄ suppression ⇄
    credential_match)."""
    from honeypot_mcp import credential_match, self_probe, suppression, token_matchers

    # Ahead of suppression: the watchdog's own health probes reach the engines
    # as ordinary connections and would otherwise be recorded as attacks. This
    # drops only the exact socket a probe used, never a class of traffic.
    if self_probe.claim(event.source_ip, event.source_port):
        return

    suppress, rule_id = await suppression.should_suppress(event)
    if suppress:
        if rule_id is not None:
            await _bump_suppression_count(rule_id)
        return

    # Credentials matcher first — most events that match a planted credential
    # token also look like normal failed logins, so we re-tag them as the
    # first stop.
    token_id = await credential_match.match(event)
    if token_id is not None:
        event.honeytoken_id = token_id
        event.severity = AlertSeverity.CRITICAL
        event.event_type = f"honeytoken_triggered_credential_via_{event.event_type}"
    else:
        # SSH key / JWT / DB row matchers — payload-pattern based.
        token_id, match_type = await token_matchers.match(event)
        if token_id is not None:
            event.honeytoken_id = token_id
            event.severity = AlertSeverity.CRITICAL
            event.event_type = f"honeytoken_triggered_{match_type}_via_{event.event_type}"

    await get_buffer().submit(event)


async def _bump_suppression_count(rule_id: int) -> None:
    """Best-effort increment of `suppressed_count` for visibility. Failures are
    swallowed — a missed counter is not worth back-pressuring honeypot ingest."""
    try:
        from sqlalchemy import update

        from honeypot_mcp.storage.models import SuppressionRule

        async with get_session() as session:
            await session.execute(
                update(SuppressionRule)
                .where(SuppressionRule.id == rule_id)
                .values(suppressed_count=SuppressionRule.suppressed_count + 1)
            )
    except Exception as e:
        log.debug("Could not bump suppression count for rule %d: %s", rule_id, e)


# IPs we never enrich — internal/loopback/placeholder addresses don't have
# meaningful VirusTotal or AbuseIPDB records and burning rate-limit on them
# is wasteful.
_NON_ENRICHABLE = frozenset({"0.0.0.0", "127.0.0.1", "::1", "localhost", ""})


def _is_enrichable_ip(ip: str) -> bool:
    if ip in _NON_ENRICHABLE:
        return False
    # Private RFC1918 / link-local space — same logic as suppression module
    # uses ipaddress.ip_network. Keeping the dependency local.
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except (ValueError, TypeError):
        return False


async def _enrich_alert_async(alert_id: int, ip: str) -> None:
    """Background task: enrich one alert with VT + AbuseIPDB + GeoIP and merge
    the result into the stored Alert.payload. Errors are swallowed — auto-
    enrichment is a UX improvement, not a guarantee, and a failing external
    API must not break ingest.

    Cached via intel/_cache.py — repeat CRITICALs from the same IP within the
    TTL window cost zero external calls."""
    try:
        from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
        from honeypot_mcp.intel.geoip import lookup_geoip
        from honeypot_mcp.intel.virustotal import lookup_virustotal

        results: list[Any] = await asyncio.gather(
            lookup_geoip(ip),
            lookup_virustotal(ip),
            lookup_abuseipdb(ip),
            return_exceptions=True,
        )
        geo, vt, abuse = results[0], results[1], results[2]
        enrichment = {
            "geoip": geo if not isinstance(geo, Exception) else {"error": str(geo)},
            "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
            "abuseipdb": abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
        }

        async with get_session() as session:
            alert = await session.get(Alert, alert_id)
            if alert is None:
                return
            # Re-assign the dict so SQLAlchemy's change-detection picks it up.
            # JSON columns don't track in-place mutation by default.
            new_payload = dict(alert.payload or {})
            new_payload["enrichment"] = enrichment
            alert.payload = new_payload
    except Exception as e:
        log.warning("Auto-enrichment failed for alert %d (ip=%s): %s", alert_id, ip, e)
