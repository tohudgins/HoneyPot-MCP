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
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert, AlertSeverity, AttackerEvent

log = logging.getLogger(__name__)

# Fraction of the queue high-water mark at which each severity starts being
# shed. LOW goes first; HIGH/CRITICAL only once the backlog is twice the mark.
_SHED_AT: dict[AlertSeverity, float] = {
    AlertSeverity.LOW: 1.0,
    AlertSeverity.MEDIUM: 1.5,
    AlertSeverity.HIGH: 2.0,
    AlertSeverity.CRITICAL: 2.0,
}
_DROP_LOG_INTERVAL = 10.0
_dropped: dict[str, int] = {s.value: 0 for s in AlertSeverity}
_last_drop_log_at: float = float("-inf")
_dropped_since_log = 0

# How often the flusher writes in-memory suppression hit counts back.
_SUPPRESSION_FLUSH_SECONDS = 5.0


def dropped_event_count() -> int:
    """Events shed by the queue high-water policy since process start."""
    return sum(_dropped.values())


def dropped_event_counts_by_severity() -> dict[str, int]:
    """`dropped_event_count()` split by severity value (low/medium/high/critical)."""
    return dict(_dropped)


def _record_drop(event: PendingEvent, queued: int) -> None:
    global _last_drop_log_at, _dropped_since_log
    key = getattr(event.severity, "value", str(event.severity))
    _dropped[key] = _dropped.get(key, 0) + 1
    _dropped_since_log += 1
    now = time.monotonic()
    if now - _last_drop_log_at >= _DROP_LOG_INTERVAL:
        log.warning(
            "Event queue over its high-water mark (%d queued) — shed %d event(s) since "
            "the last report (%d total). Ingest is outrunning the database; raise "
            "`event_queue_max` or investigate the flood.",
            queued,
            _dropped_since_log,
            dropped_event_count(),
        )
        _last_drop_log_at = now
        _dropped_since_log = 0


# ── Payload clamping ─────────────────────────────────────────────────────────
# Payloads are attacker-authored. They are clamped before they are queued so a
# flood of large events cannot exhaust memory, and sanitised so one value the
# database rejects (NUL in PostgreSQL text, a lone surrogate, bytes, NaN) cannot
# fail a flush.

_RAW_BODY_KEYS = frozenset({"raw_body_b64"})
_MAX_DEPTH = 8
_MAX_ITEMS = 512
_MAX_KEY_CHARS = 256
_MAX_TRUNCATED_KEYS_LISTED = 32


class _Clamp:
    def __init__(self, max_chars: int) -> None:
        self.max_chars = max_chars
        self.truncated = False

    def text(self, s: str, limit: int) -> str:
        if len(s) > limit:
            s = s[:limit]
            self.truncated = True
        if "\x00" in s:
            s = s.replace("\x00", "")
        try:
            s.encode("utf-8")
        except UnicodeEncodeError:
            # Lone surrogates (e.g. from `surrogateescape` decoding).
            s = s.encode("utf-8", "replace").decode("utf-8")
        return s

    def value(self, v: Any, depth: int = 0, limit: int | None = None) -> Any:
        lim = self.max_chars if limit is None else limit
        if v is None or isinstance(v, bool | int):
            return v
        if isinstance(v, float):
            return v if math.isfinite(v) else str(v)
        if isinstance(v, str):
            return self.text(v, lim)
        if isinstance(v, bytes | bytearray | memoryview):
            raw = bytes(v)
            if len(raw) > lim:
                raw = raw[:lim]
                self.truncated = True
            return self.text(raw.decode("utf-8", "replace"), lim)
        if depth >= _MAX_DEPTH:
            self.truncated = True
            return "[truncated: nested too deep]"
        if isinstance(v, dict):
            out: dict[str, Any] = {}
            for i, (k, item) in enumerate(v.items()):
                if i >= _MAX_ITEMS:
                    self.truncated = True
                    break
                out[self.text(str(k), _MAX_KEY_CHARS)] = self.value(item, depth + 1)
            return out
        if isinstance(v, list | tuple | set | frozenset):
            items: list[Any] = []
            for i, item in enumerate(v):
                if i >= _MAX_ITEMS:
                    self.truncated = True
                    break
                items.append(self.value(item, depth + 1))
            return items
        iso = getattr(v, "isoformat", None)
        return self.text(iso() if callable(iso) else str(v), lim)


def _encoded_len(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str))


def clamp_payload(payload: Any) -> tuple[dict[str, Any], int]:
    """Return `(clamped_payload, approximate_size_bytes)`.

    Every string is clipped to `event_payload_max_string_chars` (the HTTP
    engine's `raw_body_b64` to `event_raw_body_max_chars`), containers are
    bounded in depth and width, NUL characters and lone surrogates are removed,
    and values JSON cannot store become strings. If the result still exceeds
    `event_payload_max_bytes` (excluding `raw_body_b64`), whole top-level keys
    are dropped from the end and named in `payload_truncated_keys`. Anything
    clipped sets `payload_truncated: true`.
    """
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    clamp = _Clamp(max(settings.event_payload_max_string_chars, 1))
    if not isinstance(payload, dict):
        payload = {"value": payload}

    out: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    for i, (k, v) in enumerate(payload.items()):
        if i >= _MAX_ITEMS:
            clamp.truncated = True
            break
        key = clamp.text(str(k), _MAX_KEY_CHARS)
        if key in _RAW_BODY_KEYS:
            raw[key] = clamp.value(v, 1, settings.event_raw_body_max_chars)
        else:
            out[key] = clamp.value(v, 1)

    size = _encoded_len(out)
    budget = settings.event_payload_max_bytes
    if budget > 0 and size > budget:
        kept: dict[str, Any] = {}
        dropped: list[str] = []
        used = 2  # "{}"
        for key, value in out.items():
            cost = _encoded_len({key: value})
            if used + cost <= budget:
                kept[key] = value
                used += cost
            else:
                dropped.append(key)
        kept["payload_truncated_keys"] = dropped[:_MAX_TRUNCATED_KEYS_LISTED]
        out = kept
        size = used
        clamp.truncated = True

    out.update(raw)
    if clamp.truncated:
        out["payload_truncated"] = True
    return out, size + sum(len(str(v)) for v in raw.values())


def _sanitise_identity(event: PendingEvent) -> None:
    """Clip the attacker-influenced scalar columns (source_ip / event_type)."""
    clamp = _Clamp(256)
    if not isinstance(event.source_ip, str):
        event.source_ip = str(event.source_ip)
    event.source_ip = clamp.text(event.source_ip, 64)
    event.event_type = clamp.text(str(event.event_type), 128)


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
    # Estimated queued size in bytes, set by `submit_event` when it clamps the
    # payload. Drives the byte-based high-water mark.
    size_hint: int = field(default=0, init=False, repr=False, compare=False)


class EventBuffer:
    """Single-consumer asyncio queue + periodic flusher.

    `batch_size`: max events per DB transaction (50 keeps each transaction small
    enough that a flush failure loses bounded work).
    `flush_interval`: max wait (seconds) between flushes when the queue is slow.
    """

    def __init__(self, batch_size: int = 50, flush_interval: float = 1.0) -> None:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
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
        # High-water marks (0 = unbounded) and the running byte estimate.
        self._max_events = max(int(settings.event_queue_max), 0)
        self._max_bytes = max(int(settings.event_queue_max_bytes), 0)
        self._queued_bytes = 0
        self._last_count_flush = time.monotonic()

    def set_on_flush(self, hook: Callable[[list[PendingEvent]], Awaitable[None]] | None) -> None:
        """Hook invoked AFTER a successful DB flush. Used by webhooks delivery
        to fan out the same batch to subscribed consumers."""
        self._on_flush = hook

    def _load(self) -> float:
        load = 0.0
        if self._max_events:
            load = self._queue.qsize() / self._max_events
        if self._max_bytes:
            load = max(load, self._queued_bytes / self._max_bytes)
        return load

    async def submit(self, event: PendingEvent) -> None:
        """Queue an event. Below the high-water mark nothing is ever dropped;
        above it the lowest severities are shed first (see `_SHED_AT`)."""
        load = self._load()
        if load >= 1.0 and load >= _SHED_AT.get(event.severity, 2.0):
            _record_drop(event, self._queue.qsize())
            return
        self._queued_bytes += event.size_hint
        await self._queue.put(event)

    def _dequeued(self, event: PendingEvent) -> PendingEvent:
        self._queued_bytes = max(self._queued_bytes - event.size_hint, 0)
        return event

    async def _maybe_flush_suppression_counts(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_count_flush < _SUPPRESSION_FLUSH_SECONDS:
            return
        self._last_count_flush = now
        try:
            from honeypot_mcp import suppression

            await suppression.flush_suppression_counts()
        except Exception as e:
            log.debug("Suppression count flush failed: %s", e)

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
            await self._maybe_flush_suppression_counts()
            batch: list[PendingEvent] = []
            try:
                first = await asyncio.wait_for(self._queue.get(), timeout=self._flush_interval)
                batch.append(self._dequeued(first))
            except TimeoutError:
                if self._stop.is_set() and self._queue.empty():
                    await self._maybe_flush_suppression_counts(force=True)
                    return
                continue

            while len(batch) < self._batch_size:
                try:
                    batch.append(self._dequeued(self._queue.get_nowait()))
                except asyncio.QueueEmpty:
                    break

            self._in_flight = len(batch)
            try:
                written = await self._flush(batch)
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
            if written is None:
                written = batch

            if self._on_flush is not None and written:
                try:
                    await self._on_flush(written)
                except Exception as e:
                    log.warning("Event buffer on_flush hook failed: %s", e)

    async def _flush(self, batch: list[PendingEvent]) -> list[PendingEvent]:
        """Write `batch`, returning the events that were actually stored.

        One transaction for the batch; if it fails, retry once (a transient
        lock), then write the events one at a time so a single poison row —
        a value the database rejects — costs only itself rather than its 49
        innocent neighbours.
        """
        try:
            targets = await self._write(batch)
            written = batch
        except Exception as first_error:
            log.warning(
                "Event buffer flush of %d event(s) failed (%s) — retrying.",
                len(batch),
                first_error,
            )
            try:
                targets = await self._write(batch)
                written = batch
            except Exception:
                written, targets = [], []
                for ev in batch:
                    try:
                        targets.extend(await self._write([ev]))
                        written.append(ev)
                    except Exception as e:
                        log.error(
                            "Dropping an event the database refused (event_type=%s, "
                            "honeypot_id=%s, source_ip=%s): %s",
                            ev.event_type[:128],
                            ev.honeypot_id,
                            ev.source_ip[:64],
                            e,
                        )

        # Outside the session: kick off background enrichment. Failures here
        # must never affect ingest — log and move on.
        for alert_id, ip in targets:
            _schedule_enrichment(alert_id, ip)
        return written

    async def _write(self, events: list[PendingEvent]) -> list[tuple[int, str]]:
        """One transaction for `events`; returns `(alert_id, ip)` pairs to enrich."""
        # (Alert object, source_ip) for any CRITICAL event we'll auto-enrich
        # after the session commits. We can't gather inside the session because
        # alert.id isn't populated until session.flush(), and we don't want the
        # external API calls inside the DB transaction.
        to_enrich: list[tuple[Alert, str]] = []

        async with get_session() as session:
            for ev in events:
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
            return [(alert.id, ip) for alert, ip in to_enrich]


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
    # Pending enrichment lists belong to tasks on the previous loop.
    _enrich_pending.clear()


async def submit_event(event: PendingEvent) -> None:
    """Module-level convenience for engines.

    The payload is clamped first (see `clamp_payload`) so everything after —
    matchers, queue, database — sees bounded, storable data.

    Suppression rules are evaluated here — events that match an active drop or
    rate-limit rule are dropped before they enter the buffer. Credential
    honeytoken matching runs next: when planted creds appear in a login
    attempt payload, severity is escalated to CRITICAL and the event is tagged
    with `honeytoken_id` so the flusher can mark the token as triggered. A
    honeytoken hit is never suppressed: a rule written to quiet a noisy
    scanner must not hide the one attempt that used a planted credential.

    Imports are lazy to avoid a cycle (event_buffer ⇄ suppression ⇄
    credential_match)."""
    from honeypot_mcp import self_probe, suppression

    event.payload, event.size_hint = clamp_payload(event.payload)
    _sanitise_identity(event)

    # Ahead of suppression: the watchdog's own health probes reach the engines
    # as ordinary connections and would otherwise be recorded as attacks. This
    # drops only the exact socket a probe used, never a class of traffic.
    if self_probe.claim(event.source_ip, event.source_port):
        return

    try:
        suppress, rule_id = await suppression.should_suppress(event)
    except Exception as e:
        # Failing open: an event we cannot evaluate is kept, not lost.
        log.warning("Suppression check failed (%s) — keeping the event.", e)
        suppress, rule_id = False, None

    tripped = await _match_honeytokens(event)
    if suppress and not tripped:
        if rule_id is not None:
            suppression.record_suppressed(rule_id)
        return

    await get_buffer().submit(event)


async def _match_honeytokens(event: PendingEvent) -> bool:
    """Tag `event` if it carries a planted credential/token. Returns True on a hit."""
    from honeypot_mcp import credential_match, token_matchers

    try:
        # Credentials matcher first — most events that match a planted credential
        # token also look like normal failed logins, so we re-tag them as the
        # first stop.
        token_id = await credential_match.match(event)
        if token_id is not None:
            event.honeytoken_id = token_id
            event.severity = AlertSeverity.CRITICAL
            event.event_type = f"honeytoken_triggered_credential_via_{event.event_type}"
            return True
        # SSH key / JWT / DB row matchers — payload-pattern based.
        token_id, match_type = await token_matchers.match(event)
        if token_id is not None:
            event.honeytoken_id = token_id
            event.severity = AlertSeverity.CRITICAL
            event.event_type = f"honeytoken_triggered_{match_type}_via_{event.event_type}"
            return True
    except Exception as e:
        log.warning("Honeytoken matching failed (%s) — keeping the event untagged.", e)
    return False


def _is_enrichable_ip(ip: str) -> bool:
    """Only globally routable addresses are worth an external lookup — this
    excludes loopback, RFC1918, link-local, CGNAT (100.64/10), TEST-NET,
    multicast and anything else `ipaddress` marks as non-global."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return addr.is_global and not addr.is_multicast


# ── Auto-enrichment ──────────────────────────────────────────────────────────
# Bounded: at most `_ENRICH_CONCURRENCY` lookups run at once, one lookup per IP
# is in flight at a time (later CRITICALs from the same IP join its alert list),
# and every task is strongly referenced until it finishes.
_ENRICH_CONCURRENCY = 8
_MAX_ALERTS_PER_ENRICHMENT = 1000
_enrich_sem: LoopBound[asyncio.Semaphore] = LoopBound(
    lambda: asyncio.Semaphore(_ENRICH_CONCURRENCY)
)
_enrich_pending: dict[str, list[int]] = {}
_enrich_tasks: set[asyncio.Task[None]] = set()


def _schedule_enrichment(alert_id: int, ip: str) -> None:
    pending = _enrich_pending.get(ip)
    if pending is not None:
        if len(pending) < _MAX_ALERTS_PER_ENRICHMENT:
            pending.append(alert_id)
        return
    alert_ids = [alert_id]
    _enrich_pending[ip] = alert_ids
    task = asyncio.get_running_loop().create_task(
        _enrich_ip(ip, alert_ids), name=f"enrich-{ip[:64]}"
    )
    _enrich_tasks.add(task)
    task.add_done_callback(_enrich_tasks.discard)


async def _lookup_enrichment(ip: str) -> dict[str, Any]:
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
    return {
        "geoip": geo if not isinstance(geo, Exception) else {"error": str(geo)},
        "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
        "abuseipdb": abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
    }


async def _enrich_ip(ip: str, alert_ids: list[int]) -> None:
    """Background task: enrich every alert in `alert_ids` with VT + AbuseIPDB +
    GeoIP and merge the result into each stored Alert.payload. Errors are
    swallowed — auto-enrichment is a UX improvement, not a guarantee, and a
    failing external API must not break ingest.

    Cached via intel/_cache.py — repeat CRITICALs from the same IP within the
    TTL window cost zero external calls."""
    try:
        try:
            async with _enrich_sem.get():
                enrichment = await _lookup_enrichment(ip)
        finally:
            # Detach: alerts flushed from here on start a fresh lookup (which
            # the intel cache then answers for free).
            if _enrich_pending.get(ip) is alert_ids:
                del _enrich_pending[ip]

        async with get_session() as session:
            for alert_id in list(alert_ids):
                alert = await session.get(Alert, alert_id)
                if alert is None:
                    continue
                # Re-assign the dict so SQLAlchemy's change-detection picks it up.
                # JSON columns don't track in-place mutation by default.
                new_payload = dict(alert.payload or {})
                new_payload["enrichment"] = enrichment
                alert.payload = new_payload
    except Exception as e:
        log.warning("Auto-enrichment failed for ip=%s (%d alert(s)): %s", ip, len(alert_ids), e)
