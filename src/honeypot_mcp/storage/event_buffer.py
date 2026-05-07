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
from datetime import datetime, timezone
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
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("Event buffer flusher did not exit cleanly.")
            self._task = None

    def qsize(self) -> int:
        return self._queue.qsize()

    async def _run(self) -> None:
        while True:
            batch: list[PendingEvent] = []
            try:
                first = await asyncio.wait_for(self._queue.get(), timeout=self._flush_interval)
                batch.append(first)
            except asyncio.TimeoutError:
                if self._stop.is_set() and self._queue.empty():
                    return
                continue

            while len(batch) < self._batch_size:
                try:
                    batch.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            try:
                await self._flush(batch)
            except Exception as e:
                log.warning("Event buffer flush failed (%d events lost): %s", len(batch), e)
                continue

            if self._on_flush is not None:
                try:
                    await self._on_flush(batch)
                except Exception as e:
                    log.warning("Event buffer on_flush hook failed: %s", e)

    async def _flush(self, batch: list[PendingEvent]) -> None:
        async with get_session() as session:
            for ev in batch:
                session.add(Alert(
                    honeypot_id=ev.honeypot_id,
                    source_ip=ev.source_ip,
                    source_port=ev.source_port,
                    event_type=ev.event_type,
                    payload=ev.payload,
                    severity=ev.severity,
                    timestamp=ev.timestamp,
                ))
                session.add(AttackerEvent(
                    ip=ev.source_ip,
                    event_type=ev.event_type,
                    extra=ev.payload,
                    honeytoken_id=ev.honeytoken_id,
                    timestamp=ev.timestamp,
                ))


_buffer: EventBuffer | None = None


def get_buffer() -> EventBuffer:
    global _buffer
    if _buffer is None:
        _buffer = EventBuffer()
    return _buffer


def reset_for_tests() -> None:
    """Clear the singleton so the next get_buffer() returns a fresh instance.

    Each pytest-asyncio test gets its own event loop. asyncio.Queue is bound to
    the loop it was created in, so a singleton built in test A breaks in test B
    with `Queue is bound to a different event loop`. Tests that use the buffer
    must call this in their setUp."""
    global _buffer
    _buffer = None


async def submit_event(event: PendingEvent) -> None:
    """Module-level convenience for engines.

    Suppression rules are evaluated here — events that match an active drop or
    rate-limit rule are dropped before they enter the buffer. We import lazily
    to avoid an import cycle between event_buffer ⇄ suppression."""
    from honeypot_mcp import suppression

    suppress, rule_id = await suppression.should_suppress(event)
    if suppress:
        if rule_id is not None:
            await _bump_suppression_count(rule_id)
        return
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
