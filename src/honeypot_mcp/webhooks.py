"""Outbound webhook delivery.

Every flushed alert that meets a subscription's severity threshold is POSTed
to the subscription URL as JSON. If `hmac_secret` is set, the request carries
an `X-HoneyPot-Signature: sha256=<hex>` header (HMAC-SHA256 of the raw body)
so the consumer can verify authenticity.

Delivery runs in a background asyncio task drained from a queue so that slow
webhook endpoints can never back-pressure the honeypot data path. Failed
deliveries retry with exponential backoff (1s, 5s, 30s); after that, the
failure_count column tracks consecutive failures and an admin can deactivate
or repair the subscription.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
from sqlalchemy import select, update

from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent
from honeypot_mcp.storage.models import AlertSeverity, Subscription

log = logging.getLogger(__name__)

_SEVERITY_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}

_RETRY_DELAYS = (1.0, 5.0, 30.0)


def sign_body(secret: str, body: bytes) -> str:
    """`X-HoneyPot-Signature: sha256=<hex>`. Consumers verify with the same
    secret over the raw body bytes — same convention as GitHub webhooks."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _serialise(event: PendingEvent) -> dict[str, Any]:
    return {
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "event_type": event.event_type,
        "severity": event.severity.value,
        "honeypot_id": event.honeypot_id,
        "honeytoken_id": event.honeytoken_id,
        "payload": event.payload,
        "timestamp": event.timestamp.isoformat(),
    }


def _meets_threshold(event_severity: AlertSeverity, threshold: AlertSeverity) -> bool:
    return _SEVERITY_RANK[event_severity] >= _SEVERITY_RANK[threshold]


async def _post_with_retry(
    client: httpx.AsyncClient,
    sub: Subscription,
    body_bytes: bytes,
    headers: dict[str, str],
) -> tuple[bool, str | None]:
    last_err: str | None = None
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            resp = await client.post(sub.url, content=body_bytes, headers=headers, timeout=10.0)
            if 200 <= resp.status_code < 300:
                return True, None
            last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)[:200]
        if attempt < len(_RETRY_DELAYS) - 1:
            await asyncio.sleep(delay)
    return False, last_err


@dataclass
class _Job:
    event: PendingEvent
    enqueued_at: float = field(default_factory=lambda: __import__("time").monotonic())


class WebhookDelivery:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[_Job] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._client = httpx.AsyncClient()
            self._task = asyncio.create_task(self._run(), name="webhook-delivery")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except asyncio.TimeoutError:
                log.warning("Webhook delivery worker did not exit cleanly.")
            self._task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def enqueue_batch(self, events: list[PendingEvent]) -> None:
        for ev in events:
            await self._queue.put(_Job(event=ev))

    async def _run(self) -> None:
        while True:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                if self._stop.is_set() and self._queue.empty():
                    return
                continue
            try:
                await self._deliver(job.event)
            except Exception as e:
                log.warning("Webhook delivery error: %s", e)

    async def _deliver(self, event: PendingEvent) -> None:
        async with get_session() as session:
            result = await session.execute(
                select(Subscription).where(Subscription.active.is_(True))
            )
            subs = list(result.scalars().all())

        if not subs or self._client is None:
            return

        body = json.dumps(_serialise(event), default=str).encode("utf-8")

        for sub in subs:
            if not _meets_threshold(event.severity, sub.severity_threshold):
                continue

            headers = {"Content-Type": "application/json", "User-Agent": "HoneyPot-MCP/1.0"}
            if sub.hmac_secret:
                headers["X-HoneyPot-Signature"] = sign_body(sub.hmac_secret, body)

            ok, err = await _post_with_retry(self._client, sub, body, headers)
            await self._record_outcome(sub.id, ok, err)

    async def _record_outcome(self, sub_id: int, ok: bool, err: str | None) -> None:
        async with get_session() as session:
            if ok:
                await session.execute(
                    update(Subscription)
                    .where(Subscription.id == sub_id)
                    .values(
                        delivery_count=Subscription.delivery_count + 1,
                        last_delivery_at=datetime.now(timezone.utc),
                        failure_count=0,
                        last_error=None,
                    )
                )
            else:
                await session.execute(
                    update(Subscription)
                    .where(Subscription.id == sub_id)
                    .values(
                        failure_count=Subscription.failure_count + 1,
                        last_error=(err or "")[:500],
                    )
                )


_delivery: WebhookDelivery | None = None


def get_delivery() -> WebhookDelivery:
    global _delivery
    if _delivery is None:
        _delivery = WebhookDelivery()
    return _delivery
