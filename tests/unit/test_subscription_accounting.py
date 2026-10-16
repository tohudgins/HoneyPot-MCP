"""A notification the throttle declined to send is not a delivery and not evidence of health.

Found on the live VPS: the Slack subscription reported 13,025 deliveries in nine hours while its
channel had received a handful of messages, because a throttled event returned success and was
recorded as one. The same path reset `failure_count` and cleared `last_error`, so a broken webhook
would have looked healthy as soon as the throttle swallowed the next event.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(
        get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path}/subs.db", raising=False
    )
    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _subscription(**fields):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    async with get_session() as session:
        sub = Subscription(
            url="https://hooks.slack.com/services/T0/B0/xxxx",
            label="slack",
            severity_threshold=AlertSeverity.CRITICAL,
            format="slack",
            **fields,
        )
        session.add(sub)
        await session.flush()
        session.expunge(sub)
        return sub


async def _reload(sub_id: int):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Subscription

    async with get_session() as session:
        return (
            await session.execute(select(Subscription).where(Subscription.id == sub_id))
        ).scalar_one()


def _event(ip: str = "203.0.113.9"):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=1,
        source_ip=ip,
        source_port=5060,
        event_type="sip_toll_fraud_attempt",
        payload={},
        severity=AlertSeverity.CRITICAL,
        timestamp=datetime.now(UTC),
    )


@pytest.fixture
def worker(monkeypatch):
    """The real delivery worker with the network stubbed out: only the throttle and the
    bookkeeping are real."""
    from honeypot_mcp.webhooks import WebhookDelivery

    delivery = WebhookDelivery()
    sent: list = []

    async def destination(sub, fmt):
        return None, []

    async def human(event, sub, fmt, suppressed):
        sent.append(suppressed)
        return outcome["value"]

    outcome = {"value": (True, None)}
    monkeypatch.setattr(delivery, "_checked_destination", destination)
    monkeypatch.setattr(delivery, "_dispatch_human", human)
    delivery.sent, delivery.outcome = sent, outcome
    return delivery


@pytest.mark.asyncio
async def test_repeats_the_throttle_swallows_are_counted_as_suppressed_not_delivered(worker):
    sub = await _subscription()
    for _ in range(5):  # the same CRITICAL from the same source, repeatedly
        await worker._deliver_one(_event(), sub)

    row = await _reload(sub.id)
    assert len(worker.sent) == 1, "one message reaches the channel"
    assert row.delivery_count == 1, "and that is the only delivery"
    assert row.suppressed_count == 4


@pytest.mark.asyncio
async def test_a_throttled_event_never_hides_a_failing_webhook(worker):
    """The first message fails; the next four are swallowed by the throttle. Before the fix those
    four were recorded as successes, resetting failure_count to 0 and clearing last_error."""
    sub = await _subscription()
    worker.outcome["value"] = (False, "Slack answered 404: no_service")
    await worker._deliver_one(_event(), sub)
    for _ in range(4):
        await worker._deliver_one(_event(), sub)

    row = await _reload(sub.id)
    assert row.failure_count == 1 and row.last_error == "Slack answered 404: no_service"
    assert row.delivery_count == 0 and row.suppressed_count == 4
    assert row.last_delivery_at is None, "nothing was ever delivered"


@pytest.mark.asyncio
async def test_a_different_source_is_a_new_message_and_a_real_delivery_clears_the_error(worker):
    sub = await _subscription()
    worker.outcome["value"] = (False, "boom")
    await worker._deliver_one(_event("203.0.113.1"), sub)
    worker.outcome["value"] = (True, None)
    await worker._deliver_one(_event("203.0.113.2"), sub)  # a different incident pages again

    row = await _reload(sub.id)
    assert row.delivery_count == 1 and row.failure_count == 0 and row.last_error is None
    assert row.suppressed_count == 0 and row.last_delivery_at is not None


@pytest.mark.asyncio
async def test_the_list_tool_reports_suppressed_next_to_delivered():
    from honeypot_mcp.tools.integrations import alert_subscriptions_list

    sub = await _subscription()
    from honeypot_mcp.webhooks import THROTTLED, WebhookDelivery

    await WebhookDelivery()._record_outcome(sub.id, True, THROTTLED)
    listed = await alert_subscriptions_list()
    rows = listed["subscriptions"] if isinstance(listed, dict) else listed
    item = next(s for s in rows if s["id"] == sub.id)
    assert item["suppressed_count"] == 1 and item["delivery_count"] == 0
