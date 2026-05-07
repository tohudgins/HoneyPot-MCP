"""Tests for the suppression engine.

Verifies: drop rules match by exact IP, CIDR, and event-type glob;
rate-limit rules pass the first N events and drop the rest within the window;
empty patterns mean 'match anything'.
"""

import asyncio
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp import suppression
    await init_db()
    suppression.invalidate_rule_cache()
    suppression._rate_state.clear()
    yield
    await close_db()


def _event(ip="1.2.3.4", event_type="ssh_login_failed"):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity
    return PendingEvent(
        honeypot_id=None,
        source_ip=ip,
        event_type=event_type,
        payload={},
        severity=AlertSeverity.HIGH,
    )


async def _add_rule(**kw):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import SuppressionRule
    async with get_session() as session:
        r = SuppressionRule(**kw)
        session.add(r)
        await session.flush()
        return r.id


@pytest.mark.asyncio
async def test_drop_by_exact_ip():
    from honeypot_mcp import suppression
    await _add_rule(label="block-1", ip_pattern="1.2.3.4", action="drop")
    suppression.invalidate_rule_cache()

    suppress, _ = await suppression.should_suppress(_event(ip="1.2.3.4"))
    assert suppress is True

    suppress, _ = await suppression.should_suppress(_event(ip="9.9.9.9"))
    assert suppress is False


@pytest.mark.asyncio
async def test_drop_by_cidr():
    from honeypot_mcp import suppression
    await _add_rule(label="block-net", ip_pattern="10.0.0.0/8", action="drop")
    suppression.invalidate_rule_cache()

    suppress, _ = await suppression.should_suppress(_event(ip="10.5.6.7"))
    assert suppress is True

    suppress, _ = await suppression.should_suppress(_event(ip="172.16.0.1"))
    assert suppress is False


@pytest.mark.asyncio
async def test_drop_by_event_type_glob():
    from honeypot_mcp import suppression
    await _add_rule(label="block-ssh", event_type_pattern="ssh_*", action="drop")
    suppression.invalidate_rule_cache()

    suppress, _ = await suppression.should_suppress(_event(event_type="ssh_login_failed"))
    assert suppress is True

    suppress, _ = await suppression.should_suppress(_event(event_type="http_probe"))
    assert suppress is False


@pytest.mark.asyncio
async def test_rate_limit_allows_first_n_then_drops():
    from honeypot_mcp import suppression
    await _add_rule(
        label="rate",
        ip_pattern="5.5.5.5",
        action="rate_limit",
        rate_limit_count=2,
        rate_limit_window_seconds=60,
    )
    suppression.invalidate_rule_cache()

    s1, _ = await suppression.should_suppress(_event(ip="5.5.5.5"))
    s2, _ = await suppression.should_suppress(_event(ip="5.5.5.5"))
    s3, _ = await suppression.should_suppress(_event(ip="5.5.5.5"))
    s4, _ = await suppression.should_suppress(_event(ip="5.5.5.5"))

    # First two pass (allowed), 3rd and 4th are dropped (rate limit hit)
    assert s1 is False
    assert s2 is False
    assert s3 is True
    assert s4 is True


@pytest.mark.asyncio
async def test_inactive_rule_does_not_match():
    from honeypot_mcp import suppression
    await _add_rule(label="off", ip_pattern="1.1.1.1", action="drop", active=False)
    suppression.invalidate_rule_cache()

    suppress, _ = await suppression.should_suppress(_event(ip="1.1.1.1"))
    assert suppress is False
