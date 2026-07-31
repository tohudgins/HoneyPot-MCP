"""DNS canary-subdomain (FILE honeytoken) matching.

The 32-char-label match previously ran an uncached DB query plus a full
Python-side scan of every active FILE honeytoken on every matching DNS
packet — no TTL cache, unlike every other honeytoken cross-reference in this
codebase. Now goes through token_matchers.match_file_uid(), the same
TTL-cached-index pattern credential_match.py and token_matchers.py's other
matchers already use. These tests exercise the refactored path directly
(_DNSProtocol._record is plain async, no socket needed) to confirm the
matching behaviour itself didn't change.
"""

import asyncio
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    token_matchers.invalidate_cache()
    await init_db()
    yield
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _add_file_honeytoken(token_uid: str) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        t = Honeytoken(
            type=HoneytokenType.FILE,
            label="decoy.pdf",
            token_value="decoy.pdf",
            status=HoneytokenStatus.ACTIVE,
            token_meta={"token_uid": token_uid},
        )
        session.add(t)
        await session.flush()
        return t.id


@pytest.mark.asyncio
async def test_dns_canary_subdomain_matches_planted_file_token():
    from sqlalchemy import select

    from honeypot_mcp.engines.dns import _DNSProtocol
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, Honeytoken, HoneytokenStatus

    token_uid = "abcd1234abcd1234abcd1234abcd1234"
    assert len(token_uid) == 32
    token_id = await _add_file_honeytoken(token_uid)

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        proto = _DNSProtocol("dns-canary-test", honeypot_id=None)
        await proto._record("203.0.113.5", 5353, f"{token_uid}.canary.example.com", "A", "IN")
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "dns_canary_callback")
        )
        alerts = list(result.scalars().all())
        token = await session.get(Honeytoken, token_id)

    assert len(alerts) == 1
    assert alerts[0].severity.value == "critical"
    assert alerts[0].payload["matched_token_id"] == token_id
    assert token.status == HoneytokenStatus.TRIGGERED


@pytest.mark.asyncio
async def test_dns_query_with_no_matching_label_stays_uncritical():
    from sqlalchemy import select

    from honeypot_mcp.engines.dns import _DNSProtocol
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    await _add_file_honeytoken("abcd1234abcd1234abcd1234abcd1234")

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        proto = _DNSProtocol("dns-canary-test", honeypot_id=None)
        # A 32-char label that doesn't match any planted token_uid.
        await proto._record(
            "203.0.113.6", 5353, "ffffffffffffffffffffffffffffffff.example.com", "A", "IN"
        )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "dns_canary_callback")
        )
        alerts = list(result.scalars().all())

    assert not any(a.severity.value == "critical" for a in alerts)


@pytest.mark.asyncio
async def test_dns_canary_match_reflects_a_token_planted_after_first_load():
    """The index is TTL-cached, not loaded once at import time — a token
    created after the cache was warmed (but within the same test process)
    must still match once invalidate_cache() runs, exactly as
    honeytoken_create already triggers via _invalidate_matcher_caches()."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.engines.dns import _DNSProtocol
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    # Warm the cache with no tokens planted yet.
    assert await token_matchers.match_file_uid(["irrelevant"]) is None

    token_uid = "11112222333344445555666677778888"
    token_id = await _add_file_honeytoken(token_uid)
    token_matchers.invalidate_cache()  # what honeytoken_create does

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        proto = _DNSProtocol("dns-canary-test", honeypot_id=None)
        await proto._record("203.0.113.7", 5353, f"{token_uid}.z.example.com", "A", "IN")
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "dns_canary_callback")
        )
        alerts = list(result.scalars().all())

    assert any(a.payload.get("matched_token_id") == token_id for a in alerts)
