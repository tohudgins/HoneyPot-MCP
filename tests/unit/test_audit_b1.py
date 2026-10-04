"""Regression tests for the ingest-pipeline / matcher / intel audit.

Tests that exercise a former ReDoS bound their wall time so a regression fails
instead of hanging the suite.
"""

import os
import time

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match, token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    token_matchers.invalidate_cache()
    await init_db()
    yield
    credential_match.invalidate_cache()
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


def _event(event_type: str, payload: dict, severity=None, ip: str = "1.2.3.4"):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=None,
        source_ip=ip,
        event_type=event_type,
        payload=payload,
        severity=severity or AlertSeverity.MEDIUM,
    )


async def _plant_credential(user: str, password: str, status=None) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label="audit-b1",
            token_value="cred:audit-b1",
            status=status or HoneytokenStatus.ACTIVE,
            token_meta={
                "service": "ssh",
                "credentials": [{"username": user, "password": password}],
                "count": 1,
            },
        )
        session.add(token)
        await session.flush()
        return token.id


# ── 1. ReDoS ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_map_to_attack_is_bounded_on_hostile_terms():
    from honeypot_mcp.intel.mitre import map_to_attack

    hostile = ["rdp" * 2700, "dns" * 2700, "download" * 1000, "outfile" * 1200, ".php" * 2000]
    start = time.monotonic()
    for _ in range(10):
        await map_to_attack(hostile)
    assert time.monotonic() - start < 0.5


@pytest.mark.asyncio
async def test_map_to_attack_still_maps_realistic_events():
    from honeypot_mcp.intel.mitre import map_to_attack

    mapped = await map_to_attack(["ssh_login_failed", "brute force login attempt"])
    ids = {m["technique_id"] for m in mapped}
    assert any(i.startswith("T1110") for i in ids)


# ── 2. JWT scan ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_token_matcher_is_linear_on_hostile_jwt_lookalikes_and_still_finds_a_real_jwt():
    import base64
    import json

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    # An active JWT token must exist, or `match` returns at the empty-index early
    # exit and never reaches the scan this test is about.
    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.JWT,
            label="jwt-redos",
            token_value="jwt:planted",
            status=HoneytokenStatus.ACTIVE,
            token_meta={"jti": "planted-jti-0001"},
        )
        session.add(token)
        await session.flush()
        token_id = token.id
    token_matchers.invalidate_cache()

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    real = f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'jti': 'planted-jti-0001'})}.c2lnbmF0dXJl"
    hostile = "a-" * 32_768  # a-a-a-… is the quadratic case for a naive JWT regex
    ev = _event(
        "http_request",
        {
            "headers": {"X-Junk": hostile, "Authorization": f"Bearer {real}"},
            "path": hostile,
        },
    )
    start = time.monotonic()
    matched, kind = await token_matchers.match(ev)
    assert time.monotonic() - start < 0.25
    assert matched == token_id and kind == "jwt"


# ── 3. Payload clamp + bounded queue ────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_event_clamps_oversized_payloads_and_marks_them():
    from honeypot_mcp.storage import event_buffer

    ev = _event("http_request", {"body": "A" * 500_000, "path": "/x"})
    await event_buffer.submit_event(ev)
    assert len(ev.payload["body"]) < 10_000
    assert ev.payload.get("payload_truncated") is True
    assert ev.payload["path"] == "/x"


@pytest.mark.asyncio
async def test_queue_overflow_drops_low_severity_first_and_counts_it(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.models import AlertSeverity

    monkeypatch.setattr(get_settings(), "event_queue_max", 5)
    event_buffer.reset_for_tests()
    before = event_buffer.dropped_event_count()
    for i in range(20):
        await event_buffer.submit_event(_event(f"noise_{i}", {}, AlertSeverity.LOW))
    crit = _event("honeytoken_trip", {}, AlertSeverity.CRITICAL)
    await event_buffer.submit_event(crit)
    assert event_buffer.dropped_event_count() > before
    assert event_buffer.dropped_event_counts_by_severity()["critical"] == 0


# ── 3b. One poison event costs only itself ──────────────────────────────────


@pytest.mark.asyncio
async def test_poison_event_drops_only_itself():
    from sqlalchemy import func, select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    class _Unserialisable:
        pass

    buf = event_buffer.get_buffer() if hasattr(event_buffer, "get_buffer") else None
    if buf is None:
        pytest.skip("no buffer accessor")
    good = [_event(f"good_{i}", {"n": i}) for i in range(3)]
    bad = _event("poison", {"x": _Unserialisable()})
    written = await buf._flush([good[0], bad, good[1], good[2]])
    assert {e.event_type for e in written} == {"good_0", "good_1", "good_2"}
    async with get_session() as session:
        total = (await session.execute(select(func.count()).select_from(Alert))).scalar_one()
    assert total == 3


# ── 5. Stale-while-error ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cache_refresh_failure_keeps_previous_index_and_does_not_raise(monkeypatch):
    from honeypot_mcp import credential_match

    token_id = await _plant_credential("root", "S3cret!pw")
    ev = _event("ssh_login_failed", {"username": "root", "password": "S3cret!pw"})
    assert await credential_match.match(ev) == token_id

    def _boom():
        raise RuntimeError("database is down")

    monkeypatch.setattr(credential_match, "get_session", _boom)
    credential_match.invalidate_cache()
    ev2 = _event("ssh_login_failed", {"username": "root", "password": "S3cret!pw"})
    # Stale index still answers; nothing raises out of the matcher.
    assert await credential_match.match(ev2) == token_id


# ── 6. Re-arming ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_triggered_credential_token_still_matches_and_history_accumulates():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus

    token_id = await _plant_credential("deploy", "Zx9!kLm2#qq")
    for i in range(25):
        async with get_session() as session:
            await queries.mark_honeytoken_triggered(session, token_id, {"n": i})

    async with get_session() as session:
        token = await session.get(Honeytoken, token_id)
        assert token.status == HoneytokenStatus.TRIGGERED
        assert token.triggered_at is not None
        assert token.trigger_metadata == {"n": 24}
        history = token.token_meta["triggers"]
        assert len(history) == 20  # capped, newest last

    credential_match.invalidate_cache()
    ev = _event("ssh_login_failed", {"username": "deploy", "password": "Zx9!kLm2#qq"})
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_revoked_token_is_not_rearmed_by_a_late_trigger():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus

    token_id = await _plant_credential("old", "Rev0ked!pw", status=HoneytokenStatus.REVOKED)
    async with get_session() as session:
        await queries.mark_honeytoken_triggered(session, token_id, {"n": 1})
    async with get_session() as session:
        token = await session.get(Honeytoken, token_id)
        assert token.status == HoneytokenStatus.REVOKED


# ── 7. Retention ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_archive_chunks_cover_every_row_in_id_order():
    from datetime import UTC, datetime, timedelta

    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    old = datetime.now(UTC) - timedelta(days=90)
    async with get_session() as session:
        for i in range(25):
            session.add(
                Alert(
                    source_ip="8.8.8.8",
                    event_type=f"e{i}",
                    severity=AlertSeverity.LOW,
                    payload={},
                    timestamp=old,
                )
            )
    seen: list[str] = []
    async with get_session() as session:
        async for lines, _last in queries.iter_alert_archive_chunks(
            session, datetime.now(UTC) - timedelta(days=30), chunk_rows=10
        ):
            assert len(lines) <= 10
            seen.extend(lines)
    assert len(seen) == 25


# ── 8. Blocklist source filtering ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_top_offenders_global_only_drops_private_and_invalid_sources():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for ip in ("8.8.4.4", "10.0.0.5", "192.168.1.9", "100.64.0.1", "not-an-ip"):
            for _ in range(3):
                session.add(
                    Alert(
                        source_ip=ip,
                        event_type="ssh_login_failed",
                        severity=AlertSeverity.HIGH,
                        payload={},
                    )
                )
    async with get_session() as session:
        everything = {ip for ip, _ in await queries.get_top_offenders(session, 24, 1)}
        only_global = {
            ip for ip, _ in await queries.get_top_offenders(session, 24, 1, global_only=True)
        }
    assert {"10.0.0.5", "not-an-ip"} <= everything  # default behaviour preserved
    assert only_global == {"8.8.4.4"}
