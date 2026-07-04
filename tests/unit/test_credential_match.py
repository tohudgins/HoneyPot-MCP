"""Tests for the credential honeytoken matcher.

Verifies: planted (username, password) pairs from an active CREDENTIAL
honeytoken cause a matching event to be flagged with `honeytoken_id`,
escalated to CRITICAL, and re-tagged as `honeytoken_triggered_credential_*`.
Negative case: non-matching creds pass through unchanged. Cache invalidation
on revoke also clears the match.
"""

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    await init_db()
    yield
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _plant(service: str, pairs: list[tuple[str, str]], label: str = "test") -> int:
    """Insert a CREDENTIAL honeytoken directly via the DB so we don't rely on
    the MCP tool layer."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label=label,
            token_value=f"cred:test:{label}",
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                "service": service,
                "credentials": [{"username": u, "password": p} for u, p in pairs],
                "count": len(pairs),
            },
        )
        session.add(token)
        await session.flush()
        return token.id


def _event(event_type: str, payload: dict):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=None,
        source_ip="1.2.3.4",
        event_type=event_type,
        payload=payload,
        severity=AlertSeverity.MEDIUM,
    )


@pytest.mark.asyncio
async def test_ssh_login_with_planted_creds_matches():
    from honeypot_mcp import credential_match

    token_id = await _plant("ssh", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "admin", "password": "Hunter2!"})
    matched = await credential_match.match(ev)
    assert matched == token_id


@pytest.mark.asyncio
async def test_username_match_is_case_insensitive():
    from honeypot_mcp import credential_match

    token_id = await _plant("ssh", [("admin", "Pa55w0rd")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "ADMIN", "password": "Pa55w0rd"})
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_password_match_is_case_sensitive():
    from honeypot_mcp import credential_match

    await _plant("ssh", [("admin", "Pa55w0rd")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "admin", "password": "pa55w0rd"})
    assert await credential_match.match(ev) is None


@pytest.mark.asyncio
async def test_non_matching_creds_return_none():
    from honeypot_mcp import credential_match

    await _plant("ssh", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "root", "password": "toor"})
    assert await credential_match.match(ev) is None


@pytest.mark.asyncio
async def test_service_mismatch_does_not_match():
    """Token planted for FTP should not fire on an SSH login attempt."""
    from honeypot_mcp import credential_match

    await _plant("ftp", [("ftpuser", "secret123")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "ftpuser", "password": "secret123"})
    assert await credential_match.match(ev) is None


@pytest.mark.asyncio
async def test_any_service_matches_anywhere():
    from honeypot_mcp import credential_match

    token_id = await _plant("any", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    for et in ("ssh_login_failed", "http_credential_submit", "ftp_login_attempt"):
        ev = _event(et, {"username": "admin", "password": "Hunter2!"})
        assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_postgresql_login_with_planted_creds_matches():
    """postgresql_login_attempt events carry cleartext creds (the engine
    forces cleartext auth) and must match tokens planted with
    service="postgresql" — regression for the prefix map missing DB engines."""
    from honeypot_mcp import credential_match

    token_id = await _plant("postgresql", [("postgres", "Sup3rSecret!")])
    credential_match.invalidate_cache()

    ev = _event(
        "postgresql_login_attempt",
        {
            "username": "postgres",
            "password": "Sup3rSecret!",
            "database": "prod",
            "service": "postgresql",
        },
    )
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_mssql_login_with_planted_creds_matches():
    from honeypot_mcp import credential_match

    token_id = await _plant("mssql", [("sa", "Str0ng&Pass")])
    credential_match.invalidate_cache()

    ev = _event(
        "mssql_login_attempt",
        {"username": "sa", "password": "Str0ng&Pass", "database": "master", "service": "mssql"},
    )
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_db_service_tokens_do_not_cross_match():
    """A postgresql-planted token must not fire on an mssql login and vice versa."""
    from honeypot_mcp import credential_match

    await _plant("postgresql", [("dbadmin", "OnlyForPg1!")])
    credential_match.invalidate_cache()

    ev = _event(
        "mssql_login_attempt",
        {"username": "dbadmin", "password": "OnlyForPg1!", "service": "mssql"},
    )
    assert await credential_match.match(ev) is None


@pytest.mark.asyncio
async def test_http_post_data_match():
    from honeypot_mcp import credential_match

    token_id = await _plant("http", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    ev = _event(
        "http_credential_submit",
        {"post_data": {"username": "admin", "password": "Hunter2!"}, "path": "/login"},
    )
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_smtp_auth_plain_base64_decoded():
    """AUTH PLAIN encodes <authzid>\\0<user>\\0<pass> in base64. Matcher should
    decode and match."""
    import base64

    from honeypot_mcp import credential_match

    token_id = await _plant("smtp", [("alice", "wonderland")])
    credential_match.invalidate_cache()

    blob = base64.b64encode(b"\x00alice\x00wonderland").decode()
    ev = _event("smtp_auth_attempt", {"command": f"AUTH PLAIN {blob}"})
    assert await credential_match.match(ev) == token_id


@pytest.mark.asyncio
async def test_revoke_clears_match():
    from sqlalchemy import update

    from honeypot_mcp import credential_match
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus

    token_id = await _plant("ssh", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    ev = _event("ssh_login_failed", {"username": "admin", "password": "Hunter2!"})
    assert await credential_match.match(ev) == token_id

    # Revoke + invalidate (mirrors what tools/honeytoken.py:honeytoken_revoke does)
    async with get_session() as session:
        await session.execute(
            update(Honeytoken)
            .where(Honeytoken.id == token_id)
            .values(status=HoneytokenStatus.REVOKED)
        )
    credential_match.invalidate_cache()

    assert await credential_match.match(ev) is None


@pytest.mark.asyncio
async def test_submit_event_escalates_and_marks_token_triggered():
    """End-to-end: submit_event() with planted creds → CRITICAL alert with
    `honeytoken_id` set → token row flips to TRIGGERED after flush."""
    import asyncio

    from sqlalchemy import select

    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
    )

    token_id = await _plant("ssh", [("admin", "Hunter2!")])
    credential_match.invalidate_cache()

    # Start the global buffer so submit_event() has somewhere to flush.
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="1.2.3.4",
                event_type="ssh_login_failed",
                payload={"username": "admin", "password": "Hunter2!"},
                severity=AlertSeverity.MEDIUM,
            )
        )
        await asyncio.sleep(1.5)  # let the flusher drain
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())
        token = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one()

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].event_type.startswith("honeytoken_triggered_credential_via_")
    assert token.status == HoneytokenStatus.TRIGGERED
