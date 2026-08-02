"""Live-provisioned API keys: issuance, revocation, and the verifier that
checks them.

Exists because the static MCP_AUTH_TOKEN(S) settings require a process
restart to change and carry no per-person identity — these tools are the
live, per-team-member counterpart. See rbac.py's module docstring and
tools/api_keys.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.rbac import invalidate_api_key_cache
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    invalidate_api_key_cache()
    yield
    invalidate_api_key_cache()
    await close_db()


@dataclass
class _Token:
    claims: dict


def _as(monkeypatch, role: str, label: str | None = None):
    """Simulate the current call being made with a given role/label token."""
    import fastmcp.server.dependencies as deps

    claims = {"role": role} if label is None else {"role": role, "label": label}
    monkeypatch.setattr(deps, "get_access_token", lambda: _Token(claims=claims))


# ── api_key_create ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_returns_the_plaintext_token_exactly_once():
    from honeypot_mcp.tools.api_keys import api_key_create

    result = await api_key_create(label="alice", role="operator")
    assert "token" in result
    assert len(result["token"]) >= 32
    assert result["label"] == "alice"
    assert result["role"] == "operator"
    assert result["expires_at"] is None


@pytest.mark.asyncio
async def test_only_the_hash_is_stored_never_the_plaintext():
    from honeypot_mcp.rbac import hash_token
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import ApiKey
    from honeypot_mcp.tools.api_keys import api_key_create

    result = await api_key_create(label="alice", role="viewer")
    token = result["token"]

    async with get_session() as session:
        row = (await session.execute(select(ApiKey).where(ApiKey.id == result["id"]))).scalar_one()
        assert row.token_hash == hash_token(token)
        assert token not in row.token_hash


@pytest.mark.asyncio
async def test_create_rejects_empty_label():
    from honeypot_mcp.tools.api_keys import api_key_create

    assert "error" in await api_key_create(label="   ", role="viewer")


@pytest.mark.asyncio
async def test_create_rejects_non_positive_expiry():
    from honeypot_mcp.tools.api_keys import api_key_create

    assert "error" in await api_key_create(label="alice", role="viewer", expires_in_days=0)
    assert "error" in await api_key_create(label="alice", role="viewer", expires_in_days=-1)


@pytest.mark.asyncio
async def test_create_records_who_issued_it(monkeypatch):
    _as(monkeypatch, "admin", "root")
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import ApiKey
    from honeypot_mcp.tools.api_keys import api_key_create

    result = await api_key_create(label="alice", role="viewer")
    async with get_session() as session:
        row = (await session.execute(select(ApiKey).where(ApiKey.id == result["id"]))).scalar_one()
        assert row.created_by == "root (admin)"


@pytest.mark.asyncio
async def test_create_is_audited():
    from honeypot_mcp.tools.alerts import audit_log_search
    from honeypot_mcp.tools.api_keys import api_key_create

    await api_key_create(label="alice", role="operator")
    entry = (await audit_log_search(tool="api_key_create"))["actions"][0]
    assert "alice" in entry["summary"]
    assert entry["arguments"]["role"] == "operator"
    # The plaintext token must never reach the audit log.
    assert "token" not in entry["arguments"]


# ── api_key_revoke ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_marks_the_key_revoked():
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_list, api_key_revoke

    created = await api_key_create(label="alice", role="operator")
    result = await api_key_revoke(created["id"])
    assert result["status"] == "revoked"

    active = await api_key_list()
    assert not any(k["id"] == created["id"] for k in active)

    everything = await api_key_list(include_revoked=True)
    revoked = next(k for k in everything if k["id"] == created["id"])
    assert revoked["revoked_at"] is not None


@pytest.mark.asyncio
async def test_revoke_unknown_id_errors():
    from honeypot_mcp.tools.api_keys import api_key_revoke

    assert "error" in await api_key_revoke(999999)


@pytest.mark.asyncio
async def test_double_revoke_errors_instead_of_silently_succeeding():
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_revoke

    created = await api_key_create(label="alice", role="viewer")
    await api_key_revoke(created["id"])
    second = await api_key_revoke(created["id"])
    assert "error" in second
    assert "already revoked" in second["error"]


@pytest.mark.asyncio
async def test_revoke_is_audited():
    from honeypot_mcp.tools.alerts import audit_log_search
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_revoke

    created = await api_key_create(label="alice", role="viewer")
    await api_key_revoke(created["id"])
    entry = (await audit_log_search(tool="api_key_revoke"))["actions"][0]
    assert "alice" in entry["summary"]


# ── api_key_list ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_never_returns_the_token_or_its_hash():
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_list

    created = await api_key_create(label="alice", role="viewer")
    entries = await api_key_list()
    assert entries[0]["id"] == created["id"]
    for entry in entries:
        assert set(entry) == {
            "id",
            "label",
            "role",
            "created_by",
            "created_at",
            "expires_at",
            "revoked_at",
        }
        assert created["token"] not in str(entry)


@pytest.mark.asyncio
async def test_list_excludes_revoked_by_default():
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_list, api_key_revoke

    kept = await api_key_create(label="alice", role="viewer")
    gone = await api_key_create(label="bob", role="viewer")
    await api_key_revoke(gone["id"])

    active_only = await api_key_list()
    assert {k["id"] for k in active_only} == {kept["id"]}

    everything = await api_key_list(include_revoked=True)
    assert {k["id"] for k in everything} == {kept["id"], gone["id"]}


# ── rbac.verify_db_token: the actual verification path ──────────────────────


@pytest.mark.asyncio
async def test_a_freshly_created_key_verifies():
    from honeypot_mcp.rbac import verify_db_token
    from honeypot_mcp.tools.api_keys import api_key_create

    created = await api_key_create(label="alice", role="operator")
    access = await verify_db_token(created["token"])
    assert access is not None
    assert access.claims["role"] == "operator"
    assert access.claims["label"] == "alice"


@pytest.mark.asyncio
async def test_an_unknown_token_does_not_verify():
    from honeypot_mcp.rbac import verify_db_token

    assert await verify_db_token("this-token-was-never-issued") is None


@pytest.mark.asyncio
async def test_a_revoked_key_stops_verifying():
    from honeypot_mcp.rbac import verify_db_token
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_revoke

    created = await api_key_create(label="alice", role="operator")
    assert await verify_db_token(created["token"]) is not None

    await api_key_revoke(created["id"])
    assert await verify_db_token(created["token"]) is None


@pytest.mark.asyncio
async def test_an_expired_key_stops_verifying():
    from honeypot_mcp.rbac import invalidate_api_key_cache, verify_db_token
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import ApiKey
    from honeypot_mcp.tools.api_keys import api_key_create

    created = await api_key_create(label="alice", role="viewer", expires_in_days=30)
    assert await verify_db_token(created["token"]) is not None

    # Simulate time passing rather than waiting 30 real days.
    async with get_session() as session:
        row = (await session.execute(select(ApiKey).where(ApiKey.id == created["id"]))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(days=1)
    invalidate_api_key_cache()

    assert await verify_db_token(created["token"]) is None


# ── rbac.build_combined_verifier: static tokens + DB-backed keys together ───


@pytest.mark.asyncio
async def test_combined_verifier_checks_static_tokens_first():
    from honeypot_mcp.rbac import build_combined_verifier

    verifier = build_combined_verifier(
        {"static-tok": {"client_id": "honeypot-admin", "scopes": ["admin"], "role": "admin"}}
    )
    access = await verifier.verify_token("static-tok")
    assert access is not None
    assert access.claims["role"] == "admin"


@pytest.mark.asyncio
async def test_combined_verifier_falls_through_to_db_backed_keys():
    from honeypot_mcp.rbac import build_combined_verifier
    from honeypot_mcp.tools.api_keys import api_key_create

    created = await api_key_create(label="alice", role="viewer")
    verifier = build_combined_verifier(
        {"static-tok": {"client_id": "x", "scopes": [], "role": "admin"}}
    )

    # Not the static token, but a real live-provisioned one.
    access = await verifier.verify_token(created["token"])
    assert access is not None
    assert access.claims["label"] == "alice"


@pytest.mark.asyncio
async def test_combined_verifier_rejects_unknown_tokens():
    from honeypot_mcp.rbac import build_combined_verifier

    verifier = build_combined_verifier(
        {"static-tok": {"client_id": "x", "scopes": [], "role": "admin"}}
    )
    assert await verifier.verify_token("garbage") is None


# ── current_actor ────────────────────────────────────────────────────────────


def test_current_actor_defaults_to_stdio_with_no_token():
    from honeypot_mcp.rbac import current_actor

    # No FastMCP request context in a plain function call — same as stdio.
    assert current_actor() == "stdio"


def test_current_actor_combines_label_and_role(monkeypatch):
    _as(monkeypatch, "operator", "alice")
    from honeypot_mcp.rbac import current_actor

    assert current_actor() == "alice (operator)"


def test_current_actor_falls_back_to_bare_role_with_no_label(monkeypatch):
    _as(monkeypatch, "admin")
    from honeypot_mcp.rbac import current_actor

    assert current_actor() == "admin"
