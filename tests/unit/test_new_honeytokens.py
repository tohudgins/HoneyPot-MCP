"""Tests for the new honeytoken types: SSH-key, JWT, DB-row.

Covers:
* Provider correctness — the right artefacts get produced.
* token_matchers cross-reference — events with the matching pattern in
  payload fire CRITICAL and link to the originating honeytoken_id.
* End-to-end via submit_event() with the real flusher + event buffer.
"""

import asyncio
import base64
import json
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    """In-memory DB + tmp working dir so artefacts (private keys, certs) don't
    litter the repo."""
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    token_matchers.invalidate_cache()
    await init_db()
    yield
    await asyncio.sleep(0.1)
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


# ── SSH-key provider ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssh_key_provider_generates_real_keypair():
    from honeypot_mcp.tokens.ssh_key import SSHKeyProvider

    provider = SSHKeyProvider()
    token_value, meta = await provider.create({"comment": "test-key"})

    # token_value IS the fingerprint
    assert token_value.startswith("SHA256:")
    assert meta["fingerprint"] == token_value
    # Public key starts with the OpenSSH algorithm prefix
    assert meta["public_key"].startswith("ssh-rsa ")
    # Private key written to disk and is real OpenSSH PEM
    from pathlib import Path

    pem = Path(meta["private_key_path"]).read_text()
    assert "-----BEGIN OPENSSH PRIVATE KEY-----" in pem


@pytest.mark.asyncio
async def test_ssh_key_fingerprint_match_escalates_to_critical():
    """End-to-end: plant token, submit an event with the fingerprint, see the
    severity bump + flusher mark the token as TRIGGERED."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.ssh_key import SSHKeyProvider

    # Plant
    provider = SSHKeyProvider()
    fingerprint, meta = await provider.create({"comment": "trip-wire"})
    async with get_session() as session:
        t = Honeytoken(
            type=HoneytokenType.SSH_KEY,
            label="test-ssh-key",
            token_value=fingerprint,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(t)
        await session.flush()
        token_id = t.id

    token_matchers.invalidate_cache()
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="8.8.8.8",
                event_type="ssh_login_attempt",
                payload={"fingerprint": fingerprint, "username": "deploy"},
                severity=AlertSeverity.MEDIUM,
            )
        )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())
        token = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one()

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].event_type.startswith("honeytoken_triggered_ssh_key_via_")
    assert token.status == HoneytokenStatus.TRIGGERED


# ── JWT provider ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_jwt_provider_produces_valid_jwt_structure():
    from honeypot_mcp.tokens.jwt import JWTProvider

    provider = JWTProvider()
    token_value, meta = await provider.create({"subject": "svc-billing"})

    # Three base64url segments separated by dots
    parts = token_value.split(".")
    assert len(parts) == 3

    # Header decodes to {"alg":"HS256","typ":"JWT"}
    header_b64 = parts[0]
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (-len(header_b64) % 4)))
    assert header == {"alg": "HS256", "typ": "JWT"}

    # Payload contains jti / sub / iss / exp
    payload_b64 = parts[1]
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    assert payload["jti"] == meta["jti"]
    assert payload["sub"] == "svc-billing"
    assert payload["iss"]
    assert payload["exp"] > payload["iat"]


@pytest.mark.asyncio
async def test_jwt_match_via_authorization_bearer_header():
    """HTTP event with `Authorization: Bearer <jwt>` containing the planted
    jti escalates to CRITICAL."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.jwt import JWTProvider

    provider = JWTProvider()
    jwt_value, meta = await provider.create({})
    async with get_session() as session:
        t = Honeytoken(
            type=HoneytokenType.JWT,
            label="test-jwt",
            token_value=jwt_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(t)
        await session.flush()

    token_matchers.invalidate_cache()
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="8.8.8.8",
                event_type="http_probe",
                payload={
                    "method": "GET",
                    "path": "/api/users",
                    "headers": {"Authorization": f"Bearer {jwt_value}"},
                },
                severity=AlertSeverity.LOW,
            )
        )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].event_type.startswith("honeytoken_triggered_jwt_via_")


@pytest.mark.asyncio
async def test_jwt_with_unknown_jti_does_not_match():
    """A real-looking JWT whose jti we never planted should pass through
    unchanged — no false positives on third-party tokens."""
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.tokens.jwt import JWTProvider

    provider = JWTProvider()
    foreign_jwt, _ = await provider.create({})
    # Don't insert it into the DB — it's a foreign token.
    token_matchers.invalidate_cache()

    ev = PendingEvent(
        honeypot_id=None,
        source_ip="8.8.8.8",
        event_type="http_probe",
        payload={"headers": {"Authorization": f"Bearer {foreign_jwt}"}},
        severity=AlertSeverity.LOW,
    )
    token_id, match_type = await token_matchers.match(ev)
    assert token_id is None
    assert match_type is None


# ── DB-row provider ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_db_row_provider_emits_planting_sql():
    from honeypot_mcp.tokens.db_row import DBRowProvider

    provider = DBRowProvider()
    canary_email, meta = await provider.create({"domain": "corp.example", "table": "customers"})

    assert canary_email.startswith("canary-")
    assert canary_email.endswith("@corp.example")
    assert meta["canary_email"] == canary_email
    assert meta["target_table"] == "customers"
    # Row data is plausible
    assert "@" in meta["row_data"]["email"]
    assert meta["row_data"]["first_name"]

    plant = provider.plant_instructions(canary_email, meta)
    assert "INSERT INTO customers" in plant
    assert canary_email in plant


@pytest.mark.asyncio
async def test_db_row_canary_email_in_smtp_rcpt_to_triggers():
    """SMTP RCPT TO containing the canary email pattern fires CRITICAL."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.db_row import DBRowProvider

    provider = DBRowProvider()
    canary_email, meta = await provider.create({"domain": "corp.example"})
    async with get_session() as session:
        t = Honeytoken(
            type=HoneytokenType.DB_ROW,
            label="db-row-test",
            token_value=canary_email,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(t)
        await session.flush()

    token_matchers.invalidate_cache()
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="8.8.8.8",
                event_type="smtp_rcpt_to",
                payload={"command": f"RCPT TO:<{canary_email}>"},
                severity=AlertSeverity.MEDIUM,
            )
        )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.CRITICAL
    assert alerts[0].event_type.startswith("honeytoken_triggered_db_row_via_")


# ── DOCX external-image fix ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_docx_token_injects_external_image_relationship():
    """The DOCX must contain an External-mode image relationship pointing
    at the canary URL — that's what makes Word fetch on open."""
    import zipfile

    from honeypot_mcp.tokens.file_token import FileTokenProvider

    provider = FileTokenProvider()
    _token, meta = await provider.create({"file_type": "docx"})

    from pathlib import Path

    docx_path = Path(meta["file_path"])
    assert docx_path.exists()

    with zipfile.ZipFile(docx_path, "r") as z:
        rels_xml = z.read("word/_rels/document.xml.rels").decode("utf-8")
        body_xml = z.read("word/document.xml").decode("utf-8")

    # Must contain an External-mode image relationship to the canary URL.
    assert 'TargetMode="External"' in rels_xml
    assert meta["dns_canary"] in rels_xml
    # The body must reference the same rel id via r:link (NOT r:embed).
    assert "r:link=" in body_xml
    # And the relationship type must be image (not hyperlink etc).
    assert "/relationships/image" in rels_xml
