"""Tests for the `/cloud-event` HMAC-signed ingest endpoint.

Covers:
* 503 when `cloud_event_hmac_secret` is unset (default).
* 401 on missing signature.
* 401 on wrong signature.
* 202 + token-triggered when an AWS CloudTrail event matches an active
  API_KEY token.
* 202 with no alert when the event's access key isn't a known token.
* 202 + token-triggered for Azure and GCP shapes.

Each test stands the canary callback server up on a free port, POSTs
events directly, then inspects DB state to confirm the right honeytokens
were marked TRIGGERED.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import socket
import uuid

import httpx
import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Reset the settings singleton so tests can override
    # cloud_event_hmac_secret via env vars.
    import honeypot_mcp.config as _cfg
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    _cfg._settings = None

    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await init_db()
    yield
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()
    _cfg._settings = None


async def _start_canary_on(port: int):
    """Spin up the canary app on a specific port for the test."""
    from aiohttp import web

    from honeypot_mcp.canary import build_app

    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner


def _reload_settings() -> None:
    """Force `get_settings()` to re-read env vars on its next call.

    Required because the autouse fixture's `init_db()` populates the
    settings singleton BEFORE the test gets a chance to monkeypatch
    `CLOUD_EVENT_HMAC_SECRET` — without this, settings.cloud_event_hmac_secret
    keeps the empty default and the endpoint returns 503.
    """
    import honeypot_mcp.config as _cfg

    _cfg._settings = None


@pytest.mark.asyncio
async def test_cloud_event_returns_503_when_secret_unset(monkeypatch):
    """Default behaviour: refuse the endpoint if the operator hasn't
    configured a shared secret. An unsigned ingest endpoint would be an
    open trigger relay."""
    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "")
    _reload_settings()
    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=b"{}",
                headers={"Content-Type": "application/json"},
            )
        assert r.status_code == 503
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_cloud_event_returns_401_on_missing_signature(monkeypatch):
    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()
    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=b'{"foo":"bar"}',
                headers={"Content-Type": "application/json"},
            )
        assert r.status_code == 401
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_cloud_event_returns_401_on_wrong_signature(monkeypatch):
    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()
    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=b'{"foo":"bar"}',
                headers={
                    "Content-Type": "application/json",
                    "X-HoneyPot-Signature": "sha256=deadbeef",
                },
            )
        assert r.status_code == 401
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_cloudtrail_event_triggers_aws_api_key_token(monkeypatch):
    """End-to-end: plant an AWS API_KEY honeytoken, POST a CloudTrail event
    with the matching `accessKeyId`, confirm the token is TRIGGERED and a
    CRITICAL alert lands."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Alert,
        AttackerEvent,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.api_key import APIKeyProvider

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()

    # Plant the token
    provider = APIKeyProvider()
    _value, meta = await provider.create({"service": "aws"})
    access_key_id = meta["access_key_id"]

    async with get_session() as session:
        hp = Honeytoken(
            type=HoneytokenType.API_KEY,
            label="planted-aws-key",
            token_value=f"{access_key_id}:{meta['secret_access_key']}",
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(hp)
        await session.flush()
        token_id = hp.id

    # Token-matchers cache was populated before we added the new token —
    # invalidate so the index reloads.
    token_matchers.invalidate_cache()

    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        event = {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "accessKeyId": access_key_id,
                "userName": "fake",
            },
            "eventTime": "2026-05-18T12:00:00Z",
            "eventSource": "s3.amazonaws.com",
            "eventName": "ListBuckets",
            "sourceIPAddress": "203.0.113.42",
        }
        body = json.dumps(event).encode()
        sig = _sign("test-secret-12345", body)

        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-HoneyPot-Signature": sig,
                },
            )
        assert r.status_code == 202
        # Wait for the buffer flusher to land the alert
        await asyncio.sleep(0.5)
    finally:
        await runner.cleanup()

    # Token should be TRIGGERED, alert + AttackerEvent should exist
    async with get_session() as session:
        token = await session.get(Honeytoken, token_id)
        assert token is not None
        assert token.status == HoneytokenStatus.TRIGGERED

        alert_result = await session.execute(
            select(Alert).where(Alert.event_type.like("honeytoken_triggered_%_via_aws"))
        )
        alerts = list(alert_result.scalars().all())
        assert len(alerts) == 1
        assert alerts[0].severity.value == "critical"
        assert alerts[0].source_ip == "203.0.113.42"
        assert alerts[0].payload["token_id"] == token_id

        ev_result = await session.execute(
            select(AttackerEvent).where(AttackerEvent.honeytoken_id == token_id)
        )
        assert len(list(ev_result.scalars().all())) == 1


@pytest.mark.asyncio
async def test_cloud_event_unknown_key_does_not_alert(monkeypatch):
    """A valid signed event for a key that doesn't match any active token
    returns 202 but creates no alert."""
    from sqlalchemy import func, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()

    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        event = {
            "userIdentity": {"accessKeyId": "AKIANOTPLANTEDKEY00000"},
            "eventName": "GetCallerIdentity",
            "sourceIPAddress": "192.0.2.1",
        }
        body = json.dumps(event).encode()
        sig = _sign("test-secret-12345", body)

        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-HoneyPot-Signature": sig,
                },
            )
        assert r.status_code == 202
        await asyncio.sleep(0.3)
    finally:
        await runner.cleanup()

    async with get_session() as session:
        count = (await session.execute(select(func.count()).select_from(Alert))).scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_azure_event_triggers_azure_credential_token(monkeypatch):
    """Plant an Azure credential token, POST a synthetic Activity Log
    event with the matching client_id, confirm CRITICAL alert."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Alert,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.azure_credential import AzureCredentialProvider

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()

    provider = AzureCredentialProvider()
    token_value, meta = await provider.create({})

    async with get_session() as session:
        hp = Honeytoken(
            type=HoneytokenType.AZURE_CREDENTIAL,
            label="planted-azure-sp",
            token_value=token_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(hp)
        await session.flush()
        token_id = hp.id

    token_matchers.invalidate_cache()

    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        event = {
            "category": "SignInLogs",
            "claims": {"appid": meta["client_id"]},
            "callerIpAddress": "198.51.100.7",
        }
        body = json.dumps(event).encode()
        sig = _sign("test-secret-12345", body)

        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-HoneyPot-Signature": sig,
                },
            )
        assert r.status_code == 202
        await asyncio.sleep(0.5)
    finally:
        await runner.cleanup()

    async with get_session() as session:
        token = await session.get(Honeytoken, token_id)
        assert token.status == HoneytokenStatus.TRIGGERED
        alerts = list(
            (
                await session.execute(
                    select(Alert).where(Alert.event_type.like("honeytoken_triggered_%_via_azure"))
                )
            )
            .scalars()
            .all()
        )
    assert len(alerts) == 1
    assert alerts[0].severity.value == "critical"
    assert alerts[0].source_ip == "198.51.100.7"


@pytest.mark.asyncio
async def test_gcp_event_triggers_service_account_token(monkeypatch):
    """Plant a GCP service-account token, POST a synthetic audit log with
    matching principalEmail, confirm CRITICAL alert."""
    from sqlalchemy import select

    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Alert,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tokens.gcp_service_account import GCPServiceAccountProvider

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "test-secret-12345")
    _reload_settings()

    provider = GCPServiceAccountProvider()
    token_value, meta = await provider.create({})

    async with get_session() as session:
        hp = Honeytoken(
            type=HoneytokenType.GCP_SERVICE_ACCOUNT,
            label="planted-gcp-sa",
            token_value=token_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(hp)
        await session.flush()
        token_id = hp.id

    token_matchers.invalidate_cache()

    port = _free_port()
    runner = await _start_canary_on(port)
    try:
        event = {
            "protoPayload": {
                "authenticationInfo": {"principalEmail": meta["client_email"]},
            },
            "requestMetadata": {"callerIp": "203.0.113.99"},
        }
        body = json.dumps(event).encode()
        sig = _sign("test-secret-12345", body)

        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"http://127.0.0.1:{port}/cloud-event",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-HoneyPot-Signature": sig,
                },
            )
        assert r.status_code == 202
        await asyncio.sleep(0.5)
    finally:
        await runner.cleanup()

    async with get_session() as session:
        token = await session.get(Honeytoken, token_id)
        assert token.status == HoneytokenStatus.TRIGGERED
        alerts = list(
            (
                await session.execute(
                    select(Alert).where(Alert.event_type.like("honeytoken_triggered_%_via_gcp"))
                )
            )
            .scalars()
            .all()
        )
    assert len(alerts) == 1
    assert alerts[0].severity.value == "critical"
    assert alerts[0].source_ip == "203.0.113.99"


# Avoid lint complaints about unused imports
_ = uuid
