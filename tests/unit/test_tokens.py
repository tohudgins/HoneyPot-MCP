"""Unit tests for honeytoken providers."""

import pytest
from honeypot_mcp.tokens.api_key import APIKeyProvider
from honeypot_mcp.tokens.canary_url import CanaryURLProvider
from honeypot_mcp.tokens.credential import CredentialProvider


@pytest.mark.asyncio
async def test_aws_key_format():
    provider = APIKeyProvider()
    value, meta = await provider.create({"service": "aws", "prefix": "AKIA"})
    assert meta["access_key_id"].startswith("AKIA")
    assert len(meta["access_key_id"]) == 20
    assert len(meta["secret_access_key"]) == 40


@pytest.mark.asyncio
async def test_aws_key_asia_prefix():
    provider = APIKeyProvider()
    value, meta = await provider.create({"service": "aws", "prefix": "ASIA"})
    assert meta["access_key_id"].startswith("ASIA")


@pytest.mark.asyncio
async def test_generic_api_key():
    provider = APIKeyProvider()
    value, meta = await provider.create({"service": "stripe"})
    assert value.startswith("sk-")
    assert meta["service"] == "stripe"


@pytest.mark.asyncio
async def test_canary_url_format(monkeypatch):
    from honeypot_mcp import config as cfg_module
    from honeypot_mcp.config import Settings

    mock_settings = Settings(
        canary_public_url="http://localhost:8888",
        canary_callback_host="0.0.0.0",
        canary_callback_port=8888,
    )
    monkeypatch.setattr(cfg_module, "_settings", mock_settings)

    provider = CanaryURLProvider()
    value, meta = await provider.create({})
    assert value.startswith("http://localhost:8888/t/")
    assert "token_id" in meta
    assert len(meta["token_id"]) == 36  # UUID length


@pytest.mark.asyncio
async def test_credential_generation():
    provider = CredentialProvider()
    value, meta = await provider.create({"service": "ssh", "count": 3})
    assert meta["count"] == 3
    assert len(meta["credentials"]) == 3
    for cred in meta["credentials"]:
        assert "username" in cred
        assert "password" in cred
        assert cred["service"] == "ssh"


@pytest.mark.asyncio
async def test_credential_count_cap():
    provider = CredentialProvider()
    _, meta = await provider.create({"count": 999})
    assert len(meta["credentials"]) <= 20
