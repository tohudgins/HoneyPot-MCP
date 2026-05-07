"""Tests for the intel TTL cache.

Verifies: cached values are returned without invoking the underlying lookup;
expired entries trigger a fresh lookup; failed lookups (`available: False`)
are NOT cached so callers always retry.
"""

from unittest.mock import patch

import httpx
import pytest

from honeypot_mcp.intel import _cache


@pytest.fixture(autouse=True)
def clear_cache():
    _cache.clear()
    yield
    _cache.clear()


def test_cache_get_miss_returns_none():
    assert _cache.get("nope") is None


def test_cache_set_and_get():
    _cache.set("k", {"available": True, "v": 1})
    assert _cache.get("k") == {"available": True, "v": 1}


def test_cache_expiry():
    _cache.set("k", {"available": True}, ttl=0)
    # ttl=0 → entry expires immediately
    assert _cache.get("k") is None


@pytest.mark.asyncio
async def test_virustotal_cache_hit_skips_network():
    """Two calls with same IP and a cached successful result → only one network attempt."""
    from honeypot_mcp.intel import virustotal

    # Seed the cache with a successful result.
    _cache.set("vt:1.2.3.4", {"available": True, "ip": "1.2.3.4", "reputation": -10})

    with patch("honeypot_mcp.intel.virustotal.httpx.AsyncClient") as mock_client:
        result = await virustotal.lookup_virustotal("1.2.3.4")

    assert result["available"] is True
    assert result["reputation"] == -10
    mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_failed_lookup_not_cached():
    """When the API key is missing, `available: False` is returned but must NOT be
    cached — otherwise the user adding a key later wouldn't take effect."""
    from honeypot_mcp.intel import virustotal

    with patch("honeypot_mcp.config.get_settings") as mock_settings:
        mock_settings.return_value.virustotal_api_key = ""
        result = await virustotal.lookup_virustotal("8.8.8.8")
    assert result["available"] is False
    assert _cache.get("vt:8.8.8.8") is None
