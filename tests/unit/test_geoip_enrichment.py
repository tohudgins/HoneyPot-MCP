"""Tests for the GeoIP enrichment upgrade — ASN merge + reverse DNS.

These mock the MaxMind readers and the resolver so they run offline and don't
depend on the .mmdb files being present.
"""

import os
from unittest.mock import patch

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
def _clear_cache():
    from honeypot_mcp.intel import _cache

    _cache._store.clear() if hasattr(_cache, "_store") else None
    yield


@pytest.mark.asyncio
async def test_reverse_dns_merged_when_no_dbs(monkeypatch):
    """With no MaxMind DBs, a PTR hit still produces a useful result."""
    from honeypot_mcp.intel import geoip

    async def fake_ptr(ip):
        return "scan-bot.badhost.example"

    # Force both DBs to look absent, stub the resolver.
    monkeypatch.setattr(geoip, "_reverse_dns", fake_ptr)
    with patch("pathlib.Path.exists", return_value=False):
        result = await geoip.lookup_geoip("203.0.113.9")

    assert result["reverse_dns"] == "scan-bot.badhost.example"


@pytest.mark.asyncio
async def test_asn_merged_into_result(monkeypatch, tmp_path):
    """When the ASN DB is present, asn + as_org land in the result and flip
    availability true even without a city DB."""
    from honeypot_mcp.intel import geoip

    async def fake_asn(ip, path):
        return {"asn": 14061, "as_org": "DigitalOcean, LLC"}

    async def fake_ptr(ip):
        return None

    monkeypatch.setattr(geoip, "_lookup_asn", fake_asn)
    monkeypatch.setattr(geoip, "_reverse_dns", fake_ptr)

    # City DB absent, ASN DB present.
    def fake_exists(self):
        return self.name == "GeoLite2-ASN.mmdb"

    with patch("pathlib.Path.exists", fake_exists):
        result = await geoip.lookup_geoip("198.51.100.7")

    assert result["asn"] == 14061
    assert result["as_org"] == "DigitalOcean, LLC"
    assert result["available"] is True


@pytest.mark.asyncio
async def test_profile_passes_asn_through():
    """The profiler forwards the whole geoip block, so asn/reverse_dns reach
    the attacker profile without extra plumbing."""
    from honeypot_mcp.analysis.profiler import build_profile

    geoip_block = {
        "available": True,
        "ip": "1.2.3.4",
        "country": "Germany",
        "asn": 24940,
        "as_org": "Hetzner Online GmbH",
        "reverse_dns": "static.1.2.3.4.clients.your-server.de",
    }
    profile = await build_profile(
        ip="1.2.3.4",
        alerts=[],
        events=[],
        geoip=geoip_block,
        vt={"available": False},
        abuse={"available": False},
    )
    assert profile["geoip"]["asn"] == 24940
    assert profile["geoip"]["reverse_dns"].endswith("your-server.de")
