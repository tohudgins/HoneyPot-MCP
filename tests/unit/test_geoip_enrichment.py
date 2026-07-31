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
async def test_corrupted_city_db_reports_unavailable_not_success(monkeypatch, tmp_path):
    """A truncated/corrupted/wrong-format .mmdb file must NOT be reported as
    available: True — the caller caches a 'successful' result for 24h, so a
    bad database file would otherwise become a silent, self-reinforcing
    outage: every enrichment for a full day quietly returns empty geo data
    with no error surfaced anywhere. Only AddressNotFoundError (the DB opened
    fine, the IP just isn't in it) should produce available: True."""
    import geoip2.database
    import geoip2.errors

    from honeypot_mcp.intel import geoip

    class _BrokenReader:
        def __init__(self, path):
            raise OSError("Error opening database file")

    monkeypatch.setattr(geoip2.database, "Reader", _BrokenReader)

    db_path = tmp_path / "GeoLite2-City.mmdb"
    db_path.write_bytes(b"not a real mmdb file")

    result = await geoip._lookup_city("203.0.113.9", str(db_path))

    assert result["available"] is False
    assert "error" in result


@pytest.mark.asyncio
async def test_address_not_found_still_reports_available(monkeypatch, tmp_path):
    """Contrast case: a working DB that simply has no data for this IP is a
    normal outcome, not a failure — must stay available: True."""
    import geoip2.database
    import geoip2.errors

    from honeypot_mcp.intel import geoip

    class _EmptyHitReader:
        def __init__(self, path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def city(self, ip):
            raise geoip2.errors.AddressNotFoundError("The address is not in the database.")

    monkeypatch.setattr(geoip2.database, "Reader", _EmptyHitReader)

    db_path = tmp_path / "GeoLite2-City.mmdb"
    db_path.write_bytes(b"placeholder")

    result = await geoip._lookup_city("203.0.113.9", str(db_path))

    assert result["available"] is True
    assert "geo_note" in result


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
