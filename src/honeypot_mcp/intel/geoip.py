"""MaxMind GeoIP2 lookup — city geolocation, ASN, and reverse DNS."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

from honeypot_mcp.intel import _cache

log = logging.getLogger(__name__)

_CACHE_TTL = 86400  # 24h — geolocation barely changes
_PTR_TIMEOUT = 3.0  # seconds — reverse DNS can hang on missing/slow PTR zones


async def lookup_geoip(ip: str) -> dict[str, Any]:
    """Return geographic + network data for an IP.

    Combines three signals, each independently optional so the lookup degrades
    gracefully:
      * City geolocation from GeoLite2-City.mmdb (country/city/lat/long/tz).
      * Origin AS number + organisation from GeoLite2-ASN.mmdb, if present —
        the key pivot for spotting hosting/VPN/bulletproof networks.
      * Reverse DNS (PTR), if enabled — a residential-proxy or
        bulletproof-hosting hostname is a strong tell.

    Cached for 24h. Absent databases just leave their fields out rather than
    failing the whole lookup.
    """
    from honeypot_mcp.config import get_settings

    cache_key = f"geo:{ip}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    settings = get_settings()
    db_path = settings.geoip_db_path

    result: dict[str, Any]
    if db_path.exists():
        result = await _lookup_city(ip, str(db_path))
    else:
        # No city DB — still return ASN + PTR if those are available, so the
        # enrichment is useful even with only the (smaller) ASN database.
        result = {
            "available": False,
            "ip": ip,
            "note": f"GeoIP city database not found at {db_path}. "
            f"Download GeoLite2-City.mmdb from maxmind.com and place it there.",
        }

    # ── ASN enrichment (independent DB) ──────────────────────────────────────
    asn_path = settings.geoip_asn_db_path
    if asn_path.exists():
        asn_info = await _lookup_asn(ip, str(asn_path))
        if asn_info:
            result.update(asn_info)
            # If the city DB was missing, an ASN hit still makes this useful.
            result.setdefault("ip", ip)
            if asn_info.get("asn") is not None:
                result["available"] = True

    # ── Reverse DNS (PTR) ────────────────────────────────────────────────────
    if settings.geoip_reverse_dns:
        result["reverse_dns"] = await _reverse_dns(ip)

    # Only cache a result that carries real data — never cache a pure miss, so a
    # later DB install or transient DNS failure isn't pinned for 24h.
    if result.get("available") or result.get("reverse_dns"):
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
    return result


async def _lookup_city(ip: str, db_path: str) -> dict[str, Any]:
    try:
        import geoip2.database
    except ImportError:
        return {"available": False, "ip": ip, "error": "geoip2 library not installed"}

    def _lookup() -> dict[str, Any]:
        try:
            with geoip2.database.Reader(db_path) as reader:
                response = reader.city(ip)
            return {
                "available": True,
                "ip": ip,
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
            }
        except Exception as e:
            # AddressNotFoundError etc. — the DB works, the IP just isn't in it.
            return {"available": True, "ip": ip, "geo_note": str(e)}

    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _lookup)
    except Exception as e:
        log.warning("GeoIP city lookup failed for %s: %s", ip, e)
        return {"available": False, "ip": ip, "error": str(e)}


async def _lookup_asn(ip: str, db_path: str) -> dict[str, Any]:
    """Return `{asn, as_org}` from GeoLite2-ASN.mmdb, or {} on any miss."""
    try:
        import geoip2.database
    except ImportError:
        return {}

    def _lookup() -> dict[str, Any]:
        try:
            with geoip2.database.Reader(db_path) as reader:
                response = reader.asn(ip)
            return {
                "asn": response.autonomous_system_number,
                "as_org": response.autonomous_system_organization,
            }
        except Exception:
            return {}

    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _lookup)
    except Exception as e:
        log.debug("GeoIP ASN lookup failed for %s: %s", ip, e)
        return {}


async def _reverse_dns(ip: str) -> str | None:
    """Best-effort PTR lookup with a hard timeout. Returns the hostname, or
    None if there's no PTR record or the resolver is slow/unreachable."""

    def _ptr() -> str | None:
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(ip)
            return host
        except (OSError, socket.herror, socket.gaierror):
            return None

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _ptr), timeout=_PTR_TIMEOUT)
    except Exception:
        # Timeout or any resolver error — PTR is best-effort, never fatal.
        return None
