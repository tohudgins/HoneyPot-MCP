"""MaxMind GeoIP2 lookup — city geolocation, ASN, and reverse DNS."""

from __future__ import annotations

import asyncio
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from honeypot_mcp.intel import _cache

log = logging.getLogger(__name__)

_CACHE_TTL = 86400  # 24h — geolocation barely changes
_PTR_TIMEOUT = 3.0  # seconds — reverse DNS can hang on missing/slow PTR zones
# PTR lookups block a thread for as long as the resolver takes (often far past
# `_PTR_TIMEOUT`: the wait is abandoned, the thread is not). They run in their
# own small pool so a flood of unresolvable IPs cannot starve the default
# executor that the database and everything else share; once that many are in
# flight, further PTRs are skipped rather than queued.
_PTR_WORKERS = 4
_PTR_MAX_IN_FLIGHT = 2 * _PTR_WORKERS
_PTR_MISS_TTL = 300
_ptr_executor = ThreadPoolExecutor(max_workers=_PTR_WORKERS, thread_name_prefix="ptr-lookup")
_ptr_in_flight = 0


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
        import geoip2.errors
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
        except geoip2.errors.AddressNotFoundError as e:
            # The DB opened and works, the IP just isn't in it — a normal
            # outcome, not a failure.
            return {"available": True, "ip": ip, "geo_note": str(e)}
        # Anything else (corrupted/truncated file, wrong format, permission
        # error) must NOT be reported as available: True — the caller caches
        # a successful-looking result for 24h, which would turn one bad
        # database file into a silent, self-reinforcing outage: every
        # enrichment for a full day quietly returns empty geo data with no
        # error surfaced anywhere. Let it propagate to the outer handler.

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
    None if there's no PTR record or the resolver is slow/unreachable. Misses
    are remembered for `_PTR_MISS_TTL` so an IP without a PTR record is not
    re-resolved on every alert."""
    global _ptr_in_flight
    miss_key = f"ptr:{ip}"
    if _cache.get_negative(miss_key) is not None:
        return None
    if _ptr_in_flight >= _PTR_MAX_IN_FLIGHT:
        return None

    def _ptr() -> str | None:
        try:
            host, _aliases, _addrs = socket.gethostbyaddr(ip)
            return host
        except (OSError, socket.herror, socket.gaierror):
            return None

    def _release(_fut: object) -> None:
        global _ptr_in_flight
        _ptr_in_flight -= 1

    loop = asyncio.get_running_loop()
    _ptr_in_flight += 1
    future = loop.run_in_executor(_ptr_executor, _ptr)
    future.add_done_callback(_release)
    try:
        host = await asyncio.wait_for(asyncio.shield(future), timeout=_PTR_TIMEOUT)
    except Exception:
        # Timeout or any resolver error — PTR is best-effort, never fatal.
        host = None
    if host is None:
        _cache.set_negative(miss_key, {"available": False}, ttl=_PTR_MISS_TTL)
    return host
