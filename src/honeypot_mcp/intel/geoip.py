"""MaxMind GeoIP2 lookup."""

from __future__ import annotations

import logging
from typing import Any

from honeypot_mcp.intel import _cache

log = logging.getLogger(__name__)

_CACHE_TTL = 86400  # 24h — geolocation barely changes


async def lookup_geoip(ip: str) -> dict[str, Any]:
    """Return geographic data for an IP using the local MaxMind mmdb file.
    Cached for 24h — IPs almost never relocate."""
    from honeypot_mcp.config import get_settings

    cache_key = f"geo:{ip}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    settings = get_settings()
    db_path = settings.geoip_db_path

    if not db_path.exists():
        return {
            "available": False,
            "note": f"GeoIP database not found at {db_path}. "
                    f"Download GeoLite2-City.mmdb from maxmind.com and place it there.",
        }

    try:
        import geoip2.database
        import asyncio

        loop = asyncio.get_event_loop()

        def _lookup() -> dict:
            with geoip2.database.Reader(str(db_path)) as reader:
                try:
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
                        "asn": None,  # Requires separate ASN db
                    }
                except Exception as e:
                    return {"available": True, "ip": ip, "error": str(e)}

        result = await loop.run_in_executor(None, _lookup)
        if result.get("available") and "error" not in result:
            _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result

    except ImportError:
        return {"available": False, "error": "geoip2 library not installed"}
    except Exception as e:
        log.warning("GeoIP lookup failed for %s: %s", ip, e)
        return {"available": False, "error": str(e)}
