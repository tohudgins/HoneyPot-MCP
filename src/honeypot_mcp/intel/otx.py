"""AlienVault OTX (LevelBlue) — the community threat "pulses" an address appears in.

Contract (https://otx.alienvault.com/assets/static/external_api.html; auth header per the official
OTX Python SDK):
  GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general     (IPv6: .../IPv6/...)
  header `X-OTX-API-KEY: <key>`
  200 {"indicator", "type", "reputation", "asn", "country_name", "pulse_info":
       {"count": N, "pulses": [{"id", "name", "tags", "TLP", ...}], ...}, ...}
  403 invalid key · 404 indicator unknown to OTX · 429 rate limit

Pulse names are written by arbitrary OTX users, so they are cleaned and clipped like every other
vendor string (see `_common.clean`).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.intel import _cache
from honeypot_mcp.intel._common import (
    as_int,
    canonical_ip,
    clean,
    failure,
    new_client,
    not_configured,
)

log = logging.getLogger(__name__)

_BASE = "https://otx.alienvault.com/api/v1/indicators"
_CACHE_TTL = 3600
_MAX_PULSES = 5

_client: LoopBound[httpx.AsyncClient] = LoopBound(new_client)


def configured() -> bool:
    from honeypot_mcp.config import get_settings

    return bool(get_settings().otx_api_key)


async def lookup_otx(ip: str) -> dict[str, Any]:
    """How many OTX pulses mention `ip`, and the titles of the first few."""
    import ipaddress

    from honeypot_mcp.config import get_settings

    api_key = get_settings().otx_api_key
    if not api_key:
        return not_configured("AlienVault OTX", "OTX_API_KEY")
    canonical, bad = canonical_ip(ip)
    if canonical is None:
        return bad or {"available": False, "note": "not a valid IP address"}
    ip = canonical
    kind = "IPv4" if ipaddress.ip_address(ip).version == 4 else "IPv6"

    cache_key = f"otx:{ip}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    if (failed := _cache.get_negative(cache_key)) is not None:
        return failed

    try:
        resp = await _client.get().get(
            f"{_BASE}/{kind}/{ip}/general",
            headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
        )
        if resp.status_code == 404:
            result: dict[str, Any] = {
                "available": True,
                "ip": ip,
                "pulse_count": 0,
                "pulses": [],
                "note": "OTX has no record of this IP.",
            }
            _cache.set(cache_key, result, ttl=_CACHE_TTL)
            return result
        resp.raise_for_status()
        data = resp.json()
        info = data.get("pulse_info") or {}
        pulses = [
            {"name": clean(p.get("name"), 100), "tlp": clean(p.get("TLP"), 12)}
            for p in (info.get("pulses") or [])[:_MAX_PULSES]
            if isinstance(p, dict) and p.get("name")
        ]
        result = {
            "available": True,
            "ip": ip,
            "pulse_count": as_int(info.get("count")),
            "pulses": pulses,
            "reputation": as_int(data.get("reputation")),
            "asn": clean(data.get("asn"), 80),
            "country": clean(data.get("country_name"), 60),
        }
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result
    except Exception as e:  # noqa: BLE001 - a reputation source must never break its caller
        out = failure("AlienVault OTX", e)
        if not isinstance(e, httpx.TimeoutException):
            log.warning("OTX lookup failed for %s: %s", ip, out["error"])
        _cache.set_negative(cache_key, out)
        return out
