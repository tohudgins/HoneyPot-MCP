"""GreyNoise Community API (v3) — is this address a known internet-wide scanner or benign crawler?

Contract (https://docs.greynoise.io/reference/getcommunityip):
  GET https://api.greynoise.io/v3/community/{ip}      header `key: <API key>`
  200 {"ip", "noise": bool, "riot": bool, "classification": "benign|malicious|unknown",
       "name", "link", "last_seen", "message"}
  404 {"ip", "noise": false, "riot": false, "message": "IP not observed scanning the internet or
       contained in RIOT data set."}                  -> an answer: GreyNoise has never seen it
  400 not a routable IPv4 address · 429 rate limit · 5xx

`noise` = seen mass-scanning in the last 90 days; `riot` = a known benign service (CDN, search
crawler, DNS resolver). The community API covers IPv4 only, so IPv6 is not looked up.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

import httpx

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.intel import _cache
from honeypot_mcp.intel._common import clean, failure, new_client, not_configured

log = logging.getLogger(__name__)

_BASE = "https://api.greynoise.io/v3/community"
_CACHE_TTL = 3600  # classification drifts over days; the community tier is rate limited

_client: LoopBound[httpx.AsyncClient] = LoopBound(new_client)


def configured() -> bool:
    from honeypot_mcp.config import get_settings

    return bool(get_settings().greynoise_api_key)


async def lookup_greynoise(ip: str) -> dict[str, Any]:
    """Classify `ip` against GreyNoise's scanner/benign datasets (community tier)."""
    from honeypot_mcp.config import get_settings

    api_key = get_settings().greynoise_api_key
    if not api_key:
        return not_configured("GreyNoise", "GREYNOISE_API_KEY")

    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return {"available": False, "note": "not a valid IP address"}
    if addr.version != 4:
        return {"available": False, "note": "the GreyNoise community API covers IPv4 only"}
    ip = str(addr)

    cache_key = f"greynoise:{ip}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    if (failed := _cache.get_negative(cache_key)) is not None:
        return failed

    try:
        resp = await _client.get().get(
            f"{_BASE}/{ip}", headers={"key": api_key, "Accept": "application/json"}
        )
        if resp.status_code == 404:
            result: dict[str, Any] = {
                "available": True,
                "ip": ip,
                "seen": False,
                "noise": False,
                "riot": False,
                "classification": None,
                "note": "GreyNoise has not observed this IP scanning the internet.",
            }
            _cache.set(cache_key, result, ttl=_CACHE_TTL)
            return result
        resp.raise_for_status()
        data = resp.json()
        noise, riot = bool(data.get("noise")), bool(data.get("riot"))
        result = {
            "available": True,
            "ip": ip,
            "seen": noise or riot,
            "noise": noise,
            "riot": riot,
            "classification": clean(data.get("classification"), 20) or None,
            "name": clean(data.get("name"), 80),
            "last_seen": clean(data.get("last_seen"), 32),
            "link": clean(data.get("link"), 200),
        }
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result
    except Exception as e:  # noqa: BLE001 - a reputation source must never break its caller
        out = failure("GreyNoise", e)
        if not isinstance(e, httpx.TimeoutException):
            log.warning("GreyNoise lookup failed for %s: %s", ip, out["error"])
        _cache.set_negative(cache_key, out)
        return out
