"""Shodan InternetDB — open ports, CVEs and hostnames Shodan last saw on an address. No API key.

Contract (https://internetdb.shodan.io/docs, openapi.json):
  GET https://internetdb.shodan.io/{ip}
  200 {"ip", "ports": [int], "cpes": [str], "hostnames": [str], "tags": [str], "vulns": [str]}
  404 {"detail": "No information available"}   -> an answer: Shodan has nothing on this address
  422 validation error (not an IP) · 429 rate limit

Updated by Shodan about weekly. Free for NON-COMMERCIAL use only (their FAQ), so it is opt-in:
`SHODAN_INTERNETDB_ENABLED=true`.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.intel import _cache
from honeypot_mcp.intel._common import canonical_ip, clean_list, failure, new_client

log = logging.getLogger(__name__)

_BASE = "https://internetdb.shodan.io"
_CACHE_TTL = 6 * 3600  # the dataset itself is refreshed about weekly

_client: LoopBound[httpx.AsyncClient] = LoopBound(new_client)

_MAX_PORTS = 50
_MAX_VULNS = 25
_MAX_NAMES = 10


def configured() -> bool:
    from honeypot_mcp.config import get_settings

    return bool(get_settings().shodan_internetdb_enabled)


async def lookup_internetdb(ip: str) -> dict[str, Any]:
    """Ports, vulnerabilities and hostnames Shodan InternetDB holds for `ip`."""
    if not configured():
        return {
            "available": False,
            "note": (
                "Shodan InternetDB is not enabled. Set SHODAN_INTERNETDB_ENABLED=true in .env "
                "(no key needed; free for non-commercial use only)."
            ),
        }
    canonical, bad = canonical_ip(ip)
    if canonical is None:
        return bad or {"available": False, "note": "not a valid IP address"}
    ip = canonical

    cache_key = f"internetdb:{ip}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    if (failed := _cache.get_negative(cache_key)) is not None:
        return failed

    try:
        resp = await _client.get().get(f"{_BASE}/{ip}", headers={"Accept": "application/json"})
        if resp.status_code == 404:
            result: dict[str, Any] = {
                "available": True,
                "ip": ip,
                "known": False,
                "ports": [],
                "vulns": [],
                "hostnames": [],
                "tags": [],
                "cpes": [],
                "note": "Shodan InternetDB has no information on this IP.",
            }
            _cache.set(cache_key, result, ttl=_CACHE_TTL)
            return result
        resp.raise_for_status()
        data = resp.json()
        ports = [p for p in data.get("ports", []) if isinstance(p, int) and not isinstance(p, bool)]
        result = {
            "available": True,
            "ip": ip,
            "known": True,
            "ports": sorted(ports)[:_MAX_PORTS],
            "vulns": clean_list(data.get("vulns"), limit=_MAX_VULNS, item_limit=24),
            "hostnames": clean_list(data.get("hostnames"), limit=_MAX_NAMES, item_limit=100),
            "tags": clean_list(data.get("tags"), limit=_MAX_NAMES, item_limit=32),
            "cpes": clean_list(data.get("cpes"), limit=_MAX_NAMES, item_limit=80),
        }
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result
    except Exception as e:  # noqa: BLE001 - a reputation source must never break its caller
        out = failure("Shodan InternetDB", e)
        if not isinstance(e, httpx.TimeoutException):
            log.warning("InternetDB lookup failed for %s: %s", ip, out["error"])
        _cache.set_negative(cache_key, out)
        return out
