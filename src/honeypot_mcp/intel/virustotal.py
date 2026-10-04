"""VirusTotal API v3 client — async IP reputation lookup."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.intel import _cache

log = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_CACHE_TTL = 1800  # 30 min — VT data drifts slowly

# One connection pool for every lookup (per event loop), instead of a new
# client — and a new TLS handshake — per CRITICAL alert.
_client: LoopBound[httpx.AsyncClient] = LoopBound(lambda: httpx.AsyncClient(timeout=15.0))


async def lookup_virustotal(ip: str) -> dict[str, Any]:
    """Query VirusTotal v3 for IP reputation data.

    Returns detection counts, reputation score, country, AS owner, and tags.
    Respects the free-tier 4 req/min rate limit via caller-side throttling.
    Successful responses are cached for 30 minutes per IP; errors and rate
    limits are remembered for a minute so a burst does not retry each time.
    """
    import ipaddress

    from honeypot_mcp.config import get_settings

    # Interpolated into a URL path below, so only a canonical address may pass:
    # an IPv6 zone id ("::1%../../x") would otherwise steer the authenticated
    # request to another path on the VirusTotal host. Not every caller is a tool
    # that ran `validate_ip` first (the ingest path enriches stored source IPs).
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"available": False, "note": "not a valid IP address"}
    if getattr(addr, "scope_id", None):
        return {"available": False, "note": "scoped (zone-id) addresses are not looked up"}
    ip = str(addr)

    cache_key = f"vt:{ip}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    settings = get_settings()
    api_key = settings.virustotal_api_key

    if not api_key:
        return {
            "available": False,
            "note": "VIRUSTOTAL_API_KEY not set. Add it to .env to enable VT lookups.",
        }

    failed = _cache.get_negative(cache_key)
    if failed is not None:
        return failed

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    failure: dict[str, Any]
    try:
        resp = await _client.get().get(f"{_VT_BASE}/ip_addresses/{ip}", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        last_analysis = data.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total_engines = sum(last_analysis.values())

        result = {
            "available": True,
            "ip": ip,
            "reputation": data.get("reputation", 0),
            "malicious_votes": malicious,
            "suspicious_votes": suspicious,
            "total_engines": total_engines,
            "detection_ratio": f"{malicious}/{total_engines}" if total_engines else "0/0",
            "country": data.get("country", ""),
            "as_owner": data.get("as_owner", ""),
            "asn": data.get("asn"),
            "tags": data.get("tags", []),
            "network": data.get("network", ""),
        }
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            result = {"available": True, "ip": ip, "note": "IP not found in VirusTotal database."}
            _cache.set(cache_key, result, ttl=_CACHE_TTL)
            return result
        if e.response.status_code == 429:
            failure = {"available": False, "error": "VT rate limit exceeded — wait 60 seconds."}
        else:
            log.warning("VT API error for %s: %s", ip, e)
            failure = {"available": False, "error": str(e)}
    except Exception as e:
        log.warning("VT lookup failed for %s: %s", ip, e)
        failure = {"available": False, "error": str(e)}
    _cache.set_negative(cache_key, failure)
    return failure
