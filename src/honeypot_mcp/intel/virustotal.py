"""VirusTotal API v3 client — async IP reputation lookup."""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"


async def lookup_virustotal(ip: str) -> dict[str, Any]:
    """Query VirusTotal v3 for IP reputation data.

    Returns detection counts, reputation score, country, AS owner, and tags.
    Respects the free-tier 4 req/min rate limit via caller-side throttling.
    """
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    api_key = settings.virustotal_api_key

    if not api_key:
        return {
            "available": False,
            "note": "VIRUSTOTAL_API_KEY not set. Add it to .env to enable VT lookups.",
        }

    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_VT_BASE}/ip_addresses/{ip}", headers=headers)
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})

        last_analysis = data.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total_engines = sum(last_analysis.values())

        return {
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

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return {"available": True, "ip": ip, "note": "IP not found in VirusTotal database."}
        if e.response.status_code == 429:
            return {"available": False, "error": "VT rate limit exceeded — wait 60 seconds."}
        log.warning("VT API error for %s: %s", ip, e)
        return {"available": False, "error": str(e)}
    except Exception as e:
        log.warning("VT lookup failed for %s: %s", ip, e)
        return {"available": False, "error": str(e)}
