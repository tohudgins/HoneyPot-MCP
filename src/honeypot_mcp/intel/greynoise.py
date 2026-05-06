"""GreyNoise Community API client — internet scanner classification."""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)

_COMMUNITY_BASE = "https://api.greynoise.io/v3/community"


async def lookup_greynoise(ip: str) -> dict[str, Any]:
    """Query the GreyNoise Community API to classify an IP.

    Free community tier — no request limit published, key required.
    Register at greynoise.io for a free community API key.

    Returns:
        noise: True if IP is known internet background noise (mass scanner/bot).
        riot: True if IP belongs to a known benign service (Google, Cloudflare, etc.).
        name: Scanner/org name when identified.
        classification: 'malicious', 'benign', or 'unknown'.
        last_seen: ISO date when last observed.

    Why this matters for honeypots:
        noise=True  → mass automated scanner, low priority, add to blocklist.
        noise=False → potentially targeted attacker, HIGH priority investigation.
        riot=True   → legitimate service (false positive), can be ignored.
    """
    from honeypot_mcp.config import get_settings

    api_key = get_settings().greynoise_api_key
    if not api_key:
        return {
            "available": False,
            "note": "GREYNOISE_API_KEY not set. Free key at greynoise.io.",
        }

    headers = {"key": api_key, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_COMMUNITY_BASE}/{ip}", headers=headers)

            if resp.status_code == 404:
                return {
                    "available": True,
                    "ip": ip,
                    "noise": False,
                    "riot": False,
                    "classification": "unknown",
                    "name": "",
                    "last_seen": None,
                    "note": "IP not observed in GreyNoise dataset.",
                }

            resp.raise_for_status()
            data = resp.json()

        noise = data.get("noise", False)
        riot = data.get("riot", False)

        # Derive a simple priority label for the analyst
        if riot:
            priority = "benign_service"
        elif noise:
            priority = "mass_scanner"
        else:
            priority = "targeted_or_unknown"

        return {
            "available": True,
            "ip": ip,
            "noise": noise,
            "riot": riot,
            "classification": data.get("classification", "unknown"),
            "name": data.get("name", ""),
            "link": data.get("link", ""),
            "last_seen": data.get("last_seen"),
            "message": data.get("message", ""),
            "analyst_priority": priority,
            "analyst_note": _priority_note(noise, riot),
        }

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            return {"available": False, "error": "GreyNoise rate limit exceeded."}
        if e.response.status_code == 401:
            return {"available": False, "error": "Invalid GreyNoise API key."}
        log.warning("GreyNoise error for %s: %s", ip, e)
        return {"available": False, "error": str(e)}
    except Exception as e:
        log.warning("GreyNoise lookup failed for %s: %s", ip, e)
        return {"available": False, "error": str(e)}


def _priority_note(noise: bool, riot: bool) -> str:
    if riot:
        return "Known benign service — likely a false positive. Safe to ignore."
    if noise:
        return "Mass internet scanner — automated bot/worm. Low priority; add to blocklist."
    return "Not in GreyNoise mass-scanner dataset — potentially targeted. Investigate further."
