"""AbuseIPDB API v2 client — community-sourced IP abuse reports."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from honeypot_mcp.intel import _cache

log = logging.getLogger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2"
_CACHE_TTL = 900  # 15 min — abuse data updates faster than VT


async def lookup_abuseipdb(ip: str, max_age_days: int = 90) -> dict[str, Any]:
    """Query AbuseIPDB for abuse confidence score and report history.

    Free tier: 1,000 checks/day.

    Returns:
        abuseConfidenceScore (0-100), ISP, usage type, country, total reports,
        num distinct reporters, last reported timestamp, and recent report categories.
    """
    from honeypot_mcp.config import get_settings

    cache_key = f"abuse:{ip}:{max_age_days}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    api_key = get_settings().abuseipdb_api_key
    if not api_key:
        return {
            "available": False,
            "note": "ABUSEIPDB_API_KEY not set. Add it to .env — free at abuseipdb.com.",
        }

    headers = {"Key": api_key, "Accept": "application/json"}
    params: dict[str, str | int] = {
        "ipAddress": ip,
        "maxAgeInDays": max_age_days,
        "verbose": "true",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{_BASE}/check", headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})

        # Summarise the category codes from recent reports
        report_categories: dict[str, int] = {}
        for report in data.get("reports", [])[:20]:
            for cat in report.get("categories", []):
                label = _CATEGORY_NAMES.get(cat, str(cat))
                report_categories[label] = report_categories.get(label, 0) + 1

        result = {
            "available": True,
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "is_public": data.get("isPublic", True),
            "ip_version": data.get("ipVersion"),
            "is_whitelisted": data.get("isWhitelisted", False),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "domain": data.get("domain", ""),
            "hostnames": data.get("hostnames", []),
            "country_code": data.get("countryCode", ""),
            "country_name": data.get("countryName", ""),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "report_categories": report_categories,
        }
        _cache.set(cache_key, result, ttl=_CACHE_TTL)
        return result

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            return {
                "available": False,
                "error": "AbuseIPDB rate limit hit — 1,000/day on free tier.",
            }
        if e.response.status_code == 422:
            return {"available": False, "error": f"Invalid IP address: {ip}"}
        log.warning("AbuseIPDB error for %s: %s", ip, e)
        return {"available": False, "error": str(e)}
    except Exception as e:
        log.warning("AbuseIPDB lookup failed for %s: %s", ip, e)
        return {"available": False, "error": str(e)}


async def report_ip(ip: str, categories: list[int], comment: str = "") -> dict[str, Any]:
    """Submit an abuse report for an IP to AbuseIPDB.

    Common category codes:
        14 = Port Scan, 18 = Brute-Force, 20 = DDoS Attack,
        21 = FTP Brute-Force, 22 = SSH, 80 = Web App Attack.

    Args:
        ip: The attacker's IP address.
        categories: List of AbuseIPDB category codes.
        comment: Optional description of the abuse.
    """
    from honeypot_mcp.config import get_settings

    api_key = get_settings().abuseipdb_api_key
    if not api_key:
        return {"available": False, "note": "ABUSEIPDB_API_KEY not set."}

    headers = {"Key": api_key, "Accept": "application/json"}
    payload = {
        "ip": ip,
        "categories": ",".join(str(c) for c in categories),
        "comment": comment or "Detected by HoneyPot MCP honeypot system.",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{_BASE}/report", headers=headers, data=payload)
            resp.raise_for_status()
            return {"reported": True, "data": resp.json().get("data", {})}
    except Exception as e:
        log.warning("AbuseIPDB report failed for %s: %s", ip, e)
        return {"reported": False, "error": str(e)}


# AbuseIPDB category code → human-readable label
_CATEGORY_NAMES: dict[int, str] = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}
