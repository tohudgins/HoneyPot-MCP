"""abuse.ch — MalwareBazaar (file hash), URLhaus (URL / host) and ThreatFox (IOC) lookups.

One free `Auth-Key` (https://auth.abuse.ch/) covers all three; every request carries it in the
`Auth-Key` header. Contracts, from the published API documents:

MalwareBazaar  https://bazaar.abuse.ch/api/
  POST https://mb-api.abuse.ch/api/v1/   form `query=get_info&hash=<sha256|md5|sha1>`
  200 {"query_status": "ok", "data": [{"sha256_hash", "md5_hash", "sha1_hash", "first_seen",
       "last_seen", "file_name", "file_size", "file_type", "signature", "tags", "delivery_method",
       ...}]}   |   {"query_status": "hash_not_found"} | "illegal_hash" | "no_hash_provided" |
       "no_api_key" | "user_blacklisted"        (the HTTP status is 200 for all of these)

URLhaus  https://urlhaus-api.abuse.ch/
  POST https://urlhaus-api.abuse.ch/v1/host/  form `host=<ip|domain>`
  200 {"query_status": "ok", "host", "firstseen", "url_count": "120", "blacklists":
       {"spamhaus_dbl", "surbl"}, "urls": [{"url", "url_status", "threat", "tags", ...}]}
       | {"query_status": "no_results"} | "invalid_host"
  POST https://urlhaus-api.abuse.ch/v1/url/   form `url=<url>`
  200 {"query_status": "ok", "url", "url_status", "threat", "date_added", "tags",
       "payloads": [{"response_sha256", "signature", "file_type", ...}]}
       | {"query_status": "no_results"} | "invalid_url"

ThreatFox  https://threatfox.abuse.ch/api/
  POST https://threatfox-api.abuse.ch/api/v1/   JSON {"query": "search_ioc",
       "search_term": "<ioc>", "exact_match": bool}
  200 {"query_status": "ok", "data": [{"ioc", "ioc_type", "threat_type", "malware_printable",
       "confidence_level", "first_seen", "last_seen", "tags", ...}]}
       | {"query_status": "no_result", "data": "<message>"} (no match)

The wildcard ThreatFox search is substring-based and ThreatFox stores network IOCs as
`ip:port`, so an IP lookup filters the result down to entries that are that address.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import httpx

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import get_settings
from honeypot_mcp.intel import _cache
from honeypot_mcp.intel._common import (
    as_int,
    canonical_ip,
    clean,
    clean_list,
    failure,
    new_client,
    not_configured,
)

log = logging.getLogger(__name__)

_MB_URL = "https://mb-api.abuse.ch/api/v1/"
# MalwareBazaar is slow for a known hash (7-8 s). Only the explicit `lookup_hash` tool calls it, never
# the notification fan-out, so it uses `intel_lookup_timeout_seconds` instead of the 3 s provider budget.
_URLHAUS_BASE = "https://urlhaus-api.abuse.ch/v1"
_THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

_CACHE_TTL = 1800
_HASH_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_MAX_URL_CHARS = 2048

_NOT_FOUND = frozenset({"hash_not_found", "no_results", "no_result"})
_AUTH_STATUSES = frozenset(
    {"no_api_key", "user_blacklisted", "unauthorized", "invalid_api_key", "auth_key_required"}
)

_client: LoopBound[httpx.AsyncClient] = LoopBound(new_client)


def configured() -> bool:

    return bool(get_settings().abusech_auth_key)


def _key() -> str:

    return get_settings().abusech_auth_key


def _bad_status(provider: str, status: str) -> dict[str, Any]:
    if status in _AUTH_STATUSES:
        return {
            "available": False,
            "error": f"{provider} rejected the Auth-Key ({clean(status, 40)}); check ABUSECH_AUTH_KEY.",
        }
    return {"available": False, "error": f"{provider} answered {clean(status, 40)}."}


async def _post(
    cache_key: str,
    provider: str,
    url: str,
    *,
    form: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """`(json, None)` on an HTTP-level success or `(None, failure result)`. Honours and writes the
    negative cache; the success cache is written by the caller once it has shaped the result."""
    if (failed := _cache.get_negative(cache_key)) is not None:
        return None, failed
    headers = {"Auth-Key": _key(), "Accept": "application/json"}
    try:
        wait = timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT
        resp = await _client.get().post(url, headers=headers, data=form, json=body, timeout=wait)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise ValueError("unexpected response shape")
        return data, None
    except Exception as e:  # noqa: BLE001 - a reputation source must never break its caller
        out = failure(provider, e)
        if isinstance(e, httpx.TimeoutException):
            if timeout is not None:
                out["error"] = f"{provider} timed out after {timeout:g}s."
        else:
            log.warning("%s lookup failed: %s", provider, out["error"])
        _cache.set_negative(cache_key, out)
        return None, out


def _finish(cache_key: str, result: dict[str, Any]) -> dict[str, Any]:
    _cache.set(cache_key, result, ttl=_CACHE_TTL)
    return result


async def lookup_malwarebazaar(file_hash: str) -> dict[str, Any]:
    """What MalwareBazaar knows about a SHA-256 (or MD5 / SHA-1) file hash."""
    if not _key():
        return not_configured("abuse.ch MalwareBazaar", "ABUSECH_AUTH_KEY")
    file_hash = str(file_hash).strip().lower()
    if not _HASH_RE.match(file_hash):
        return {"available": False, "note": "not a valid MD5, SHA-1 or SHA-256 hex digest"}

    cache_key = f"abusech:mb:{file_hash}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached

    data, bad = await _post(
        cache_key,
        "MalwareBazaar",
        _MB_URL,
        form={"query": "get_info", "hash": file_hash},
        timeout=get_settings().intel_lookup_timeout_seconds,
    )
    if data is None:
        return bad or {"available": False, "error": "MalwareBazaar lookup failed"}

    status = str(data.get("query_status", ""))
    if status in _NOT_FOUND:
        return _finish(
            cache_key,
            {
                "available": True,
                "hash": file_hash,
                "known": False,
                "note": "MalwareBazaar has no sample with this hash.",
            },
        )
    rows = data.get("data")
    if status != "ok" or not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        out = _bad_status("MalwareBazaar", status or "an unexpected response")
        _cache.set_negative(cache_key, out)
        return out
    row = rows[0]
    sha256 = clean(row.get("sha256_hash"), 64)
    return _finish(
        cache_key,
        {
            "available": True,
            "hash": file_hash,
            "known": True,
            "sha256": sha256,
            "md5": clean(row.get("md5_hash"), 32),
            "sha1": clean(row.get("sha1_hash"), 40),
            "signature": clean(row.get("signature"), 80) or None,
            "file_name": clean(row.get("file_name"), 120),
            "file_type": clean(row.get("file_type"), 32),
            "file_size": as_int(row.get("file_size")),
            "first_seen": clean(row.get("first_seen"), 32),
            "last_seen": clean(row.get("last_seen"), 32),
            "delivery_method": clean(row.get("delivery_method"), 32) or None,
            "tags": clean_list(row.get("tags"), limit=10, item_limit=32),
            "link": f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "",
        },
    )


async def lookup_urlhaus_host(host: str) -> dict[str, Any]:
    """URLhaus's record of malware URLs served from an IP address or domain."""
    if not _key():
        return not_configured("abuse.ch URLhaus", "ABUSECH_AUTH_KEY")
    host = str(host).strip().lower()
    if not _HOST_RE.match(host):
        return {"available": False, "note": "not a valid IP address or hostname"}

    cache_key = f"abusech:uh:host:{host}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    data, bad = await _post(cache_key, "URLhaus", f"{_URLHAUS_BASE}/host/", form={"host": host})
    if data is None:
        return bad or {"available": False, "error": "URLhaus lookup failed"}

    status = str(data.get("query_status", ""))
    if status in _NOT_FOUND:
        return _finish(
            cache_key,
            {"available": True, "host": host, "listed": False, "url_count": 0, "tags": []},
        )
    if status != "ok":
        out = _bad_status("URLhaus", status or "an unexpected response")
        _cache.set_negative(cache_key, out)
        return out

    urls = [u for u in (data.get("urls") or []) if isinstance(u, dict)]
    tags: dict[str, int] = {}
    for entry in urls:
        for tag in clean_list(entry.get("tags"), limit=10, item_limit=32):
            tags[tag] = tags.get(tag, 0) + 1
    raw_lists = data.get("blacklists")
    blacklists: dict[str, Any] = raw_lists if isinstance(raw_lists, dict) else {}
    return _finish(
        cache_key,
        {
            "available": True,
            "host": host,
            "listed": True,
            "url_count": as_int(data.get("url_count"), len(urls)),
            "online_urls": sum(1 for u in urls if u.get("url_status") == "online"),
            "first_seen": clean(data.get("firstseen"), 32),
            "tags": [t for t, _n in sorted(tags.items(), key=lambda kv: -kv[1])[:8]],
            "blacklists": {k: clean(v, 32) for k, v in list(blacklists.items())[:4]},
            "link": clean(data.get("urlhaus_reference"), 200),
        },
    )


async def lookup_urlhaus_url(url: str) -> dict[str, Any]:
    """URLhaus's record of one specific URL (status, threat, the payloads it served)."""
    if not _key():
        return not_configured("abuse.ch URLhaus", "ABUSECH_AUTH_KEY")
    url = str(url).strip()
    if not url or len(url) > _MAX_URL_CHARS:
        return {"available": False, "note": "not a usable URL"}

    cache_key = f"abusech:uh:url:{url}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    data, bad = await _post(cache_key, "URLhaus", f"{_URLHAUS_BASE}/url/", form={"url": url})
    if data is None:
        return bad or {"available": False, "error": "URLhaus lookup failed"}

    status = str(data.get("query_status", ""))
    if status in _NOT_FOUND:
        return _finish(cache_key, {"available": True, "url": url, "listed": False})
    if status != "ok":
        out = _bad_status("URLhaus", status or "an unexpected response")
        _cache.set_negative(cache_key, out)
        return out
    payloads = [
        {
            "sha256": clean(p.get("response_sha256"), 64),
            "signature": clean(p.get("signature"), 80) or None,
            "file_type": clean(p.get("file_type"), 32),
        }
        for p in (data.get("payloads") or [])[:5]
        if isinstance(p, dict)
    ]
    return _finish(
        cache_key,
        {
            "available": True,
            "url": url,
            "listed": True,
            "url_status": clean(data.get("url_status"), 16),
            "threat": clean(data.get("threat"), 40),
            "date_added": clean(data.get("date_added"), 32),
            "tags": clean_list(data.get("tags"), limit=10, item_limit=32),
            "payloads": payloads,
            "link": clean(data.get("urlhaus_reference"), 200),
        },
    )


async def lookup_threatfox(
    ioc: str, *, exact: bool = True, address_only: bool = False
) -> dict[str, Any]:
    """ThreatFox entries for an indicator (IP, `ip:port`, domain, URL or hash).

    `exact=False` is the vendor's wildcard (substring) search. `address_only=True` then keeps
    only entries that ARE the searched address (bare, or as `address:port`): a substring search
    for `1.2.3.4` also returns `11.2.3.45:80`, and ThreatFox stores network IOCs as `ip:port`, so
    an exact search would miss the common case.
    """
    if not _key():
        return not_configured("abuse.ch ThreatFox", "ABUSECH_AUTH_KEY")
    ioc = str(ioc).strip()
    if not ioc or len(ioc) > _MAX_URL_CHARS:
        return {"available": False, "note": "not a usable indicator"}

    cache_key = f"abusech:tf:{int(exact)}:{int(address_only)}:{ioc}"
    if (cached := _cache.get(cache_key)) is not None:
        return cached
    data, bad = await _post(
        cache_key,
        "ThreatFox",
        _THREATFOX_URL,
        body={"query": "search_ioc", "search_term": ioc, "exact_match": exact},
    )
    if data is None:
        return bad or {"available": False, "error": "ThreatFox lookup failed"}

    status = str(data.get("query_status", ""))
    if status in _NOT_FOUND:
        return _finish(
            cache_key, {"available": True, "ioc": ioc, "listed": False, "match_count": 0}
        )
    rows = data.get("data")
    if status != "ok" or not isinstance(rows, list):
        out = _bad_status("ThreatFox", status or "an unexpected response")
        _cache.set_negative(cache_key, out)
        return out
    matches = [r for r in rows if isinstance(r, dict)]
    if address_only:
        matches = [
            r
            for r in matches
            if (value := str(r.get("ioc", ""))) == ioc or value.startswith(f"{ioc}:")
        ]
    return _finish(cache_key, _threatfox_summary(ioc, matches))


def _threatfox_summary(ioc: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    families: dict[str, int] = {}
    threat_types: set[str] = set()
    for row in rows:
        family = clean(row.get("malware_printable") or row.get("malware"), 60)
        if family:
            families[family] = families.get(family, 0) + 1
        if row.get("threat_type"):
            threat_types.add(clean(row["threat_type"], 40))
    first_seen = sorted(clean(r.get("first_seen"), 32) for r in rows if r.get("first_seen"))
    return {
        "available": True,
        "ioc": ioc,
        "listed": bool(rows),
        "match_count": len(rows),
        "malware": [f for f, _n in sorted(families.items(), key=lambda kv: -kv[1])[:5]],
        "threat_types": sorted(threat_types)[:5],
        "confidence_max": max((as_int(r.get("confidence_level")) for r in rows), default=0),
        "first_seen": first_seen[0] if first_seen else "",
    }


async def lookup_abusech_ip(ip: str) -> dict[str, Any]:
    """ThreatFox + URLhaus on one source address, for alert enrichment.

    Two requests (made concurrently, each cached). The aggregate itself is not cached: its parts
    are, and a partial answer must not be pinned for the success TTL.
    """
    if not _key():
        return not_configured("abuse.ch", "ABUSECH_AUTH_KEY")
    canonical, bad = canonical_ip(ip)
    if canonical is None:
        return bad or {"available": False, "note": "not a valid IP address"}
    ip = canonical

    async def urlhaus() -> dict[str, Any]:
        if ":" in ip:
            return {"available": False, "note": "URLhaus host lookups skip IPv6 literals"}
        return await lookup_urlhaus_host(ip)

    tf, uh = await asyncio.gather(lookup_threatfox(ip, exact=False, address_only=True), urlhaus())

    if not tf.get("available") and not uh.get("available"):
        return tf if tf.get("error") else uh
    return {
        "available": True,
        "ip": ip,
        "listed": bool(tf.get("listed") or uh.get("listed")),
        "malware": tf.get("malware") or [],
        "threatfox": tf,
        "urlhaus": uh,
    }
