"""Shared plumbing for the optional reputation providers (GreyNoise, abuse.ch, OTX, InternetDB).

Conventions every provider follows, so callers can treat them uniformly:

* `{"available": False, "note": ...}`  — not configured (no key / not enabled). Never an error.
* `{"available": False, "error": ...}` — configured but the call failed (auth rejected, rate
  limit, timeout, transport). Remembered briefly under the negative cache so a burst of CRITICALs
  does not become a burst of failing calls; never cached as a success.
* `{"available": True, ...}`           — the vendor answered. "Not found" is an answer
  (`available: True` with an empty result), and is cached like any other.

Everything a vendor returns is **third-party text** that originates, in the end, from people who
attack the internet (a malware family label, a pulse title, a hostname). It is shown to humans in
chat channels and to a language model in tool results, so `clean()` reduces it to a short single
line with no control characters before it is stored in a result. It is data to display — never
something to execute, follow or interpolate into an instruction.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import httpx

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")

DEFAULT_TIMEOUT = 3.0


def provider_timeout() -> float:
    from honeypot_mcp.config import get_settings

    value = get_settings().intel_provider_timeout_seconds
    return value if value > 0 else DEFAULT_TIMEOUT


def new_client() -> httpx.AsyncClient:
    """One pooled client per event loop (callers wrap this in `LoopBound`), short timeout."""
    return httpx.AsyncClient(timeout=provider_timeout(), follow_redirects=False)


def clean(value: Any, limit: int = 120) -> str:
    """A vendor-supplied string as one short printable line."""
    text = _CONTROL.sub(" ", str(value if value is not None else "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def clean_list(values: Any, *, limit: int, item_limit: int = 80) -> list[str]:
    """First `limit` entries of a vendor list, each cleaned; non-lists give []."""
    if not isinstance(values, list):
        return []
    return [clean(v, item_limit) for v in values[:limit] if v not in (None, "")]


def as_int(value: Any, default: int = 0) -> int:
    """Vendors send counts as numbers or as numeric strings (URLhaus: `"url_count": "120"`)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def canonical_ip(ip: str) -> tuple[str | None, dict[str, Any] | None]:
    """`(canonical address, None)` or `(None, failure result)`.

    The address is interpolated into a URL path, so only a canonical one may pass: an IPv6 zone id
    (`::1%../../x`) would otherwise steer a credentialed request to another path on the vendor's
    host. Not every caller ran `validate_ip` first (the ingest path enriches stored source IPs).
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None, {"available": False, "note": "not a valid IP address"}
    if getattr(addr, "scope_id", None):
        return None, {
            "available": False,
            "note": "scoped (zone-id) addresses are not looked up",
        }
    return str(addr), None


def not_configured(provider: str, setting: str) -> dict[str, Any]:
    return {
        "available": False,
        "note": f"{provider} is not configured. Set {setting} in .env to enable it.",
    }


def failure(provider: str, exc: BaseException) -> dict[str, Any]:
    """Map a transport/HTTP exception to a failure result. Never contains a credential: httpx
    exception text names the URL and status, not the request headers or POST body."""
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return {
                "available": False,
                "error": f"{provider} rejected the credentials (HTTP {code}); check the key.",
            }
        if code == 429:
            return {"available": False, "error": f"{provider} rate limit exceeded."}
        return {"available": False, "error": f"{provider} returned HTTP {code}."}
    if isinstance(exc, httpx.TimeoutException):
        return {"available": False, "error": f"{provider} timed out after {provider_timeout():g}s."}
    return {"available": False, "error": f"{provider} lookup failed: {clean(exc, 160)}"}
