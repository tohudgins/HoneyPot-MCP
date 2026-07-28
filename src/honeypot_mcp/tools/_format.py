"""Response shaping for MCP tools.

An MCP tool result goes straight into a model's context window, so a tool that
returns everything it knows is a bug even when the data is correct. Honeypot
payloads are the worst case: the HTTP engine alone captures every request
header plus up to 64 KB of base64-encoded body, so a 200-row triage query can
carry megabytes of forensic detail that nobody asked for.

The rule these helpers implement: **list tools summarise, detail tools expand.**
`alerts_recent` returns a digest of the fields an analyst triages on;
`alerts_get` returns the whole payload for the one alert they picked.
"""

from __future__ import annotations

from typing import Any

# Fields worth showing in a triage digest, grouped by why an analyst cares.
# Order matters — it's the order they appear in the digest.
_DIGEST_KEYS: tuple[str, ...] = (
    # Who they claimed to be
    "username",
    "user",
    "login",
    "password",
    "service",
    "database",
    # What they asked for
    "method",
    "path",
    "query",
    "command",
    "commands",
    "input",
    "url",
    "qtype",
    "qname",
    # What it means
    "exploit_categories",
    "honeytoken_id",
    "note",
    "ransom_note",
    "filename",
    "file_hash",
    "sha256",
    # Who they actually are (RDP/SSH client fingerprints)
    "client_name",
    "client_build",
    "client_version",
    "mstshash",
    "session_id",
)

# Never worth carrying into a list view: high-volume, low-signal-per-byte.
# Available in full via alerts_get.
_DIGEST_DROP: frozenset[str] = frozenset(
    {
        "headers",
        "raw_body_b64",
        "raw_content_type",
        "cookies",
        "enrichment",
        "demo",
    }
)

# A single captured value longer than this is truncated in the digest. Long
# enough to keep a full URL path or a short shell command intact.
_MAX_DIGEST_VALUE_CHARS = 160

# Ceiling for one alert's full payload (alerts_get). A 64 KB base64 body is
# legitimate forensic data, but it should not silently consume a context
# window — past this the value is truncated with an explicit marker.
_MAX_FULL_VALUE_CHARS = 4_000


def _clip(value: Any, limit: int) -> Any:
    """Truncate a single value, marking it so the reader knows data was cut."""
    if isinstance(value, str) and len(value) > limit:
        return f"{value[:limit]}… [+{len(value) - limit} chars, use alerts_get]"
    if isinstance(value, list) and len(value) > 20:
        return value[:20] + [f"… [+{len(value) - 20} more]"]
    return value


def digest_payload(payload: Any) -> dict[str, Any]:
    """Reduce an alert payload to the fields an analyst triages on.

    Surfaces the high-signal keys (credentials tried, path requested, command
    run, exploit category matched) and the enrichment verdict, and drops bulk
    forensic fields. Returns `{}` for an empty payload so the key can be
    omitted entirely from the response.
    """
    if not isinstance(payload, dict) or not payload:
        return {}

    digest: dict[str, Any] = {}
    for key in _DIGEST_KEYS:
        if key in payload and payload[key] not in (None, "", [], {}):
            digest[key] = _clip(payload[key], _MAX_DIGEST_VALUE_CHARS)

    # Enrichment is nested and verbose; lift just the verdict-bearing fields.
    enrichment = payload.get("enrichment")
    if isinstance(enrichment, dict):
        geo = enrichment.get("geoip")
        if isinstance(geo, dict):
            if country := geo.get("country"):
                digest["country"] = country
            if as_org := geo.get("as_org"):
                digest["as_org"] = as_org
        vt = enrichment.get("virustotal")
        if isinstance(vt, dict) and vt.get("malicious"):
            digest["vt_malicious"] = vt["malicious"]
        abuse = enrichment.get("abuseipdb")
        if isinstance(abuse, dict) and abuse.get("abuse_confidence_score"):
            digest["abuse_score"] = abuse["abuse_confidence_score"]

    # Anything unrecognised still matters — a new engine's fields shouldn't be
    # invisible just because this list predates it. Include them, minus noise.
    for key, value in payload.items():
        if key in digest or key in _DIGEST_DROP or key in _DIGEST_KEYS:
            continue
        if value in (None, "", [], {}):
            continue
        if isinstance(value, dict):
            continue  # nested structures belong in the full payload
        digest[key] = _clip(value, _MAX_DIGEST_VALUE_CHARS)

    return digest


def validate_ip(ip: str) -> str | None:
    """Return an error message if `ip` isn't a valid address, else None.

    Every IP reaching these tools was typed or transcribed by a model reading
    an alert, so a typo is a realistic failure. Without this the tool runs a
    query that matches nothing and reports "no activity found" — which reads
    as a clean bill of health rather than a malformed request.
    """
    import ipaddress

    try:
        ipaddress.ip_address(ip.strip())
    except ValueError:
        return (
            f"'{ip}' is not a valid IPv4 or IPv6 address. Expected something like "
            f"192.0.2.10 or 2001:db8::1 — check the value copied from the alert."
        )
    return None


def truncate_payload(payload: Any) -> Any:
    """Return a full payload with only pathologically long values clipped.

    Used by detail tools, where the caller explicitly asked for everything on
    one record. Preserves structure; only individual oversized strings shrink.
    """
    if not isinstance(payload, dict):
        return payload
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            out[key] = truncate_payload(value)
        else:
            out[key] = _clip(value, _MAX_FULL_VALUE_CHARS)
    return out
