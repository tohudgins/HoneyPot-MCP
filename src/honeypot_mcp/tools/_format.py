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

import re
from datetime import UTC, datetime
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
        value = payload.get(key)
        if key in payload and value not in (None, "", [], {}) and not isinstance(value, dict):
            # Nested structures belong in the full payload (alerts_get), same
            # rule the catch-all loop below already applies to unrecognised
            # keys — this loop had no such guard, so a _DIGEST_KEYS field
            # (e.g. "command") holding a dict instead of the usual string
            # would leak the raw structure into the digest untouched: _clip()
            # only special-cases str/list, so a dict passes through as-is.
            digest[key] = _clip(value, _MAX_DIGEST_VALUE_CHARS)

    # Enrichment is nested and verbose; lift just the verdict-bearing fields.
    enrichment = payload.get("enrichment")
    if isinstance(enrichment, dict):
        geo = enrichment.get("geoip")
        if isinstance(geo, dict):
            if country := geo.get("country"):
                digest["country"] = country
            if as_org := geo.get("as_org"):
                digest["as_org"] = as_org
        # `malicious_votes` is the key `intel.virustotal` actually returns.
        # This read `malicious`, which that dict never contains, so a VT
        # verdict was silently absent from every digest — the guard is a
        # truthiness check, so a wrong key looks exactly like "no detections".
        vt = enrichment.get("virustotal")
        if isinstance(vt, dict) and vt.get("malicious_votes"):
            digest["vt_malicious"] = vt["malicious_votes"]
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


def resolve_artifact_path(output_path: str | None, *, prefix: str, extension: str) -> Any:
    """Resolve a caller-supplied artifact path, confined to `reports_dir`.

    Returns a `Path`, or a `str` error message if the path escapes the
    directory.

    This is a security boundary, not tidiness. Exports embed captured attack
    payloads, and this server's control plane is driven by a language model
    that *reads those payloads* — so attacker-authored text reaches the same
    context that decides which tools to call, with which arguments. An
    unconstrained `output_path` therefore turns "attacker writes a string into
    a honeypot" into a candidate arbitrary-file-write with attacker-chosen
    content, without the attacker ever authenticating to anything.

    Confining writes to one directory removes that primitive regardless of
    whether any given injection attempt succeeds.
    """
    from pathlib import Path

    from honeypot_mcp.config import get_settings

    root = get_settings().reports_dir.resolve()
    if not output_path:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        return root / f"{prefix}-{stamp}.{extension}"

    try:
        candidate = Path(output_path).expanduser()
        # A bare filename is the common, intended case.
        dest = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    except Exception as e:
        # output_path is attacker-adjacent (see the docstring), so a string
        # that Path/.expanduser()/.resolve() itself rejects must not raise
        # out of a tool call uncaught — same outcome as any other rejected
        # path: a clean error, not a crash. Deliberately broad: property-
        # based testing found two *different* exception types from this one
        # call chain in a single run (ValueError on an embedded null byte,
        # RuntimeError from expanduser() on "~0" — a `~user` form for a user
        # that doesn't exist) — enumerating exception types here is a losing
        # game against arbitrary attacker-chosen strings.
        return f"{output_path!r} is not a usable path: {e}"
    if dest != root and root not in dest.parents:
        return (
            f"Refusing to write outside the reports directory ({root}). "
            f"Pass a filename, or a path inside that directory, instead of {output_path!r}."
        )
    return dest


def write_artifact(
    content: str,
    *,
    prefix: str,
    extension: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Write bulk tool output to disk and describe it, instead of returning it.

    Exports scale with attacker count, not with anything the caller chose: a
    STIX bundle for a few hundred alerts is well over 100 KB, and a blocklist
    grows a line per offending IP. Returning that inline spends the whole
    budget on content destined for a firewall or a TIP, not for reading.

    Returns the path plus size metadata, or an `error` key if the write failed.
    """
    dest = resolve_artifact_path(output_path, prefix=prefix, extension=extension)
    if isinstance(dest, str):
        return {"error": dest}
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    except OSError as e:
        return {"error": f"Could not write {dest}: {e}"}

    return {
        "path": str(dest),
        "bytes": len(content.encode("utf-8")),
        "lines": content.count("\n") + 1,
    }


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_honeypot_name(name: str) -> str | None:
    """Return an error message if `name` is unsafe, else None.

    Honeypot names are not just labels: they become filesystem paths
    (`tls/<name>/server.key`) and Docker container names. A name containing a
    path separator or `..` therefore escapes the intended directory, so this is
    a traversal guard rather than a formatting preference. The character set
    also matches Docker's own container-name rules, so a name that passes here
    cannot fail later at `docker run`.
    """
    if not name or not _NAME_RE.match(name):
        return (
            f"Invalid honeypot name {name!r}. Use 1-64 characters: letters, digits, "
            f"dot, dash or underscore, starting with a letter or digit. Names become "
            f"directory and container names, so separators and '..' are not allowed."
        )
    return None


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
