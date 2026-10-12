"""Outbound webhook + SIEM delivery.

Every flushed alert that meets a subscription's severity threshold is
serialised into the subscription's chosen `format` and delivered via the
appropriate transport. Ten formats are supported, in two groups.

**SIEM formats** fill an index and are never throttled — dropping an event
would corrupt the record they exist to keep:

* `json` — raw JSON envelope, optionally HMAC-signed via
  `X-HoneyPot-Signature: sha256=<hex>` (consumer verifies with the same
  secret, same convention as GitHub webhooks).
* `splunk_hec` — Splunk HTTP Event Collector. Body is
  `{"time": ..., "host": ..., "sourcetype": "honeypot:alert", "event": {...}}`
  and the HEC token rides in `Authorization: Splunk <token>` (stored in
  `subscription.hmac_secret`).
* `elastic_ecs` — Elastic Common Schema. Fields are re-mapped to the
  ECS namespace (`source.ip`, `event.action`, `event.severity`, `@timestamp`).
  Compatible with Elastic Bulk API receivers and Filebeat HTTP input.
* `cef` — ArcSight Common Event Format. Pipe-delimited text body that
  QRadar's Universal CEF Connector also ingests.
* `syslog` — RFC 5424 framed message. The subscription URL scheme picks
  the transport — `udp://host:514` for UDP datagrams,
  `tcp://host:514` for TCP-framed delivery.
* `loki` — Grafana Loki push API. Body is `{"streams": [...]}` with
  nanosecond string timestamps. Stream labels are deliberately
  low-cardinality (job / severity / event_type only — never source_ip, which
  would create a stream per attacker); the IP stays queryable in the line via
  `| json | source_ip="…"`. Auth via `Authorization: Basic <pre-encoded>` if
  `hmac_secret` is set (operator pre-encodes `userid:token` for Grafana Cloud).
* `datadog` — Datadog Logs API. Body is a single-element JSON list per
  the v2 logs intake. `DD-API-KEY: <hmac_secret>` carries the API key.

**Human channels** interrupt a person, so their scarce resource is attention
rather than storage. All three are coalesced by `_NotifyThrottle` (CRITICAL
exempt) — a channel that relays a scanner one-to-one gets muted, which is worse
than no integration because everyone then believes they are covered:

* `slack` — incoming webhook, Block Kit. Sets `text` as well as `blocks`, or
  the mobile push arrives as "This content can't be displayed".
* `teams` — incoming webhook, MessageCard (renders on both the classic O365
  connector and the Workflows path; Adaptive Cards only work on the latter).
* `email` — SMTP via `asyncio.to_thread`. The URL carries everything:
  `smtp://user:pw@host:587/?from=…&to=a@x,b@y&tls=starttls|implicit|none`.

Delivery runs in background asyncio tasks drained from a bounded queue so slow
webhook endpoints can never back-pressure the honeypot data path. The global
queue fans out into one bounded queue per subscription, each delivered with
its own small concurrency budget, so one dead endpoint stalls only itself.
When a queue is full the oldest lowest-severity event is shed first and
counted (`WebhookDelivery.dropped_count`). HTTP deliveries retry with
exponential backoff (1s, 5s, 30s); UDP syslog is fire-and-forget (UDP has no
retry semantics) but failures are still recorded against `failure_count`. The
`last_error` column gives operators a one-line failure reason without needing
log access.

**Destinations are policed.** A subscription streams captured attack data to
an address of the caller's choosing, so it is an SSRF/exfiltration primitive
unless the address is checked. Link-local (cloud metadata), unspecified,
multicast and reserved addresses are always refused; loopback and private
ranges are refused unless `webhook_allow_private_destinations` is set. The
check runs at subscribe time and again before every delivery (hostnames are
re-resolved and every returned address must pass), and syslog connects to the
exact address that was validated.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import re
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, update

from honeypot_mcp import __version__
from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent
from honeypot_mcp.storage.models import AlertSeverity, Subscription

log = logging.getLogger(__name__)

_SEVERITY_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}

# Severity mappings into each format's native scale.
# ECS uses 0-9 (RFC equivalent). CEF uses 0-10. Syslog uses 0-7 inverted
# (0=Emergency, 7=Debug) where lower = more severe.
_ECS_SEVERITY = {
    AlertSeverity.LOW: 3,
    AlertSeverity.MEDIUM: 5,
    AlertSeverity.HIGH: 7,
    AlertSeverity.CRITICAL: 9,
}
_CEF_SEVERITY = {
    AlertSeverity.LOW: 3,
    AlertSeverity.MEDIUM: 6,
    AlertSeverity.HIGH: 8,
    AlertSeverity.CRITICAL: 10,
}
# Syslog severities per RFC 5424 §6.2.1. We never use 0 (Emergency) /
# 1 (Alert) — those imply system-wide outages, not honeypot events.
_SYSLOG_SEVERITY = {
    AlertSeverity.CRITICAL: 2,  # Critical
    AlertSeverity.HIGH: 3,  # Error
    AlertSeverity.MEDIUM: 4,  # Warning
    AlertSeverity.LOW: 6,  # Informational
}
# Syslog facility 16 = local0. Operators can grep on this to bucket
# honeypot traffic separately from system logs at the SIEM input.
_SYSLOG_FACILITY = 16

_RETRY_DELAYS = (1.0, 5.0, 30.0)
_HOSTNAME = "honeypot-mcp"
# ECS release these documents claim conformance to. Bump only alongside an
# actual field review — consumers use it to decide how to read the document.
_ECS_VERSION = "8.11.0"
# CEF header identity. Vendor and product are what an ArcSight/QRadar operator
# sees in the device list and writes correlation rules against, so "server"
# (the previous product value) was actively unhelpful — it identified nothing.
_CEF_VENDOR = "HoneyPotMCP"
_CEF_PRODUCT = "HoneyPot-MCP"

# Active-subscription cache. Delivery previously issued one `SELECT … WHERE
# active` per event — a DB round-trip on the ingest hot path, even in the
# common case of zero subscribers. Subscriptions change rarely, so we cache
# them (refreshed on TTL, invalidated explicitly on subscribe/unsubscribe and
# on worker start), mirroring the suppression-rule cache.
_SUB_CACHE_TTL = 30.0
_sub_cache: list[Subscription] | None = None
_sub_cache_ts: float = 0.0


def invalidate_subscription_cache() -> None:
    """Force the next delivery to re-read subscriptions from the DB."""
    global _sub_cache
    _sub_cache = None


async def _active_subscriptions() -> list[Subscription]:
    """Active subscriptions, cached for `_SUB_CACHE_TTL`. Detached from the
    loading session (`expunge_all`) so `_record_outcome`'s stat updates never
    interact with the cache and post-commit attribute expiry can't bite."""
    global _sub_cache, _sub_cache_ts
    now = time.monotonic()
    cache = _sub_cache
    if cache is not None and now - _sub_cache_ts < _SUB_CACHE_TTL:
        return cache
    async with get_session() as session:
        result = await session.execute(select(Subscription).where(Subscription.active.is_(True)))
        subs = list(result.scalars().all())
        session.expunge_all()
    _sub_cache = subs
    _sub_cache_ts = now
    return subs


def sign_body(secret: str, body: bytes) -> str:
    """`X-HoneyPot-Signature: sha256=<hex>`. Consumers verify with the same
    secret over the raw body bytes — same convention as GitHub webhooks."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _meets_threshold(event_severity: AlertSeverity, threshold: AlertSeverity) -> bool:
    return _SEVERITY_RANK[event_severity] >= _SEVERITY_RANK[threshold]


# ── Destination policy ──────────────────────────────────────────────────────
#
# A subscription points a stream of captured attack data — and, through the
# HTTP/SMTP/syslog transports, outbound connections from this host — at an
# address of the caller's choosing. Unchecked, that is an SSRF primitive
# against the cloud metadata service and anything else on the host's network,
# reachable by whoever can call `alert_subscribe` (and, because the control
# plane is driven by a model that reads attacker-authored strings, potentially
# by an attacker who never authenticated).

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_DEFAULT_PORTS = {"http": 80, "https": 443, "udp": 514, "tcp": 514, "smtp": 587, "smtps": 465}
# RFC 6052 well-known NAT64 prefix: the low 32 bits are an IPv4 destination the
# translator will connect to, so `64:ff9b::a9fe:a9fe` is the metadata service.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_RESOLVE_TIMEOUT = 5.0


class DestinationRefusedError(ValueError):
    """The destination resolves to an address captured data must not be sent to."""


def redact_url(url: str) -> str:
    """`scheme://host[:port]` only — never userinfo, path or query.

    Webhook URLs routinely carry their credential in the path (Slack, Teams)
    or userinfo (SMTP), and email URLs carry recipient addresses in the query.
    Anything shown to a viewer-tier caller or written to the audit log goes
    through here.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "[unparseable url]"
    scheme = (parsed.scheme or "").lower()
    if not host:
        return f"{scheme}://[no host]" if scheme else "[unparseable url]"
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}" + (f":{port}" if port is not None else "")


def destination_refusal(ip: _IPAddress, *, allow_private: bool) -> str | None:
    """Why `ip` must not receive deliveries, or None if it may."""
    if isinstance(ip, ipaddress.IPv6Address):
        # The kernel connects `::ffff:127.0.0.1` to loopback; judge the
        # embedded IPv4 address, not the wrapper.
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64_PREFIX:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            reason = destination_refusal(embedded, allow_private=allow_private)
            if reason is not None:
                return f"NAT64 address embedding a {reason}"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_link_local:
        return "link-local address (cloud metadata services live here)"
    if ip.is_multicast:
        return "multicast address"
    if ip.is_reserved:
        return "reserved address"
    if ip.is_global or allow_private:
        return None
    kind = "loopback" if ip.is_loopback else "private/non-public"
    return f"{kind} address (set WEBHOOK_ALLOW_PRIVATE_DESTINATIONS=true to allow internal targets)"


def destination_endpoint(url: str, fmt: str) -> tuple[str, int, int]:
    """(host, port, socket type) a subscription will actually connect to.

    Raises ValueError for a URL that names no usable host or port.
    """
    fmt = (fmt or "json").lower()
    if fmt == "email":
        cfg = _parse_smtp_url(url)
        return str(cfg["host"]), int(cfg["port"]), socket.SOCK_STREAM
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    scheme = (parsed.scheme or "").lower()
    port = parsed.port or _DEFAULT_PORTS.get(scheme, 443)
    socktype = socket.SOCK_DGRAM if fmt == "syslog" and scheme == "udp" else socket.SOCK_STREAM
    return host, port, socktype


async def resolve_destination(
    host: str,
    port: int,
    *,
    socktype: int = socket.SOCK_STREAM,
    allow_private: bool | None = None,
) -> list[str]:
    """Every address `host` resolves to, after checking each one.

    ALL addresses must pass: a DNS name answering with one public and one
    internal address would otherwise let the connecting library pick the
    internal one. Raises `DestinationRefusedError` on a policy refusal and
    `OSError` (incl. `TimeoutError`) if the name cannot be resolved.
    """
    if allow_private is None:
        allow_private = get_settings().webhook_allow_private_destinations
    addresses: list[_IPAddress] = []
    try:
        addresses.append(ipaddress.ip_address(host))
    except ValueError:
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socktype), timeout=_RESOLVE_TIMEOUT
        )
        for info in infos:
            raw = str(info[4][0])
            try:
                addresses.append(ipaddress.ip_address(raw))
            except ValueError:
                raise DestinationRefusedError(
                    f"{host} resolved to an unparseable address {raw!r}"
                ) from None
    if not addresses:
        raise OSError(f"{host} did not resolve to any address")
    for address in addresses:
        reason = destination_refusal(address, allow_private=allow_private)
        if reason is not None:
            shown = host if host == str(address) else f"{host} -> {address}"
            raise DestinationRefusedError(f"{shown} is a {reason}")
    return list(dict.fromkeys(str(a) for a in addresses))


async def check_destination(url: str, fmt: str) -> tuple[str | None, list[str]]:
    """(refusal-or-None, validated addresses) for a subscription URL.

    The delivery-time gate. Never raises: a refusal or an unresolvable name is
    returned as the error string `_record_outcome` stores in `last_error`.
    """
    try:
        host, port, socktype = destination_endpoint(url, fmt)
        addresses = await resolve_destination(host, port, socktype=socktype)
    except DestinationRefusedError as e:
        return f"destination refused: {e}"[:200], []
    except (OSError, ValueError) as e:
        return f"destination unresolvable: {e}"[:200], []
    return None, addresses


# ── Escaping for human channels and CEF ─────────────────────────────────────
#
# Everything a notification shows about an event is attacker-chosen: the
# username, the path, the User-Agent. Interpolated raw, a username of
# `<!channel>` pings a whole Slack workspace, a backtick closes the code span
# and turns the rest into formatting, and a CR/LF in an email value forges
# lines ("Severity : low") an on-call reader trusts.

_LINE_BREAKS = re.compile(r"[\r\n\x0b\x0c\x85\u2028\u2029]+")


def _one_line(value: object) -> str:
    """Collapse every line break to a single space."""
    return _LINE_BREAKS.sub(" ", str(value))


def _slack_escape(value: object) -> str:
    """Slack's three mandatory escapes, plus the backtick.

    Slack documents `&`, `<` and `>` as the characters to escape in mrkdwn
    (`<…>` is how mentions and links are written). Captured values are shown
    inside a code span, so a backtick would end the span early; it is swapped
    for the look-alike U+02CB.
    """
    text = _one_line(value)
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "\u02cb")
    )


def _teams_escape(value: object) -> str:
    """Teams cards are sent with markdown off, so only HTML and line breaks
    remain to neutralise — MessageCard fields still honour a subset of HTML."""
    return html.escape(_one_line(value), quote=False)


# ── Format renderers ────────────────────────────────────────────────────────


def _base_event_dict(event: PendingEvent) -> dict[str, Any]:
    """The canonical native shape — used as input by every renderer."""
    return {
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "event_type": event.event_type,
        "severity": event.severity.value,
        "honeypot_id": event.honeypot_id,
        "honeytoken_id": event.honeytoken_id,
        "payload": event.payload,
        "timestamp": event.timestamp.isoformat(),
    }


# Backwards-compat alias — the old delivery worker called this `_serialise`,
# and the existing webhook test still imports it. Keep both names working
# so the test surface doesn't churn.
_serialise = _base_event_dict


def render_json(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Default JSON envelope. HMAC-signed if `sub.hmac_secret` is set."""
    body = json.dumps(_base_event_dict(event), default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "HoneyPot-MCP/1.0"}
    if sub.hmac_secret:
        headers["X-HoneyPot-Signature"] = sign_body(sub.hmac_secret, body)
    return body, headers


def render_splunk_hec(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Splunk HTTP Event Collector envelope.

    The HEC schema is documented at
    https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    `event` can be any JSON value; we hand it the canonical native dict.
    Time is unix-epoch seconds with millisecond precision (Splunk accepts
    floats here)."""
    envelope = {
        "time": event.timestamp.timestamp(),
        "host": _HOSTNAME,
        "source": "honeypot-mcp",
        "sourcetype": "honeypot:alert",
        "event": _base_event_dict(event),
    }
    body = json.dumps(envelope, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "HoneyPot-MCP/1.0",
    }
    if sub.hmac_secret:
        # Splunk HEC authenticates via `Authorization: Splunk <token>`. We
        # reuse the `hmac_secret` column to store the token — it's
        # conceptually the same thing (a per-subscription auth secret).
        headers["Authorization"] = f"Splunk {sub.hmac_secret}"
    return body, headers


# Payload keys engines use for the attacker-supplied username, most specific
# first. Both ECS (`user.name`) and CEF (`suser`) have a first-class field for
# this, and an analyst filters on it constantly — "show me every host that
# tried `root`" is a first-move query in any SIEM. Leaving it buried in a JSON
# blob inside a custom string field means it is technically present and
# practically unsearchable.
_ACTOR_KEYS = ("username", "user", "login", "email", "account", "dn", "community")


def _extract_actor(payload: dict[str, Any]) -> str | None:
    """Best-effort attacker username from an event payload."""
    for key in _ACTOR_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value[:256]
    # HTTP form posts arrive nested; check one level down for the same keys.
    nested = payload.get("post_data")
    if isinstance(nested, dict):
        for key in _ACTOR_KEYS:
            value = nested.get(key)
            if isinstance(value, str) and value.strip():
                return value[:256]
    return None


# Explicit outcome markers in event_type. Ordered failure-first because
# "login_failed" contains neither marker in the success list but several
# event types contain both words in other combinations.
_OUTCOME_FAILURE = ("_failed", "_invalid", "_denied", "_rejected", "_refused")
_OUTCOME_SUCCESS = ("_success", "_triggered", "_granted", "_accepted")


def _ecs_outcome(event_type: str) -> str:
    """ECS `event.outcome` for a honeypot event — `unknown` unless we know.

    This was hardcoded to `"success"`, which is wrong in the common case and
    actively misleading: `event.outcome` drives the authentication panels in
    Kibana's Security app, so a hundred thousand rejected brute-force attempts
    rendered as a hundred thousand *successful* logins. `unknown` is a valid
    ECS value and the honest one where we genuinely cannot tell.
    """
    et = event_type.lower()
    if any(marker in et for marker in _OUTCOME_FAILURE):
        return "failure"
    if any(marker in et for marker in _OUTCOME_SUCCESS):
        return "success"
    # Every engine that emits `*_login_attempt` / `*_auth_attempt` captures the
    # credential and then rejects it (MSSQL returns error 18456, PostgreSQL
    # returns 28P01, and so on), so from the attacker's side these did fail.
    if et.endswith("_login_attempt") or et.endswith("_auth_attempt"):
        return "failure"
    return "unknown"


def _ecs_event_category(event_type: str, honeytoken_id: int | None) -> list[str]:
    """Map honeypot event types into ECS `event.category` taxonomy.

    Empty list is valid ECS but reduces searchability — we prefer to assign
    the closest match. ECS categories are a closed set documented at
    https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html.
    """
    et = event_type.lower()
    if honeytoken_id is not None or "honeytoken" in et:
        return ["intrusion_detection"]
    if "login" in et or "auth" in et or "credential" in et:
        return ["authentication", "intrusion_detection"]
    if "scan" in et or "probe" in et or "recon" in et:
        return ["network", "intrusion_detection"]
    if "command" in et or "exec" in et or "eval" in et:
        return ["process", "intrusion_detection"]
    if "file" in et or "download" in et:
        return ["file", "intrusion_detection"]
    return ["intrusion_detection"]


def _confidence_band(score: int) -> str:
    """AbuseIPDB's 0-100 score → the ECS `threat.indicator.confidence` vocabulary."""
    if score >= 75:
        return "High"
    if score >= 40:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def _vt_confidence_band(malicious: int) -> str:
    """VirusTotal detection count → the same ECS confidence vocabulary.

    Banded on the absolute count, not the share of engines: most of the ~94
    engines VT polls do not score IP reputation at all, so the denominator is
    close to meaningless and a ratio buries a real finding. 11 engines calling
    an address malicious is 11/94 — 12%, which any ratio-based band reads as
    "Low" while an analyst reads it as "block this".
    """
    if malicious >= 10:
        return "High"
    if malicious >= 4:
        return "Medium"
    if malicious > 0:
        return "Low"
    return "None"


def _ecs_enrichment(doc: dict[str, Any], event: PendingEvent) -> None:
    """Lift `payload.enrichment` into the ECS fields consumers actually query.

    Auto-enrichment already resolves geo, ASN and reputation for every CRITICAL
    event, but all of it only ever reached the wire inside `event.original` —
    a JSON string. Elastic cannot search, aggregate or map a field it cannot
    see, so the Security app's network map stayed empty while the coordinates
    that would populate it sat in the same document. Same defect the `user.name`
    fix addressed: present, but not as a field.
    """
    enrichment = (event.payload or {}).get("enrichment")
    if not isinstance(enrichment, dict):
        return

    source = doc.setdefault("source", {})

    geo_src = enrichment.get("geoip")
    if isinstance(geo_src, dict) and geo_src.get("available"):
        geo: dict[str, Any] = {}
        for ecs_key, our_key in (
            ("country_name", "country"),
            ("country_iso_code", "country_code"),
            ("city_name", "city"),
            ("timezone", "timezone"),
        ):
            if value := geo_src.get(our_key):
                geo[ecs_key] = value
        lat, lon = geo_src.get("latitude"), geo_src.get("longitude")
        if lat is not None and lon is not None:
            # ECS `geo.location` is a geo_point; the object form with `lat`/`lon`
            # is what the default index template maps. A [lon, lat] array is also
            # legal but silently reverses if a consumer guesses the order.
            geo["location"] = {"lat": lat, "lon": lon}
        if geo:
            source["geo"] = geo

        autonomous: dict[str, Any] = {}
        if (asn := geo_src.get("asn")) is not None:
            autonomous["number"] = asn
        if as_org := geo_src.get("as_org"):
            autonomous["organization"] = {"name": as_org}
        if autonomous:
            source["as"] = autonomous

    # Reputation is an enrichment *of* this event, not a threat-intel document
    # about the indicator, so it belongs under `threat.enrichments[]` — the
    # shape Elastic's own indicator-match rules produce and its UI renders.
    enrichments: list[dict[str, Any]] = []
    abuse = enrichment.get("abuseipdb")
    if isinstance(abuse, dict) and abuse.get("available"):
        score = abuse.get("abuse_confidence_score") or 0
        indicator: dict[str, Any] = {
            "ip": event.source_ip,
            "type": "ipv4-addr",
            "provider": "AbuseIPDB",
            "confidence": _confidence_band(int(score)),
        }
        if (reports := abuse.get("total_reports")) is not None:
            indicator["sightings"] = reports
        enrichments.append(
            {
                "indicator": indicator,
                "matched": {
                    "atomic": event.source_ip,
                    "field": "source.ip",
                    "type": "indicator_match_rule",
                },
            }
        )
    vt = enrichment.get("virustotal")
    if isinstance(vt, dict) and vt.get("available"):
        malicious = int(vt.get("malicious_votes") or 0)
        indicator = {
            "ip": event.source_ip,
            "type": "ipv4-addr",
            "provider": "VirusTotal",
            "confidence": _vt_confidence_band(malicious),
            "sightings": malicious,
        }
        if ratio := vt.get("detection_ratio"):
            indicator["description"] = f"VirusTotal detections: {ratio}"
        enrichments.append(
            {
                "indicator": indicator,
                "matched": {
                    "atomic": event.source_ip,
                    "field": "source.ip",
                    "type": "indicator_match_rule",
                },
            }
        )
    if enrichments:
        doc["threat"] = {"enrichments": enrichments}

    if not source:
        doc.pop("source", None)


def render_elastic_ecs(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Elastic Common Schema field-renamed JSON.

    Compatible with Filebeat HTTP input, Logstash http input, and the
    Elasticsearch Bulk API (each line is a self-contained ECS document).
    """
    actor = _extract_actor(event.payload or {})
    doc: dict[str, Any] = {
        "@timestamp": event.timestamp.isoformat(),
        # Required by the ECS spec, and consumers key compatibility handling
        # off it. Its absence marks a document as non-conformant.
        "ecs": {"version": _ECS_VERSION},
        "event": {
            "action": event.event_type,
            "category": _ecs_event_category(event.event_type, event.honeytoken_id),
            "kind": "alert",
            "severity": _ECS_SEVERITY[event.severity],
            "dataset": "honeypot.mcp",
            "module": "honeypot-mcp",
            "outcome": _ecs_outcome(event.event_type),
            # Nested, not a dotted "event.original" key alongside this object.
            # Elasticsearch expands dots at index time so the old form usually
            # survived, but it is ambiguous on every other ECS consumer
            # (Logstash, OpenSearch, Vector) and trivially avoidable.
            "original": json.dumps(_base_event_dict(event), default=str),
        },
        "host": {"name": _HOSTNAME, "type": "honeypot"},
        "message": f"{event.event_type} from {event.source_ip}",
        "labels": {"severity_name": event.severity.value},
        "honeypot": {
            "id": event.honeypot_id,
            "token_id": event.honeytoken_id,
        },
    }
    if event.source_ip:
        doc["source"] = {"ip": event.source_ip}
        if event.source_port is not None:
            doc["source"]["port"] = event.source_port
    if actor:
        doc["user"] = {"name": actor}
    # `related.*` is how the Elastic Security app pivots across indices — an
    # analyst clicks an IP and every document that mentions it anywhere comes
    # back. Populating it is what makes these events first-class in that UI
    # rather than a separate island the built-in views cannot correlate.
    related: dict[str, list[str]] = {}
    if event.source_ip:
        related["ip"] = [event.source_ip]
    if actor:
        related["user"] = [actor]
    if related:
        doc["related"] = related
    _ecs_enrichment(doc, event)

    body = json.dumps(doc, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "HoneyPot-MCP/1.0",
    }
    if sub.hmac_secret:
        # Elastic-stack receivers typically accept an `Authorization`
        # header — basic-auth-or-token style. Treat hmac_secret as a
        # bearer token here (ApiKey style).
        headers["Authorization"] = f"ApiKey {sub.hmac_secret}"
    return body, headers


def _cef_escape(value: str) -> str:
    """CEF header values escape `|` and `\\`, and may not contain line breaks.

    A raw CR or LF ends the record in every line-oriented CEF receiver, so an
    attacker-chosen value carrying one could forge a whole second event.
    """
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "\\r").replace("\n", "\\n")


def _cef_ext_escape(value: str) -> str:
    """CEF extension values escape `=`, `\\`, and both line-break characters."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


# Protocol names a plain `.title()` mangles. "Ssh Login Attempt" in an ArcSight
# console is the kind of detail that tells an analyst the integration was
# written by someone who doesn't work in one.
_ACRONYMS = {
    "ssh": "SSH",
    "ftp": "FTP",
    "smtp": "SMTP",
    "http": "HTTP",
    "https": "HTTPS",
    "smb": "SMB",
    "rdp": "RDP",
    "vnc": "VNC",
    "dns": "DNS",
    "ldap": "LDAP",
    "snmp": "SNMP",
    "imap": "IMAP",
    "pop3": "POP3",
    "sip": "SIP",
    "nfs": "NFS",
    "mssql": "MSSQL",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "mongodb": "MongoDB",
    "api": "API",
    "jndi": "JNDI",
    "tds": "TDS",
    "rsync": "rsync",
    "memcached": "Memcached",
    "telnet": "Telnet",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "elasticsearch": "Elasticsearch",
    "redis": "Redis",
    "ip": "IP",
    "url": "URL",
    "aws": "AWS",
    "rce": "RCE",
    "sqli": "SQLi",
    "xss": "XSS",
    "lfi": "LFI",
    "rfi": "RFI",
    "ssrf": "SSRF",
}


def _humanize_event_type(event_type: str) -> str:
    """`ssh_login_attempt` → `SSH Login Attempt`."""
    return " ".join(_ACRONYMS.get(word, word.title()) for word in event_type.split("_"))


def render_cef(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """ArcSight Common Event Format (CEF 0).

    Spec: https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/
    Layout:
        CEF:0|Vendor|Product|Version|EventID|EventName|Severity|extension

    The `extension` part is `key=value key=value …`. Quoting is per
    `_cef_ext_escape`. Custom fields use the `cs1` / `cs2` / `cn1` slots
    with matching `*Label` keys.
    """
    event_type_safe = _cef_escape(event.event_type)
    parts = [
        "CEF:0",
        _CEF_VENDOR,  # device vendor
        _CEF_PRODUCT,  # device product
        __version__,  # device version — real, so rules can gate on it
        event_type_safe,  # signature/event ID (stable, machine-facing)
        _cef_escape(_humanize_event_type(event.event_type)),  # human name
        str(_CEF_SEVERITY[event.severity]),
    ]
    header = "|".join(parts)

    ext_pairs: list[str] = [
        f"rt={int(event.timestamp.timestamp() * 1000)}",
        f"src={_cef_ext_escape(event.source_ip or '0.0.0.0')}",
    ]
    if event.source_port is not None:
        ext_pairs.append(f"spt={event.source_port}")
    # No `dpt`: the honeypot's own port isn't carried on the event, and the
    # service is already identifiable from the event_type prefix and cs1
    # (honeypot_id). Emitting a wrong or invented value would be worse.
    #
    # `suser` is the CEF standard slot for the acting username. It was only
    # ever present inside the cs4 JSON blob, which no correlation rule reads.
    actor = _extract_actor(event.payload or {})
    if actor:
        ext_pairs.append(f"suser={_cef_ext_escape(actor)}")
    ext_pairs.append(f"outcome={_ecs_outcome(event.event_type)}")
    if event.honeypot_id is not None:
        ext_pairs.append(f"cs1={event.honeypot_id}")
        ext_pairs.append("cs1Label=honeypot_id")
    if event.honeytoken_id is not None:
        ext_pairs.append(f"cs2={event.honeytoken_id}")
        ext_pairs.append("cs2Label=honeytoken_id")
    ext_pairs.append(f"cs3={_cef_ext_escape(event.severity.value)}")
    ext_pairs.append("cs3Label=honeypot_severity")
    ext_pairs.append(f"msg={_cef_ext_escape(event.event_type)}")
    # Stash the full payload as cs4 so SIEM analysts can grep it.
    payload_json = json.dumps(event.payload, default=str)
    ext_pairs.append(f"cs4={_cef_ext_escape(payload_json[:1024])}")
    ext_pairs.append("cs4Label=honeypot_payload")

    body_text = header + "|" + " ".join(ext_pairs) + "\n"
    body = body_text.encode("utf-8")
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "User-Agent": "HoneyPot-MCP/1.0",
    }
    return body, headers


# Datadog `status` mapping (info / warning / error / critical) per the
# v2 logs intake. Anything else is treated as info by the Datadog backend.
_DD_STATUS = {
    AlertSeverity.LOW: "info",
    AlertSeverity.MEDIUM: "warning",
    AlertSeverity.HIGH: "error",
    AlertSeverity.CRITICAL: "critical",
}


def render_loki(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Grafana Loki push API envelope.

    Spec: https://grafana.com/docs/loki/latest/reference/api/#push-log-entries-to-loki

    Timestamp **must** be a string of nanoseconds. Loki silently rejects
    integer timestamps with a 400.

    **Stream labels are deliberately low-cardinality.** `source_ip` used to be
    a label, on the reasoning that Loki indexes by labels and an analyst wants
    to slice by attacker. That is precisely the documented Loki anti-pattern:
    every distinct label-value combination creates a separate stream, and an
    internet-facing honeypot sees tens of thousands of unique source IPs in a
    day — enough to blow past `max_streams_per_user`, balloon the index, and
    degrade the whole Loki tenant, not just this data source.

    The IP is still fully queryable, because it is in the log line and LogQL
    parses it there: `{job="honeypot-mcp"} | json | source_ip="203.0.113.44"`.
    That is the idiomatic pattern and costs nothing at ingest.
    """
    ts_ns = str(int(event.timestamp.timestamp() * 1_000_000_000))
    payload_line = json.dumps(_base_event_dict(event), default=str)
    stream = {
        "job": "honeypot-mcp",
        "severity": event.severity.value,
        "event_type": event.event_type,
    }
    envelope = {"streams": [{"stream": stream, "values": [[ts_ns, payload_line]]}]}
    body = json.dumps(envelope, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "HoneyPot-MCP/1.0",
    }
    if sub.hmac_secret:
        # Grafana Cloud Loki uses HTTP basic auth where the credential is
        # `<userid>:<token>`. Operators pre-encode the whole thing and we
        # pass it through unchanged so the same column works for self-hosted
        # Loki behind any basic-auth proxy too.
        headers["Authorization"] = f"Basic {sub.hmac_secret}"
    return body, headers


def render_datadog(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Datadog Logs API v2 envelope.

    Spec: https://docs.datadoghq.com/api/latest/logs/#send-logs
    The endpoint accepts a single object or an array; we always send an
    array so the same path works for batched calls in the future.
    """
    log_entry = {
        "ddsource": "honeypot-mcp",
        "ddtags": f"env:prod,severity:{event.severity.value},event_type:{event.event_type}",
        "hostname": _HOSTNAME,
        "service": "honeypot",
        "message": json.dumps(_base_event_dict(event), default=str),
        "status": _DD_STATUS[event.severity],
    }
    body = json.dumps([log_entry], default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "HoneyPot-MCP/1.0",
    }
    if sub.hmac_secret:
        headers["DD-API-KEY"] = sub.hmac_secret
    return body, headers


def render_syslog(event: PendingEvent, sub: Subscription) -> bytes:
    """RFC 5424 framed syslog message.

    Spec: https://tools.ietf.org/html/rfc5424
    Layout:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG

    PRI = facility * 8 + severity. Timestamp is RFC 3339 (ISO 8601).
    """
    severity = _SYSLOG_SEVERITY[event.severity]
    pri = _SYSLOG_FACILITY * 8 + severity
    timestamp = event.timestamp.isoformat(timespec="milliseconds")
    if not timestamp.endswith("Z") and "+" not in timestamp[-6:]:
        # RFC 5424 timestamps need explicit TZ. ISO format includes it for
        # tz-aware datetimes already.
        timestamp += "Z"
    msgid = event.event_type[:32]
    # No structured-data block — represent as `-` per spec.
    msg = json.dumps(_base_event_dict(event), default=str)
    line = f"<{pri}>1 {timestamp} {_HOSTNAME} honeypot - {msgid} - {msg}"
    return line.encode("utf-8")


# Channels that interrupt a person rather than filling an index. Only these
# are throttled — a SIEM wants every event, and silently dropping one would
# corrupt the record it exists to keep.
_HUMAN_CHANNELS = frozenset({"slack", "teams", "email"})
# Returned (with ok=True) for an event the throttle declined to send. Recorded as `suppressed_count`,
# never as a delivery: counted as one, it overstated what reached the channel (13,025 "deliveries"
# of a Slack subscription that had received a handful of messages) and, as a "success", reset
# failure_count and cleared last_error, so a broken webhook looked healthy.
THROTTLED = "throttled"


class _NotifyThrottle:
    """Per-subscription coalescing for human-facing channels.

    A single scanner produces thousands of events an hour. Relaying those
    one-to-one into a Slack channel makes it unreadable within a minute, and
    the predictable human response is to mute the channel — at which point the
    honeypot has an alerting integration that is strictly worse than none,
    because everyone believes they are covered.

    So a given (subscription, event_type, source_ip) fires at most once per
    window. The suppressed count rides along on the next message that does go
    out, so volume is still visible; it just is not the delivery mechanism.

    CRITICAL is exempt from that per-IP window. It is rare by construction — a
    triggered honeytoken, a container escape, a ransom note — and those are
    precisely the events someone must see immediately even if the same IP
    already fired something a minute ago. It is not unlimited, though: spoofed
    UDP sources rotate `source_ip`, so each (subscription, event_type) is
    capped per minute and the suppressed count rides on the next message.
    """

    def __init__(
        self,
        window_seconds: float = 300.0,
        max_keys: int = 4096,
        critical_cap: int = 30,
        critical_window: float = 60.0,
        critical_repeat_window: float = 300.0,
    ) -> None:
        self._window = window_seconds
        self._max_keys = max_keys
        self._last_sent: dict[tuple[int, str, str], float] = {}
        self._suppressed: dict[tuple[int, str, str], int] = {}
        # CRITICAL is exempt from the per-IP window, but spoofed-source UDP
        # CRITICALs rotate source_ip, so the same event_type could otherwise
        # page a channel without limit. A generous per-(subscription,
        # event_type) cap keeps that bounded; the suppressed count rides on
        # the next message that does go out.
        self._critical_cap = critical_cap
        self._critical_window = critical_window
        self._critical_repeat_window = critical_repeat_window
        self._last_critical: dict[tuple[int, str, str], float] = {}
        self._critical_sent: dict[tuple[int, str], deque[float]] = {}
        self._critical_suppressed: dict[tuple[int, str], int] = {}

    def _check_critical(self, sub_id: int, event: PendingEvent) -> tuple[bool, int]:
        key = (sub_id, event.event_type)
        now = time.monotonic()
        # The same CRITICAL from the same source, repeated: the first one pages, the rest ride
        # along as a count. A honeytoken trigger is the highest-fidelity signal this platform has,
        # so it is never coalesced. Found on the live droplet: one source sending ~700 SIP
        # toll-fraud INVITEs an hour was a Slack message every five seconds, because the per-type
        # cap below (30 a minute) is far above any single scanner's rate.
        tripwire = event.honeytoken_id is not None
        repeat_key = (sub_id, event.event_type, event.source_ip or "")
        if not tripwire and self._critical_repeat_window > 0:
            last = self._last_critical.get(repeat_key)
            if last is not None and now - last < self._critical_repeat_window:
                self._suppressed[repeat_key] = self._suppressed.get(repeat_key, 0) + 1
                return False, 0
        sent = self._critical_sent.get(key)
        if sent is None:
            if len(self._critical_sent) >= self._max_keys:
                victims = sorted(
                    self._critical_sent,
                    key=lambda k: (
                        self._critical_suppressed.get(k, 0) > 0,
                        self._critical_sent[k][-1] if self._critical_sent[k] else 0.0,
                    ),
                )[: max(self._max_keys // 4, 1)]
                for stale in victims:
                    self._critical_sent.pop(stale, None)
                    self._critical_suppressed.pop(stale, None)
            sent = self._critical_sent[key] = deque()
        while sent and now - sent[0] >= self._critical_window:
            sent.popleft()
        if self._critical_cap and len(sent) >= self._critical_cap:
            self._critical_suppressed[key] = self._critical_suppressed.get(key, 0) + 1
            return False, 0
        sent.append(now)
        carried = self._critical_suppressed.pop(key, 0)
        if not tripwire and self._critical_repeat_window > 0:
            # Spoofed sources rotate source_ip: bound the map like the others, and evict keys
            # holding an unsent count last so volume is delayed, never discarded.
            if len(self._last_critical) >= self._max_keys:
                for old in sorted(
                    self._last_critical,
                    key=lambda k: (self._suppressed.get(k, 0) > 0, self._last_critical[k]),
                )[: self._max_keys // 4]:
                    self._last_critical.pop(old, None)
                    self._suppressed.pop(old, None)
            self._last_critical[repeat_key] = now
            carried += self._suppressed.pop(repeat_key, 0)
        return True, carried

    def check(self, sub_id: int, event: PendingEvent) -> tuple[bool, int]:
        """Returns (should_send, suppressed_since_last_send)."""
        if event.severity is AlertSeverity.CRITICAL:
            return self._check_critical(sub_id, event)
        key = (sub_id, event.event_type, event.source_ip or "")
        now = time.monotonic()
        last = self._last_sent.get(key)
        if last is not None and now - last < self._window:
            self._suppressed[key] = self._suppressed.get(key, 0) + 1
            return False, 0
        # Unbounded growth would be a slow leak on a host seeing a wide IP
        # spread, so drop the oldest entries once the map gets large.
        # Keys with a nonzero pending _suppressed count are evicted last —
        # evicting one before its count ever rides out on a send silently
        # discards it, which breaks this class's own guarantee that
        # suppressed volume is never hidden, only delayed. Only spills into
        # a nonzero-suppressed key if there aren't enough zero-suppressed
        # ones to make room, so eviction still terminates either way.
        if len(self._last_sent) >= self._max_keys:
            oldest = sorted(
                self._last_sent,
                key=lambda k: (self._suppressed.get(k, 0) > 0, self._last_sent[k]),
            )[: self._max_keys // 4]
            for stale in oldest:
                self._last_sent.pop(stale, None)
                self._suppressed.pop(stale, None)
        self._last_sent[key] = now
        return True, self._suppressed.pop(key, 0)


# ── Human notification channels ─────────────────────────────────────────────
#
# Distinct from the SIEM formats above, and the difference drives every design
# choice here. A SIEM ingests everything and lets an analyst query later; a chat
# channel or inbox interrupts a person. So these renderers optimise for
# *decidability at a glance* — can the reader tell in two seconds whether to get
# up? — and the delivery path throttles them (see `_NotifyThrottle`), because a
# notifier that fires four thousand times is worse than no notifier at all.

# Chat accent colours. Deliberately the same four the console reserves for
# status, so a CRITICAL looks like a CRITICAL wherever someone sees it.
_NOTIFY_COLOUR = {
    AlertSeverity.CRITICAL: "#d03b3b",
    AlertSeverity.HIGH: "#ec835a",
    AlertSeverity.MEDIUM: "#fab219",
    AlertSeverity.LOW: "#0ca30c",
}
_NOTIFY_EMOJI = {
    AlertSeverity.CRITICAL: "🚨",
    AlertSeverity.HIGH: "⚠️",
    AlertSeverity.MEDIUM: "🔸",
    AlertSeverity.LOW: "ℹ️",
}
# Payload keys worth putting in front of a human, in the order they answer
# "what happened and how bad is it". Everything else stays in the platform —
# a notification is a pointer, not a record.
_NOTIFY_FIELDS = (
    ("username", "Username"),
    ("password", "Password"),
    ("command", "Command"),
    ("path", "Path"),
    ("method", "Method"),
    ("exploit_categories", "Exploit"),
    ("reasons", "Indicators"),
    ("country", "Country"),
    ("asn_org", "Network"),
    ("abuse_score", "AbuseIPDB"),
    ("vt_malicious", "VirusTotal"),
    ("user_agent", "User-Agent"),
)


def _notify_facts(event: PendingEvent) -> list[tuple[str, str]]:
    """The handful of payload fields a human should see, clipped for chat."""
    payload = event.payload or {}
    facts: list[tuple[str, str]] = []
    for key, label in _NOTIFY_FIELDS:
        value = payload.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        text = str(value)
        facts.append((label, text[:180] + ("…" if len(text) > 180 else "")))
    return facts


def _notify_title(event: PendingEvent) -> str:
    return f"{event.severity.value.upper()} · {_humanize_event_type(_one_line(event.event_type))}"


def _honeypot_label(event: PendingEvent) -> str:
    """Canary, Slack and cloud-audit triggers have no honeypot behind them."""
    if event.honeypot_id is None:
        return "no honeypot (canary / token trigger)"
    return f"honeypot #{event.honeypot_id}"


def render_slack(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Slack incoming webhook, Block Kit.

    `text` is set as well as `blocks` because Slack uses it for the mobile
    push notification and the browser-tab preview; a blocks-only message
    arrives on a phone as "This content can't be displayed", which defeats the
    purpose of alerting someone who is away from their desk.
    """
    facts = [(label, _slack_escape(value)) for label, value in _notify_facts(event)]
    source_ip = _slack_escape(event.source_ip or "unknown")
    title = _slack_escape(_notify_title(event))
    fallback = f"{_NOTIFY_EMOJI[event.severity]} {title} from {source_ip}"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{_NOTIFY_EMOJI[event.severity]} {_notify_title(event)}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Source IP*\n`{source_ip}`"},
                {
                    "type": "mrkdwn",
                    "text": f"*Time*\n{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC",
                },
            ],
        },
    ]
    if facts:
        # Slack caps a section at 10 fields and silently rejects the whole
        # message above that, so the slice is load-bearing, not cosmetic.
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{label}*\n`{value}`"}
                    for label, value in facts[:8]
                ],
            }
        )
    if event.honeytoken_id is not None:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"🍯 *Honeytoken {event.honeytoken_id} triggered* — "
                            "a planted credential was used. This is the highest-fidelity "
                            "signal the platform produces."
                        ),
                    }
                ],
            }
        )

    payload = {
        "text": fallback,
        "attachments": [{"color": _NOTIFY_COLOUR[event.severity], "blocks": blocks}],
    }
    body = json.dumps(payload, default=str).encode("utf-8")
    return body, {"Content-Type": "application/json", "User-Agent": "HoneyPot-MCP/1.0"}


def render_teams(event: PendingEvent, sub: Subscription) -> tuple[bytes, dict[str, str]]:
    """Microsoft Teams incoming webhook.

    Emits a MessageCard rather than an Adaptive Card. Adaptive Cards are the
    newer format, but over an *incoming webhook* they require the Power
    Automate "Workflows" connector, whereas MessageCard works on both the
    classic Office 365 connector and the Workflows compatibility path. Since
    the operator only pastes a URL and cannot tell us which they created,
    MessageCard is the one that renders in both places.

    `summary` is mandatory — Teams rejects a card without it (HTTP 400,
    "Summary or Text is required"), which is an easy way to ship a notifier
    that silently never posts.
    """
    facts = [
        {"name": label, "value": _teams_escape(value)} for label, value in _notify_facts(event)
    ]
    source_ip = _teams_escape(event.source_ip or "unknown")
    facts.insert(0, {"name": "Source IP", "value": source_ip})
    facts.insert(1, {"name": "Time", "value": f"{event.timestamp.isoformat()}"})
    if event.honeytoken_id is not None:
        facts.append({"name": "Honeytoken", "value": f"#{event.honeytoken_id} triggered"})

    card = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": _notify_title(event),
        "themeColor": _NOTIFY_COLOUR[event.severity].lstrip("#"),
        "title": f"{_NOTIFY_EMOJI[event.severity]} {_notify_title(event)}",
        "sections": [
            {
                "activityTitle": f"Attacker {source_ip}",
                "activitySubtitle": _honeypot_label(event),
                "facts": facts,
                # Off: every fact value is attacker-chosen, and with markdown
                # on a username like `[reset password](https://evil)` renders
                # as a live link in the SOC channel.
                "markdown": False,
            }
        ],
    }
    body = json.dumps(card, default=str).encode("utf-8")
    return body, {"Content-Type": "application/json", "User-Agent": "HoneyPot-MCP/1.0"}


def render_email(event: PendingEvent, sub: Subscription) -> tuple[str, str]:
    """(subject, body) for an SMTP notification.

    Plain text on purpose. These land in mail clients, ticketing systems and
    phone lock screens with wildly different HTML support, and the content is
    attacker-controlled — rendering it as HTML would be an injection surface
    for no benefit a honeypot alert actually needs.

    Every attacker-derived value is collapsed to one line: a CR/LF inside a
    captured username would otherwise forge body lines ("Severity : low") that
    a reader trusts, and in the subject would make the header unsendable.
    """
    source_ip = _one_line(event.source_ip or "unknown")
    event_type = _one_line(event.event_type)
    subject = (
        f"[HoneyPot {event.severity.value.upper()}] "
        f"{_humanize_event_type(event_type)} from {source_ip}"
    )
    lines = [
        _notify_title(event),
        "",
        f"Source IP   : {source_ip}"
        + (f":{event.source_port}" if event.source_port is not None else ""),
        f"Event type  : {event_type}",
        f"Severity    : {event.severity.value}",
        f"Time (UTC)  : {event.timestamp.isoformat()}",
        "Honeypot ID : "
        + (str(event.honeypot_id) if event.honeypot_id is not None else "none (canary trigger)"),
    ]
    if event.honeytoken_id is not None:
        lines += [
            f"Honeytoken  : #{event.honeytoken_id} TRIGGERED — a planted credential was used.",
        ]
    facts = _notify_facts(event)
    if facts:
        lines += ["", "Captured details:"]
        lines += [f"  {label:<12}: {_one_line(value)}" for label, value in facts]
    lines += [
        "",
        "--",
        "HoneyPot MCP. Use `alerts_get` for the full payload and "
        "`analyze_attacker` to profile this source.",
    ]
    return subject, "\n".join(lines)


# ── Transports ──────────────────────────────────────────────────────────────


async def _post_with_retry(
    client: httpx.AsyncClient,
    url: str,
    body_bytes: bytes,
    headers: dict[str, str],
) -> tuple[bool, str | None]:
    last_err: str | None = None
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            resp = await client.post(url, content=body_bytes, headers=headers, timeout=10.0)
            if 200 <= resp.status_code < 300:
                return True, None
            last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)[:200]
        if attempt < len(_RETRY_DELAYS) - 1:
            await asyncio.sleep(delay)
    return False, last_err


_LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def _parse_smtp_url(url: str) -> dict[str, Any]:
    """`smtp://user:pass@host:587/?from=a@b&to=c@d,e@f&tls=starttls` → kwargs.

    Everything rides in the URL because `Subscription` has exactly one string
    field for a destination, and adding columns for one channel would make the
    schema lopsided. Recipients are comma-separated in the `to` query param.

    Raises ValueError with a message an operator can act on — a mistyped
    notification target that fails silently is the reason nobody trusts alerts.
    """
    from urllib.parse import parse_qs

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("smtp", "smtps"):
        raise ValueError(f"email URL must use smtp:// or smtps:// (got {scheme or 'none'!r})")
    if not parsed.hostname:
        raise ValueError("email URL is missing a host")

    query = parse_qs(parsed.query)
    recipients = [addr.strip() for addr in ",".join(query.get("to", [])).split(",") if addr.strip()]
    if not recipients:
        raise ValueError("email URL needs at least one recipient: ...?to=soc@example.com")
    sender = (query.get("from") or [""])[0].strip() or (parsed.username or "honeypot-mcp")
    if "@" not in sender:
        sender = f"{sender}@{parsed.hostname}"

    # smtps:// means implicit TLS on connect (usually 465); smtp:// upgrades
    # with STARTTLS unless explicitly disabled for a local relay that has none.
    mode = (query.get("tls") or ["starttls" if scheme == "smtp" else "implicit"])[0].lower()
    if mode not in ("starttls", "implicit", "none"):
        raise ValueError(f"email URL tls= must be starttls, implicit or none (got {mode!r})")
    if mode == "none" and parsed.username and parsed.hostname not in _LOOPBACK_NAMES:
        raise ValueError(
            "refusing SMTP AUTH over tls=none to a non-loopback host: the password "
            "would cross the network in clear text. Use tls=starttls or tls=implicit."
        )
    default_port = 465 if mode == "implicit" else 587
    return {
        "host": parsed.hostname,
        "port": parsed.port or default_port,
        "username": parsed.username,
        "password": parsed.password,
        "sender": sender,
        "recipients": recipients,
        "tls": mode,
    }


def _send_email_blocking(cfg: dict[str, Any], subject: str, body: str) -> None:
    """Synchronous SMTP send. Run via `asyncio.to_thread` — `smtplib` blocks,
    and blocking the delivery worker stalls every other subscription."""
    import smtplib
    import ssl
    from email.message import EmailMessage

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["sender"]
    message["To"] = ", ".join(cfg["recipients"])
    # Lets a mail client thread a repeat offender's alerts together instead of
    # scattering them, without us inventing Message-IDs.
    message["X-HoneyPot-MCP"] = __version__
    message.set_content(body)

    context = ssl.create_default_context()
    if cfg["tls"] == "implicit":
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            cfg["host"], cfg["port"], timeout=15, context=context
        )
    else:
        server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=15)
    try:
        if cfg["tls"] == "starttls":
            server.starttls(context=context)
        if cfg["username"]:
            server.login(cfg["username"], cfg["password"] or "")
        server.send_message(message)
    finally:
        with contextlib.suppress(Exception):
            server.quit()


async def _send_email(sub: Subscription, subject: str, body: str) -> tuple[bool, str | None]:
    try:
        cfg = _parse_smtp_url(sub.url)
    except ValueError as e:
        return False, str(e)[:200]
    try:
        await asyncio.to_thread(_send_email_blocking, cfg, subject, body)
        return True, None
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:200]


class _SyslogUDPProtocol(asyncio.DatagramProtocol):
    """Minimal fire-and-forget datagram sender. UDP has no delivery
    confirmation — we report success once `sendto` returns."""

    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.error: Exception | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Cast rather than isinstance: on Python 3.11
        # `_SelectorDatagramTransport` is not a subclass of
        # `asyncio.DatagramTransport` (the MRO changed in 3.12), so an
        # isinstance assert fires on every UDP syslog delivery and asyncio
        # logs it as an unhandled callback exception.
        self.transport = cast(asyncio.DatagramTransport, transport)

    def error_received(self, exc: Exception) -> None:
        self.error = exc


async def _send_syslog_udp(host: str, port: int, body: bytes) -> tuple[bool, str | None]:
    loop = asyncio.get_event_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _SyslogUDPProtocol, remote_addr=(host, port)
        )
        try:
            transport.sendto(body)
            # Give the kernel a tick to flush + report ICMP unreachables.
            await asyncio.sleep(0.05)
        finally:
            transport.close()
        if proto.error is not None:
            return False, str(proto.error)[:200]
        return True, None
    except Exception as e:
        return False, str(e)[:200]


async def _send_syslog_tcp(host: str, port: int, body: bytes) -> tuple[bool, str | None]:
    """TCP-framed syslog. RFC 6587 octet-counting frame:
    `<MSG-LEN> <MSG>` where MSG-LEN is the ASCII byte count.
    """
    framed = f"{len(body)} ".encode() + body
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            try:
                writer.write(framed)
                await writer.drain()
                return True, None
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        except Exception as e:
            last_err = str(e)[:200]
            if attempt < len(_RETRY_DELAYS) - 1:
                await asyncio.sleep(delay)
                continue
            return False, last_err
    return False, "unreachable"


# ── Job + worker ────────────────────────────────────────────────────────────


@dataclass
class _Job:
    event: PendingEvent
    enqueued_at: float = field(default_factory=time.monotonic)


# One subscription may have this many deliveries running at once, and this many
# waiting. A slow destination then costs only itself: the worker never waits on
# it, and anything beyond the backlog is counted and skipped rather than piling
# up in memory.
_SUB_CONCURRENCY = 4
# How long a validated destination is trusted before it is re-resolved.
_DEST_CACHE_SECONDS = 10.0
_MAX_SUB_BACKLOG = 64


class WebhookDelivery:
    def __init__(self) -> None:
        # Two lanes so overflow can shed LOW-severity events in O(1): the
        # worker drains `_high` first, and a full queue discards from `_low`
        # before it ever discards anything that matters.
        self._high: deque[_Job] = deque()
        self._low: deque[_Job] = deque()
        self._wakeup = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._client: httpx.AsyncClient | None = None
        self._throttle = _NotifyThrottle(
            window_seconds=get_settings().notify_throttle_seconds,
            critical_cap=get_settings().notify_critical_per_minute,
            critical_repeat_window=get_settings().notify_critical_repeat_seconds,
        )
        self._sub_sems: dict[int, asyncio.Semaphore] = {}
        self._sub_backlog: dict[int, int] = {}
        self._dest_cache: dict[tuple[str, str, bool], tuple[float, str | None, list[str]]] = {}
        self._inflight: set[asyncio.Task[None]] = set()
        self.dropped_count = 0
        self._dropped_since_log = 0
        self._last_drop_log = 0.0

    @property
    def pending(self) -> int:
        """Events queued for delivery and not yet handed to a subscription."""
        return len(self._high) + len(self._low)

    def _note_drop(self) -> None:
        self.dropped_count += 1
        self._dropped_since_log += 1
        now = time.monotonic()
        if now - self._last_drop_log >= 10.0:
            log.warning(
                "Webhook delivery is shedding events (%d in the last interval, %d total): "
                "a destination is slower than the event rate. Raise `webhook_queue_max` "
                "or fix the slow subscription.",
                self._dropped_since_log,
                self.dropped_count,
            )
            self._last_drop_log = now
            self._dropped_since_log = 0

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            # Drop any cache from a previous run / test so the first delivery
            # reflects the current DB.
            invalidate_subscription_cache()
            self._sub_sems.clear()
            self._client = httpx.AsyncClient()
            self._task = asyncio.create_task(self._run(), name="webhook-delivery")

    async def stop(self) -> None:
        self._stop.set()
        self._wakeup.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except TimeoutError:
                log.warning("Webhook delivery worker did not exit cleanly.")
            self._task = None
        if self._inflight:
            _done, pending = await asyncio.wait(set(self._inflight), timeout=10.0)
            for task in pending:
                task.cancel()
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def enqueue_batch(self, events: list[PendingEvent]) -> None:
        cap = max(int(get_settings().webhook_queue_max), 0)
        for ev in events:
            low = ev.severity is AlertSeverity.LOW
            if cap and self.pending >= cap:
                if self._low:
                    self._low.popleft()
                    self._note_drop()
                elif low:
                    self._note_drop()
                    continue
                else:
                    self._high.popleft()
                    self._note_drop()
            (self._low if low else self._high).append(_Job(event=ev))
        if events:
            self._wakeup.set()

    def _pop(self) -> _Job | None:
        if self._high:
            return self._high.popleft()
        if self._low:
            return self._low.popleft()
        return None

    async def _run(self) -> None:
        while True:
            job = self._pop()
            if job is None:
                if self._stop.is_set():
                    return
                self._wakeup.clear()
                if self.pending:
                    continue
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._wakeup.wait(), timeout=1.0)
                continue
            try:
                await self._deliver(job.event)
            except Exception as e:
                log.warning("Webhook delivery error: %s", e)

    async def _deliver(self, event: PendingEvent) -> None:
        """Fan an event out to every matching subscription without waiting on
        any of them — each delivery runs as its own bounded task."""
        subs = await _active_subscriptions()
        if not subs:
            return

        for sub in subs:
            if not _meets_threshold(event.severity, sub.severity_threshold):
                continue
            backlog = self._sub_backlog.get(sub.id, 0)
            if backlog >= _MAX_SUB_BACKLOG:
                self._note_drop()
                continue
            self._sub_backlog[sub.id] = backlog + 1
            task = asyncio.create_task(self._deliver_one(event, sub), name=f"webhook-{sub.id}")
            self._inflight.add(task)
            task.add_done_callback(self._inflight.discard)

    async def _deliver_one(self, event: PendingEvent, sub: Subscription) -> None:
        try:
            sem = self._sub_sems.setdefault(sub.id, asyncio.Semaphore(_SUB_CONCURRENCY))
            async with sem:
                try:
                    ok, err = await self._dispatch(event, sub)
                except Exception as e:
                    ok, err = False, f"renderer failure: {e!s}"[:200]
                await self._record_outcome(sub.id, ok, err)
        except Exception as e:
            log.warning("Webhook delivery to subscription %s failed: %s", sub.id, e)
        finally:
            left = self._sub_backlog.get(sub.id, 1) - 1
            if left > 0:
                self._sub_backlog[sub.id] = left
            else:
                self._sub_backlog.pop(sub.id, None)

    async def _checked_destination(
        self, sub: Subscription, fmt: str
    ) -> tuple[str | None, list[str]]:
        """`check_destination` with a short per-URL cache, so a burst of events
        to one subscription costs one DNS resolution, not one each. The TTL is
        deliberately brief: it bounds the DNS-rebinding window."""
        now = time.monotonic()
        key = (sub.url, fmt, get_settings().webhook_allow_private_destinations)
        hit = self._dest_cache.get(key)
        if hit is not None and hit[0] > now:
            return hit[1], hit[2]
        refusal, addresses = await check_destination(sub.url, fmt)
        if len(self._dest_cache) >= 256:
            self._dest_cache.clear()
        self._dest_cache[key] = (now + _DEST_CACHE_SECONDS, refusal, addresses)
        return refusal, addresses

    async def _dispatch(self, event: PendingEvent, sub: Subscription) -> tuple[bool, str | None]:
        """Pick the renderer + transport for this subscription's format."""
        fmt = (sub.format or "json").lower()

        # The destination policy is enforced here, on every delivery, not only
        # when the subscription was created: a hostname can be re-pointed at
        # cloud metadata or an internal service after it was accepted, a name
        # that did not resolve at subscribe time can resolve later, and the
        # `webhook_allow_private_destinations` setting can be tightened.
        refusal, addresses = await self._checked_destination(sub, fmt)
        if refusal:
            return False, refusal

        if fmt == "syslog":
            return await self._dispatch_syslog(event, sub, addresses[0] if addresses else None)

        if fmt in _HUMAN_CHANNELS:
            send, suppressed = self._throttle.check(sub.id, event)
            if not send:
                # Not a failure: the event is stored, indexed and queryable —
                # we simply declined to interrupt a human twice for the same
                # thing. Recording it as an error would make a healthy
                # subscription look broken.
                return True, THROTTLED
            return await self._dispatch_human(event, sub, fmt, suppressed)

        # HTTP-shaped formats
        if fmt == "json":
            body, headers = render_json(event, sub)
        elif fmt == "splunk_hec":
            body, headers = render_splunk_hec(event, sub)
        elif fmt == "elastic_ecs":
            body, headers = render_elastic_ecs(event, sub)
        elif fmt == "cef":
            body, headers = render_cef(event, sub)
        elif fmt == "loki":
            body, headers = render_loki(event, sub)
        elif fmt == "datadog":
            body, headers = render_datadog(event, sub)
        else:
            return False, f"unknown format: {fmt}"

        if self._client is None:
            return False, "delivery client not started"
        return await _post_with_retry(self._client, sub.url, body, headers)

    async def _dispatch_human(
        self, event: PendingEvent, sub: Subscription, fmt: str, suppressed: int
    ) -> tuple[bool, str | None]:
        """Slack / Teams / email. Carries the suppressed-since-last count so
        throttling never hides volume, it only stops volume being the delivery
        mechanism."""
        note = (
            f"+{suppressed} similar event(s) suppressed since the last notification"
            if suppressed
            else ""
        )

        if fmt == "email":
            subject, body = render_email(event, sub)
            if note:
                body = f"{body}\n\n({note}.)"
            return await _send_email(sub, subject, body)

        if fmt == "slack":
            payload_bytes, headers = render_slack(event, sub)
            if note:
                doc = json.loads(payload_bytes)
                doc["attachments"][0]["blocks"].append(
                    {"type": "context", "elements": [{"type": "mrkdwn", "text": note}]}
                )
                payload_bytes = json.dumps(doc).encode("utf-8")
        else:  # teams
            payload_bytes, headers = render_teams(event, sub)
            if note:
                doc = json.loads(payload_bytes)
                doc["sections"][0]["facts"].append({"name": "Suppressed", "value": note})
                payload_bytes = json.dumps(doc).encode("utf-8")

        if self._client is None:
            return False, "delivery client not started"
        return await _post_with_retry(self._client, sub.url, payload_bytes, headers)

    async def _dispatch_syslog(
        self, event: PendingEvent, sub: Subscription, connect_host: str | None = None
    ) -> tuple[bool, str | None]:
        """Send via UDP or TCP depending on the URL scheme. `connect_host` is
        the address `check_destination` validated; connecting to it rather
        than re-resolving the hostname closes the rebinding window."""
        parsed = urlparse(sub.url)
        scheme = parsed.scheme.lower()
        host = connect_host or parsed.hostname
        port = parsed.port or 514
        if not host:
            return False, "syslog URL missing host"

        body = render_syslog(event, sub)
        if scheme == "udp":
            return await _send_syslog_udp(host, port, body)
        if scheme == "tcp":
            return await _send_syslog_tcp(host, port, body)
        return False, f"syslog URL must use udp:// or tcp:// (got {scheme!r})"

    async def _record_outcome(self, sub_id: int, ok: bool, err: str | None) -> None:
        async with get_session() as session:
            if ok and err == THROTTLED:
                # Declined on purpose: not a delivery, and not evidence the channel works, so it
                # must not touch delivery_count, last_delivery_at, failure_count or last_error.
                await session.execute(
                    update(Subscription)
                    .where(Subscription.id == sub_id)
                    .values(suppressed_count=Subscription.suppressed_count + 1)
                )
            elif ok:
                await session.execute(
                    update(Subscription)
                    .where(Subscription.id == sub_id)
                    .values(
                        delivery_count=Subscription.delivery_count + 1,
                        last_delivery_at=datetime.now(UTC),
                        failure_count=0,
                        last_error=None,
                    )
                )
            else:
                await session.execute(
                    update(Subscription)
                    .where(Subscription.id == sub_id)
                    .values(
                        failure_count=Subscription.failure_count + 1,
                        last_error=(err or "")[:500],
                    )
                )


_delivery: WebhookDelivery | None = None


def webhook_dropped_count() -> int:
    """Events the delivery layer has shed (queue overflow or a backlogged
    subscription). Counterpart to the event buffer's dropped counter, for the
    metrics endpoint."""
    return get_delivery().dropped_count


def get_delivery() -> WebhookDelivery:
    global _delivery
    if _delivery is None:
        _delivery = WebhookDelivery()
    return _delivery
