"""Outbound webhook + SIEM delivery.

Every flushed alert that meets a subscription's severity threshold is
serialised into the subscription's chosen `format` and delivered via the
appropriate transport. Seven formats are supported:

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

Delivery runs in a background asyncio task drained from a queue so slow
webhook endpoints can never back-pressure the honeypot data path. HTTP
deliveries retry with exponential backoff (1s, 5s, 30s); UDP syslog is
fire-and-forget (UDP has no retry semantics) but failures are still
recorded against `failure_count`. The `last_error` column gives operators
a one-line failure reason without needing log access.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse

import httpx
from sqlalchemy import select, update

from honeypot_mcp import __version__
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
    """CEF header values escape `|` and `\\`; extension values escape `=`."""
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n")


def _cef_ext_escape(value: str) -> str:
    """CEF extension values escape `=`, `\\`, and newlines."""
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")


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


class WebhookDelivery:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[_Job] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            # Drop any cache from a previous run / test so the first delivery
            # reflects the current DB.
            invalidate_subscription_cache()
            self._client = httpx.AsyncClient()
            self._task = asyncio.create_task(self._run(), name="webhook-delivery")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10.0)
            except TimeoutError:
                log.warning("Webhook delivery worker did not exit cleanly.")
            self._task = None
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def enqueue_batch(self, events: list[PendingEvent]) -> None:
        for ev in events:
            await self._queue.put(_Job(event=ev))

    async def _run(self) -> None:
        while True:
            try:
                job = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except TimeoutError:
                if self._stop.is_set() and self._queue.empty():
                    return
                continue
            try:
                await self._deliver(job.event)
            except Exception as e:
                log.warning("Webhook delivery error: %s", e)

    async def _deliver(self, event: PendingEvent) -> None:
        subs = await _active_subscriptions()
        if not subs:
            return

        for sub in subs:
            if not _meets_threshold(event.severity, sub.severity_threshold):
                continue
            try:
                ok, err = await self._dispatch(event, sub)
            except Exception as e:
                ok, err = False, f"renderer failure: {e!s}"[:200]
            await self._record_outcome(sub.id, ok, err)

    async def _dispatch(self, event: PendingEvent, sub: Subscription) -> tuple[bool, str | None]:
        """Pick the renderer + transport for this subscription's format."""
        fmt = (sub.format or "json").lower()

        if fmt == "syslog":
            return await self._dispatch_syslog(event, sub)

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

    async def _dispatch_syslog(
        self, event: PendingEvent, sub: Subscription
    ) -> tuple[bool, str | None]:
        """Send via UDP or TCP depending on the URL scheme."""
        parsed = urlparse(sub.url)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
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
            if ok:
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


def get_delivery() -> WebhookDelivery:
    global _delivery
    if _delivery is None:
        _delivery = WebhookDelivery()
    return _delivery
