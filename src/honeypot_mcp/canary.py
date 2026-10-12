"""Canary callback HTTP server.

Receives hits on canary URLs (`/t/{token_id}`), kubectl requests against a
kubeconfig token (`/t/{token_id}/version`, `/t/{token_id}/api`, ...) and PDF
pixel-tracker requests (`/t/{token_uid}.png`). On a match, records a CRITICAL
alert and an AttackerEvent linked to the honeytoken, and marks the token
triggered.

Every trigger is handed to the event buffer, so it reaches the same flusher
as any honeypot event: the Alert and AttackerEvent rows are written there, the
token is marked triggered there, and the `on_flush` hook fans the event out to
webhook subscribers (Slack, Teams, email, SIEM formats) and kicks off
auto-enrichment. Writing the rows directly, as this module once did, produced
alerts that no notification channel ever saw.

This server is lifecycle-managed by `server.py:lifespan`. Bind host/port come
from settings: `canary_callback_host`, `canary_callback_port`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from aiohttp import web
from sqlalchemy import func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.http_identity import NGINX_BANNER, identity_runner, server_identity_middleware
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, clamp_payload, get_buffer
from honeypot_mcp.storage.models import (
    AlertSeverity,
    Honeytoken,
    HoneytokenStatus,
    HoneytokenType,
)

log = logging.getLogger(__name__)

# 1x1 transparent PNG, base64-encoded (decoded at import).
_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII="
)

# Per-source sliding-window rate limit. The callback server is a public-facing
# HTTP endpoint that returns 200 OK to anyone — without a limit, an attacker
# who guesses a canary URL can hammer it 10k req/sec, stressing the buffer
# flusher and potentially DOSing real alert delivery.
_RATE_WINDOW_SECONDS = 60.0
_RATE_MAX_PER_WINDOW = 30  # 30 hits/source/min is generous for legitimate canary use
# Global ceiling on hits that matched a real token and so cost an alert and a
# database write. The per-source limit alone does nothing against a botnet: ten
# thousand addresses at 30 hits each is still 300k a minute. It is applied only
# after the token lookup: counted on every request, a flood of random ids would
# exhaust it and the canary would silently ignore the one hit that matters.
_GLOBAL_RATE_MAX_PER_WINDOW = 600
# Above this many tracked sources we sweep out decayed windows.
_RATE_STATE_MAX_IPS = 10_000
_rate_state: dict[str, deque[float]] = defaultdict(deque)
_global_hits: deque[float] = deque()
# The sweep walks every tracked source, so running it on every request once the
# table is large would make each request O(N) — the very load a flood wants to
# create. It runs only once the table has grown by half a table's worth since
# the last sweep.
_rate_sweep_threshold = _RATE_STATE_MAX_IPS


def _rate_key(src_ip: str) -> str:
    """Bucket an address for rate limiting.

    An IPv6 end-site is routinely handed a whole /64, so keying by full address
    gives one host 2^64 independent budgets. IPv4-mapped IPv6 collapses onto its
    IPv4 address.
    """
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return src_ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        prefix = ipaddress.IPv6Address((int(addr) >> 64) << 64)
        return f"{prefix}/64"
    return src_ip


def _rate_limit_check(src_ip: str) -> bool:
    """Return True if this source is over the rate limit and should be dropped.

    Sliding-window count via a deque of monotonic timestamps per source.
    """
    global _rate_sweep_threshold
    now = time.monotonic()
    key = _rate_key(src_ip)
    window = _rate_state[key]
    cutoff = now - _RATE_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= _RATE_MAX_PER_WINDOW:
        return True
    window.append(now)
    # Evict fully-decayed windows so the dict doesn't grow unbounded with one
    # deque per source ever seen on a long-lived public deployment.
    if len(_rate_state) > _rate_sweep_threshold:
        _evict_stale_rate_windows(cutoff)
        # Still over the cap with live windows only: shed the oldest-seen
        # sources rather than let memory follow the attacker's address count.
        while len(_rate_state) > _RATE_STATE_MAX_IPS:
            del _rate_state[next(iter(_rate_state))]
        _rate_sweep_threshold = max(
            _RATE_STATE_MAX_IPS, len(_rate_state) + _RATE_STATE_MAX_IPS // 2
        )
    return False


def _evict_stale_rate_windows(cutoff: float) -> None:
    """Drop sources whose entire window has decayed below `cutoff` (no hits in the
    last `_RATE_WINDOW_SECONDS`). Called only when the table grows large."""
    stale = [ip for ip, w in _rate_state.items() if not w or w[-1] < cutoff]
    for ip in stale:
        del _rate_state[ip]


def _global_rate_limit_check() -> bool:
    """True if the server as a whole has taken too many hits this window."""
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW_SECONDS
    while _global_hits and _global_hits[0] < cutoff:
        _global_hits.popleft()
    if len(_global_hits) >= _GLOBAL_RATE_MAX_PER_WINDOW:
        return True
    _global_hits.append(now)
    return False


def _over_limit(src_ip: str) -> bool:
    """Per-source limit only. The global ceiling is applied after the token
    lookup (see `_global_rate_limit_check`), so requests for ids that match
    nothing can never consume the budget real triggers need."""
    return _rate_limit_check(src_ip)


# ── Token lookup index ─────────────────────────────────────────────────────

_CANARY_TYPES: tuple[HoneytokenType, ...] = (
    HoneytokenType.CANARY_URL,
    HoneytokenType.FILE,
    HoneytokenType.KUBECONFIG,
    HoneytokenType.SLACK_WEBHOOK,
)

# The callback server is unauthenticated and public, so a lookup must not cost a
# table scan per hit. `_index` maps the identifier carried in a URL
# (`token_meta.token_id` / `token_meta.token_uid`) to the token's primary key and
# type. Only identity lives here: whether the token is still live is read from
# the database at trigger time, so revocation takes effect immediately and never
# waits on this cache.
_INDEX_TTL_SECONDS = 30.0


@dataclass(frozen=True)
class _IndexEntry:
    token_pk: int
    type: HoneytokenType


_index: dict[str, _IndexEntry] = {}
_index_loaded_at: float = 0.0
# (engine identity, row count, highest id) of the honeytokens table when the
# index was built. The engine identity catches a swapped database (restored
# backup, test fixtures), where count and highest id can coincide by chance.
_index_signature: tuple[int, int, int] | None = None
_index_lock: asyncio.Lock | None = None
_index_lock_loop: asyncio.AbstractEventLoop | None = None


def invalidate_token_index() -> None:
    """Force the next lookup to rebuild the index."""
    global _index_loaded_at, _index_signature
    _index_loaded_at = 0.0
    _index_signature = None


def _get_index_lock() -> asyncio.Lock:
    # An asyncio lock binds to the loop it first contends on; this module
    # outlives any one loop (every test gets a fresh one), so rebuild on change.
    global _index_lock, _index_lock_loop
    loop = asyncio.get_running_loop()
    if _index_lock is None or _index_lock_loop is not loop:
        _index_lock = asyncio.Lock()
        _index_lock_loop = loop
    return _index_lock


async def _table_signature(session: Any) -> tuple[int, int, int]:
    row = (await session.execute(select(func.count(), func.max(Honeytoken.id)))).one()
    return id(session.bind), int(row[0] or 0), int(row[1] or 0)


async def _refresh_index(*, force: bool) -> None:
    """Rebuild the index.

    `force` rebuilds unconditionally (TTL expiry). Otherwise it first compares a
    one-row aggregate against the table state the index was built from, and
    rebuilds only if tokens were created or deleted since — which is how a token
    created seconds ago (possibly by another process) becomes reachable without
    waiting out the TTL, at the price of one trivial query per unknown id.
    """
    global _index, _index_loaded_at, _index_signature
    async with _get_index_lock():
        if force and time.monotonic() - _index_loaded_at <= _INDEX_TTL_SECONDS:
            return  # someone else refreshed while we waited for the lock
        async with get_session() as session:
            signature = await _table_signature(session)
            if not force and signature == _index_signature:
                return
            rows = (
                await session.execute(
                    select(Honeytoken.id, Honeytoken.type, Honeytoken.token_meta).where(
                        Honeytoken.type.in_(_CANARY_TYPES)
                    )
                )
            ).all()
        fresh: dict[str, _IndexEntry] = {}
        for token_pk, token_type, meta in rows:
            for key in ("token_id", "token_uid"):
                ident = (meta or {}).get(key)
                if isinstance(ident, str) and ident:
                    fresh[ident] = _IndexEntry(token_pk, token_type)
        _index = fresh
        _index_signature = signature
        _index_loaded_at = time.monotonic()


async def _find_token_by_id(
    token_id: str, types: tuple[HoneytokenType, ...] | None = None
) -> int | None:
    """Resolve a request's token identifier to a honeytoken primary key.

    By default matches CANARY_URL, FILE, KUBECONFIG, and SLACK_WEBHOOK — all
    of which store the lookup identifier in `token_meta.token_id` (or
    `token_meta.token_uid` for FILE).

    Pass an explicit `types` tuple to restrict the match (e.g. the Slack
    webhook handler only wants SLACK_WEBHOOK matches so a token_id collision
    with a CANARY_URL doesn't fire the wrong alert type).
    """
    search_types = types or _CANARY_TYPES
    if time.monotonic() - _index_loaded_at > _INDEX_TTL_SECONDS:
        await _refresh_index(force=True)
    entry = _index.get(token_id)
    if entry is None:
        await _refresh_index(force=False)
        entry = _index.get(token_id)
    if entry is not None and entry.type in search_types:
        return entry.token_pk
    return None


@dataclass(frozen=True)
class _LiveToken:
    id: int
    type: HoneytokenType
    label: str
    planted_at: str


async def _load_live_token(token_pk: int) -> _LiveToken | None:
    """Read the token's current row; None if it is gone or revoked.

    TRIGGERED tokens stay live: the first hit is often a link prefetcher or a
    mail scanner rather than the intruder, and a token that went quiet after it
    would hide the real access that follows.
    """
    async with get_session() as session:
        live = await session.get(Honeytoken, token_pk)
        if live is None or live.status == HoneytokenStatus.REVOKED:
            return None
        return _LiveToken(
            id=live.id,
            type=live.type,
            label=live.label,
            planted_at=str((live.token_meta or {}).get("planted_at", "")),
        )


async def _emit_trigger(
    live: _LiveToken, event_type: str, src_ip: str, trigger_meta: dict[str, Any]
) -> None:
    """Hand a honeytoken trigger to the event buffer.

    Submitted straight to the buffer rather than through `submit_event`: that
    function runs suppression, whose rules are written for honeypot noise and
    must not be able to discard a honeytoken trip, and credential matching,
    which would re-tag an event that is already a trigger. The flusher writes the
    Alert and AttackerEvent, marks the token triggered (it keys on
    `honeytoken_id` plus the `honeytoken_triggered_` prefix, so exactly once per
    event), and invokes the `on_flush` hook that feeds webhook delivery.
    """
    payload, _size = clamp_payload(
        {
            "token_id": live.id,
            "token_label": live.label,
            "token_type": live.type.value,
            # Where it was planted, if the operator recorded it. This is
            # what turns "a token fired" into "someone reached the finance
            # share" — the first question triage asks.
            "planted_at": live.planted_at,
            **trigger_meta,
        }
    )
    await get_buffer().submit(
        PendingEvent(
            honeypot_id=None,
            source_ip=src_ip,
            source_port=None,
            event_type=event_type,
            # Same size bound `submit_event` applies to every other event.
            payload=payload,
            severity=AlertSeverity.CRITICAL,
            honeytoken_id=live.id,
        )
    )


_MAX_HEADER_VALUE_CHARS = 1024
_MAX_HEADERS = 64


def _headers_snapshot(request: web.Request) -> dict[str, str]:
    return {k: v[:_MAX_HEADER_VALUE_CHARS] for k, v in list(request.headers.items())[:_MAX_HEADERS]}


async def _trigger(token_pk: int, request: web.Request) -> None:
    src_ip = request.remote or "0.0.0.0"
    live = await _load_live_token(token_pk)
    if live is None:
        return
    user_agent = request.headers.get("User-Agent", "")
    trigger_meta: dict[str, Any] = {
        "trigger_ip": src_ip,
        "user_agent": user_agent,
        "referer": request.headers.get("Referer", ""),
        "headers": _headers_snapshot(request),
        "path": request.path,
        "host_header": request.headers.get("Host", ""),
    }
    await _emit_trigger(live, f"honeytoken_triggered_{live.type.value}", src_ip, trigger_meta)
    log.warning(
        "Honeytoken TRIGGERED — id=%s type=%s label=%r src=%s ua=%r",
        live.id,
        live.type.value,
        live.label,
        src_ip,
        user_agent,
    )


async def _handle_token(request: web.Request) -> web.Response:
    src_ip = request.remote or "0.0.0.0"
    raw = request.match_info.get("token_id", "")
    if _over_limit(src_ip):
        # Still return 200 OK — surfacing 429 to the attacker would
        # fingerprint the limit. We just skip the trigger logic.
        log.debug("Rate-limited canary hit from %s", src_ip)
        if raw.endswith(".png"):
            return web.Response(body=_PIXEL, content_type="image/png")
        return web.Response(text="OK", content_type="text/plain")

    # PDF tracker uses /t/<uid>.png — strip extension for matching.
    token_id = raw.split(".", 1)[0]
    token_pk = await _find_token_by_id(token_id)
    if token_pk is not None and not _global_rate_limit_check():
        await _trigger(token_pk, request)

    if raw.endswith(".png"):
        return web.Response(body=_PIXEL, content_type="image/png")
    # Generic 200 — give attackers no signal that they hit a canary.
    return web.Response(text="OK", content_type="text/plain")


# ── kubectl against a kubeconfig token ─────────────────────────────────────

# kubeconfig tokens point `server:` at `<canary>/t/<token_id>`, and kubectl
# appends its API paths to that base. The responses below are what kubectl needs
# to get past discovery; they match the decoy `engines/kubernetes.py` API server
# (same version) so the two don't disagree about what cluster this is.
_K8S_VERSION_DOC: dict[str, str] = {
    "major": "1",
    "minor": "28",
    "gitVersion": "v1.28.4",
    "gitCommit": "bae2c62678db2b5053817bc97181fcc2e8388103",
    "gitTreeState": "clean",
    "buildDate": "2023-11-15T16:48:54Z",
    "goVersion": "go1.20.11",
    "compiler": "gc",
    "platform": "linux/amd64",
}
_K8S_API_VERSIONS: dict[str, Any] = {
    "kind": "APIVersions",
    "versions": ["v1"],
    "serverAddressByClientCIDRs": [],
}
_K8S_API_GROUPS: dict[str, Any] = {
    "kind": "APIGroupList",
    "apiVersion": "v1",
    "groups": [
        {
            "name": group,
            "versions": [{"groupVersion": f"{group}/v1", "version": "v1"}],
            "preferredVersion": {"groupVersion": f"{group}/v1", "version": "v1"},
        }
        for group in ("apps", "batch", "rbac.authorization.k8s.io", "networking.k8s.io")
    ],
}
_K8S_CORE_RESOURCES: dict[str, Any] = {
    "kind": "APIResourceList",
    "groupVersion": "v1",
    "resources": [
        {
            "name": name,
            "singularName": "",
            "namespaced": namespaced,
            "kind": kind,
            "verbs": ["get", "list"],
        }
        for name, namespaced, kind in (
            ("namespaces", False, "Namespace"),
            ("nodes", False, "Node"),
            ("pods", True, "Pod"),
            ("secrets", True, "Secret"),
            ("services", True, "Service"),
        )
    ],
}
_K8S_FORBIDDEN: dict[str, Any] = {
    "kind": "Status",
    "apiVersion": "v1",
    "metadata": {},
    "status": "Failure",
    "message": 'forbidden: User "system:anonymous" cannot get path',
    "reason": "Forbidden",
    "details": {},
    "code": 403,
}


def _kubernetes_response(tail: str) -> web.Response:
    """The reply kubectl expects for `tail`, the path after `/t/<token_id>`."""
    path = "/" + tail.strip("/")
    if path == "/version":
        return web.json_response(_K8S_VERSION_DOC)
    if path == "/api":
        return web.json_response(_K8S_API_VERSIONS)
    if path == "/apis":
        return web.json_response(_K8S_API_GROUPS)
    if path == "/api/v1":
        return web.json_response(_K8S_CORE_RESOURCES)
    if path in ("/healthz", "/livez", "/readyz"):
        return web.Response(text="ok", content_type="text/plain")
    if path.startswith(("/api/", "/apis/", "/openapi", "/version/")):
        return web.json_response(_K8S_FORBIDDEN, status=403)
    # Anything else under a canary URL (an appended path on a link, say) stays
    # the same bare 200 as the token's own URL.
    return web.Response(text="OK", content_type="text/plain")


async def _handle_token_tail(request: web.Request) -> web.Response:
    """`/t/{token_id}/{tail}` — kubectl's requests against a kubeconfig token.

    The response depends only on the path, never on whether the token matched,
    so it can't be used to probe for valid ids.
    """
    src_ip = request.remote or "0.0.0.0"
    response = _kubernetes_response(request.match_info.get("tail", ""))
    if _over_limit(src_ip):
        log.debug("Rate-limited canary hit from %s", src_ip)
        return response

    token_id = request.match_info.get("token_id", "").split(".", 1)[0]
    token_pk = await _find_token_by_id(token_id)
    if token_pk is not None and not _global_rate_limit_check():
        await _trigger(token_pk, request)
    return response


async def serve_if_token(request: web.Request) -> web.Response | None:
    """For a web honeypot that is reachable from outside: answer `/t/<id>` if `<id>` is a planted
    canary token, else None so the caller carries on as an ordinary web server.

    The callback server binds loopback and the host firewall closes it, so a canary URL planted in
    decoy content could never call back. Serving the same paths from the honeypot's own public port
    needs no new exposure. Unlike the loopback server, an unknown id returns None (a 404 from the
    caller) instead of a generic 200: on a public web server, every `/t/<anything>` answering 200
    would be a fingerprint of its own, and ids are 128-bit so there is nothing to enumerate.
    """
    if not request.path.startswith("/t/"):
        return None
    raw, slash, tail = request.path[3:].partition("/")
    token_pk = await _find_token_by_id(raw.split(".", 1)[0])
    if token_pk is None:
        return None
    if not _over_limit(request.remote or "0.0.0.0") and not _global_rate_limit_check():
        await _trigger(token_pk, request)
    if slash:  # kubectl against a kubeconfig token: the path after /t/<id>
        return _kubernetes_response(tail)
    if raw.endswith(".png"):
        return web.Response(body=_PIXEL, content_type="image/png")
    return web.Response(text="OK", content_type="text/plain")


_PLANTED_TTL_SECONDS = 30.0
_planted_url: tuple[float, str | None] = (0.0, None)


async def planted_canary_url() -> str | None:
    """The URL of an active canary-URL token, for decoy content a scanner reads and may follow.

    Cached for 30 s like the credential index, so a decoy hit costs no query; a token revoked in
    the last 30 s may still be served once, which is harmless (a revoked token no longer fires).
    """
    global _planted_url
    loaded, value = _planted_url
    if loaded and time.monotonic() - loaded < _PLANTED_TTL_SECONDS:
        return value
    try:
        async with get_session() as session:
            row = (
                (
                    await session.execute(
                        select(Honeytoken)
                        .where(
                            Honeytoken.type == HoneytokenType.CANARY_URL,
                            Honeytoken.status.in_(
                                (HoneytokenStatus.ACTIVE, HoneytokenStatus.TRIGGERED)
                            ),
                        )
                        .order_by(Honeytoken.id)
                        .limit(1)
                    )
                )
                .scalars()
                .first()
            )
        value = (row.token_meta or {}).get("full_url") if row is not None else None
    except Exception:  # noqa: BLE001 - decoy content must never fail a request
        log.debug("planted canary lookup failed", exc_info=True)
        return value
    _planted_url = (time.monotonic(), value)
    return value


async def _handle_root(_request: web.Request) -> web.Response:
    return web.Response(text="OK", content_type="text/plain")


async def _handle_slack_webhook(request: web.Request) -> web.Response:
    """Slack-shaped webhook URL `/services/T<id>/B<id>/<token_id>`.

    SlackWebhookProvider tokens point at this path. We route the trailing
    token_id through the same trigger machinery as `/t/<token_id>`. Returns
    a Slack-flavoured `ok` response on match so attackers think their test
    POST succeeded — keeps them engaged for follow-up exfiltration.
    """
    token_id = request.match_info.get("token_id", "")
    src_ip = request.remote or "0.0.0.0"
    if _over_limit(src_ip):
        return web.Response(text="ok", content_type="text/plain")

    token_pk = await _find_token_by_id(token_id, types=(HoneytokenType.SLACK_WEBHOOK,))
    if token_pk is not None and not _global_rate_limit_check():
        await _trigger(token_pk, request)
    # Real Slack webhooks reply `200 OK` with body `ok` on accepted posts.
    return web.Response(text="ok", content_type="text/plain")


# ── Cloud audit-log ingest ─────────────────────────────────────────────────

# CloudTrail / Azure Activity / GCP Audit events forwarded one at a time are a
# few KB. The cap is checked against Content-Length before the body is read, so
# an oversized POST is refused without being buffered or HMAC'd.
_MAX_CLOUD_EVENT_BYTES = 256 * 1024


async def _read_body_capped(request: web.Request, cap: int) -> bytes | None:
    """The request body, or None if it exceeds `cap` bytes.

    Trusts Content-Length only to refuse early; chunked uploads (no length) are
    counted as they stream so they can't bypass the cap.
    """
    declared = getattr(request, "content_length", None)
    if declared is not None and declared > cap:
        return None
    buf = bytearray()
    async for chunk in request.content.iter_chunked(64 * 1024):
        buf += chunk
        if len(buf) > cap:
            return None
    return bytes(buf)


def _clean_ip(value: Any) -> str | None:
    """`value` as a normalised IP string, or None if it isn't one."""
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


async def _handle_cloud_event(request: web.Request) -> web.Response:
    """Ingest endpoint for forwarded cloud audit-log events.

    Forwarder workflow:
      1. CloudTrail / Azure Activity Log / GCP Audit Log → Cloud
         function / Lambda / Pub/Sub trigger.
      2. The trigger HMAC-SHA256-signs the raw JSON body with the shared
         `cloud_event_hmac_secret` and POSTs it here.
      3. We compare-secure the signature, then `match_cloud_event`s the
         payload against cloud-credential tokens. On match we fire
         the same CRITICAL alert + AttackerEvent trail as a canary URL hit.

    Returns 202 Accepted regardless of match (don't leak match state to
    a potentially attacker-controlled forwarder). 401 on signature
    mismatch, 503 if the operator hasn't configured a secret yet, 413 if the
    body is over the size cap.
    """
    settings = get_settings()
    secret = settings.cloud_event_hmac_secret
    if not secret:
        # Refuse to operate without an opt-in shared secret. An unsigned
        # ingest endpoint is an open trigger relay for arbitrary alert spam.
        return web.json_response({"error": "cloud_event_hmac_secret not configured"}, status=503)

    provided_sig = request.headers.get("X-HoneyPot-Signature", "")
    if not provided_sig:
        return web.json_response({"error": "invalid signature"}, status=401)

    raw = await _read_body_capped(request, _MAX_CLOUD_EVENT_BYTES)
    if raw is None:
        return web.json_response({"error": "payload too large"}, status=413)

    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    # Compare as bytes: `compare_digest` raises TypeError on a non-ASCII `str`,
    # which an unauthenticated caller could provoke with one header value.
    if not hmac.compare_digest(
        provided_sig.encode("utf-8", errors="replace"), expected.encode("ascii")
    ):
        return web.json_response({"error": "invalid signature"}, status=401)

    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return web.json_response({"error": "invalid JSON"}, status=400)

    if not isinstance(event, dict):
        return web.json_response({"error": "expected JSON object"}, status=400)

    # Match against cloud-credential tokens via the central index.
    from honeypot_mcp.token_matchers import match_cloud_event

    token_id, source = await match_cloud_event(event)
    if token_id is not None:
        # `_trigger_cloud` re-reads the row, so a token revoked since the matcher
        # index was built does not fire.
        await _trigger_cloud(token_id, request, event, source or "unknown")

    # Always 202 — don't leak whether the event matched.
    return web.json_response({"accepted": True}, status=202)


async def _trigger_cloud(
    token_pk: int, request: web.Request, event: dict[str, Any], source: str
) -> None:
    """Alert path for cloud-event matches. Mirrors `_trigger()` but the
    trigger_meta captures the forwarded event itself rather than HTTP request
    headers, since the actual attacker is on the cloud side, not directly
    hitting our endpoint."""
    live = await _load_live_token(token_pk)
    if live is None:
        return
    forwarder_ip = request.remote or "0.0.0.0"
    # Pull out the attacker IP from the cloud event if present — CloudTrail
    # has `sourceIPAddress`, Azure has `callerIpAddress`, GCP has
    # `requestMetadata.callerIp`. Only a syntactically valid address is used:
    # CloudTrail also reports AWS service names ("ec2.amazonaws.com") there, and
    # the value ends up in IP-keyed tables and block-list exports.
    request_metadata = event.get("requestMetadata")
    gcp_ip = request_metadata.get("callerIp") if isinstance(request_metadata, dict) else None
    cloud_ip = (
        _clean_ip(event.get("sourceIPAddress"))
        or _clean_ip(event.get("callerIpAddress"))
        or _clean_ip(gcp_ip)
    )
    attacker_ip = cloud_ip or forwarder_ip

    trigger_meta: dict[str, Any] = {
        "trigger_ip": attacker_ip,
        "forwarder_ip": forwarder_ip,
        "source_cloud": source,
        "raw_event": event,
    }
    await _emit_trigger(
        live,
        f"honeytoken_triggered_{live.type.value}_via_{source}",
        attacker_ip,
        trigger_meta,
    )
    log.warning(
        "Cloud honeytoken TRIGGERED — id=%s type=%s label=%r source=%s attacker=%s",
        live.id,
        live.type.value,
        live.label,
        source,
        attacker_ip,
    )


def build_app() -> web.Application:
    # The whole point of the bare `200 OK` responses below is that a triggered
    # token looks like an ordinary web resource. aiohttp's default
    # `Server: Python/3.x aiohttp/3.y.z` banner defeats that on its own, so
    # this server presents as stock nginx instead.
    app = web.Application(middlewares=[server_identity_middleware(NGINX_BANNER)])
    app.router.add_get("/", _handle_root)
    app.router.add_get("/t/{token_id}", _handle_token)
    # kubectl appends its API paths to the kubeconfig token's `server:` URL
    # (`/t/<id>/version`, `/t/<id>/api`, ...), which `{token_id}` alone can't
    # match because it stops at `/`. Any method: kubectl also POSTs (e.g.
    # access reviews).
    app.router.add_route("*", "/t/{token_id}/{tail:.*}", _handle_token_tail)
    # Slack-shaped webhook path. Real Slack uses
    # `hooks.slack.com/services/T.../B.../<secret>` and attackers expect
    # the same path shape; route the trailing component through the
    # Slack-webhook trigger handler.
    app.router.add_route("*", "/services/{team_id}/{bot_id}/{token_id}", _handle_slack_webhook)
    # HMAC-signed cloud audit log ingest. The operator configures their
    # CloudTrail / Azure Activity / GCP Audit forwarder to POST signed
    # events here; events matching a planted credential token fire a
    # CRITICAL alert.
    app.router.add_post("/cloud-event", _handle_cloud_event)
    return app


async def start_canary_server() -> web.AppRunner | None:
    """Start the canary callback server. Returns the runner so caller can shut it down,
    or None if the port couldn't be bound (logged but non-fatal)."""
    settings = get_settings()
    host = settings.canary_callback_host
    port = settings.canary_callback_port

    runner = identity_runner(build_app(), NGINX_BANNER)
    try:
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        log.info("Canary callback server listening on %s:%d", host, port)
        return runner
    except OSError as e:
        log.warning(
            "Canary callback server could not bind %s:%d (%s) — canary tokens will not trigger.",
            host,
            port,
            e,
        )
        await runner.cleanup()
        return None
