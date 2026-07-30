"""Canary callback HTTP server.

Receives hits on canary URLs (`/t/{token_id}`) and PDF pixel-tracker requests
(`/t/{token_uid}.png`). On a match, marks the honeytoken as triggered, records
a CRITICAL alert, and creates an AttackerEvent linked to the token.

This server is lifecycle-managed by `server.py:lifespan`. Bind host/port come
from settings: `canary_callback_host`, `canary_callback_port`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from collections import defaultdict, deque
from typing import Any

from aiohttp import web
from sqlalchemy import select

from honeypot_mcp.config import get_settings
from honeypot_mcp.http_identity import NGINX_BANNER, identity_runner, server_identity_middleware
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    AlertSeverity,
    AttackerEvent,
    Honeytoken,
    HoneytokenStatus,
    HoneytokenType,
)

log = logging.getLogger(__name__)

# 1x1 transparent PNG, base64-encoded (decoded at import).
_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII="
)

# Per-IP sliding-window rate limit. The callback server is a public-facing
# HTTP endpoint that returns 200 OK to anyone — without a limit, an attacker
# who guesses a canary URL can hammer it 10k req/sec, stressing the buffer
# flusher and potentially DOSing real alert delivery.
_RATE_WINDOW_SECONDS = 60.0
_RATE_MAX_PER_WINDOW = 30  # 30 hits/IP/min is generous for legitimate canary use
# Above this many tracked IPs we sweep out decayed windows on the next hit.
_RATE_STATE_MAX_IPS = 10_000
_rate_state: dict[str, deque[float]] = defaultdict(deque)


def _rate_limit_check(src_ip: str) -> bool:
    """Return True if this IP is over the rate limit and should be dropped.

    Sliding-window count via a deque of monotonic timestamps per IP.
    """
    now = time.monotonic()
    window = _rate_state[src_ip]
    cutoff = now - _RATE_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= _RATE_MAX_PER_WINDOW:
        return True
    window.append(now)
    # Evict fully-decayed windows so the dict doesn't grow unbounded with one
    # deque per source IP ever seen on a long-lived public deployment.
    if len(_rate_state) > _RATE_STATE_MAX_IPS:
        _evict_stale_rate_windows(cutoff)
    return False


def _evict_stale_rate_windows(cutoff: float) -> None:
    """Drop IPs whose entire window has decayed below `cutoff` (no hits in the
    last `_RATE_WINDOW_SECONDS`). Called only when the table grows large."""
    stale = [ip for ip, w in _rate_state.items() if not w or w[-1] < cutoff]
    for ip in stale:
        del _rate_state[ip]


async def _find_token_by_id(
    token_id: str, types: tuple[HoneytokenType, ...] | None = None
) -> Honeytoken | None:
    """Match a request token_id against active honeytokens of the given types.

    By default matches CANARY_URL, FILE, KUBECONFIG, and SLACK_WEBHOOK — all
    of which store the lookup identifier in `token_meta.token_id` (or
    `token_meta.token_uid` for FILE).

    Pass an explicit `types` tuple to restrict the match (e.g. the Slack
    webhook handler only wants SLACK_WEBHOOK matches so a token_id collision
    with a CANARY_URL doesn't fire the wrong alert type).
    """
    search_types = types or (
        HoneytokenType.CANARY_URL,
        HoneytokenType.FILE,
        HoneytokenType.KUBECONFIG,
        HoneytokenType.SLACK_WEBHOOK,
    )
    async with get_session() as session:
        result = await session.execute(
            select(Honeytoken).where(
                Honeytoken.status == HoneytokenStatus.ACTIVE,
                Honeytoken.type.in_(search_types),
            )
        )
        for t in result.scalars().all():
            meta = t.token_meta or {}
            if meta.get("token_id") == token_id or meta.get("token_uid") == token_id:
                return t
    return None


async def _trigger(token: Honeytoken, request: web.Request) -> None:
    src_ip = request.remote or "0.0.0.0"
    user_agent = request.headers.get("User-Agent", "")
    referer = request.headers.get("Referer", "")
    trigger_meta: dict[str, Any] = {
        "trigger_ip": src_ip,
        "user_agent": user_agent,
        "referer": referer,
        "headers": dict(request.headers),
        "path": request.path,
        "host_header": request.headers.get("Host", ""),
    }
    async with get_session() as session:
        # Re-fetch in this session to avoid cross-session detached state.
        live = await session.get(Honeytoken, token.id)
        if not live or live.status != HoneytokenStatus.ACTIVE:
            return
        await queries.mark_honeytoken_triggered(session, live.id, trigger_meta)
        await queries.create_alert(
            session,
            honeypot_id=None,
            source_ip=src_ip,
            source_port=None,
            event_type=f"honeytoken_triggered_{live.type.value}",
            payload={
                "token_id": live.id,
                "token_label": live.label,
                "token_type": live.type.value,
                # Where it was planted, if the operator recorded it. This is
                # what turns "a token fired" into "someone reached the finance
                # share" — the first question triage asks.
                "planted_at": (live.token_meta or {}).get("planted_at", ""),
                **trigger_meta,
            },
            severity=AlertSeverity.CRITICAL,
        )
        session.add(
            AttackerEvent(
                ip=src_ip,
                event_type=f"honeytoken_triggered_{live.type.value}",
                honeytoken_id=live.id,
                extra=trigger_meta,
            )
        )
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
    if _rate_limit_check(src_ip):
        # Still return 200 OK — surfacing 429 to the attacker would
        # fingerprint the limit. We just skip the trigger logic.
        log.debug("Rate-limited canary hit from %s", src_ip)
        if request.match_info.get("token_id", "").endswith(".png"):
            return web.Response(body=_PIXEL, content_type="image/png")
        return web.Response(text="OK", content_type="text/plain")

    raw = request.match_info.get("token_id", "")
    # PDF tracker uses /t/<uid>.png — strip extension for matching.
    token_id = raw.split(".", 1)[0]
    token = await _find_token_by_id(token_id)
    if token:
        await _trigger(token, request)

    if raw.endswith(".png"):
        return web.Response(body=_PIXEL, content_type="image/png")
    # Generic 200 — give attackers no signal that they hit a canary.
    return web.Response(text="OK", content_type="text/plain")


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
    if _rate_limit_check(src_ip):
        return web.Response(text="ok", content_type="text/plain")

    token = await _find_token_by_id(token_id, types=(HoneytokenType.SLACK_WEBHOOK,))
    if token:
        await _trigger(token, request)
    # Real Slack webhooks reply `200 OK` with body `ok` on accepted posts.
    return web.Response(text="ok", content_type="text/plain")


async def _handle_cloud_event(request: web.Request) -> web.Response:
    """Ingest endpoint for forwarded cloud audit-log events.

    Forwarder workflow:
      1. CloudTrail / Azure Activity Log / GCP Audit Log → Cloud
         function / Lambda / Pub/Sub trigger.
      2. The trigger HMAC-SHA256-signs the raw JSON body with the shared
         `cloud_event_hmac_secret` and POSTs it here.
      3. We compare-secure the signature, then `match_cloud_event`s the
         payload against active cloud-credential tokens. On match we fire
         the same CRITICAL alert + AttackerEvent trail as a canary URL hit.

    Returns 202 Accepted regardless of match (don't leak match state to
    a potentially attacker-controlled forwarder). 401 on signature
    mismatch, 503 if the operator hasn't configured a secret yet.
    """
    settings = get_settings()
    secret = settings.cloud_event_hmac_secret
    if not secret:
        # Refuse to operate without an opt-in shared secret. An unsigned
        # ingest endpoint is an open trigger relay for arbitrary alert spam.
        return web.json_response({"error": "cloud_event_hmac_secret not configured"}, status=503)

    raw = await request.read()
    provided_sig = request.headers.get("X-HoneyPot-Signature", "")
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not provided_sig or not hmac.compare_digest(provided_sig, expected):
        return web.json_response({"error": "invalid signature"}, status=401)

    try:
        event = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return web.json_response({"error": "invalid JSON"}, status=400)

    if not isinstance(event, dict):
        return web.json_response({"error": "expected JSON object"}, status=400)

    # Match against active cloud-credential tokens via the central index.
    from honeypot_mcp.token_matchers import match_cloud_event

    token_id, source = await match_cloud_event(event)
    if token_id is not None:
        # Resolve to a full Honeytoken row, then reuse the existing
        # `_trigger()` so the mark-triggered + create-alert + AttackerEvent
        # path is identical to canary-URL triggers.
        async with get_session() as session:
            token = await session.get(Honeytoken, token_id)
        if token is not None and token.status == HoneytokenStatus.ACTIVE:
            # Build a pseudo-request carrying the event for downstream
            # logging context. We can't reuse the inbound request object
            # because _trigger() reads `.remote` / `.headers` / `.path`.
            await _trigger_cloud(token, request, event, source or "unknown")

    # Always 202 — don't leak whether the event matched.
    return web.json_response({"accepted": True}, status=202)


async def _trigger_cloud(token: Honeytoken, request: web.Request, event: dict, source: str) -> None:
    """Mark-triggered + alert path for cloud-event matches. Mirrors
    `_trigger()` but the trigger_meta captures the forwarded event itself
    rather than HTTP request headers, since the actual attacker is on the
    cloud side, not directly hitting our endpoint."""
    forwarder_ip = request.remote or "0.0.0.0"
    # Pull out the attacker IP from the cloud event if present — CloudTrail
    # has `sourceIPAddress`, Azure has `callerIpAddress`, GCP has
    # `requestMetadata.callerIp`.
    cloud_ip = (
        event.get("sourceIPAddress")
        or event.get("callerIpAddress")
        or (event.get("requestMetadata") or {}).get("callerIp")
    )
    attacker_ip = cloud_ip if isinstance(cloud_ip, str) else forwarder_ip

    trigger_meta: dict[str, Any] = {
        "trigger_ip": attacker_ip,
        "forwarder_ip": forwarder_ip,
        "source_cloud": source,
        "raw_event": event,
    }
    async with get_session() as session:
        live = await session.get(Honeytoken, token.id)
        if not live or live.status != HoneytokenStatus.ACTIVE:
            return
        await queries.mark_honeytoken_triggered(session, live.id, trigger_meta)
        await queries.create_alert(
            session,
            honeypot_id=None,
            source_ip=attacker_ip,
            source_port=None,
            event_type=f"honeytoken_triggered_{live.type.value}_via_{source}",
            payload={
                "token_id": live.id,
                "token_label": live.label,
                "token_type": live.type.value,
                # Where it was planted, if the operator recorded it. This is
                # what turns "a token fired" into "someone reached the finance
                # share" — the first question triage asks.
                "planted_at": (live.token_meta or {}).get("planted_at", ""),
                **trigger_meta,
            },
            severity=AlertSeverity.CRITICAL,
        )
        session.add(
            AttackerEvent(
                ip=attacker_ip,
                event_type=f"honeytoken_triggered_{live.type.value}_via_{source}",
                honeytoken_id=live.id,
                extra=trigger_meta,
            )
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
