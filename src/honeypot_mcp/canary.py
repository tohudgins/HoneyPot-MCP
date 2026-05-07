"""Canary callback HTTP server.

Receives hits on canary URLs (`/t/{token_id}`) and PDF pixel-tracker requests
(`/t/{token_uid}.png`). On a match, marks the honeytoken as triggered, records
a CRITICAL alert, and creates an AttackerEvent linked to the token.

This server is lifecycle-managed by `server.py:lifespan`. Bind host/port come
from settings: `canary_callback_host`, `canary_callback_port`.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

from aiohttp import web
from sqlalchemy import select

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
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
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIA"
    "AAoAAv/lxKUAAAAASUVORK5CYII="
)


async def _find_token_by_id(token_id: str) -> Honeytoken | None:
    """Match a request token_id against either canary_url tokens (token_meta.token_id)
    or file tokens (token_meta.token_uid). Iterates active tokens — fine at SOC scale."""
    async with get_session() as session:
        result = await session.execute(
            select(Honeytoken).where(
                Honeytoken.status == HoneytokenStatus.ACTIVE,
                Honeytoken.type.in_([HoneytokenType.CANARY_URL, HoneytokenType.FILE]),
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
                **trigger_meta,
            },
            severity=AlertSeverity.CRITICAL,
        )
        session.add(AttackerEvent(
            ip=src_ip,
            event_type=f"honeytoken_triggered_{live.type.value}",
            honeytoken_id=live.id,
            extra=trigger_meta,
        ))
    log.warning(
        "Honeytoken TRIGGERED — id=%s type=%s label=%r src=%s ua=%r",
        live.id, live.type.value, live.label, src_ip, user_agent,
    )


async def _handle_token(request: web.Request) -> web.Response:
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


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", _handle_root)
    app.router.add_get("/t/{token_id}", _handle_token)
    return app


async def start_canary_server() -> web.AppRunner | None:
    """Start the canary callback server. Returns the runner so caller can shut it down,
    or None if the port couldn't be bound (logged but non-fatal)."""
    settings = get_settings()
    host = settings.canary_callback_host
    port = settings.canary_callback_port

    runner = web.AppRunner(build_app())
    try:
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        log.info("Canary callback server listening on %s:%d", host, port)
        return runner
    except OSError as e:
        log.warning("Canary callback server could not bind %s:%d (%s) — canary tokens will not trigger.", host, port, e)
        await runner.cleanup()
        return None
