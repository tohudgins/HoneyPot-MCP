"""HTTP honeypot engine — custom aiohttp server with persona-driven fingerprint resistance.

A "persona" (Apache/Nginx/IIS variant) is picked at deploy time and persisted
to the honeypot's config dict, so the same honeypot keeps a stable identity
across restarts but two honeypots in one project pick different personas. The
persona drives Server header, X-Powered-By, session cookie name, 404 page,
extra headers, and per-response timing jitter.

Body content (login forms, fake .env files) lives in `http_templates.py`.
Selection of which template a configured endpoint serves stays in `config`,
so users can map their own paths to templates the same way they always have.

Realistic well-known endpoints (`/robots.txt`, `/favicon.ico`, `/sitemap.xml`,
`/.well-known/security.txt`) live in `http_endpoints.py` and are always
served — a real web server has these and an empty/404 response on any of
them is a single-curl tell.

Session cookies are issued on every request using the persona's cookie name
(`PHPSESSID` / `ASP.NET_SessionId` / etc). The session id is tracked
in-process: repeat visits from the same session bump severity (signals
active reconnaissance vs one-shot scanner). Sessions are not authenticated
— we never accept any login because a real hardened login page rejects
unknown users, and "accepts any password" is itself a fingerprint.

TLS: setting `config["tls"] = True` at deploy time enables HTTPS on the
configured port using a self-signed cert generated lazily via
`engines/tls.py:ensure_cert`. The same cert is reused across restarts so a
scanner pinning the cert SHA sees stability.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import secrets
import time
from typing import Any

from aiohttp import web
from sqlalchemy import update

from honeypot_mcp.engines import http_endpoints
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.http_personas import (
    HTTPPersona,
    get_persona,
    pick_random_persona_id,
)
from honeypot_mcp.engines.http_templates import get_template
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity, Honeypot

log = logging.getLogger(__name__)


# Path → severity for known sensitive endpoints.
_PATH_SEVERITY: dict[str, AlertSeverity] = {
    "/admin": AlertSeverity.HIGH,
    "/phpmyadmin": AlertSeverity.HIGH,
    "/wp-admin": AlertSeverity.HIGH,
    "/.env": AlertSeverity.CRITICAL,
    "/login": AlertSeverity.MEDIUM,
}

_DEFAULT_ENDPOINTS = [
    {"path": "/admin", "template": "admin_panel"},
    {"path": "/phpmyadmin", "template": "phpmyadmin_5"},
    {"path": "/wp-admin", "template": "wordpress_admin"},
    {"path": "/.env", "template": "env_laravel"},
    {"path": "/login", "template": "generic_login"},
]

# Repeat-visit threshold — once a session has hit this many endpoints we
# treat them as active recon and bump severity.
_RECON_THRESHOLD = 5

# Session inactivity timeout — drop sessions inactive for this long so the
# in-memory map doesn't grow unbounded under sustained scanning.
_SESSION_TTL_SECONDS = 3600


class HTTPEngine(HoneypotEngine):
    """Runs an aiohttp application in a background asyncio task."""

    def __init__(self) -> None:
        self._runners: dict[str, tuple[web.AppRunner, str]] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        # Resolve DB id once at start so the request handler doesn't have to
        # round-trip the DB on every request.
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        # Pick + persist a persona on first start. Stays stable across restarts
        # so two probes from the same scanner see the same identity.
        if "persona" not in config:
            config["persona"] = pick_random_persona_id()
            if hp_id is not None:
                async with get_session() as session:
                    await session.execute(
                        update(Honeypot).where(Honeypot.id == hp_id).values(config=config)
                    )

        persona = get_persona(config.get("persona"))
        tls_enabled = bool(config.get("tls"))
        log.info("HTTP honeypot '%s' deploying as persona=%s tls=%s", name, persona.id, tls_enabled)

        app = self._build_app(name, hp_id, persona, config)
        runner = web.AppRunner(app)
        await runner.setup()

        ssl_context = None
        if tls_enabled:
            # Lazy import — keeps the cryptography dep optional for HTTP-only
            # deployments. ImportError fails loudly so the operator sees why.
            from honeypot_mcp.engines.tls import build_server_ssl_context

            ssl_context = build_server_ssl_context(name, common_name=name)

        site = web.TCPSite(runner, "0.0.0.0", port, ssl_context=ssl_context)
        await site.start()

        container_id = f"http-{secrets.token_hex(8)}"
        self._runners[container_id] = (runner, name)
        log.info(
            "HTTP honeypot '%s' listening on %s://0.0.0.0:%d (id=%s, persona=%s)",
            name,
            "https" if tls_enabled else "http",
            port,
            container_id[:12],
            persona.id,
        )
        return container_id

    async def stop(self, container_id: str, remove: bool = False) -> None:
        entry = self._runners.pop(container_id, None)
        if entry:
            runner, _ = entry
            await runner.cleanup()

    async def status(self, container_id: str) -> dict[str, Any]:
        running = container_id in self._runners
        return {"running": running, "type": "aiohttp_in_process"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["[HTTP honeypot] In-process server — check application logs for events."]

    def _build_app(
        self,
        honeypot_name: str,
        hp_id: int | None,
        persona: HTTPPersona,
        config: dict[str, Any],
    ) -> web.Application:
        endpoints = config.get("endpoints", _DEFAULT_ENDPOINTS)
        # Map path → template name, built once at start so the per-request
        # handler is just a dict lookup.
        path_to_template: dict[str, str] = {
            ep["path"]: ep.get("template", "generic_login") for ep in endpoints if "path" in ep
        }

        app = web.Application()
        # Per-honeypot in-memory session store. Keyed by session_id (cookie
        # value). Two honeypots don't share state.
        sessions: dict[str, dict[str, Any]] = {}

        def _persona_headers() -> dict[str, str]:
            h = {"Server": persona.server_header}
            if persona.x_powered_by:
                h["X-Powered-By"] = persona.x_powered_by
            for k, v in persona.extra_headers:
                h[k] = v
            return h

        def _get_or_create_session(request: web.Request) -> tuple[str, dict[str, Any], bool]:
            """Return `(session_id, session_dict, is_new)`. Prunes expired
            sessions opportunistically — keeps the dict bounded under
            sustained scanning without a separate sweeper task."""
            now = time.monotonic()
            # Cheap LRU-ish prune: drop anything past TTL.
            expired = [
                sid for sid, s in sessions.items() if now - s["last_seen"] > _SESSION_TTL_SECONDS
            ]
            for sid in expired:
                sessions.pop(sid, None)

            sid_opt = request.cookies.get(persona.cookie_name)
            if sid_opt and sid_opt in sessions:
                sessions[sid_opt]["last_seen"] = now
                sessions[sid_opt]["hits"] += 1
                return sid_opt, sessions[sid_opt], False
            new_sid = secrets.token_hex(13)  # PHPSESSID-shaped length
            sessions[new_sid] = {"created": now, "last_seen": now, "hits": 1}
            return new_sid, sessions[new_sid], True

        async def _record(
            request: web.Request,
            event_type: str,
            severity: AlertSeverity,
            extra: dict[str, Any] | None = None,
        ) -> None:
            payload = {
                "method": request.method,
                "path": request.path,
                "user_agent": request.headers.get("User-Agent", ""),
                "headers": dict(request.headers),
                "persona": persona.id,
                "tls": bool(config.get("tls")),
            }
            if extra:
                payload.update(extra)
            await submit_event(
                PendingEvent(
                    honeypot_id=hp_id,
                    source_ip=request.remote or "0.0.0.0",
                    event_type=event_type,
                    payload=payload,
                    severity=severity,
                )
            )

        def _set_session_cookie(response: web.Response, sid: str) -> None:
            # Real PHP / ASP.NET sessions are HttpOnly, no SameSite override.
            # Don't set Secure here even on TLS — many real legacy stacks
            # don't, and adding it would itself be a fingerprint.
            response.set_cookie(persona.cookie_name, sid, httponly=True, path="/")

        async def _serve_with_persona(
            request: web.Request,
            body: str | bytes,
            status: int = 200,
            content_type: str = "text/html",
        ) -> web.Response:
            sid, sess, is_new = _get_or_create_session(request)
            # Per-persona timing jitter — uniform sub-ms responses are themselves
            # a fingerprint.
            if persona.jitter_ms_max > 0:
                delay_s = random.uniform(persona.jitter_ms_min, persona.jitter_ms_max) / 1000.0
                await asyncio.sleep(delay_s)
            headers = _persona_headers()
            if isinstance(body, bytes):
                resp = web.Response(
                    body=body, status=status, content_type=content_type, headers=headers
                )
            else:
                resp = web.Response(
                    text=body, status=status, content_type=content_type, headers=headers
                )
            if is_new:
                _set_session_cookie(resp, sid)
            return resp

        # ── Well-known endpoints ────────────────────────────────────────
        async def _handle_robots(request: web.Request) -> web.Response:
            await _record(request, "http_recon_probe", AlertSeverity.LOW, {"target": "robots.txt"})
            return await _serve_with_persona(
                request, http_endpoints.get_robots_txt(), content_type="text/plain"
            )

        async def _handle_favicon(request: web.Request) -> web.Response:
            await _record(request, "http_recon_probe", AlertSeverity.LOW, {"target": "favicon"})
            return await _serve_with_persona(
                request, http_endpoints.get_favicon(), content_type="image/x-icon"
            )

        async def _handle_sitemap(request: web.Request) -> web.Response:
            await _record(request, "http_recon_probe", AlertSeverity.LOW, {"target": "sitemap"})
            host = request.headers.get("Host", "localhost")
            return await _serve_with_persona(
                request, http_endpoints.get_sitemap_xml(host), content_type="application/xml"
            )

        async def _handle_security_txt(request: web.Request) -> web.Response:
            await _record(
                request, "http_recon_probe", AlertSeverity.LOW, {"target": "security.txt"}
            )
            host = request.headers.get("Host", "localhost")
            return await _serve_with_persona(
                request, http_endpoints.get_security_txt(host), content_type="text/plain"
            )

        # ── API attack-surface endpoints ────────────────────────────────
        async def _handle_oidc_config(request: web.Request) -> web.Response:
            await _record(
                request, "http_api_probe", AlertSeverity.MEDIUM, {"target": "oidc-config"}
            )
            host = request.headers.get("Host", "localhost")
            return await _serve_with_persona(
                request,
                http_endpoints.get_openid_configuration(host),
                content_type="application/json",
            )

        async def _handle_swagger(request: web.Request) -> web.Response:
            await _record(request, "http_api_probe", AlertSeverity.MEDIUM, {"target": "swagger"})
            host = request.headers.get("Host", "localhost")
            return await _serve_with_persona(
                request,
                http_endpoints.get_swagger_json(host),
                content_type="application/json",
            )

        async def _handle_graphql(request: web.Request) -> web.Response:
            """POST with `__schema` → introspection probe (LOW, return schema).
            POST with anything else → injection attempt (HIGH, parse error).
            GET → curl poke at the endpoint (MEDIUM)."""
            body_text = ""
            if request.method == "POST":
                body_text = await request.text()

            severity = AlertSeverity.MEDIUM
            if "__schema" in body_text or "IntrospectionQuery" in body_text:
                payload_body = http_endpoints.get_graphql_introspection()
                event_extra = {"target": "graphql", "probe": "introspection"}
                severity = AlertSeverity.LOW
            else:
                payload_body = http_endpoints.get_graphql_error()
                event_extra = {"target": "graphql", "probe": "non-introspection"}
                if request.method == "POST":
                    severity = AlertSeverity.HIGH
                    event_extra["body_preview"] = body_text[:512]

            await _record(request, "http_api_probe", severity, event_extra)
            return await _serve_with_persona(request, payload_body, content_type="application/json")

        # ── Main catch-all handler ──────────────────────────────────────
        async def _handle(request: web.Request) -> web.Response:
            path = request.path
            method = request.method
            user_agent = request.headers.get("User-Agent", "")
            host_header = request.headers.get("Host", "localhost")

            post_data: dict = {}
            if method == "POST":
                with contextlib.suppress(Exception):
                    post_data = dict(await request.post())

            matched_template = path_to_template.get(path)
            severity = _PATH_SEVERITY.get(path, AlertSeverity.LOW)
            event_type = "http_credential_submit" if post_data else "http_probe"

            # Active-recon escalation: a session with many hits indicates the
            # scanner is mapping the site, not a one-shot probe.
            sid, sess, is_new = _get_or_create_session(request)
            if sess["hits"] >= _RECON_THRESHOLD and severity == AlertSeverity.LOW:
                severity = AlertSeverity.MEDIUM
                event_type = "http_active_recon"

            payload = {
                "method": method,
                "path": path,
                "user_agent": user_agent,
                "headers": dict(request.headers),
                "post_data": dict(post_data),
                "has_credentials": bool(post_data),
                "matched_endpoint": matched_template is not None,
                "persona": persona.id,
                "session_id": sid,
                "session_hits": sess["hits"],
                "tls": bool(config.get("tls")),
            }

            await submit_event(
                PendingEvent(
                    honeypot_id=hp_id,
                    source_ip=request.remote or "0.0.0.0",
                    event_type=event_type,
                    payload=payload,
                    severity=severity,
                )
            )

            if persona.jitter_ms_max > 0:
                delay_s = random.uniform(persona.jitter_ms_min, persona.jitter_ms_max) / 1000.0
                await asyncio.sleep(delay_s)

            response_headers = _persona_headers()

            if matched_template is not None:
                content_type = "text/plain" if path.endswith(".env") else "text/html"
                resp = web.Response(
                    text=get_template(matched_template),
                    content_type=content_type,
                    status=200,
                    headers=response_headers,
                )
            else:
                resp = web.Response(
                    text=persona.render_not_found(host_header),
                    content_type="text/html",
                    status=404,
                    headers=response_headers,
                )
            if is_new:
                _set_session_cookie(resp, sid)
            return resp

        # ── Routes ──────────────────────────────────────────────────────
        # Specific well-known paths first so they don't fall through to the
        # main handler.
        app.router.add_get("/robots.txt", _handle_robots)
        app.router.add_get("/favicon.ico", _handle_favicon)
        app.router.add_get("/sitemap.xml", _handle_sitemap)
        app.router.add_get("/.well-known/security.txt", _handle_security_txt)

        # API attack-surface endpoints
        app.router.add_get("/.well-known/openid-configuration", _handle_oidc_config)
        app.router.add_get("/swagger.json", _handle_swagger)
        app.router.add_get("/api/swagger.json", _handle_swagger)
        app.router.add_get("/openapi.json", _handle_swagger)
        app.router.add_route("*", "/graphql", _handle_graphql)
        app.router.add_route("*", "/api/graphql", _handle_graphql)

        for ep in endpoints:
            if "path" in ep:
                app.router.add_route("*", ep["path"], _handle)
        # Catch-all so we capture probes to unknown paths and serve the 404.
        app.router.add_route("*", "/{tail:.*}", _handle)

        return app
