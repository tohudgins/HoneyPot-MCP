"""HTTP honeypot engine — custom aiohttp server with persona-driven fingerprint resistance.

A "persona" (Apache/Nginx/IIS variant) is picked at deploy time and persisted
to the honeypot's config dict, so the same honeypot keeps a stable identity
across restarts but two honeypots in one project pick different personas. The
persona drives Server header, X-Powered-By, session cookie name, 404 page,
extra headers, and per-response timing jitter.

Body content (login forms, fake .env files) lives in `http_templates.py`.
Selection of which template a configured endpoint serves stays in `config`,
so users can map their own paths to templates the same way they always have.
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
from typing import Any

from aiohttp import web
from sqlalchemy import update

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.http_personas import (
    HTTPPersona,
    get_persona,
    pick_random_persona_id,
)
from honeypot_mcp.engines.http_templates import get_template
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
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
                        update(Honeypot)
                        .where(Honeypot.id == hp_id)
                        .values(config=config)
                    )

        persona = get_persona(config.get("persona"))
        log.info("HTTP honeypot '%s' deploying as persona=%s", name, persona.id)

        app = self._build_app(name, hp_id, persona, config)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()

        container_id = f"http-{secrets.token_hex(8)}"
        self._runners[container_id] = (runner, name)
        log.info(
            "HTTP honeypot '%s' listening on port %d (id=%s, persona=%s)",
            name, port, container_id[:12], persona.id,
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
            ep["path"]: ep.get("template", "generic_login")
            for ep in endpoints
            if "path" in ep
        }

        app = web.Application()

        async def _handle(request: web.Request) -> web.Response:
            path = request.path
            method = request.method
            src_ip = request.remote or "0.0.0.0"
            user_agent = request.headers.get("User-Agent", "")
            host_header = request.headers.get("Host", "localhost")

            post_data: dict = {}
            if method == "POST":
                try:
                    post_data = dict(await request.post())
                except Exception:
                    pass

            matched_template = path_to_template.get(path)
            severity = _PATH_SEVERITY.get(path, AlertSeverity.LOW)
            event_type = "http_credential_submit" if post_data else "http_probe"

            # Capture the full POST body — credentials are forensic evidence
            # (attacker fingerprinting, credential-reuse correlation across honeypots).
            payload = {
                "method": method,
                "path": path,
                "user_agent": user_agent,
                "headers": dict(request.headers),
                "post_data": dict(post_data),
                "has_credentials": bool(post_data),
                "matched_endpoint": matched_template is not None,
                "persona": persona.id,
            }

            await submit_event(PendingEvent(
                honeypot_id=hp_id,
                source_ip=src_ip,
                event_type=event_type,
                payload=payload,
                severity=severity,
            ))

            # Per-persona response timing jitter — uniform sub-ms responses
            # are themselves a fingerprint.
            if persona.jitter_ms_max > 0:
                delay_s = random.uniform(persona.jitter_ms_min, persona.jitter_ms_max) / 1000.0
                await asyncio.sleep(delay_s)

            response_headers = {"Server": persona.server_header}
            if persona.x_powered_by:
                response_headers["X-Powered-By"] = persona.x_powered_by
            for k, v in persona.extra_headers:
                response_headers[k] = v

            # Configured endpoint → serve its template.
            if matched_template is not None:
                content_type = "text/plain" if path.endswith(".env") else "text/html"
                return web.Response(
                    text=get_template(matched_template),
                    content_type=content_type,
                    status=200,
                    headers=response_headers,
                )

            # Anything else → realistic per-persona 404. Generic-login on every
            # unknown path was itself a fingerprint.
            return web.Response(
                text=persona.render_not_found(host_header),
                content_type="text/html",
                status=404,
                headers=response_headers,
            )

        for ep in endpoints:
            if "path" in ep:
                app.router.add_route("*", ep["path"], _handle)
        # Catch-all so we capture probes to unknown paths and serve the 404.
        app.router.add_route("*", "/{tail:.*}", _handle)

        return app
