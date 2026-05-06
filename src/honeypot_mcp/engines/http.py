"""HTTP honeypot engine — custom aiohttp server with fake endpoints."""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from aiohttp import web

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# Fake HTML responses keyed by template name
_TEMPLATES: dict[str, str] = {
    "admin_panel": """<!DOCTYPE html><html><head><title>Admin Login</title></head><body>
<h2>Admin Panel</h2><form method="POST">
Username: <input name="username"><br>Password: <input type="password" name="password"><br>
<input type="submit" value="Login"></form></body></html>""",

    "phpmyadmin": """<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>
<h1>phpMyAdmin 5.2.1</h1><form method="POST">
Username: <input name="username" value="root"><br>Password: <input type="password" name="password"><br>
<input type="submit" value="Go"></form></body></html>""",

    "wordpress_admin": """<!DOCTYPE html><html><head><title>WordPress Admin</title></head><body>
<h1>WordPress Login</h1><form method="POST">
<input name="log" placeholder="Username"><br><input type="password" name="pwd" placeholder="Password"><br>
<input type="submit" value="Log In"></form></body></html>""",

    "env_file": """APP_KEY=base64:rAndOmKeyHerE1234567890==
DB_HOST=127.0.0.1
DB_DATABASE=production_db
DB_USERNAME=root
DB_PASSWORD=SuperSecret123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""",

    "generic_login": """<!DOCTYPE html><html><head><title>Login</title></head><body>
<h2>Please Login</h2><form method="POST">
Username: <input name="username"><br>Password: <input type="password" name="password"><br>
<input type="submit" value="Login"></form></body></html>""",
}

# Map event types to severity
_PATH_SEVERITY: dict[str, AlertSeverity] = {
    "/admin": AlertSeverity.HIGH,
    "/phpmyadmin": AlertSeverity.HIGH,
    "/wp-admin": AlertSeverity.HIGH,
    "/.env": AlertSeverity.CRITICAL,
    "/login": AlertSeverity.MEDIUM,
}


class HTTPEngine(HoneypotEngine):
    """Runs an aiohttp application in a background asyncio task."""

    def __init__(self) -> None:
        self._runners: dict[str, tuple[web.AppRunner, str]] = {}  # container_id → (runner, name)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        app = self._build_app(name, config)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()

        container_id = f"http-{secrets.token_hex(8)}"
        self._runners[container_id] = (runner, name)
        log.info("HTTP honeypot '%s' listening on port %d (id=%s)", name, port, container_id[:12])
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
        return [f"[HTTP honeypot] In-process server — check application logs for events."]

    def _build_app(self, honeypot_name: str, config: dict[str, Any]) -> web.Application:
        server_header = config.get("fake_server_header", "Apache/2.4.41 (Ubuntu)")
        endpoints = config.get("endpoints", [
            {"path": "/admin", "template": "admin_panel"},
            {"path": "/phpmyadmin", "template": "phpmyadmin"},
            {"path": "/wp-admin", "template": "wordpress_admin"},
            {"path": "/.env", "template": "env_file"},
            {"path": "/login", "template": "generic_login"},
        ])

        app = web.Application()

        async def _handle(request: web.Request) -> web.Response:
            path = request.path
            method = request.method
            src_ip = request.remote or "0.0.0.0"
            user_agent = request.headers.get("User-Agent", "")

            body = ""
            post_data: dict = {}
            if method == "POST":
                try:
                    post_data = dict(await request.post())
                    body = str(post_data)
                except Exception:
                    body = await request.text()

            severity = _PATH_SEVERITY.get(path, AlertSeverity.LOW)
            event_type = "http_credential_submit" if post_data else "http_probe"

            payload = {
                "method": method,
                "path": path,
                "user_agent": user_agent,
                "headers": dict(request.headers),
                "post_data": {k: v for k, v in post_data.items() if "pass" not in k.lower()},
                "has_credentials": bool(post_data),
            }

            async with get_session() as session:
                hp = await queries.get_honeypot_by_name(session, honeypot_name)
                await queries.create_alert(
                    session,
                    honeypot_id=hp.id if hp else None,
                    source_ip=src_ip,
                    source_port=None,
                    event_type=event_type,
                    payload=payload,
                    severity=severity,
                )
                from honeypot_mcp.storage.models import AttackerEvent
                session.add(AttackerEvent(ip=src_ip, event_type=event_type, extra=payload))

            # Check canary token triggers (for /.env and similar)
            if path in ("/.env", "/backup", "/.git/config"):
                from honeypot_mcp.storage.models import Honeytoken, HoneytokenType, HoneytokenStatus
                from sqlalchemy import select
                async with get_session() as session:
                    result = await session.execute(
                        select(Honeytoken).where(
                            Honeytoken.type == HoneytokenType.CANARY_URL,
                            Honeytoken.status == HoneytokenStatus.ACTIVE,
                        )
                    )
                    # Trigger matching tokens
                    for token in result.scalars().all():
                        if path in token.token_value:
                            await queries.mark_honeytoken_triggered(
                                session, token.id, {"trigger_ip": src_ip, "path": path}
                            )

            # Match template
            template_name = "generic_login"
            for ep in endpoints:
                if ep.get("path") == path:
                    template_name = ep.get("template", "generic_login")
                    break

            html = _TEMPLATES.get(template_name, "<html><body>Not Found</body></html>")
            status_code = 200 if path != "/.env" else 200

            return web.Response(
                text=html,
                content_type="text/html" if not path.endswith(".env") else "text/plain",
                status=status_code,
                headers={"Server": server_header, "X-Powered-By": "PHP/7.4.33"},
            )

        # Register all configured endpoints plus a catch-all
        for ep in endpoints:
            app.router.add_route("*", ep["path"], _handle)
        app.router.add_route("*", "/{tail:.*}", _handle)

        return app
