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
import base64
import contextlib
import logging
import random
import re
import secrets
import string
import time
from typing import Any
from urllib.parse import unquote

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
from honeypot_mcp.http_identity import server_identity_middleware
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

# Cap raw bodies at 64 KB so a single 10 MB upload from a scanner can't
# bloat the alert payload. Real exploit payloads (webshells, RCE chains)
# almost always fit well under this.
_MAX_RAW_BODY_BYTES = 65_536


# Exploit signatures scanned across the whole request surface (path, query,
# headers, User-Agent, body). Ordered high-to-low so the first hit sets the
# floor; all matches are recorded. Honeypot traffic has no legit users, so the
# false-positive cost of broad patterns is near zero.
_HTTP_ATTACK_SIGNATURES: list[tuple[str, re.Pattern[str], AlertSeverity]] = [
    (
        "log4shell",
        re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)", re.I),
        AlertSeverity.CRITICAL,
    ),
    ("shellshock", re.compile(r"\(\s*\)\s*\{\s*:?\s*;", re.I), AlertSeverity.CRITICAL),
    (
        "command_injection",
        re.compile(
            r"(;|\||&&|\|\|)\s*(cat|wget|curl|bash|/bin/sh|/bin/bash|nc|ncat|python|perl|id|whoami|uname)\b|\$\((cat|id|whoami|uname|curl|wget)|`(cat|id|whoami|curl|wget)|nc\s+-e|bash\s+-i",
            re.I,
        ),
        AlertSeverity.CRITICAL,
    ),
    (
        "webshell",
        re.compile(
            r"<\?php|eval\s*\(\s*\$_(get|post|request|cookie)|system\s*\(\s*\$_|assert\s*\(\s*\$_|base64_decode\s*\(\s*\$_",
            re.I,
        ),
        AlertSeverity.CRITICAL,
    ),
    (
        "ognl_struts",
        re.compile(r"%\{[^}]*(#context|#_memberAccess|ognl|Runtime@getRuntime)", re.I),
        AlertSeverity.CRITICAL,
    ),
    ("spring4shell", re.compile(r"class\.module\.classLoader", re.I), AlertSeverity.CRITICAL),
    (
        "sqli",
        re.compile(
            r"union\s+(all\s+)?select|\bor\s+1\s*=\s*1\b|'\s*or\s*'1'\s*=\s*'1|\bsleep\(\s*\d|\bbenchmark\(|\bpg_sleep\(|information_schema\.",
            re.I,
        ),
        AlertSeverity.HIGH,
    ),
    (
        "path_traversal",
        re.compile(r"\.\./|\.\.%2f|%2e%2e[/\\]|\.\.\\|%252e%252e", re.I),
        AlertSeverity.HIGH,
    ),
    (
        "lfi_rfi",
        re.compile(
            r"/etc/passwd|/proc/self/environ|php://(filter|input)|data://|expect://|file:///", re.I
        ),
        AlertSeverity.HIGH,
    ),
    (
        "ssrf",
        re.compile(
            r"gopher://|dict://|169\.254\.169\.254|metadata\.google|/latest/meta-data/", re.I
        ),
        AlertSeverity.HIGH,
    ),
    (
        "deserialization",
        re.compile(
            r"java\.lang\.Runtime|rO0AB[A-Za-z0-9+/]|__proto__|constructor\[.prototype", re.I
        ),
        AlertSeverity.HIGH,
    ),
    (
        "xss",
        re.compile(r"<script\b|onerror\s*=|onload\s*=|javascript:", re.I),
        AlertSeverity.MEDIUM,
    ),
]

_SEV_RANK = {
    AlertSeverity.LOW: 0,
    AlertSeverity.MEDIUM: 1,
    AlertSeverity.HIGH: 2,
    AlertSeverity.CRITICAL: 3,
}

# Upper bound on the request surface fed to the exploit regexes, so a large
# POST body can't turn every request into an oversized scan.
_MAX_SCAN_SURFACE = 32_768


def _classify_http_attack(surface: str) -> tuple[list[str], AlertSeverity | None]:
    """Scan the request surface for exploit signatures. Returns the matched
    category labels and the highest matched severity (or None if clean)."""
    matched: list[str] = []
    top: AlertSeverity | None = None
    for label, pattern, sev in _HTTP_ATTACK_SIGNATURES:
        if pattern.search(surface):
            matched.append(label)
            if top is None or _SEV_RANK[sev] > _SEV_RANK[top]:
                top = sev
    return matched, top


# Auth-failed response variants. The previous engine returned the SAME
# byte sequence on every failed login, which is itself a fingerprint —
# a scanner can submit two requests, diff the responses, and confirm
# there's no real auth backend. Real login pages return slightly
# different wording across versions / locales / WAFs, so we rotate.
_LOGIN_FAILURE_VARIANTS: tuple[str, ...] = (
    "Invalid username or password.",
    "Authentication failed. Please try again.",
    "Login failed: bad credentials.",
    "The username or password you entered is incorrect.",
    "We could not log you in with those details.",
    "Sign-in unsuccessful. Check your credentials and retry.",
)

# Paths that warrant serving plausible decoy content instead of a 404 or a
# fixed template. Scanners that probe these are looking for exfil-grade
# data; returning believable bait gets them to stick around longer and
# captures their full TTPs. Tokens embedded in the bait are throwaway —
# not persisted, not matched — so they cost nothing if leaked.
_DECOY_PATHS: frozenset[str] = frozenset(
    {
        "/.env",
        "/config.json",
        "/wp-config.php",
        "/.aws/credentials",
        "/.kube/config",
    }
)


def _rand_alnum(n: int, upper: bool = False) -> str:
    """Fixed-length random alphanumeric string for token-shape decoys."""
    alphabet = (string.ascii_uppercase if upper else string.ascii_letters) + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _generate_decoy(path: str) -> tuple[str, str]:
    """Return `(body, content_type)` for a decoy response.

    Each call mints fresh throwaway token-shaped strings. Nothing here is
    a real honeytoken — they're decorative bait so the response *looks*
    like what an attacker hopes to find. Real honeytokens fire via the
    proper providers; mixing the two would risk leaking real tracker URLs
    in scrape data.
    """
    aws_key_id = "AKIA" + _rand_alnum(16, upper=True)
    aws_secret = _rand_alnum(40)
    db_password = _rand_alnum(20)
    jwt_payload = (
        base64.urlsafe_b64encode(b'{"sub":"admin","role":"superuser","iat":1700000000}')
        .rstrip(b"=")
        .decode("ascii")
    )
    fake_jwt = f"eyJhbGciOiJIUzI1NiJ9.{jwt_payload}.{_rand_alnum(43)}"

    if path == "/.env":
        body = (
            f"APP_NAME=Laravel\n"
            f"APP_ENV=production\n"
            f"APP_KEY=base64:{_rand_alnum(32)}=\n"
            f"APP_DEBUG=false\n"
            f"DB_CONNECTION=mysql\n"
            f"DB_HOST=127.0.0.1\n"
            f"DB_PORT=3306\n"
            f"DB_DATABASE=production\n"
            f"DB_USERNAME=appuser\n"
            f"DB_PASSWORD={db_password}\n"
            f"AWS_ACCESS_KEY_ID={aws_key_id}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_secret}\n"
            f"AWS_DEFAULT_REGION=us-east-1\n"
            f"JWT_SECRET={_rand_alnum(48)}\n"
            f"STRIPE_SECRET=sk_live_{_rand_alnum(24)}\n"
        )
        return body, "text/plain"

    if path == "/config.json":
        body = (
            "{\n"
            '  "version": "1.2.4",\n'
            '  "environment": "production",\n'
            f'  "api_token": "{fake_jwt}",\n'
            f'  "database": {{\n'
            f'    "host": "db.internal",\n'
            f'    "user": "appuser",\n'
            f'    "password": "{db_password}"\n'
            "  },\n"
            f'  "aws": {{\n'
            f'    "access_key_id": "{aws_key_id}",\n'
            f'    "secret_access_key": "{aws_secret}"\n'
            "  }\n"
            "}\n"
        )
        return body, "application/json"

    if path == "/wp-config.php":
        body = (
            "<?php\n"
            "define( 'DB_NAME', 'wordpress' );\n"
            "define( 'DB_USER', 'wpuser' );\n"
            f"define( 'DB_PASSWORD', '{db_password}' );\n"
            "define( 'DB_HOST', 'localhost' );\n"
            "define( 'DB_CHARSET', 'utf8mb4' );\n"
            f"define( 'AUTH_KEY',         '{_rand_alnum(64)}' );\n"
            f"define( 'SECURE_AUTH_KEY',  '{_rand_alnum(64)}' );\n"
            f"define( 'LOGGED_IN_KEY',    '{_rand_alnum(64)}' );\n"
            "$table_prefix = 'wp_';\n"
            "define( 'WP_DEBUG', false );\n"
            "require_once ABSPATH . 'wp-settings.php';\n"
        )
        return body, "application/x-httpd-php"

    if path == "/.aws/credentials":
        body = (
            "[default]\n"
            f"aws_access_key_id = {aws_key_id}\n"
            f"aws_secret_access_key = {aws_secret}\n"
            "region = us-east-1\n"
            "\n"
            "[deploy]\n"
            f"aws_access_key_id = AKIA{_rand_alnum(16, upper=True)}\n"
            f"aws_secret_access_key = {_rand_alnum(40)}\n"
            "region = us-west-2\n"
        )
        return body, "text/plain"

    if path == "/.kube/config":
        body = (
            "apiVersion: v1\n"
            "kind: Config\n"
            "clusters:\n"
            "- cluster:\n"
            f"    server: https://k8s.internal:6443\n"
            f"    certificate-authority-data: {_rand_alnum(80)}\n"
            "  name: production\n"
            "contexts:\n"
            "- context:\n"
            "    cluster: production\n"
            "    user: admin\n"
            "  name: production\n"
            "current-context: production\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            f"    token: {fake_jwt}\n"
        )
        return body, "application/yaml"

    # Should never hit — caller checks the path against _DECOY_PATHS first.
    return "", "text/plain"


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

        def _persona_headers() -> dict[str, str]:
            h = {"Server": persona.server_header}
            if persona.x_powered_by:
                h["X-Powered-By"] = persona.x_powered_by
            for k, v in persona.extra_headers:
                h[k] = v
            return h

        # Apply the persona to *every* response, not just the ones whose handler
        # remembers to call `_persona_headers()`. Anything that slips through —
        # an aiohttp-generated 404 or 405, a future handler — would otherwise
        # fall back to aiohttp's own `Server` banner and expose the stack.
        _persona_extra = {k: v for k, v in _persona_headers().items() if k != "Server"}
        app = web.Application(
            middlewares=[server_identity_middleware(persona.server_header, _persona_extra)]
        )
        # Per-honeypot in-memory session store. Keyed by session_id (cookie
        # value). Two honeypots don't share state.
        sessions: dict[str, dict[str, Any]] = {}

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

            # Body parsing — content-type dispatch. Form/multipart goes through
            # request.post() so credential_match keeps seeing the parsed
            # `post_data` dict; non-form bodies (JSON, binary, raw exploit
            # payloads) get captured as base64-encoded raw bytes, capped, so
            # webshell uploads + RCE chains aren't silently lost.
            post_data: dict = {}
            raw_body_b64: str | None = None
            raw_content_type: str | None = None
            raw_body_scan = ""
            if method in ("POST", "PUT", "PATCH"):
                ct = (request.headers.get("Content-Type") or "").lower()
                is_form = "application/x-www-form-urlencoded" in ct or "multipart/form-data" in ct
                if is_form:
                    with contextlib.suppress(Exception):
                        post_data = dict(await request.post())
                else:
                    with contextlib.suppress(Exception):
                        raw = await request.read()
                        if raw:
                            capped = raw[:_MAX_RAW_BODY_BYTES]
                            raw_body_b64 = base64.b64encode(capped).decode("ascii")
                            raw_body_scan = capped.decode("utf-8", errors="replace")
                            raw_content_type = ct or "application/octet-stream"

            matched_template = path_to_template.get(path)
            severity = _PATH_SEVERITY.get(path, AlertSeverity.LOW)
            event_type = "http_credential_submit" if post_data else "http_probe"

            # Active-recon escalation: a session with many hits indicates the
            # scanner is mapping the site, not a one-shot probe.
            sid, sess, is_new = _get_or_create_session(request)
            if sess["hits"] >= _RECON_THRESHOLD and severity == AlertSeverity.LOW:
                severity = AlertSeverity.MEDIUM
                event_type = "http_active_recon"

            # Recon-path interception: serve plausible bait instead of the
            # usual template/404 fallback. Severity escalates to MEDIUM because
            # a probe for `/.env` or `/.aws/credentials` is unambiguously
            # malicious — no real user hits these paths.
            serve_decoy = path in _DECOY_PATHS
            if serve_decoy:
                event_type = "http_decoy_served"
                if severity == AlertSeverity.LOW:
                    severity = AlertSeverity.MEDIUM

            # Exploit-signature scan across the whole request surface (path +
            # query + headers + UA + body), with the surface also URL-decoded so
            # %-encoded payloads don't slip past. Any hit re-tags the event and
            # raises severity to at least the matched level — this is the intel
            # a SOC actually wants (which CVE/technique was thrown at you).
            surface_parts = [request.path_qs, user_agent]
            surface_parts.extend(str(v) for v in request.headers.values())
            surface_parts.extend(f"{k}={v}" for k, v in post_data.items())
            if raw_body_scan:
                surface_parts.append(raw_body_scan)
            # Bound the scanned surface: exploit strings (jndi, <?php, ../,
            # UNION SELECT) are short and appear early, so scanning the first
            # 32 KB catches them without letting a large POST turn each request
            # into a big regex sweep. The full body is still captured verbatim
            # in raw_body_b64 for forensics.
            surface = " ".join(surface_parts)[:_MAX_SCAN_SURFACE]
            exploit_categories, exploit_sev = _classify_http_attack(
                surface + " " + unquote(surface)
            )
            if exploit_sev is not None:
                event_type = "http_exploit_attempt"
                if _SEV_RANK[exploit_sev] > _SEV_RANK[severity]:
                    severity = exploit_sev

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
            if raw_body_b64 is not None:
                payload["raw_body_b64"] = raw_body_b64
                payload["raw_content_type"] = raw_content_type
            if serve_decoy:
                payload["decoy_target"] = path
            if exploit_categories:
                payload["exploit_categories"] = exploit_categories

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

            # POST /login: rotate the auth-failed wording AND add extra
            # variable timing on top of the persona jitter. A real login
            # endpoint does a password hash compare (100-500ms); a fixed
            # sub-ms uniform response is itself a single-probe tell.
            if method == "POST" and path == "/login":
                await asyncio.sleep(random.uniform(0.18, 0.65))
                variant = random.choice(_LOGIN_FAILURE_VARIANTS)
                login_html = (
                    "<!DOCTYPE html><html><head><title>Sign in</title></head><body>"
                    "<h1>Sign in</h1>"
                    '<form method="POST" action="/login">'
                    '<label>Username <input name="username" /></label>'
                    '<label>Password <input name="password" type="password" /></label>'
                    '<button type="submit">Log in</button>'
                    "</form>"
                    f'<p class="error" style="color:#c00">{variant}</p>'
                    "</body></html>"
                )
                resp = web.Response(
                    text=login_html,
                    content_type="text/html",
                    status=401,
                    headers=response_headers,
                )
                if is_new:
                    _set_session_cookie(resp, sid)
                return resp

            if serve_decoy:
                decoy_body, decoy_ct = _generate_decoy(path)
                resp = web.Response(
                    text=decoy_body,
                    content_type=decoy_ct,
                    status=200,
                    headers=response_headers,
                )
            elif matched_template is not None:
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
