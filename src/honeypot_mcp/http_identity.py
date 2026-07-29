"""Server-identity control for every aiohttp server this project exposes.

aiohttp stamps `Server: Python/3.x aiohttp/3.y.z` on any response that doesn't
set the header itself (`web_response._start` does a `setdefault`). For a
deception platform that default is a disclosure bug: it tells a scanner the
service is a Python app no matter how convincing the body is. It cost us two
real tells at once —

  * the Elasticsearch engine served a flawless ES 8.11.3 JSON document under
    `Server: Python/3.14 aiohttp/3.13.5`, and nmap duly reported "aiohttp";
  * the canary callback server, which is *internet-facing by design* and
    deliberately returns a bare `200 OK` "so attackers can't fingerprint it",
    advertised the same banner on every token callback.

So identity is set explicitly here rather than left to a library default.
"""

from __future__ import annotations

from typing import Any

from aiohttp import web, web_response

# A bare, extremely common banner. Real nginx sends exactly this when
# `server_tokens off` is set — the default in Debian/Ubuntu packages and most
# hardening guides — so it is both plausible and unremarkable.
NGINX_BANNER = "nginx"


def _neutralise_aiohttp_default_banner() -> None:
    """Replace aiohttp's default `Server` banner process-wide.

    Middleware cannot cover every response. When aiohttp rejects a request at
    the *protocol* level — an unparseable method, non-HTTP bytes on an HTTP
    port, a malformed request line — `RequestHandler.handle_error` builds a
    `400 Bad Request` without ever entering the application, so no middleware
    runs and the response carries aiohttp's default banner.

    That path is not an edge case for a honeypot: scanners open with malformed
    probes constantly. It meant a single junk request revealed
    `Server: Python/3.x aiohttp/3.y.z` from the HTTP honeypot regardless of
    which Apache/IIS/nginx persona it was wearing — defeating the entire
    persona system, whose only job is to stop exactly that inference.

    `aiohttp.web_response` reads this module-level name inside `_start` via
    `headers.setdefault(...)`, and exposes no supported hook to override it, so
    rebinding the name is the available fix. It changes only the *default*: any
    response that sets `Server` explicitly still wins.
    """
    web_response.SERVER_SOFTWARE = NGINX_BANNER


_neutralise_aiohttp_default_banner()


def server_identity_middleware(
    server: str | None,
    extra_headers: dict[str, str] | None = None,
) -> Any:
    """Build a middleware that pins the `Server` header and adds fixed headers.

    `server=None` suppresses the banner (aiohttp cannot omit the header once
    it is set, so this emits it empty — still far better than disclosing the
    implementation). Pass a string to impersonate a specific server.
    """
    headers = dict(extra_headers or {})

    @web.middleware
    async def _middleware(request: web.Request, handler: Any) -> web.StreamResponse:
        response = await handler(request)
        response.headers.update(headers)
        # Setting the key at all defeats aiohttp's setdefault, which is the
        # only hook available before the response is written.
        response.headers["Server"] = server or ""
        return response

    return _middleware
