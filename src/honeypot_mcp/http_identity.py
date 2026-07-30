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

import asyncio
from typing import Any

from aiohttp import web, web_protocol, web_response, web_server

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


def identity_runner(app: web.Application, server: str) -> web.AppRunner:
    """An `AppRunner` whose *protocol-level* errors also wear the right banner.

    Middleware cannot reach every response. When aiohttp rejects a request
    before routing — an unparseable method, non-HTTP bytes on an HTTP port, an
    oversized header — `RequestHandler.handle_error` builds the reply itself,
    and it falls back to the process-wide `SERVER_SOFTWARE`. One global cannot
    be right for several listeners at once, so an Apache-persona honeypot and a
    Docker API decoy both answered malformed probes as nginx.

    That is not a cosmetic gap. `nmap -sV` sends malformed probes deliberately
    and matches on whatever comes back, so it identified the Docker API engine
    as nginx — a service nobody runs on 2375 — and an expert diffing a
    malformed against a well-formed response saw two different servers on one
    port. Every persona in the system leaked at the same seam.

    aiohttp has no per-server setting for this, but the object graph is
    reachable: `AppRunner._make_server()` builds the `Server`, `Server.__call__`
    builds the `RequestHandler`, and `handle_error` returns an ordinary
    `Response` before it is written. Subclassing the three and stamping the
    header on the way out fixes it without touching the global, so listeners in
    one process can wear different identities. An explicitly set header beats
    the `setdefault` that would otherwise apply the global.
    """

    class _IdentityRequestHandler(web_protocol.RequestHandler):  # type: ignore[misc,type-arg]
        def handle_error(
            self,
            request: Any,
            status: int = 500,
            exc: BaseException | None = None,
            message: str | None = None,
        ) -> Any:
            response = super().handle_error(request, status, exc, message)
            response.headers["Server"] = server
            return response

    class _IdentityServer(web_server.Server):  # type: ignore[misc]
        def __call__(self) -> Any:
            return _IdentityRequestHandler(self, loop=self._loop, **self._kwargs)

    class _IdentityRunner(web.AppRunner):
        async def _make_server(self) -> Any:
            loop = asyncio.get_event_loop()
            self._app._set_loop(loop)
            self._app.on_startup.freeze()
            await self._app.startup()
            self._app.freeze()
            return _IdentityServer(
                self._app._handle,  # type: ignore[arg-type]
                request_factory=self._app._make_request,
                loop=loop,
                **self._kwargs,
            )

    return _IdentityRunner(app)


class ExactHeaderResponse(web.Response):
    """A response with no `Server` header and a caller-chosen header order.

    Some services genuinely send none, and "none" is not something aiohttp can
    express: `_prepare_headers` unconditionally `setdefault`s the header, so
    the best a caller can normally do is an empty `Server:` line — which is
    still a line, and still wrong.

    It matters because nmap's service signatures are exact. Its Docker match is
    a real daemon's 404 — `Content-Type`, `Date`, `Content-Length: 29`, that
    body, and nothing else — so a single extra header makes an otherwise
    byte-faithful response fail to identify, and the port reads as `unknown` or,
    worse, as whatever the fallback banner says.

    Order matters for the same reason. nmap's Docker rule expects
    `Content-Type`, then `Date`, then `Content-Length`; aiohttp emits
    Content-Length before Date, and that alone is enough to miss. Header order
    is semantically irrelevant to HTTP and entirely relevant to fingerprinting.

    `_prepare_headers` runs before `_write_headers`, so this is the last point
    at which either can be changed.
    """

    #: Header names in the order they should appear. Anything not listed keeps
    #: its existing relative position, after the ordered ones.
    header_order: tuple[str, ...] = ()

    async def _prepare_headers(self) -> None:
        await super()._prepare_headers()
        self._headers.popall("Server", None)  # type: ignore[arg-type]
        if not self.header_order:
            return
        remaining = [
            (name, value)
            for name, value in self._headers.items()
            if name.lower() not in {h.lower() for h in self.header_order}
        ]
        ordered = [
            (name, self._headers[name]) for name in self.header_order if name in self._headers
        ]
        self._headers.clear()
        for name, value in ordered + remaining:
            self._headers.add(name, value)
