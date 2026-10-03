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
from dataclasses import dataclass
from typing import Any

from aiohttp import web, web_protocol, web_response, web_server

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.conn_limit import ConnectionLimiter

# Idle keep-alive. aiohttp's own default is ~1 hour, which lets one client park
# a socket on a honeypot indefinitely between requests.
_KEEPALIVE_SECONDS = 15.0

# The most a body helper reads from a stream. Matches aiohttp's default
# `client_max_size`, which every engine's `web.Application` now sets explicitly.
MAX_REQUEST_BYTES = 1024 * 1024

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


def identity_runner(
    app: web.Application,
    server: str,
    *,
    max_connections_per_ip: int | None = None,
    first_request_timeout: float | None = None,
    keepalive_timeout: float = _KEEPALIVE_SECONDS,
) -> web.AppRunner:
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

    The same handler subclass is where connection hygiene lives, because
    aiohttp offers it nowhere else: a per-source-IP concurrent connection cap
    (`max_connections_per_ip`, default from settings, 0 = unlimited), a timer
    that closes a connection which has not produced a complete request head
    within `first_request_timeout` seconds (default from settings, 0 = off —
    aiohttp waits forever for a first request), and `keepalive_timeout`.
    Every parameter is optional so existing callers are unchanged.
    """
    settings = get_settings()
    cap = (
        settings.max_connections_per_ip
        if max_connections_per_ip is None
        else max_connections_per_ip
    )
    first_timeout = (
        settings.http_first_request_timeout_seconds
        if first_request_timeout is None
        else first_request_timeout
    )
    limiter = ConnectionLimiter(cap)

    class _IdentityRequestHandler(web_protocol.RequestHandler):  # type: ignore[misc,type-arg]
        _hp_ip: str = ""
        _hp_admitted: bool = False
        _hp_seen_request: bool = False
        _hp_first_timer: asyncio.TimerHandle | None = None

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            super().connection_made(transport)
            peer = transport.get_extra_info("peername") or ("", 0)
            self._hp_ip = peer[0] if peer else ""
            if not limiter.try_acquire(self._hp_ip):
                # Over the per-IP cap: drop it. The handler task started by
                # `super().connection_made` is cancelled by `force_close`.
                self.force_close()
                return
            self._hp_admitted = True
            if first_timeout > 0:
                self._hp_first_timer = self._loop.call_later(first_timeout, self._hp_first_expired)

        def _hp_first_expired(self) -> None:
            self._hp_first_timer = None
            if not self._hp_seen_request:
                self.force_close()

        async def _handle_request(self, request: Any, start_time: Any, request_handler: Any) -> Any:
            # A request head has been fully parsed: this is no longer a
            # slowloris, and body slowness is bounded by `read_body`.
            self._hp_seen_request = True
            if self._hp_first_timer is not None:
                self._hp_first_timer.cancel()
                self._hp_first_timer = None
            return await super()._handle_request(request, start_time, request_handler)

        def connection_lost(self, exc: BaseException | None) -> None:
            if self._hp_first_timer is not None:
                self._hp_first_timer.cancel()
                self._hp_first_timer = None
            if self._hp_admitted:
                self._hp_admitted = False
                limiter.release(self._hp_ip)
            super().connection_lost(exc)

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

    return _IdentityRunner(app, keepalive_timeout=keepalive_timeout)


@dataclass(frozen=True)
class BodyRead:
    """Result of `read_body`: what arrived, and why reading stopped."""

    data: bytes
    #: More than `limit` bytes were available; `data` is the first `limit`.
    truncated: bool = False
    #: The body was still arriving when the timeout fired; `data` is partial.
    timed_out: bool = False


def body_timeout() -> float | None:
    """The configured body deadline in seconds, or None when disabled."""
    seconds = get_settings().http_body_timeout_seconds
    return seconds if seconds > 0 else None


async def with_body_timeout(awaitable: Any) -> Any:
    """Await a body read (`request.post()`, `request.text()`…) under the
    configured body deadline. Raises `TimeoutError` when it fires."""
    async with asyncio.timeout(body_timeout()):
        return await awaitable


async def read_body(request: web.Request, limit: int = MAX_REQUEST_BYTES) -> BodyRead:
    """Read the whole request body, up to `limit` bytes, within the body deadline.

    `request.content.read(n)` returns as soon as *one* chunk is available, so a
    body sent in two TCP writes was silently cut in half — and an escape POST
    split across writes lost its payload. This loops until EOF instead. It
    never raises for a slow or broken sender: whatever arrived is returned and
    flagged, because a partial capture is evidence and an exception is not.
    """
    buf = bytearray()
    truncated = False
    timed_out = False
    try:
        async with asyncio.timeout(body_timeout()):
            while True:
                chunk = await request.content.readany()
                if not chunk:
                    break
                buf += chunk
                if len(buf) > limit:
                    truncated = True
                    del buf[limit:]
                    break
    except TimeoutError:
        timed_out = True
    except Exception:  # client reset or malformed framing: keep what arrived
        pass
    return BodyRead(bytes(buf), truncated, timed_out)


def clip(value: object, limit: int) -> str:
    """`value` as a str of at most `limit` characters that is safe to JSON-encode.

    aiohttp decodes header bytes with `surrogateescape`, so a header can carry
    lone surrogates that PostgreSQL's JSON type rejects — one such request would
    otherwise fail the whole batch it is flushed in.
    """
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        text = text[:limit]
    return text.encode("utf-8", "replace").decode("utf-8")


# Headers that carry stolen credentials. They are kept (and kept whole) even
# when a request pads dozens of junk headers ahead of them, because
# `token_matchers` reads them out of the stored payload.
_CREDENTIAL_HEADERS = frozenset(
    {"authorization", "proxy-authorization", "cookie", "x-api-key", "x-auth-token"}
)


def safe_headers(
    request: web.Request, max_items: int = 64, max_value: int = 2048
) -> dict[str, str]:
    """The request headers as a bounded `{name: value}` dict for an event payload.

    aiohttp allows 128 headers of 8 KB each, so an unshaped copy lets one
    request put ~1 MB into the payload. Credential-bearing headers are taken
    first and are not clipped below aiohttp's own 8 KB field limit.
    """
    items = list(request.headers.items())
    ordered = [kv for kv in items if kv[0].lower() in _CREDENTIAL_HEADERS]
    ordered += [kv for kv in items if kv[0].lower() not in _CREDENTIAL_HEADERS]
    out: dict[str, str] = {}
    for name, value in ordered:
        if len(out) >= max_items:
            break
        limit = 8192 if name.lower() in _CREDENTIAL_HEADERS else max_value
        out.setdefault(clip(name, 256), clip(value, limit))
    return out


def safe_query(request: web.Request, max_items: int = 64, max_value: int = 1024) -> dict[str, str]:
    """The query string as a bounded `{name: value}` dict for an event payload."""
    out: dict[str, str] = {}
    for name, value in request.query.items():
        if len(out) >= max_items:
            break
        out[clip(name, 256)] = clip(value, max_value)
    return out


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
