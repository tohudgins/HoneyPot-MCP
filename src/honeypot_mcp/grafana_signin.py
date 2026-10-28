"""A single-use link that opens a Grafana dashboard already signed in.

Grafana asks for a password, which this server writes to a private file and never returns (a
model would repeat it into a transcript). Telling the person to open that file and type it in is
exactly the kind of instruction a tool should not hand back. Instead the server holds the password
and issues a link that signs them in:

1. `mint()` starts a tiny server on a free loopback port and returns `http://127.0.0.1:<port>/<token>`.
2. The first request for that path makes the server log in to Grafana itself (Grafana's `/login`
   takes JSON) and answer with a redirect to the dashboard that carries Grafana's session cookie.
   Cookies are scoped to a host, not a port, so the browser sends it on to Grafana at the same
   `127.0.0.1`.
3. The link works once and for ten minutes. The server then closes, so a link left in a transcript
   is dead, and it only ever listens on loopback.

The password reaches nothing but Grafana and the person's own browser session cookie.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from urllib.parse import urlsplit

import httpx

from honeypot_mcp.engines._tasks import spawn

log = logging.getLogger(__name__)

LIFETIME_SECONDS = 600
_servers: set[asyncio.Server] = set()


def _response(status: str, headers: list[tuple[str, str]], body: bytes = b"") -> bytes:
    lines = [
        f"HTTP/1.1 {status}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "Cache-Control: no-store",
    ]
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


async def _login_cookies(grafana_port: int, user: str, password: str) -> list[str] | None:
    """Log in to Grafana the way its own page does and return the Set-Cookie header values."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"http://127.0.0.1:{grafana_port}/login", json={"user": user, "password": password}
            )
    except httpx.HTTPError as exc:
        log.warning("Grafana sign-in link: login request failed (%s)", type(exc).__name__)
        return None
    cookies = resp.headers.get_list("set-cookie")
    return cookies if resp.status_code == 200 and cookies else None


async def mint(grafana_port: int, user: str, password: str, destination: str) -> str:
    """Return a single-use link that signs in to Grafana and lands on `destination`.

    `destination` is a full URL on that Grafana (a dashboard with its time range). Raises OSError
    if no loopback port can be opened; the caller falls back to the plain URL.
    """
    token = secrets.token_urlsafe(24)
    done = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        reply = _response("404 Not Found", [], b"Not found")
        used = False
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            host = next(
                (ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("host:")),
                "",
            )
            # DNS-rebinding guard: only a request addressed to the loopback name we handed out.
            on_loopback = urlsplit("//" + host).hostname in ("127.0.0.1", "localhost")
            if len(parts) >= 2 and parts[0] == "GET" and parts[1] == f"/{token}" and on_loopback:
                cookies = await _login_cookies(grafana_port, user, password)
                if cookies is None:
                    reply = _response(
                        "502 Bad Gateway",
                        [("Content-Type", "text/plain")],
                        b"Could not sign in to Grafana. Ask for a new link (grafana_status).",
                    )
                else:
                    reply = _response(
                        "302 Found",
                        [("Location", destination)] + [("Set-Cookie", c) for c in cookies],
                    )
                used = True
        except (
            TimeoutError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            ConnectionError,
        ):
            pass
        try:
            writer.write(reply)
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()
        if used:
            done.set()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    _servers.add(server)
    port = server.sockets[0].getsockname()[1]

    async def close_when_done() -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(done.wait(), timeout=LIFETIME_SECONDS)
        server.close()
        _servers.discard(server)

    spawn(close_when_done(), name="grafana-signin-link")
    return f"http://127.0.0.1:{port}/{token}"
