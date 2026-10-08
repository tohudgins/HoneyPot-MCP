"""A TLS listener that answers the way Go and OpenSSL servers do when the handshake never starts.

`web.TCPSite(..., ssl_context=ctx)` hands every connection straight to asyncio's TLS layer. When
that layer rejects the first bytes it closes the socket with nothing written, so:

* nmap's `SSLSessionReq` probe (an SSLv3-versioned ClientHello) against a context whose minimum is
  TLS 1.2 gets silence where a real server sends a `protocol_version` alert. `nmap -sV` then
  reports `m2ap?` instead of `ssl/http`, and the `ssl-cert` script never runs.
* Plaintext HTTP sent to the port gets silence where Go's `net/http` answers
  `HTTP/1.0 400 Bad Request` with a one-line explanation. That reply is also how scanners find
  out that the port is "really" HTTP behind TLS.

`TLSFrontSite` accepts the raw sockets itself, `MSG_PEEK`s at most a ClientHello's first 16 bytes
(consuming nothing), and then either hands the untouched socket to asyncio's TLS machinery with
`loop.connect_accepted_socket` (so the application still sees the real peer address) or writes
the reply a real server would and closes.

Everything between `accept()` and the handoff is bounded: a sniff deadline, a global cap and a
per-source cap on connections still being classified, and a cap on how much of a client's
leftover bytes are read while lingering. A slow-loris therefore cannot accumulate tasks or
descriptors.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import logging
import re
import socket
import ssl
from collections.abc import Callable
from typing import Any

from aiohttp import web

from honeypot_mcp.engines._tasks import spawn

log = logging.getLogger(__name__)

# What a Go `crypto/tls` server writes before a connection has negotiated a version: a fatal
# (level 2) `protocol_version` (70) alert in a TLS 1.0-versioned record. nmap-service-probes
# matches it with `^\x15\x03[\x00-\x04]\0\x02\x02[F\x28]`.
PROTOCOL_VERSION_ALERT = b"\x15\x03\x01\x00\x02\x02\x46"

# net/http's reply to plaintext on an HTTPS listener (`tls.RecordHeaderError` handling in
# `http.Server.serve`), byte for byte.
GO_PLAINTEXT_HTTP_REPLY = (
    b"HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
)

# What to write to plaintext HTTP: fixed bytes, a callable given the request's Host header (so
# the reply can carry a current Date and name the host), or None to just close, as IIS does.
PlaintextReply = bytes | Callable[[str | None], bytes | None] | None

_HOST_HEADER = re.compile(rb"\r\nHost:[ \t]*([A-Za-z0-9.\-:\[\]]{1,255})", re.IGNORECASE)


def _peek_host(sock: socket.socket) -> str | None:
    """The Host header of the HTTP request waiting on `sock`, from a bounded non-consuming peek."""
    try:
        head = sock.recv(2048, socket.MSG_PEEK | socket.MSG_DONTWAIT)
    except OSError:
        return None
    match = _HOST_HEADER.search(head)
    if match is None:
        return None
    host = match.group(1).decode("ascii")
    return host.rsplit(":", 1)[0] if not host.endswith("]") and host.count(":") == 1 else host


_PEEK_BYTES = 16  # 5-byte record header + 4-byte handshake header + 2-byte legacy_version, + slack
_MAX_RECORD_PAYLOAD = 1 << 14  # RFC 8446 section 5.1: a plaintext record never exceeds 2^14
_MIN_HELLO_VERSION = 0x0303  # TLS 1.2; the contexts this fronts have minimum_version >= 1.2

# Methods a scanner or browser sends. Matched as `<METHOD><space>` against the peeked bytes.
_HTTP_METHODS = tuple(
    m + b" "
    for m in (
        b"GET",
        b"HEAD",
        b"POST",
        b"PUT",
        b"DELETE",
        b"OPTIONS",
        b"PATCH",
        b"CONNECT",
        b"TRACE",
        b"PROPFIND",
    )
)

_SNIFF_TIMEOUT = 5.0
_HANDSHAKE_TIMEOUT = 10.0
_WRITE_TIMEOUT = 2.0
_LINGER_SECONDS = 1.0
_LINGER_MAX_BYTES = 64 * 1024
_MAX_PENDING = 256
_MAX_PENDING_PER_IP = 32
_ACCEPT_ERROR_BACKOFF = 1.0


class _Kind(enum.Enum):
    TLS = "tls"  # a ClientHello this server can negotiate
    OLD_TLS = "old_tls"  # a ClientHello below TLS 1.2
    HTTP = "http"  # plaintext HTTP request
    OTHER = "other"  # neither: close without a word
    NEED_MORE = "need_more"


def classify_first_bytes(data: bytes) -> _Kind:
    """Decide what the first (peeked) bytes of a connection are. Pure, and bounded by `len(data)`.

    `NEED_MORE` means the bytes seen so far are consistent with TLS or HTTP but too few to tell
    which branch applies.
    """
    if not data:
        return _Kind.NEED_MORE

    first = data[0]
    if first == 0x16:  # handshake record
        if len(data) >= 2 and data[1] != 0x03:
            return _Kind.OTHER
        if len(data) >= 3 and data[2] > 0x04:
            return _Kind.OTHER
        if len(data) >= 5:
            length = int.from_bytes(data[3:5], "big")
            if not 4 <= length <= _MAX_RECORD_PAYLOAD:
                return _Kind.OTHER
        if len(data) >= 6 and data[5] != 0x01:  # not a ClientHello
            return _Kind.OTHER
        if len(data) < 11:
            return _Kind.NEED_MORE
        hello_version = int.from_bytes(data[9:11], "big")
        if hello_version >> 8 != 0x03:
            return _Kind.OTHER
        return _Kind.TLS if hello_version >= _MIN_HELLO_VERSION else _Kind.OLD_TLS

    longest = max(len(m) for m in _HTTP_METHODS)
    head = data[:longest]
    if any(head.startswith(m) for m in _HTTP_METHODS):
        return _Kind.HTTP
    if len(data) < longest and any(m.startswith(head) for m in _HTTP_METHODS):
        return _Kind.NEED_MORE
    return _Kind.OTHER


def _peek(sock: socket.socket) -> bytes | None:
    """`recv(MSG_PEEK)` without consuming: `b""` = nothing yet, `None` = closed or errored."""
    try:
        data = sock.recv(_PEEK_BYTES, socket.MSG_PEEK)
    except (BlockingIOError, InterruptedError):
        return b""
    except OSError:
        return None
    return data if data else None  # recv() == b"" on a non-blocking socket is EOF


async def _wait_readable(sock: socket.socket, timeout: float) -> bool:
    """True once `sock` is readable; False if `timeout` elapses first."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[None] = loop.create_future()

    def _ready() -> None:
        if not fut.done():
            fut.set_result(None)

    fd = sock.fileno()
    loop.add_reader(fd, _ready)
    try:
        async with asyncio.timeout(timeout):
            await fut
    except TimeoutError:
        return False
    finally:
        loop.remove_reader(fd)
    return True


class TLSFrontSite(web.BaseSite):
    """Drop-in for `web.TCPSite(..., ssl_context=ctx)` that answers non-handshakes like Go does."""

    __slots__ = (
        "_host",
        "_port",
        "_bound_port",
        "_lsock",
        "_accept_task",
        "_tasks",
        "_pending_by_ip",
        "_sniff_timeout",
        "_handshake_timeout",
        "_max_pending",
        "_max_pending_per_ip",
        "_plaintext_reply",
        "_alert",
        "_stopped",
    )

    def __init__(
        self,
        runner: web.BaseRunner,
        host: str | None,
        port: int,
        *,
        ssl_context: ssl.SSLContext,
        backlog: int = 128,
        sniff_timeout: float = _SNIFF_TIMEOUT,
        handshake_timeout: float = _HANDSHAKE_TIMEOUT,
        max_pending: int = _MAX_PENDING,
        max_pending_per_ip: int = _MAX_PENDING_PER_IP,
        plaintext_reply: PlaintextReply = GO_PLAINTEXT_HTTP_REPLY,
        version_alert: bytes = PROTOCOL_VERSION_ALERT,
    ) -> None:
        super().__init__(runner, ssl_context=ssl_context, backlog=backlog)
        self._host = host
        self._port = port
        self._bound_port: int | None = None
        self._lsock: socket.socket | None = None
        self._accept_task: asyncio.Task[Any] | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._pending_by_ip: dict[str, int] = {}
        self._sniff_timeout = sniff_timeout
        self._handshake_timeout = handshake_timeout
        self._max_pending = max_pending
        self._max_pending_per_ip = max_pending_per_ip
        self._plaintext_reply = plaintext_reply
        self._alert = version_alert
        self._stopped = False

    @property
    def port(self) -> int:
        return self._bound_port if self._bound_port is not None else self._port

    @property
    def name(self) -> str:
        return f"https://{self._host or '0.0.0.0'}:{self.port}"  # noqa: S104

    @property
    def pending(self) -> int:
        """Connections accepted but not yet classified and handed off (for tests/metrics)."""
        return len(self._tasks)

    async def start(self) -> None:
        if self._lsock is not None:
            raise RuntimeError(f"{self!r} is already started")
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            self._host or None, self._port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
        )
        family, kind, proto, _, addr = infos[0]
        sock = socket.socket(family, kind, proto)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setblocking(False)
            sock.bind(addr)
            sock.listen(self._backlog)
        except BaseException:
            sock.close()
            raise
        self._lsock = sock
        self._bound_port = sock.getsockname()[1]
        await super().start()  # registers the site with the runner
        self._accept_task = spawn(self._accept_loop(sock), name=f"tls-front-accept:{self.port}")

    async def stop(self) -> None:
        self._runner._check_site(self)
        await self._shutdown()
        self._runner._unreg_site(self)

    async def _shutdown(self) -> None:
        self._stopped = True
        tasks = list(self._tasks)
        if self._accept_task is not None:
            tasks.append(self._accept_task)
        for task in tasks:
            task.cancel()
        # Awaited so no sniff task outlives the site, and the listening socket is closed only
        # after nothing is registered with the selector for it.
        await asyncio.gather(*tasks, return_exceptions=True)
        self._accept_task = None
        if self._lsock is not None:
            self._lsock.close()
            self._lsock = None

    # ── accept ──────────────────────────────────────────────────────────────────────────

    async def _accept_loop(self, lsock: socket.socket) -> None:
        loop = asyncio.get_running_loop()
        while not self._stopped:
            try:
                conn, addr = await loop.sock_accept(lsock)
            except OSError as exc:
                if self._stopped or lsock.fileno() == -1:
                    return
                # EMFILE and friends: back off rather than spin; the listener stays open.
                log.warning("TLS front accept failed on port %d: %s", self.port, exc)
                await asyncio.sleep(_ACCEPT_ERROR_BACKOFF)
                continue
            self._admit(conn, addr[0] if addr else "")

    def _admit(self, conn: socket.socket, ip: str) -> None:
        if len(self._tasks) >= self._max_pending or (
            self._pending_by_ip.get(ip, 0) >= self._max_pending_per_ip
        ):
            conn.close()
            return
        self._pending_by_ip[ip] = self._pending_by_ip.get(ip, 0) + 1
        task = spawn(self._handle(conn, ip), name=f"tls-front-conn:{self.port}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ── per connection ─────────────────────────────────────────────────────────────────

    async def _handle(self, conn: socket.socket, ip: str) -> None:
        handed_off = False
        try:
            kind = await self._sniff(conn)
            loop = asyncio.get_running_loop()
            server = self._runner.server
            if kind is _Kind.TLS and server is not None:
                await loop.connect_accepted_socket(
                    server,
                    conn,
                    ssl=self._ssl_context,
                    ssl_handshake_timeout=self._handshake_timeout,
                )
                handed_off = True
            elif kind is _Kind.OLD_TLS:
                await self._reply_and_close(conn, self._alert)
            elif kind is _Kind.HTTP:
                reply = self._plaintext_reply
                if callable(reply):
                    reply = reply(_peek_host(conn))
                if reply:
                    await self._reply_and_close(conn, reply)
        except (OSError, TimeoutError, ssl.SSLError) as exc:
            # A failed handshake or a vanished peer: ordinary scanner behaviour, not an error.
            log.debug("TLS front connection from %s dropped: %r", ip, exc)
        finally:
            if not handed_off:
                conn.close()
            left = self._pending_by_ip.get(ip, 1) - 1
            if left > 0:
                self._pending_by_ip[ip] = left
            else:
                self._pending_by_ip.pop(ip, None)

    async def _sniff(self, conn: socket.socket) -> _Kind:
        """Peek until the first bytes classify, the peer goes away or the deadline passes."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._sniff_timeout
        delay = 0.005
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return _Kind.OTHER
            data = _peek(conn)
            if data is None:
                return _Kind.OTHER
            if not data:
                # Nothing yet: park on readability (no polling for a silent peer).
                if not await _wait_readable(conn, remaining):
                    return _Kind.OTHER
                continue
            kind = classify_first_bytes(data)
            if kind is not _Kind.NEED_MORE:
                return kind
            # Some bytes, not enough. They stay readable (peek consumes nothing), so waiting
            # on readability would spin; back off instead. Bounded by the deadline above.
            await asyncio.sleep(min(delay, remaining))
            delay = min(delay * 2, 0.1)

    async def _reply_and_close(self, conn: socket.socket, payload: bytes) -> None:
        """Write `payload`, half-close, and swallow what the client still sends.

        Closing with unread bytes in the receive queue makes the kernel send RST, which can
        reach the client before our reply is read and turn it into ECONNRESET. The drain is
        capped in both time and bytes.
        """
        loop = asyncio.get_running_loop()
        try:
            async with asyncio.timeout(_WRITE_TIMEOUT):
                await loop.sock_sendall(conn, payload)
            conn.shutdown(socket.SHUT_WR)
            drained = 0
            async with asyncio.timeout(_LINGER_SECONDS):
                while drained < _LINGER_MAX_BYTES:
                    chunk = await loop.sock_recv(conn, 4096)
                    if not chunk:
                        break
                    drained += len(chunk)
        except (OSError, TimeoutError):
            return


async def start_tls_site(
    runner: web.BaseRunner,
    host: str | None,
    port: int,
    ssl_context: ssl.SSLContext,
    **options: Any,
) -> web.BaseSite:
    """Start a `TLSFrontSite` on `runner` — a drop-in for `await web.TCPSite(...).start()`.

    `runner.cleanup()` stops the site and releases the port. Keyword `options` are passed to
    `TLSFrontSite` (timeouts, caps, alternative reply bytes).
    """
    site = TLSFrontSite(runner, host, port, ssl_context=ssl_context, **options)
    try:
        await site.start()
    except BaseException:
        with contextlib.suppress(Exception):
            await site._shutdown()
        raise
    return site
