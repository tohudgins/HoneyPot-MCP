"""Per-source-IP concurrent-connection cap for the in-process TCP engines.

A single hostile or broken peer can otherwise open arbitrarily many sockets
against an engine. The read bounds in each engine limit memory *per*
connection, but nothing caps the *number* of concurrent connections from one
IP — this closes that gap.

Two integration surfaces, mirroring how the engines start their listeners:

- `asyncio.Protocol` engines call `loop.create_server(factory, ...)`. Wrap the
  factory with `limited_factory(factory, limiter)`: each accepted connection is
  admitted or rejected in `connection_made` before the real protocol ever sees
  it. Rejected connections are closed immediately and the inner protocol is
  never driven, so its state machine only ever runs for admitted peers.
- Coroutine-handler engines (SMB) call `asyncio.start_server(handler, ...)`.
  Wrap the handler with `limited_handler(handler, limiter)`.

`max_per_ip <= 0` disables the cap entirely (the limiter admits everything),
so the default-off path costs a single integer comparison.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable

log = logging.getLogger(__name__)


class ConnectionLimiter:
    """Tracks live connection counts per source IP for one engine instance.

    Not thread-safe, but asyncio is single-threaded and every mutation happens
    from a callback on the one event loop, so no locking is needed.
    """

    def __init__(self, max_per_ip: int) -> None:
        self._max = max_per_ip
        self._counts: dict[str, int] = defaultdict(int)

    def try_acquire(self, ip: str) -> bool:
        """Reserve a slot for `ip`. Returns False if the IP is already at the
        cap (caller must reject the connection without calling `release`)."""
        if self._max <= 0:
            return True
        if self._counts[ip] >= self._max:
            return False
        self._counts[ip] += 1
        return True

    def release(self, ip: str) -> None:
        """Return a slot previously reserved via a successful `try_acquire`."""
        if self._max <= 0:
            return
        n = self._counts.get(ip, 0)
        if n <= 1:
            self._counts.pop(ip, None)
        else:
            self._counts[ip] = n - 1

    def live_count(self, ip: str) -> int:
        return self._counts.get(ip, 0)


def _peer_ip(transport: asyncio.BaseTransport) -> str:
    peer = transport.get_extra_info("peername") or ("", 0)
    return peer[0] if peer else ""


class _LimitedProtocol(asyncio.Protocol):
    """Delegating wrapper that admits or rejects a connection by source-IP cap
    before handing it to the real protocol. All `Protocol` callbacks forward to
    the inner protocol only for admitted connections."""

    def __init__(self, inner: asyncio.Protocol, limiter: ConnectionLimiter) -> None:
        self._inner = inner
        self._limiter = limiter
        self._admitted = False
        self._ip = ""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._ip = _peer_ip(transport)
        if not self._limiter.try_acquire(self._ip):
            log.debug("Connection from %s rejected: per-IP cap reached.", self._ip)
            transport.close()
            return
        self._admitted = True
        self._inner.connection_made(transport)

    def data_received(self, data: bytes) -> None:
        if self._admitted:
            self._inner.data_received(data)

    def eof_received(self) -> bool | None:
        if self._admitted:
            return self._inner.eof_received()
        return None

    def connection_lost(self, exc: Exception | None) -> None:
        if self._admitted:
            self._admitted = False
            self._limiter.release(self._ip)
            self._inner.connection_lost(exc)

    def pause_writing(self) -> None:
        if self._admitted:
            self._inner.pause_writing()

    def resume_writing(self) -> None:
        if self._admitted:
            self._inner.resume_writing()


def limited_factory(
    factory: Callable[[], asyncio.Protocol], limiter: ConnectionLimiter
) -> Callable[[], asyncio.Protocol]:
    """Wrap a `create_server` protocol factory so each connection is capped."""
    return lambda: _LimitedProtocol(factory(), limiter)


def limited_handler(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    limiter: ConnectionLimiter,
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    """Wrap a `start_server` coroutine handler so each connection is capped."""

    async def _wrapped(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip = _peer_ip(writer.transport)
        if not limiter.try_acquire(ip):
            log.debug("Connection from %s rejected: per-IP cap reached.", ip)
            writer.close()
            return
        try:
            await handler(reader, writer)
        finally:
            limiter.release(ip)

    return _wrapped
