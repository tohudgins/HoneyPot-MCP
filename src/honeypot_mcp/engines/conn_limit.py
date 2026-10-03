"""Connection-level protection shared by the in-process engines.

A single hostile or broken peer can otherwise open arbitrarily many sockets
against an engine, hold them open forever, or make an engine answer a spoofed
UDP datagram with something larger than what it was sent. The read bounds in
each engine limit memory *per* connection; this module covers the rest:

- **Per-source-IP cap** (`ConnectionLimiter`): concurrent connections per IP.
- **Process-wide ceiling** (`max_total_connections` setting): the per-IP cap is
  defeated by many source addresses, so the sum across every limiter is capped
  too.
- **Idle timeout and maximum session lifetime** (`engine_idle_timeout_seconds`,
  `engine_max_session_seconds`): slowloris protection applied centrally, so no
  engine needs a timer of its own.
- **Live-transport tracking** (`ConnectionLimiter.close_all`, `shutdown_server`):
  on Python >= 3.12.1 `Server.wait_closed()` waits for every live connection,
  so `stop()` on an engine with an idle client hangs forever unless the
  connections are closed first.
- **Per-source UDP reply rate** (`UdpReplyLimiter`): UDP source addresses are
  trivially spoofed, so replies are token-bucketed per source.
- **Bounded line extraction** (`extract_lines`): O(n) splitting with a hard cap
  on lines per read and bytes per line.

Two integration surfaces, mirroring how the engines start their listeners:

- `asyncio.Protocol` engines call `loop.create_server(factory, ...)`. Wrap the
  factory with `limited_factory(factory, limiter)`: each accepted connection is
  admitted or rejected in `connection_made` before the real protocol ever sees
  it. Rejected connections are closed immediately and the inner protocol is
  never driven, so its state machine only ever runs for admitted peers.
- Coroutine-handler engines (SMB, RDP) call `asyncio.start_server(handler, ...)`.
  Wrap the handler with `limited_handler(handler, limiter)`.

`max_per_ip <= 0` disables the per-IP cap (the limiter admits everything), so
the default-off path costs a single integer comparison.

An inner protocol that upgrades its transport (STARTTLS) must hand the
*wrapper* to `loop.start_tls`, not itself, or the wrapper never sees
`connection_lost` and the limiter slot leaks. A protocol opts in by defining
`adopt_wrapper(wrapper)`; `_LimitedProtocol` calls it before `connection_made`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import weakref
from collections import OrderedDict, defaultdict, deque
from collections.abc import Awaitable, Callable
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._tasks import spawn

log = logging.getLogger(__name__)

# Every limiter that exists, so the process-wide connection ceiling can sum
# their live counts. Weak, so a discarded limiter (an engine that was replaced,
# a test's throwaway) stops counting the moment it is collected.
_ALL_LIMITERS: weakref.WeakSet[ConnectionLimiter] = weakref.WeakSet()


def _running_loop() -> asyncio.AbstractEventLoop | None:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def _abort(transport: Any) -> None:
    """Close `transport` without waiting for the peer: an idle or expired
    connection is, by definition, not cooperating."""
    fn = getattr(transport, "abort", None) or getattr(transport, "close", None)
    if fn is not None:
        with contextlib.suppress(Exception):
            fn()


class ConnectionLimiter:
    """Tracks live connection counts per source IP for one engine instance.

    Not thread-safe, but asyncio is single-threaded and every mutation happens
    from a callback on the one event loop, so no locking is needed.
    """

    def __init__(self, max_per_ip: int) -> None:
        self._max = max_per_ip
        self._counts: dict[str, int] = defaultdict(int)
        self._total = 0
        self._transports: set[Any] = set()
        _ALL_LIMITERS.add(self)

    @property
    def total(self) -> int:
        """Connections currently admitted through this limiter."""
        return self._total

    def try_acquire(self, ip: str) -> bool:
        """Reserve a slot for `ip`. Returns False if the IP is already at the
        cap or the process-wide ceiling is reached (caller must reject the
        connection without calling `release`)."""
        ceiling = get_settings().max_total_connections
        if ceiling > 0 and sum(lim._total for lim in _ALL_LIMITERS) >= ceiling:
            return False
        if self._max > 0:
            if self._counts[ip] >= self._max:
                return False
            self._counts[ip] += 1
        self._total += 1
        return True

    def release(self, ip: str) -> None:
        """Return a slot previously reserved via a successful `try_acquire`."""
        if self._max > 0:
            n = self._counts.get(ip, 0)
            if n == 0:
                return  # never acquired: nothing to give back
            if n == 1:
                self._counts.pop(ip, None)
            else:
                self._counts[ip] = n - 1
        if self._total > 0:
            self._total -= 1

    def live_count(self, ip: str) -> int:
        return self._counts.get(ip, 0)

    def track(self, transport: Any) -> None:
        """Remember an admitted connection so `close_all` can end it."""
        self._transports.add(transport)

    def untrack(self, transport: Any) -> None:
        self._transports.discard(transport)

    def close_all(self, ports: set[int] | None = None) -> None:
        """Abort live admitted connections. Called from `stop()` after the
        listening socket is closed.

        Engines are per-type singletons, so one limiter serves every honeypot
        of that type; `ports` restricts the close to connections accepted on
        those local ports (the honeypot being stopped). None closes all."""
        for transport in list(self._transports):
            if ports is not None:
                sockname = transport.get_extra_info("sockname")
                if not isinstance(sockname, tuple) or len(sockname) < 2:
                    continue
                if sockname[1] not in ports:
                    continue
            _abort(transport)
            self._transports.discard(transport)


def close_after_error(transport: Any, grace: float = 2.0) -> None:
    """End a connection after an error reply without destroying that reply.

    `close()` with unread input still queued makes the kernel send RST, which
    can discard the reply the peer has not read yet. Instead: stop reading
    (so nothing more is processed), half-close so the peer sees the reply and
    then EOF, and drop the socket after a short grace period."""
    if transport.is_closing():
        return
    with contextlib.suppress(Exception):
        transport.pause_reading()
    loop = _running_loop()
    if loop is not None and transport.can_write_eof():
        transport.write_eof()
        loop.call_later(grace, _abort, transport)
    else:
        transport.close()


async def shutdown_server(
    server: asyncio.AbstractServer,
    limiter: ConnectionLimiter | None = None,
    timeout: float = 5.0,
) -> None:
    """Stop accepting, drop live connections, and wait (bounded) for the close.

    `Server.wait_closed()` blocks until every connection is gone on Python
    >= 3.12.1, so a client that simply sits idle would hang `stop()` forever.
    Only connections accepted by *this* server are dropped.
    """
    ports: set[int] = set()
    for sock in getattr(server, "sockets", None) or ():
        with contextlib.suppress(OSError, IndexError, TypeError):
            ports.add(int(sock.getsockname()[1]))
    server.close()
    if limiter is not None:
        limiter.close_all(ports)
    try:
        await asyncio.wait_for(server.wait_closed(), timeout=timeout)
    except TimeoutError:
        log.warning("Server did not finish closing within %.0fs; continuing.", timeout)


def _peer_ip(transport: asyncio.BaseTransport) -> str:
    peer = transport.get_extra_info("peername") or ("", 0)
    return peer[0] if peer else ""


def _setting_seconds(override: float | None, name: str) -> float:
    return float(getattr(get_settings(), name)) if override is None else float(override)


class _SessionTimers:
    """Idle timeout + maximum lifetime for one connection.

    Activity is a timestamp, not a rescheduled timer: `touch()` runs on every
    received chunk, and cancelling/creating a `TimerHandle` per chunk would turn
    a packet flood into heap churn. The idle timer instead wakes when it is
    due, checks how long the connection has really been quiet, and re-arms for
    the remainder.
    """

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        idle: float,
        lifetime: float,
        expire: Callable[[str], None],
    ) -> None:
        self._loop = loop
        self._idle = idle
        self._expire = expire
        self._last = loop.time()
        self._idle_handle: asyncio.TimerHandle | None = None
        self._life_handle: asyncio.TimerHandle | None = None
        if idle > 0:
            self._idle_handle = loop.call_later(idle, self._check_idle)
        if lifetime > 0:
            self._life_handle = loop.call_later(lifetime, self._expire, "lifetime")

    def touch(self) -> None:
        self._last = self._loop.time()

    def _check_idle(self) -> None:
        quiet = self._loop.time() - self._last
        if quiet >= self._idle:
            self._idle_handle = None
            self._expire("idle")
        else:
            self._idle_handle = self._loop.call_later(self._idle - quiet, self._check_idle)

    def cancel(self) -> None:
        for handle in (self._idle_handle, self._life_handle):
            if handle is not None:
                handle.cancel()
        self._idle_handle = self._life_handle = None


class _LimitedProtocol(asyncio.Protocol):
    """Delegating wrapper that admits or rejects a connection by source-IP cap
    before handing it to the real protocol. All `Protocol` callbacks forward to
    the inner protocol only for admitted connections."""

    def __init__(
        self,
        inner: asyncio.Protocol,
        limiter: ConnectionLimiter,
        idle_timeout: float | None = None,
        max_session: float | None = None,
    ) -> None:
        self._inner = inner
        self._limiter = limiter
        self._idle_timeout = idle_timeout
        self._max_session = max_session
        self._admitted = False
        self._ip = ""
        self._transport: asyncio.BaseTransport | None = None
        self._timers: _SessionTimers | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._ip = _peer_ip(transport)
        if not self._limiter.try_acquire(self._ip):
            log.debug("Connection from %s rejected: connection cap reached.", self._ip)
            transport.close()
            return
        self._admitted = True
        self._transport = transport
        self._limiter.track(transport)
        loop = _running_loop()
        if loop is not None:
            idle = _setting_seconds(self._idle_timeout, "engine_idle_timeout_seconds")
            lifetime = _setting_seconds(self._max_session, "engine_max_session_seconds")
            if idle > 0 or lifetime > 0:
                self._timers = _SessionTimers(loop, idle, lifetime, self._expire)
        adopt = getattr(self._inner, "adopt_wrapper", None)
        if callable(adopt):
            adopt(self)
        self._inner.connection_made(transport)

    def _expire(self, reason: str) -> None:
        log.debug("Closing %s connection from %s.", reason, self._ip)
        if self._transport is not None:
            _abort(self._transport)

    def data_received(self, data: bytes) -> None:
        if self._admitted:
            if self._timers is not None:
                self._timers.touch()
            self._inner.data_received(data)

    def eof_received(self) -> bool | None:
        if self._admitted:
            return self._inner.eof_received()
        return None

    def connection_lost(self, exc: Exception | None) -> None:
        if self._admitted:
            self._admitted = False
            if self._timers is not None:
                self._timers.cancel()
                self._timers = None
            if self._transport is not None:
                self._limiter.untrack(self._transport)
            self._limiter.release(self._ip)
            self._inner.connection_lost(exc)

    def touch(self) -> None:
        """Feed the idle timer. Protocols that upgrade to TLS receive their
        bytes directly from the SSL transport, bypassing `data_received`."""
        if self._timers is not None:
            self._timers.touch()

    def pause_writing(self) -> None:
        if self._admitted:
            self._inner.pause_writing()

    def resume_writing(self) -> None:
        if self._admitted:
            self._inner.resume_writing()


def limited_factory(
    factory: Callable[[], asyncio.Protocol],
    limiter: ConnectionLimiter,
    idle_timeout: float | None = None,
    max_session: float | None = None,
) -> Callable[[], asyncio.Protocol]:
    """Wrap a `create_server` protocol factory so each connection is capped,
    idle-timed and lifetime-bounded. `None` timeouts come from settings at
    connection time; 0 disables."""
    return lambda: _LimitedProtocol(factory(), limiter, idle_timeout, max_session)


def limited_handler(
    handler: Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]],
    limiter: ConnectionLimiter,
    idle_timeout: float | None = None,
    max_session: float | None = None,
) -> Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]:
    """Wrap a `start_server` coroutine handler so each connection is capped,
    idle-timed and lifetime-bounded."""

    async def _wrapped(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        transport = writer.transport
        ip = _peer_ip(transport)
        if not limiter.try_acquire(ip):
            log.debug("Connection from %s rejected: connection cap reached.", ip)
            writer.close()
            return
        limiter.track(transport)
        timers: _SessionTimers | None = None
        loop = _running_loop()
        if loop is not None:
            idle = _setting_seconds(idle_timeout, "engine_idle_timeout_seconds")
            lifetime = _setting_seconds(max_session, "engine_max_session_seconds")
            if idle > 0 or lifetime > 0:

                def _expire(reason: str) -> None:
                    log.debug("Closing %s connection from %s.", reason, ip)
                    # `writer.transport` is the live one even after start_tls.
                    _abort(writer.transport)
                    _abort(transport)

                timers = _SessionTimers(loop, idle, lifetime, _expire)
                # The handler reads through a StreamReader, so the only place
                # inbound activity is observable is where the protocol feeds it.
                original_feed = reader.feed_data
                touch = timers.touch

                def _feed(data: bytes) -> None:
                    touch()
                    original_feed(data)

                reader.feed_data = _feed  # type: ignore[assignment,method-assign]
        try:
            await handler(reader, writer)
        finally:
            if timers is not None:
                timers.cancel()
            limiter.untrack(transport)
            limiter.release(ip)

    return _wrapped


# ── Bounded line extraction ─────────────────────────────────────────────────


def extract_lines(
    buf: bytes, *, max_lines: int, max_line: int
) -> tuple[list[bytes], bytes, str | None]:
    """Split complete LF-terminated lines off `buf` in one linear pass.

    Returns `(lines, remainder, problem)`; each line has its trailing CR
    removed. `problem` is `"flood"` when more than `max_lines` complete lines
    were present (the extra input stays unprocessed and `remainder` is empty)
    and `"too_long"` when any line, complete or still-accumulating, exceeds
    `max_line` bytes. The caller closes the connection on a problem; lines
    extracted before it are still returned so what the peer did send is kept.

    The naive `while b"\\n" in buf: buf.split(b"\\n", 1)` re-scans and re-copies
    the whole buffer for every line, which is quadratic in the number of lines
    in one read.
    """
    lines: list[bytes] = []
    pos = 0
    while True:
        i = buf.find(b"\n", pos)
        if i < 0:
            break
        if len(lines) >= max_lines:
            return lines, b"", "flood"
        end = i - 1 if i > pos and buf[i - 1] == 13 else i
        if end - pos > max_line:
            return lines, b"", "too_long"
        lines.append(buf[pos:end])
        pos = i + 1
    remainder = buf[pos:]
    if len(remainder) > max_line:
        return lines, b"", "too_long"
    return lines, remainder, None


class LineWorker:
    """Runs an async handler over received lines, one at a time and in order,
    on a single retained task per connection.

    Spawning a task per line lets a pipelined flood create thousands of
    concurrent coroutines, each holding its own state and — for the login
    paths — sleeping through an auth-failure delay, and it also lets lines
    race one another (a SASL continuation overtaking its AUTHENTICATE). One
    worker with a bounded queue gives ordering and a hard ceiling.

    `submit()` returns False when the connection has queued too many lines at
    once or sent too many in total; the caller then closes it. Lines accepted
    before that are still processed, so what a flooding peer sent is recorded.
    """

    def __init__(
        self,
        handler: Callable[[bytes], Awaitable[None]],
        *,
        name: str,
        max_pending: int = 64,
        max_total: int = 512,
    ) -> None:
        self._handler = handler
        self._name = name
        self._max_pending = max_pending
        self._max_total = max_total
        self._queue: deque[bytes] = deque()
        self._task: asyncio.Task[Any] | None = None
        self._total = 0
        self._stopped = False

    def submit(self, lines: list[bytes]) -> bool:
        if self._stopped or not lines:
            return True
        self._total += len(lines)
        if self._total > self._max_total or len(self._queue) + len(lines) > self._max_pending:
            return False
        self._queue.extend(lines)
        if self._task is None or self._task.done():
            self._task = spawn(self._run(), name=self._name)
        return True

    def stop(self) -> None:
        """Drop everything queued and ignore further lines (the protocol is
        ending the session itself, e.g. QUIT)."""
        self._stopped = True
        self._queue.clear()

    async def _run(self) -> None:
        while self._queue and not self._stopped:
            line = self._queue.popleft()
            try:
                await self._handler(line)
            except Exception:
                log.exception("%s: line handler failed", self._name)


# ── UDP reply rate limiting ─────────────────────────────────────────────────


class UdpReplyLimiter:
    """Per-source-IP token bucket for UDP replies.

    UDP sources are trivially spoofed, so every reply is a packet aimed at a
    third party. Limiting how fast any one address is answered caps what the
    honeypot can contribute to a reflection attack even when each reply is
    small. Only the *reply* is withheld — callers still record the event.

    The table is bounded: past `max_entries` the least-recently-seen source is
    evicted (it simply starts with a full bucket if it returns).
    """

    def __init__(
        self,
        rate: float | None = None,
        burst: int | None = None,
        max_entries: int = 4096,
    ) -> None:
        settings = get_settings()
        self._rate = float(settings.udp_reply_rate_per_second if rate is None else rate)
        self._burst = float(max(1, settings.udp_reply_burst if burst is None else burst))
        self._max_entries = max_entries
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def allow(self, ip: str, now: float | None = None) -> bool:
        """True if a reply to `ip` may be sent now (consumes one token)."""
        if self._rate <= 0:
            return True
        t = time.monotonic() if now is None else now
        tokens, last = self._buckets.pop(ip, (self._burst, t))
        tokens = min(self._burst, tokens + max(0.0, t - last) * self._rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._buckets[ip] = (tokens, t)
        while len(self._buckets) > self._max_entries:
            self._buckets.popitem(last=False)
        return allowed

    def __len__(self) -> int:
        return len(self._buckets)
