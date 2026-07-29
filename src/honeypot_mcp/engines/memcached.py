"""Memcached honeypot engine — tcp/11211, the classic amplification reflector.

An exposed memcached is not primarily a data-theft target; it is a weapon.
UDP memcached produced the largest DDoS attacks on record (GitHub, 1.35 Tbps,
2018) because a tiny `stats` or `get` request returns a response thousands of
times larger, and the source address can be spoofed. The attack pattern is
distinctive and worth catching precisely:

1. `stats` — measure the reflector and confirm it answers.
2. `set` a large value under a known key — stage the amplification payload.
3. `get` that key repeatedly, with the victim's address spoofed as the source.

So `set` with a large body followed by a `get` of the same key is treated as
amplification staging rather than as ordinary cache traffic, which is the
signal an operator actually wants.

This engine speaks the classic *text* protocol over TCP. UDP is where the
reflection happens, but a UDP listener that answers spoofed traffic would make
the honeypot an actual participant in someone else's DDoS — so the sensor
watches the reconnaissance and staging over TCP and never reflects. That is a
deliberate limit, recorded in KNOWN_LIMITATIONS.md.

`flush_all` is captured separately: it destroys every cached entry and, against
a real deployment, is an availability attack in a single unauthenticated word.

Wire format reference: memcached `doc/protocol.txt`.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# One constant, everything derived — a server whose `version` disagrees with
# its `stats` output is a fingerprint in itself.
_MEMCACHED_VERSION = "1.6.21"

# A `set` at least this large is staging for reflection rather than caching a
# session blob. The published amplification research uses payloads of ~1 MB;
# this is deliberately far lower so the intent is caught early.
_AMPLIFICATION_PAYLOAD_BYTES = 4096

# Cap on stored value bytes we keep per connection, so a scanner cannot use the
# honeypot's own memory as its staging area.
_MAX_TRACKED_VALUE_BYTES = 64 * 1024

_MAX_LINE_BYTES = 8192


def _stats_lines(uptime: int, conn_id: int) -> list[str]:
    """A believable `stats` block for memcached 1.6.x.

    nmap identifies memcached from this response, and the numbers have to look
    like a server that has been up for a while — an all-zero counter set is as
    obvious as an empty banner.
    """
    return [
        f"STAT pid {10000 + (conn_id % 5000)}",
        f"STAT uptime {uptime}",
        f"STAT time {int(time.time())}",
        f"STAT version {_MEMCACHED_VERSION}",
        "STAT pointer_size 64",
        "STAT rusage_user 4.128000",
        "STAT rusage_system 9.216000",
        "STAT max_connections 1024",
        f"STAT curr_connections {3 + (conn_id % 7)}",
        f"STAT total_connections {1024 + conn_id}",
        "STAT rejected_connections 0",
        "STAT connection_structures 12",
        "STAT response_obj_oom 0",
        "STAT response_obj_count 1",
        "STAT read_buf_count 8",
        "STAT read_buf_bytes 131072",
        "STAT cmd_get 184213",
        "STAT cmd_set 41082",
        "STAT cmd_flush 0",
        "STAT cmd_touch 0",
        "STAT get_hits 171904",
        "STAT get_misses 12309",
        "STAT get_expired 884",
        "STAT delete_hits 402",
        "STAT delete_misses 91",
        "STAT incr_hits 0",
        "STAT decr_hits 0",
        "STAT bytes_read 28472913",
        "STAT bytes_written 991284471",
        "STAT limit_maxbytes 67108864",
        "STAT accepting_conns 1",
        "STAT threads 4",
        f"STAT bytes {2_400_000 + conn_id * 17}",
        "STAT curr_items 8421",
        "STAT total_items 41082",
        "STAT evictions 0",
        "STAT reclaimed 331",
    ]


class _MemcachedProtocol(asyncio.Protocol):
    _conn_counter = 0

    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._started = time.time()
        # Keys this peer has staged with a large value — the second half of the
        # amplification pattern only matters for keys it actually set.
        self._staged: dict[str, int] = {}
        # Set when a `set` header has been read and we are consuming its body.
        self._pending_body: tuple[str, int] | None = None
        _MemcachedProtocol._conn_counter += 1
        self._conn_id = _MemcachedProtocol._conn_counter

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        # Real memcached sends no greeting; it waits for a command.
        asyncio.create_task(self._record("memcached_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_LINE_BYTES + _MAX_TRACKED_VALUE_BYTES:
            # Oversized garbage — real memcached errors out rather than buffering.
            self._send(b"ERROR\r\n")
            self._buf = b""
            return
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            if self._pending_body is not None:
                key, _declared = self._pending_body
                self._pending_body = None
                self._send(b"STORED\r\n")
                self._on_stored(key, len(line))
                continue
            if not self._handle_line(line):
                return

    def _send(self, payload: bytes) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(payload)

    def _handle_line(self, raw: bytes) -> bool:
        """Return False to stop processing (connection closing)."""
        try:
            text = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            self._send(b"ERROR\r\n")
            return True
        if not text:
            return True
        parts = text.split()
        command = parts[0].lower()

        if command == "version":
            self._send(f"VERSION {_MEMCACHED_VERSION}\r\n".encode())
            asyncio.create_task(
                self._record("memcached_version_probe", AlertSeverity.LOW, {"command": text[:200]})
            )
            return True

        if command == "stats":
            uptime = int(time.time() - self._started) + 864_000
            body = "\r\n".join(_stats_lines(uptime, self._conn_id)) + "\r\nEND\r\n"
            self._send(body.encode())
            # `stats` is how a reflector is measured: the response is ~1.5 KB
            # for a ~7-byte request, and it confirms the server answers at all.
            asyncio.create_task(
                self._record(
                    "memcached_stats_probe",
                    AlertSeverity.MEDIUM,
                    {
                        "command": text[:200],
                        "response_bytes": len(body),
                        "amplification_factor": round(len(body) / max(len(raw) + 2, 1), 1),
                    },
                )
            )
            return True

        if command == "set" and len(parts) >= 5:
            key = parts[1]
            try:
                declared = int(parts[4])
            except ValueError:
                self._send(b"CLIENT_ERROR bad command line format\r\n")
                return True
            if declared > _MAX_TRACKED_VALUE_BYTES:
                # Consume without storing; still record the intent.
                self._send(b"SERVER_ERROR object too large for cache\r\n")
                self._on_stored(key, declared)
                return True
            self._pending_body = (key, declared)
            return True

        if command in ("get", "gets") and len(parts) >= 2:
            keys = parts[1:]
            staged = [k for k in keys if k in self._staged]
            if staged:
                # Stage-then-reflect: the payload this peer just stored is now
                # being pulled back. Against a spoofed source that response goes
                # to the victim.
                total = sum(self._staged[k] for k in staged)
                asyncio.create_task(
                    self._record(
                        "memcached_amplification_attempt",
                        AlertSeverity.CRITICAL,
                        {
                            "command": text[:200],
                            "keys": staged[:10],
                            "staged_bytes": total,
                            "amplification_factor": round(total / max(len(raw) + 2, 1), 1),
                            "note": "large value stored then retrieved — reflector staging",
                        },
                    )
                )
                payload = b""
                for k in staged:
                    size = self._staged[k]
                    payload += f"VALUE {k} 0 {size}\r\n".encode() + b"A" * size + b"\r\n"
                self._send(payload + b"END\r\n")
                return True
            self._send(b"END\r\n")
            asyncio.create_task(
                self._record(
                    "memcached_get", AlertSeverity.LOW, {"command": text[:200], "keys": keys[:10]}
                )
            )
            return True

        if command == "flush_all":
            self._send(b"OK\r\n")
            asyncio.create_task(
                self._record(
                    "memcached_flush_all",
                    AlertSeverity.HIGH,
                    {
                        "command": text[:200],
                        "note": "destroys every cached entry — unauthenticated availability attack",
                    },
                )
            )
            return True

        if command == "quit":
            if self._transport is not None:
                self._transport.close()
            return False

        if command in ("delete", "add", "replace", "append", "prepend", "incr", "decr", "touch"):
            self._send(b"NOT_FOUND\r\n")
            asyncio.create_task(
                self._record("memcached_command", AlertSeverity.LOW, {"command": text[:200]})
            )
            return True

        self._send(b"ERROR\r\n")
        asyncio.create_task(
            self._record("memcached_command", AlertSeverity.LOW, {"command": text[:200]})
        )
        return True

    def _on_stored(self, key: str, size: int) -> None:
        if size >= _AMPLIFICATION_PAYLOAD_BYTES:
            self._staged[key] = min(size, _MAX_TRACKED_VALUE_BYTES)
            asyncio.create_task(
                self._record(
                    "memcached_large_set",
                    AlertSeverity.HIGH,
                    {
                        "key": key[:120],
                        "value_bytes": size,
                        "note": "oversized value — amplification payload staging",
                    },
                )
            )
        else:
            asyncio.create_task(
                self._record(
                    "memcached_set", AlertSeverity.LOW, {"key": key[:120], "value_bytes": size}
                )
            )

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        self._staged.clear()


class MemcachedEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _MemcachedProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"memcached-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("Memcached honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_memcached"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["Memcached honeypot is in-process — events are stored directly in the database."]
