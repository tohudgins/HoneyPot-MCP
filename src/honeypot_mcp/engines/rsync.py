"""rsync daemon honeypot — tcp/873, exposed module enumeration.

An rsync daemon left open to the internet is a recurring breach cause: the
protocol has no authentication by default, and a single anonymous command lists
every share on the box and then copies it. Backup servers are the usual victim,
which means the exposure is not a foothold but the archive itself.

The reconnaissance step is also the exploitation step, and that shapes what is
worth recording:

* Sending an empty module name returns the **module list** — the equivalent of
  `rsync rsync://host/`. Doing that is the entire discovery phase, so it is
  logged as enumeration with the modules the attacker learned about.
* Selecting a module that a real daemon exposes without `auth users` gets
  straight to a file transfer. That is data leaving, and it is recorded as
  such rather than as another connection.
* A module configured with `auth users` challenges, and the response is a
  base64 MD5 of the password against a server-chosen salt — capturable, and
  crackable offline, exactly like the SIP digest.

The advertised modules are named to be worth taking: backups, database dumps,
configuration. A daemon exposing nothing interesting is not one an attacker
spends time on.

Wire format: the rsync daemon protocol — a `@RSYNCD:` version handshake, then
newline-delimited text until a module is selected.

After `@RSYNCD: OK` a client of protocol 30+ (every rsync 3.x) sends its server
argument vector NUL-separated, ended by an empty word, and then waits for the
daemon's setup bytes and file list; a daemon that goes quiet there is visibly
not one. `rsync_wire.py` produces that listing (protocol 31, no incremental
recursion) from a small decoy tree per module, the client's end-of-phase
markers are answered, and the session closes cleanly. Pulls are refused by
hanging up once the client asks for file data. Protocol 29 and older clients
(openrsync, rsync 2.x) use a different list encoding and are closed after their
arguments are recorded. Events are unchanged except that `rsync_file_request`
carries `files_listed`.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import secrets
import time
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import (
    ConnectionLimiter,
    LineWorker,
    extract_lines,
    limited_factory,
    shutdown_server,
)
from honeypot_mcp.engines.rsync_wire import (
    MAX_LISTED,
    ClientStream,
    ListEntry,
    decoy_tree,
    encode_session,
    encode_stats,
    parse_server_args,
    resolve_request,
)
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# Protocol 31 is what rsync 3.1–3.2 speak; the client refuses versions it does
# not recognise, so this has to be a real one.
_RSYNC_VERSION = "31.0"

# Modules an attacker would want, with the mix a real backup host has: some
# open, one protected. `MOTD` is what a daemon prints before the list.
_MOTD = "backup01 rsync service - authorised use only"
_MODULES: tuple[tuple[str, str, bool], ...] = (
    # (name, comment, requires_auth)
    ("backups", "Nightly system backups", False),
    ("db-dumps", "PostgreSQL nightly dumps", False),
    ("etc", "Configuration archive", True),
    ("home", "User home directories", True),
    ("public", "Public read-only mirror", False),
)
_AUTH_MODULES = {name for name, _c, needs_auth in _MODULES if needs_auth}
_OPEN_MODULES = {name for name, _c, needs_auth in _MODULES if not needs_auth}

_MAX_LINE = 4096
# Lines handled per network read, and in total per connection. A real client
# sends its option list (one line per argument) and a file request; every
# open-module line past this is a CRITICAL event, so an unbounded count would
# let one connection mint unbounded alerts.
_MAX_LINES_PER_READ = 32
_MAX_LINES_PER_CONNECTION = 128
# Events recorded per connection once a module is open. Generous enough for a
# real client's full option list plus its file requests.
_MAX_TRANSFER_EVENTS = 64
# A client speaking protocol 30+ separates its argument words with NUL, not LF,
# and ends them with an empty word. Bounds for that phase:
_MAX_ARG_BYTES = 16384
# After the list is sent the client may still be writing (its filter list);
# read and discard for a moment so closing never RSTs the list away.
_DRAIN_SECONDS = 3.0
_MAX_DRAIN_BYTES = 65536
# The greeting version we speak; a newer client is held to it.
_SPOKEN_PROTOCOL = 31
# Oldest protocol whose file-list encoding the listing implements.
_MIN_LIST_PROTOCOL = 30
_STATS_READ = 140  # bytes a real sender reports having read for a listing
_VERSION_RE = re.compile(r"@RSYNCD:\s*(\d+)")

_STATE_HANDSHAKE = 0
_STATE_MODULE = 1
_STATE_AUTH = 2
_STATE_TRANSFER = 3


class _RsyncProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._worker = LineWorker(
            self._handle_raw,
            name="rsync-lines",
            max_pending=_MAX_LINES_PER_READ * 2,
            max_total=_MAX_LINES_PER_CONNECTION,
        )
        self._state = _STATE_HANDSHAKE
        self._module = ""
        self._challenge = ""
        self._transfer_events = 0
        self._client_proto = 0
        # Argument phase after `@RSYNCD: OK` (NUL-separated for protocol >= 30).
        self._args_mode = False
        self._arg_buf = b""
        self._post_args = False
        self._drained = 0
        self._drain_handle: asyncio.TimerHandle | None = None
        self._argv: list[str] = []
        self._client = ClientStream()
        self._session_sent = False
        self._post_buf = b""
        self._entries: list[ListEntry] = []
        self._missing: list[str] = []

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._send(f"@RSYNCD: {_RSYNC_VERSION}\n")
        spawn(self._record("rsync_connection", AlertSeverity.LOW, {}), name="rsync-connect")

    def _send(self, text: str) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(text.encode("utf-8", errors="replace"))

    def _close(self) -> None:
        # Session ending on our side: drop lines queued behind this one.
        self._worker.stop()
        if self._transport is not None:
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        if self._post_args:
            # The list has been sent; whatever the client still writes is read
            # and dropped (bounded) until it hangs up or the drain timer fires.
            self._drained += len(data)
            if self._drained > _MAX_DRAIN_BYTES:
                self._close()
                return
            if self._session_sent:
                self._feed_client(data)
            else:
                self._post_buf += data
            return
        if self._args_mode:
            self._data_args(data)
            return
        lines, self._buf, problem = extract_lines(
            self._buf + data, max_lines=_MAX_LINES_PER_READ, max_line=_MAX_LINE
        )
        accepted = self._worker.submit(lines)
        if problem or not accepted:
            # Flood or oversized line: keep what was already queued (it is
            # evidence), refuse the rest and hang up.
            self._send("@ERROR: protocol error\n")
            if self._transport is not None:
                self._transport.close()

    def _data_args(self, data: bytes) -> None:
        """Protocol 30+ argument words: NUL-terminated, ended by an empty word.
        Each becomes one queued "line", so they are handled in order by the same
        worker as the text phase."""
        buf = self._arg_buf + data
        words = buf.split(b"\0")
        self._arg_buf = words.pop()
        problem = len(self._arg_buf) > _MAX_LINE or len(buf) > _MAX_ARG_BYTES
        done = b"" in words
        if done:
            # Later bytes are the client's own protocol data, not arguments.
            self._post_args = True
            # What follows the empty word is the client's own data, already in
            # this read; keep it for when the list has gone out.
            self._post_buf += b"\0".join(words[words.index(b"") + 1 :] + [self._arg_buf])
            words = words[: words.index(b"") + 1]
            self._arg_buf = b""
        accepted = self._worker.submit(words[:_MAX_LINES_PER_READ])
        if problem or not accepted or len(words) > _MAX_LINES_PER_READ:
            self._send("@ERROR: protocol error\n")
            if self._transport is not None:
                self._transport.close()

    async def _handle_raw(self, raw: bytes) -> None:
        await self._handle(raw.decode("utf-8", errors="replace").strip())

    async def _handle(self, line: str) -> None:
        if self._state == _STATE_HANDSHAKE:
            # Client echoes `@RSYNCD: <version>`; anything else is a scanner
            # poking the port rather than speaking rsync.
            if not line.startswith("@RSYNCD:"):
                await self._record("rsync_invalid_probe", AlertSeverity.LOW, {"data": line[:120]})
                self._send("@ERROR: protocol version mismatch\n")
                self._close()
                return
            match = _VERSION_RE.match(line)
            self._client_proto = min(int(match.group(1)), _SPOKEN_PROTOCOL) if match else 0
            self._state = _STATE_MODULE
            return

        if self._state == _STATE_MODULE:
            if line == "" or line == "#list":
                # The discovery step. This single exchange is what tells an
                # attacker the box is worth returning to.
                listing = f"{_MOTD}\n" + "".join(
                    f"{name}\t{comment}\n" for name, comment, _a in _MODULES
                )
                self._send(listing + "@RSYNCD: EXIT\n")
                await self._record(
                    "rsync_module_enumeration",
                    AlertSeverity.HIGH,
                    {
                        "modules_disclosed": [n for n, _c, _a in _MODULES],
                        "note": "listed every share — the whole discovery phase in one command",
                    },
                )
                self._close()
                return

            self._module = line.split(" ", 1)[0]
            if self._module in _AUTH_MODULES:
                self._challenge = base64.b64encode(secrets.token_bytes(16)).decode().rstrip("=")
                self._send(f"@RSYNCD: AUTHREQD {self._challenge}\n")
                self._state = _STATE_AUTH
                await self._record(
                    "rsync_module_access",
                    AlertSeverity.HIGH,
                    {"module": self._module[:64], "auth_required": True},
                )
                return

            if self._module in _OPEN_MODULES:
                # No auth on this module, so the next thing the client does is
                # copy files. That is the breach, not a probe.
                self._send("@RSYNCD: OK\n")
                self._state = _STATE_TRANSFER
                self._args_mode = self._client_proto >= _MIN_LIST_PROTOCOL
                await self._record(
                    "rsync_anonymous_access",
                    AlertSeverity.CRITICAL,
                    {
                        "module": self._module[:64],
                        "note": (
                            "unauthenticated access to an exposed rsync module — "
                            "the next step is bulk file copy"
                        ),
                    },
                )
                return

            self._send(f"@ERROR: Unknown module '{self._module[:64]}'\n")
            await self._record(
                "rsync_unknown_module", AlertSeverity.MEDIUM, {"module": self._module[:64]}
            )
            self._close()
            return

        if self._state == _STATE_AUTH:
            # `<user> <base64 md5 response>` — the response is a digest over
            # our salt, so it is crackable with the salt we just recorded.
            parts = line.split(" ", 1)
            username = parts[0] if parts else ""
            response = parts[1] if len(parts) > 1 else ""
            await self._record(
                "rsync_auth_attempt",
                AlertSeverity.HIGH,
                {
                    "module": self._module[:64],
                    "username": username[:128],
                    "challenge": self._challenge,
                    "digest_response": response[:128],
                    "service": "rsync",
                },
            )
            if self._transport is not None and not self._transport.is_closing():
                await asyncio.sleep(0.8)
            self._send("@ERROR: auth failed on module " + self._module + "\n")
            self._close()
            return

        # Post-OK: the client sends its option list, then the file request.
        # Every line here is an event (file requests are CRITICAL), so the
        # count per connection is bounded: past it the session is evidence
        # enough and further lines are dropped rather than minting alerts.
        self._transfer_events += 1
        if self._transfer_events > _MAX_TRANSFER_EVENTS:
            self._close()
            return
        if line == "":
            # End of the client's argument list.
            await self._finish_args()
            return
        self._argv.append(line)
        if line.startswith("-") or line == ".":
            await self._record(
                "rsync_transfer_options", AlertSeverity.MEDIUM, {"options": line[:200]}
            )
            return
        files_listed = self._plan_listing(line)
        await self._record(
            "rsync_file_request",
            AlertSeverity.CRITICAL,
            {
                "module": self._module[:64],
                "path": line[:200],
                "note": "attempted bulk file read",
                "files_listed": files_listed,
            },
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
        self._buf = b""
        self._arg_buf = b""
        if self._drain_handle is not None:
            self._drain_handle.cancel()
            self._drain_handle = None

    def _plan_listing(self, request: str) -> int:
        """Resolve one path argument against the decoy tree now, so the event
        that records the request can carry how many entries the client will be
        shown. Returns 0 when nothing can be listed."""
        if self._client_proto < _MIN_LIST_PROTOCOL:
            return 0
        args = parse_server_args(self._argv)
        tree = decoy_tree(self._module, self._name, time.time())
        if not args.sender or args.unsupported or tree is None:
            return 0
        entries = resolve_request(tree, request, self._module, args)
        if entries is None:
            self._missing.append(
                f'rsync: [sender] link_stat "/{request[:200]}" (in {self._module}) '
                "failed: No such file or directory (2)\n"
            )
            return 0
        room = max(MAX_LISTED - len(self._entries), 0)
        self._entries.extend(entries[:room])
        return min(len(entries), room)

    async def _finish_args(self) -> None:
        """The client sent its empty terminating argument: this is where a real
        daemon starts the transfer. A listing is answered; anything else (an
        upload, protocol 29 or older, options we cannot encode) ends the session,
        having been recorded."""
        self._args_mode = False
        self._post_args = True
        args = parse_server_args(self._argv)
        if (
            self._client_proto < _MIN_LIST_PROTOCOL
            or not args.sender
            or args.unsupported
            or self._transport is None
            or self._transport.is_closing()
        ):
            self._close()
            return
        self._transport.write(
            encode_session(self._entries, args, secrets.randbits(32), self._missing)
        )
        # Keep reading for a moment: the client's filter list and end-of-phase
        # markers may still be in flight, and closing on unread data would RST
        # away the bytes just written.
        self._worker.stop()
        self._session_sent = True
        self._client.stats = encode_stats(
            _STATS_READ,
            sum(len(e.name) for e in self._entries),
            sum(e.node.size for e in self._entries),
        )
        pending, self._post_buf = self._post_buf, b""
        if pending:
            self._feed_client(pending)
        self._drain_handle = asyncio.get_running_loop().call_later(_DRAIN_SECONDS, self._close)

    def _feed_client(self, data: bytes) -> None:
        for reply in self._client.feed(data):
            if self._transport is not None and not self._transport.is_closing():
                self._transport.write(reply)
        if self._client.finished:
            self._close()


class RsyncEngine(HoneypotEngine):
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
            limited_factory(lambda: _RsyncProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"rsync-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("rsync honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_rsync"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["rsync honeypot is in-process — events are stored directly in the database."]


def _md5_response(password: str, challenge: str) -> str:
    """Reference implementation of rsync's auth digest, for tests.

    rsync hashes a zero-filled 4-byte prefix, the password, then the challenge,
    and base64-encodes the digest with padding stripped.
    """
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(b"\x00\x00\x00\x00")
    digest.update(password.encode())
    digest.update(challenge.encode())
    return base64.b64encode(digest.digest()).decode().rstrip("=")
