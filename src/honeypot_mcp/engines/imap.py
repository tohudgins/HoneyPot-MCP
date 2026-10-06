"""IMAP honeypot engine — tcp/143, cleartext mailbox credentials and the mailbox behind them.

Mail is where credential-stuffing campaigns cash out. A working mailbox login
gives an attacker password-reset control over every other account the address
owns, plus the archive itself, so IMAP is scanned continuously by botnets
replaying breach corpora. Port 143 in particular is the *cleartext* port: a
plain `LOGIN` command carries the username and password with no encryption, so
every attempt is a full credential capture.

What makes this convincing rather than a socket that says OK:

* The greeting advertises a real Dovecot capability set. Scanners parse it, and
  an implausible or empty CAPABILITY response is the fastest way to be
  identified as a decoy. Only what is implemented is advertised.
* `LOGINDISABLED` is deliberately *absent*. A real hardened server advertises
  it on 143 to force STARTTLS, but then the attacker never sends the password —
  the whole point here is to be the misconfigured server they are hunting.
* `LOGIN`, `AUTHENTICATE PLAIN` and `AUTHENTICATE LOGIN` all decode to the same
  capture, base64 unwrapped, and go through the same judgement.
* Failures return `NO [AUTHENTICATIONFAILED]` with Dovecot's real wording and a
  deliberate delay, matching how a real server rate-limits guessing.

A login succeeds only for a credential an operator planted as a honeytoken (the
event buffer's matcher marks the event) or the one weak pair this honeypot
derives from its name; `accepted_logins` in its config replaces it and an empty
list lets nobody in, exactly as for POP3 and the HTTP admin area. A visitor who
gets in reaches the same read-only maildrop POP3 serves (`engines/maildrop.py`):
what the SMTP honeypot accepted, delivery-failure notices included, plus a few
ordinary internal messages. Flags, expunges and the like are remembered for the
session only; nothing a visitor does changes what the next one sees.

Wire format: RFC 3501 (IMAP4rev1), RFC 4616 (SASL PLAIN), RFC 2177 (IDLE),
RFC 2342 (NAMESPACE), RFC 7888 (LITERAL+).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import secrets
import zlib
from dataclasses import dataclass, field
from typing import Any

from honeypot_mcp import credential_match
from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import get_settings
from honeypot_mcp.engines import imap_mailbox as mbx
from honeypot_mcp.engines._bounds import write_backlogged
from honeypot_mcp.engines._sasl import (
    LOGIN_PASSWORD_PROMPT,
    LOGIN_USERNAME_PROMPT,
    decode_plain,
    decode_text,
)
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import (
    ConnectionLimiter,
    LineWorker,
    close_after_error,
    limited_factory,
    shutdown_server,
)
from honeypot_mcp.engines.http_admin import accepted_pairs
from honeypot_mcp.engines.maildrop import MAILDROP, StoredMessage
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_DOVECOT_VERSION = "2.3.19.1"

# Note the absence of LOGINDISABLED — see the module docstring. This is the capability
# list Dovecot 2.3 sends on an unencrypted port with plaintext auth permitted, which is
# exactly the misconfiguration attackers scan for.
_CAPABILITIES = (
    "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN"
)
# After login: STARTTLS and AUTH= are no longer offered, and what the mailbox side
# implements is.
_CAPABILITIES_AUTHENTICATED = (
    "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ NAMESPACE UNSELECT CHILDREN"
)

_MAX_LINE = 8192
# Lines processed per network read. A real client pipelines a handful of
# commands; more than this in one read is a flood and the connection is closed.
_MAX_LINES_PER_READ = 16
# A mailbox session is many commands; this bounds one connection, not one read.
_MAX_COMMANDS_PER_CONNECTION = 4096
# Real servers pause before rejecting a bad password. Instant rejection makes
# brute-forcing cheap and identifies the server as fake.
_AUTH_FAIL_DELAY = 1.2
# Reply bytes tolerated unread before the connection is dropped (a peer pipelining FETCHes
# and never reading the answers).
_MAX_WRITE_BACKLOG = 4 * 1024 * 1024
# Above this many unsent bytes a FETCH waits for the peer to read before producing more: a slow
# but honest client must not be mistaken for one that never reads. Past `_WRITE_WAIT` seconds
# of no progress it is treated as the latter.
_WRITE_SOFT_LIMIT = 256 * 1024
_WRITE_WAIT = 15.0
# Most FETCH items one command may ask for. Each item is built before anything is written, and
# a 32 KB line can name thousands of copies of RFC822.
_MAX_FETCH_ITEMS = 16
_MAX_KEYWORDS = 32
_MAX_KEYWORD_LENGTH = 64
_MAX_PATTERN = 128
# Largest number of literals one command may use (LOGIN {n} {m}), and the marker that tells the
# worker a payload is a literal's bytes rather than a line.
_MAX_LITERALS_PER_COMMAND = 8
_LITERAL_TAG = b"\x00LIT"
_LITERAL_MARKER = re.compile(rb"\s\{(\d{1,10})(\+?)\}\s*$")
# Largest literal a client may send. Bigger is refused and the connection closed, as a real
# server does for a message over its limit; nothing here stores what a client appends.
_MAX_LITERAL = 16 * 1024
_MAX_FETCH_EVENTS = 20

_SYSTEM_FLAGS = ("\\Answered", "\\Flagged", "\\Deleted", "\\Seen", "\\Draft")
_FLAG_BY_LOWER = {f.lower(): f for f in _SYSTEM_FLAGS}
_FOLDERS = ("INBOX", "Sent", "Drafts", "Trash", "Junk")
# What one connection may add to the (otherwise read-only) mailbox: folders it creates, and mail it
# APPENDs or COPYs. All of it lives and dies with the connection.
_MAX_USER_FOLDERS = 8
_MAX_SESSION_MESSAGES = 50
_MAX_SESSION_BYTES = 512 * 1024
_MAX_APPEND = 128 * 1024
_MAX_APPEND_EVENTS = 20
_FOLDER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,39}")
# A flag is a system flag (`\\Seen`) or a plain keyword atom; nothing that needs quoting.
_FLAG = re.compile(
    r"\\(?:Answered|Flagged|Deleted|Seen|Draft)|[A-Za-z0-9$_.-]{1,64}", re.IGNORECASE
)
# `tag APPEND ...`: the only command whose literal may be a whole message.
_APPEND_LINE = re.compile(r"\S+\s+APPEND\s", re.IGNORECASE)
# Everything one connection may be sent, however it is asked for: a few pipelined FETCHes of
# the largest messages are megabytes, and a connection that never stops asking is a client
# reading the mailbox in a loop.
_MAX_CONNECTION_OUTPUT = 64 * 1024 * 1024
_ATTRIBUTES = {"Sent": "\\Sent", "Drafts": "\\Drafts", "Trash": "\\Trash", "Junk": "\\Junk"}


@dataclass
class _Selected:
    """The folder a session has open, as that session sees it."""

    name: str
    read_only: bool
    messages: list[StoredMessage]
    flags: dict[int, set[str]] = field(default_factory=dict)  # UID -> flags
    expunged: set[int] = field(default_factory=set)

    def view(self) -> list[StoredMessage]:
        return [m for m in self.messages if m.number not in self.expunged]


def _initial_flags(message: StoredMessage) -> set[str]:
    """Old mail is read; anything delivered after the mailbox was created is new."""
    return {"\\Seen"} if message.uid.startswith("seed") else set()


class _IMAPProtocol(asyncio.Protocol):
    def __init__(
        self,
        honeypot_name: str,
        hp_id: int | None,
        accepted: frozenset[tuple[str, str]] = frozenset(),
        mail_domain: str = "corp.local",
    ) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._accepted = accepted
        self._mail_domain = mail_domain
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._worker = LineWorker(
            self._handle_raw, name="imap-lines", max_total=_MAX_COMMANDS_PER_CONNECTION
        )
        # Set once a login succeeds: the mailbox the session is for, and what it has open.
        self._mailbox: str | None = None
        self._selected: _Selected | None = None
        # (tag, stage, username so far) while an AUTHENTICATE exchange waits for a line.
        self._sasl: tuple[str, str, str] | None = None
        # A command line that ended in a literal marker: (the command so far, literal size).
        self._literal: tuple[str, int] | None = None
        # The command built so far when a literal has arrived and the line has not ended.
        self._command_prefix: str | None = None
        self._literal_count = 0
        # Receive-side framing: literal bytes still to come, and those gathered.
        self._literal_remaining = 0
        self._literal_bytes = bytearray()
        self._idle_tag: str | None = None
        self._fetch_events = 0
        # What this session has done to each folder: flags set and messages expunged. Kept
        # for the connection, not for the folder being open, so re-selecting shows the same
        # mailbox the visitor left, and never reaches the shared maildrop.
        self._flag_store: dict[str, dict[int, set[str]]] = {}
        self._expunge_store: dict[str, set[int]] = {}
        # Folders this connection created, and mail it added to any folder.
        self._user_folders: list[str] = []
        self._appended: dict[str, list[StoredMessage]] = {}
        self._session_bytes = 0
        self._append_events = 0
        self._last_literal = b""
        # The command text that preceded the last literal (`a APPEND Sent (\\Seen) `): APPEND's
        # folder and flags are read from it alone, never from the message that follows.
        self._last_literal_head = ""
        self._overlay_counter = 0
        # How often each user-folder name has been deleted or renamed away: a recreated folder
        # restarts its UIDs, which RFC 3501 requires to be announced as a new UIDVALIDITY.
        self._folder_generation: dict[str, int] = {}
        self._sent_total = 0
        # Framing (data_received) and command handling (_handle) each track whether the command
        # being assembled is an APPEND, since only its literal may be message-sized.
        self._frame_continuation = False
        self._frame_append = False
        self._handle_append = False

    # ── connection plumbing ──────────────────────────────────────────────────

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._send(f"* OK [CAPABILITY {_CAPABILITIES}] Dovecot ready.\r\n")
        spawn(self._record("imap_connection", AlertSeverity.LOW, {}), name="imap-connect")

    def _send(self, text: str) -> None:
        self._send_bytes(text.encode("utf-8", errors="replace"))

    def _send_bytes(self, data: bytes) -> None:
        if self._transport is None or self._transport.is_closing():
            return
        self._sent_total += len(data)
        if self._sent_total > _MAX_CONNECTION_OUTPUT:
            self._transport.abort()
            return
        if write_backlogged(self._transport, _MAX_WRITE_BACKLOG):
            # A peer pipelining FETCHes and never reading the answers.
            self._transport.abort()
            return
        # Half-closed by `close_after_error` (write_eof already sent): lines still queued
        # behind a flood are processed for the evidence they carry, but their replies have
        # nowhere to go.
        with contextlib.suppress(RuntimeError):
            self._transport.write(data)

    def data_received(self, data: bytes) -> None:
        """Split the stream into command lines and literals.

        A command line ending `{n}` is followed by exactly n bytes of literal data, which are
        taken as bytes (they may contain line breaks) and handed to the worker as one item;
        they are not command lines and do not count towards the per-read line budget."""
        data = self._buf + data
        self._buf = b""
        lines: list[bytes] = []
        problem: str | None = None
        pos = 0
        while pos < len(data):
            if self._literal_remaining:
                take = data[pos : pos + self._literal_remaining]
                self._literal_bytes += take
                self._literal_remaining -= len(take)
                pos += len(take)
                if not self._literal_remaining:
                    lines.append(_LITERAL_TAG + bytes(self._literal_bytes))
                    self._literal_bytes = bytearray()
                continue
            end = data.find(b"\n", pos)
            if end < 0:
                self._buf = data[pos:]
                if len(self._buf) > _MAX_LINE * 4:
                    problem = "too_long"
                break
            line = data[pos : end - 1 if end > pos and data[end - 1] == 13 else end]
            if len(line) > _MAX_LINE * 4:
                problem = "too_long"
                break
            command_lines = [x for x in lines if not x.startswith(_LITERAL_TAG)]
            if len(command_lines) >= _MAX_LINES_PER_READ:
                problem = "flood"
                break
            lines.append(line)
            pos = end + 1
            if not self._frame_continuation:  # the first line of a command decides its literal cap
                self._frame_append = self._mailbox is not None and bool(
                    _APPEND_LINE.match(line.decode("utf-8", errors="replace"))
                )
            marker = _LITERAL_MARKER.search(line)
            self._frame_continuation = marker is not None
            if marker:
                size = int(marker.group(1))
                if size > (_MAX_APPEND if self._frame_append else _MAX_LITERAL):
                    break  # the worker answers NO [TOOBIG] and hangs up when it reaches this line
                self._literal_remaining = size
                if size == 0:
                    lines.append(_LITERAL_TAG)
        accepted = self._worker.submit(lines)
        if problem or not accepted:
            # Flood or oversized line: keep what was already queued (it is
            # evidence), refuse the rest and hang up.
            self._send("* BYE Line too long\r\n" if problem == "too_long" else "* BYE Too fast\r\n")
            if self._transport is not None:
                close_after_error(self._transport)

    async def _handle_raw(self, raw: bytes) -> None:
        if raw.startswith(_LITERAL_TAG):
            await self._literal_payload(raw[len(_LITERAL_TAG) :])
            return
        line = raw.decode("utf-8", errors="replace")
        try:
            await self._handle(line)
        except Exception:
            # A parser or builder that fails must still answer the command, or the client
            # waits forever for a tagged reply and the session is wedged.
            log.exception("IMAP command failed")
            self._literal = None
            self._command_prefix = None
            self._send(f"{_tag_of(line)} NO [SERVERBUG] Internal error.\r\n")

    def _close(self) -> None:
        # The session is ending on our side (LOGOUT, flood): lines still queued
        # behind the one being handled are dropped, not answered into a dead socket.
        self._worker.stop()
        if self._transport is not None:
            self._transport.close()

    def connection_lost(self, exc: Exception | None) -> None:
        self._buf = b""

    async def _record(
        self, event_type: str, severity: AlertSeverity, payload: dict
    ) -> PendingEvent:
        """Submit an event and return it: the buffer marks a planted credential on the event
        itself, which is how a login learns it was a honeytoken."""
        src_ip, src_port = self._peer
        event = PendingEvent(
            honeypot_id=self._hp_id,
            source_ip=src_ip,
            source_port=src_port,
            event_type=event_type,
            payload=payload,
            severity=severity,
        )
        await submit_event(event)
        return event

    # ── command dispatch ─────────────────────────────────────────────────────

    async def _handle(self, line: str) -> None:
        if self._idle_tag is not None:
            if line.strip().upper() == "DONE":
                tag, self._idle_tag = self._idle_tag, None
                self._send(f"{tag} OK Idle completed.\r\n")
            return
        if self._sasl is not None:
            await self._continue_sasl(line)
            return
        if self._literal is not None:
            # A line where a literal's bytes should be: the client is not following the
            # protocol. Drop the half-built command.
            self._literal = None
            self._command_prefix = None
            self._send("* BAD Literal expected.\r\n")
            return
        if self._command_prefix is not None:
            # The rest of a command whose earlier argument was a literal.
            line, self._command_prefix = self._command_prefix + line, None
        elif not self._literal_count:
            # A new command: whatever literal an earlier command left behind is not its message.
            self._last_literal, self._last_literal_head = b"", ""
            self._handle_append = self._mailbox is not None and bool(_APPEND_LINE.match(line))

        # A line ending in a literal marker: `a LOGIN user {8}` (or `{8+}`). The bytes follow.
        marker = re.search(r"\s\{(\d{1,10})(\+?)\}\s*$", line)
        if marker:
            size = int(marker.group(1))
            cap = _MAX_APPEND if self._handle_append else _MAX_LITERAL
            if size > cap or self._literal_count >= _MAX_LITERALS_PER_COMMAND:
                self._send(
                    f"{_tag_of(line)} NO [TOOBIG] Literal too large.\r\n* BYE Literal too large.\r\n"
                )
                self._close()
                return
            if not marker.group(2):
                self._send("+ Ready for literal data\r\n")
            self._literal_count += 1
            self._literal = (line[: marker.start() + 1], size)
            return
        self._literal_count = 0
        await self._dispatch(line)

    async def _literal_payload(self, payload: bytes) -> None:
        """A literal's bytes arrived. It becomes a quoted argument of the command being built;
        the rest of the command follows on the next line."""
        if self._literal is None:
            self._send("* BAD Unexpected literal.\r\n")
            return
        head, _size = self._literal
        self._literal = None
        self._last_literal = payload
        self._last_literal_head = head
        text = payload.decode("utf-8", errors="replace")
        quoted = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        self._command_prefix = head + quoted

    async def _dispatch(self, line: str) -> None:
        parts = line.strip().split(" ", 2)
        if len(parts) < 2:
            self._send("* BAD Invalid command\r\n")
            return
        tag, command = _tag_of(parts[0]), parts[1].upper()
        rest = parts[2] if len(parts) > 2 else ""

        if command == "CAPABILITY":
            capabilities = _CAPABILITIES_AUTHENTICATED if self._mailbox else _CAPABILITIES
            self._send(f"* CAPABILITY {capabilities}\r\n{tag} OK Capability completed.\r\n")
            await self._record("imap_capability_probe", AlertSeverity.LOW, {"command": line[:200]})
            return
        if command == "LOGIN":
            if self._mailbox is not None:
                self._send(f"{tag} NO [CLIENTBUG] Already logged in.\r\n")
                return
            username, password = _split_login_args(rest)
            await self._attempt_login(tag, username, password, "LOGIN")
            return
        if command == "AUTHENTICATE":
            await self._begin_sasl(tag, rest)
            return
        if command == "STARTTLS":
            # Declining keeps the session in the clear, which is where the password is
            # capturable. A real server that fails to negotiate responds exactly like this.
            self._send(f"{tag} NO TLS handshake failed.\r\n")
            await self._record("imap_starttls_declined", AlertSeverity.LOW, {})
            return
        if command == "LOGOUT":
            self._send(f"* BYE Logging out\r\n{tag} OK Logout completed.\r\n")
            self._close()
            return
        if command in ("ID", "NOOP", "ENABLE") and self._mailbox is None:
            self._send(f"{tag} OK {command} completed.\r\n")
            await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})
            return

        if self._mailbox is None:
            if command in _MAILBOX_COMMANDS:
                # Unauthenticated access to mailbox commands is what an exposed or
                # misconfigured server would leak, so it is worth recording even though we
                # answer with a refusal.
                self._send(f"{tag} NO Not authenticated.\r\n")
                await self._record(
                    "imap_mailbox_access", AlertSeverity.MEDIUM, {"command": line[:200]}
                )
                return
            self._send(f"{tag} BAD Unknown command.\r\n")
            await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})
            return

        await self._authenticated(tag, command, rest, line)

    # ── authentication ───────────────────────────────────────────────────────

    async def _attempt_login(self, tag: str, username: str, password: str, method: str) -> None:
        """The one place a login is judged, whichever command it arrived in."""
        attempt = await self._record(
            "imap_login_attempt",
            AlertSeverity.HIGH,
            {
                "username": username[:256],
                "password": password[:256],
                "service": "imap",
                "method": method,
            },
        )
        if self._transport is not None and not self._transport.is_closing():
            await asyncio.sleep(_AUTH_FAIL_DELAY)
        planted = credential_match.is_credential_trip(attempt)
        if username and (planted or (username.lower(), password) in self._accepted):
            await self._open_mailbox(tag, username, planted)
            return
        self._send(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")

    async def _open_mailbox(self, tag: str, username: str, planted: bool) -> None:
        self._mailbox = username.split("@", 1)[0].lower()[:64]
        count = len(MAILDROP.messages(self._mailbox, self._mail_domain))
        self._send(f"{tag} OK [CAPABILITY {_CAPABILITIES_AUTHENTICATED}] Logged in\r\n")
        await self._record(
            "imap_login_success",
            AlertSeverity.HIGH,
            {
                "username": username[:256],
                "planted_credential": planted,
                "messages": count,
                "service": "imap",
            },
        )

    async def _begin_sasl(self, tag: str, rest: str) -> None:
        words = rest.strip().split(None, 1)
        mechanism = words[0].upper() if words else ""
        initial = words[1].strip() if len(words) > 1 else ""
        if self._mailbox is not None:
            self._send(f"{tag} NO [CLIENTBUG] Already logged in.\r\n")
            return
        if mechanism == "PLAIN":
            if initial:  # SASL-IR: the credential may ride on the same line
                username, password = decode_plain(initial)
                await self._attempt_login(tag, username, password, "AUTHENTICATE PLAIN")
            else:
                self._sasl = (tag, "plain", "")
                self._send("+ \r\n")
            return
        if mechanism == "LOGIN":
            if initial:
                self._sasl = (tag, "login_pass", decode_text(initial))
                self._send(f"+ {LOGIN_PASSWORD_PROMPT}\r\n")
            else:
                self._sasl = (tag, "login_user", "")
                self._send(f"+ {LOGIN_USERNAME_PROMPT}\r\n")
            return
        self._send(f"{tag} NO Unsupported authentication mechanism.\r\n")
        await self._record(
            "imap_auth_attempt",
            AlertSeverity.MEDIUM,
            {"mechanism": mechanism[:40], "service": "imap"},
        )

    async def _continue_sasl(self, line: str) -> None:
        assert self._sasl is not None
        tag, stage, username = self._sasl
        self._sasl = None
        if line.strip() == "*":
            self._send(f"{tag} BAD Authentication aborted.\r\n")
            return
        if stage == "plain":
            user, password = decode_plain(line)
            await self._attempt_login(tag, user, password, "AUTHENTICATE PLAIN")
        elif stage == "login_user":
            self._sasl = (tag, "login_pass", decode_text(line))
            self._send(f"+ {LOGIN_PASSWORD_PROMPT}\r\n")
        else:
            await self._attempt_login(tag, username, decode_text(line), "AUTHENTICATE LOGIN")

    # ── authenticated state ──────────────────────────────────────────────────

    async def _authenticated(self, tag: str, command: str, rest: str, line: str) -> None:
        assert self._mailbox is not None
        if command == "UID":
            sub, _, tail = rest.partition(" ")
            if sub.upper() not in ("FETCH", "STORE", "SEARCH", "COPY"):
                # UID EXPUNGE needs UIDPLUS, which is not advertised.
                self._send(f"{tag} BAD Error in IMAP command UID: Unknown command.\r\n")
                return
            await self._selected_command(tag, sub.upper(), tail, uid_mode=True, line=line)
            return
        if command in ("NOOP", "CHECK"):
            self._poll_new_mail()
            self._send(f"{tag} OK {command.title()} completed.\r\n")
        elif command == "ID":
            self._send(f'* ID ("name" "Dovecot")\r\n{tag} OK ID completed.\r\n')
        elif command == "ENABLE":
            self._send(f"{tag} OK Enable completed.\r\n")
        elif command == "NAMESPACE":
            self._send(f'* NAMESPACE (("" "/")) NIL NIL\r\n{tag} OK Namespace completed.\r\n')
        elif command in ("LIST", "LSUB"):
            self._list(tag, command, rest)
        elif command == "STATUS":
            self._status(tag, rest)
        elif command in ("SELECT", "EXAMINE"):
            self._select(tag, command, rest)
        elif command == "IDLE":
            self._poll_new_mail()
            self._idle_tag = tag
            self._send("+ idling\r\n")
        elif command in ("SUBSCRIBE", "UNSUBSCRIBE"):
            self._send(f"{tag} OK {command.title()} completed.\r\n")
        elif command == "CREATE":
            await self._create(tag, rest, line)
        elif command == "DELETE":
            await self._delete(tag, rest, line)
        elif command == "RENAME":
            await self._rename(tag, rest, line)
        elif command == "APPEND":
            await self._append(tag, rest, line)
        elif command in ("FETCH", "STORE", "SEARCH", "EXPUNGE", "CLOSE", "UNSELECT", "COPY"):
            await self._selected_command(tag, command, rest, uid_mode=False, line=line)
        else:
            self._send(f"{tag} BAD Unknown command.\r\n")
            await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})

    def _folder_messages(self, name: str) -> list[StoredMessage]:
        """A folder's messages as this connection sees them: the shared ones, then what it added,
        in UID order (mail it appended to the inbox takes a number from the shared counter, so
        it sorts among the real mail by when it arrived)."""
        assert self._mailbox is not None
        if name == "INBOX":
            base = list(MAILDROP.messages(self._mailbox, self._mail_domain))
        elif name in _FOLDERS:
            base = MAILDROP.folder(self._mailbox, name, self._mail_domain)
        else:
            base = []
        return sorted(base + self._appended.get(name, []), key=lambda m: m.number)

    def _canonical(self, name: str) -> str | None:
        if name.upper() == "INBOX":
            return "INBOX"
        if name in _FOLDERS or name in self._user_folders:
            return name
        return None

    def _all_folders(self) -> list[str]:
        return [*_FOLDERS, *sorted(self._user_folders)]

    def _uidnext(self, folder: str) -> int:
        assert self._mailbox is not None
        highest = max((m.number for m in self._folder_messages(folder)), default=0)
        if folder == "INBOX":
            highest = max(highest, MAILDROP.next_number(self._mailbox, self._mail_domain) - 1)
        return highest + 1

    def _uidvalidity(self, folder: str) -> int:
        assert self._mailbox is not None
        base = MAILDROP.validity(self._mailbox, self._mail_domain)
        if folder == "INBOX":
            return base
        return (
            base
            + 1
            + zlib.crc32(folder.encode()) % 1000
            + 1009 * self._folder_generation.get(folder, 0)
        )

    def _add_message(self, folder: str, raw: bytes, flags: set[str]) -> bool:
        """Put a message into `folder` for this connection only. False if over budget."""
        if (
            sum(len(v) for v in self._appended.values()) >= _MAX_SESSION_MESSAGES
            or self._session_bytes + len(raw) > _MAX_SESSION_BYTES
        ):
            return False
        self._overlay_counter += 1
        if folder == "INBOX":
            # From the shared counter, so it can never collide with mail delivered later and the
            # UIDs stay ascending in the order things arrived.
            assert self._mailbox is not None
            number = MAILDROP.reserve_number(self._mailbox, self._mail_domain)
        else:
            number = max((m.number for m in self._folder_messages(folder)), default=0) + 1
        message = StoredMessage(
            uid=f"s{self._overlay_counter}", raw=raw[:_MAX_APPEND], number=number
        )
        self._appended.setdefault(folder, []).append(message)
        self._session_bytes += len(message.raw)
        self._flag_store.setdefault(folder, {})[number] = set(flags)
        sel = self._selected
        if sel is not None and sel.name == folder:
            sel.messages.append(message)
            self._send(f"* {len(sel.view())} EXISTS\r\n* 1 RECENT\r\n")
        return True

    async def _create(self, tag: str, rest: str, line: str) -> None:
        args = _split_args(rest)
        name = args[0] if args else ""
        if name.upper() == "INBOX" or name in self._all_folders():
            self._send(f"{tag} NO [ALREADYEXISTS] Mailbox already exists.\r\n")
        elif not _FOLDER_NAME.fullmatch(name) or len(self._user_folders) >= _MAX_USER_FOLDERS:
            self._send(f"{tag} NO [CANNOT] Invalid mailbox name.\r\n")
        else:
            self._user_folders.append(name)
            self._send(f"{tag} OK Create completed.\r\n")
        await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})

    async def _delete(self, tag: str, rest: str, line: str) -> None:
        args = _split_args(rest)
        name = args[0] if args else ""
        if name not in self._user_folders:
            what = (
                "[NOPERM] Permission denied"
                if self._canonical(name)
                else "[NONEXISTENT] Mailbox doesn't exist"
            )
            self._send(f"{tag} NO {what}.\r\n")
        else:
            self._forget_folder(name)
            self._send(f"{tag} OK Delete completed.\r\n")
        await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})

    def _forget_folder(self, name: str) -> None:
        self._folder_generation[name] = self._folder_generation.get(name, 0) + 1
        self._user_folders.remove(name)
        self._session_bytes -= sum(len(m.raw) for m in self._appended.pop(name, []))
        self._flag_store.pop(name, None)
        self._expunge_store.pop(name, None)
        if self._selected is not None and self._selected.name == name:
            self._selected = None

    async def _rename(self, tag: str, rest: str, line: str) -> None:
        args = _split_args(rest)
        old, new = (args + ["", ""])[:2]
        if old not in self._user_folders:
            self._send(f"{tag} NO [NOPERM] Permission denied.\r\n")
        elif new.upper() == "INBOX" or new in self._all_folders():
            self._send(f"{tag} NO [ALREADYEXISTS] Mailbox already exists.\r\n")
        elif not _FOLDER_NAME.fullmatch(new):
            self._send(f"{tag} NO [CANNOT] Invalid mailbox name.\r\n")
        else:
            self._folder_generation[old] = self._folder_generation.get(old, 0) + 1
            self._user_folders[self._user_folders.index(old)] = new
            if old in self._appended:
                self._appended[new] = self._appended.pop(old)
            if old in self._flag_store:
                self._flag_store[new] = self._flag_store.pop(old)
            if old in self._expunge_store:
                self._expunge_store[new] = self._expunge_store.pop(old)
            if self._selected is not None and self._selected.name == old:
                self._selected = None
            self._send(f"{tag} OK Rename completed.\r\n")
        await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})

    async def _append(self, tag: str, rest: str, line: str) -> None:
        """APPEND folder [(flags)] [date] {literal}: the message is kept for this connection."""
        raw, self._last_literal = self._last_literal, b""
        head, self._last_literal_head = self._last_literal_head, ""
        # `tag APPEND folder [(flags)] [date-time]`: drop the tag and the command word.
        rest = head.strip().split(None, 2)[2] if len(head.split(None, 2)) > 2 else rest
        args = _split_args(rest.split("(", 1)[0])
        folder = self._canonical(args[0]) if args else None
        if not raw:
            self._send(f"{tag} BAD Error in IMAP command APPEND: Missing message literal.\r\n")
            return
        if folder is None:
            self._send(
                f"{tag} NO [TRYCREATE] Mailbox doesn't exist: {_safe(args[0] if args else '')}\r\n"
            )
            return
        flag_text = re.search(r"\(([^)]*)\)", rest)
        flags = {
            _FLAG_BY_LOWER.get(f.lower(), f) for f in (flag_text[1].split() if flag_text else [])
        }
        if len(flags) > _MAX_KEYWORDS or not all(_FLAG.fullmatch(f) for f in flags):
            self._send(f"{tag} BAD Error in IMAP command APPEND: Invalid flags.\r\n")
            return
        if not self._add_message(folder, raw, flags):
            self._send(f"{tag} NO [OVERQUOTA] Mailbox is over quota.\r\n")
            return
        self._send(f"{tag} OK Append completed.\r\n")
        if self._append_events < _MAX_APPEND_EVENTS:
            self._append_events += 1
            await self._record(
                "imap_append",
                AlertSeverity.MEDIUM,
                {
                    "folder": folder,
                    "size_bytes": len(raw),
                    "subject": _subject_of(raw),
                    "service": "imap",
                },
            )

    def _copy(self, tag: str, rest: str, sel: _Selected, uid_mode: bool) -> None:
        spec, _, target_text = rest.partition(" ")
        seqnums = self._seqnums(spec, sel, uid_mode)
        args = _split_args(target_text)
        if seqnums is None or not args:
            self._send(f"{tag} BAD Error in IMAP command COPY: Invalid arguments.\r\n")
            return
        target = self._canonical(args[0])
        if target is None:
            self._send(f"{tag} NO [TRYCREATE] Mailbox doesn't exist: {_safe(args[0])}\r\n")
            return
        view = sel.view()
        chosen = [view[seq - 1] for seq in seqnums]
        # All or nothing: a COPY that stopped part-way would leave a partial copy behind.
        if not self._fits(len(chosen), sum(len(m.raw) for m in chosen)):
            self._send(f"{tag} NO [OVERQUOTA] Mailbox is over quota.\r\n")
            return
        for message in chosen:
            flags = set(sel.flags.get(message.number, set())) - {"\\Recent"}
            self._add_message(target, message.raw, flags)
        self._send(f"{tag} OK Copy completed.\r\n")

    def _fits(self, count: int, size: int) -> bool:
        """Whether `count` more messages of `size` bytes fit in this connection's allowance."""
        return (
            sum(len(v) for v in self._appended.values()) + count <= _MAX_SESSION_MESSAGES
            and self._session_bytes + size <= _MAX_SESSION_BYTES
        )

    def _list(self, tag: str, command: str, rest: str) -> None:
        args = _split_args(rest)
        if len(args) < 2:
            self._send(f"{tag} BAD Missing arguments.\r\n")
            return
        reference, pattern = args[0], args[1]
        if pattern == "":
            self._send(
                f'* {command} (\\Noselect) "/" ""\r\n{tag} OK {command.title()} completed.\r\n'
            )
            return
        full = (reference + pattern).replace("%", "*")  # a flat hierarchy: % and * agree
        for name in self._all_folders():
            if _wild_match(full, name):
                attrs = ["\\HasNoChildren"] + ([_ATTRIBUTES[name]] if name in _ATTRIBUTES else [])
                self._send(f'* {command} ({" ".join(attrs)}) "/" {mbx.imap_string(name)}\r\n')
        self._send(f"{tag} OK {command.title()} completed.\r\n")

    def _status(self, tag: str, rest: str) -> None:
        assert self._mailbox is not None
        args = _split_args(rest.split("(", 1)[0])
        items = re.findall(r"[A-Za-z]+", rest.split("(", 1)[1]) if "(" in rest else []
        folder = self._canonical(args[0]) if args else None
        if folder is None or not items:
            self._send(
                f"{tag} NO [NONEXISTENT] Mailbox doesn't exist: {_safe(args[0] if args else '')}\r\n"
            )
            return
        gone = self._expunge_store.get(folder, set())
        messages = [m for m in self._folder_messages(folder) if m.number not in gone]
        store = self._flag_store.get(folder, {})
        unseen = sum(1 for m in messages if "\\Seen" not in store.get(m.number, _initial_flags(m)))
        values = {
            "MESSAGES": len(messages),
            "RECENT": 0,
            "UIDNEXT": self._uidnext(folder),
            "UIDVALIDITY": self._uidvalidity(folder),
            "UNSEEN": unseen,
        }
        wanted = [i.upper() for i in items if i.upper() in values]
        body = " ".join(f"{i} {values[i]}" for i in wanted)
        self._send(f"* STATUS {mbx.imap_string(folder)} ({body})\r\n{tag} OK Status completed.\r\n")

    def _select(self, tag: str, command: str, rest: str) -> None:
        assert self._mailbox is not None
        args = _split_args(rest)
        folder = self._canonical(args[0]) if args else None
        if folder is None:
            self._selected = None
            self._send(
                f"{tag} NO [NONEXISTENT] Mailbox doesn't exist: {_safe(args[0] if args else '')}\r\n"
            )
            return
        read_only = command == "EXAMINE"
        messages = self._folder_messages(folder)
        store = self._flag_store.setdefault(folder, {})
        for message in messages:
            store.setdefault(message.number, _initial_flags(message))
        self._selected = _Selected(
            name=folder,
            read_only=read_only,
            messages=messages,
            flags=store,
            expunged=self._expunge_store.setdefault(folder, set()),
        )
        view = self._selected.view()
        first_unseen = next(
            (i + 1 for i, m in enumerate(view) if "\\Seen" not in self._selected.flags[m.number]),
            None,
        )
        validity = self._uidvalidity(folder)
        next_uid = self._uidnext(folder)
        permanent = "()" if read_only else "(\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)"
        lines = [
            f"* FLAGS ({' '.join(_SYSTEM_FLAGS)})",
            f"* OK [PERMANENTFLAGS {permanent}] Flags permitted.",
            f"* {len(view)} EXISTS",
            "* 0 RECENT",
        ]
        if first_unseen:
            lines.append(f"* OK [UNSEEN {first_unseen}] First unseen.")
        lines += [
            f"* OK [UIDVALIDITY {validity}] UIDs valid",
            f"* OK [UIDNEXT {next_uid}] Predicted next UID",
            f"{tag} OK [{'READ-ONLY' if read_only else 'READ-WRITE'}] {command.title()} completed.",
        ]
        self._send("\r\n".join(lines) + "\r\n")

    def _poll_new_mail(self) -> None:
        """Mail delivered since the folder was opened (by the SMTP honeypot, say) appears the
        way it does on a real server: an untagged EXISTS the next time the client asks."""
        sel = self._selected
        if sel is None or sel.name != "INBOX" or self._mailbox is None:
            return
        known = max((m.number for m in sel.messages), default=0)
        fresh = [m for m in MAILDROP.messages(self._mailbox, self._mail_domain) if m.number > known]
        if not fresh:
            return
        for message in fresh:
            sel.messages.append(message)
            sel.flags[message.number] = _initial_flags(message)
        self._send(f"* {len(sel.view())} EXISTS\r\n* {len(fresh)} RECENT\r\n")

    # ── selected state ───────────────────────────────────────────────────────

    async def _selected_command(
        self, tag: str, command: str, rest: str, *, uid_mode: bool, line: str
    ) -> None:
        sel = self._selected
        if sel is None:
            self._send(f"{tag} BAD Command not valid in this state (no mailbox selected).\r\n")
            return
        if command == "FETCH":
            await self._fetch(tag, rest, sel, uid_mode)
        elif command == "STORE":
            self._store(tag, rest, sel, uid_mode)
        elif command == "SEARCH":
            await self._search(tag, rest, sel, uid_mode)
        elif command == "EXPUNGE":
            if sel.read_only:
                self._send(f"{tag} NO [READ-ONLY] Mailbox is read-only.\r\n")
                return
            self._expunge(sel)
            self._send(f"{tag} OK Expunge completed.\r\n")
        elif command == "CLOSE":
            if not sel.read_only:
                self._expunge(sel, silent=True)
            self._selected = None
            self._send(f"{tag} OK Close completed.\r\n")
        elif command == "UNSELECT":
            self._selected = None
            self._send(f"{tag} OK Unselect completed.\r\n")
        elif command == "COPY":
            self._copy(tag, rest, sel, uid_mode)
        else:
            self._send(f"{tag} BAD Unknown command.\r\n")

    def _seqnums(self, spec: str, sel: _Selected, uid_mode: bool) -> list[int] | None:
        """Message sequence numbers for a set, or None if the set is not valid syntax."""
        if not mbx.valid_seqset(spec):
            return None
        view = sel.view()
        if uid_mode:
            return mbx.uid_set_to_seqnums(spec, [m.number for m in view])
        return mbx.parse_seqset(spec, len(view))

    async def _writable(self) -> bool:
        """Wait for the peer to read what it has been sent before producing more. A slow
        client is made to wait; one that makes no progress for `_WRITE_WAIT` seconds is dropped
        (False). Producing a whole mailbox into the write buffer first would both buffer a
        megabyte per command and abort an honest client on a slow link."""
        waited = 0.0
        while self._transport is not None and not self._transport.is_closing():
            if self._transport.get_write_buffer_size() <= _WRITE_SOFT_LIMIT:
                return True
            if waited >= _WRITE_WAIT:
                self._transport.abort()
                return False
            await asyncio.sleep(0.02)
            waited += 0.02
        return False

    async def _fetch(self, tag: str, rest: str, sel: _Selected, uid_mode: bool) -> None:
        spec, _, item_text = rest.partition(" ")
        seqnums = self._seqnums(spec, sel, uid_mode)
        items = mbx.tokenize_fetch_items(item_text) if item_text.strip() else []
        if seqnums is None or not items:
            self._send(f"{tag} BAD Error in IMAP command FETCH: Invalid arguments.\r\n")
            return
        if len(items) > _MAX_FETCH_ITEMS:
            self._send(f"{tag} BAD Error in IMAP command FETCH: Too many fetch attributes.\r\n")
            return
        if uid_mode and not any(i.upper() == "UID" for i in items):
            items.insert(0, "UID")
        for item in items:
            if not _valid_fetch_item(item):
                self._send(f"{tag} BAD Error in IMAP command FETCH: Invalid fetch attribute.\r\n")
                return
        view = sel.view()
        for seq in seqnums:
            message = view[seq - 1]
            flags = sel.flags.setdefault(message.number, set())
            # Rendering parses the message, which is CPU work on attacker-chosen content: it
            # runs off the event loop (which also serves every other honeypot), a few at a time.
            response, new_flags, read_body = await _run_cpu(
                _render_fetch, seq, message.number, message.raw, items, set(flags), sel.read_only
            )
            flags.clear()
            flags.update(new_flags)
            if not await self._writable():
                return
            self._send_bytes(response)
            if read_body and self._fetch_events < _MAX_FETCH_EVENTS:
                self._fetch_events += 1
                await self._record(
                    "imap_message_fetched",
                    AlertSeverity.MEDIUM,
                    {
                        "mailbox": self._mailbox,
                        "uid": message.number,
                        "subject": _subject_of(message.raw),
                        "service": "imap",
                    },
                )
        self._send(f"{tag} OK Fetch completed.\r\n")

    def _store(self, tag: str, rest: str, sel: _Selected, uid_mode: bool) -> None:
        match = re.match(r"(\S+)\s+([+-]?)FLAGS(\.SILENT)?\s+\(?([^)]*)\)?\s*$", rest.strip(), re.I)
        if not match:
            self._send(f"{tag} BAD Error in IMAP command STORE: Invalid arguments.\r\n")
            return
        seqnums = self._seqnums(match.group(1), sel, uid_mode)
        if seqnums is None:
            self._send(f"{tag} BAD Error in IMAP command STORE: Invalid message set.\r\n")
            return
        if sel.read_only:
            self._send(f"{tag} NO [READ-ONLY] Mailbox is read-only.\r\n")
            return
        mode, silent = match.group(2), bool(match.group(3))
        wanted = {_FLAG_BY_LOWER.get(f.lower(), f) for f in match.group(4).split()}
        # Keywords are remembered per message for the life of the connection and echoed in every
        # FLAGS response, so how many and how long are bounded.
        if len(wanted) > _MAX_KEYWORDS or any(
            len(f) > _MAX_KEYWORD_LENGTH or not f.isprintable() for f in wanted
        ):
            self._send(f"{tag} NO [LIMIT] Too many or too long flags.\r\n")
            return
        if not all(
            _FLAG.fullmatch(f) for f in wanted
        ):  # atoms that would need quoting, \\Recent...
            self._send(f"{tag} BAD Error in IMAP command STORE: Invalid flag.\r\n")
            return
        view = sel.view()
        for seq in seqnums:
            message = view[seq - 1]
            flags = sel.flags.setdefault(message.number, set())
            if mode == "+":
                if len(flags | wanted) > _MAX_KEYWORDS + len(_SYSTEM_FLAGS):
                    self._send(f"{tag} NO [LIMIT] Too many flags on a message.\r\n")
                    return
                flags |= wanted
            elif mode == "-":
                flags -= wanted
            else:
                flags.clear()
                flags |= wanted
            if not silent:
                uid_part = f" UID {message.number}" if uid_mode else ""
                self._send(f"* {seq} FETCH (FLAGS ({' '.join(sorted(flags))}){uid_part})\r\n")
        self._send(f"{tag} OK Store completed.\r\n")

    async def _search(self, tag: str, rest: str, sel: _Selected, uid_mode: bool) -> None:
        text = rest.strip()
        if text.upper().startswith("CHARSET"):
            text = text.split(None, 2)[2] if len(text.split(None, 2)) > 2 else ""
        criteria = mbx.tokenize_search(text)
        try:
            mbx.validate_search(criteria)
        except mbx.SearchError as e:
            self._send(f"{tag} BAD Error in IMAP command SEARCH: {_safe(str(e))}.\r\n")
            return
        view = sel.view()
        snapshot = [(m.number, m.raw, set(sel.flags.get(m.number, set()))) for m in view]
        largest_uid = max((m.number for m in view), default=0)
        try:
            matched = await _run_cpu(_search_view, snapshot, criteria, largest_uid)
        except mbx.SearchError as e:
            self._send(f"{tag} BAD Error in IMAP command SEARCH: {_safe(str(e))}.\r\n")
            return
        hits = [view[i].number if uid_mode else i + 1 for i in matched]
        self._send(f"* SEARCH{''.join(f' {n}' for n in hits)}\r\n{tag} OK Search completed.\r\n")

    def _expunge(self, sel: _Selected, *, silent: bool = False) -> None:
        """Remove \\Deleted messages from this session's view. The maildrop is shared decoy
        state: one visitor must not be able to empty it for the next."""
        position = 1
        for message in list(sel.view()):
            if "\\Deleted" in sel.flags.get(message.number, set()):
                sel.expunged.add(message.number)
                if not silent:
                    self._send(f"* {position} EXPUNGE\r\n")
            else:
                position += 1


# ── off-loop work ──────────────────────────────────────────────────────────────

_CPU_SLOTS: LoopBound[asyncio.Semaphore] = LoopBound(lambda: asyncio.Semaphore(4))


async def _run_cpu(function: Any, *args: Any) -> Any:
    """Run CPU-bound work on a thread, at most four at once process-wide."""
    async with _CPU_SLOTS.get():
        return await asyncio.to_thread(function, *args)


def _render_fetch(
    seq: int,
    uid: int,
    raw: bytes,
    items: list[str],
    flags: set[str],
    read_only: bool,
) -> tuple[bytes, set[str], bool]:
    """One message's `* n FETCH (...)` line. Returns (bytes, flags afterwards, whether the
    body was read). Pure, so it can run on a thread; the parse of each structure is done once
    however many times an item is repeated."""
    seen_before = set(flags)
    wants_flags = any(i.upper() == "FLAGS" for i in items)
    cache: dict[str, Any] = {}

    def cached(key: str, make: Any) -> Any:
        if key not in cache:
            cache[key] = make()
        return cache[key]

    out: list[bytes] = []
    read_body = False
    for item in items:
        name = item.upper()
        body = mbx.parse_body_item(item)
        if name == "FLAGS":
            out.append(b"FLAGS (" + " ".join(sorted(flags)).encode() + b")")
        elif name == "UID":
            out.append(f"UID {uid}".encode())
        elif name == "RFC822.SIZE":
            out.append(f"RFC822.SIZE {len(raw)}".encode())
        elif name == "INTERNALDATE":
            date = cached("date", lambda: mbx.internaldate(raw))
            out.append(f'INTERNALDATE "{date}"'.encode())
        elif name == "ENVELOPE":
            envelope = cached("envelope", lambda: mbx.build_envelope(raw))
            out.append(b"ENVELOPE " + envelope.encode("utf-8", errors="replace"))
        elif name in ("BODYSTRUCTURE", "BODY"):
            extended = name == "BODYSTRUCTURE"
            structure = cached(
                name, lambda extended=extended: mbx.build_bodystructure(raw, extended=extended)
            )
            out.append(f"{name} ".encode() + structure.encode("utf-8", errors="replace"))
        elif name in ("RFC822", "RFC822.HEADER", "RFC822.TEXT"):
            section = {"RFC822": "", "RFC822.HEADER": "HEADER", "RFC822.TEXT": "TEXT"}[name]
            data = mbx.fetch_section(raw, section)
            out.append(f"{name} {{{len(data)}}}\r\n".encode() + data)
            if name != "RFC822.HEADER":
                read_body = True
                if not read_only:
                    flags.add("\\Seen")
        elif body is not None:
            peek, section, partial = body
            data = mbx.fetch_section(raw, section, partial)
            label = f"BODY[{section}]" + (f"<{partial[0]}>" if partial else "")
            out.append(f"{label} {{{len(data)}}}\r\n".encode() + data)
            upper = section.upper()
            if not upper.startswith("HEADER") and not upper.endswith(("MIME", "HEADER")):
                read_body = True
                if not peek and not read_only:
                    flags.add("\\Seen")
    if flags != seen_before and not wants_flags:
        out.append(b"FLAGS (" + " ".join(sorted(flags)).encode() + b")")
    return f"* {seq} FETCH (".encode() + b" ".join(out) + b")\r\n", flags, read_body


def _search_view(
    messages: list[tuple[int, bytes, set[str]]], criteria: list[str], largest_uid: int
) -> list[int]:
    """Indexes (0-based) of the messages matching `criteria`. Pure, for a thread."""
    return [
        index
        for index, (uid, raw, flags) in enumerate(messages)
        if mbx.matches_search(
            raw, index + 1, uid, flags, criteria, count=len(messages), largest_uid=largest_uid
        )
    ]


# ── module helpers ────────────────────────────────────────────────────────────

_MAILBOX_COMMANDS = {
    "SELECT", "EXAMINE", "LIST", "LSUB", "FETCH", "STATUS", "SEARCH", "STORE", "UID", "EXPUNGE",
    "CLOSE", "COPY", "APPEND", "NAMESPACE", "IDLE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE",
    "UNSUBSCRIBE", "CHECK", "UNSELECT",
}  # fmt: skip

_SIMPLE_FETCH_ITEMS = {
    "FLAGS", "UID", "RFC822", "RFC822.SIZE", "RFC822.HEADER", "RFC822.TEXT",
    "INTERNALDATE", "ENVELOPE", "BODY", "BODYSTRUCTURE",
}  # fmt: skip


def _valid_fetch_item(item: str) -> bool:
    return item.upper() in _SIMPLE_FETCH_ITEMS or mbx.parse_body_item(item) is not None


def _tag_of(line: str) -> str:
    """The client's tag for echoing in a reply: printable, no spaces, bounded. An unparseable
    one becomes `*`, which is how a server addresses a reply it cannot attribute."""
    tag = line.split(" ", 1)[0]
    clean = "".join(c for c in tag[:32] if c.isprintable() and c not in ' (){%*"\\]')
    return clean or "*"


def _wild_match(pattern: str, text: str) -> bool:
    """LIST pattern matching: `*` matches anything, `%` anything but the hierarchy delimiter
    (these folder names are flat, so they agree). Iterative, with no regex or `fnmatch`: a
    client-chosen pattern compiled by `fnmatch` is cached process-wide, one entry per distinct
    pattern."""
    if len(pattern) > _MAX_PATTERN:
        return False
    p = t = 0
    star = mark = -1
    pattern, text = pattern.upper(), text.upper()
    while t < len(text):
        if p < len(pattern) and pattern[p] in "*%":
            star, mark = p, t
            p += 1
        elif p < len(pattern) and pattern[p] == text[t]:
            p += 1
            t += 1
        elif star >= 0:
            mark += 1
            p, t = star + 1, mark
        else:
            return False
    while p < len(pattern) and pattern[p] in "*%":
        p += 1
    return p == len(pattern)


def _subject_of(raw: bytes) -> str:
    for line in raw[:4096].decode("utf-8", errors="replace").splitlines():
        if line.lower().startswith("subject:"):
            return line[8:].strip()[:200]
        if not line.strip():
            break
    return ""


def _safe(text: str) -> str:
    """Attacker text echoed in a reply: printable and short, no line breaks."""
    return "".join(c for c in text[:48] if c.isprintable())


def _split_args(rest: str) -> list[str]:
    """Split command arguments, honouring IMAP's quoted-string form.

    Clients send `LOGIN user pass`, `LOGIN "user" "pass"`, or a mix, and a
    password containing a space only survives if the quoting is respected.
    """
    args: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    quoted_empty = False
    for char in rest.strip():
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            if in_quotes and not current:
                quoted_empty = True
            in_quotes = not in_quotes
        elif char == " " and not in_quotes:
            if current or quoted_empty:
                args.append("".join(current))
                current = []
                quoted_empty = False
        else:
            current.append(char)
    if current or quoted_empty:
        args.append("".join(current))
    return args


def _split_login_args(rest: str) -> tuple[str, str]:
    """`LOGIN` arguments as (username, password)."""
    args = _split_args(rest)
    return (args[0] if args else ""), (args[1] if len(args) > 1 else "")


class IMAPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        accepted = accepted_pairs(name, config.get("accepted_logins"))
        mail_domain = str(config.get("mail_domain") or "corp.local")[:64]
        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(
                lambda: _IMAPProtocol(name, hp_id, accepted, mail_domain), self._limiter
            ),
            host="0.0.0.0",
            port=port,
        )
        cid = f"imap-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("IMAP honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_imap"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["IMAP honeypot is in-process — events are stored directly in the database."]
