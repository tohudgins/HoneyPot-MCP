"""POP3 honeypot engine — tcp/110, the other half of the mail sweep.

POP3 and IMAP are scanned by the same credential-stuffing botnets, usually in
the same pass, because either one proves a mailbox password is good. Running
one without the other leaves an obvious hole in a mail-shaped decoy: a host
answering on 143 but refusing 110 is an unusual configuration, and the sweep
that finds it will note the inconsistency.

The capture surface is even simpler than IMAP's. `USER` then `PASS` sends the
password in the clear with no encoding at all, so a single exchange yields a
full credential. `APOP` is also offered because some tooling prefers it, and
although it hashes the password against the greeting's timestamp, that
timestamp is ours — so the digest is recorded alongside the challenge that
produced it and remains crackable offline, exactly like the SIP and rsync
digests.

`CAPA` deliberately does not advertise `STLS`-only operation: forcing TLS would
stop the attacker sending the password, which is the one thing this engine
exists to collect.

A login succeeds only for a credential an operator planted as a honeytoken (the event
buffer's matcher marks the event) or the one weak pair this honeypot derives from its name
(`accepted_logins` in its config replaces it; an empty list turns access off, as for the
HTTP admin area). A spray that gets in reaches a real, read-only maildrop
(`engines/maildrop.py`): what the SMTP honeypot accepted, including delivery-failure
notices, plus a few ordinary internal messages so the inbox is not conspicuously empty.
`DELE` is acknowledged and nothing is ever removed.

Wire format: RFC 1939 (POP3), RFC 2449 (CAPA).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from typing import Any

from honeypot_mcp import credential_match
from honeypot_mcp.config import get_settings
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
    extract_lines,
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
_MAX_LINE = 4096
# Lines processed per network read; more is a flood and the connection is closed.
_MAX_LINES_PER_READ = 16
# Real servers pause before rejecting. Instant refusal makes guessing free and
# is itself a tell.
_AUTH_FAIL_DELAY = 1.2
# Retrieval events recorded per session; a client downloading a whole mailbox is one finding.
_MAX_RETRIEVAL_EVENTS = 20
_MAX_WRITE_BACKLOG = 512 * 1024


def _safe(text: str) -> str:
    """Attacker text echoed in a reply: printable, short, no line breaks."""
    return "".join(c for c in text[:32] if c.isprintable())


def _subject_of(raw: bytes) -> str:
    for line in raw[:4096].decode("utf-8", errors="replace").splitlines():
        if line.lower().startswith("subject:"):
            return line[8:].strip()[:200]
        if not line.strip():
            break
    return ""


_CAPABILITIES = (
    "CAPA",
    "TOP",
    "UIDL",
    "RESP-CODES",
    "PIPELINING",
    "AUTH-RESP-CODE",
    "USER",
    "SASL PLAIN LOGIN",
)


class _POP3Protocol(asyncio.Protocol):
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
        # Set once a login succeeds: the POP3 "transaction" state (RFC 1939 §5).
        self._mailbox: str | None = None
        self._messages: list[StoredMessage] = []
        # (stage, username so far) while an AUTH exchange waits for its next line.
        self._sasl: tuple[str, str] | None = None
        self._deleted: set[int] = set()
        self._retrievals = 0
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._worker = LineWorker(self._handle_raw, name="pop3-lines", max_total=2048)
        self._username = ""
        # The APOP challenge from our greeting. Recorded with any digest so the
        # captured hash can be attacked offline.
        self._apop_challenge = ""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._apop_challenge = f"<{secrets.token_hex(8)}.{int(time.time())}@mail>"
        self._send(f"+OK Dovecot ready. {self._apop_challenge}")
        spawn(self._record("pop3_connection", AlertSeverity.LOW, {}), name="pop3-connect")

    def _send(self, text: str) -> None:
        if self._transport is not None and not self._transport.is_closing():
            if write_backlogged(self._transport, _MAX_WRITE_BACKLOG):
                # A peer pipelining RETRs and never reading the replies: ~4 KB of commands
                # bought 61 MB of buffered output on one connection.
                self._transport.abort()
                return
            # Half-closed by `close_after_error`; see the IMAP engine.
            with contextlib.suppress(RuntimeError):
                self._transport.write((text + "\r\n").encode("utf-8", errors="replace"))

    def _close(self) -> None:
        # Session ending on our side: drop lines queued behind this one.
        self._worker.stop()
        if self._transport is not None:
            self._transport.close()

    async def _auth_delay(self) -> None:
        if self._transport is not None and not self._transport.is_closing():
            await asyncio.sleep(_AUTH_FAIL_DELAY)

    def data_received(self, data: bytes) -> None:
        lines, self._buf, problem = extract_lines(
            self._buf + data, max_lines=_MAX_LINES_PER_READ, max_line=_MAX_LINE * 4
        )
        accepted = self._worker.submit(lines)
        if problem or not accepted:
            # Flood or oversized line: keep what was already queued (it is
            # evidence), refuse the rest and hang up.
            self._send("-ERR Line too long" if problem == "too_long" else "-ERR Too fast")
            if self._transport is not None:
                close_after_error(self._transport)

    async def _handle_raw(self, raw: bytes) -> None:
        await self._handle(raw.decode("utf-8", errors="replace").strip())

    async def _handle(self, line: str) -> None:
        if self._sasl is not None:
            await self._continue_auth(line)
            return
        if not line:
            return
        parts = line.split(" ", 1)
        command = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

        if self._mailbox is not None and await self._transaction(command, rest):
            return

        if command == "CAPA":
            body = "\r\n".join(_CAPABILITIES)
            self._send(f"+OK Capability list follows\r\n{body}\r\n.")
            await self._record("pop3_capability_probe", AlertSeverity.LOW, {"command": line[:200]})
            return

        if command == "USER":
            self._username = rest
            self._send(f"+OK User {rest[:64]} accepted")
            return

        if command == "PASS":
            # The whole point of port 110: no encoding, no encryption.
            await self._attempt_login(self._username, rest, "USER/PASS")
            return

        if command == "APOP":
            # `APOP <user> <md5 digest over challenge+password>`.
            apop = rest.split(" ", 1)
            username = apop[0] if apop else ""
            digest = apop[1] if len(apop) > 1 else ""
            await self._record(
                "pop3_login_attempt",
                AlertSeverity.HIGH,
                {
                    "username": username[:256],
                    "digest_response": digest[:128],
                    "challenge": self._apop_challenge,
                    "service": "pop3",
                    "method": "APOP",
                },
            )
            await self._auth_delay()
            self._send("-ERR [AUTH] Authentication failed.")
            return

        if command == "AUTH":
            await self._begin_auth(rest)
            return

        if command == "STLS":
            # Declining keeps the session cleartext, which is where the
            # password is capturable.
            self._send("-ERR TLS handshake failed.")
            await self._record("pop3_stls_declined", AlertSeverity.LOW, {})
            return

        if command == "QUIT":
            self._send("+OK Logging out.")
            self._close()
            return

        if command in ("STAT", "LIST", "UIDL", "RETR", "DELE", "TOP", "NOOP", "RSET"):
            # Mailbox commands before authenticating are what an exposed or
            # broken server would leak, so they are worth recording.
            self._send("-ERR Not authenticated.")
            await self._record("pop3_mailbox_access", AlertSeverity.MEDIUM, {"command": line[:200]})
            return

        self._send("-ERR Unknown command.")
        await self._record("pop3_command", AlertSeverity.LOW, {"command": line[:200]})

    async def _attempt_login(self, username: str, password: str, method: str) -> None:
        """The one place a plaintext login is judged, whichever way it arrived."""
        attempt = await self._record(
            "pop3_login_attempt",
            AlertSeverity.HIGH,
            {
                "username": username[:256],
                "password": password[:256],
                "service": "pop3",
                "method": method,
            },
        )
        await self._auth_delay()
        planted = credential_match.is_credential_trip(attempt)
        if username and (planted or (username.lower(), password) in self._accepted):
            await self._open_mailbox(username, planted)
            return
        self._send("-ERR [AUTH] Authentication failed.")

    async def _begin_auth(self, rest: str) -> None:
        """`AUTH`, `AUTH PLAIN [initial-response]`, `AUTH LOGIN` (RFC 5034)."""
        words = rest.split(None, 1)
        mechanism = words[0].upper() if words else ""
        if not mechanism:
            self._send("+OK\r\nPLAIN\r\nLOGIN\r\n.")
            return
        if mechanism == "PLAIN":
            if len(words) > 1:
                username, password = decode_plain(words[1])
                await self._attempt_login(username, password, "AUTH PLAIN")
            else:
                self._sasl = ("plain", "")
                self._send("+ ")
            return
        if mechanism == "LOGIN":
            if len(words) > 1:  # an initial response carries the username
                self._sasl = ("login_pass", decode_text(words[1]))
                self._send(f"+ {LOGIN_PASSWORD_PROMPT}")
            else:
                self._sasl = ("login_user", "")
                self._send(f"+ {LOGIN_USERNAME_PROMPT}")
            return
        self._send("-ERR Unsupported authentication mechanism.")
        await self._record(
            "pop3_auth_attempt",
            AlertSeverity.MEDIUM,
            {"mechanism": mechanism[:64], "service": "pop3"},
        )

    async def _continue_auth(self, line: str) -> None:
        """The next line of a multi-step AUTH exchange."""
        assert self._sasl is not None
        stage, username = self._sasl
        self._sasl = None
        if line.strip() == "*":  # the client cancels
            self._send("-ERR Authentication cancelled.")
            return
        if stage == "plain":
            user, password = decode_plain(line)
            await self._attempt_login(user, password, "AUTH PLAIN")
        elif stage == "login_user":
            self._sasl = ("login_pass", decode_text(line))
            self._send(f"+ {LOGIN_PASSWORD_PROMPT}")
        else:
            await self._attempt_login(username, decode_text(line), "AUTH LOGIN")

    async def _record(
        self, event_type: str, severity: AlertSeverity, payload: dict
    ) -> PendingEvent:
        """Submit an event and return it: the buffer marks a planted credential on the
        event itself, which is how a login learns it was a honeytoken."""
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

    async def _open_mailbox(self, username: str, planted: bool) -> None:
        mailbox = username.split("@", 1)[0].lower()[:64]
        self._mailbox = mailbox
        self._messages = MAILDROP.messages(mailbox, self._mail_domain)
        self._deleted = set()
        self._send("+OK Logged in.")
        await self._record(
            "pop3_login_success",
            AlertSeverity.HIGH,
            {
                "username": username[:256],
                "planted_credential": planted,
                "messages": len(self._messages),
                "service": "pop3",
            },
        )

    def _live(self) -> list[tuple[int, StoredMessage]]:
        """(1-based number, message) for messages not marked deleted."""
        return [(i + 1, m) for i, m in enumerate(self._messages) if (i + 1) not in self._deleted]

    def _pick(self, rest: str) -> tuple[int, StoredMessage] | None:
        word = rest.split()[0] if rest.split() else ""
        # int() accepts "1_0", "+1" and Arabic-Indic digits, and refuses over 4300 digits.
        if not (word.isascii() and word.isdigit()) or len(word) > 9:
            return None
        number = int(word)
        if number < 1 or number > len(self._messages) or number in self._deleted:
            return None
        return number, self._messages[number - 1]

    @staticmethod
    def _stuffed(raw: bytes, *, header_only: bool = False, body_lines: int = 0) -> str:
        """A message as POP3 sends it: CRLF lines, leading dots doubled, ending ".".
        TOP sends the headers plus `body_lines` lines of body."""
        text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")
        if header_only:
            try:
                split = lines.index("")
            except ValueError:
                split = len(lines)
            lines = lines[: split + 1 + body_lines]
        out = [("." + ln if ln.startswith(".") else ln) for ln in lines]
        return "\r\n".join(out) + "\r\n."

    async def _transaction(self, command: str, rest: str) -> bool:
        """Commands valid once logged in. Returns False for anything it does not own so
        the caller can fall through to the shared handling (CAPA, QUIT, unknown)."""
        live = self._live()
        if command == "STAT":
            self._send(f"+OK {len(live)} {sum(m.size for _, m in live)}")
            return True
        if command in ("LIST", "UIDL"):
            if rest:
                picked = self._pick(rest)
                if picked is None:
                    self._send("-ERR There's no message " + _safe(rest) + ".")
                else:
                    number, message = picked
                    self._send(f"+OK {number} {message.size if command == 'LIST' else message.uid}")
                return True
            rows = [f"{n} {m.size if command == 'LIST' else m.uid}" for n, m in live]
            self._send("\r\n".join([f"+OK {len(live)} messages:", *rows, "."]))
            return True
        if command in ("RETR", "TOP"):
            picked = self._pick(rest)
            if picked is None:
                self._send("-ERR There's no message " + _safe(rest.split(" ")[0]) + ".")
                return True
            number, message = picked
            if command == "TOP":
                try:
                    count = max(0, int(rest.split()[1]))
                except (ValueError, IndexError):
                    self._send("-ERR Invalid line count.")
                    return True
                self._send(
                    "+OK\r\n" + self._stuffed(message.raw, header_only=True, body_lines=count)
                )
                return True
            self._send(f"+OK {message.size} octets\r\n" + self._stuffed(message.raw))
            if self._retrievals < _MAX_RETRIEVAL_EVENTS:
                self._retrievals += 1
                subject = _subject_of(message.raw)
                await self._record(
                    "pop3_message_retrieved",
                    AlertSeverity.MEDIUM,
                    {"mailbox": self._mailbox, "message": number, "subject": subject},
                )
            return True
        if command == "DELE":
            picked = self._pick(rest)
            if picked is None:
                self._send("-ERR There's no message " + _safe(rest) + ".")
            else:
                # Acknowledged and remembered for this session only: the maildrop is
                # shared decoy state and an intruder must not be able to empty it.
                self._deleted.add(picked[0])
                self._send("+OK Marked to be deleted.")
            return True
        if command == "RSET":
            self._deleted.clear()
            self._send("+OK")
            return True
        if command == "NOOP":
            self._send("+OK")
            return True
        if command in ("USER", "PASS", "APOP", "AUTH"):
            # AUTH was reachable here: it swallowed the next command as a credential and, on
            # success, swapped the session to another mailbox: one more guess per command.
            self._send("-ERR Command not permitted when logged in.")
            return True
        return False

    def connection_lost(self, exc: Exception | None) -> None:
        self._buf = b""


class POP3Engine(HoneypotEngine):
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
                lambda: _POP3Protocol(name, hp_id, accepted, mail_domain), self._limiter
            ),
            host="0.0.0.0",
            port=port,
        )
        cid = f"pop3-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("POP3 honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_pop3"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["POP3 honeypot is in-process — events are stored directly in the database."]


def apop_digest(challenge: str, password: str) -> str:
    """Reference APOP digest, for tests: md5(challenge + password)."""
    import hashlib

    return hashlib.md5((challenge + password).encode(), usedforsecurity=False).hexdigest()
