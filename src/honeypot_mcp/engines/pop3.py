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

Not implemented: an actual maildrop. `STAT` and `LIST` answer from a fixed
fiction so a client that authenticates sees a plausible empty-ish mailbox.

Wire format: RFC 1939 (POP3), RFC 2449 (CAPA).
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

_DOVECOT_VERSION = "2.3.19.1"
_MAX_LINE = 4096
# Real servers pause before rejecting. Instant refusal makes guessing free and
# is itself a tell.
_AUTH_FAIL_DELAY = 1.2

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
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
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
        asyncio.create_task(self._record("pop3_connection", AlertSeverity.LOW, {}))

    def _send(self, text: str) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write((text + "\r\n").encode("utf-8", errors="replace"))

    def _close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_LINE * 4:
            self._buf = b""
            self._send("-ERR Line too long")
            self._close()
            return
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            asyncio.create_task(self._handle(raw.decode("utf-8", errors="replace").strip()))

    async def _handle(self, line: str) -> None:
        if not line:
            return
        parts = line.split(" ", 1)
        command = parts[0].upper()
        rest = parts[1].strip() if len(parts) > 1 else ""

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
            await self._record(
                "pop3_login_attempt",
                AlertSeverity.HIGH,
                {
                    "username": self._username[:256],
                    "password": rest[:256],
                    "service": "pop3",
                    "method": "USER/PASS",
                },
            )
            await asyncio.sleep(_AUTH_FAIL_DELAY)
            self._send("-ERR [AUTH] Authentication failed.")
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
            await asyncio.sleep(_AUTH_FAIL_DELAY)
            self._send("-ERR [AUTH] Authentication failed.")
            return

        if command == "AUTH":
            if not rest:
                self._send("+OK\r\nPLAIN\r\nLOGIN\r\n.")
                return
            self._send("-ERR [AUTH] Authentication failed.")
            await self._record(
                "pop3_auth_attempt",
                AlertSeverity.MEDIUM,
                {"mechanism": rest[:64], "service": "pop3"},
            )
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

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _POP3Protocol(name, hp_id), self._limiter),
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
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_pop3"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["POP3 honeypot is in-process — events are stored directly in the database."]


def apop_digest(challenge: str, password: str) -> str:
    """Reference APOP digest, for tests: md5(challenge + password)."""
    import hashlib

    return hashlib.md5((challenge + password).encode(), usedforsecurity=False).hexdigest()
