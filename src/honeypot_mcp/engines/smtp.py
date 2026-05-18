"""SMTP honeypot engine — Postfix-flavoured asyncio SMTP server.

Fidelity notes
--------------
A scanner-grade honeypot needs more than `250 OK`. Real Postfix advertises a
specific extension set in response to `EHLO`; `HELO` returns a single-line
greeting (no extensions). Mismatching either is a textbook fingerprint.

This implementation:

* Returns a Postfix-realistic multi-line `EHLO` response (PIPELINING, SIZE,
  VRFY, ETRN, STARTTLS, AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN,
  SMTPUTF8).
* Returns a single-line `HELO` response — the asymmetry is itself realistic.
* Announces STARTTLS but closes the connection on the next bytes (we don't
  ship a TLS handler; announcing then failing is more realistic than not
  announcing).
* Accepts the `DATA` body until a bare `.` line; logs the first 4KB.
* Returns `252` for `VRFY` — Postfix's default "neither confirm nor deny".

It is still a low-fidelity SMTP — no real mail queue, no TLS — but
significantly harder to fingerprint at the first-probe level than the
previous `250 OK` skeleton.
"""

from __future__ import annotations

import asyncio
import logging
import random
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


# Hostname pool used when a honeypot is deployed without an explicit
# `smtp_hostname` in its config. A scanner that hits two SMTP honeypots in
# the same project sees different hostnames — defeats trivial correlation.
_SMTP_HOSTNAME_POOL = [
    "mail.corp.local",
    "smtp.corp.local",
    "mx1.corp.local",
    "mta.corp.local",
    "mailserver.internal",
]


def _pick_hostname() -> str:
    return random.choice(_SMTP_HOSTNAME_POOL)


# Postfix-style EHLO extension list, in the order a real Postfix would emit.
# All lines except the last are `250-`; the terminator line is `250 `.
_EHLO_EXTENSIONS = (
    "PIPELINING",
    "SIZE 10240000",
    "VRFY",
    "ETRN",
    "STARTTLS",
    "AUTH PLAIN LOGIN",
    "AUTH=PLAIN LOGIN",  # legacy form some clients still test for
    "ENHANCEDSTATUSCODES",
    "8BITMIME",
    "DSN",
    "SMTPUTF8",
)


def _build_ehlo_response(hostname: str) -> bytes:
    """Build the multi-line `EHLO` response with Postfix-style continuation."""
    lines = [f"250-{hostname} Hello"]
    for ext in _EHLO_EXTENSIONS[:-1]:
        lines.append(f"250-{ext}")
    lines.append(f"250 {_EHLO_EXTENSIONS[-1]}")
    return ("\r\n".join(lines) + "\r\n").encode()


class _SMTPProtocol(asyncio.Protocol):
    """Postfix-flavoured SMTP banner-and-capture protocol."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None, hostname: str) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._hostname = hostname
        self._transport: asyncio.Transport | None = None
        self._buf = b""
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._in_data = False
        self._data_lines: list[str] = []
        self._data_size = 0
        self._tls_active = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # asyncio.Protocol's contract narrows this — it's always a stream
        # Transport (writable) in practice. Cast for mypy correctness.
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        transport.write(f"220 {self._hostname} ESMTP Postfix\r\n".encode())
        asyncio.create_task(self._record_event("smtp_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            decoded = line.decode("utf-8", errors="replace")
            if self._in_data:
                self._handle_data_line(decoded)
            else:
                self._dispatch(decoded.strip())

    def _dispatch(self, line: str) -> None:
        if not line:
            return
        upper = line.upper()
        t = self._transport
        if t is None:
            return

        if upper.startswith("EHLO"):
            t.write(_build_ehlo_response(self._hostname))
        elif upper.startswith("HELO"):
            # Legacy single-line greeting — Postfix-correct, no extensions.
            t.write(f"250 {self._hostname}\r\n".encode())
        elif upper == "STARTTLS":
            if self._tls_active:
                t.write(b"503 5.5.1 TLS already active\r\n")
            else:
                t.write(b"220 2.0.0 Ready to start TLS\r\n")
                # Pause reading IMMEDIATELY so the TLS ClientHello bytes
                # can't reach our plaintext data_received() between this
                # 220 reply and the moment loop.start_tls() takes over
                # the read path. Without this, a fast client's first TLS
                # record arrives at _dispatch() as garbage, gets answered
                # with `502 Command not recognised`, and the handshake
                # poisons the wire — post-TLS EHLO then fails with
                # WRONG_VERSION_NUMBER on the client side.
                t.pause_reading()
                asyncio.create_task(self._upgrade_to_tls())
        elif upper.startswith("AUTH"):
            t.write(b"334 VXNlcm5hbWU6\r\n")  # base64("Username:")
            asyncio.create_task(
                self._record_event("smtp_auth_attempt", AlertSeverity.HIGH, {"command": line})
            )
        elif upper.startswith("MAIL FROM"):
            t.write(b"250 2.1.0 Ok\r\n")
            asyncio.create_task(
                self._record_event("smtp_mail_from", AlertSeverity.MEDIUM, {"command": line})
            )
        elif upper.startswith("RCPT TO"):
            t.write(b"250 2.1.5 Ok\r\n")
            asyncio.create_task(
                self._record_event("smtp_rcpt_to", AlertSeverity.MEDIUM, {"command": line})
            )
        elif upper == "DATA":
            t.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            self._in_data = True
            self._data_lines = []
            self._data_size = 0
        elif upper.startswith("VRFY"):
            t.write(b"252 2.5.2 Send some mail, I'll try my best\r\n")
            asyncio.create_task(
                self._record_event("smtp_vrfy", AlertSeverity.LOW, {"command": line})
            )
        elif upper.startswith("ETRN"):
            t.write(b"500 5.5.2 Need account name\r\n")
        elif upper in ("RSET", "NOOP"):
            t.write(b"250 2.0.0 Ok\r\n")
        elif upper == "QUIT":
            t.write(b"221 2.0.0 Bye\r\n")
            t.close()
        else:
            t.write(b"502 5.5.2 Error: command not recognized\r\n")

    def _handle_data_line(self, line: str) -> None:
        """Collect message body until a bare `.` ends DATA."""
        if line == ".":
            self._in_data = False
            queue_id = secrets.token_hex(5).upper()
            t = self._transport
            if t is not None:
                t.write(f"250 2.0.0 Ok: queued as {queue_id}\r\n".encode())
            # First 4 KB only — keeps payload size bounded even on spam blast.
            body_preview = "\n".join(self._data_lines)[:4096]
            asyncio.create_task(
                self._record_event(
                    "smtp_message_received",
                    AlertSeverity.HIGH,
                    {
                        "queue_id": queue_id,
                        "size_bytes": self._data_size,
                        "body_preview": body_preview,
                    },
                )
            )
            self._data_lines = []
            self._data_size = 0
            return
        # SMTP dot-stuffing: a line starting with `..` represents a literal `.`
        if line.startswith(".."):
            line = line[1:]
        self._data_size += len(line) + 2  # +CRLF
        if len(self._data_lines) < 200:
            self._data_lines.append(line)

    async def _upgrade_to_tls(self) -> None:
        """Replace the plaintext transport with a TLS-wrapped one.

        After this completes, the client must re-issue `EHLO` per RFC 3207
        — we clear protocol state so any pre-TLS context can't leak across
        the TLS boundary. Failure closes the connection; that looks like a
        broken cert config to the attacker, which is a plausible real-server
        failure mode."""
        from honeypot_mcp.engines.tls import build_server_ssl_context

        if self._transport is None:
            return
        try:
            ssl_ctx = build_server_ssl_context(self._name, common_name=self._hostname)
            loop = asyncio.get_event_loop()
            new_transport = await loop.start_tls(
                self._transport,
                self,
                ssl_ctx,
                server_side=True,
                ssl_handshake_timeout=5.0,
            )
            # start_tls returns BaseTransport | None at the type level.
            # In practice on success it's always a writable Transport.
            assert new_transport is not None
            self._transport = new_transport  # type: ignore[assignment]
            self._tls_active = True
            # Per RFC 3207: discard everything before TLS and require fresh EHLO.
            self._buf = b""
            self._in_data = False
            self._data_lines = []
            self._data_size = 0
            log.info("STARTTLS upgrade succeeded for %s", self._peer[0])
            await self._record_event(
                "smtp_starttls_handshake",
                AlertSeverity.LOW,
                {"cipher": new_transport.get_extra_info("cipher")},
            )
        except Exception as e:
            log.warning("STARTTLS handshake failed for %s: %s", self._peer[0], e)
            if self._transport is not None:
                # Reading was paused before the handshake started — if we
                # don't close, we'd leak a paused transport. Closing is
                # also a believable failure mode (broken cert config).
                self._transport.close()

    async def _record_event(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
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
        pass


class SMTPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, tuple[asyncio.AbstractServer, str]] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        # Pick + persist a hostname on first start so the same honeypot keeps
        # its identity across restarts. Same persona-pinning pattern as SSH/HTTP.
        if "smtp_hostname" not in config:
            config["smtp_hostname"] = _pick_hostname()
            async with get_session() as session:
                from sqlalchemy import update

                from honeypot_mcp.storage.models import Honeypot

                await session.execute(
                    update(Honeypot).where(Honeypot.name == name).values(config=config)
                )

        hostname = config.get("smtp_hostname") or _pick_hostname()
        # User escape hatch: explicit fake_banner_hostname overrides persona.
        hostname = config.get("fake_banner_hostname", hostname)

        # Look up DB id
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _SMTPProtocol(name, hp_id, hostname),
            host="0.0.0.0",
            port=port,
        )
        container_id = f"smtp-{secrets.token_hex(8)}"
        self._servers[container_id] = (server, name)
        log.info("SMTP honeypot '%s' listening on port %d as %s", name, port, hostname)
        return container_id

    async def stop(self, container_id: str, remove: bool = False) -> None:
        entry = self._servers.pop(container_id, None)
        if entry:
            server, _ = entry
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_smtp"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["SMTP honeypot is in-process — events are stored directly in the database."]
