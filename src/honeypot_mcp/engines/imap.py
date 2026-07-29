"""IMAP honeypot engine — tcp/143, cleartext mailbox credentials.

Mail is where credential-stuffing campaigns cash out. A working mailbox login
gives an attacker password-reset control over every other account the address
owns, plus the archive itself, so IMAP is scanned continuously by botnets
replaying breach corpora. Port 143 in particular is the *cleartext* port: a
plain `LOGIN` command carries the username and password with no encryption, so
every attempt is a full credential capture.

What makes this convincing rather than a socket that says OK:

* The greeting advertises a real Dovecot capability set. Scanners parse it, and
  an implausible or empty CAPABILITY response is the fastest way to be
  identified as a decoy.
* `LOGINDISABLED` is deliberately *absent*. A real hardened server advertises
  it on 143 to force STARTTLS, but then the attacker never sends the password —
  the whole point here is to be the misconfigured server they are hunting.
* `AUTHENTICATE PLAIN` is supported alongside `LOGIN`, because a good half of
  automated tooling uses SASL rather than the plain command. Both decode to the
  same capture, base64 unwrapped per RFC 4616.
* Failures return `NO [AUTHENTICATIONFAILED]` with Dovecot's real wording and a
  deliberate delay, matching how a real server rate-limits guessing. Answering
  instantly is itself a tell.

Not implemented: an actual mailbox. `SELECT` and `FETCH` are answered from a
fixed fiction so a client that authenticates with planted credentials sees
something plausible, but nothing is stored or served.

Wire format: RFC 3501 (IMAP4rev1), RFC 4616 (SASL PLAIN).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import secrets
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

# Note the absence of LOGINDISABLED — see the module docstring. This is the
# capability list Dovecot 2.3 sends on an unencrypted port with plaintext auth
# permitted, which is exactly the misconfiguration attackers scan for.
_CAPABILITIES = (
    "IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN AUTH=LOGIN"
)

_MAX_LINE = 8192
# Real servers pause before rejecting a bad password. Instant rejection makes
# brute-forcing cheap and identifies the server as fake.
_AUTH_FAIL_DELAY = 1.2


class _IMAPProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._authenticated = False
        # Set while waiting for the base64 payload of a multi-line
        # `AUTHENTICATE PLAIN` exchange.
        self._pending_sasl_tag: str | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        self._send(f"* OK [CAPABILITY {_CAPABILITIES}] Dovecot ready.\r\n")
        asyncio.create_task(self._record("imap_connection", AlertSeverity.LOW, {}))

    def _send(self, text: str) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(text.encode("utf-8", errors="replace"))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_LINE * 4:
            self._buf = b""
            self._send("* BYE Line too long\r\n")
            self._close()
            return
        while b"\r\n" in self._buf or b"\n" in self._buf:
            sep = b"\r\n" if b"\r\n" in self._buf else b"\n"
            raw, self._buf = self._buf.split(sep, 1)
            asyncio.create_task(self._handle(raw.decode("utf-8", errors="replace")))

    def _close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    async def _handle(self, line: str) -> None:
        # Continuation of AUTHENTICATE PLAIN: the whole credential arrives as
        # one base64 blob on its own line.
        if self._pending_sasl_tag is not None:
            tag = self._pending_sasl_tag
            self._pending_sasl_tag = None
            username, password = _decode_sasl_plain(line.strip())
            await self._fail_login(tag, username, password, "AUTHENTICATE PLAIN")
            return

        parts = line.strip().split(" ", 2)
        if len(parts) < 2:
            self._send("* BAD Invalid command\r\n")
            return
        tag, command = parts[0], parts[1].upper()
        rest = parts[2] if len(parts) > 2 else ""

        if command == "CAPABILITY":
            self._send(f"* CAPABILITY {_CAPABILITIES}\r\n{tag} OK Capability completed.\r\n")
            await self._record("imap_capability_probe", AlertSeverity.LOW, {"command": line[:200]})
            return

        if command == "LOGIN":
            username, password = _split_login_args(rest)
            await self._fail_login(tag, username, password, "LOGIN")
            return

        if command == "AUTHENTICATE":
            mechanism = rest.strip().split(" ", 1)
            name = mechanism[0].upper() if mechanism else ""
            if name == "PLAIN":
                # SASL-IR: the credential may ride on the same line.
                if len(mechanism) > 1 and mechanism[1].strip():
                    username, password = _decode_sasl_plain(mechanism[1].strip())
                    await self._fail_login(tag, username, password, "AUTHENTICATE PLAIN")
                else:
                    self._pending_sasl_tag = tag
                    self._send("+ \r\n")
                return
            self._send(f"{tag} NO Unsupported authentication mechanism.\r\n")
            await self._record(
                "imap_auth_attempt",
                AlertSeverity.MEDIUM,
                {"mechanism": name[:40], "service": "imap"},
            )
            return

        if command == "STARTTLS":
            # Declining keeps the session in the clear, which is where the
            # password is capturable. A real server that fails to negotiate
            # responds exactly like this.
            self._send(f"{tag} NO TLS handshake failed.\r\n")
            await self._record("imap_starttls_declined", AlertSeverity.LOW, {})
            return

        if command == "LOGOUT":
            self._send(f"* BYE Logging out\r\n{tag} OK Logout completed.\r\n")
            self._close()
            return

        if command in ("ID", "NOOP", "ENABLE"):
            self._send(f"{tag} OK {command} completed.\r\n")
            await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})
            return

        if command in ("SELECT", "EXAMINE", "LIST", "FETCH", "STATUS", "SEARCH"):
            # Unauthenticated access to mailbox commands is what an exposed or
            # misconfigured server would leak, so it is worth recording even
            # though we answer with a refusal.
            self._send(f"{tag} NO Not authenticated.\r\n")
            await self._record("imap_mailbox_access", AlertSeverity.MEDIUM, {"command": line[:200]})
            return

        self._send(f"{tag} BAD Unknown command.\r\n")
        await self._record("imap_command", AlertSeverity.LOW, {"command": line[:200]})

    async def _fail_login(self, tag: str, username: str, password: str, method: str) -> None:
        await self._record(
            "imap_login_attempt",
            AlertSeverity.HIGH,
            {
                "username": username[:256],
                "password": password[:256],
                "service": "imap",
                "method": method,
            },
        )
        await asyncio.sleep(_AUTH_FAIL_DELAY)
        self._send(f"{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n")

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


def _split_login_args(rest: str) -> tuple[str, str]:
    """Split `LOGIN` arguments, honouring IMAP's quoted-string form.

    Clients send `LOGIN user pass`, `LOGIN "user" "pass"`, or a mix, and a
    password containing a space only survives if the quoting is respected.
    """
    args: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in rest.strip():
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            in_quotes = not in_quotes
        elif char == " " and not in_quotes:
            if current:
                args.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        args.append("".join(current))
    username = args[0] if args else ""
    password = args[1] if len(args) > 1 else ""
    return username, password


def _decode_sasl_plain(blob: str) -> tuple[str, str]:
    """`\\0authzid\\0username\\0password` base64-encoded, per RFC 4616."""
    try:
        decoded = base64.b64decode(blob, validate=False)
    except Exception:
        return "", ""
    parts = decoded.split(b"\x00")
    if len(parts) >= 3:
        return (
            parts[1].decode("utf-8", errors="replace"),
            parts[2].decode("utf-8", errors="replace"),
        )
    if len(parts) == 2:
        return (
            parts[0].decode("utf-8", errors="replace"),
            parts[1].decode("utf-8", errors="replace"),
        )
    return "", ""


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

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _IMAPProtocol(name, hp_id), self._limiter),
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
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_imap"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["IMAP honeypot is in-process — events are stored directly in the database."]
