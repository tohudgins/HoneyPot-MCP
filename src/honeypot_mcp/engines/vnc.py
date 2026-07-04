"""VNC honeypot engine — RFB 003.008 banner + VNC Auth handshake.

VNC is one of the larger categories of public-internet brute-force traffic
alongside RDP — exposed RealVNC / TightVNC / UltraVNC servers are common
targets and the protocol leaks an attacker fingerprint in the very first
exchange (the protocol-version string the client advertises identifies
the client family: TightVNC, RealVNC, vncviewer, etc.).

This engine implements just enough of the protocol to:

* Advertise `RFB 003.008` (the version that matches the install base of
  current OSS / commercial VNC servers).
* Negotiate one security type (VNC Auth, type 2).
* Send a 16-byte authentication challenge.
* Capture the client's 16-byte DES-encrypted response — that's the actual
  brute-force payload, and it's logged for offline analysis. Real RealVNC
  password storage uses the same DES challenge/response so the captured
  bytes are equivalent to a hash-cracking target.
* Reply "Authentication failed" with a short reason string and close.

We are NOT implementing post-auth framebuffer encoding, screen sharing, or
input handling. The point is to catch the brute-force population — RFB
3.8 protocol-version exchange + VNC Auth flow covers that.

Wire format reference: RFC 6143 (The Remote Framebuffer Protocol).
"""

from __future__ import annotations

import asyncio
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

# RFB protocol version banner. 12 bytes including trailing newline.
# Matches the version advertised by current RealVNC / TightVNC / TigerVNC.
_RFB_VERSION = b"RFB 003.008\n"

# Security type byte for VNC Auth (RFC 6143 §7.1.2 / §7.2.2).
_SECURITY_TYPE_VNC_AUTH = 2

# Server-side state machine.
_STATE_AWAIT_VERSION = 0
_STATE_AWAIT_SECURITY_SELECTION = 1
_STATE_AWAIT_AUTH_RESPONSE = 2


class _VNCProtocol(asyncio.Protocol):
    """RFB 003.008 banner + VNC Auth handshake capture."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._state = _STATE_AWAIT_VERSION
        self._challenge = secrets.token_bytes(16)
        self._client_version: str | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        # Send the server's protocol-version greeting immediately. Most
        # clients respond within one RTT.
        transport.write(_RFB_VERSION)
        asyncio.create_task(self._record("vnc_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        # Each state consumes a fixed number of bytes — drain greedily so
        # we don't deadlock on a client that pipelines its writes.
        progressed = True
        while progressed:
            progressed = self._advance()

    def _advance(self) -> bool:
        """Try to consume one state's worth of bytes. Return True if we
        consumed any (caller loops); False if we need more data."""
        t = self._transport
        if t is None:
            return False

        if self._state == _STATE_AWAIT_VERSION:
            # Client's protocol version is also 12 bytes ending in `\n`.
            if len(self._buf) < 12:
                return False
            version_line = self._buf[:12]
            self._buf = self._buf[12:]
            self._client_version = version_line.decode("utf-8", errors="replace").rstrip()
            # Send security types list: 1 byte (count) + 1 byte per type.
            t.write(bytes([1, _SECURITY_TYPE_VNC_AUTH]))
            self._state = _STATE_AWAIT_SECURITY_SELECTION
            asyncio.create_task(
                self._record(
                    "vnc_handshake",
                    AlertSeverity.LOW,
                    {"client_version": self._client_version},
                )
            )
            return True

        if self._state == _STATE_AWAIT_SECURITY_SELECTION:
            if len(self._buf) < 1:
                return False
            selected = self._buf[0]
            self._buf = self._buf[1:]
            # Whatever the client picked, we send the VNC Auth challenge.
            # A real server would reject mismatching selections, but giving
            # the attacker the challenge maximises captured brute-force
            # data without changing the failure outcome.
            t.write(self._challenge)
            self._state = _STATE_AWAIT_AUTH_RESPONSE
            asyncio.create_task(
                self._record(
                    "vnc_security_selected",
                    AlertSeverity.LOW,
                    {"selected_type": selected},
                )
            )
            return True

        if self._state == _STATE_AWAIT_AUTH_RESPONSE:
            if len(self._buf) < 16:
                return False
            response = self._buf[:16]
            self._buf = self._buf[16:]
            # Build SecurityResult: 4 bytes status (1 = fail) + length-
            # prefixed reason string. RFB 3.8 includes the reason; 3.3
            # does not.
            reason = b"Authentication failure"
            packet = (1).to_bytes(4, "big") + len(reason).to_bytes(4, "big") + reason
            t.write(packet)
            asyncio.create_task(
                self._record(
                    "vnc_auth_attempt",
                    AlertSeverity.MEDIUM,
                    {
                        "client_version": self._client_version,
                        "challenge_hex": self._challenge.hex(),
                        "response_hex": response.hex(),
                    },
                )
            )
            t.close()
            return False

        return False

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
        pass


class VNCEngine(HoneypotEngine):
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
            limited_factory(lambda: _VNCProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"vnc-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("VNC honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_vnc"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["VNC honeypot is in-process — events are stored directly in the database."]
