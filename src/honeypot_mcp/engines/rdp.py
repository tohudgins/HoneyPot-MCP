"""RDP honeypot engine — captures the X.224 Connection Request handshake.

RDP brute-force traffic is one of the largest single categories of internet
attack volume (driving most ransomware initial-access incidents). A
banner-only honeypot catches it cheaply: we parse the initial X.224 TPDU,
extract the leaked `Cookie: mstshash=user[@DOMAIN]` field that almost every
RDP client and brute-force tool sends in the clear, and return a believable
Connection Confirm with a negotiation failure. That's enough to log the
attacker's claimed username, source, and tool fingerprint (the negotiation
request flags reveal whether they wanted RDP / SSL / CredSSP, which itself
identifies the tool family).

Wire format references:
* RFC 905 — X.224 Connection-Oriented Transport Protocol
* MS-RDPBCGR §2.2.1.1 — X.224 Connection Request PDU
* MS-RDPBCGR §2.2.1.2 — X.224 Connection Confirm PDU

We are NOT implementing the rest of the protocol stack (no MCS, no TLS, no
CredSSP). After the Connection Confirm we send a negotiation-failure
response and close the connection. That looks like "server rejected your
proposed security layer" to the attacker — believable failure mode for a
hardened server. Documented in KNOWN_LIMITATIONS.md as banner-only fidelity.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


# RDP negotiation request types (MS-RDPBCGR §2.2.1.1.1).
_RDP_NEG_REQ = 0x01
# Negotiation response types (§2.2.1.2.1).
_RDP_NEG_RSP = 0x02  # success
_RDP_NEG_FAILURE = 0x03  # failure

# Failure codes (§2.2.1.2.2).
_FAILURE_SSL_REQUIRED_BY_SERVER = 0x00000001
_FAILURE_SSL_NOT_ALLOWED_BY_SERVER = 0x00000002
_FAILURE_SSL_CERT_NOT_ON_SERVER = 0x00000003
_FAILURE_INCONSISTENT_FLAGS = 0x00000004
_FAILURE_HYBRID_REQUIRED_BY_SERVER = 0x00000005


def _parse_x224_cr(data: bytes) -> dict[str, Any]:
    """Parse a TPKT + X.224 Connection Request PDU.

    Returns the fields we care about for logging. Robust to malformed input
    — anything that doesn't parse cleanly returns `{}` rather than raising,
    so the engine never crashes on attacker-crafted traffic.

    Wire layout:
        TPKT header   : 4 bytes — version(1), reserved(1), length-be(2)
        X.224 header  : 7 bytes — len(1), code(1)=0xE0 (CR), dst-ref(2),
                                  src-ref(2), class(1)
        Variable data : RDP-specific. Often starts with the routing token or
                        a `Cookie: mstshash=...` line ending in 0x0D 0x0A,
                        followed by an RDP Negotiation Request (8 bytes).
    """
    out: dict[str, Any] = {}
    if len(data) < 11:
        return out
    tpkt_version = data[0]
    if tpkt_version != 3:
        return out

    out["tpkt_length"] = int.from_bytes(data[2:4], "big")
    x224_code = data[5]
    if x224_code & 0xF0 != 0xE0:
        return out
    out["x224_code"] = "ConnectionRequest"

    var = data[11:]
    if not var:
        return out

    # Cookie / routing-token line ends with CR-LF. Find it without raising.
    cr_lf = var.find(b"\r\n")
    if cr_lf != -1:
        line = var[:cr_lf]
        out["routing_line"] = line.decode("utf-8", errors="replace")
        # Common form: `Cookie: mstshash=username` (sometimes with @DOMAIN).
        if line.startswith(b"Cookie: mstshash="):
            cookie_value = line[len(b"Cookie: mstshash=") :].decode("utf-8", errors="replace")
            out["mstshash"] = cookie_value
            # Split user@domain if present
            if "@" in cookie_value:
                user, _, domain = cookie_value.partition("@")
                out["username"] = user
                out["domain"] = domain
            else:
                out["username"] = cookie_value
        rdp_neg = var[cr_lf + 2 :]
    else:
        rdp_neg = var

    # RDP Negotiation Request: type(1)=0x01, flags(1), length(2 LE)=8,
    # requestedProtocols(4 LE).
    if len(rdp_neg) >= 8 and rdp_neg[0] == _RDP_NEG_REQ:
        flags = rdp_neg[1]
        requested = int.from_bytes(rdp_neg[4:8], "little")
        out["neg_flags"] = flags
        out["requested_protocols"] = requested
        # Decode the protocol bitmask into readable names (MS-RDPBCGR §2.2.1.1.1).
        names = []
        if requested == 0:
            names.append("STANDARD_RDP")
        if requested & 0x00000001:
            names.append("SSL")
        if requested & 0x00000002:
            names.append("HYBRID_CredSSP")
        if requested & 0x00000004:
            names.append("RDSTLS")
        if requested & 0x00000008:
            names.append("HYBRID_EX")
        out["requested_protocols_names"] = names

    return out


def _build_neg_failure_response(failure_code: int = _FAILURE_SSL_REQUIRED_BY_SERVER) -> bytes:
    """Build a TPKT + X.224 Connection Confirm with an RDP negotiation failure.

    Common real-world response for a server that requires NLA/SSL but the
    client requested only Standard RDP. Looks like a hardened configuration
    rather than a broken honeypot.

    Wire layout:
        TPKT  : version(3), reserved(0), length-be(2)=19
        X.224 : len(1)=14, code(1)=0xD0 (CC), dst-ref(2), src-ref(2), class(1)
        NegFailure: type(1)=0x03, flags(1)=0, length(2 LE)=8, failureCode(4 LE)
    """
    x224 = (
        bytes([14, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
        + bytes([_RDP_NEG_FAILURE, 0x00])
        + (8).to_bytes(2, "little")
        + failure_code.to_bytes(4, "little")
    )
    tpkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big")
    return tpkt + x224


class _RDPProtocol(asyncio.Protocol):
    """Captures the X.224 Connection Request and responds with a believable
    negotiation failure. We log severity HIGH because RDP probes are almost
    always brute-force or recon tools — there's no legitimate first-probe
    traffic on RDP from an unknown source IP."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._handled = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("rdp_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        # We only care about the first packet (the X.224 CR). Subsequent
        # bytes are ignored — we'll close the connection shortly anyway.
        if self._handled or self._transport is None:
            return
        self._handled = True

        parsed = _parse_x224_cr(data)
        # HIGH severity if we got an actual handshake; LOW if it's just port-
        # scan garbage that didn't parse.
        sev = AlertSeverity.HIGH if "x224_code" in parsed else AlertSeverity.LOW
        et = "rdp_handshake" if "x224_code" in parsed else "rdp_invalid_probe"
        asyncio.create_task(self._record(et, sev, {**parsed, "raw_bytes": len(data)}))

        # Respond with negotiation failure — believable "server requires NLA"
        # response. Close shortly after so the attacker tool moves on.
        self._transport.write(_build_neg_failure_response())
        self._transport.close()

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


class RDPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _RDPProtocol(name, hp_id),
            host="0.0.0.0",
            port=port,
        )
        cid = f"rdp-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("RDP honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_rdp"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["RDP honeypot is in-process — events are stored directly in the database."]
