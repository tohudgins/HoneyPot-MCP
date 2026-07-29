"""SIP honeypot engine — udp/tcp 5060, VoIP scanning and toll fraud.

Port 5060 receives some of the most persistent automated traffic on the
internet, and for an unusually direct reason: a compromised PBX converts into
money. An attacker who registers an extension places international or
premium-rate calls billed to the victim, often within minutes of the scan, and
the bill lands before anyone notices. That makes SIP one of the few services
where the attacker's motive is immediate revenue rather than access.

The attack has three distinct phases, and they are worth separating because
they mean different things:

1. **Enumeration** — `OPTIONS` sweeps to find live SIP endpoints. SIPVicious
   (`svmap`) is the canonical tool and still identifies itself in the
   User-Agent as `friendly-scanner`, so it is worth calling out by name.
2. **Extension discovery** — `REGISTER` for sequential extensions (100, 101,
   1000…) to learn which exist. A real PBX answers differently for a valid
   extension with a bad password than for one that does not exist, and that
   difference is the whole enumeration primitive.
3. **Toll fraud** — `INVITE` to an international or premium-rate number. This
   is the payoff, and `_is_toll_fraud_target` recognises the destination
   prefixes that only appear in fraud: satellite ranges, known premium-rate
   country codes, and the test numbers scanners dial to confirm a working
   route before selling it on.

Digest authentication is answered with a real challenge so the attacker's tool
computes and sends a response. That response is captured — it is a crackable
MD5 digest over a known nonce, which is materially more useful than a bare
"someone tried to register".

Implemented over both UDP and TCP, because scanners use both and a service
present on only one is a tell. Not implemented: media (RTP), call setup beyond
the first response, or a real registrar.

Wire format: RFC 3261 (SIP), RFC 7616 (digest auth).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
from typing import Any, cast

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_PBX_NAME = "Asterisk PBX 18.10.0"
_REALM = "asterisk"
_MAX_DATAGRAM = 65_535

# Scanners that announce themselves. Naming the tool in the alert saves an
# analyst a lookup and distinguishes commodity sweeps from targeted probing.
_KNOWN_SCANNERS = re.compile(
    r"(friendly-scanner|sipvicious|sipcli|sundayddr|sip-scan|VaxSIPUserAgent|"
    r"sipsak|smap|iWar|Nmap NSE)",
    re.I,
)

# Destinations that essentially only appear in toll fraud. The satellite and
# premium ranges are expensive per minute, which is the entire point; the test
# prefixes are what scanners dial to prove a route works before selling it.
_TOLL_FRAUD_PREFIXES = (
    "00881",  # Global Mobile Satellite
    "00882",  # International Networks
    "00883",
    "+881",
    "+882",
    "+883",
    "00639",  # premium ranges commonly abused
    "0090",
    "00212",
    "00225",
    "00234",
    "00243",
    "00252",
    "00370",
    "00371",
    "00372",
    "00373",
    "00375",
    "00509",
    "00676",
    "00677",
    "00678",
    "0053",
    "100777",  # scanner "does this route work?" test numbers
    "9011",
)


def _header(message: str, name: str) -> str:
    """First value of a SIP header, case-insensitively."""
    pattern = re.compile(rf"^{re.escape(name)}\s*:\s*(.+)$", re.I | re.M)
    match = pattern.search(message)
    return match.group(1).strip() if match else ""


def parse_sip(message: str) -> dict[str, Any] | None:
    """Parse enough of a SIP request to classify it. None if not SIP."""
    lines = message.split("\r\n") if "\r\n" in message else message.split("\n")
    if not lines or not lines[0]:
        return None
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 3 or not parts[2].upper().startswith("SIP/"):
        return None
    method = parts[0].upper()
    if not method.isalpha():
        return None
    return {
        "method": method,
        "uri": parts[1],
        "via": _header(message, "Via"),
        "from": _header(message, "From"),
        "to": _header(message, "To"),
        "call_id": _header(message, "Call-ID"),
        "cseq": _header(message, "CSeq"),
        "user_agent": _header(message, "User-Agent"),
        "contact": _header(message, "Contact"),
        "authorization": _header(message, "Authorization"),
    }


def extract_extension(uri_or_header: str) -> str:
    """Pull the user part out of `sip:1001@host` or `"x" <sip:1001@host>`."""
    match = re.search(r"sip:([^@>\s;]+)", uri_or_header, re.I)
    if match:
        return match.group(1)
    return ""


def parse_digest(authorization: str) -> dict[str, str]:
    """Parse a `Digest` Authorization header into its fields."""
    if not authorization.lower().startswith("digest"):
        return {}
    fields: dict[str, str] = {}
    for key, quoted, bare in re.findall(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', authorization[6:]):
        fields[key.lower()] = quoted or bare
    return fields


def is_toll_fraud_target(uri: str) -> bool:
    """True when the dialled number looks like a fraud destination."""
    number = extract_extension(uri)
    normalised = re.sub(r"[^\d+]", "", number)
    if not normalised:
        return False
    if any(normalised.startswith(p) for p in _TOLL_FRAUD_PREFIXES):
        return True
    # A long international-looking string dialled from an unregistered peer is
    # not someone calling reception.
    return normalised.startswith("00") and len(normalised) >= 13


def classify(request: dict[str, Any]) -> tuple[str, AlertSeverity, dict[str, Any]]:
    """Map a parsed SIP request to an event type, severity and extra payload."""
    method = request["method"]
    user_agent = request.get("user_agent", "")
    scanner = _KNOWN_SCANNERS.search(user_agent)
    extra: dict[str, Any] = {}
    if scanner:
        extra["scanner_tool"] = scanner.group(0)

    if method == "OPTIONS":
        return (
            "sip_scan" if scanner else "sip_options_probe",
            AlertSeverity.MEDIUM if scanner else AlertSeverity.LOW,
            extra,
        )

    if method == "REGISTER":
        extension = extract_extension(request.get("to") or request.get("uri", ""))
        extra["extension"] = extension[:64]
        digest = parse_digest(request.get("authorization", ""))
        if digest:
            extra.update(
                {
                    "username": digest.get("username", "")[:128],
                    "digest_response": digest.get("response", "")[:64],
                    "nonce": digest.get("nonce", "")[:64],
                    "realm": digest.get("realm", "")[:64],
                    "service": "sip",
                }
            )
            return "sip_register_attempt", AlertSeverity.HIGH, extra
        return "sip_extension_probe", AlertSeverity.MEDIUM, extra

    if method == "INVITE":
        target = request.get("uri", "")
        extra["dialled"] = extract_extension(target)[:64]
        if is_toll_fraud_target(target):
            extra["note"] = (
                "call to a premium-rate or satellite destination from an "
                "unregistered peer — toll fraud"
            )
            return "sip_toll_fraud_attempt", AlertSeverity.CRITICAL, extra
        return "sip_invite", AlertSeverity.HIGH, extra

    if method in ("SUBSCRIBE", "NOTIFY", "PUBLISH", "MESSAGE", "REFER"):
        return "sip_request", AlertSeverity.LOW, extra

    return "sip_request", AlertSeverity.LOW, extra


def _response_line(status: int, reason: str) -> str:
    return f"SIP/2.0 {status} {reason}"


def build_response(request: dict[str, Any], status: int, reason: str, extra: str = "") -> str:
    """Echo the correlation headers a real UA requires, or it ignores us."""
    lines = [
        _response_line(status, reason),
        f"Via: {request.get('via', '')}",
        f"From: {request.get('from', '')}",
        f"To: {request.get('to', '')}",
        f"Call-ID: {request.get('call_id', '')}",
        f"CSeq: {request.get('cseq', '')}",
        f"Server: {_PBX_NAME}",
    ]
    if extra:
        lines.append(extra)
    lines.extend(["Content-Length: 0", "", ""])
    return "\r\n".join(lines)


def build_auth_challenge(request: dict[str, Any], status: int = 401) -> str:
    """401/407 with a fresh digest nonce.

    The nonce is random per challenge, as a real registrar's is, and it is
    recorded alongside the response the attacker computes — together they make
    the captured digest crackable offline.
    """
    nonce = secrets.token_hex(16)
    opaque = hashlib.md5(nonce.encode(), usedforsecurity=False).hexdigest()[:16]
    header = "WWW-Authenticate" if status == 401 else "Proxy-Authenticate"
    challenge = (
        f'{header}: Digest realm="{_REALM}", nonce="{nonce}", opaque="{opaque}", '
        f'algorithm=MD5, qop="auth"'
    )
    reason = "Unauthorized" if status == 401 else "Proxy Authentication Required"
    return build_response(request, status, reason, challenge)


class _SIPHandler:
    """Shared request handling for both transports."""

    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id

    async def handle(self, data: bytes, peer: tuple[str, int]) -> bytes | None:
        message = data.decode("utf-8", errors="replace")
        request = parse_sip(message)
        if request is None:
            await self._record(
                peer,
                "sip_invalid_probe",
                AlertSeverity.LOW,
                {"bytes": len(data), "head": message[:120]},
            )
            return None

        event_type, severity, extra = classify(request)
        await self._record(
            peer,
            event_type,
            severity,
            {
                "method": request["method"],
                "uri": request["uri"][:200],
                "user_agent": request.get("user_agent", "")[:200],
                "from": request.get("from", "")[:200],
                **extra,
            },
        )

        method = request["method"]
        if method == "OPTIONS":
            # A real PBX answers OPTIONS with 200 and an Allow list; silence
            # would just make the scanner move on without revealing itself.
            return build_response(
                request,
                200,
                "OK",
                "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO",
            ).encode()
        if method == "REGISTER":
            # Always challenge. The first REGISTER never carries credentials,
            # and the challenge is what makes the tool send them.
            return build_auth_challenge(request, 401).encode()
        if method == "INVITE":
            return build_auth_challenge(request, 407).encode()
        if method in ("ACK", "CANCEL"):
            return None
        return build_response(request, 200, "OK").encode()

    async def _record(
        self, peer: tuple[str, int], event_type: str, severity: AlertSeverity, payload: dict
    ) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=peer[0],
                source_port=peer[1],
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )


class _SIPDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: _SIPHandler) -> None:
        self._handler = handler
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Cast, never isinstance — `_SelectorDatagramTransport` is not a
        # `DatagramTransport` subclass on Python 3.11, and the resulting
        # AssertionError is swallowed by asyncio, leaving the engine mute.
        self._transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > _MAX_DATAGRAM:
            return
        asyncio.create_task(self._respond(data, addr))

    async def _respond(self, data: bytes, addr: tuple[str, int]) -> None:
        reply = await self._handler.handle(data, addr)
        if reply and self._transport is not None:
            try:
                self._transport.sendto(reply, addr)
            except Exception as e:  # pragma: no cover - transport teardown race
                log.debug("SIP UDP reply failed for %s: %s", addr, e)


class _SIPStreamProtocol(asyncio.Protocol):
    def __init__(self, handler: _SIPHandler) -> None:
        self._handler = handler
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_DATAGRAM:
            self._buf = b""
            return
        # SIP over TCP frames on the blank line ending the headers; we have no
        # bodies to read, so that boundary is the whole message.
        while b"\r\n\r\n" in self._buf:
            message, self._buf = self._buf.split(b"\r\n\r\n", 1)
            asyncio.create_task(self._respond(message + b"\r\n\r\n"))

    async def _respond(self, data: bytes) -> None:
        reply = await self._handler.handle(data, self._peer)
        if reply and self._transport is not None and not self._transport.is_closing():
            self._transport.write(reply)

    def connection_lost(self, exc: Exception | None) -> None:
        self._buf = b""


class SIPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, tuple[asyncio.AbstractServer, asyncio.DatagramTransport]] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        handler = _SIPHandler(name, hp_id)
        loop = asyncio.get_event_loop()
        # Both transports: scanners use each, and a SIP service reachable on
        # only one of them is itself a fingerprint.
        udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _SIPDatagramProtocol(handler), local_addr=("0.0.0.0", port)
        )
        tcp_server = await loop.create_server(
            limited_factory(lambda: _SIPStreamProtocol(handler), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"sip-{secrets.token_hex(8)}"
        self._servers[cid] = (tcp_server, udp_transport)
        log.info("SIP honeypot '%s' listening on tcp+udp/%d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        entry = self._servers.pop(container_id, None)
        if entry:
            tcp_server, udp_transport = entry
            tcp_server.close()
            await tcp_server.wait_closed()
            udp_transport.close()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_sip"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["SIP honeypot is in-process — events are stored directly in the database."]
