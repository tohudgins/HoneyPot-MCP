"""SNMP honeypot engine — udp/161, cleartext community strings.

SNMP v1 and v2c authenticate with a community string sent in the clear on every
request, and an enormous number of internet-facing devices still run with the
factory defaults `public` and `private`. That makes port 161 both a constant
scan target and a genuinely high-value capture: the community string an
attacker tries tells you which vendor's default list they are working from, and
a `private` (write) attempt is an attempt to reconfigure the device, not just
read it.

What this catches:

* **Community-string brute force** — each attempt is recorded with the string
  itself, so `honeytoken_generate_credentials` values planted as fake community
  strings cross-reference here like any other service.
* **Default-credential success** — `public` / `private` are answered, because a
  scanner that gets nothing back moves on and you learn only that it knocked.
* **`GetBulkRequest` amplification** — SNMP is a reflection vector (a small
  GetBulk yields a large multi-varbind response), and this is how a reflector
  is measured.
* **Write attempts (`SetRequest`)** — on a real device this is configuration
  change or firmware tampering.

Responses carry a believable `sysDescr` so the sensor looks like a specific
piece of network kit rather than an empty socket.

**It never amplifies.** GetBulk is recorded and answered minimally rather than
with the large response a real agent would send, because SNMP source addresses
are trivially spoofed and a helpful reply would make this honeypot a
participant in someone else's DDoS. Same reasoning as the memcached engine.

Wire format: RFC 1157 (v1) / RFC 3416 (v2c), ASN.1 BER. Only the subset needed
to parse a request and build a response is implemented — there is no MIB tree.
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

# BER tags.
_SEQUENCE = 0x30
_INTEGER = 0x02
_OCTET_STRING = 0x04
_NULL = 0x05
_OID = 0x06

# SNMP PDU types (context-specific constructed).
_GET_REQUEST = 0xA0
_GET_NEXT_REQUEST = 0xA1
_GET_RESPONSE = 0xA2
_SET_REQUEST = 0xA3
_GET_BULK_REQUEST = 0xA5

_PDU_NAMES = {
    _GET_REQUEST: "GetRequest",
    _GET_NEXT_REQUEST: "GetNextRequest",
    _SET_REQUEST: "SetRequest",
    _GET_BULK_REQUEST: "GetBulkRequest",
}

_VERSION_NAMES = {0: "v1", 1: "v2c", 3: "v3"}

# Community strings that a real device would still be running with. Answering
# these keeps the scanner engaged; everything else gets the silence a wrong
# community produces on a real agent.
_ACCEPTED_COMMUNITIES = frozenset({"public", "private"})

# The persona this agent presents. A Cisco IOS string is the single most common
# thing behind an exposed 161.
_SYS_DESCR = (
    "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, "
    "RELEASE SOFTWARE (fc3)"
)
_SYS_OBJECT_ID = "1.3.6.1.4.1.9.1.2494"
_SYS_NAME = "sw-core-01"
_SYS_LOCATION = "DC1 / Rack 14"
_SYS_CONTACT = "netops@example.com"
_SYS_UPTIME_TICKS = 284_913_400  # ~33 days, in hundredths of a second

_SCALARS: dict[str, tuple[int, Any]] = {
    "1.3.6.1.2.1.1.1.0": (_OCTET_STRING, _SYS_DESCR),
    "1.3.6.1.2.1.1.2.0": (_OID, _SYS_OBJECT_ID),
    "1.3.6.1.2.1.1.3.0": (0x43, _SYS_UPTIME_TICKS),  # TimeTicks
    "1.3.6.1.2.1.1.4.0": (_OCTET_STRING, _SYS_CONTACT),
    "1.3.6.1.2.1.1.5.0": (_OCTET_STRING, _SYS_NAME),
    "1.3.6.1.2.1.1.6.0": (_OCTET_STRING, _SYS_LOCATION),
    "1.3.6.1.2.1.1.7.0": (_INTEGER, 78),
}

_MAX_DATAGRAM = 8192


# ── Minimal BER ─────────────────────────────────────────────────────────────


def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_int(value: int, tag: int = _INTEGER) -> bytes:
    if value == 0:
        return _tlv(tag, b"\x00")
    length = (value.bit_length() + 8) // 8
    return _tlv(tag, value.to_bytes(length, "big", signed=True))


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        if part < 0x80:
            out.append(part)
            continue
        chunk = bytearray()
        chunk.insert(0, part & 0x7F)
        part >>= 7
        while part:
            chunk.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        out.extend(chunk)
    return _tlv(_OID, bytes(out))


def _decode_length(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise ValueError("bad BER length")
    return int.from_bytes(data[pos : pos + count], "big"), pos + count


def _decode_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    if pos >= len(data):
        raise ValueError("truncated BER")
    tag = data[pos]
    length, pos = _decode_length(data, pos + 1)
    if pos + length > len(data):
        raise ValueError("BER length exceeds datagram")
    return tag, data[pos : pos + length], pos + length


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def parse_snmp(datagram: bytes) -> dict[str, Any] | None:
    """Parse an SNMP v1/v2c message. Returns None if it is not SNMP.

    Deliberately tolerant: a malformed packet from a scanner is still worth
    recording, so callers treat None as "unparsed probe" rather than an error.
    """
    try:
        tag, body, _ = _decode_tlv(datagram, 0)
        if tag != _SEQUENCE:
            return None
        pos = 0
        tag, raw_version, pos = _decode_tlv(body, pos)
        if tag != _INTEGER:
            return None
        version = int.from_bytes(raw_version, "big") if raw_version else 0
        tag, raw_community, pos = _decode_tlv(body, pos)
        if tag != _OCTET_STRING:
            return None
        community = raw_community.decode("utf-8", errors="replace")
        pdu_tag, pdu_body, _ = _decode_tlv(body, pos)

        inner = 0
        _t, raw_request_id, inner = _decode_tlv(pdu_body, inner)
        request_id = int.from_bytes(raw_request_id, "big", signed=True) if raw_request_id else 0
        _t, _err_status, inner = _decode_tlv(pdu_body, inner)
        _t, _err_index, inner = _decode_tlv(pdu_body, inner)
        _t, varbind_list, _ = _decode_tlv(pdu_body, inner)

        oids: list[str] = []
        vpos = 0
        while vpos < len(varbind_list):
            _t, varbind, vpos = _decode_tlv(varbind_list, vpos)
            otag, oid_raw, _ = _decode_tlv(varbind, 0)
            if otag == _OID:
                oids.append(_decode_oid(oid_raw))
        return {
            "version": version,
            "version_name": _VERSION_NAMES.get(version, str(version)),
            "community": community,
            "pdu_type": pdu_tag,
            "pdu_name": _PDU_NAMES.get(pdu_tag, f"0x{pdu_tag:02x}"),
            "request_id": request_id,
            "oids": oids,
        }
    except (ValueError, IndexError):
        return None


def _encode_value(tag: int, value: Any) -> bytes:
    if tag == _OCTET_STRING:
        return _tlv(_OCTET_STRING, str(value).encode())
    if tag == _OID:
        return _encode_oid(str(value))
    if tag in (_INTEGER, 0x43, 0x41):
        return _encode_int(int(value), tag)
    return _tlv(_NULL, b"")


def build_response(request: dict[str, Any]) -> bytes:
    """Build a GetResponse for a parsed request.

    GetBulk is answered with the same single-varbind shape as a Get rather than
    the repeated varbinds a real agent returns — see the module docstring: a
    faithful GetBulk reply is the amplification.
    """
    varbinds = b""
    for oid in request["oids"][:8] or ["1.3.6.1.2.1.1.1.0"]:
        lookup = oid
        if request["pdu_type"] == _GET_NEXT_REQUEST:
            # Walkers start at 1.3.6.1.2.1.1 and expect the first scalar back.
            lookup = "1.3.6.1.2.1.1.1.0" if not oid.endswith(".0") else oid
        tag, value = _SCALARS.get(lookup, (_OCTET_STRING, _SYS_DESCR))
        varbinds += _tlv(_SEQUENCE, _encode_oid(lookup) + _encode_value(tag, value))

    pdu = (
        _encode_int(request["request_id"])
        + _encode_int(0)  # error-status: noError
        + _encode_int(0)  # error-index
        + _tlv(_SEQUENCE, varbinds)
    )
    message = (
        _encode_int(request["version"])
        + _tlv(_OCTET_STRING, request["community"].encode())
        + _tlv(_GET_RESPONSE, pdu)
    )
    return _tlv(_SEQUENCE, message)


def build_get_request(oid: str, community: str = "public", request_id: int = 1) -> bytes:
    """A well-formed v2c GetRequest. Used by the health probe and by tests."""
    varbind = _tlv(_SEQUENCE, _encode_oid(oid) + _tlv(_NULL, b""))
    pdu = (
        _encode_int(request_id)
        + _encode_int(0)  # error-status
        + _encode_int(0)  # error-index
        + _tlv(_SEQUENCE, varbind)  # varbind list
    )
    message = _encode_int(1) + _tlv(_OCTET_STRING, community.encode()) + _tlv(_GET_REQUEST, pdu)
    return _tlv(_SEQUENCE, message)


def classify(request: dict[str, Any]) -> tuple[str, AlertSeverity]:
    """Map a parsed request to an event type and severity."""
    community = request["community"]
    if request["pdu_type"] == _SET_REQUEST:
        return "snmp_set_request", AlertSeverity.CRITICAL
    if request["pdu_type"] == _GET_BULK_REQUEST:
        return "snmp_bulk_request", AlertSeverity.HIGH
    if community in _ACCEPTED_COMMUNITIES:
        return "snmp_default_community", AlertSeverity.HIGH
    return "snmp_community_attempt", AlertSeverity.MEDIUM


class _SNMPProtocol(asyncio.DatagramProtocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.DatagramTransport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > _MAX_DATAGRAM:
            return
        request = parse_snmp(data)
        if request is None:
            asyncio.create_task(
                self._record(
                    addr,
                    "snmp_invalid_probe",
                    AlertSeverity.LOW,
                    {"bytes": len(data), "head_hex": data[:32].hex()},
                )
            )
            return

        event_type, severity = classify(request)
        asyncio.create_task(
            self._record(
                addr,
                event_type,
                severity,
                {
                    "community": request["community"],
                    "username": request["community"],
                    "password": request["community"],
                    "service": "snmp",
                    "version": request["version_name"],
                    "pdu": request["pdu_name"],
                    "oids": request["oids"][:10],
                },
            )
        )

        # Only a valid community gets an answer; a real agent stays silent
        # otherwise, and answering everything would be a fingerprint.
        if request["community"] in _ACCEPTED_COMMUNITIES and self._transport is not None:
            try:
                self._transport.sendto(build_response(request), addr)
            except Exception as e:  # pragma: no cover - transport teardown race
                log.debug("SNMP response failed for %s: %s", addr, e)

    async def _record(
        self, addr: tuple[str, int], event_type: str, severity: AlertSeverity, payload: dict
    ) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=addr[0],
                source_port=addr[1],
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )


class SNMPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._transports: dict[str, asyncio.DatagramTransport] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _SNMPProtocol(name, hp_id), local_addr=("0.0.0.0", port)
        )
        cid = f"snmp-{secrets.token_hex(8)}"
        self._transports[cid] = transport
        log.info("SNMP honeypot '%s' listening on udp/%d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        transport = self._transports.pop(container_id, None)
        if transport:
            transport.close()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._transports, "type": "asyncio_snmp"}

    async def health_check(self, container_id: str, port: int) -> dict[str, Any]:
        """SNMP is UDP — a TCP probe would always fail.

        Sends a real GetRequest for sysDescr with a valid community and waits
        for any reply, mirroring the DNS engine's UDP check.
        """
        transport = self._transports.get(container_id)
        if transport is None:
            return {"alive": False, "detail": "Transport not registered", "method": "internal"}
        if transport.is_closing():
            return {"alive": False, "detail": "Transport is closing", "method": "internal"}

        from honeypot_mcp import self_probe

        loop = asyncio.get_event_loop()

        class _Probe(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.received = asyncio.Event()

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                self.received.set()

        proto = _Probe()
        probe_transport = None
        try:
            probe_transport, _ = await loop.create_datagram_endpoint(
                lambda: proto, remote_addr=("127.0.0.1", port)
            )
            # Claim the probe's own socket so the agent above does not record
            # the health check as a community-string attempt every 30 seconds.
            self_probe.register(probe_transport.get_extra_info("sockname"))
            probe_transport.sendto(build_get_request("1.3.6.1.2.1.1.1.0"))
            try:
                await asyncio.wait_for(proto.received.wait(), timeout=2.0)
                return {"alive": True, "detail": "SNMP agent answered probe", "method": "udp_snmp"}
            except TimeoutError:
                return {"alive": False, "detail": "SNMP probe timed out", "method": "udp_snmp"}
        except Exception as e:
            return {"alive": False, "detail": f"SNMP probe error: {e}", "method": "udp_snmp"}
        finally:
            if probe_transport is not None:
                probe_transport.close()

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["SNMP honeypot is in-process — events are stored directly in the database."]
