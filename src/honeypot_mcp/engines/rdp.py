"""RDP honeypot engine — X.224 banner + optional TLS-upgraded MCS capture.

RDP brute-force traffic is one of the largest single categories of internet
attack volume (driving most ransomware initial-access incidents). The
baseline behaviour here is banner-only: we parse the initial X.224 TPDU,
extract the leaked `Cookie: mstshash=user[@DOMAIN]` field that almost every
RDP client and brute-force tool sends in the clear, and return a believable
Connection Confirm. That alone catches every Mirai/Hydra/NLBrute-style
scanner.

When the client requests SSL or HYBRID/CredSSP (most modern mstsc clients
and serious credential-stuffing tools do), we go one step further: send a
NegRSP success selecting the SSL layer, upgrade the connection to TLS using
the same self-signed cert we use for HTTPS/SMTP, and read the next PDU —
the MCS Connect Initial. From it we extract the embedded GCC
ConferenceCreateRequest userData blocks (TS_UD_CS_CORE + TS_UD_CS_SEC),
which leak high-value fingerprint data: the attacker's clientName,
clientBuild, keyboard layout, screen resolution, and supported encryption
methods. We log an `rdp_mcs_handshake` HIGH-severity event with everything
captured, then close.

We deliberately do NOT implement the rest of the protocol stack (no MCS
Connect Response, no channel join, no CredSSP). After the MCS capture we
close — to the attacker tool that looks like a transient server failure or
TLS-layer rejection. CredSSP would let us capture NTLM hashes, but
implementing it correctly is a significant attack surface in itself.

Wire format references:
* RFC 905 — X.224 Connection-Oriented Transport Protocol
* MS-RDPBCGR §2.2.1.1 — X.224 Connection Request PDU
* MS-RDPBCGR §2.2.1.2 — X.224 Connection Confirm PDU
* MS-RDPBCGR §2.2.1.3 — MCS Connect Initial + GCC ConferenceCreateRequest
* T.124 §8.7   — GCC ConferenceCreateRequest definition
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.tls import build_server_ssl_context
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

# Protocol bitmask values (§2.2.1.1.1).
_PROTOCOL_RDP = 0x00000000
_PROTOCOL_SSL = 0x00000001
_PROTOCOL_HYBRID = 0x00000002

# MCS Connect Initial: TPKT + X.224 Data TPDU prefix bytes.
# After 7 bytes (4 TPKT + 3 X.224 Data) the BER-encoded MCS payload begins.
_X224_DATA_HEADER = bytes([0x02, 0xF0, 0x80])

# GCC ConferenceCreateRequest userData magic — fixed prefix for every real
# RDP client. Used to locate the start of TS_UD_* blocks inside the BER
# wrapper without writing a full ASN.1 parser.
_GCC_CCR_MAGIC = b"\x00\x05\x00\x14\x7c\x00\x01"

# TS_UD_* header type values (MS-RDPBCGR §2.2.1.3.x). Two-byte little-endian.
_TS_UD_CS_CORE = b"\x01\xc0"
_TS_UD_CS_SEC = b"\x02\xc0"


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
    """TPKT + X.224 Connection Confirm carrying an RDP negotiation failure.

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


def _build_neg_success_response(selected_protocol: int = _PROTOCOL_SSL) -> bytes:
    """TPKT + X.224 Connection Confirm carrying a negotiation success.

    Used when the client requested SSL or HYBRID and we want to continue the
    handshake into TLS. We always echo `_PROTOCOL_SSL` because we implement
    the SSL upgrade path; if the client wanted HYBRID, the SSL response is
    still valid — modern clients downgrade or close cleanly.

    Wire layout matches `_build_neg_failure_response` except the inner block
    is NegRSP (0x02) instead of NegFailure (0x03), and the payload is the
    selectedProtocol bitmask.
    """
    x224 = (
        bytes([14, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
        + bytes([_RDP_NEG_RSP, 0x00])
        + (8).to_bytes(2, "little")
        + selected_protocol.to_bytes(4, "little")
    )
    tpkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big")
    return tpkt + x224


def _decode_utf16le_field(blob: bytes) -> str:
    """Decode a UTF-16LE field, trimming trailing nulls. Never raises."""
    try:
        return blob.decode("utf-16-le", errors="replace").rstrip("\x00").rstrip()
    except Exception:
        return ""


def _parse_mcs_connect_initial(data: bytes) -> dict[str, Any]:
    """Extract attacker fingerprint fields from an MCS Connect Initial PDU.

    Real RDP clients (mstsc, FreeRDP, rdesktop) emit a Connect Initial whose
    BER wrapper holds a GCC ConferenceCreateRequest. Inside the CCR's
    userData section sit several TS_UD_* blocks; the two we care about are
    `TS_UD_CS_CORE` (clientName / clientBuild / desktop resolution / keyboard
    layout) and `TS_UD_CS_SEC` (encryption methods).

    Rather than implementing a full ASN.1 BER parser, we locate the GCC
    userData by its fixed magic prefix `\\x00\\x05\\x00\\x14\\x7c\\x00\\x01`
    (the start of every real CCR — `t124Identifier` + length tags), then
    walk forward looking for the TS_UD_CS_CORE and TS_UD_CS_SEC tags.

    Returns whatever was extracted; never raises. Missing or malformed
    fields are simply absent from the returned dict.
    """
    out: dict[str, Any] = {}
    if len(data) < 20:
        return out

    # Find the GCC ConferenceCreateRequest userData magic. If we can't
    # locate it, treat the PDU as unparseable but don't raise.
    gcc_start = data.find(_GCC_CCR_MAGIC)
    if gcc_start < 0:
        return out
    udata = data[gcc_start + len(_GCC_CCR_MAGIC) :]

    # TS_UD_CS_CORE: clientCoreData (MS-RDPBCGR §2.2.1.3.2).
    core_idx = udata.find(_TS_UD_CS_CORE)
    if core_idx >= 0:
        core = udata[core_idx:]
        # Header: type(2 LE) + length(2 LE). length includes header itself.
        if len(core) >= 4:
            core_len = int.from_bytes(core[2:4], "little")
            core_body = core[4:core_len] if core_len <= len(core) else core[4:]
            # version u32 LE — useful but not a unique fingerprint.
            if len(core_body) >= 4:
                out["client_version"] = int.from_bytes(core_body[:4], "little")
            if len(core_body) >= 8:
                out["desktop_width"] = int.from_bytes(core_body[4:6], "little")
                out["desktop_height"] = int.from_bytes(core_body[6:8], "little")
            if len(core_body) >= 10:
                out["color_depth"] = int.from_bytes(core_body[8:10], "little")
            # SASSequence at offset 10-12 — skipped (always 0xAA03).
            if len(core_body) >= 16:
                out["keyboard_layout"] = int.from_bytes(core_body[12:16], "little")
            if len(core_body) >= 20:
                out["client_build"] = int.from_bytes(core_body[16:20], "little")
            # clientName: 32 bytes UTF-16LE starting at offset 20.
            if len(core_body) >= 52:
                out["client_name"] = _decode_utf16le_field(core_body[20:52])
            # clientDigProductId at offset 88 (after keyboard fields + imeFileName).
            # Layout: 20 + 32 + 4 + 4 + 4 + 64 = 128 → product id at 128.
            if len(core_body) >= 192:
                out["client_dig_product_id"] = _decode_utf16le_field(core_body[128:192])

    # TS_UD_CS_SEC: clientSecurityData (MS-RDPBCGR §2.2.1.3.3).
    sec_idx = udata.find(_TS_UD_CS_SEC)
    if sec_idx >= 0:
        sec = udata[sec_idx:]
        if len(sec) >= 12:
            sec_len = int.from_bytes(sec[2:4], "little")
            sec_body = sec[4:sec_len] if sec_len <= len(sec) else sec[4:]
            if len(sec_body) >= 8:
                out["encryption_methods"] = int.from_bytes(sec_body[0:4], "little")
                out["ext_encryption_methods"] = int.from_bytes(sec_body[4:8], "little")

    return out


async def _record_event(
    hp_id: int | None,
    peer: tuple[str, int],
    event_type: str,
    severity: AlertSeverity,
    payload: dict,
) -> None:
    src_ip, src_port = peer
    await submit_event(
        PendingEvent(
            honeypot_id=hp_id,
            source_ip=src_ip,
            source_port=src_port,
            event_type=event_type,
            payload=payload,
            severity=severity,
        )
    )


async def _handle_rdp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    honeypot_name: str,
    honeypot_id: int | None,
) -> None:
    """Drive one RDP connection from the X.224 banner to (optionally) the
    MCS Connect Initial capture, then close."""
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)

    # Always log the initial connection at LOW severity (matches the previous
    # banner-only engine's behaviour so dashboards don't drift).
    asyncio.create_task(
        _record_event(honeypot_id, peer, "rdp_connection", AlertSeverity.LOW, {})
    )

    try:
        first = await asyncio.wait_for(reader.read(4096), timeout=10.0)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        with contextlib.suppress(Exception):
            writer.close()
        return

    if not first:
        with contextlib.suppress(Exception):
            writer.close()
        return

    parsed = _parse_x224_cr(first)
    sev = AlertSeverity.HIGH if "x224_code" in parsed else AlertSeverity.LOW
    et = "rdp_handshake" if "x224_code" in parsed else "rdp_invalid_probe"
    asyncio.create_task(
        _record_event(honeypot_id, peer, et, sev, {**parsed, "raw_bytes": len(first)})
    )

    requested = parsed.get("requested_protocols", 0)
    wants_tls = bool(requested & (_PROTOCOL_SSL | _PROTOCOL_HYBRID))

    if not wants_tls:
        # Pre-existing path: tell the client "I require SSL" and bail. Looks
        # like a hardened server to scanners that only speak Standard RDP.
        with contextlib.suppress(Exception):
            writer.write(_build_neg_failure_response())
            await writer.drain()
        with contextlib.suppress(Exception):
            writer.close()
            await writer.wait_closed()
        return

    # Client wants TLS. Send Connection Confirm + NegRSP(success, SSL), then
    # upgrade the stream.
    try:
        writer.write(_build_neg_success_response(_PROTOCOL_SSL))
        await writer.drain()
    except Exception:
        with contextlib.suppress(Exception):
            writer.close()
        return

    ssl_ctx = build_server_ssl_context(honeypot_name)

    try:
        # `StreamWriter.start_tls` lands cleanly in Python 3.11+. The new
        # transport replaces the old plaintext one on the same writer.
        await asyncio.wait_for(writer.start_tls(ssl_ctx, server_hostname=None), timeout=5.0)
    except Exception as e:
        log.debug("RDP TLS upgrade failed for %s:%d — %s", peer[0], peer[1], e)
        with contextlib.suppress(Exception):
            writer.close()
        return

    # Read the MCS Connect Initial PDU. Most clients send it within ~10
    # round trips of the TLS handshake; if they don't, just bail.
    try:
        mcs_pdu = await asyncio.wait_for(reader.read(8192), timeout=10.0)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        with contextlib.suppress(Exception):
            writer.close()
        return

    fingerprint = _parse_mcs_connect_initial(mcs_pdu)
    payload = {
        **fingerprint,
        "tls_negotiated": True,
        "mcs_bytes": len(mcs_pdu),
        "requested_protocols": requested,
        "selected_protocol": _PROTOCOL_SSL,
    }
    asyncio.create_task(
        _record_event(honeypot_id, peer, "rdp_mcs_handshake", AlertSeverity.HIGH, payload)
    )

    # Closing now looks like a transient server failure to the attacker —
    # acceptable behaviour for a honeypot that explicitly doesn't intend to
    # serve real RDP traffic.
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


class RDPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await _handle_rdp_client(
                    reader, writer, honeypot_name=name, honeypot_id=hp_id
                )
            except Exception as e:
                log.warning("RDP handler error: %s", e)

        server = await asyncio.start_server(_handler, host="0.0.0.0", port=port)
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
