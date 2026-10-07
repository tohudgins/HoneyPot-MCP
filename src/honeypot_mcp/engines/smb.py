"""SMB honeypot engine — negotiate capture, NTLM credential capture, EternalBlue/DoublePulsar.

SMB on tcp/445 is one of the most heavily scanned surfaces on the public
internet: it's the initial-access vector behind WannaCry, NotPetya, and a large
share of ransomware intrusions. Two populations hit it and both are caught:

**Credential sprayers** speak SMB2. `engines/smb2.py` negotiates dialect 2.1 and plays the
server side of NTLM session setup, so a login attempt from `smbclient`, impacket, NetExec or
Metasploit yields the account, domain, workstation and a NetNTLMv2 response with its hashcat
line (`smb_ntlm_auth`). The login is refused: there is no file server behind it.

**Scanners and exploit tools** announce themselves loudly in the first one or two SMB1 packets:

* Any SMB1 (`\\xffSMB`) negotiation on 445 in 2020s traffic is already
  suspicious — modern clients speak SMB2/3. EternalBlue *requires* SMB1.
* The DoublePulsar backdoor check is a specific SMB1 Trans2 SESSION_SETUP
  (subcommand 0x000e) request — scanners send it to see if a host is already
  implanted. That request is a near-perfect IOC.
* EternalBlue itself sends oversized/malformed Trans2 requests right after the
  negotiate, before any real session exists.

An SMB1 negotiate that offers only SMB1 dialects (nmap, exploit tools) is answered in SMB1 to
keep the tool talking, and the follow-up packets are classified — emitting a CRITICAL
`smb_exploit_attempt` on a DoublePulsar/EternalBlue signature and capturing NTLM session-setup
data (username/hostname/domain) when present. A multi-protocol negotiate that also offers
SMB 2.x (impacket, older smbclient) is answered in SMB2, as Windows does.

We deliberately do NOT implement a real SMB file server (no tree connect, no
file I/O) — that's a large attack surface and not the goal. This is the same
"detection-focused, not a full protocol stack" tier as the RDP engine.

Wire references:
* MS-SMB   §2.2  — SMB1 message syntax
* MS-SMB2  §2.2  — SMB2 negotiate and session setup
* [MS-CIFS] §2.2.4.52 — TRANS2_SESSION_SETUP (the DoublePulsar subcommand)
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import struct
from datetime import UTC, datetime
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_handler, shutdown_server
from honeypot_mcp.engines.rdp_nla import AuthMessage, HostIdentity, hashcat_line, identity_for
from honeypot_mcp.engines.smb2 import (
    DIALECT_2_0_2,
    DIALECT_WILDCARD,
    negotiate_response,
    serve_smb2,
    stable_guid,
)
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_SMB1_MAGIC = b"\xffSMB"
_SMB2_MAGIC = b"\xfeSMB"

# SMB1 command codes (MS-CIFS §2.2.2.1).
_SMB_COM_NEGOTIATE = 0x72
_SMB_COM_SESSION_SETUP_ANDX = 0x73
_SMB_COM_TRANSACTION2 = 0x32

# Trans2 subcommands. 0x000e = SESSION_SETUP — the DoublePulsar ping uses this
# with no legitimate purpose, so seeing it is a strong backdoor-scan IOC.
_TRANS2_SESSION_SETUP = 0x000E


def _read_netbios_frame_len(header: bytes) -> int:
    """Direct-hosted SMB on 445 prefixes each message with a 4-byte header:
    a zero type byte then a 24-bit big-endian length."""
    if len(header) < 4:
        return 0
    return int.from_bytes(header[1:4], "big")


def _classify_first_packet(smb_msg: bytes) -> dict[str, Any]:
    """Parse an SMB message body (after the 4-byte NetBIOS length) into the
    fields we log. Robust to garbage — returns what it can, never raises."""
    out: dict[str, Any] = {"raw_bytes": len(smb_msg)}
    if smb_msg[:4] == _SMB1_MAGIC:
        out["smb_version"] = "SMB1"
        if len(smb_msg) >= 5:
            out["command"] = smb_msg[4]
        # SMB1 negotiate lists dialects as 0x02-prefixed null-terminated ASCII.
        if out.get("command") == _SMB_COM_NEGOTIATE:
            out["dialects"] = _parse_smb1_dialects(smb_msg)
    elif smb_msg[:4] == _SMB2_MAGIC:
        out["smb_version"] = "SMB2"
    else:
        out["smb_version"] = "unknown"
    return out


def _parse_smb1_dialects(smb_msg: bytes) -> list[str]:
    # Header is 32 bytes; then WordCount(1), ByteCount(2), then the dialect
    # buffer. We just scan the tail for 0x02-prefixed null-terminated strings.
    try:
        body = smb_msg[32:]
        # Skip WordCount(1) + ByteCount(2).
        buf = body[3:] if len(body) > 3 else b""
        dialects: list[str] = []
        i = 0
        while i < len(buf):
            if buf[i] == 0x02:
                end = buf.find(b"\x00", i + 1)
                if end == -1:
                    break
                dialects.append(buf[i + 1 : end].decode("ascii", errors="replace"))
                i = end + 1
            else:
                i += 1
        return dialects
    except Exception:
        return []


def _looks_like_doublepulsar_or_eternalblue(smb_msg: bytes) -> str | None:
    """Return an IOC label if this packet matches a known EternalBlue /
    DoublePulsar signature, else None."""
    if smb_msg[:4] != _SMB1_MAGIC or len(smb_msg) < 5:
        return None
    command = smb_msg[4]
    if command == _SMB_COM_TRANSACTION2:
        # Trans2 SESSION_SETUP (subcommand 0x000e) is the DoublePulsar ping —
        # no legitimate SMB client ever sends it.
        # Subcommand sits in the Trans2 parameter block; scan for the marker.
        if struct.pack("<H", _TRANS2_SESSION_SETUP) in smb_msg[32:]:
            return "doublepulsar_ping (Trans2 SESSION_SETUP)"
        return "eternalblue_trans2 (SMB1 Trans2 pre-auth)"
    return None


class SMBEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        ident = identity_for(name, config)
        guid = stable_guid(name)

        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await _handle_smb_client(reader, writer, honeypot_id=hp_id, ident=ident, guid=guid)
            except Exception as e:
                log.warning("SMB handler error: %s", e)

        server = await asyncio.start_server(
            limited_handler(_handler, self._limiter), host="0.0.0.0", port=port
        )
        cid = f"smb-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("SMB honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_smb"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["SMB honeypot is in-process — events are stored directly in the database."]


async def _read_frame(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    """Read one length-prefixed SMB message. Returns the SMB body (without the
    4-byte NetBIOS header), or None on EOF/timeout/oversize."""
    try:
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        return None
    length = _read_netbios_frame_len(header)
    if length == 0 or length > 65535:  # sane bound — real negotiates are tiny
        return None
    try:
        return await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
    except (TimeoutError, asyncio.IncompleteReadError, OSError):
        return None


def _filetime_now() -> int:
    """Current time as a Windows FILETIME (100ns ticks since 1601-01-01 UTC)."""
    unix_seconds = datetime.now(UTC).timestamp()
    return int((unix_seconds + 11644473600) * 10_000_000)


def _select_dialect_index(dialects: list[str]) -> int:
    """Pick the index of NT LM 0.12 from the client's offered dialect list.

    A real server answers with the index of the dialect it chose. Always
    replying 0 selects whatever the client listed first — for most scanners
    that's the 1987-era "PC NETWORK PROGRAM 1.0" — which no modern server would
    ever negotiate, and which nmap rejects outright (its SMB signatures require
    an index of 1-7).
    """
    for i, name in enumerate(dialects):
        if name.strip() == "NT LM 0.12":
            return i
    # Fall back to the last offered dialect: servers pick the most capable one
    # they understand, and it is never index 0 in a real exchange.
    return max(len(dialects) - 1, 1)


def _build_smb1_negotiate_response(
    request: bytes, dialects: list[str], ident: HostIdentity | None = None
) -> bytes:
    """A believable SMB1 Negotiate Response selecting NT LM 0.12 and demanding
    challenge/response auth. Enough to make an exploit tool proceed to its
    session-setup / exploit packet.

    TID/PID/UID/MID are echoed from the request: SMB clients use them to
    correlate a response with the request that produced it, so inventing
    values is a protocol error as well as a fingerprint.
    """
    # Echo the request's correlation fields when the header is complete
    # (32-byte SMB1 header); fall back to values a real client would send.
    if len(request) >= 32:
        tid, pid_low, uid, mid = struct.unpack_from("<HHHH", request, 24)
        # Windows answers with the Flags2 bits the client sent (unicode, NT status, ...). A
        # constant here is what `nmap -sV` compares against the request it just made.
        (flags2,) = struct.unpack_from("<H", request, 10)
    else:
        tid, pid_low, uid, mid = 0, 0x0640, 0, 1
        flags2 = 0xC001

    # SMB header (32 bytes).
    header = (
        _SMB1_MAGIC
        + bytes([_SMB_COM_NEGOTIATE])
        + struct.pack("<I", 0)  # NT status = success
        + bytes([0x88])  # flags: reply + case-insensitive
        + struct.pack("<H", flags2)
        + struct.pack("<H", 0)  # PIDHigh
        + b"\x00" * 8  # security signature
        + struct.pack("<H", 0)  # reserved
        + struct.pack("<H", tid)
        + struct.pack("<H", pid_low)
        + struct.pack("<H", uid)
        + struct.pack("<H", mid)
    )
    challenge = secrets.token_bytes(8)
    # Negotiate response parameters (WordCount = 17). The sizes and capability word are what a
    # Windows 7 / Server 2008 R2 host reports, which is the persona EternalBlue-era tooling
    # expects to find on 445.
    params = struct.pack(
        "<HBHHIIIIQhB",
        _select_dialect_index(dialects),
        0x03,  # SecurityMode: user-level + challenge/response
        10,  # MaxMpxCount
        1,  # MaxNumberVcs
        4356,  # MaxBufferSize
        65536,  # MaxRawSize
        0,  # SessionKey
        0x0001_E3FC,  # Capabilities: unicode, large files, NT SMBs, status32, DFS, large r/w
        _filetime_now(),  # SystemTime — 0 renders as 1601-01-01 in any client
        0,  # ServerTimeZone
        len(challenge),  # ChallengeLength
    )
    # DomainName then ServerName, both UTF-16LE and NUL-terminated; a response that stops after
    # the domain is structurally short of anything a Windows host sends.
    # The domain and server name are the ones the NTLM CHALLENGE discloses over SMB2 and RDP:
    # a host that is WORKGROUP/FS01 here and CORP/WIN-xxxx a packet later is two hosts.
    domain = f"{ident.domain if ident else 'WORKGROUP'}\x00".encode("utf-16-le")
    server = f"{ident.computer if ident else 'FS01'}\x00".encode("utf-16-le")
    data = challenge + domain + server
    body = bytes([17]) + params + struct.pack("<H", len(data)) + data
    smb = header + body
    netbios = b"\x00" + len(smb).to_bytes(3, "big")
    return netbios + smb


async def _record(
    hp_id: int | None,
    peer: tuple[str, int],
    event_type: str,
    severity: AlertSeverity,
    payload: dict,
) -> None:
    await submit_event(
        PendingEvent(
            honeypot_id=hp_id,
            source_ip=peer[0],
            source_port=peer[1],
            event_type=event_type,
            payload=payload,
            severity=severity,
        )
    )


async def _handle_smb_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    honeypot_id: int | None,
    ident: HostIdentity,
    guid: bytes,
) -> None:
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    spawn(_record(honeypot_id, peer, "smb_connection", AlertSeverity.LOW, {}), name="smb-event")

    first = await _read_frame(reader, timeout=10.0)
    if first is None:
        with contextlib.suppress(Exception):
            writer.close()
        return

    info = _classify_first_packet(first)
    # SMB1 negotiate on 445 is itself notable; SMB2 is normal.
    severity = AlertSeverity.MEDIUM if info.get("smb_version") == "SMB1" else AlertSeverity.LOW
    event_info = dict(info)
    dialects: list[str] = info.get("dialects") or []
    if "dialects" in event_info:
        # The full list drives dialect selection; the event only needs a sample.
        event_info["dialects"] = [d[:64] for d in event_info["dialects"][:32]]
    spawn(_record(honeypot_id, peer, "smb_negotiate", severity, event_info), name="smb-event")

    async def send(data: bytes) -> None:
        writer.write(b"\x00" + len(data).to_bytes(3, "big") + data)
        await asyncio.wait_for(writer.drain(), timeout=5.0)

    async def read_frame(timeout: float) -> bytes | None:
        return await _read_frame(reader, timeout=timeout)

    async def on_auth(auth: AuthMessage, challenge: bytes, negotiate: dict[str, Any]) -> None:
        payload: dict[str, Any] = {
            **negotiate,
            "username": auth.username,
            "domain": auth.domain,
            "workstation": auth.workstation,
            "ntlm_version": "v2" if len(auth.nt_response) > 24 else "v1",
            "service": "smb",
            "server_challenge_hex": challenge.hex(),
            "nt_response_hex": auth.nt_response.hex(),
        }
        cracked = hashcat_line(auth, challenge)
        if cracked is not None:
            payload["hashcat_mode"], payload["hashcat_line"] = cracked
        await _record(honeypot_id, peer, "smb_ntlm_auth", AlertSeverity.HIGH, payload)

    # A client that offers SMB 2.x gets SMB2, as it does from Windows: either its own SMB2
    # NEGOTIATE, or (impacket, older smbclient) an SMB1 multi-protocol negotiate that lists
    # "SMB 2.002" / "SMB 2.???", which a server answers with an SMB2 response.
    smb2_first: bytes | None = None
    use_smb2 = False
    if info.get("smb_version") == "SMB2":
        use_smb2, smb2_first = True, first
    elif info.get("command") == _SMB_COM_NEGOTIATE and any(
        d in ("SMB 2.002", "SMB 2.???") for d in dialects
    ):
        wildcard = "SMB 2.???" in dialects
        with contextlib.suppress(OSError, TimeoutError):
            await send(
                negotiate_response(None, DIALECT_WILDCARD if wildcard else DIALECT_2_0_2, guid)
            )
            use_smb2 = True

    if use_smb2:
        with contextlib.suppress(OSError, TimeoutError):
            await serve_smb2(smb2_first, read_frame, send, ident, guid, on_auth)
    elif info.get("smb_version") == "SMB1":
        # Respond to an SMB1-only negotiate so the exploit tool proceeds.
        with contextlib.suppress(Exception):
            writer.write(_build_smb1_negotiate_response(first, dialects, ident))
            await asyncio.wait_for(writer.drain(), timeout=5.0)

        # Read up to a few follow-up packets looking for the exploit/backdoor
        # signature or session-setup credentials.
        for _ in range(3):
            pkt = await _read_frame(reader, timeout=8.0)
            if pkt is None:
                break
            ioc = _looks_like_doublepulsar_or_eternalblue(pkt)
            if ioc:
                spawn(
                    _record(
                        honeypot_id,
                        peer,
                        "smb_exploit_attempt",
                        AlertSeverity.CRITICAL,
                        {"ioc": ioc, "raw_bytes": len(pkt)},
                    ),
                    name="smb-event",
                )
                break
            if pkt[:4] == _SMB1_MAGIC and len(pkt) >= 5 and pkt[4] == _SMB_COM_SESSION_SETUP_ANDX:
                spawn(
                    _record(
                        honeypot_id,
                        peer,
                        "smb_session_setup",
                        AlertSeverity.HIGH,
                        {"detail": "SMB1 session setup", **_extract_session_setup(pkt)},
                    ),
                    name="smb-event",
                )

    with contextlib.suppress(Exception):
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=5.0)


def _extract_session_setup(pkt: bytes) -> dict[str, Any]:
    """Best-effort pull of readable ASCII/UTF-16 strings (OS, LanMan, domain,
    username) from an SMB1 SESSION_SETUP_ANDX. Never raises."""
    out: dict[str, Any] = {}
    try:
        tail = pkt[32:]
        # Grab printable UTF-16LE runs — native OS / domain / account often sit
        # here in the clear for pre-NTLMv2 setups.
        text = tail.decode("utf-16-le", errors="ignore")
        tokens = [t for t in text.split("\x00") if t.isprintable() and len(t) >= 2]
        if tokens:
            out["strings"] = [t[:120] for t in tokens[:12]]
    except Exception:
        pass
    return out
