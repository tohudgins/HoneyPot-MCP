"""IMAP, SIP, rsync and NFS engines.

Four surfaces that complete the catalogue against what is actually scanned:
mailbox credential stuffing, VoIP toll fraud, and the two file-sharing
protocols whose reconnaissance step *is* the breach.

The tests target the classification boundaries, because that is where these
engines differ from a socket that says OK. An rsync honeypot that logs
"connection" is worthless; one that distinguishes listing the modules from
taking an open one is an incident report. Same for SIP: a sweep, an extension
guess and a call to a satellite prefix mean three very different things and
must not collapse into "sip traffic".
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import os
import socket
import struct

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _register(name: str, hp_type) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = _free_port()
    async with get_session() as session:
        session.add(
            Honeypot(name=name, type=hp_type, port=port, status=HoneypotStatus.RUNNING, config={})
        )
    return port


async def _alerts() -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return list((await session.execute(select(Alert))).scalars().all())


async def _of_type(event_type: str) -> list:
    return [a for a in await _alerts() if a.event_type == event_type]


async def _talk(port: int, steps: list[tuple[bytes | None, float]]) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    got = b""
    try:
        for payload, wait in steps:
            if payload:
                writer.write(payload)
                await writer.drain()
            await asyncio.sleep(wait)
            with contextlib.suppress(TimeoutError):
                got += await asyncio.wait_for(reader.read(8192), timeout=0.6)
        return got
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# ── IMAP ────────────────────────────────────────────────────────────────────


async def test_imap_greeting_does_not_advertise_logindisabled():
    """LOGINDISABLED would stop the attacker sending the password.

    A hardened server advertises it on 143 to force STARTTLS. This honeypot is
    impersonating the misconfigured server they are hunting, so its absence is
    the entire point rather than an oversight.
    """
    from honeypot_mcp.engines.imap import _CAPABILITIES

    assert "LOGINDISABLED" not in _CAPABILITIES
    assert "IMAP4rev1" in _CAPABILITIES
    assert "AUTH=PLAIN" in _CAPABILITIES


@pytest.mark.parametrize(
    ("rest", "expected"),
    [
        ("user pass", ("user", "pass")),
        ('"user@corp.com" "Summer 2024!"', ("user@corp.com", "Summer 2024!")),
        ('admin "p@ss w0rd"', ("admin", "p@ss w0rd")),
        ('"quoted" bare', ("quoted", "bare")),
    ],
)
async def test_imap_login_argument_parsing_handles_quoting(rest, expected):
    """A password containing a space only survives if quoting is respected."""
    from honeypot_mcp.engines.imap import _split_login_args

    assert _split_login_args(rest) == expected


async def test_imap_sasl_plain_is_decoded():
    from honeypot_mcp.engines.imap import _decode_sasl_plain

    blob = base64.b64encode(b"\x00svc_mail\x00Hunter2!").decode()
    assert _decode_sasl_plain(blob) == ("svc_mail", "Hunter2!")
    assert _decode_sasl_plain("not base64 at all!!") == ("", "")


async def test_imap_captures_cleartext_credentials():
    from honeypot_mcp.engines.imap import IMAPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("imap-1", HoneypotType.IMAP)
    engine = IMAPEngine()
    cid = await engine.start("imap-1", port, {})
    try:
        response = await _talk(
            port, [(None, 0.2), (b'a1 LOGIN "admin@corp.com" "Summer2024!"\r\n', 1.6)]
        )
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert b"Dovecot ready" in response
    assert b"AUTHENTICATIONFAILED" in response, "must match Dovecot's real rejection wording"

    logins = await _of_type("imap_login_attempt")
    assert logins and logins[0].severity.value == "high"
    payload = logins[0].payload
    assert payload["username"] == "admin@corp.com"
    assert payload["password"] == "Summer2024!"
    assert payload["service"] == "imap"


# ── SIP ─────────────────────────────────────────────────────────────────────


def _sip(method: str, uri: str, user_agent: str = "friendly-scanner", extra: str = "") -> str:
    return (
        f"{method} {uri} SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n"
        f"From: <sip:100@1.1.1.1>;tag=t\r\nTo: <{uri}>\r\nCall-ID: 1@1.1.1.1\r\n"
        f"CSeq: 1 {method}\r\nUser-Agent: {user_agent}\r\n{extra}Content-Length: 0\r\n\r\n"
    )


@pytest.mark.parametrize(
    ("number", "is_fraud"),
    [
        ("sip:00881234567890@h", True),  # satellite
        ("sip:00882991234567@h", True),
        ("sip:0090555123456789@h", True),
        ("sip:004412345678901234@h", True),  # long international from a stranger
        ("sip:1001@h", False),  # internal extension
        ("sip:reception@h", False),
        ("sip:100@h", False),
    ],
)
async def test_toll_fraud_destinations_are_recognised(number, is_fraud):
    from honeypot_mcp.engines.sip import is_toll_fraud_target

    assert is_toll_fraud_target(number) is is_fraud


async def test_sip_separates_scanning_from_registration_from_fraud():
    """Three phases that mean three different things must not collapse."""
    from honeypot_mcp.engines.sip import classify, parse_sip

    scan = classify(parse_sip(_sip("OPTIONS", "sip:100@h")))
    assert scan[0] == "sip_scan"
    assert scan[2]["scanner_tool"].lower() == "friendly-scanner"

    probe = classify(parse_sip(_sip("REGISTER", "sip:1001@h")))
    assert probe[0] == "sip_extension_probe"
    assert probe[2]["extension"] == "1001"

    fraud = classify(parse_sip(_sip("INVITE", "sip:00881234567890@h")))
    assert fraud[0] == "sip_toll_fraud_attempt"
    assert fraud[1].value == "critical"
    assert fraud[2]["dialled"] == "00881234567890"


async def test_sip_digest_response_is_captured_with_its_nonce():
    """The response is only crackable if the nonce it was computed over is kept."""
    from honeypot_mcp.engines.sip import classify, parse_sip

    auth = (
        'Authorization: Digest username="1001", realm="asterisk", '
        'nonce="abc123", uri="sip:h", response="deadbeef"\r\n'
    )
    event_type, severity, extra = classify(parse_sip(_sip("REGISTER", "sip:1001@h", extra=auth)))
    assert event_type == "sip_register_attempt"
    assert severity.value == "high"
    assert extra["username"] == "1001"
    assert extra["digest_response"] == "deadbeef"
    assert extra["nonce"] == "abc123"
    assert extra["service"] == "sip"


async def test_sip_register_is_challenged_so_credentials_are_sent():
    """Without a challenge the tool never sends the password."""
    from honeypot_mcp.engines.sip import build_auth_challenge, parse_sip

    challenge = build_auth_challenge(parse_sip(_sip("REGISTER", "sip:1001@h")))
    assert challenge.startswith("SIP/2.0 401 Unauthorized")
    assert 'realm="asterisk"' in challenge
    assert "nonce=" in challenge
    # The correlation headers have to be echoed or a real UA ignores the reply.
    assert "Call-ID: 1@1.1.1.1" in challenge
    assert "CSeq: 1 REGISTER" in challenge


async def test_sip_nonce_is_fresh_per_challenge():
    from honeypot_mcp.engines.sip import build_auth_challenge, parse_sip

    request = parse_sip(_sip("REGISTER", "sip:1001@h"))
    first = build_auth_challenge(request).split('nonce="')[1].split('"')[0]
    second = build_auth_challenge(request).split('nonce="')[1].split('"')[0]
    assert first != second


async def test_sip_non_sip_traffic_is_not_parsed_as_sip():
    from honeypot_mcp.engines.sip import parse_sip

    assert parse_sip("GET / HTTP/1.1\r\nHost: x\r\n\r\n") is None
    assert parse_sip("") is None
    assert parse_sip("\x00\x01\x02binary garbage") is None


# ── rsync ───────────────────────────────────────────────────────────────────


async def test_rsync_enumeration_and_anonymous_access_are_different_events():
    """Listing shares is recon; taking an open one is the breach."""
    from honeypot_mcp.engines.rsync import RsyncEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("rsync-1", HoneypotType.RSYNC)
    engine = RsyncEngine()
    cid = await engine.start("rsync-1", port, {})
    try:
        listing = await _talk(port, [(None, 0.2), (b"@RSYNCD: 31.0\n", 0.2), (b"\n", 0.6)])
        await _talk(port, [(None, 0.2), (b"@RSYNCD: 31.0\n", 0.2), (b"backups\n", 0.5)])
        await asyncio.sleep(0.5)
    finally:
        await engine.stop(cid)

    assert b"@RSYNCD: 31.0" in listing
    assert b"backups" in listing and b"db-dumps" in listing

    enumeration = await _of_type("rsync_module_enumeration")
    assert enumeration and enumeration[0].severity.value == "high"
    assert "backups" in enumeration[0].payload["modules_disclosed"]

    anonymous = await _of_type("rsync_anonymous_access")
    assert anonymous and anonymous[0].severity.value == "critical"


async def test_rsync_protected_module_challenges_and_captures_the_digest():
    from honeypot_mcp.engines.rsync import RsyncEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("rsync-2", HoneypotType.RSYNC)
    engine = RsyncEngine()
    cid = await engine.start("rsync-2", port, {})
    try:
        challenge = await _talk(port, [(None, 0.2), (b"@RSYNCD: 31.0\n", 0.2), (b"etc\n", 0.5)])
        await asyncio.sleep(0.3)
    finally:
        await engine.stop(cid)

    assert b"@RSYNCD: AUTHREQD" in challenge
    access = await _of_type("rsync_module_access")
    assert access and access[0].payload["auth_required"] is True


async def test_rsync_rejects_a_non_rsync_client():
    """Port-scan garbage must not be mistaken for a session."""
    from honeypot_mcp.engines.rsync import RsyncEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("rsync-3", HoneypotType.RSYNC)
    engine = RsyncEngine()
    cid = await engine.start("rsync-3", port, {})
    try:
        response = await _talk(port, [(None, 0.2), (b"GET / HTTP/1.0\n", 0.5)])
        await asyncio.sleep(0.3)
    finally:
        await engine.stop(cid)

    assert b"@ERROR" in response
    assert await _of_type("rsync_invalid_probe")


# ── NFS ─────────────────────────────────────────────────────────────────────


def _rpc(program: int, version: int, procedure: int, args: bytes = b"") -> bytes:
    body = (
        struct.pack(">IIIIII", 0x1234, 0, 2, program, version, procedure)
        + struct.pack(">IIII", 0, 0, 0, 0)
        + args
    )
    return struct.pack(">I", 0x80000000 | len(body)) + body


def _xdr(value: str) -> bytes:
    raw = value.encode()
    return struct.pack(">I", len(raw)) + raw + b"\x00" * ((4 - len(raw) % 4) % 4)


async def test_nfs_rpc_call_round_trips():
    from honeypot_mcp.engines.nfs import build_reply, parse_rpc_call

    call = parse_rpc_call(_rpc(100005, 3, 5)[4:])
    assert call is not None
    assert call["program"] == 100005
    assert call["procedure"] == 5
    assert call["program_name"] == "mountd"

    reply = build_reply(call["xid"], b"")
    assert struct.unpack(">I", reply[:4])[0] == 0x1234
    assert struct.unpack(">I", reply[4:8])[0] == 1  # MSG_REPLY


async def test_nfs_export_list_is_well_formed_and_terminated():
    """A missing terminator makes showmount hang — louder than not answering."""
    from honeypot_mcp.engines.nfs import _EXPORTS, build_export_list

    blob = build_export_list()
    assert blob.endswith(struct.pack(">I", 0))
    for path, _groups in _EXPORTS:
        assert path.encode() in blob


async def test_nfs_showmount_discloses_exports_and_flags_world_readable():
    from honeypot_mcp.engines.nfs import NFSEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("nfs-1", HoneypotType.NFS)
    engine = NFSEngine()
    cid = await engine.start("nfs-1", port, {})
    try:
        await _talk(port, [(_rpc(100005, 3, 5), 0.5)])
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    events = await _of_type("nfs_export_enumeration")
    assert events and events[0].severity.value == "high"
    payload = events[0].payload
    assert "/srv/backups" in payload["exports_disclosed"]
    # The `*` shares are what decide the attacker's next move, so they are
    # called out separately rather than left for the reader to work out.
    assert "/srv/backups" in payload["world_readable"]
    assert "/home" not in payload["world_readable"]


async def test_nfs_mount_of_a_world_export_is_critical_and_granted():
    from honeypot_mcp.engines.nfs import NFSEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("nfs-2", HoneypotType.NFS)
    engine = NFSEngine()
    cid = await engine.start("nfs-2", port, {})
    try:
        granted = await _talk(port, [(_rpc(100005, 3, 1, _xdr("/srv/backups")), 0.5)])
        denied = await _talk(port, [(_rpc(100005, 3, 1, _xdr("/home")), 0.5)])
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert struct.unpack(">I", granted[28:32])[0] == 0, "world export should mount"
    assert struct.unpack(">I", denied[28:32])[0] != 0, "restricted export should not"

    mounts = await _of_type("nfs_mount_attempt")
    severities = {m.payload.get("granted"): m.severity.value for m in mounts}
    assert severities.get(True) == "critical"
    assert severities.get(False) == "high"


# ── Cross-cutting ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("service", ["imap", "sip", "rsync"])
async def test_new_credential_services_are_matchable(service):
    """A planted credential for these must cross-reference, not fall through."""
    from honeypot_mcp.credential_match import _infer_service

    assert _infer_service(f"{service}_login_attempt") == service


async def test_every_new_engine_is_in_the_capability_registry():
    from honeypot_mcp.deception.capabilities import BY_TYPE
    from honeypot_mcp.storage.models import HoneypotType

    for hp_type in (HoneypotType.IMAP, HoneypotType.SIP, HoneypotType.RSYNC, HoneypotType.NFS):
        assert hp_type.value in BY_TYPE
        capability = BY_TYPE[hp_type.value]
        assert capability.signature_events, f"{hp_type.value} would show zero ATT&CK coverage"
