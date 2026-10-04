"""RDP's CredSSP (NLA) path.

Windows clients ask for Network Level Authentication; the old engine selected plain
TLS regardless and waited for an MCS PDU an NLA client never sends, so modern
clients got nothing and no NTLM material was captured. Now the CredSSP/NTLM exchange
runs, the NetNTLMv2 response is captured in hashcat form, and a planted honeytoken
password is recognised from it.

The NTLM client here is hand-built from MS-NLMP; the arithmetic is checked against
the specification's published vectors, and (outside the suite) against pyspnego.
"""

import asyncio
import hashlib
import hmac
import os
import socket
import ssl
import struct

import pytest
from sqlalchemy.exc import OperationalError

from honeypot_mcp.engines import rdp_nla as nla

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


# ── Primitives, against published vectors ───────────────────────────────────


def test_md4_matches_the_rfc_1320_vectors():
    assert nla._md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert nla._md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert nla._md4(b"message digest").hex() == "d9130a8164549fe818874806e1c7014b"
    assert nla._md4(b"a" * 1000) == hashlib.new("md4", b"a" * 1000).digest() if _has_md4() else True


def _has_md4() -> bool:
    try:
        hashlib.new("md4")
        return True
    except ValueError:
        return False


def test_ntlmv2_proof_matches_the_ms_nlmp_test_vector():
    """MS-NLMP section 4.2.4: user "User", domain "Domain", password "Password"."""
    nt_hash = nla._md4("Password".encode("utf-16-le"))
    assert nt_hash.hex() == "a4f49c406510bdcab6824ee7c30fd852"
    key = hmac.new(nt_hash, ("USER" + "Domain").encode("utf-16-le"), hashlib.md5).digest()
    assert key.hex() == "0c868a403bfd7a93a3001ef22ef02e3f"

    server_challenge = bytes.fromhex("0123456789abcdef")
    blob = bytes.fromhex(
        "0101000000000000" "0000000000000000" "aaaaaaaaaaaaaaaa" "00000000"
        "02000c0044006f006d00610069006e00" "01000c00530065007200760065007200" "00000000" "00000000"
    )  # fmt: skip
    proof = hmac.new(key, server_challenge + blob, hashlib.md5).digest()
    assert proof.hex() == "68cd0ab851e51c96aabc927bebef6a1c"
    assert nla.verify_ntlmv2(server_challenge, proof + blob, "User", "Domain", "Password")
    assert not nla.verify_ntlmv2(server_challenge, proof + blob, "User", "Domain", "password")


# ── DER ─────────────────────────────────────────────────────────────────────


def test_ts_request_round_trips_and_the_error_code_is_a_signed_ntstatus():
    token = b"NTLMSSP\x00\x01\x00\x00\x00" + b"\x00" * 20
    parsed = nla.parse_ts_request(nla.build_ts_request(6, token))
    assert parsed.version == 6 and parsed.nego_token == token
    # STATUS_LOGON_FAILURE as 4-byte two's complement, what CredSSP peers read.
    assert nla.build_ts_request(6, error_code=0xC000006D).endswith(
        b"\xa4\x06\x02\x04\xc0\x00\x00\x6d"
    )


@pytest.mark.parametrize(
    "hostile",
    [
        b"",
        b"\x30",
        b"\x30\x84\xff\xff\xff\xff",  # 4 GiB length
        b"\x30\x03\x01",
        b"\xa0" * 64,
        b"\x30\x82\xff\xff" + b"A" * 10,
        b"\x30\x0a\xa1\x08\x30\x06\x30\x04\xa0\x02\x04\xff",  # nested length past the end
    ],
)
def test_hostile_der_is_rejected_quickly(hostile):
    import time

    start = time.monotonic()
    with pytest.raises(ValueError):
        nla.parse_ts_request(hostile)
    assert time.monotonic() - start < 0.1


def test_the_challenge_carries_the_target_info_a_windows_host_discloses():
    ident = nla.identity_for("sensor-1")
    msg = nla.build_challenge(ident, b"\x11" * 8)
    assert msg[:8] == b"NTLMSSP\x00" and struct.unpack_from("<I", msg, 8)[0] == 2
    assert msg[24:32] == b"\x11" * 8
    for text in (ident.domain, ident.computer, ident.dns_domain, ident.dns_computer):
        assert text.encode("utf-16-le") in msg
    assert nla.identity_for("sensor-1") == ident  # stable per honeypot
    assert nla.identity_for("sensor-2").computer != ident.computer


def test_identity_overrides_come_from_the_honeypot_config():
    ident = nla.identity_for("x", {"rdp_hostname": "fileserver01", "rdp_domain": "Contoso.Local"})
    assert ident.computer == "FILESERVER01" and ident.dns_domain == "contoso.local"
    assert ident.domain == "CONTOSO"


# ── End to end ──────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _rdp(name: str = "rdp-nla"):
    from honeypot_mcp.engines.rdp import RDPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        session.add(Honeypot(name=name, type=HoneypotType.RDP, port=port))
        await session.flush()
    engine = RDPEngine()
    return port, engine, await engine.start(name, port, {})


def _ntlm_negotiate() -> bytes:
    return b"NTLMSSP\x00" + struct.pack("<II", 1, 0xE2088297) + b"\x00" * 16


def _ntlm_authenticate(
    challenge_msg: bytes, user: str, domain: str, password: str, workstation: str = "CLIENT01"
) -> bytes:
    """An AUTHENTICATE_MESSAGE with a correct NTLMv2 response (MS-NLMP 3.3.2)."""
    server_challenge = challenge_msg[24:32]
    info_len, _, info_off = struct.unpack_from("<HHI", challenge_msg, 40)
    target_info = challenge_msg[info_off : info_off + info_len]
    client_challenge = b"\xcc" * 8
    blob = (
        b"\x01\x01\x00\x00" + b"\x00" * 4 + b"\x00" * 8 + client_challenge + b"\x00" * 4
        + target_info + b"\x00" * 4
    )  # fmt: skip
    nt_hash = nla._md4(password.encode("utf-16-le"))
    key = hmac.new(nt_hash, (user.upper() + domain).encode("utf-16-le"), hashlib.md5).digest()
    proof = hmac.new(key, server_challenge + blob, hashlib.md5).digest()
    nt_response = proof + blob

    parts = [
        b"",  # LmChallengeResponse (empty)
        nt_response,
        domain.encode("utf-16-le"),
        user.encode("utf-16-le"),
        workstation.encode("utf-16-le"),
        b"",  # EncryptedRandomSessionKey
    ]
    header = 64
    offset = header
    fields = b""
    payload = b""
    for part in parts:
        fields += struct.pack("<HHI", len(part), len(part), offset)
        payload += part
        offset += len(part)
    return b"NTLMSSP\x00" + struct.pack("<I", 3) + fields + struct.pack("<I", 0xE2888215) + payload


def _client(port: int, user: str, domain: str, password: str, *, finish: bool = True) -> dict:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    cookie = b"Cookie: mstshash=" + user.encode() + b"\r\n"
    neg = bytes([1, 0]) + (8).to_bytes(2, "little") + (3).to_bytes(4, "little")
    x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    s.sendall(bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big") + x224)
    cc = s.recv(64)
    out: dict = {"selected": struct.unpack("<I", cc[-4:])[0], "neg_flags": cc[12]}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls = ctx.wrap_socket(s)

    def read_msg() -> bytes:
        head = tls.recv(2)
        n = head[1]
        extra = b""
        if n & 0x80:
            extra = tls.recv(n & 0x7F)
            n = int.from_bytes(extra, "big")
        body = b""
        while len(body) < n:
            chunk = tls.recv(n - len(body))
            if not chunk:
                break
            body += chunk
        return head + extra + body

    tls.sendall(nla.build_ts_request(6, _ntlm_negotiate()))
    challenge = nla.parse_ts_request(read_msg()).nego_token or b""
    out["challenge"] = challenge
    if finish:
        tls.sendall(nla.build_ts_request(6, _ntlm_authenticate(challenge, user, domain, password)))
        try:
            out["final"] = read_msg()
        except OSError:
            out["final"] = b""
    tls.close()
    return out


async def _events(event_type: str) -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    for _ in range(50):
        try:
            async with get_session() as session:
                rows = (
                    (await session.execute(select(Alert).where(Alert.event_type == event_type)))
                    .scalars()
                    .all()
                )
        except OperationalError:
            # In-memory SQLite shares one connection: a read can land mid-commit.
            await asyncio.sleep(0.1)
            continue
        if rows:
            return list(rows)
        await asyncio.sleep(0.1)
    return []


async def test_an_nla_client_gets_credssp_and_its_ntlmv2_response_is_captured():
    port, engine, cid = await _rdp()
    try:
        out = await asyncio.to_thread(_client, port, "alice", "ACME", "Summer2026!")
    finally:
        await engine.stop(cid)
    assert out["selected"] == 2, "an NLA client must be given CredSSP, not plain TLS"
    assert out["neg_flags"] == 0x1F  # the flags a Windows server sends
    assert out["final"].endswith(b"\xa4\x06\x02\x04\xc0\x00\x00\x6d")  # STATUS_LOGON_FAILURE

    rows = await _events("rdp_nla_auth")
    assert rows
    p = rows[0].payload
    assert (p["username"], p["domain"], p["workstation"]) == ("alice", "ACME", "CLIENT01")
    assert p["ntlm_version"] == "v2" and p["hashcat_mode"] == "5600"
    assert p["hashcat_line"].startswith("alice::ACME:") and p["hashcat_line"].count(":") == 5
    challenge = bytes.fromhex(p["server_challenge_hex"])
    nt = bytes.fromhex(p["nt_response_hex"])
    assert nla.verify_ntlmv2(challenge, nt, "alice", "ACME", "Summer2026!")
    assert not nla.verify_ntlmv2(challenge, nt, "alice", "ACME", "Summer2026?")


async def test_a_scanner_that_only_wants_the_challenge_is_recorded_as_host_identification():
    port, engine, cid = await _rdp()
    try:
        out = await asyncio.to_thread(_client, port, "scan", "X", "x", finish=False)
    finally:
        await engine.stop(cid)
    assert out["challenge"][:8] == b"NTLMSSP\x00"
    rows = await _events("rdp_nla_negotiate")
    assert rows and rows[0].severity.value == "medium"
    assert rows[0].payload["target_computer"].startswith("WIN-")


async def test_a_planted_rdp_credential_trips_the_honeytoken_from_the_ntlm_response_alone():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label="rdp-planted",
            token_value="cred:rdp-planted",
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                "service": "rdp",
                "credentials": [{"username": "svc-rdp", "password": "Zx9!kLm2#qq"}],
            },
        )
        session.add(token)
        await session.flush()
        token_id = token.id
    port, engine, cid = await _rdp("rdp-planted")
    try:
        await asyncio.to_thread(_client, port, "SVC-RDP", "ACME", "Zx9!kLm2#qq")
    finally:
        await engine.stop(cid)
    rows = await _events("honeytoken_triggered_credential_via_rdp_nla_auth")
    assert rows and rows[0].severity.value == "critical"
    for _ in range(40):
        async with get_session() as session:
            tripped = (await session.get(Honeytoken, token_id)).status
        if tripped == HoneytokenStatus.TRIGGERED:
            break
        await asyncio.sleep(0.1)
    assert tripped == HoneytokenStatus.TRIGGERED


async def test_a_wrong_password_for_a_planted_username_does_not_trip_it():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="rdp-planted-2",
                token_value="cred:rdp-planted-2",
                status=HoneytokenStatus.ACTIVE,
                token_meta={
                    "service": "rdp",
                    "credentials": [{"username": "svc-rdp", "password": "Zx9!kLm2#qq"}],
                },
            )
        )
    port, engine, cid = await _rdp("rdp-planted-2")
    try:
        await asyncio.to_thread(_client, port, "svc-rdp", "ACME", "not-the-password")
    finally:
        await engine.stop(cid)
    assert await _events("rdp_nla_auth")
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session as gs
    from honeypot_mcp.storage.models import Alert

    async with gs() as session:
        tripped = (
            (
                await session.execute(
                    select(Alert).where(Alert.event_type.like("honeytoken_triggered%"))
                )
            )
            .scalars()
            .all()
        )
    assert not tripped


async def test_a_client_asking_only_for_ssl_still_gets_plain_tls():
    from honeypot_mcp.engines import rdp

    ssl_only = rdp._build_neg_success_response(1)
    nla_reply = rdp._build_neg_success_response(2)
    assert ssl_only[-4:] == b"\x01\x00\x00\x00" and nla_reply[-4:] == b"\x02\x00\x00\x00"
