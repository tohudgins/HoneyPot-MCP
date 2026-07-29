"""Protocol-fidelity regression tests.

Every assertion here corresponds to a defect found by pointing real clients and
`nmap -sV` at the engines. Each one is a case where the engine was *functional*
but distinguishable from the software it impersonates — which for a honeypot is
the same as being broken, since a scanner that fingerprints the decoy stops
producing the attack data the honeypot exists to collect.

Where a check encodes an external tool's expectations, the relevant nmap
signature is quoted so a future change can tell what it would break.
"""

import os
import re
import struct

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


# ── Redis: the RESP3 HELLO handshake ─────────────────────────────────────────


def test_redis_hello_is_answered_for_resp2_and_resp3():
    """Every modern client (redis-py, ioredis, go-redis) opens with HELLO. The
    engine used to reject it, so clients errored out on connect and no attack
    traffic was ever captured."""
    from honeypot_mcp.engines.redis import _hello_reply

    resp2 = _hello_reply(2, 5)
    assert resp2.startswith(b"*14\r\n"), "RESP2 encodes the reply as a flat array"

    resp3 = _hello_reply(3, 5)
    assert resp3.startswith(b"%7\r\n"), "RESP3 encodes the same fields as a map"

    for payload in (resp2, resp3):
        assert b"redis" in payload
        assert b"standalone" in payload
        assert b"master" in payload


def test_redis_hello_version_matches_info_version():
    """A server reporting one version in INFO and another in HELLO is
    self-inconsistent, which is exactly the tell the persona systems exist to
    remove."""
    from honeypot_mcp.engines.redis import _INFO_RESPONSE, _REDIS_VERSION, _hello_reply

    assert f"redis_version:{_REDIS_VERSION}" in _INFO_RESPONSE
    assert _REDIS_VERSION.encode() in _hello_reply(2, 1)


def test_redis_connection_ids_increase():
    """Real Redis hands out an increasing per-connection id; a server that
    always answers id:1 is trivially distinguishable."""
    from honeypot_mcp.engines.redis import _next_client_id

    first, second = _next_client_id(), _next_client_id()
    assert second > first


# ── MSSQL: PRELOGIN structure ────────────────────────────────────────────────


def test_mssql_prelogin_matches_nmap_signature():
    """nmap's generic ms-sql-s softmatch is
    `^\\x04\\x01\\x00[\\x25-\\x2b]\\x00\\x00\\x01`.

    Real SQL Server always answers with four options (VERSION, ENCRYPTION,
    INSTOPT, THREADID) producing a 0x25-byte packet. Emitting only two produced
    0x1a bytes, which matched nothing — leaving the port reported as an
    unidentified service.
    """
    from honeypot_mcp.engines.mssql import _build_prelogin_response

    pkt = _build_prelogin_response()
    assert pkt[:3] == b"\x04\x01\x00"
    assert 0x25 <= pkt[3] <= 0x2B, f"packet length {pkt[3]:#x} outside nmap's expected range"
    assert pkt[4:7] == b"\x00\x00\x01"
    assert len(pkt) == pkt[3], "declared TDS length must match the real packet size"


def test_mssql_prelogin_declares_all_four_options():
    from honeypot_mcp.engines.mssql import (
        _PL_ENCRYPTION,
        _PL_INSTOPT,
        _PL_THREADID,
        _PL_VERSION,
        _build_prelogin_response,
    )

    body = _build_prelogin_response()[8:]  # strip TDS header
    tokens = []
    pos = 0
    while pos < len(body) and body[pos] != 0xFF:
        tokens.append(body[pos])
        pos += 5
    assert tokens == [_PL_VERSION, _PL_ENCRYPTION, _PL_INSTOPT, _PL_THREADID]


def test_mssql_prelogin_offsets_are_internally_consistent():
    """Each option's declared offset/length must actually address its data, or
    a real client rejects the packet."""
    from honeypot_mcp.engines.mssql import _SQL_VERSION, _build_prelogin_response

    body = _build_prelogin_response()[8:]
    pos, options = 0, {}
    while pos < len(body) and body[pos] != 0xFF:
        token, offset, length = struct.unpack_from(">BHH", body, pos)
        options[token] = body[offset : offset + length]
        pos += 5

    major, minor, build, _sub = _SQL_VERSION
    assert options[0x00][:4] == struct.pack(">BBH", major, minor, build)
    assert options[0x01] == b"\x02", "ENCRYPT_NOT_SUP keeps Login7 in the clear"


# ── PostgreSQL: error frames ─────────────────────────────────────────────────


def test_postgres_error_response_matches_nmap_softmatch():
    """nmap identifies PostgreSQL purely from its error frame:
    `^E\\0\\0\\0.SFATAL\\0(?:VFATAL\\0)?C\\w{5}\\0M`.

    The engine used to close silently on a malformed startup packet, so the
    service was unidentifiable — conspicuous for a database that is otherwise
    one of the easiest things on the internet to fingerprint.
    """
    from honeypot_mcp.engines.postgresql import _error_response

    frame = _error_response("FATAL", "08P01", "invalid length of startup packet")
    assert re.match(rb"^E\x00\x00\x00.SFATAL\x00(?:VFATAL\x00)?C\w{5}\x00M", frame, re.S)


def test_postgres_error_response_length_is_correct():
    from honeypot_mcp.engines.postgresql import _error_response

    frame = _error_response("FATAL", "28P01", "password authentication failed")
    declared = struct.unpack("!I", frame[1:5])[0]
    assert declared == len(frame) - 1, "length field covers everything after the tag byte"


@pytest.mark.asyncio
async def test_postgres_replies_to_a_malformed_startup_packet():
    """An HTTP probe's 'GET ' reads as a 1.2-billion-byte length. Real
    PostgreSQL answers with a FATAL error rather than hanging up mutely."""
    import asyncio

    from honeypot_mcp.engines.postgresql import _PGProtocol

    written: list[bytes] = []

    # Must subclass asyncio.Transport — the protocol asserts the type.
    class _FakeTransport(asyncio.Transport):
        def write(self, data: bytes) -> None:
            written.append(data)

        def close(self) -> None:
            pass

        def get_extra_info(self, _name: str, default=None):
            return ("198.51.100.9", 4444)

        def is_closing(self) -> bool:
            return False

    proto = _PGProtocol(honeypot_id=None)
    proto.connection_made(_FakeTransport())
    proto.data_received(b"GET / HTTP/1.0\r\n\r\n")

    assert written, "a malformed startup packet must draw a reply, not silence"
    assert b"invalid length of startup packet" in written[0]


# ── SMB: negotiate response correctness ──────────────────────────────────────


def _smb1_negotiate_request(pid: int = 0x0640, mid: int = 1) -> bytes:
    """A minimal SMB1 negotiate request carrying correlation fields."""
    header = (
        b"\xffSMB"
        + bytes([0x72])
        + struct.pack("<I", 0)
        + bytes([0x18])
        + struct.pack("<H", 0xC853)
        + struct.pack("<H", 0)
        + b"\x00" * 8
        + struct.pack("<H", 0)
        + struct.pack("<H", 0)  # TID
        + struct.pack("<H", pid)
        + struct.pack("<H", 0)  # UID
        + struct.pack("<H", mid)
    )
    dialects = b"\x02NT LM 0.12\x00"
    return header + bytes([0]) + struct.pack("<H", len(dialects)) + dialects


def test_smb_negotiate_echoes_client_correlation_fields():
    """SMB clients match a response to its request via TID/PID/UID/MID.
    Inventing values is a protocol error, not just a fingerprint."""
    from honeypot_mcp.engines.smb import _build_smb1_negotiate_response

    request = _smb1_negotiate_request(pid=0x0640, mid=1)
    resp = _build_smb1_negotiate_response(request, ["NT LM 0.12"])

    smb = resp[4:]  # strip the NetBIOS frame header
    tid, pid, uid, mid = struct.unpack_from("<HHHH", smb, 24)
    assert (pid, mid) == (0x0640, 1)
    assert (tid, uid) == (0, 0)


def test_smb_negotiate_matches_nmap_softmatch():
    """nmap's microsoft-ds softmatch requires PID `@\\x06`, MID `\\x01\\0` and a
    dialect index of 1-7. Replying with index 0 selects whatever the client
    listed first — for most scanners the 1987-era "PC NETWORK PROGRAM 1.0",
    which no real server would negotiate."""
    from honeypot_mcp.engines.smb import _build_smb1_negotiate_response

    dialects = ["PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"]
    resp = _build_smb1_negotiate_response(_smb1_negotiate_request(), dialects)

    pattern = (
        rb"^\x00\x00..\xffSMBr\x00\x00\x00\x00[\x80-\xff]..\x00\x00\x00\x00\x00\x00\x00\x00"
        rb"\x00\x00\x00\x00\x00\x00@\x06\x00\x00\x01\x00\x11[\x01-\x07]\x00"
    )
    assert re.match(pattern, resp, re.S), "response no longer matches nmap's SMB signature"


def test_smb_selects_nt_lm_dialect_by_index():
    from honeypot_mcp.engines.smb import _select_dialect_index

    assert _select_dialect_index(["PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"]) == 2
    assert _select_dialect_index(["NT LM 0.12"]) == 0
    # Never index 0 when the client offered several and none is NT LM 0.12.
    assert _select_dialect_index(["A", "B", "C"]) == 2


def test_smb_system_time_is_not_the_epoch():
    """SystemTime 0 is 1601-01-01 in FILETIME — visible in any SMB client."""
    from honeypot_mcp.engines.smb import _build_smb1_negotiate_response, _filetime_now

    resp = _build_smb1_negotiate_response(_smb1_negotiate_request(), ["NT LM 0.12"])
    # Params begin after NetBIOS(4) + SMB header(32) + WordCount(1). Within the
    # "<HBHHIIIIQhB" parameter block SystemTime starts at byte 23.
    params_at = 4 + 32 + 1
    system_time = struct.unpack_from("<Q", resp, params_at + 23)[0]
    assert system_time > 0
    assert abs(system_time - _filetime_now()) < 10 * 10_000_000  # within 10s


# ── MongoDB: version coherence and serverStatus ──────────────────────────────


def test_mongodb_wire_version_matches_advertised_release():
    """MongoDB 5.0 speaks wire version 13. Claiming 5.0.14 in buildInfo while
    negotiating wire version 8 (that is 4.0) is self-contradictory."""
    from honeypot_mcp.engines.mongodb import (
        _MONGO_VERSION,
        _MONGO_WIRE_VERSION,
        _ismaster_reply,
    )

    assert _MONGO_VERSION.startswith("5.0")
    assert _MONGO_WIRE_VERSION == 13
    assert _ismaster_reply()["maxWireVersion"] == _MONGO_WIRE_VERSION


def test_mongodb_server_status_carries_a_version_for_nmap():
    """nmap's generic MongoDB rule is `m|^.*version.....([\\.\\d]+)|s` against
    the serverStatus reply. Falling through to a bare {ok: 1.0} left the port
    unidentified."""
    from honeypot_mcp.engines.mongodb import _MONGO_VERSION, _bson_encode, _server_status_reply

    encoded = _bson_encode(_server_status_reply())
    match = re.search(rb"version.{5}([\d.]+)", encoded, re.S)
    assert match, "serverStatus must expose a version field"
    assert match.group(1).decode() == _MONGO_VERSION


def test_mongodb_localtime_is_a_real_datetime():
    """localTime 0 renders as 1970-01-01 in every client."""
    from datetime import UTC, datetime

    from honeypot_mcp.engines.mongodb import _bson_encode, _ismaster_reply

    reply = _ismaster_reply()
    assert isinstance(reply["localTime"], datetime)

    encoded = _bson_encode({"localTime": datetime.now(UTC)})
    assert b"\x09localTime\x00" in encoded, "must encode as BSON UTC datetime (type 0x09)"


# ── aiohttp server identity ──────────────────────────────────────────────────


def test_aiohttp_default_banner_is_neutralised():
    """aiohttp stamps `Server: Python/3.x aiohttp/3.y.z` on responses that don't
    set the header — including protocol-level 400s built by `handle_error`,
    which no middleware can reach. One malformed request therefore exposed the
    stack behind every HTTP persona.
    """
    from aiohttp import web_response

    import honeypot_mcp.http_identity  # noqa: F401  (import applies the patch)

    assert "aiohttp" not in web_response.SERVER_SOFTWARE.lower()
    assert "python" not in web_response.SERVER_SOFTWARE.lower()


@pytest.mark.asyncio
async def test_server_identity_middleware_overrides_and_adds_headers():
    from aiohttp import web

    from honeypot_mcp.http_identity import server_identity_middleware

    middleware = server_identity_middleware("Apache/2.4.41", {"X-Powered-By": "PHP/7.4.3"})

    async def handler(_request):
        return web.Response(text="hi")

    response = await middleware(None, handler)
    assert response.headers["Server"] == "Apache/2.4.41"
    assert response.headers["X-Powered-By"] == "PHP/7.4.3"


@pytest.mark.asyncio
async def test_elasticsearch_marks_itself_as_elastic():
    """Clients check `X-elastic-product` to confirm they're talking to genuine
    Elasticsearch, so its absence is a tell of its own."""
    from aiohttp import web

    from honeypot_mcp.engines.elasticsearch import _elastic_headers

    async def handler(_request):
        return web.json_response({"tagline": "You Know, for Search"})

    response = await _elastic_headers(None, handler)
    assert response.headers["X-elastic-product"] == "Elasticsearch"
    assert "aiohttp" not in response.headers.get("Server", "").lower()
