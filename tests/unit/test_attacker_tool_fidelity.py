"""Defects found by pointing real attacker tooling at the engines.

Each test pins a way a real client (`snmpwalk`, `ldapsearch`, `kubectl`, `smbclient`, impacket,
`mariadb`, `redis-cli`, `psql`) told the decoy from the real service. Unit tests that feed an
engine synthetic bytes passed throughout, because the bytes were what the engine author expected;
the tools expect what the real server sends.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import struct

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match, suppression
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    suppression.invalidate_rule_cache()
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()


async def _register(name: str, hp_type) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = free_port()
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


async def _events(event_type: str) -> list:
    """The persisted alerts of one type, read once the flusher has drained and stopped.

    Polling while the flusher runs is a race on the in-memory SQLite database: all sessions
    share one connection, so a poll's commit lands in the middle of the flusher's statements
    ("cannot commit transaction - SQL statements in progress", ~40% of runs on Python 3.11).
    Engines submit from spawned tasks, hence the short settle before draining. Call it once,
    last: the buffer stays stopped for the rest of the test.
    """
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    await asyncio.sleep(0.5)
    await event_buffer.get_buffer().stop()
    async with get_session() as session:
        rows = (
            (await session.execute(select(Alert).where(Alert.event_type == event_type)))
            .scalars()
            .all()
        )
    return list(rows)


# ── SNMP: snmpwalk ──────────────────────────────────────────────────────────


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split("."))


def _snmp(pdu_type: int, oid: str, **kw):
    from honeypot_mcp.engines import snmp

    request = snmp.parse_snmp(snmp.build_get_request(oid, pdu_type=pdu_type, **kw))
    assert request is not None
    return request


async def test_snmpwalk_visits_every_oid_once_in_order_and_ends_in_end_of_mib_view():
    """`snmpwalk` aborts with "OID not increasing" when GetNext returns the OID it was given;
    the old agent answered every GetNext with sysDescr, so no walk ever got past one line."""
    from honeypot_mcp.engines import snmp

    seen: list[str] = []
    oid = "1.3.6.1"
    last = b""
    for _ in range(200):
        last = snmp.build_response(_snmp(0xA1, oid))
        nxt = snmp.parse_snmp(last)["oids"][0]
        if nxt == oid:
            break
        seen.append(nxt)
        oid = nxt
    assert len(seen) > 10
    assert seen == sorted(set(seen), key=_oid_key), "every OID once, in lexicographic order"
    assert last.endswith(b"\x82\x00"), "the walk must end in endOfMibView"


async def test_snmp_v1_has_no_exceptions_so_a_missing_oid_is_nosuchname():
    from honeypot_mcp.engines import snmp

    for pdu_type, oid in ((0xA0, "1.3.6.1.2.1.1.99.0"), (0xA1, "1.3.6.1.2.1.2.2.1.8.4")):
        response = snmp.parse_snmp(snmp.build_response(_snmp(pdu_type, oid, version=0)))
        assert response["error_status"] == 2  # noSuchName
        assert response["error_index"] == 1


async def test_snmp_v2c_unknown_oid_is_nosuchobject_never_a_stand_in_value():
    from honeypot_mcp.engines import snmp

    response = snmp.build_response(_snmp(0xA0, "1.3.6.1.2.1.1.99.0"))
    assert response.endswith(b"\x80\x00")
    assert snmp._SYS_DESCR.encode() not in response


async def test_snmp_getbulk_returns_max_repetitions_successive_oids():
    from honeypot_mcp.engines import snmp

    request = _snmp(0xA5, "1.3.6.1.2.1.1.1", non_repeaters=0, max_repetitions=5)
    oids = snmp.parse_snmp(snmp.build_response(request))["oids"]
    assert len(oids) == 5
    assert oids == sorted(oids, key=_oid_key)


async def test_snmp_set_is_refused_as_not_writable_not_acknowledged():
    from honeypot_mcp.engines import snmp

    response = snmp.parse_snmp(snmp.build_response(_snmp(0xA3, "1.3.6.1.2.1.1.5.0")))
    assert response["error_status"] == 17  # notWritable


async def test_snmp_uptime_advances_between_reads(monkeypatch):
    """Two reads of sysUpTime that agree to the tick are a static decoy."""
    from honeypot_mcp.engines import snmp

    request = _snmp(0xA0, "1.3.6.1.2.1.1.3.0")
    first = snmp.build_response(request)
    monkeypatch.setattr(snmp, "_STARTED", snmp._STARTED - 10)
    assert snmp.build_response(request) != first


# ── LDAP: ldapsearch ────────────────────────────────────────────────────────


def _ldap_search(base: str, scope: int, attrs: list[str]) -> bytes:
    from honeypot_mcp.engines import ldap as ldap_mod

    tlv, enc_int = ldap_mod._tlv, ldap_mod._encode_int
    attributes = b"".join(tlv(0x04, a.encode()) for a in attrs)
    body = (
        tlv(0x04, base.encode())
        + enc_int(scope, 0x0A)
        + enc_int(0, 0x0A)
        + enc_int(0)
        + enc_int(0)
        + tlv(0x01, b"\x00")
        + tlv(0x87, b"objectClass")
        + tlv(0x30, attributes)
    )
    return tlv(0x30, enc_int(1) + tlv(0x63, body))


async def _ldap_exchange(request: bytes) -> bytes:
    from honeypot_mcp.engines.ldap import LDAPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("ldap-fid", HoneypotType.LDAP)
    engine = LDAPEngine()
    cid = await engine.start("ldap-fid", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        data = b""
        with contextlib.suppress(TimeoutError):
            while b"\x65" not in data[-14:] or len(data) < 8:
                data += await asyncio.wait_for(reader.read(65536), timeout=2.0)
        writer.close()
        return data
    finally:
        await engine.stop(cid)


async def test_ldap_rootdse_is_readable_anonymously_and_names_the_domain():
    """Every LDAP client reads the rootDSE first. An empty answer to it is how `ldapsearch`
    told the decoy from a domain controller."""
    data = await _ldap_exchange(_ldap_search("", 0, []))
    for expected in (
        b"namingContexts",
        b"DC=corp,DC=local",
        b"supportedLDAPVersion",
        b"dnsHostName",
    ):
        assert expected in data


async def test_ldap_rootdse_honours_the_requested_attribute_list():
    data = await _ldap_exchange(_ldap_search("", 0, ["defaultNamingContext"]))
    assert b"defaultNamingContext" in data
    assert b"supportedLDAPVersion" not in data


async def test_ldap_anonymous_search_below_the_root_is_refused_like_active_directory():
    data = await _ldap_exchange(_ldap_search("dc=corp,dc=local", 2, []))
    assert b"\x65" in data and b"\x0a\x01\x01" in data  # searchResDone, operationsError
    assert b"a successful bind must be completed" in data


# ── Kubernetes: kubectl ─────────────────────────────────────────────────────


async def _k8s():
    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("k8s-fid", HoneypotType.KUBERNETES)
    engine = KubernetesEngine()
    cid = await engine.start("k8s-fid", port, {})
    return engine, cid, port


async def test_kubernetes_api_speaks_tls_only():
    """kube-apiserver has no plaintext listener; like Go's net/http, plaintext HTTP to the
    TLS port is answered with a fixed 400 and never reaches the application."""
    import httpx

    engine, cid, port = await _k8s()
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            assert (await client.get(f"https://127.0.0.1:{port}/version")).status_code == 200
            plain = await client.get(f"http://127.0.0.1:{port}/version")
    finally:
        await engine.stop(cid)
    assert plain.status_code == 400
    assert plain.text == "Client sent an HTTP request to an HTTPS server.\n"
    assert "gitVersion" not in plain.text


async def test_kubernetes_identity_is_stable_across_requests():
    """A scanner that asks twice must get one cluster: commit, UIDs and pod names are fixed;
    only Audit-Id (per request in a real server) changes."""
    import httpx

    engine, cid, port = await _k8s()
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            base = f"https://127.0.0.1:{port}"
            first = [
                await client.get(base + p) for p in ("/version", "/api/v1/namespaces/default/pods")
            ]
            second = [
                await client.get(base + p) for p in ("/version", "/api/v1/namespaces/default/pods")
            ]
    finally:
        await engine.stop(cid)
    for a, b in zip(first, second, strict=True):
        assert a.json() == b.json()
        assert (
            a.headers["X-Kubernetes-Pf-Flowschema-Uid"]
            == b.headers["X-Kubernetes-Pf-Flowschema-Uid"]
        )
        assert a.headers["Audit-Id"] != b.headers["Audit-Id"]


async def test_kubernetes_kubectl_table_request_gets_a_table_with_the_columns_kubectl_prints():
    import httpx

    engine, cid, port = await _k8s()
    accept = "application/json;as=Table;v=v1;g=meta.k8s.io,application/json"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            base = f"https://127.0.0.1:{port}"
            pods = (
                await client.get(
                    base + "/api/v1/namespaces/default/pods", headers={"Accept": accept}
                )
            ).json()
            discovery = (await client.get(base + "/api/v1")).json()
            health = await client.get(base + "/healthz")
            deploys = (await client.get(base + "/apis/apps/v1/deployments")).json()
    finally:
        await engine.stop(cid)
    assert pods["kind"] == "Table"
    assert [c["name"] for c in pods["columnDefinitions"][:5]] == [
        "Name",
        "Ready",
        "Status",
        "Restarts",
        "Age",
    ]
    assert pods["rows"][0]["cells"][1:3] == ["1/1", "Running"]
    # `kubectl get pods` needs the resource list; `po` and `ns` need shortNames in it.
    resources = {r["name"]: r for r in discovery["resources"]}
    assert resources["pods"]["shortNames"] == ["po"] and "pods/exec" in resources
    assert (health.status_code, health.text) == (200, "ok")
    assert deploys == {
        "kind": "DeploymentList",
        "apiVersion": "apps/v1",
        "metadata": {"resourceVersion": "48211"},
        "items": [],
    }


# ── SMB2: smbclient, impacket ───────────────────────────────────────────────


def _smb_login(port: int, user: str, password: str, domain: str) -> tuple[int, int]:
    """(negotiated dialect, NTSTATUS of the login) from impacket, a client we did not write."""
    from impacket.smbconnection import SessionError, SMBConnection

    conn = SMBConnection("127.0.0.1", "127.0.0.1", sess_port=port, timeout=10)
    dialect = conn.getDialect()
    try:
        conn.login(user, password, domain)
    except SessionError as exc:
        return dialect, exc.getErrorCode()
    finally:
        with contextlib.suppress(Exception):
            conn.close()
    return dialect, 0


async def _smb():
    from honeypot_mcp.engines.smb import SMBEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("smb-fid", HoneypotType.SMB)
    engine = SMBEngine()
    cid = await engine.start("smb-fid", port, {})
    return engine, cid, port


async def test_smb2_login_is_captured_as_a_netntlmv2_response_that_cracks():
    """Every current client starts with SMB2; the engine used to close on it, so no sprayer got
    far enough to hand over a credential. The captured response must verify against the
    password the client really used, or the hashcat line is worthless."""
    from honeypot_mcp.engines.rdp_nla import verify_ntlmv2

    engine, cid, port = await _smb()
    try:
        dialect, status = await asyncio.to_thread(_smb_login, port, "jsmith", "Summer2026!", "CORP")
        events = await _events("smb_ntlm_auth")
    finally:
        await engine.stop(cid)

    assert dialect == 0x0210
    assert status == 0xC000006D  # STATUS_LOGON_FAILURE: a login is never granted
    assert len(events) == 1
    p = events[0].payload
    assert (p["username"], p["domain"], p["ntlm_version"]) == ("jsmith", "CORP", "v2")
    assert p["hashcat_mode"] == "5600"
    challenge, nt = bytes.fromhex(p["server_challenge_hex"]), bytes.fromhex(p["nt_response_hex"])
    assert verify_ntlmv2(challenge, nt, "jsmith", "CORP", "Summer2026!")
    assert not verify_ntlmv2(challenge, nt, "jsmith", "CORP", "Summer2026")


async def test_smb2_login_with_a_planted_credential_trips_the_honeytoken():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="smb-decoy",
                token_value="cred:test:smb",
                status=HoneytokenStatus.ACTIVE,
                token_meta={
                    "service": "smb",
                    "credentials": [{"username": "svc-backup", "password": "Fall2026!Backup"}],
                    "count": 1,
                },
            )
        )
    credential_match.invalidate_cache()

    engine, cid, port = await _smb()
    try:
        await asyncio.to_thread(_smb_login, port, "svc-backup", "Fall2026!Backup", "CORP")
        tripped = await _events("honeytoken_triggered_credential_via_smb_ntlm_auth")
    finally:
        await engine.stop(cid)
    assert tripped and tripped[0].severity.value == "critical"


async def test_smb1_only_negotiate_still_gets_the_windows_persona_smb1_answer():
    """nmap and exploit tooling offer SMB1 dialects only and must keep getting an SMB1 reply
    that names the same host the NTLM challenge does."""
    from honeypot_mcp.engines.rdp_nla import identity_for

    engine, cid, port = await _smb()
    dialects = b"".join(b"\x02" + d + b"\x00" for d in (b"PC NETWORK PROGRAM 1.0", b"NT LM 0.12"))
    header = (
        b"\xffSMBr"
        + b"\x00" * 4
        + b"\x18\x01\x40"
        + b"\x00" * 12
        + b"\x00\x00\x40\x06\x00\x00\x01\x00"
    )
    smb = header + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x00" + len(smb).to_bytes(3, "big") + smb)
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        writer.close()
    finally:
        await engine.stop(cid)
    ident = identity_for("smb-fid")
    assert reply[4:8] == b"\xffSMB"
    assert ident.domain.encode("utf-16-le") in reply
    assert ident.computer.encode("utf-16-le") in reply


# ── MySQL: mariadb client ───────────────────────────────────────────────────


async def _mysql_packet(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    header = await asyncio.wait_for(reader.readexactly(4), timeout=3.0)
    length = int.from_bytes(header[:3], "little")
    return header[3], await asyncio.wait_for(reader.readexactly(length), timeout=3.0)


async def test_mysql_auth_switch_captures_the_password_of_a_client_that_names_another_plugin():
    """libmariadb's first packet names `dummy_fallback_auth` and carries no password; it waits
    for the server to say which plugin to use. An immediate OK made that client report a protocol
    error, and the password was never captured."""
    from honeypot_mcp.credential_verify import mysql_native_token
    from honeypot_mcp.engines.mysql import MySQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mysql-fid", HoneypotType.MYSQL)
    engine = MySQLEngine()
    cid = await engine.start("mysql-fid", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _mysql_packet(reader)  # server greeting
        flags = (
            0x00000200 | 0x00008000 | 0x00080000
        )  # PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH
        response = (
            struct.pack("<IIB", flags, 1 << 24, 45)
            + b"\x00" * 23
            + b"root\x00"
            + b"\x00"  # empty auth response
            + b"dummy_fallback_auth\x00"
        )
        writer.write(struct.pack("<I", len(response))[:3] + b"\x01" + response)
        await writer.drain()

        seq, switch = await _mysql_packet(reader)
        assert switch[0] == 0xFE and switch[1:].startswith(b"mysql_native_password\x00")
        salt = switch[1 + len(b"mysql_native_password\x00") : -1]
        assert len(salt) == 20
        scramble = mysql_native_token(b"Root123", salt)
        writer.write(struct.pack("<I", len(scramble))[:3] + bytes([seq + 1]) + scramble)
        await writer.drain()
        _, ok = await _mysql_packet(reader)
        writer.close()
    finally:
        await engine.stop(cid)

    assert ok[0] == 0x00
    p = (await _events("mysql_login_attempt"))[0].payload
    assert p["username"] == "root"
    assert p["auth_plugin"] == "dummy_fallback_auth"
    assert "database" not in p, "the plugin name was being filed as the database"
    assert p["auth_response_hex"] == scramble.hex()


async def test_mysql_show_databases_returns_the_default_schemas_as_a_result_set():
    """The mariadb client printed nothing for `show databases`: the reply was a bare OK."""
    from honeypot_mcp.engines.mysql import MySQLEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("mysql-fid2", HoneypotType.MYSQL)
    engine = MySQLEngine()
    cid = await engine.start("mysql-fid2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await _mysql_packet(reader)
        flags = 0x00000200 | 0x00008000 | 0x00080000
        response = (
            struct.pack("<IIB", flags, 1 << 24, 45)
            + b"\x00" * 23
            + b"root\x00\x14"
            + b"\x00" * 20
            + b"mysql_native_password\x00"
        )
        writer.write(struct.pack("<I", len(response))[:3] + b"\x01" + response)
        await writer.drain()
        await _mysql_packet(reader)  # OK
        query = b"\x03show databases"
        writer.write(struct.pack("<I", len(query))[:3] + b"\x00" + query)
        await writer.drain()
        packets: list[bytes] = []
        eofs = 0
        while eofs < 2:
            _, body = await _mysql_packet(reader)
            packets.append(body)
            eofs += body[:1] == b"\xfe" and len(body) < 9
        writer.close()
    finally:
        await engine.stop(cid)
    # column count, column definition, EOF, one row per database, EOF
    rows = [p[1 : 1 + p[0]].decode() for p in packets[3:-1]]
    assert rows == ["information_schema", "mysql", "performance_schema", "sys"]


# ── MSSQL: impacket mssqlclient ─────────────────────────────────────────────


def _tds_tokens(packet: bytes) -> tuple[bytes, bytes]:
    """(ERROR token body, bytes after it) from a TDS response packet."""
    payload = packet[8:]
    assert payload[0] == 0xAA
    (length,) = struct.unpack_from("<H", payload, 1)
    return payload[3 : 3 + length], payload[3 + length :]


@pytest.mark.parametrize(
    ("tds_version", "done_len", "line_len"),
    [(0x71000001, 1 + 2 + 2 + 4, 2), (0x74000004, 1 + 2 + 2 + 8, 4)],
)
async def test_mssql_login_failure_uses_the_tds_version_the_client_negotiated(
    tds_version, done_len, line_len
):
    """impacket asks for TDS 7.1 and parsed the 7.2+ DONE row count as a stray token."""
    from honeypot_mcp.engines import mssql

    error, rest = _tds_tokens(mssql._build_login_error(tds_version, "sa"))
    assert len(rest) == done_len and rest[0] == 0xFD
    text = "Login failed for user 'sa'.".encode("utf-16-le")
    assert text in error
    # number(4) state(1) class(1) msg-len(2) msg  server-len(1) server  proc-len(1)  line
    assert len(error) == 4 + 1 + 1 + 2 + len(text) + 1 + len("SQL01") * 2 + 1 + line_len


# ── PostgreSQL: psql, nmap ──────────────────────────────────────────────────


async def test_postgresql_startup_errors_carry_source_location_fields():
    """A real ErrorResponse always ends F(file) L(line) R(routine); nmap reads the line number
    to name the version and the decoy was identified as only "PostgreSQL DB"."""
    from honeypot_mcp.engines import postgresql

    frame = postgresql._error_response(
        "FATAL", "0A000", "unsupported frontend protocol 1.0", postgresql._SRC_UNSUPPORTED_PROTOCOL
    )
    assert frame.endswith(b"Fpostmaster.c\x00L2142\x00RProcessStartupPacket\x00\x00")
    assert struct.unpack_from("!I", frame, 1)[0] == len(frame) - 1


@pytest.mark.parametrize(
    ("sql", "tag"),
    [
        ("create table t (a int)", "CREATE TABLE"),
        ("INSERT INTO t VALUES (1)", "INSERT 0 1"),
        ("set application_name = 'x'", "SET"),
        ("copy t to program 'id'", "COPY 0"),
        ("drop table t;", "DROP TABLE"),
    ],
)
async def test_postgresql_command_tags_are_the_ones_a_real_server_sends(sql, tag):
    from honeypot_mcp.engines.postgresql import _command_tag

    assert _command_tag(sql) == tag


async def test_postgresql_version_string_agrees_with_the_server_version_parameter():
    from honeypot_mcp.engines import postgresql

    assert "14.10 (Debian 14.10-1.pgdg120+1)" in postgresql._VERSION_STRING


# ── Redis: redis-cli ────────────────────────────────────────────────────────


async def _redis(*commands: list[str]) -> list[bytes]:
    from honeypot_mcp.engines.redis import RedisEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("redis-fid", HoneypotType.REDIS)
    engine = RedisEngine()
    cid = await engine.start("redis-fid", port, {})
    replies: list[bytes] = []
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for command in commands:
            writer.write(
                f"*{len(command)}\r\n".encode()
                + b"".join(f"${len(a)}\r\n{a}\r\n".encode() for a in command)
            )
            await writer.drain()
            replies.append(await asyncio.wait_for(reader.read(4096), timeout=2.0))
        writer.close()
    finally:
        await engine.stop(cid)
    return replies


async def test_redis_unknown_command_error_has_the_redis_7_wording():
    (reply,) = await _redis(["FOO", "bar", "baz"])
    assert reply == b"-ERR unknown command 'FOO', with args beginning with: 'bar' 'baz' \r\n"


async def test_redis_client_subcommands_that_libraries_send_on_connect_are_answered():
    """redis-py >= 5 sends CLIENT SETINFO on every connection."""
    ident, setname, getname, setinfo, listing = await _redis(
        ["CLIENT", "ID"],
        ["CLIENT", "SETNAME", "scanner"],
        ["CLIENT", "GETNAME"],
        ["CLIENT", "SETINFO", "LIB-NAME", "redis-py"],
        ["CLIENT", "LIST"],
    )
    assert ident.startswith(b":")
    assert setname == b"+OK\r\n" and setinfo == b"+OK\r\n"
    assert getname == b"$7\r\nscanner\r\n"
    assert b"name=scanner" in listing and b"cmd=client|list" in listing


# ── Kubernetes: single objects, describe, watch ─────────────────────────────


async def test_kubernetes_single_object_gets_agree_with_the_list_and_missing_ones_404_like_k8s():
    """`kubectl get pod X`, `describe` and `-o yaml` GET one object by name; before, every one
    of them was a 404 no real cluster gives for a pod it just listed."""
    import httpx

    engine, cid, port = await _k8s()
    accept = "application/json;as=Table;v=v1;g=meta.k8s.io,application/json"
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            base = f"https://127.0.0.1:{port}"
            listed = (await client.get(base + "/api/v1/namespaces/default/pods")).json()["items"][0]
            name = listed["metadata"]["name"]
            one = (await client.get(base + f"/api/v1/namespaces/default/pods/{name}")).json()
            table = (
                await client.get(
                    base + f"/api/v1/namespaces/default/pods/{name}", headers={"Accept": accept}
                )
            ).json()
            missing = await client.get(base + "/api/v1/namespaces/default/pods/nope")
            namespace = (await client.get(base + "/api/v1/namespaces/payments")).json()
            no_namespace = await client.get(base + "/api/v1/namespaces/bogus")
            node = (await client.get(base + "/api/v1/nodes/ip-10-0-1-42.ec2.internal")).json()
            other_ns = (await client.get(base + "/api/v1/namespaces/bogus/pods")).json()
            system = (await client.get(base + "/api/v1/namespaces/kube-system/pods")).json()
            events = (await client.get(base + "/api/v1/namespaces/default/events")).json()
    finally:
        await engine.stop(cid)
    assert one == {"kind": "Pod", "apiVersion": "v1", **listed}
    assert table["kind"] == "Table" and [r["cells"][0] for r in table["rows"]] == [name]
    assert missing.status_code == 404
    assert missing.json()["details"] == {"name": "nope", "kind": "pods"}
    assert missing.json()["message"] == 'pods "nope" not found'
    assert namespace["kind"] == "Namespace" and namespace["metadata"]["name"] == "payments"
    assert no_namespace.status_code == 404
    assert node["kind"] == "Node"
    assert other_ns["items"] == [], "a namespace that does not exist has no pods"
    assert {i["metadata"]["name"].rsplit("-", 2)[0] for i in system["items"]} == {
        "coredns",
        "kube-proxy",
    }
    assert events["kind"] == "EventList" and events["items"] == []


async def test_kubernetes_watch_replays_current_objects_then_ends_at_timeoutseconds():
    import httpx

    engine, cid, port = await _k8s()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            base = f"https://127.0.0.1:{port}"
            started = asyncio.get_running_loop().time()
            fresh = await client.get(
                base + "/api/v1/namespaces/default/pods?watch=true&timeoutSeconds=1"
            )
            resumed = await client.get(
                base
                + "/api/v1/namespaces/default/pods?watch=true&timeoutSeconds=1&resourceVersion=30002"
            )
            elapsed = asyncio.get_running_loop().time() - started
    finally:
        await engine.stop(cid)
    events = [json.loads(line) for line in fresh.text.splitlines()]
    assert [e["type"] for e in events] == ["ADDED"] * 3
    assert all(e["object"]["kind"] == "Pod" for e in events)
    assert fresh.headers["Transfer-Encoding"] == "chunked"
    assert resumed.text == "", "a client that resumed from a resourceVersion is not replayed"
    assert 1.5 < elapsed < 6, "each watch ends at the client's timeoutSeconds"
