"""Replaying a capture through Suricata or Zeek: the sandbox, the parsers, the tools.

A fake Docker client stands in for the daemon so every argument the module hands Docker can be
pinned (no network, read-only root, capabilities dropped, a read-only mount of the pcap, removal on
success, timeout and exception) and every failure path driven. The fake "engine" writes realistic
output files into the output directory it was given, so the parsers run against EVE and Zeek JSON
shaped like the real ones. What a fake cannot show (that the pinned images really read an
SLL2-framed capture offline under these flags) is in
`tests/integration/test_pcap_detect_real.py`.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import os
import stat
import struct
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import docker.errors
import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

# ── a capture ────────────────────────────────────────────────────────────────────────────────


def make_pcap(path: Path, packets: int = 3, *, link: int = 276, start: float = 1_760_000_000.0):
    """A structurally valid pcap (the engines are fake, only the headers are read)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link))
    for i in range(packets):
        frame = bytes(20 + i)
        ts = start + i * 2
        data += struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000), len(frame), len(frame))
        data += frame
    path.write_bytes(bytes(data))
    return path


# ── realistic engine output ──────────────────────────────────────────────────────────────────

_FLOW = {"src_ip": "192.0.2.10", "dest_ip": "198.51.100.5", "src_port": 51912, "dest_port": 5060}


def _eve(**kw: Any) -> str:
    base = {
        "timestamp": "2026-10-12T00:13:19.793805+0000",
        "flow_id": 2001992742426906,
        "src_ip": "192.0.2.10",
        "src_port": 51912,
        "dest_ip": "198.51.100.5",
        "dest_port": 5060,
        "proto": "UDP",
        "ip_v": 4,
        "pkt_src": "wire/pcap",
    }
    base.update(kw)
    return json.dumps(base)


def _alert(sid: int, msg: str, *, cat: str, sev: int, ts: str, src="192.0.2.10", **kw) -> str:
    return _eve(
        timestamp=ts,
        event_type="alert",
        src_ip=src,
        dest_ip="198.51.100.5" if src == "192.0.2.10" else "192.0.2.10",
        alert={
            "action": "allowed",
            "gid": 1,
            "signature_id": sid,
            "rev": 4,
            "signature": msg,
            "category": cat,
            "severity": sev,
        },
        app_proto="sip",
        direction="to_server",
        flow={**_FLOW, "pkts_toserver": 1, "pkts_toclient": 0},
        # The engine can be configured to log these; they must never reach a result.
        payload="SECRET-PAYLOAD-BYTES",
        payload_printable="SECRET-PAYLOAD-PRINTABLE",
        packet="U0VDUkVULVBBQ0tFVA==",
        **kw,
    )


EVE_LINES = [
    _eve(
        event_type="sip",
        timestamp="2026-10-12T00:13:19.793805+0000",
        sip={
            "method": "INVITE",
            "uri": "sip:00421232229874@198.51.100.5",
            "version": "SIP/2.0",
            "request_line": "INVITE sip:00421232229874@198.51.100.5 SIP/2.0",
        },
    ),
    _eve(
        event_type="sip",
        timestamp="2026-10-12T00:13:19.900000+0000",
        src_ip="198.51.100.5",
        dest_ip="192.0.2.10",
        sip={"code": "407", "reason": "Proxy Authentication Required", "version": "SIP/2.0"},
    ),
    _eve(
        event_type="sip",
        timestamp="2026-10-12T00:13:20.000000+0000",
        sip={"method": "REGISTER", "uri": "sip:198.51.100.5"},
    ),
    _alert(
        2100158,
        "GPL VOIP SIP INVITE message flooding",
        cat="Attempted Denial of Service",
        sev=2,
        ts="2026-10-12T00:20:00.000000+0000",
    ),  # fmt: skip
    _alert(
        2100158,
        "GPL VOIP SIP INVITE message flooding",
        cat="Attempted Denial of Service",
        sev=2,
        ts="2026-10-12T00:21:00.000000+0000",
    ),  # fmt: skip
    _alert(
        2200075,
        "SURICATA UDPv4 invalid checksum",
        cat="Generic Protocol Command Decode",
        sev=3,
        ts="2026-10-12T00:13:19.794495+0000",
        src="198.51.100.5",
    ),  # fmt: skip
    _eve(
        event_type="flow",
        timestamp="2026-10-12T00:12:46.814090+0000",
        app_proto="sip",
        flow={
            "pkts_toserver": 6,
            "pkts_toclient": 6,
            "bytes_toserver": 3426,
            "bytes_toclient": 2782,
            "start": "2026-10-12T00:12:46.814090+0000",
            "state": "established",
            "reason": "timeout",
            "alerted": True,
        },
    ),  # fmt: skip
    _eve(
        event_type="dns",
        timestamp="2026-10-12T00:14:00.000000+0000",
        dest_port=53,
        dns={"type": "query", "id": 1, "rrname": "Example.Test", "rrtype": "A"},
    ),  # fmt: skip
    _eve(
        event_type="dns",
        timestamp="2026-10-12T00:14:01.000000+0000",
        dest_port=53,
        dns={
            "type": "answer",
            "id": 1,
            "rrname": "example.test",
            "rrtype": "A",
            "rcode": "NOERROR",
        },
    ),  # fmt: skip
    _eve(
        event_type="http",
        timestamp="2026-10-12T00:15:00.000000+0000",
        dest_port=80,
        http={
            "hostname": "bait.test",
            "url": "/.env",
            "http_user_agent": "curl/8.4.0",
            "http_method": "GET",
            "status": 404,
        },
    ),  # fmt: skip
    _eve(
        event_type="tls",
        timestamp="2026-10-12T00:16:00.000000+0000",
        dest_port=443,
        tls={"sni": "Secure.Example.Test", "version": "TLS 1.2"},
    ),  # fmt: skip
    _eve(
        event_type="ssh",
        timestamp="2026-10-12T00:17:00.000000+0000",
        dest_port=22,
        ssh={
            "client": {"proto_version": "2.0", "software_version": "paramiko_3.4.0"},
            "server": {"proto_version": "2.0", "software_version": "OpenSSH_8.0"},
        },
    ),  # fmt: skip
    _eve(
        event_type="anomaly",
        timestamp="2026-10-12T00:18:00.000000+0000",
        anomaly={
            "type": "applayer",
            "event": "APPLAYER_WRONG_DIRECTION_FIRST_DATA",
            "layer": "proto",
        },
    ),  # fmt: skip
    _eve(
        event_type="fileinfo",
        timestamp="2026-10-12T00:19:00.000000+0000",
        fileinfo={
            "filename": "/dropper.sh",
            "size": 120,
            "magic": "ASCII text",
            "state": "CLOSED",
            "sha256": "0" * 64,
        },
    ),  # fmt: skip
    json.dumps(
        {
            "timestamp": "2026-10-16T23:10:43.064106+0000",
            "event_type": "stats",
            "stats": {
                "uptime": 10,
                "decoder": {"pkts": 18, "bytes": 9000, "invalid": 0},
                "flow": {"total": 1},
                "detect": {"alert": 3, "alerts_suppressed": 0},
                "tcp": {"reassembly_gap": 2},
            },
        }
    ),
]

SURICATA_LOG = (
    "Notice: suricata: This is Suricata version 8.0.7 RELEASE running in USER mode\n"
    "Info: detect: 1 rule files processed. 53211 rules successfully loaded, 0 rules failed, "
    "0 rules skipped\n"
    "Notice: pcap: read 1 file, 18 packets, 9000 bytes\n"
)

ZEEK_LOGS: dict[str, list[dict[str, Any]]] = {
    "conn": [
        {"ts": 1791763966.8, "uid": "C1", "id.orig_h": "192.0.2.10", "id.orig_p": 40000,
         "id.resp_h": "198.51.100.5", "id.resp_p": 5060, "proto": "udp", "service": "sip",
         "conn_state": "SF", "history": "Dd", "orig_bytes": 700, "resp_bytes": 300},
        {"ts": 1791763970.0, "uid": "C2", "id.orig_h": "192.0.2.10", "id.orig_p": 40001,
         "id.resp_h": "198.51.100.5", "id.resp_p": 23, "proto": "tcp",
         "conn_state": "S0", "history": "S"},
        {"ts": 1791763971.0, "uid": "C3", "id.orig_h": "203.0.113.9", "id.orig_p": 40002,
         "id.resp_h": "198.51.100.5", "id.resp_p": 3389, "proto": "tcp",
         "conn_state": "REJ", "history": "Sr"},
        {"ts": 1791763972.0, "uid": "C4", "id.orig_h": "203.0.113.9", "id.orig_p": 40003,
         "id.resp_h": "198.51.100.5", "id.resp_p": 22, "proto": "tcp", "service": "ssh",
         "conn_state": "SF", "history": "ShADadFf", "orig_bytes": 50, "resp_bytes": 60},
    ],
    "notice": [
        {"ts": 1791763980.0, "note": "Scan::Port_Scan", "msg": "192.0.2.10 scanned 15 ports",
         "src": "192.0.2.10", "dst": "198.51.100.5"},
        {"ts": 1791763981.0, "note": "Scan::Port_Scan", "msg": "192.0.2.10 scanned 15 ports",
         "src": "192.0.2.10"},
    ],
    "weird": [
        {"ts": 1791763990.0, "name": "bad_TCP_checksum", "id.orig_h": "192.0.2.10"},
        {"ts": 1791763991.0, "name": "bad_TCP_checksum", "id.orig_h": "203.0.113.9"},
        {"ts": 1791763992.0, "name": "data_before_established", "id.orig_h": "192.0.2.10"},
    ],
    "dns": [
        {"ts": 1.0, "query": "Example.Test", "qtype_name": "A", "rcode_name": "NOERROR"},
        {"ts": 2.0, "query": "example.test", "qtype_name": "AAAA", "rcode_name": "NXDOMAIN"},
    ],
    "http": [
        {"ts": 1.0, "host": "bait.test", "method": "GET", "uri": "/.env",
         "user_agent": "curl/8.4.0", "status_code": 404},
    ],
    "ssh": [
        {"ts": 1.0, "client": "SSH-2.0-paramiko_3.4.0", "server": "SSH-2.0-OpenSSH_8.0",
         "auth_attempts": 3, "auth_success": False},
    ],
    "sip": [
        {"ts": 1.0, "method": "INVITE", "uri": "sip:00421232229874@198.51.100.5",
         "user_agent": "Linksys-SPA942", "status_code": 407,
         "request_from": "<sip:1000@198.51.100.5>"},
        {"ts": 2.0, "method": "REGISTER", "uri": "sip:198.51.100.5",
         "user_agent": "Linksys-SPA942", "status_code": 401},
    ],
    "ssl": [
        {"ts": 1.0, "server_name": "Secure.Example.Test", "version": "TLSv12",
         "cipher": "TLS_AES_128_GCM_SHA256", "established": True},
    ],
    "files": [
        {"ts": 1.0, "source": "HTTP", "mime_type": "application/x-sh", "seen_bytes": 120,
         "sha1": "a" * 40, "md5": "b" * 32},
    ],
    "software": [
        {"ts": 1.0, "software_type": "HTTP::SERVER", "name": "nginx", "unparsed_version": "nginx/1.25"},
    ],
    "reporter": [{"ts": 1.0, "level": "Reporter::WARNING", "message": "a script warning"}],
}  # fmt: skip


# ── a fake Docker daemon ─────────────────────────────────────────────────────────────────────


class FakeContainer:
    def __init__(self, client: FakeClient, spec: dict[str, Any]) -> None:
        self.client = client
        self.spec = spec
        self.name = f"c{next(client.ids):04d}"
        self.labels = dict(spec.get("labels", {}))
        self.status = "created"
        self.attrs: dict[str, Any] = {
            "Created": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "State": {"ExitCode": 0, "OOMKilled": False},
        }
        self.mounts = {
            v["bind"]: (Path(host), v["mode"]) for host, v in spec.get("volumes", {}).items()
        }
        self.logs_text = ""
        self.killed = False
        self.removed_with_volumes: bool | None = None

    def start(self) -> None:
        if self.client.fail_start:
            raise docker.errors.APIError(self.client.fail_start)
        self.status = "running"
        self.client.runner(self)
        if not self.client.hang:
            self.status = "exited"

    def reload(self) -> None:
        pass

    def kill(self) -> None:
        self.killed = True
        self.status = "exited"
        self.attrs["State"]["ExitCode"] = 137

    def logs(self, stdout: bool = True, stderr: bool = True, tail: int = 100) -> bytes:
        return self.logs_text.encode()

    def remove(self, force: bool = False, v: bool = False) -> None:
        self.removed_with_volumes = v
        if self not in self.client.store:
            raise docker.errors.NotFound("gone")
        self.client.store.remove(self)
        self.client.removed.append(self)


class FakeContainers:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def create(self, **spec: Any) -> FakeContainer:
        if self.client.fail_create:
            raise docker.errors.APIError(self.client.fail_create)
        c = FakeContainer(self.client, spec)
        self.client.created.append(c)
        self.client.store.append(c)
        return c

    def list(self, all: bool = False, filters: dict[str, str] | None = None) -> list[Any]:
        out = list(self.client.store)
        if filters and "label" in filters:
            key, _, value = filters["label"].partition("=")
            out = [c for c in out if c.labels.get(key) == value]
        return out


class FakeImages:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def get(self, name: str) -> object:
        if not self.client.have_image:
            raise docker.errors.ImageNotFound(name)
        return object()

    def pull(self, repo: str, tag: str | None = None) -> None:
        if self.client.pull_error:
            raise self.client.pull_error
        self.client.pulled.append(f"{repo}:{tag}")
        self.client.have_image = True


class FakeClient:
    def __init__(self) -> None:
        self.ids = itertools.count(1)
        self.store: list[FakeContainer] = []
        self.created: list[FakeContainer] = []
        self.removed: list[FakeContainer] = []
        self.pulled: list[str] = []
        self.have_image = True
        self.pull_error: Exception | None = None
        self.fail_create: str | None = None
        self.fail_start: str | None = None
        self.hang = False
        self.runner = self.run_suricata
        self.containers = FakeContainers(self)
        self.images = FakeImages(self)
        # What the engine saw at the moment it ran (the staging directory is gone afterwards).
        self.seen: list[dict[str, Any]] = []
        self.eve_lines: list[str] = list(EVE_LINES)
        self.suricata_log = SURICATA_LOG
        self.exit_code = 0
        self.oom = False
        self.zeek_logs: dict[str, list[dict[str, Any]]] = {k: list(v) for k, v in ZEEK_LOGS.items()}

    def ping(self) -> bool:
        return True

    # engines ---------------------------------------------------------------------------

    def _observe(self, c: FakeContainer) -> dict[str, Any]:
        seen: dict[str, Any] = {"container": c}
        cap = c.mounts.get("/in")
        if cap:
            host, mode = cap
            seen["in_mode"] = mode
            seen["in_bytes"] = (host / "capture.pcap").read_bytes()
            seen["root_mode"] = stat.S_IMODE(host.parent.stat().st_mode)
            seen["root"] = host.parent
        rules = c.mounts.get("/rules")
        if rules and (rules[0] / "all.rules").exists():
            seen["rules"] = (rules[0] / "all.rules").read_text()
            seen["classification"] = (rules[0] / "classification.config").exists()
        self.seen.append(seen)
        c.attrs["State"]["ExitCode"] = self.exit_code
        c.attrs["State"]["OOMKilled"] = self.oom
        return seen

    def run_suricata(self, c: FakeContainer) -> None:
        self._observe(c)
        out = c.mounts["/out"][0]
        (out / "eve.json").write_text("\n".join(self.eve_lines) + "\n")
        (out / "stats.log").write_text("stats")
        c.logs_text = self.suricata_log

    def run_zeek(self, c: FakeContainer) -> None:
        self._observe(c)
        out = c.mounts["/out"][0]
        for name, rows in self.zeek_logs.items():
            (out / f"{name}.log").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        c.logs_text = ""


# ── fixtures ─────────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()
    # A persistent database creates its engine lazily; open it once before anything patches settings.
    async with get_session():
        pass
    yield
    await asyncio.sleep(0.05)
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture(autouse=True)
def scratch_tempdir(tmp_path, monkeypatch):
    """Working directories go under the test's own tmp dir."""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    return scratch


@pytest.fixture(autouse=True)
def fast_poll(monkeypatch):
    from honeypot_mcp import pcap_detect

    monkeypatch.setattr(pcap_detect, "_POLL_SECONDS", 0.01)


@pytest.fixture
def docker_client(monkeypatch):
    from honeypot_mcp import pcap_detect

    client = FakeClient()
    monkeypatch.setattr(pcap_detect, "_docker_client", lambda: client)
    return client


@pytest.fixture
def capture(tmp_path):
    from honeypot_mcp.config import get_settings

    path = make_pcap(Path(get_settings().reports_dir) / "pcap-192.0.2.10-20261012T031612Z.pcap")
    return path


@pytest.fixture
def rules_cache(tmp_path):
    """A cached ruleset as `detection_rules_update` leaves it."""
    from honeypot_mcp.config import get_settings

    cache = Path(get_settings().detection_rules_dir)
    cache.mkdir(parents=True, mode=0o700)
    (cache / "suricata.rules").write_text('alert udp any any -> any 5060 (msg:"ET TEST"; sid:1;)\n')
    (cache / "classification.config").write_text("config classification: x,y,3\n")
    (cache / "ruleset.json").write_text(
        json.dumps(
            {
                "name": "Emerging Threats Open",
                "retrieved_at": "2026-10-16T23:19:19+00:00",
                "suricata_version": "8.0.7",
            }
        )
    )
    return cache


async def _audit_rows():
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    async with get_session() as session:
        return (await session.execute(select(AuditLog))).scalars().all()


def _no_docker(monkeypatch):
    from honeypot_mcp import pcap_detect

    def boom():
        raise AssertionError("Docker must not be consulted")

    monkeypatch.setattr(pcap_detect, "_docker_client", boom)


# ── what Docker is asked to run ──────────────────────────────────────────────────────────────


def _assert_sandboxed(spec: dict[str, Any]) -> None:
    assert spec["network_mode"] == "none"
    assert spec["read_only"] is True
    assert spec["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in spec["security_opt"]
    assert spec["user"] not in ("", "root", "0", "0:0")
    assert spec["labels"]["honeypot-mcp"] == "detect"
    assert spec["mem_limit"] == spec["memswap_limit"]
    assert spec["pids_limit"] > 0
    assert spec["nano_cpus"] > 0
    assert "noexec" in spec["tmpfs"]["/tmp"]
    assert "privileged" not in spec
    assert "ports" not in spec


async def test_suricata_container_is_sandboxed(docker_client, capture, rules_cache):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    result = await pcap_detect(capture.name, engine="suricata")

    assert "error" not in result, result
    spec = docker_client.created[0].spec
    _assert_sandboxed(spec)
    assert spec["image"] == get_settings().detection_suricata_image == "jasonish/suricata:8.0.7"
    assert spec["user"] == "suricata"
    assert spec["entrypoint"] == ["/usr/bin/suricata"]
    cmd = spec["command"]
    assert cmd[cmd.index("-r") + 1] == "/in/capture.pcap"
    assert cmd[cmd.index("-k") + 1] == "none"
    assert cmd[cmd.index("--runmode") + 1] == "single"
    assert cmd[cmd.index("-l") + 1] == "/out"
    assert cmd[cmd.index("-S") + 1] == "/rules/all.rules"
    modes = {v["bind"]: v["mode"] for v in spec["volumes"].values()}
    assert modes == {"/in": "ro", "/out": "rw", "/rules": "ro"}
    assert spec["mem_limit"] == f"{get_settings().detection_memory_mb}m"


async def test_zeek_container_is_sandboxed(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.runner = docker_client.run_zeek
    result = await pcap_detect(capture.name, engine="zeek")

    assert "error" not in result, result
    spec = docker_client.created[0].spec
    _assert_sandboxed(spec)
    assert spec["image"] == "zeek/zeek:8.0.10"
    assert spec["user"] == "nobody"
    assert spec["command"][:2] == ["zeek", "-C"]
    assert "LogAscii::use_json=T" in spec["command"]
    assert spec["working_dir"] == "/out"
    assert {v["bind"]: v["mode"] for v in spec["volumes"].values()} == {"/in": "ro", "/out": "rw"}


async def test_the_pcap_is_a_private_copy_mounted_read_only(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    original = capture.read_bytes()
    await pcap_detect(capture.name)

    seen = docker_client.seen[0]
    assert seen["in_mode"] == "ro"
    assert seen["in_bytes"] == original
    assert seen["root_mode"] == 0o700, "the staging directory must be private to the server's user"
    # Nothing of the original's directory is mounted: the volume is the staged copy's directory.
    assert Path(seen["root"]) != capture.parent
    assert capture.read_bytes() == original


async def test_working_directory_is_removed_after_a_run(docker_client, capture, scratch_tempdir):
    from honeypot_mcp.tools.detect import pcap_detect

    await pcap_detect(capture.name)

    assert not docker_client.seen[0]["root"].exists()
    assert list(scratch_tempdir.iterdir()) == []


async def test_container_is_removed_after_success(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    await pcap_detect(capture.name)

    assert len(docker_client.created) == 1
    assert docker_client.store == []
    assert docker_client.removed == docker_client.created
    assert docker_client.removed[0].removed_with_volumes is True


async def test_container_is_killed_and_removed_on_timeout(docker_client, capture, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.hang = True
    monkeypatch.setattr(get_settings(), "detection_timeout_seconds", 0.15)

    result = await pcap_detect(capture.name)

    assert "did not finish within" in result["error"]
    assert "hint" in result
    assert docker_client.created[0].killed
    assert docker_client.store == [], "a timed-out container must not be left behind"
    assert docker_client.removed == docker_client.created
    assert not docker_client.seen[0]["root"].exists()


async def test_container_is_removed_when_start_fails(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.fail_start = "OCI runtime create failed: boom"
    result = await pcap_detect(capture.name)

    assert "error" in result and "Traceback" not in json.dumps(result)
    assert docker_client.store == []
    assert docker_client.removed == docker_client.created


async def test_container_is_removed_when_reading_logs_raises(docker_client, capture, monkeypatch):
    from honeypot_mcp.tools.detect import pcap_detect

    def boom(self, **kw):
        raise RuntimeError("daemon went away")

    monkeypatch.setattr(FakeContainer, "logs", boom)
    result = await pcap_detect(capture.name)

    # An unreadable log is not fatal; the container is gone either way.
    assert docker_client.store == []
    assert "error" not in result or "Traceback" not in json.dumps(result)


async def test_oversize_output_kills_the_engine(docker_client, capture, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    def flood(c):
        docker_client._observe(c)
        (c.mounts["/out"][0] / "eve.json").write_bytes(b"x" * (2 * 1024 * 1024))

    docker_client.runner = flood
    docker_client.hang = True
    monkeypatch.setattr(get_settings(), "detection_max_output_mb", 1)

    result = await pcap_detect(capture.name)

    assert "wrote more than 1 MB" in result["error"]
    assert docker_client.created[0].killed
    assert docker_client.store == []


async def test_out_of_memory_is_reported_with_the_setting_to_raise(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.exit_code = 137
    docker_client.oom = True
    result = await pcap_detect(capture.name)

    assert "ran out of memory" in result["error"]
    assert "DETECTION_MEMORY_MB" in result["hint"]


async def test_engine_crash_is_an_error_not_a_traceback(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.exit_code = 1
    docker_client.suricata_log = "Error: pcap: pcap file reader thread failed to initialize\n"
    result = await pcap_detect(capture.name)

    assert "exited with status 1" in result["error"]
    assert "pcap file reader thread failed" in result["error"]
    assert "Traceback" not in json.dumps(result)


async def test_only_the_rules_update_is_given_a_network(docker_client, capture, rules_cache):
    """The whole point of the split: a replay can never reach out, whatever it is replaying."""
    from honeypot_mcp.tools.detect import detection_rules_update, pcap_detect

    docker_client.have_image = False  # the first run pulls an image, from the Docker client
    await pcap_detect(capture.name, engine="suricata")
    docker_client.runner = docker_client.run_zeek
    await pcap_detect(capture.name, engine="zeek")
    detect_specs = list(docker_client.created)
    assert detect_specs and all(c.spec["network_mode"] == "none" for c in detect_specs)
    assert all(c.spec.get("entrypoint") != ["suricata-update"] for c in detect_specs)

    docker_client.runner = _update_runner(docker_client)
    result = await detection_rules_update()
    assert "error" not in result, result

    update_specs = docker_client.created[len(detect_specs) :]
    networked = [c.spec for c in update_specs if c.spec["network_mode"] != "none"]
    assert len(networked) == 1
    assert networked[0]["entrypoint"] == ["suricata-update"]
    # The validation of the downloaded rules is a separate container with no network.
    assert any(c.spec["network_mode"] == "none" and "-T" in c.spec["command"] for c in update_specs)


# ── confinement ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "../../etc/passwd",
        "sub/../../escape.pcap",
        "/etc/passwd",
        "",
        "   ",
        "nope.pcap",
        "bad\x00name.pcap",
    ],
)
async def test_paths_outside_the_capture_directories_are_refused(bad, monkeypatch, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    _no_docker(monkeypatch)
    result = await pcap_detect(bad)

    assert "error" in result
    assert "Traceback" not in json.dumps(result)


async def test_a_symlink_out_of_the_reports_directory_is_refused(tmp_path, monkeypatch, capture):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    outside = make_pcap(tmp_path / "elsewhere" / "secret.pcap")
    link = Path(get_settings().reports_dir) / "link.pcap"
    link.symlink_to(outside)
    _no_docker(monkeypatch)

    result = await pcap_detect("link.pcap")

    assert "error" in result


async def test_a_directory_is_not_a_capture(monkeypatch, capture):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    (Path(get_settings().reports_dir) / "adir").mkdir()
    _no_docker(monkeypatch)

    assert "error" in await pcap_detect("adir")


async def test_oversize_capture_is_refused_with_the_setting_named(monkeypatch, capture):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    big = Path(get_settings().reports_dir) / "big.pcap"
    make_pcap(big, packets=1)
    with big.open("ab") as fh:
        fh.write(b"\0" * (2 * 1024 * 1024))
    monkeypatch.setattr(get_settings(), "detection_max_pcap_mb", 1)
    _no_docker(monkeypatch)

    result = await pcap_detect("big.pcap")

    assert "DETECTION_MAX_PCAP_MB" in result["error"]
    assert result["file"]["name"] == "big.pcap"


async def test_unknown_engine_is_refused_before_anything_runs(monkeypatch, capture):
    from honeypot_mcp import pcap_detect as module

    _no_docker(monkeypatch)
    result = await module.detect(capture.name, "snort")

    assert "Unknown engine" in result["error"]


async def test_a_file_that_is_not_a_capture_is_an_error(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    junk = Path(get_settings().reports_dir) / "junk.pcap"
    junk.parent.mkdir(parents=True, exist_ok=True)
    junk.write_bytes(b"this is not a capture file at all" * 4)
    _no_docker(monkeypatch)

    result = await pcap_detect("junk.pcap")

    assert "not a pcap" in result["error"]


@pytest.mark.parametrize("size", [0, 24])
async def test_an_empty_capture_is_an_honest_no_packets_result(size, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    path = Path(get_settings().reports_dir) / "empty.pcap"
    path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 276)
    path.write_bytes(header[:size])
    _no_docker(monkeypatch)

    for engine in ("suricata", "zeek"):
        result = await pcap_detect("empty.pcap", engine=engine)
        assert "error" not in result, result
        assert result["ran"] is False
        assert result["packets"] == 0 and result["count"] == 0
        assert "no packets" in result["note"]
        assert result["file"]["bytes"] == size


# ── Docker problems ──────────────────────────────────────────────────────────────────────────


async def test_docker_unavailable_is_an_error_with_a_hint(monkeypatch, capture):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.tools.detect import pcap_detect

    def down():
        raise module.DetectError("Docker is not available (x).", "Start Docker.")

    monkeypatch.setattr(module, "_docker_client", down)
    result = await pcap_detect(capture.name)

    assert result["error"].startswith("Docker is not available")
    assert result["hint"] == "Start Docker."


async def test_real_client_factory_reports_a_missing_daemon(monkeypatch):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "docker_socket", "unix:///nonexistent/docker.sock")
    with pytest.raises(module.DetectError) as exc:
        module._docker_client()
    assert "Docker is not available" in exc.value.message
    assert exc.value.hint


async def test_first_use_pulls_the_image_and_says_so(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.have_image = False
    first = await pcap_detect(capture.name)
    second = await pcap_detect(capture.name)

    assert first["image_pulled"] is True
    assert second["image_pulled"] is False
    assert docker_client.pulled == ["jasonish/suricata:8.0.7"]


async def test_failed_pull_is_an_error_and_no_container_is_created(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.have_image = False
    docker_client.pull_error = RuntimeError("dial tcp: no such host")
    result = await pcap_detect(capture.name)

    assert "Could not pull jasonish/suricata:8.0.7" in result["error"]
    assert "docker pull" in result["hint"]
    assert docker_client.created == []


async def test_a_mount_the_daemon_refuses_is_explained(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.fail_create = "Mounts denied: the path is not shared from the host"
    result = await pcap_detect(capture.name)

    assert "not allowed to mount" in result["error"]
    assert "File sharing" in result["hint"]


async def test_replay_never_downloads_rules(docker_client, capture, monkeypatch):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.tools.detect import pcap_detect

    async def boom():
        raise AssertionError("pcap_detect must not update rules")

    monkeypatch.setattr(module, "update_rules", boom)
    result = await pcap_detect(capture.name)

    assert result["rules_loaded"] == 0 or "rules" in result
    assert all(c.spec["entrypoint"] == ["/usr/bin/suricata"] for c in docker_client.created)


async def test_stale_labelled_containers_are_reaped_and_others_left(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    old = FakeContainer(docker_client, {"labels": {"honeypot-mcp": "detect"}})
    old.attrs["Created"] = "2026-01-01T00:00:00.123456789Z"
    fresh = FakeContainer(docker_client, {"labels": {"honeypot-mcp": "detect"}})
    foreign = FakeContainer(docker_client, {"labels": {"honeypot-mcp": "grafana"}})
    foreign.attrs["Created"] = "2020-01-01T00:00:00Z"
    unlabelled = FakeContainer(docker_client, {"labels": {}})
    unlabelled.attrs["Created"] = "2020-01-01T00:00:00Z"
    docker_client.store.extend([old, fresh, foreign, unlabelled])

    await pcap_detect(capture.name)

    assert old in docker_client.removed
    assert fresh not in docker_client.removed
    assert foreign not in docker_client.removed
    assert unlabelled not in docker_client.removed


# ── rules ────────────────────────────────────────────────────────────────────────────────────


async def test_without_cached_rules_the_result_says_so_plainly(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.suricata_log = "Notice: suricata: This is Suricata version 8.0.7 RELEASE\n"
    result = await pcap_detect(capture.name)

    assert "error" not in result
    assert result["rules_loaded"] == 0
    assert result["rules"]["ruleset"] is None
    assert "detection_rules_update" in result["note"]
    assert "rules_loaded is 0" in result["note"]
    # It still ran: protocol events need no rules.
    assert result["protocols"]["events"]["sip"] == 3
    seen = docker_client.seen[0]
    assert seen["rules"].strip() == ""


async def test_cached_rules_and_custom_rules_are_loaded_together(
    docker_client, capture, rules_cache
):
    from honeypot_mcp.tools.detect import pcap_detect

    (rules_cache / "custom.rules").write_text(
        'alert tcp any any -> any 22 (msg:"MINE"; sid:900001;)\n'
    )
    result = await pcap_detect(capture.name)

    staged = docker_client.seen[0]["rules"]
    assert "ET TEST" in staged and "MINE" in staged
    assert docker_client.seen[0]["classification"] is True
    assert result["rules_loaded"] == 53211
    assert result["rules"]["custom_rules"] is True
    assert result["rules"]["ruleset"] == "Emerging Threats Open"
    assert result["rules"]["validated_with"] == "8.0.7"
    assert "note" not in result or "rules_loaded is 0" not in result["note"]


async def test_a_symlinked_custom_rules_file_is_not_followed(
    docker_client, capture, rules_cache, tmp_path
):
    from honeypot_mcp.tools.detect import pcap_detect

    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT\n")
    (rules_cache / "custom.rules").symlink_to(secret)

    result = await pcap_detect(capture.name)

    assert "TOP-SECRET-CONTENT" not in docker_client.seen[0]["rules"]
    assert result["rules"]["custom_rules"] is False


async def test_rules_that_fail_to_load_are_counted_and_named(docker_client, capture, rules_cache):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.suricata_log = (
        "Info: detect: 1 rule files processed. 10 rules successfully loaded, 2 rules failed, 0 rules skipped\n"
        'Error: detect: error parsing signature "alert tcp any any -> any 1 (msg:broken" from file /rules/all.rules at line 4\n'
    )
    result = await pcap_detect(capture.name)

    assert result["rules"]["failed"] == 2
    assert "2 rule(s) failed to load" in result["note"]
    assert "error parsing signature" in result["rules"]["errors"][0]


async def test_a_ruleset_validated_by_another_suricata_is_flagged(
    docker_client, capture, rules_cache
):
    from honeypot_mcp.tools.detect import pcap_detect

    meta = json.loads((rules_cache / "ruleset.json").read_text())
    meta["suricata_version"] = "7.0.11"
    (rules_cache / "ruleset.json").write_text(json.dumps(meta))
    result = await pcap_detect(capture.name)

    assert "validated with Suricata 7.0.11" in result["note"]


def _update_runner(client: FakeClient, *, rules_loaded: int = 53211, failed: int = 0, ok=True):
    """Fake `suricata-update` then fake `suricata -T`."""

    def runner(c: FakeContainer) -> None:
        client._observe(c)
        if c.spec.get("entrypoint") == ["suricata-update"]:
            out = c.mounts["/rules"][0]
            if ok:
                (out / "suricata.rules").write_text("alert ip any any -> any any (msg:x; sid:1;)\n")
                (out / "classification.config").write_text("config classification: a,b,1\n")
            c.logs_text = (
                "23/09/2026 -- Fetching https://rules.emergingthreats.net/open/suricata-8.0.7/emerging.rules.tar.gz.\n"
                "Writing rules to /rules/suricata.rules: total: 69171; enabled: 53211; added: 1\n"
            )
            c.attrs["State"]["ExitCode"] = 0 if ok else 1
            if not ok:
                c.logs_text = (
                    "Error: Failed to fetch https://rules.emergingthreats.net: timed out\n"
                )
        else:
            c.logs_text = (
                "Notice: suricata: This is Suricata version 8.0.7 RELEASE running in SYSTEM mode\n"
                f"Info: detect: 1 rule files processed. {rules_loaded} rules successfully loaded, "
                f"{failed} rules failed, 0 rules skipped\n"
            )
            c.attrs["State"]["ExitCode"] = 0 if not failed and rules_loaded else 1

    return runner


async def test_rules_update_installs_validated_rules_privately(docker_client):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import detection_rules_update

    docker_client.runner = _update_runner(docker_client)
    result = await detection_rules_update()

    assert "error" not in result, result
    cache = Path(get_settings().detection_rules_dir)
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    for name in ("suricata.rules", "classification.config", "ruleset.json"):
        assert stat.S_IMODE((cache / name).stat().st_mode) == 0o600
    assert result["ruleset"] == "Emerging Threats Open"
    assert result["rules_total"] == 69171
    assert result["rules_enabled"] == 53211
    assert result["rules_loaded"] == 53211
    assert result["suricata_version"] == "8.0.7"
    assert result["source"].startswith("https://rules.emergingthreats.net/open/suricata-8.0.7/")
    assert datetime.fromisoformat(result["retrieved_at"]).tzinfo is not None
    assert len(result["sha256"]) == 64
    assert json.loads((cache / "ruleset.json").read_text())["rules_loaded"] == 53211
    # Both containers are gone, and so is the working directory.
    assert docker_client.store == []
    assert not docker_client.seen[0].get("root")


async def test_rules_update_leaves_custom_rules_alone(docker_client, rules_cache):
    from honeypot_mcp.tools.detect import detection_rules_update

    (rules_cache / "custom.rules").write_text("# mine\n")
    docker_client.runner = _update_runner(docker_client)
    result = await detection_rules_update()

    assert result["custom_rules"] is True
    assert (rules_cache / "custom.rules").read_text() == "# mine\n"


async def test_failed_validation_keeps_the_old_rules(docker_client, rules_cache):
    from honeypot_mcp.tools.detect import detection_rules_update

    before = (rules_cache / "suricata.rules").read_text()
    meta_before = (rules_cache / "ruleset.json").read_text()
    docker_client.runner = _update_runner(docker_client, rules_loaded=10, failed=3)
    result = await detection_rules_update()

    assert "did not pass validation" in result["error"]
    assert "existing rules were kept" in result["error"]
    assert (rules_cache / "suricata.rules").read_text() == before
    assert (rules_cache / "ruleset.json").read_text() == meta_before
    assert docker_client.store == []


async def test_failed_download_keeps_the_old_rules(docker_client, rules_cache):
    from honeypot_mcp.tools.detect import detection_rules_update

    before = (rules_cache / "suricata.rules").read_text()
    docker_client.runner = _update_runner(docker_client, ok=False)
    result = await detection_rules_update()

    assert "exited with status 1" in result["error"]
    assert "existing rules were kept" in result["error"]
    assert "internet" in result["hint"]
    assert (rules_cache / "suricata.rules").read_text() == before
    assert docker_client.store == []


async def test_update_with_no_docker_or_no_network_image(docker_client):
    from honeypot_mcp.tools.detect import detection_rules_update

    docker_client.have_image = False
    docker_client.pull_error = RuntimeError("offline")
    result = await detection_rules_update()

    assert "Could not pull" in result["error"]
    assert docker_client.created == []


# ── Suricata parsing ─────────────────────────────────────────────────────────────────────────


async def test_suricata_digest_from_eve_json(docker_client, capture, rules_cache):
    from honeypot_mcp.tools.detect import pcap_detect

    result = await pcap_detect(capture.name, top=10)

    assert result["engine"] == "suricata"
    assert result["engine_version"] == "8.0.7"
    assert result["packets"] == 3
    assert result["window"]["first"].startswith("2025-10-09") or result["window"]["first"]
    assert result["window"]["seconds"] == 4.0
    assert result["count"] == 3  # all alerts
    alerts = result["alerts"]
    assert alerts["total"] == 3
    assert alerts["checksum_artifacts"] == 1
    assert alerts["excluding_checksum_artifacts"] == 2
    first, second = alerts["by_signature"]
    # The real signature comes first; the checksum decoder rule is last and flagged.
    assert first["sid"] == 2100158 and first["count"] == 2
    assert first["signature"] == "GPL VOIP SIP INVITE message flooding"
    assert first["category"] == "Attempted Denial of Service" and first["severity"] == 2
    assert first["sources"] == 1 and first["destinations"] == 1
    assert first["first_seen"] == "2026-10-12T00:20:00.000000+00:00"
    assert first["last_seen"] == "2026-10-12T00:21:00.000000+00:00"
    assert first["example"]["dst_port"] == 5060 and first["example"]["app_proto"] == "sip"
    assert second["sid"] == 2200075 and second["capture_artifact"] is True
    assert alerts["by_category"]["Attempted Denial of Service"] == 2
    assert alerts["by_severity"] == {"2": 2, "3": 1}
    assert "invalid checksum" in result["note"]

    # Sources are the flow's initiator even when the alert fired on the reply packet.
    top = result["top_sources"][0]
    assert top["ip"] == "192.0.2.10"
    assert top["flows"] == 1 and top["packets"] == 12 and top["bytes"] == 6208
    assert top["alerts"] == 2

    protocols = result["protocols"]
    assert protocols["events"]["sip"] == 3 and protocols["events"]["alert"] == 3
    assert protocols["events"]["flow"] == 1 and protocols["events"]["dns"] == 2
    assert protocols["flows_by_app_proto"] == {"sip": 1}
    assert protocols["destination_ports"] == [{"value": "5060/UDP", "count": 1}]

    app = result["app_layer"]
    assert app["sip"]["methods"] == [
        {"value": "INVITE", "count": 1},
        {"value": "REGISTER", "count": 1},
    ]
    assert app["sip"]["status_codes"] == [{"value": "407", "count": 1}]
    assert app["dns"]["queries"] == [{"value": "example.test", "count": 1}]
    assert app["dns"]["rcodes"] == [{"value": "NOERROR", "count": 1}]
    assert app["http"]["urls"] == [{"value": "/.env", "count": 1}]
    assert app["http"]["user_agents"] == [{"value": "curl/8.4.0", "count": 1}]
    assert app["tls"]["sni"] == [{"value": "secure.example.test", "count": 1}]
    assert app["ssh"]["clients"] == [{"value": "paramiko_3.4.0", "count": 1}]

    assert result["anomalies"]["total"] == 1
    assert "applayer:APPLAYER_WRONG_DIRECTION_FIRST_DATA" in result["anomalies"]["by_event"]
    assert result["engine_stats"]["packets_decoded"] == 18
    assert result["engine_stats"]["tcp_reassembly_gaps"] == 2
    assert result["engine_stats"]["alerts_generated"] == 3
    assert result["rules_loaded"] == 53211
    assert result["truncated"] is False


async def test_no_payload_bytes_reach_the_result_or_the_artifact(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    result = await pcap_detect(capture.name)

    dumped = json.dumps(result)
    for needle in ("SECRET-PAYLOAD", "U0VDUkVULVBBQ0tFVA", "payload_printable"):
        assert needle not in dumped
    artifact = Path(result["artifact"]["path"]).read_text()
    for needle in ("SECRET-PAYLOAD", "U0VDUkVULVBBQ0tFVA", '"payload', '"packet"'):
        assert needle not in artifact


async def test_artifact_is_written_to_reports_and_only_its_path_is_returned(docker_client, capture):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    result = await pcap_detect(capture.name)

    art = result["artifact"]
    path = Path(art["path"])
    assert path.parent == Path(get_settings().reports_dir).resolve()
    assert path.name.startswith("detect-suricata-pcap-192.0.2.10-")
    assert path.suffix == ".jsonl"
    lines = path.read_text().splitlines()
    assert art["bytes"] == path.stat().st_size
    assert art["rows"] == len(lines) - 1
    meta = json.loads(lines[0])["_meta"]
    assert meta["engine"] == "suricata" and meta["source"] == capture.name
    rows = [json.loads(line) for line in lines[1:]]
    alert = next(r for r in rows if r["type"] == "alert")
    assert {"sid", "sig", "cat", "sev", "src", "dst"} <= set(alert)
    assert not any(k in r for r in rows for k in ("payload", "packet"))
    # The digest itself carries no per-event list.
    assert len(json.dumps(result)) < 20_000


async def test_artifact_rows_are_capped_and_the_result_says_so(docker_client, capture, monkeypatch):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.tools.detect import pcap_detect

    monkeypatch.setattr(module, "_MAX_ARTIFACT_ROWS", 4)
    result = await pcap_detect(capture.name)

    assert result["artifact"]["rows"] == 4
    assert result["artifact"]["truncated"] is True
    assert result["artifact"]["rows_not_written"] > 0
    assert result["truncated"] is True


async def test_event_cap_marks_the_result_truncated(docker_client, capture, monkeypatch):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.tools.detect import pcap_detect

    monkeypatch.setattr(module, "_MAX_ROWS", 5)
    result = await pcap_detect(capture.name)

    assert result["truncated"] is True
    assert "first 5 EVE events" in result["note"]


async def test_damaged_eve_lines_are_skipped_and_counted(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.eve_lines = [
        "{not json",
        "[1, 2, 3]",
        *EVE_LINES,
        "x" * 2_000_000,
    ]
    result = await pcap_detect(capture.name)

    assert result["alerts"]["total"] == 3
    assert "unreadable EVE line(s) were skipped" in result["note"]


async def test_unparsable_eve_output_is_an_error(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.eve_lines = ["this is not json at all", "nor is this"]
    result = await pcap_detect(capture.name)

    assert "no readable EVE output" in result["error"]
    assert "hint" in result


async def test_missing_eve_file_is_an_error(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    def silent(c):
        docker_client._observe(c)

    docker_client.runner = silent
    result = await pcap_detect(capture.name)

    assert "no readable EVE output" in result["error"]


async def test_a_symlink_planted_in_the_output_directory_is_not_followed(
    docker_client, capture, tmp_path
):
    from honeypot_mcp.tools.detect import pcap_detect

    decoy = tmp_path / "decoy.json"
    decoy.write_text(EVE_LINES[3] + "\n")

    def hostile(c):
        docker_client._observe(c)
        (c.mounts["/out"][0] / "eve.json").symlink_to(decoy)

    docker_client.runner = hostile
    result = await pcap_detect(capture.name)

    assert "error" in result, "output reached through a symlink must not be parsed"


async def test_an_engine_that_decodes_nothing_is_an_error_naming_its_message(
    docker_client, capture
):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.eve_lines = [
        json.dumps(
            {
                "timestamp": "2026-10-16T23:10:43.064106+0000",
                "event_type": "stats",
                "stats": {"decoder": {"pkts": 0, "bytes": 0}},
            }
        )
    ]
    docker_client.suricata_log = (
        "Error: pcap: datalink type 276 not (yet) supported in module PcapFile.\n"
    )
    result = await pcap_detect(capture.name)

    assert "decoded none of the 3 packets" in result["error"]
    assert "datalink type 276" in result["error"]
    assert "Suricata 8" in result["hint"]


# ── Zeek parsing ─────────────────────────────────────────────────────────────────────────────


async def test_zeek_digest_from_json_logs(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.runner = docker_client.run_zeek
    result = await pcap_detect(capture.name, engine="zeek", top=5)

    assert result["engine"] == "zeek" and result["engine_version"] == "8.0.10"
    assert result["packets"] == 3 and result["window"]["seconds"] == 4.0
    assert result["detections"] == {"notices": 2, "weird": 3}
    assert result["count"] == 5
    assert result["logs"]["conn"]["rows"] == 4 and result["logs"]["sip"]["rows"] == 2

    conns = result["connections"]
    assert conns["total"] == 4
    assert conns["by_service"] == {"-": 2, "sip": 1, "ssh": 1}
    assert conns["by_state"] == {"S0": 1, "REJ": 1, "SF": 2}
    assert conns["anomalies"] == {"S0": 1, "REJ": 1}
    assert {"value": "Dd", "count": 1} in conns["history_top"]
    assert {"value": "23/tcp", "count": 1} in conns["destination_ports"]
    src = {s["ip"]: s for s in conns["top_sources"]}
    assert src["192.0.2.10"]["connections"] == 2 and src["192.0.2.10"]["bytes"] == 1000
    assert src["192.0.2.10"]["unanswered_or_rejected"] == 1
    assert src["203.0.113.9"]["unanswered_or_rejected"] == 1

    notices = result["notices"]
    assert notices["total"] == 2
    assert notices["groups"][0]["note"] == "Scan::Port_Scan" and notices["groups"][0]["count"] == 2
    assert notices["groups"][0]["example_src"] == "192.0.2.10"
    weird = result["weird"]
    assert weird["total"] == 3
    assert weird["by_name"][0] == {"name": "bad_TCP_checksum", "count": 2, "sources": 2}

    proto = result["protocols"]
    assert proto["dns"]["queries"] == [{"value": "example.test", "count": 2}]
    assert proto["dns"]["rcodes"] == {"NOERROR": 1, "NXDOMAIN": 1}
    assert proto["http"]["hosts"] == [{"value": "bait.test", "count": 1}]
    assert proto["http"]["user_agents"] == [{"value": "curl/8.4.0", "count": 1}]
    assert proto["http"]["uris"] == [{"value": "/.env", "count": 1}]
    assert proto["http"]["status_codes"] == {"404": 1}
    assert proto["ssh"]["clients"] == [{"value": "SSH-2.0-paramiko_3.4.0", "count": 1}]
    assert proto["ssh"]["auth_attempts"] == 3 and proto["ssh"]["auth"] == {"failure": 1}
    assert proto["sip"]["methods"] == {"INVITE": 1, "REGISTER": 1}
    assert proto["sip"]["status_codes"] == {"401": 1, "407": 1}
    assert proto["sip"]["user_agents"] == [{"value": "Linksys-SPA942", "count": 2}]
    assert proto["sip"]["from"] == [{"value": "<sip:1000@198.51.100.5>", "count": 1}]
    assert proto["tls"]["sni"] == [{"value": "secure.example.test", "count": 1}]
    assert proto["tls"]["handshakes"] == {"established": 1}
    assert result["files"]["total"] == 1 and result["files"]["seen_bytes"] == 120
    assert result["files"]["by_mime_type"] == {"application/x-sh": 1}
    assert result["files"]["hashes"][0]["sha1_or_md5"] == "a" * 40
    assert result["software"] == [{"value": "nginx nginx/1.25", "count": 1}]
    assert result["engine_messages"] == ["a script warning"]
    assert result["truncated"] is False


async def test_zeek_only_reports_logs_that_exist(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.runner = docker_client.run_zeek
    docker_client.zeek_logs = {"conn": ZEEK_LOGS["conn"]}
    result = await pcap_detect(capture.name, engine="zeek")

    assert set(result["logs"]) == {"conn"}
    for absent in ("notices", "weird", "protocols", "files", "software"):
        assert absent not in result
    assert result["count"] == 0


async def test_zeek_with_no_ip_traffic_says_so(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.runner = docker_client.run_zeek
    docker_client.zeek_logs = {}
    result = await pcap_detect(capture.name, engine="zeek")

    assert "error" not in result
    assert "no connection log" in result["note"]


async def test_zeek_damaged_and_oversized_logs(docker_client, capture, monkeypatch):
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.tools.detect import pcap_detect

    def runner(c):
        docker_client._observe(c)
        out = c.mounts["/out"][0]
        rows = [json.dumps(r) for r in ZEEK_LOGS["conn"]]
        (out / "conn.log").write_text("\n".join(["{bad", *rows, '"just a string"']) + "\n")

    docker_client.runner = runner
    monkeypatch.setattr(module, "_MAX_ROWS", 2)
    result = await pcap_detect(capture.name, engine="zeek")

    assert result["truncated"] is True
    assert "Only the first 2 rows" in result["note"]
    assert "unreadable log line(s) were skipped" in result["note"]
    assert result["connections"]["total"] == 2


async def test_zeek_logs_that_are_not_json_are_an_error(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    def runner(c):
        docker_client._observe(c)
        (c.mounts["/out"][0] / "conn.log").write_text("#separator \\x09\n#fields\tts\tuid\n")

    docker_client.runner = runner
    result = await pcap_detect(capture.name, engine="zeek")

    assert "could not be parsed as JSON" in result["error"]


async def test_artifact_strings_are_clipped_and_cleaned_for_zeek(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.runner = docker_client.run_zeek
    docker_client.zeek_logs = {
        "http": [{"ts": 1.0, "host": "bait.test", "uri": "/" + "A" * 1000 + "\x00\x1b[31m"}]
    }
    result = await pcap_detect(capture.name, engine="zeek")

    rows = Path(result["artifact"]["path"]).read_text().splitlines()
    row = json.loads(rows[1])
    assert row["log"] == "http" and len(row["uri"]) <= 300
    assert "\x00" not in rows[1] and "\x1b" not in rows[1]
    assert len(result["protocols"]["http"]["uris"][0]["value"]) <= 120


# ── audit, tiers, modes ──────────────────────────────────────────────────────────────────────


async def test_each_run_is_audited_without_file_contents(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    await pcap_detect(capture.name, engine="suricata")
    rows = [r for r in await _audit_rows() if r.tool == "pcap_detect"]

    assert len(rows) == 1
    row = rows[0]
    assert row.outcome == "ok"
    assert row.target == capture.name
    assert row.arguments == {"path": capture.name, "engine": "suricata", "top": 10}
    assert "invalid checksum" not in (row.summary or "")
    assert "SECRET" not in json.dumps(row.arguments) + (row.summary or "")
    assert "alert" not in json.dumps(row.arguments)


async def test_failed_runs_are_audited_as_errors(docker_client, capture):
    from honeypot_mcp.tools.detect import pcap_detect

    docker_client.exit_code = 1
    await pcap_detect(capture.name)
    await pcap_detect("../../etc/passwd")
    rows = [r for r in await _audit_rows() if r.tool == "pcap_detect"]

    assert [r.outcome for r in rows] == ["error", "error"]
    assert all(r.error for r in rows)


async def test_rules_update_is_audited(docker_client):
    from honeypot_mcp.tools.detect import detection_rules_update

    docker_client.runner = _update_runner(docker_client)
    await detection_rules_update()
    rows = [r for r in await _audit_rows() if r.tool == "detection_rules_update"]

    assert len(rows) == 1 and rows[0].outcome == "ok"
    assert "53211 rules loaded" in rows[0].summary


async def test_tiers_and_decorators():
    from honeypot_mcp import rbac
    from honeypot_mcp.server import mcp

    assert "pcap_detect" in rbac.OPERATOR_TOOLS
    assert "detection_rules_update" in rbac.ADMIN_TOOLS
    assert "pcap_detect" not in rbac.VIEWER_TOOLS | rbac.ADMIN_TOOLS
    tools = {t.name: t for t in await mcp.list_tools()}
    assert tools["pcap_detect"].annotations.readOnlyHint is False
    assert tools["pcap_detect"].annotations.openWorldHint is True
    assert tools["detection_rules_update"].annotations.openWorldHint is True
    props = tools["pcap_detect"].parameters["properties"]
    assert props["engine"]["enum"] == ["suricata", "zeek"]
    assert set(props) == {"path", "engine", "top"}
    assert tools["detection_rules_update"].parameters.get("properties", {}) == {}


async def test_works_in_analysis_mode_with_capture_disabled(docker_client, capture):
    """These tools read a capture file; they never touch the sensors the analysis-mode gate guards."""
    from honeypot_mcp import instance_lock
    from honeypot_mcp.tools.detect import detection_rules_update, pcap_detect

    instance_lock.set_analysis_mode()
    try:
        assert instance_lock.read_only_error() is not None
        result = await pcap_detect(capture.name)
        docker_client.runner = _update_runner(docker_client)
        update = await detection_rules_update()
    finally:
        instance_lock.set_ownership(True)

    assert "error" not in result, result
    assert "error" not in update, update


# ── helpers ──────────────────────────────────────────────────────────────────────────────────


def test_split_image():
    from honeypot_mcp.pcap_detect import _split_image

    assert _split_image("jasonish/suricata:8.0.7") == ("jasonish/suricata", "8.0.7")
    assert _split_image("localhost:5000/suri") == ("localhost:5000/suri", "latest")
    assert _split_image("zeek/zeek@sha256:" + "a" * 64) == ("zeek/zeek@sha256:" + "a" * 64, None)


def test_dir_size_does_not_follow_symlinks(tmp_path):
    from honeypot_mcp.pcap_detect import _dir_size

    (tmp_path / "a").write_bytes(b"x" * 100)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b").write_bytes(b"y" * 50)
    big = tmp_path.parent / "big-outside.bin"
    big.write_bytes(b"z" * 10_000)
    (tmp_path / "link").symlink_to(big)

    assert _dir_size(tmp_path, 1 << 20) < 1000


def test_capture_scan_reads_pcap_and_pcapng_headers(tmp_path):
    from honeypot_mcp.pcap_detect import scan_capture

    path = make_pcap(tmp_path / "x.pcap", packets=5, link=1)
    with path.open("rb") as fh:
        scan = scan_capture(fh, path.stat().st_size)
    assert scan.packets == 5 and scan.format == "pcap" and scan.link_types == [1]
    assert scan.last - scan.first == 8.0 and scan.problem is None

    nonsense = tmp_path / "y.pcap"
    nonsense.write_bytes(b"\x00\x01\x02\x03" * 10)
    with nonsense.open("rb") as fh:
        assert scan_capture(fh, 40).problem


def test_settings_are_pinned_and_bounded():
    from honeypot_mcp.config import Settings

    s = Settings()
    assert s.detection_suricata_image.endswith(":8.0.7")
    assert ":" in s.detection_zeek_image and not s.detection_zeek_image.endswith(":latest")
    assert s.detection_timeout_seconds >= 10 and s.detection_memory_mb >= 256
    assert s.detection_rules_dir.is_absolute()
