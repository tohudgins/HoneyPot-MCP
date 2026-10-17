"""Does `pcap_detect` really replay a capture through the pinned engines, inside the sandbox?

`tests/unit/test_pcap_detect.py` pins the arguments handed to a fake Docker client and parses
fixture output. It cannot show what only the daemon can: that the pinned images read an
SLL2-framed capture (the framing `tcpdump -i any` writes) offline under these flags, that the
read-only mounts and the non-root user can actually read the staged files, and that the sandbox
really denies what it is meant to (network, writes to the root filesystem, privileges).

Opt-in (`RUN_DOCKER_TESTS=1`): it needs the pinned Suricata and Zeek images (pulled on first use),
and internet access for the rules download. Skips itself without Docker.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytest.importorskip("docker", reason="docker SDK not installed")


@pytest.fixture(autouse=True)
async def database():
    """The tools write an audit row; give them a schema to write it to."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()
    async with get_session():
        pass
    yield
    event_buffer.reset_for_tests()
    await close_db()


skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs Docker and RUN_DOCKER_TESTS=1 (runs Suricata and Zeek containers)",
)


def _ip_checksum(header: bytes) -> int:
    total = sum(struct.unpack("!10H", header))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _sll2_udp_frame(src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    head = head[:10] + struct.pack("!H", _ip_checksum(head)) + head[12:]
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 0, 6, b"\0" * 8)
    return sll2 + head + udp


def _sip_capture(path: Path, requests: int = 3) -> Path:
    """INVITEs to 5060 from a TEST-NET address, each answered 401, in Linux cooked v2 frames
    (link type 276)."""
    data = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 276))
    for i in range(requests):
        sip = (
            f"INVITE sip:100{i}@198.51.100.5 SIP/2.0\r\n"
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
            "From: <sip:1000@192.0.2.10>;tag=1\r\nTo: <sip:100@198.51.100.5>\r\n"
            f"Call-ID: call{i}@192.0.2.10\r\nCSeq: 1 INVITE\r\n"
            "User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        frame = _sll2_udp_frame(
            bytes([192, 0, 2, 10]), bytes([198, 51, 100, 5]), 5060 + i, 5060, sip
        )
        reply = (
            "SIP/2.0 401 Unauthorized\r\n"
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK1\r\n"
            "From: <sip:1000@192.0.2.10>;tag=1\r\nTo: <sip:100@198.51.100.5>;tag=2\r\n"
            f"Call-ID: call{i}@192.0.2.10\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        answer = _sll2_udp_frame(
            bytes([198, 51, 100, 5]), bytes([192, 0, 2, 10]), 5060, 5060 + i, reply
        )
        ts = 1_760_000_000 + i
        data += struct.pack("<IIII", ts, 0, len(frame), len(frame)) + frame
        data += struct.pack("<IIII", ts, 500_000, len(answer), len(answer)) + answer
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(data))
    return path


def _ours() -> list:
    import docker

    return docker.from_env().containers.list(all=True, filters={"label": "honeypot-mcp=detect"})


@skip_docker
async def test_both_engines_replay_an_sll2_capture_offline(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import pcap_detect

    settings = get_settings()
    capture = _sip_capture(Path(settings.reports_dir) / "pcap-192.0.2.10-20261012T031612Z.pcap")

    suricata = await pcap_detect(capture.name, engine="suricata")
    assert "error" not in suricata, suricata
    assert suricata["packets"] == 6
    assert suricata["engine_stats"]["packets_decoded"] == 6
    assert suricata["protocols"]["events"]["sip"] == 6
    assert suricata["app_layer"]["sip"]["methods"] == [{"value": "INVITE", "count": 3}]
    # No rules cached in this test's rules directory: it says so instead of claiming a clean capture.
    assert suricata["rules_loaded"] == 0
    assert "detection_rules_update" in suricata["note"]

    zeek = await pcap_detect(capture.name, engine="zeek")
    assert "error" not in zeek, zeek
    assert zeek["connections"]["total"] == 3
    assert zeek["connections"]["by_service"] == {"sip": 3}
    assert zeek["protocols"]["sip"]["methods"] == {"INVITE": 3}
    assert zeek["protocols"]["sip"]["status_codes"] == {"401": 3}

    assert _ours() == [], "a replay must leave no container behind"


@skip_docker
async def test_rules_update_then_a_replay_with_signatures(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.detect import detection_rules_update, pcap_detect

    settings = get_settings()
    capture = _sip_capture(Path(settings.reports_dir) / "pcap-192.0.2.10-20261012T031612Z.pcap")

    update = await detection_rules_update()
    assert "error" not in update, update
    assert update["ruleset"] == "Emerging Threats Open"
    assert update["rules_loaded"] > 10_000
    assert update["suricata_version"].startswith("8.")
    assert oct(Path(update["rules_dir"]).stat().st_mode & 0o777) == "0o700"

    result = await pcap_detect(capture.name, engine="suricata")
    assert "error" not in result, result
    assert result["rules_loaded"] == update["rules_loaded"]
    assert result["rules"]["ruleset"] == "Emerging Threats Open"
    assert result["rules"]["failed"] == 0
    assert _ours() == []


@skip_docker
def test_the_sandbox_denies_what_it_is_meant_to_deny(tmp_path):
    """Run the module's own container spec with a probe instead of an engine."""
    from honeypot_mcp import pcap_detect as module
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    client = module._docker_client()
    module._ensure_image(client, settings.detection_suricata_image)
    staged = tmp_path / "in"
    staged.mkdir()
    (staged / "capture.pcap").write_bytes(b"x")
    out = tmp_path / "out"
    out.mkdir()
    os.chmod(out, 0o777)
    os.chmod(staged, 0o755)

    probe = r"""
import os, socket
res = {}
def attempt(name, fn):
    try:
        fn(); res[name] = "ALLOWED"
    except Exception as e:
        res[name] = "denied"
def tcp():
    s = socket.create_connection(("1.1.1.1", 53), timeout=3)
def write_root():
    open("/etc/probe", "w").write("x")
def write_in():
    open("/in/probe", "w").write("x")
def write_tmp():
    open("/tmp/probe", "w").write("x")
def write_out():
    open("/out/probe", "w").write("x")
attempt("network", tcp)
attempt("write_rootfs", write_root)
attempt("write_pcap_mount", write_in)
res["write_tmp"] = "ok" if (attempt("t", write_tmp) or True) else ""
attempt("write_out", write_out)
status = dict(l.split(":\t", 1) for l in open("/proc/self/status").read().splitlines() if ":\t" in l)
print("uid", os.getuid())
print("CapEff", status["CapEff"].strip())
print("NoNewPrivs", status["NoNewPrivs"].strip())
print("network", res["network"], "rootfs", res["write_rootfs"], "pcap", res["write_pcap_mount"])
print("out", res["write_out"])
"""
    spec = module._container_spec(
        image=settings.detection_suricata_image,
        engine="suricata",
        command=["-c", probe],
        entrypoint=["python3"],
        user=module._USERS["suricata"],
        mounts=[(staged, "/in", "ro"), (out, "/out", "rw")],
        mem_mb=256,
        cpus=1.0,
    )
    outcome = module._run_container(client, spec, timeout=60)

    assert outcome.exit_code == 0, outcome.logs
    lines = dict(line.split(" ", 1) for line in outcome.logs.splitlines() if " " in line)
    assert lines["uid"] != "0"
    assert lines["CapEff"] == "0000000000000000"
    assert lines["NoNewPrivs"] == "1"
    assert "network denied" in outcome.logs
    assert "rootfs denied" in outcome.logs
    assert "pcap denied" in outcome.logs
    assert "out ALLOWED" in outcome.logs
    assert _ours() == []
    assert not (staged / "probe").exists()
