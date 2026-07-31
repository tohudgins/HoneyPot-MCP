"""Packet capture.

Capturing needs privileges the test runner does not have, so the live tcpdump
process is not exercised here. Everything downstream of it is, against **real
pcap files run through real tcpdump** — reading a capture file needs no
privileges, so the filter-and-merge path that `pcap_extract` depends on is
genuinely tested rather than mocked into agreement with itself.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

_HAS_TCPDUMP = shutil.which("tcpdump") is not None


def _ipv4_tcp_packet(src: str, dst: str, sport: int = 51234, dport: int = 2222) -> bytes:
    """A minimal but structurally valid Ethernet/IPv4/TCP frame.

    Real enough for tcpdump's BPF to match `host x.x.x.x` on it, which is the
    only property under test. Checksums are zero — tcpdump does not verify them
    when filtering.
    """
    payload = b"honeypot-test"
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, (5 << 4), 0x18, 8192, 0, 0) + payload
    total = 20 + len(tcp)
    ip = (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total,
            0,
            0,
            64,
            6,
            0,
            bytes(int(o) for o in src.split(".")),
            bytes(int(o) for o in dst.split(".")),
        )
        + tcp
    )
    ethernet = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return ethernet + ip


def _write_pcap(path, packets: list[bytes]) -> None:
    """libpcap format, Ethernet link type, microsecond resolution."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, packet in enumerate(packets):
            fh.write(struct.pack("<IIII", 1780000000 + index, 0, len(packet), len(packet)))
            fh.write(packet)


# ── Capability reporting ────────────────────────────────────────────────────


def test_capability_reports_a_reason_when_unavailable():
    """ "Capture is off" without a cause is the state an operator must never be
    in — they discover it when they go looking for evidence, which is always
    after the incident."""
    from honeypot_mcp.pcap import probe_capability

    capability = probe_capability()
    assert capability.reason
    if not capability.available:
        # The message has to say what to do, not just that something failed.
        assert any(
            hint in capability.reason.lower()
            for hint in ("install", "setcap", "root", "permission", "interface")
        ), capability.reason


def test_capability_is_a_plain_dict_for_tool_output():
    from honeypot_mcp.pcap import probe_capability

    payload = probe_capability().as_dict()
    assert set(payload) == {"available", "reason", "tcpdump"}


# ── BPF filter construction ─────────────────────────────────────────────────


def test_filter_qualifies_tcp_and_udp_separately():
    """An unqualified `port 53` also captures TCP/53, which on a DNS honeypot
    means recording zone transfers the UDP engine never saw."""
    from honeypot_mcp.pcap import build_filter

    assert build_filter([(2222, "tcp")]) == "tcp port 2222"
    assert build_filter([(5353, "udp")]) == "udp port 5353"


def test_filter_leaves_both_transports_unqualified():
    """SIP answers on TCP *and* UDP at 5060; qualifying it would silently drop
    half the traffic the engine handles."""
    from honeypot_mcp.pcap import build_filter

    assert build_filter([(5060, "both")]) == "port 5060"


def test_filter_is_empty_with_no_honeypots():
    """An empty filter must not become a capture-everything filter — that would
    record the operator's own SSH session and fill the ring with noise."""
    from honeypot_mcp.pcap import build_filter

    assert build_filter([]) == ""


def test_filter_is_deterministic_and_deduplicated():
    from honeypot_mcp.pcap import build_filter

    a = build_filter([(8080, "tcp"), (2222, "tcp"), (8080, "tcp")])
    b = build_filter([(2222, "tcp"), (8080, "tcp")])
    assert a == b == "tcp port 2222 or tcp port 8080"


def test_transport_comes_from_the_capability_registry():
    """Rather than a private list of "the UDP ones" in the capture module,
    which is the duplication that always drifts."""
    from honeypot_mcp.deception.capabilities import transport_for

    assert transport_for("dns") == "udp"
    assert transport_for("snmp") == "udp"
    assert transport_for("sip") == "both"
    assert transport_for("ssh") == "tcp"
    # Unknown types default to TCP rather than raising: a filter covering TCP
    # beats a filter that fails to build and records nothing.
    assert transport_for("nonexistent") == "tcp"


# ── pcap file handling ──────────────────────────────────────────────────────


def test_merge_produces_a_readable_file_with_every_packet(tmp_path):
    from honeypot_mcp.pcap import merge_pcaps

    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    _write_pcap(a, [_ipv4_tcp_packet("203.0.113.1", "198.51.100.1")] * 3)
    _write_pcap(b, [_ipv4_tcp_packet("203.0.113.2", "198.51.100.1")] * 2)

    out = tmp_path / "merged.pcap"
    assert merge_pcaps([a, b], out) == 5
    assert out.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def test_merge_with_no_input_writes_a_valid_empty_pcap(tmp_path):
    """A zero-byte file reads as *corrupt* in Wireshark, which looks like a bug
    in the capture rather than an honest "no matching packets"."""
    from honeypot_mcp.pcap import merge_pcaps

    out = tmp_path / "empty.pcap"
    assert merge_pcaps([], out) == 0
    assert out.stat().st_size == 24
    assert out.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def test_merge_keeps_packets_before_a_truncated_trailing_record(tmp_path):
    """tcpdump may be mid-write on the live ring file. Discarding the whole file
    would lose the most recent — and most relevant — packets."""
    from honeypot_mcp.pcap import merge_pcaps

    source = tmp_path / "partial.pcap"
    _write_pcap(source, [_ipv4_tcp_packet("203.0.113.5", "198.51.100.1")] * 4)
    blob = source.read_bytes()
    source.write_bytes(blob[:-7])  # chop the final record mid-way

    out = tmp_path / "merged.pcap"
    assert merge_pcaps([source], out) == 3


def test_merge_skips_files_that_are_not_pcaps(tmp_path):
    from honeypot_mcp.pcap import merge_pcaps

    junk = tmp_path / "notes.txt"
    junk.write_text("not a capture")
    good = tmp_path / "good.pcap"
    _write_pcap(good, [_ipv4_tcp_packet("203.0.113.9", "198.51.100.1")])

    assert merge_pcaps([junk, good], tmp_path / "out.pcap") == 1


# ── The extract path, through real tcpdump ──────────────────────────────────


@pytest.mark.skipif(not _HAS_TCPDUMP, reason="tcpdump not installed")
def test_tcpdump_filters_our_synthetic_frames_by_host(tmp_path):
    """Proves the frames are well-formed enough for BPF, which is what the
    extract path relies on. If this fails, `pcap_extract` returns zero packets
    for every query and looks like "no such traffic"."""
    source = tmp_path / "ring.pcap"
    _write_pcap(
        source,
        [
            _ipv4_tcp_packet("203.0.113.10", "198.51.100.1"),
            _ipv4_tcp_packet("203.0.113.11", "198.51.100.1"),
            _ipv4_tcp_packet("203.0.113.10", "198.51.100.1"),
        ],
    )
    out = tmp_path / "filtered.pcap"
    result = subprocess.run(
        ["tcpdump", "-r", str(source), "-w", str(out), "-n", "host 203.0.113.10"],
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr.decode()

    from honeypot_mcp.pcap import merge_pcaps

    assert merge_pcaps([out], tmp_path / "final.pcap") == 2


@pytest.mark.asyncio
@pytest.mark.skipif(not _HAS_TCPDUMP, reason="tcpdump not installed")
async def test_extract_pulls_one_attacker_out_of_the_ring(tmp_path, monkeypatch):
    """The whole point of the capture: an alert names an IP, and the analyst
    gets that IP's packets rather than a 1 GB ring to sift through."""
    from honeypot_mcp.pcap import PcapCapture

    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    _write_pcap(
        pcap_dir / "honeypot.pcap0",
        [
            _ipv4_tcp_packet("203.0.113.10", "198.51.100.1"),
            _ipv4_tcp_packet("203.0.113.99", "198.51.100.1"),
        ],
    )
    _write_pcap(
        pcap_dir / "honeypot.pcap1",
        [_ipv4_tcp_packet("203.0.113.10", "198.51.100.1")] * 4,
    )

    reports = tmp_path / "reports"
    reports.mkdir()
    monkeypatch.setenv("PCAP_DIR", str(pcap_dir))
    monkeypatch.setenv("REPORTS_DIR", str(reports))
    import honeypot_mcp.config as config_module

    config_module._settings = None
    try:
        capture = PcapCapture()
        assert len(capture.files()) == 2

        result = await capture.extract("203.0.113.10", "extract.pcap")
        assert "error" not in result, result
        assert result["packets"] == 5, "should find the attacker's packets in both ring files"
        assert result["searched_files"] == 2
        # And the noise from the other host must not come along.
        assert result["bytes"] > 24
    finally:
        config_module._settings = None


@pytest.mark.asyncio
async def test_extract_rejects_a_malformed_ip():
    """These IPs are transcribed by a model reading an alert, so a typo is
    realistic — and returning "0 packets" for one reads as an all-clear."""
    from honeypot_mcp.pcap import PcapCapture

    result = await PcapCapture().extract("203.0.113.999", "out.pcap")
    assert "error" in result and "not a valid IP" in result["error"]


@pytest.mark.asyncio
async def test_start_is_a_no_op_without_honeypots(tmp_path, monkeypatch):
    """Capturing on an empty filter would mean capturing everything."""
    from honeypot_mcp.pcap import PcapCapture

    result = await PcapCapture().start([])
    assert result["started"] is False
    assert "no honeypots" in result["reason"]


@pytest.mark.asyncio
async def test_refresh_is_silent_when_capture_is_disabled():
    """`honeypot_deploy` calls this unconditionally, so it must not raise or
    log noise on the overwhelmingly common disabled path."""
    from honeypot_mcp.pcap import refresh_capture

    await refresh_capture()  # must not raise


# ── pcap_control (the MCP tool wrapper, not just the underlying module) ────


@pytest.mark.asyncio
async def test_pcap_control_rejects_an_unknown_action():
    """`action` is now a `Literal`, so a compliant MCP client can't send this —
    but the tool is directly callable as plain Python in tests (and by any
    caller that bypasses schema validation), so the runtime guard still
    matters."""
    from honeypot_mcp.tools.pcap import pcap_control

    result = await pcap_control("bogus")
    assert result == {"error": "action must be start, stop or restart (got 'bogus')"}


@pytest.mark.asyncio
async def test_pcap_control_stop_is_a_no_op_when_not_running():
    import honeypot_mcp.pcap as pcap_module
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.pcap import pcap_control

    pcap_module._capture = None
    await init_db()
    try:
        result = await pcap_control("stop")
        assert result["stopped"] is True
        assert result["running"] is False
    finally:
        await close_db()
        pcap_module._capture = None


@pytest.mark.asyncio
async def test_pcap_control_start_reports_disabled_when_pcap_is_off():
    """Default config has PCAP_ENABLED=false — starting must degrade
    gracefully rather than trying to shell out to tcpdump."""
    import honeypot_mcp.config as config_module
    import honeypot_mcp.pcap as pcap_module
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.pcap import pcap_control

    pcap_module._capture = None
    config_module._settings = None
    await init_db()
    try:
        assert config_module.get_settings().pcap_enabled is False
        result = await pcap_control("start")
        assert result["started"] is False
        assert result["enabled"] is False
    finally:
        await close_db()
        pcap_module._capture = None
        config_module._settings = None
