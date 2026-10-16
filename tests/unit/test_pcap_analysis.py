"""Reading a capture back: `pcap_analysis` and the `pcap_analyze` / `pcap_files` tools.

Every capture here is built in the test by a small writer (Ethernet / Linux cooked /
raw / loopback framing, IPv4 and IPv6, UDP and TCP, pcap and pcapng), so what is
asserted is what was put in. The file content is attacker-authored, so a large part
of the suite is about what must *not* happen: a hostile length field, a truncated
record, a path that escapes the capture directory, or random corruption must produce
an honest result and never an exception, a hang or an allocation the file dictated.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import random
import socket
import struct
import time

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp import pcap_analysis as pa  # noqa: E402

BASE_TS = 1_780_000_000
CLIENT = "198.51.100.7"
SERVER = "192.0.2.10"

# ── Capture writers ─────────────────────────────────────────────────────────


def _ip(addr: str) -> bytes:
    return socket.inet_aton(addr)


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(
    sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"", window: int = 8192
) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0) + payload


def ipv4(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0, _ip(src), _ip(dst)
    )
    return header + l4


def ipv6(src: str, dst: str, nxt: int, l4: bytes) -> bytes:
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(l4),
        nxt,
        64,
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )
    return header + l4


def eth(ip_packet: bytes, etype: int = 0x0800) -> bytes:
    return (
        b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02" + struct.pack("!H", etype) + ip_packet
    )


def sll(ip_packet: bytes, *, outgoing: bool = False) -> bytes:
    header = struct.pack("!HHH8sH", 4 if outgoing else 0, 1, 6, b"\x00" * 8, 0x0800)
    return header + ip_packet


def sll2(ip_packet: bytes, *, outgoing: bool = False) -> bytes:
    header = struct.pack("!HHIHBB8s", 0x0800, 0, 1, 1, 4 if outgoing else 0, 6, b"\x00" * 8)
    return header + ip_packet


def pcap_bytes(
    packets: list[bytes],
    *,
    linktype: int = 1,
    nano: bool = False,
    big: bool = False,
    start: float = BASE_TS,
    step: float = 0.01,
) -> bytes:
    order = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype)
    for i, packet in enumerate(packets):
        ts = start + i * step
        sec = int(ts)
        frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
        out += struct.pack(order + "IIII", sec, frac, len(packet), len(packet)) + packet
    return out


def pcapng_bytes(packets: list[bytes], *, linktype: int = 1, big: bool = False) -> bytes:
    order = ">" if big else "<"

    def block(btype: int, body: bytes) -> bytes:
        body += b"\x00" * (-len(body) % 4)
        total = 12 + len(body)
        return struct.pack(order + "II", btype, total) + body + struct.pack(order + "I", total)

    shb = block(0x0A0D0D0A, struct.pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    # if_tsresol option = 9 (nanoseconds), then end of options.
    idb_options = (
        struct.pack(order + "HH", 9, 1) + b"\x09\x00\x00\x00" + struct.pack(order + "HH", 0, 0)
    )
    idb = block(1, struct.pack(order + "HHI", linktype, 0, 0) + idb_options)
    out = shb + idb
    for i, packet in enumerate(packets):
        ts = int((BASE_TS + i * 0.01) * 1e9)
        body = struct.pack(order + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(packet), len(packet))
        out += block(6, body + packet)
    return out


def write(path, data: bytes):
    path.write_bytes(data)
    return path


def analyze(data: bytes, **kwargs):
    return pa.analyze_capture(io.BytesIO(data), len(data), **kwargs)


def tcp_conversation(
    c2s: list[bytes],
    s2c: list[bytes] | None = None,
    *,
    sport: int = 40000,
    dport: int = 80,
    src: str = CLIENT,
    dst: str = SERVER,
    close: bool = True,
    frame=eth,
) -> list[bytes]:
    """Handshake, request segments, response segments, orderly close."""
    s2c = s2c or []
    out: list[bytes] = []
    cseq, sseq = 1000, 5000

    def c(flags: int, payload: bytes = b"") -> bytes:
        nonlocal cseq
        seg = frame(ipv4(src, dst, 6, tcp(sport, dport, cseq, sseq, flags, payload)))
        cseq += len(payload) + (1 if flags & 0x02 else 0) + (1 if flags & 0x01 else 0)
        return seg

    def s(flags: int, payload: bytes = b"") -> bytes:
        nonlocal sseq
        seg = frame(ipv4(dst, src, 6, tcp(dport, sport, sseq, cseq, flags, payload)))
        sseq += len(payload) + (1 if flags & 0x02 else 0) + (1 if flags & 0x01 else 0)
        return seg

    out.append(c(0x02))
    out.append(s(0x12))
    out.append(c(0x10))
    for chunk in c2s:
        out.append(c(0x18, chunk))
    for chunk in s2c:
        out.append(s(0x18, chunk))
    if close:
        out.append(c(0x11))
        out.append(s(0x11))
    return out


def tcp_conversation_sll(*args, **kwargs):  # pragma: no cover - thin alias
    return tcp_conversation(*args, **kwargs)


def sip_invite(
    user: str, *, ua: str = "Linksys-SPA942", frm: str = "9000", branch: str = "1"
) -> bytes:
    return (
        f"INVITE sip:{user}@{SERVER} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK{branch}\r\n"
        f"From: <sip:{frm}@{SERVER}>;tag=123\r\n"
        f"To: <sip:{user}@{SERVER}>\r\n"
        "Call-ID: abc@host\r\nCSeq: 1 INVITE\r\n"
        f"User-Agent: {ua}\r\nContent-Length: 0\r\n\r\n"
    ).encode()


SIP_407 = (
    b"SIP/2.0 407 Proxy Authentication Required\r\n"
    b"Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK1\r\n"
    b"Server: Asterisk PBX 18.10.0\r\n"
    b'Proxy-Authenticate: Digest realm="asterisk", nonce="931c5739ab39d9333bd1861c028ea95c", '
    b'algorithm=MD5, qop="auth"\r\nContent-Length: 0\r\n\r\n'
)


def dns_query(name: str, qtype: int = 1, *, response: bool = False) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    flags = 0x8180 if response else 0x0100
    return (
        struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + struct.pack("!HH", qtype, 1)
    )


def u32(n: int) -> bytes:
    return struct.pack("!I", n)


def kexinit(lists: list[str]) -> bytes:
    payload = b"\x14" + b"\x07" * 16
    for item in lists:
        payload += u32(len(item)) + item.encode()
    payload += b"\x00" + u32(0)
    pad = 8 - (len(payload) + 5) % 8
    pad = pad + 8 if pad < 4 else pad
    return u32(len(payload) + pad + 1) + bytes([pad]) + payload + b"\x00" * pad


def client_hello(*, sni: str | None = "scan.example.test") -> bytes:
    def ext(kind: int, data: bytes) -> bytes:
        return struct.pack("!HH", kind, len(data)) + data

    exts = ext(0x0A0A, b"")  # GREASE, must not appear in JA3
    if sni:
        name = sni.encode()
        exts += ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    exts += ext(10, struct.pack("!HHH", 4, 29, 23))
    exts += ext(11, b"\x01\x00")
    exts += ext(43, b"\x04\x03\x04\x03\x03")
    exts += ext(16, struct.pack("!HB", 3, 2) + b"h2")
    body = (
        struct.pack("!H", 0x0303)
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 8)
        + struct.pack("!HHHH", 0x0A0A, 0x1301, 0x1302, 0xC02B)
        + b"\x01\x00"
        + struct.pack("!H", len(exts))
        + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# ── Reading and decoding ────────────────────────────────────────────────────


def test_sip_over_udp_is_decoded_and_dial_prefix_variants_are_grouped():
    frames = []
    for i, number in enumerate(
        ["00421232229865", "+421232229865", "421232229865", "0421232229865"]
    ):
        frames.append(
            eth(ipv4(CLIENT, SERVER, 17, udp(5060, 5060, sip_invite(number, branch=str(i)))))
        )
        frames.append(eth(ipv4(SERVER, CLIENT, 17, udp(5060, 5060, SIP_407))))
    result = analyze(pcap_bytes(frames))

    assert result["format"] == "pcap" and result["truncated"] is False
    assert result["packets"]["analysed"] == 8
    sip = result["services"]["sip"]
    assert sip["messages"] == 8
    assert sip["requests"] == {"INVITE": 4}
    assert sip["responses"] == {"407": 4}
    assert sip["user_agents"][0] == {"value": "Linksys-SPA942", "count": 4}
    assert sip["server_headers"][0]["value"] == "Asterisk PBX 18.10.0"
    assert sip["from_users"][0] == {"value": "9000", "count": 4}
    assert {row["value"] for row in sip["dialled"]} == {
        "00421232229865",
        "+421232229865",
        "421232229865",
        "0421232229865",
    }
    # One destination reached through four dial prefixes.
    groups = sip["dialled_groups"]
    assert len(groups) == 1
    assert groups[0]["destination"] == "421232229865"
    assert groups[0]["calls"] == 4 and groups[0]["distinct_variants"] == 4
    assert {p["value"] for p in groups[0]["dial_prefixes"]} == {"00", "+", "(none)", "0"}
    # Nonce challenge seen, no digest response sent.
    assert sip["digest"]["challenges_with_nonce"] == 4
    assert sip["digest"]["responses_with_digest"] == 0
    # The port table names the service and the service host.
    assert result["ports"][0]["port"] == 5060 and result["ports"][0]["service_guess"] == "sip"
    assert result["local_side"]["service_hosts"][0]["host"] == SERVER
    assert result["window"]["duration_seconds"] == pytest.approx(0.07, abs=0.001)


def test_sip_digest_response_username_is_reported_without_the_response_value():
    auth = (
        sip_invite("100")
        .decode()
        .replace(
            "Content-Length: 0",
            'Authorization: Digest username="1000", realm="asterisk", nonce="n", '
            'uri="sip:x", response="0123456789abcdef0123456789abcdef"\r\nContent-Length: 0',
        )
    ).encode()
    result = analyze(pcap_bytes([eth(ipv4(CLIENT, SERVER, 17, udp(5060, 5060, auth)))]))
    digest = result["services"]["sip"]["digest"]
    assert digest["responses_with_digest"] == 1
    assert digest["usernames"][0]["value"] == "1000"
    assert "0123456789abcdef" not in repr(result)


def test_sip_over_tcp_reads_several_messages_from_one_stream():
    stream = sip_invite("200", branch="a") + sip_invite("201", branch="b")
    frames = tcp_conversation([stream], dport=5060)
    result = analyze(pcap_bytes(frames))
    sip = result["services"]["sip"]
    assert sip["messages"] == 2 and sip["transports"] == {"tcp": 2}
    assert {row["value"] for row in sip["dialled"]} == {"200", "201"}


def test_http_request_headers_basic_auth_and_form_credentials():
    basic = base64.b64encode(b"admin:hunter2").decode()
    request = (
        "POST /login HTTP/1.1\r\nHost: portal.example.test\r\nUser-Agent: Mozilla/5.0 (probe)\r\n"
        f"Authorization: Basic {basic}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 32\r\n\r\nusername=alice&password=pa55w0rd"
    ).encode()
    request2 = b"GET /.env HTTP/1.0\r\n\r\n"
    response = b"HTTP/1.1 404 Not Found\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n"
    frames = tcp_conversation([request + request2], [response])
    result = analyze(pcap_bytes(frames))

    http = result["services"]["http"]
    assert http["requests"] == 2
    assert http["methods"] == {"POST": 1, "GET": 1}
    assert {row["value"] for row in http["paths"]} == {"/login", "/.env"}
    assert http["hosts"][0]["value"] == "portal.example.test"
    assert any(r["value"] == "Mozilla/5.0 (probe)" for r in http["user_agents"])
    assert http["response_status_codes"] == {"404": 1}
    assert http["header_order_fingerprints"]
    creds = {(c["username"], c["password"]) for c in result["credentials"]["top"]}
    assert ("admin", "hunter2") in creds
    assert ("alice", "pa55w0rd") in creds
    assert result["tcp"]["answered"] == 1 and result["tcp"]["with_payload"] == 1


def test_dns_query_name_and_type():
    frames = [
        eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("Probe.Example.TEST", 28)))),
        eth(
            ipv4(
                SERVER,
                CLIENT,
                17,
                udp(53, 40000, dns_query("probe.example.test", 28, response=True)),
            )
        ),
    ]
    dns = analyze(pcap_bytes(frames))["services"]["dns"]
    assert dns["queries"] == 1 and dns["responses"] == 1
    assert dns["qnames"][0]["value"] == "probe.example.test"
    assert dns["qtypes"] == {"AAAA": 1}


@pytest.mark.parametrize(
    ("linktype", "frame", "decides_by_direction"),
    [
        (1, eth, False),
        (113, sll, True),
        (276, sll2, True),
        (101, lambda ip, outgoing=False: ip, False),
    ],
)
def test_every_supported_framing_decodes_the_same_conversation(
    linktype, frame, decides_by_direction
):
    frames = [
        frame(ipv4(CLIENT, SERVER, 17, udp(40000, 5060, sip_invite("100")))),
        # Where the link layer records direction, the reply is marked as outgoing.
        frame(ipv4(SERVER, CLIENT, 17, udp(5060, 40000, SIP_407)), outgoing=True)
        if decides_by_direction
        else frame(ipv4(SERVER, CLIENT, 17, udp(5060, 40000, SIP_407))),
    ]
    result = analyze(pcap_bytes(frames, linktype=linktype))
    assert result["packets"]["ip"] == 2
    assert result["services"]["sip"]["requests"] == {"INVITE": 1}
    assert result["conversations"][0]["server"] == SERVER
    assert result["conversations"][0]["client"] == CLIENT
    how = result["local_side"]["how_decided"]
    assert ("link_direction" in how) is decides_by_direction


def test_link_direction_beats_the_port_heuristic_for_the_service_side():
    """The service listens on a high port the heuristics would call the client: only the
    capture's own in/out marking (Linux cooked capture) gets it right."""
    out = []
    for i in range(3):
        out.append(sll2(ipv4(CLIENT, SERVER, 17, udp(40000, 50000, b"ping %d" % i))))
        out.append(sll2(ipv4(SERVER, CLIENT, 17, udp(50000, 40000, b"pong")), outgoing=True))
    result = analyze(pcap_bytes(out, linktype=276))
    assert result["conversations"][0]["server_port"] == 50000
    assert result["conversations"][0]["server"] == SERVER
    assert result["local_side"]["how_decided"] == {"link_direction": 6}
    # Without direction (Ethernet) the lower port is assumed to be the service.
    plain = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 50000, b"ping")))]
    guess = analyze(pcap_bytes(plain))
    assert guess["local_side"]["how_decided"] == {"lower_port": 1}


def test_loopback_and_openbsd_loopback_framing():
    ip_packet = ipv4(CLIENT, SERVER, 17, udp(40000, 5060, sip_invite("100")))
    for linktype, header in (
        (0, struct.pack("<I", 2)),
        (0, struct.pack(">I", 2)),
        (108, struct.pack(">I", 2)),
    ):
        result = analyze(pcap_bytes([header + ip_packet], linktype=linktype))
        assert result["services"]["sip"]["requests"] == {"INVITE": 1}, (linktype, header)


def test_ipv6_tcp_and_udp():
    src, dst = "2001:db8::7", "2001:db8::10"
    frames = [
        eth(ipv6(src, dst, 17, udp(40000, 53, dns_query("v6.example.test"))), 0x86DD),
        eth(ipv6(src, dst, 6, tcp(40001, 6379, 1, 0, 0x02)), 0x86DD),
    ]
    result = analyze(pcap_bytes(frames))
    assert result["packets"]["ipv6"] == 2 and result["packets"]["ipv4"] == 0
    assert result["services"]["dns"]["queries"] == 1
    assert result["tcp"]["flag_packets"]["syn_only"] == 1
    assert {c["client"] for c in result["conversations"]} == {src}


def test_ipv6_extension_headers_are_walked_to_the_transport():
    src, dst = "2001:db8::7", "2001:db8::10"
    inner = udp(40000, 53, dns_query("ext.example.test"))
    hop_by_hop = bytes([17, 0]) + b"\x00" * 6  # next=UDP, 8-byte header
    frame = eth(ipv6(src, dst, 0, hop_by_hop + inner), 0x86DD)
    assert (
        analyze(pcap_bytes([frame]))["services"]["dns"]["qnames"][0]["value"] == "ext.example.test"
    )


def test_byte_orders_and_timestamp_resolutions_and_pcapng():
    frames = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("t.example.test"))))] * 3
    for data, fmt, res in (
        (pcap_bytes(frames), "pcap", "micro"),
        (pcap_bytes(frames, big=True), "pcap", "micro"),
        (pcap_bytes(frames, nano=True), "pcap", "nano"),
        (pcap_bytes(frames, nano=True, big=True), "pcap", "nano"),
        (pcapng_bytes(frames), "pcapng", "nano"),
        (pcapng_bytes(frames, big=True), "pcapng", "nano"),
    ):
        result = analyze(data)
        assert result["format"] == fmt and result["timestamp_resolution"] == res, (fmt, res)
        assert result["packets"]["analysed"] == 3
        assert result["window"]["first"].startswith("2026-"), result["window"]
        assert result["window"]["duration_seconds"] == pytest.approx(0.02, abs=0.002)


def test_icmp_and_other_ip_protocols_are_counted():
    ping = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"x" * 8
    frames = [
        eth(ipv4(CLIENT, SERVER, 1, ping)),
        eth(ipv4(CLIENT, SERVER, 47, b"\x00" * 16)),
    ]
    result = analyze(pcap_bytes(frames))
    assert result["icmp"] == {"echo-request/0": 1}
    assert result["other_ip_protocols"] == {"47": 1}
    assert set(result["transports"]) == {"icmp", "other"}


# ── TCP ─────────────────────────────────────────────────────────────────────


def test_syn_only_scan_resets_and_port_sweep_are_reported():
    frames = []
    for port in range(1000, 1030):
        frames.append(eth(ipv4(CLIENT, SERVER, 6, tcp(50000 + port, port, 7, 0, 0x02))))
    # One refused (RST+ACK back), one answered then reset.
    frames.append(eth(ipv4(SERVER, CLIENT, 6, tcp(1000, 51000, 0, 8, 0x14))))
    frames.append(eth(ipv4(CLIENT, SERVER, 6, tcp(60000, 2222, 7, 0, 0x00))))  # NULL scan
    frames.append(eth(ipv4(CLIENT, SERVER, 6, tcp(60001, 2222, 7, 0, 0x29))))  # FIN|PSH|URG
    t = analyze(pcap_bytes(frames))["tcp"]
    assert t["flag_packets"]["syn_only"] == 30
    assert t["flag_packets"]["rst"] == 1
    assert t["flag_packets"]["null"] == 1 and t["flag_packets"]["xmas"] == 1
    assert t["syn_only_unanswered"] == 29 and t["refused_by_rst"] == 1
    sweep = t["port_scan_sources"][0]
    assert sweep["source"] == CLIENT and sweep["distinct_ports_probed"] == 30


def test_reassembly_tolerates_reordering_retransmission_and_overlap():
    request = b"GET /alpha/beta HTTP/1.1\r\nHost: reorder.example.test\r\nUser-Agent: seg\r\n\r\n"
    cut1, cut2 = 20, 45
    parts = [request[:cut1], request[cut1:cut2], request[cut2:]]
    frames = tcp_conversation(
        [parts[0], parts[1], parts[2]], [b"HTTP/1.1 200 OK\r\n\r\n"], close=False
    )
    # frames: SYN, SYN-ACK, ACK, d0, d1, d2, response. Swap d1/d2 and replay d0 (retransmit) and
    # an overlapping copy of d1+d2.
    d0, d1, d2 = frames[3], frames[4], frames[5]
    mix = frames[:3] + [d0, d2, d0, d1] + frames[6:]
    # Both orderings must read the same request.
    for variant in (frames, mix):
        http = analyze(pcap_bytes(variant + tcp_conversation([], close=True)[:0]))["services"][
            "http"
        ]
        assert http["paths"][0]["value"] == "/alpha/beta"
        assert http["hosts"][0]["value"] == "reorder.example.test"


def test_stream_skips_a_lost_segment_and_counts_the_gap():
    stream = pa._Stream(1024, 100)
    stream.add(100, b"AAAA")
    stream.add(108, b"CCCC")  # 104..107 never arrives
    assert bytes(stream.buf) == b"AAAA"
    assert stream.finish() == b"AAAACCCC"
    assert stream.gaps == 1


def test_stream_trims_overlap_and_ignores_pure_retransmits():
    stream = pa._Stream(1024, 0)
    stream.add(0, b"hello ")
    stream.add(0, b"hello ")  # exact retransmit
    stream.add(3, b"lo world")  # overlaps three already-seen bytes
    assert stream.finish() == b"hello world"
    assert stream.retrans == 2


def test_stream_handles_sequence_wraparound_and_respects_its_byte_cap():
    stream = pa._Stream(8, 0xFFFFFFFE)
    stream.add(0xFFFFFFFE, b"ab")
    stream.add(0, b"cd")
    assert bytes(stream.buf) == b"abcd"
    stream.add(2, b"x" * 100)
    assert len(stream.buf) == 8 and stream.full


# ── Cleartext protocols ─────────────────────────────────────────────────────


def creds_of(result) -> set[tuple[str, str | None, str | None]]:
    return {(c["service"], c["username"], c["password"]) for c in result["credentials"]["top"]}


def test_telnet_login_is_paired_using_the_servers_prompts():
    server = b"\xff\xfd\x18login: \r\nPassword: \r\nlogin: \r\nPassword: \r\n"
    client = b"\xff\xfb\x18root\r\x00hi3518\r\x00admin\r\x00admin\r\x00"
    result = analyze(pcap_bytes(tcp_conversation([client], [server], dport=23)))
    assert ("telnet", "root", "hi3518") in creds_of(result)
    assert ("telnet", "admin", "admin") in creds_of(result)
    assert result["services"]["telnet"]["sessions"] == 1


def test_ftp_pop3_imap_smtp_redis_logins():
    plain = base64.b64encode(b"\x00mailuser\x00s3cret").decode()
    frames = []
    frames += tcp_conversation(
        [b"USER ftpuser\r\nPASS ftp-pass\r\nQUIT\r\n"], [b"220 hi\r\n"], dport=21, sport=41001
    )
    frames += tcp_conversation(
        [b"USER popuser\r\nPASS pop-pass\r\n"], [b"+OK\r\n"], dport=110, sport=41002
    )
    frames += tcp_conversation(
        [b'a1 LOGIN imapuser "imap pass"\r\n'], [b"* OK\r\n"], dport=143, sport=41003
    )
    frames += tcp_conversation(
        [
            f"EHLO x\r\nAUTH PLAIN {plain}\r\nMAIL FROM:<a@b.test>\r\nRCPT TO:<c@d.test>\r\n"
            "DATA\r\nUSER notacommand\r\n.\r\nQUIT\r\n".encode()
        ],
        [b"220 mail\r\n"],
        dport=25,
        sport=41004,
    )
    resp = b"*2\r\n$4\r\nAUTH\r\n$6\r\nr3dis!\r\n*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n"
    frames += tcp_conversation([resp], [b"+OK\r\n"], dport=6379, sport=41005)
    result = analyze(pcap_bytes(frames))
    found = creds_of(result)
    assert ("ftp", "ftpuser", "ftp-pass") in found
    assert ("pop3", "popuser", "pop-pass") in found
    assert ("imap", "imapuser", "imap pass") in found
    assert ("smtp", "mailuser", "s3cret") in found
    assert ("redis", None, "r3dis!") in found
    smtp = result["services"]["smtp"]
    assert smtp["mail_from"][0]["value"] == "<a@b.test>"
    assert {c["value"] for c in smtp["commands"]} >= {
        "EHLO",
        "AUTH",
        "MAIL",
        "RCPT",
        "DATA",
        "QUIT",
    }
    assert "USER" not in {c["value"] for c in smtp["commands"]}  # inside DATA
    assert result["services"]["redis"]["notable"][0]["value"] == "CONFIG SET dir"


def test_binary_credential_values_are_dropped_and_long_ones_clipped():
    garbage = b"\x00\x01\x02\xfe\xff" * 4
    result = analyze(
        pcap_bytes(tcp_conversation([b"USER " + garbage + b"\r\nPASS pw-ok\r\n"], dport=21))
    )
    row = result["credentials"]["top"][0]
    assert row["username"] is None  # binary is dropped, not stored or escaped
    assert row["password"] == "pw-ok"
    longish = analyze(
        pcap_bytes(tcp_conversation([b"USER u\r\nPASS " + b"q" * 300 + b"\r\n"], dport=21))
    )
    assert len(longish["credentials"]["top"][0]["password"]) <= 160
    huge = analyze(
        pcap_bytes(tcp_conversation([b"USER u\r\nPASS " + b"q" * 5000 + b"\r\n"], dport=21))
    )
    assert huge["credentials"]["top"][0]["password"] is None  # absurdly long: not a password


def test_mysql_greeting_version_and_login_user():
    greeting_body = b"\x0a" + b"8.0.36-test\x00" + b"\x01\x00\x00\x00" + b"\x00" * 20
    greeting = len(greeting_body).to_bytes(3, "little") + b"\x00" + greeting_body
    login_body = (
        struct.pack("<IIB", 0x000FA68D, 1 << 24, 33) + b"\x00" * 23 + b"dbadmin\x00" + b"\x00" * 4
    )
    login = len(login_body).to_bytes(3, "little") + b"\x01" + login_body
    result = analyze(pcap_bytes(tcp_conversation([login], [greeting], dport=3306)))
    mysql = result["services"]["mysql"]
    assert mysql["server_versions"][0]["value"] == "8.0.36-test"
    assert mysql["login_users"][0]["value"] == "dbadmin"


# ── SSH / TLS ───────────────────────────────────────────────────────────────

KEX = ["curve25519-sha256,diffie-hellman-group14-sha1", "ssh-ed25519,rsa-sha2-512"]
ENC_C, ENC_S = "aes128-ctr,aes256-ctr", "chacha20-poly1305@openssh.com"
MAC_C, MAC_S = "hmac-sha2-256", "hmac-sha2-512"


def _lists() -> list[str]:
    return [KEX[0], KEX[1], ENC_C, ENC_S, MAC_C, MAC_S, "none,zlib", "none", "", ""]


def test_ssh_identification_and_hassh_match_the_published_definition():
    client = b"SSH-2.0-libssh_0.9.6\r\n" + kexinit(_lists())
    server = b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n" + kexinit(_lists())
    result = analyze(pcap_bytes(tcp_conversation([client], [server], dport=22)))
    ssh = result["services"]["ssh"]
    assert ssh["client_versions"][0]["value"] == "SSH-2.0-libssh_0.9.6"
    assert ssh["server_versions"][0]["value"] == "SSH-2.0-OpenSSH_9.2p1 Debian-2"
    expected = hashlib.md5(f"{KEX[0]};{ENC_C};{MAC_C};none,zlib".encode()).hexdigest()
    expected_server = hashlib.md5(f"{KEX[0]};{ENC_S};{MAC_S};none".encode()).hexdigest()
    assert ssh["hassh"][0]["hassh"] == expected
    assert ssh["hassh_server"][0]["hassh_server"] == expected_server
    assert ssh["client_kexinit"] == 1


def test_tls_client_hello_sni_version_and_ja3_without_grease():
    result = analyze(pcap_bytes(tcp_conversation([client_hello()], dport=443)))
    tls = result["services"]["tls"]
    assert tls["sni"][0]["value"] == "scan.example.test"
    assert tls["versions"] == {"TLS1.3": 1}
    ja3 = "771,4865-4866-49195,0-10-11-43-16,29-23,0"
    assert tls["ja3"][0]["ja3"] == hashlib.md5(ja3.encode()).hexdigest()
    assert tls["alpn"][0]["value"] == "h2"


@pytest.mark.parametrize(
    "parser",
    [pa.parse_tls_client_hello, pa.parse_ssh_kexinit, pa.parse_dns, pa.parse_ssh_ident],
)
def test_binary_parsers_survive_hostile_length_fields(parser):
    rng = random.Random(7)
    seeds = [client_hello(), b"SSH-2.0-x\r\n" + kexinit(_lists()), dns_query("a.b.test")]
    for seed in seeds:
        for _ in range(400):
            blob = bytearray(seed)
            for _i in range(rng.randint(1, 6)):
                blob[rng.randrange(len(blob))] = rng.choice(
                    [0, 0xFF, 0x7F, 0x80, rng.randrange(256)]
                )
            parser(bytes(blob))
            parser(bytes(blob[: rng.randrange(len(blob))]))
    assert parser(b"") is None


def test_ssh_kexinit_with_giant_name_list_length_is_rejected():
    pkt = bytearray(kexinit(_lists()))
    pkt[22:26] = u32(0xFFFFFFF0)  # first name-list length
    assert pa.parse_ssh_kexinit(b"SSH-2.0-x\r\n" + bytes(pkt)) is None


# ── Payload samples ─────────────────────────────────────────────────────────


def test_payload_samples_clip_dedupe_and_separate_binary():
    frames = []
    for i in range(6):  # same shape, only a long digit run differs
        payload = f"HELLO-{100000 + i} {'z' * 400}".encode()
        frames.append(eth(ipv4(CLIENT, SERVER, 17, udp(40000 + i, 9999, payload))))
    frames.append(eth(ipv4(CLIENT, SERVER, 17, udp(40010, 9999, b"OTHER payload shape"))))
    frames.append(eth(ipv4(CLIENT, SERVER, 17, udp(40011, 9999, bytes(range(200, 250))))))
    result = analyze(pcap_bytes(frames), samples=5)
    block = result["payload_samples"]["udp/9999"]
    assert block["payloads"] == 8
    assert block["samples"][0]["count"] == 6 and len(block["samples"][0]["text"]) <= 160
    assert block["binary_payloads"] == 1
    assert block["binary_samples_hex"][0]["hex_prefix"].startswith("c8c9")
    assert analyze(pcap_bytes(frames), samples=0)["payload_samples"]["udp/9999"]["samples"] == []


def test_quoted_text_has_control_bytes_removed():
    nasty = b"GET /\x1b[31mred\x07 HTTP/1.1\r\nHost: h\r\nUser-Agent: a\x00b\x1bc\r\n\r\n"
    result = analyze(pcap_bytes(tcp_conversation([nasty])))
    blob = repr(result["services"]["http"]) + repr(result["payload_samples"])
    assert "\x1b" not in blob and "\x07" not in blob and "\x00" not in blob


# ── Truncation, damage and hostile input ────────────────────────────────────


def test_zero_byte_header_only_and_short_files_are_clean_empty_results():
    for data in (b"", pcap_bytes([]), pcap_bytes([])[:10], pcap_bytes([], linktype=276)):
        result = analyze(data)
        assert "error" not in result, data
        assert result["packets"]["analysed"] == 0
        assert result["truncated"] is False
        assert result["note"]
        assert result["window"]["first"] is None
    assert analyze(pcap_bytes([], linktype=276))["format"] == "pcap"
    assert analyze(b"")["format"] is None


def test_truncated_trailing_record_is_reported_not_fatal():
    frames = [
        eth(ipv4(CLIENT, SERVER, 17, udp(40000, 5060, sip_invite("100", branch=str(i)))))
        for i in range(5)
    ]
    data = pcap_bytes(frames)
    for cut in (7, 20, 16 + 5):
        result = analyze(data[:-cut])
        assert result["packets"]["analysed"] == 4, cut
        assert result["partial_trailing_record"] is True
        assert result["truncated"] is False
        assert "error" not in result
    # A cut that lands exactly on a record boundary is not a partial record.
    exact = len(data) - (16 + len(frames[-1]))
    assert analyze(data[:exact])["partial_trailing_record"] is False


def test_hostile_record_length_stops_reading_without_allocating_it():
    good = eth(ipv4(CLIENT, SERVER, 17, udp(40000, 5060, sip_invite("100"))))
    data = pcap_bytes([good, good])
    data += struct.pack("<IIII", BASE_TS, 0, 0xFFFFFFFF, 0xFFFFFFFF) + b"tail"
    result = analyze(data)
    assert result["packets"]["analysed"] == 2
    assert result["truncated"] is True and result["truncated_reason"] == "corrupt_record"
    assert any("captured bytes" in w for w in result["warnings"])
    # A length below the hard cap but beyond the file is just a partial tail.
    data = pcap_bytes([good]) + struct.pack("<IIII", BASE_TS, 0, 900_000, 900_000) + b"short"
    result = analyze(data)
    assert result["partial_trailing_record"] is True and result["truncated"] is False


def test_oversized_caplen_never_triggers_a_large_read():
    class Spy(io.BytesIO):
        biggest = 0

        def read(self, n=-1):
            Spy.biggest = max(Spy.biggest, n if n is not None else 0)
            return super().read(n)

    data = pcap_bytes([]) + struct.pack("<IIII", 0, 0, 0x7FFFFFFF, 0x7FFFFFFF)
    spy = Spy(data)
    result = pa.analyze_capture(spy, len(data))
    assert result["truncated"] is True
    assert Spy.biggest <= pa.MAX_RECORD_BYTES


def test_packet_cap_is_reported_as_truncation():
    frames = [
        eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query(f"n{i}.example.test"))))
        for i in range(50)
    ]
    result = analyze(pcap_bytes(frames), max_packets=10)
    assert result["packets"]["analysed"] == 10
    assert result["truncated"] is True and result["truncated_reason"] == "max_packets"
    assert "10 packets" in result["limit_note"]
    assert analyze(pcap_bytes(frames), max_packets=50)["truncated"] is False


def test_time_budget_stops_a_long_analysis_and_says_so():
    frames = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("slow.example.test"))))] * 2100
    result = analyze(pcap_bytes(frames), time_budget=-1.0)
    assert result["truncated_reason"] == "time_budget"
    assert result["packets"]["analysed"] < 2100


def test_not_a_capture_is_an_error_not_an_exception():
    result = analyze(b"GET / HTTP/1.1\r\n\r\n" * 10)
    assert "not a pcap" in result["error"]


def test_unsupported_link_type_is_counted_and_flagged():
    result = analyze(pcap_bytes([b"\x00" * 40], linktype=147))
    assert result["packets"]["analysed"] == 1 and result["packets"]["undecodable"] == 1
    assert any("unsupported link types" in w for w in result["warnings"])


def test_ip_fragments_and_damaged_headers_do_not_break_decoding():
    frag = bytearray(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("f.example.test"))))
    frag[6:8] = struct.pack("!H", 0x0010)  # fragment offset 16: not the first
    short = eth(ipv4(CLIENT, SERVER, 6, b"\x00\x01"))  # TCP header cut short
    bad_ihl = bytearray(ipv4(CLIENT, SERVER, 17, b"x" * 12))
    bad_ihl[0] = 0x4F  # claims a 60-byte header
    result = analyze(pcap_bytes([eth(bytes(frag)), short, eth(bytes(bad_ihl))]))
    assert result["packets"]["ip_fragments_not_first"] == 1
    assert result["packets"]["undecodable"] == 1
    assert "decode error" not in " ".join(result["warnings"])


def test_pcapng_damage_is_reported():
    frames = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("n.example.test"))))] * 3
    data = pcapng_bytes(frames)
    assert analyze(data[:-5])["partial_trailing_record"] is True
    assert analyze(data[:-5])["packets"]["analysed"] == 2
    bad = bytearray(data)
    bad[-4:] = b"\x01\x02\x03\x04"  # last block trailer disagrees with its header
    result = analyze(bytes(bad))
    assert result["truncated"] is True and result["packets"]["analysed"] == 2
    huge = data + struct.pack("<II", 6, 0xFFFFFFF0)
    assert analyze(huge)["truncated_reason"] == "corrupt_record"


def _mixed_capture() -> bytes:
    frames: list[bytes] = []
    frames += [
        eth(ipv4(CLIENT, SERVER, 17, udp(5060, 5060, sip_invite("0042123", branch=str(i)))))
        for i in range(4)
    ]
    frames.append(eth(ipv4(SERVER, CLIENT, 17, udp(5060, 5060, SIP_407))))
    frames.append(eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("fuzz.example.test")))))
    frames += tcp_conversation(
        [b"GET /x HTTP/1.1\r\nHost: h\r\nUser-Agent: u\r\n\r\n"],
        [b"HTTP/1.1 200 OK\r\n\r\n"],
        sport=41000,
    )
    frames += tcp_conversation(
        [b"SSH-2.0-fuzz\r\n" + kexinit(_lists())], [b"SSH-2.0-srv\r\n"], dport=22, sport=41001
    )
    frames += tcp_conversation([client_hello()], dport=443, sport=41002)
    frames += tcp_conversation([b"USER a\r\nPASS b\r\n"], dport=21, sport=41003)
    frames += tcp_conversation([b"*2\r\n$4\r\nAUTH\r\n$1\r\nx\r\n"], dport=6379, sport=41004)
    return pcap_bytes(frames)


def test_random_mutation_of_a_valid_capture_never_raises_or_hangs():
    """Fuzz: bit flips, byte overwrites, truncations, inserted garbage and spliced
    chunks across the whole file, so headers, record framing and every protocol
    decoder see damaged input. Any exception, any swallowed decode error (a bug
    the per-packet guard would otherwise hide) or a slow run fails."""
    original = _mixed_capture()
    assert analyze(original)["warnings"] == []
    rng = random.Random(20261016)
    started = time.monotonic()
    for round_no in range(600):
        blob = bytearray(original)
        for _ in range(rng.randint(1, 12)):
            # Odd rounds only overwrite bytes in place, so record framing survives and
            # the damage lands inside the packets, where the protocol decoders live.
            kind = rng.randrange(2) if round_no % 2 else rng.randrange(5)
            pos = rng.randrange(24, len(blob)) if round_no % 2 else rng.randrange(len(blob))
            if kind == 0:
                blob[pos] ^= 1 << rng.randrange(8)
            elif kind == 1:
                blob[pos] = rng.choice([0x00, 0xFF, 0x7F, 0x80, rng.randrange(256)])
            elif kind == 2:
                blob[pos:pos] = os.urandom(rng.randint(1, 40))
            elif kind == 3:
                del blob[pos : pos + rng.randint(1, 60)]
            else:
                end = rng.randrange(pos, len(blob))
                blob[pos:end] = blob[pos:end][::-1]
        if round_no % 2 == 0 and rng.random() < 0.3:
            del blob[rng.randrange(len(blob)) :]
        result = analyze(bytes(blob), time_budget=5.0)
        assert isinstance(result, dict), round_no
        assert not any("decode error" in w for w in result.get("warnings", [])), (
            round_no,
            result["warnings"],
        )
    assert time.monotonic() - started < 60


def test_pure_random_bytes_after_a_valid_header_are_harmless():
    rng = random.Random(3)
    header = pcap_bytes([])
    for _ in range(200):
        for linktype in (1, 113, 276, 101, 0):
            blob = bytearray(header)
            blob[20:24] = struct.pack("<I", linktype)
            blob += rng.randbytes(rng.randint(0, 600))
            analyze(bytes(blob))


def test_dial_prefix_grouping_does_not_merge_unrelated_numbers():
    counts = {
        "0014155550100": 5,
        "14155550100": 4,
        "+14155550100": 3,
        "004420123456": 2,
        "100": 9,
        "1000": 9,
    }
    groups = pa.group_dialled_numbers(counts)
    assert [g["destination"] for g in groups] == ["14155550100", "004420123456"]
    assert groups[0]["calls"] == 12 and groups[0]["distinct_variants"] == 3


# ── Confinement ─────────────────────────────────────────────────────────────

ROOTS_NAMES = ("extract", "ring")


@pytest.fixture
def roots(tmp_path):
    reports = tmp_path / "reports"
    ring = tmp_path / "ring"
    reports.mkdir()
    ring.mkdir()
    return reports, ring, [("extract", reports), ("ring", ring)]


def _open(name, roots_list, max_bytes=10**9):
    fh, path, kind, size = pa.open_capture(name, roots_list, max_bytes)
    fh.close()
    return path, kind, size


def test_files_inside_either_directory_open_by_name_or_absolute_path(roots):
    reports, ring, spec = roots
    data = pcap_bytes([])
    write(reports / "pcap-x.pcap", data)
    write(ring / "honeypot.pcap0", data)
    assert _open("pcap-x.pcap", spec)[1:] == ("extract", len(data))
    assert _open("honeypot.pcap0", spec)[1] == "ring"
    assert _open(str(reports / "pcap-x.pcap"), spec)[1] == "extract"
    assert _open(str(ring / "honeypot.pcap0"), spec)[1] == "ring"
    sub = reports / "nested"
    sub.mkdir()
    write(sub / "n.pcap", data)
    assert _open("nested/n.pcap", spec)[0].name == "n.pcap"


def test_paths_that_leave_the_capture_directories_are_refused(roots, tmp_path):
    reports, ring, spec = roots
    secret = write(tmp_path / "secret.pcap", pcap_bytes([]))
    for bad in (
        str(secret),
        "../secret.pcap",
        "nested/../../secret.pcap",
        "..",
        "/etc/passwd",
        "~/anything",
        "",
        "   ",
        "a\x00b",
    ):
        with pytest.raises(pa.CaptureAccessError):
            pa.open_capture(bad, spec, 10**9)


def test_dotdot_is_refused_even_when_it_would_stay_inside(roots):
    reports, _ring, spec = roots
    (reports / "sub").mkdir()
    write(reports / "ok.pcap", pcap_bytes([]))
    with pytest.raises(pa.CaptureAccessError, match=r"\.\."):
        pa.open_capture("sub/../ok.pcap", spec, 10**9)


def test_symlink_escaping_the_directory_is_refused_but_an_internal_one_is_fine(roots, tmp_path):
    reports, _ring, spec = roots
    outside = write(tmp_path / "outside.pcap", pcap_bytes([]))
    (reports / "escape.pcap").symlink_to(outside)
    (reports / "dirlink").symlink_to(tmp_path)
    with pytest.raises(pa.CaptureAccessError):
        pa.open_capture("escape.pcap", spec, 10**9)
    with pytest.raises(pa.CaptureAccessError):
        pa.open_capture("dirlink/outside.pcap", spec, 10**9)
    with pytest.raises(pa.CaptureAccessError):
        pa.open_capture(str(reports / "escape.pcap"), spec, 10**9)
    real = write(reports / "real.pcap", pcap_bytes([]))
    (reports / "inner.pcap").symlink_to(real)
    assert _open("inner.pcap", spec)[0] == real.resolve()


def test_non_regular_files_and_directories_are_refused(roots):
    reports, _ring, spec = roots
    (reports / "adir.pcap").mkdir()
    with pytest.raises(pa.CaptureAccessError):
        pa.open_capture("adir.pcap", spec, 10**9)
    fifo = reports / "fifo.pcap"
    os.mkfifo(fifo)
    started = time.monotonic()
    with pytest.raises(pa.CaptureAccessError, match="regular file"):
        pa.open_capture("fifo.pcap", spec, 10**9)
    assert time.monotonic() - started < 2  # a FIFO must not block the read


def test_missing_file_and_oversized_file_have_distinct_messages(roots):
    reports, _ring, spec = roots
    with pytest.raises(pa.CaptureAccessError, match="not found"):
        pa.open_capture("nope.pcap", spec, 10**9)
    write(reports / "big.pcap", pcap_bytes([]) + b"\x00" * 5000)
    with pytest.raises(pa.CaptureAccessError, match="analysis limit"):
        pa.open_capture("big.pcap", spec, 1000)


# ── Tools ───────────────────────────────────────────────────────────────────


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    reports, ring = tmp_path / "reports", tmp_path / "ring"
    reports.mkdir()
    ring.mkdir()
    monkeypatch.setattr(settings, "reports_dir", reports)
    monkeypatch.setattr(settings, "pcap_dir", ring)
    monkeypatch.setattr(settings, "pcap_enabled", False)
    import honeypot_mcp.pcap as pcap_module

    pcap_module._capture = None
    yield reports, ring
    pcap_module._capture = None


@pytest.mark.asyncio
async def test_pcap_analyze_tool_reads_an_extract_and_hides_absolute_paths(dirs):
    from honeypot_mcp.tools.pcap import pcap_analyze

    reports, _ring = dirs
    frames = [
        eth(ipv4(CLIENT, SERVER, 17, udp(5060, 5060, sip_invite("0042123456", branch=str(i)))))
        for i in range(3)
    ]
    write(reports / f"pcap-{CLIENT}-20261012T030753Z.pcap", pcap_bytes(frames, linktype=1))
    result = await pcap_analyze(
        f"pcap-{CLIENT}-20261012T030753Z.pcap", top=3, samples_per_service=2
    )
    assert result["file"]["kind"] == "extract"
    assert result["services"]["sip"]["requests"] == {"INVITE": 3}
    assert str(reports) not in repr(result)
    assert len(result["payload_samples"]["sip"]["samples"]) <= 2


@pytest.mark.asyncio
async def test_pcap_analyze_tool_refuses_escapes_and_honours_the_size_setting(
    dirs, tmp_path, monkeypatch
):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.pcap import pcap_analyze

    reports, ring = dirs
    write(tmp_path / "secret.pcap", pcap_bytes([]))
    assert "error" in await pcap_analyze("../secret.pcap")
    assert "error" in await pcap_analyze(str(tmp_path / "secret.pcap"))
    frames_big = [
        eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("b.example.test"))))
    ] * 20000
    write(ring / "honeypot.pcap1", pcap_bytes(frames_big, linktype=1))
    monkeypatch.setattr(get_settings(), "pcap_analyze_max_file_mb", 1)
    refused = await pcap_analyze("honeypot.pcap1")
    assert "analysis limit" in refused["error"]
    monkeypatch.setattr(get_settings(), "pcap_analyze_max_file_mb", 512)
    ok = await pcap_analyze("honeypot.pcap1")
    assert ok["file"]["kind"] == "ring" and ok["packets"]["analysed"] == 20000
    monkeypatch.setattr(get_settings(), "pcap_analyze_max_packets", 2)
    frames = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("x.example.test"))))] * 5
    write(reports / "many.pcap", pcap_bytes(frames))
    capped = await pcap_analyze("many.pcap")
    assert capped["truncated"] is True and capped["packets"]["analysed"] == 2


@pytest.mark.asyncio
async def test_pcap_files_lists_ring_and_extracts_with_packet_counts(dirs):
    from honeypot_mcp.tools.pcap import pcap_files

    reports, ring = dirs
    frames = [eth(ipv4(CLIENT, SERVER, 17, udp(40000, 53, dns_query("x.example.test"))))] * 4
    write(ring / "honeypot.pcap0", pcap_bytes(frames))
    write(reports / "pcap-a.pcap", pcap_bytes(frames[:2]))
    write(reports / "pcap-empty.pcap", pcap_bytes([]))
    write(reports / "report.html", b"<html>")  # not a capture: must not be listed
    write(reports / "ng.pcapng", pcapng_bytes(frames[:3]))
    (reports / "link.pcap").symlink_to(ring / "honeypot.pcap0")  # symlinks are never listed
    os.utime(ring / "honeypot.pcap0", (BASE_TS, BASE_TS))

    result = await pcap_files()
    by_name = {row["name"]: row for row in result["files"]}
    assert set(by_name) == {"honeypot.pcap0", "pcap-a.pcap", "pcap-empty.pcap", "ng.pcapng"}
    assert by_name["honeypot.pcap0"]["kind"] == "ring" and by_name["honeypot.pcap0"]["packets"] == 4
    assert by_name["pcap-a.pcap"]["kind"] == "extract" and by_name["pcap-a.pcap"]["packets"] == 2
    assert by_name["pcap-empty.pcap"]["packets"] == 0
    assert by_name["ng.pcapng"]["packets"] == 3
    # Existing fields are intact.
    for key in ("count", "files", "total_bytes", "capture_reaches_back_to", "note"):
        assert key in result
    row = by_name["pcap-a.pcap"]
    assert {"name", "bytes", "modified", "age_minutes"} <= set(row)
    assert result["ring_count"] == 1 and result["extract_count"] == 3
    assert result["capture_reaches_back_to"].startswith("2026-")
    assert result["total_bytes"] == result["ring_bytes"] + result["extract_bytes"]
    # Ring first, then extracts.
    assert [r["kind"] for r in result["files"]][0] == "ring"


@pytest.mark.asyncio
async def test_pcap_files_lists_extracts_when_capture_is_disabled_and_dirs_are_missing(
    tmp_path, monkeypatch
):
    import honeypot_mcp.pcap as pcap_module
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.pcap import pcap_files

    settings = get_settings()
    reports = tmp_path / "reports"
    monkeypatch.setattr(settings, "reports_dir", reports)
    monkeypatch.setattr(settings, "pcap_dir", tmp_path / "never-created")
    monkeypatch.setattr(settings, "pcap_enabled", False)
    pcap_module._capture = None
    try:
        empty = await pcap_files()
        assert empty["count"] == 0 and empty["capture_reaches_back_to"] is None
        reports.mkdir()
        write(reports / "pcap-z.pcap", pcap_bytes([]))
        listed = await pcap_files()
        assert [r["name"] for r in listed["files"]] == ["pcap-z.pcap"]
        assert listed["ring_count"] == 0
    finally:
        pcap_module._capture = None


def test_pcap_analyze_is_viewer_tier_and_read_only():
    import honeypot_mcp.server  # noqa: F401  (registers the tools)
    import honeypot_mcp.tools.pcap  # noqa: F401
    from honeypot_mcp import rbac, tool_hints

    assert "pcap_analyze" in rbac.VIEWER_TOOLS
    assert tool_hints.hints("pcap_analyze")["annotations"].readOnlyHint is True


def test_pcap_files_ring_and_listing_helpers_handle_symlink_loops(tmp_path):
    (tmp_path / "loop.pcap").symlink_to(tmp_path / "loop.pcap")
    files, more = pa.list_capture_files(tmp_path, ("*.pcap",))
    assert files == [] and more is False
    assert pa.list_capture_files(tmp_path / "missing", ("*.pcap",)) == ([], False)
