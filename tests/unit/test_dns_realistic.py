"""Tests for the DNS engine's realistic-response synthesis.

Verifies the engine returns plausible answers for A / AAAA / MX / NS / TXT /
SOA queries (instead of uniform NXDOMAIN, which is itself a fingerprint),
while still NXDOMAIN-ing unknown types and still escalating canary callback
queries to CRITICAL.

Uses dnslib directly to avoid spinning up a real UDP server in unit tests —
exercises the synthesis function in isolation.
"""

import os

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def _build_query(qname: str, qtype_name: str):
    import dnslib

    return dnslib.DNSRecord.question(qname, qtype=qtype_name)


def test_a_query_returns_routable_ipv4():
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("example.test", "A")
    reply = _build_realistic_reply(q, "example.test", "A")
    answers = list(reply.rr)
    assert len(answers) == 1
    assert dnslib.QTYPE[answers[0].rtype] == "A"
    ip = str(answers[0].rdata)
    # Must NOT be in well-known reserved ranges (which would be a tell).
    assert not ip.startswith(("10.", "127.", "169.254.", "192.168.", "0.", "255."))
    assert not ip.startswith(("172.16.", "172.17.", "172.31."))


def test_a_query_is_deterministic():
    """Same name → same IP across calls. Real DNS caches expect stability."""
    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("foo.bar.test", "A")
    r1 = _build_realistic_reply(q, "foo.bar.test", "A")
    r2 = _build_realistic_reply(q, "foo.bar.test", "A")
    assert str(list(r1.rr)[0].rdata) == str(list(r2.rr)[0].rdata)


def test_mx_query_returns_two_priorities():
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("corp.test", "MX")
    reply = _build_realistic_reply(q, "corp.test", "MX")
    answers = list(reply.rr)
    assert len(answers) == 2
    # Both should be MX records
    for a in answers:
        assert dnslib.QTYPE[a.rtype] == "MX"
    # Different preferences (10 + 20 from primary/backup)
    prefs = sorted(a.rdata.preference for a in answers)
    assert prefs == [10, 20]


def test_ns_query_returns_two_nameservers():
    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("corp.test", "NS")
    reply = _build_realistic_reply(q, "corp.test", "NS")
    assert len(list(reply.rr)) == 2


def test_txt_query_returns_spf_record():
    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("corp.test", "TXT")
    reply = _build_realistic_reply(q, "corp.test", "TXT")
    answers = list(reply.rr)
    assert len(answers) == 1
    txt = str(answers[0].rdata).lower()
    assert "v=spf1" in txt


def test_unknown_qtype_still_returns_nxdomain():
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("foo.test", "SRV")
    reply = _build_realistic_reply(q, "foo.test", "SRV")
    assert reply.header.rcode == dnslib.RCODE.NXDOMAIN


def test_aaaa_query_returns_ipv6():
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("ipv6.test", "AAAA")
    reply = _build_realistic_reply(q, "ipv6.test", "AAAA")
    answers = list(reply.rr)
    assert len(answers) == 1
    assert dnslib.QTYPE[answers[0].rtype] == "AAAA"


def test_soa_query_returns_soa_record():
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = _build_query("corp.test", "SOA")
    reply = _build_realistic_reply(q, "corp.test", "SOA")
    answers = list(reply.rr)
    assert len(answers) == 1
    assert dnslib.QTYPE[answers[0].rtype] == "SOA"


# ── Recon / exfil classification ─────────────────────────────────────────────


def test_dns_classifies_zone_transfer_high():
    from honeypot_mcp.engines.dns import _classify_dns_query
    from honeypot_mcp.storage.models import AlertSeverity

    et, sev = _classify_dns_query("corp.test", "AXFR", "IN")
    assert et == "dns_zone_transfer"
    assert sev == AlertSeverity.HIGH


def test_dns_classifies_version_bind_probe():
    from honeypot_mcp.engines.dns import _classify_dns_query

    # By CHAOS class...
    assert _classify_dns_query("anything", "TXT", "CH")[0] == "dns_version_probe"
    # ...or by the well-known name.
    assert _classify_dns_query("version.bind", "TXT", "IN")[0] == "dns_version_probe"


def test_dns_classifies_any_query():
    from honeypot_mcp.engines.dns import _classify_dns_query

    assert _classify_dns_query("example.test", "ANY", "IN")[0] == "dns_any_query"


def test_dns_detects_tunneling_but_not_normal_names():
    from honeypot_mcp.engines.dns import _classify_dns_query, _looks_like_tunneling

    # Long encoded label = tunneling.
    tunnel = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPIFAKEEXFILDATAABCDEF.evil.test"
    assert _looks_like_tunneling(tunnel)
    assert _classify_dns_query(tunnel, "A", "IN")[0] == "dns_tunneling_suspected"
    # Normal FQDN and the 32-char file-token label must NOT trip it.
    assert not _looks_like_tunneling("www.example.com")
    assert not _looks_like_tunneling("a" * 32 + ".canary.test")


def test_dns_normal_query_is_low():
    from honeypot_mcp.engines.dns import _classify_dns_query
    from honeypot_mcp.storage.models import AlertSeverity

    et, sev = _classify_dns_query("www.example.com", "A", "IN")
    assert et == "dns_query"
    assert sev == AlertSeverity.LOW


# ── Behaviour found by running real `dig` against the engine ─────────────────


def _reply(name: str, qtype: str, qclass: str = "IN"):
    import dnslib

    from honeypot_mcp.engines.dns import _build_realistic_reply

    q = dnslib.DNSRecord.question(name, qtype, qclass)
    return _build_realistic_reply(q, name, qtype)


def test_answers_are_a_recursive_resolvers_not_aa_ra_ad_together():
    """dnslib defaults aa=1 and echoes the request's AD bit, so a plain `dig` saw `aa ra ad` on every
    answer. That combination is never sent: AD means DNSSEC-validated, and nothing validates here."""
    import dnslib

    q = dnslib.DNSRecord.question("example.com", "A")
    q.header.ad = 1  # `dig` sends this
    from honeypot_mcp.engines.dns import _build_realistic_reply

    reply = _build_realistic_reply(q, "example.com", "A")
    assert (reply.header.aa, reply.header.ra, reply.header.ad) == (0, 1, 0)


def test_chaos_version_probe_gets_a_bind_version_not_an_spf_record():
    import dnslib

    reply = _reply("version.bind", "TXT", "CH")
    assert reply.header.rcode == dnslib.RCODE.NOERROR
    rr = reply.rr[0]
    assert rr.rclass == dnslib.CLASS.CH
    assert "ubuntu" in str(rr.rdata).lower() and "spf" not in str(rr.rdata).lower()
    assert _reply("bogus.bind", "TXT", "CH").header.rcode == dnslib.RCODE.REFUSED


def test_any_is_answered_consistently_with_a_minimal_rfc8482_record():
    """It used to be NXDOMAIN for a name that answered A, which contradicts itself."""
    import dnslib

    reply = _reply("example.com", "ANY")
    assert reply.header.rcode == dnslib.RCODE.NOERROR and len(reply.rr) == 1
    assert reply.rr[0].rtype == dnslib.QTYPE.HINFO and b"RFC8482" in reply.rr[0].rdata.cpu
    assert len(reply.pack()) < 80, "a full ANY answer is an amplification vector"


def test_zone_transfers_are_refused_and_the_txt_record_is_not_double_quoted():
    import dnslib

    assert _reply("example.com", "AXFR").header.rcode == dnslib.RCODE.REFUSED
    assert _reply("example.com", "IXFR").header.rcode == dnslib.RCODE.REFUSED
    text = str(_reply("example.com", "TXT").rr[0].rdata)
    assert text.count('"') == 2, f"literal quotes inside the TXT string: {text}"
    assert "0.0.0.0/0" not in text


async def test_zone_transfers_arrive_over_tcp_and_are_recorded_and_refused():
    """AXFR is TCP-only in practice. With UDP alone `dns_zone_transfer` could only fire on a rare
    UDP attempt, and a real transfer got a refused connection and left no trace."""
    import asyncio
    import socket

    import dnslib

    from honeypot_mcp.engines.dns import DNSEngine
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    engine = DNSEngine()
    recorded: list[tuple[str, str]] = []

    from honeypot_mcp.engines import dns as dns_module

    async def capture(self, src_ip, src_port, qname, qtype, qclass="IN"):
        recorded.append((qtype, dns_module._classify_dns_query(qname, qtype, qclass)[0]))

    original = dns_module._DNSProtocol._record
    dns_module._DNSProtocol._record = capture  # type: ignore[method-assign]
    cid = await engine.start("dns-tcp-test", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        for qtype in ("AXFR", "A"):
            wire = dnslib.DNSRecord.question("example.com", qtype).pack()
            writer.write(len(wire).to_bytes(2, "big") + wire)
            await writer.drain()
            size = int.from_bytes(await reader.readexactly(2), "big")
            answer = dnslib.DNSRecord.parse(await reader.readexactly(size))
            if qtype == "AXFR":
                assert answer.header.rcode == dnslib.RCODE.REFUSED
            else:
                assert answer.rr, "ordinary queries are answered over TCP as over UDP"
        writer.close()
    finally:
        await engine.stop(cid)
        dns_module._DNSProtocol._record = original  # type: ignore[method-assign]
        await close_db()
        event_buffer.reset_for_tests()

    assert ("AXFR", "dns_zone_transfer") in recorded
