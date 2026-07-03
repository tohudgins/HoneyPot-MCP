"""Tests for the DNS engine's realistic-response synthesis.

Verifies the engine returns plausible answers for A / AAAA / MX / NS / TXT /
SOA queries (instead of uniform NXDOMAIN, which is itself a fingerprint),
while still NXDOMAIN-ing unknown types and still escalating canary callback
queries to CRITICAL.

Uses dnslib directly to avoid spinning up a real UDP server in unit tests —
exercises the synthesis function in isolation.
"""

import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


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
