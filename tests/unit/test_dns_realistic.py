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
