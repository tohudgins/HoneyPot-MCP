"""Slack, Teams and email notifications carry the source's reputation, at a bounded cost.

A notification used to show only the event: whoever was paged had to go and look the address up.
The reputation is looked up through the per-IP cache the background enrichment already uses, and
only when a message is actually about to be sent, so the number of lookups is bounded by messages
sent (49 in a 20-hour run with 619 source IPs), never by events seen. A slow or failing third party
must not delay or block the alert.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

FULL = {
    "geoip": {"available": True, "country": "Netherlands", "city": "Amsterdam"},
    "abuseipdb": {
        "available": True,
        "abuse_confidence_score": 100,
        "total_reports": 1234,
        "isp": "DigitalOcean, LLC",
        "country_name": "Netherlands",
    },
    "virustotal": {
        "available": True,
        "malicious_votes": 12,
        "total_engines": 94,
        "asn": 14061,
        "as_owner": "DIGITALOCEAN-ASN",
    },
}


def _event(ip: str = "198.51.101.7"):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=1,
        source_ip=ip,
        source_port=5060,
        event_type="sip_toll_fraud_attempt",
        payload={},
        severity=AlertSeverity.CRITICAL,
        timestamp=datetime.now(UTC),
    )


def _sub(fmt: str = "slack"):
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    return Subscription(
        id=1,
        url="https://hooks.slack.com/x",
        label="s",
        severity_threshold=AlertSeverity.LOW,
        format=fmt,
    )


def test_a_full_enrichment_becomes_four_short_lines():
    from honeypot_mcp.webhooks import reputation_facts

    assert reputation_facts(FULL) == [
        ("Location", "Netherlands (Amsterdam)"),
        ("Network", "AS14061 · DigitalOcean, LLC"),
        ("AbuseIPDB", "100/100 · 1,234 report(s)"),
        ("VirusTotal", "12 of 94 engines"),
    ]


def test_unavailable_sources_are_left_out_not_shown_as_noise():
    from honeypot_mcp.webhooks import reputation_facts

    only_geo = {
        "geoip": {"available": True, "country": "Romania", "city": None},
        "abuseipdb": {"available": False, "note": "ABUSEIPDB_API_KEY not set"},
        "virustotal": {"available": False, "error": "VT rate limit exceeded"},
    }
    assert reputation_facts(only_geo) == [("Location", "Romania")]
    assert reputation_facts({}) == [] and reputation_facts(None) == []
    assert reputation_facts({"geoip": {"error": "boom"}, "abuseipdb": {"error": "boom"}}) == []


def test_slack_gets_its_own_reputation_section_within_slacks_field_limit():
    from honeypot_mcp.webhooks import render_slack, reputation_facts

    plain = json.loads(render_slack(_event(), _sub())[0])
    rich = json.loads(render_slack(_event(), _sub(), reputation_facts(FULL))[0])
    blocks = rich["attachments"][0]["blocks"]
    assert len(blocks) == len(plain["attachments"][0]["blocks"]) + 1
    section = next(b for b in blocks if any("AbuseIPDB" in f["text"] for f in b.get("fields", [])))
    assert len(section["fields"]) == 4 <= 10, "Slack rejects a section above 10 fields"
    assert any("100/100" in f["text"] for f in section["fields"])


def test_third_party_text_is_escaped_before_it_reaches_a_human():
    """ISP and owner names come from an API, but they are strings a person reads in a chat
    channel: `<`, `&` and a backtick must not become mentions, links or broken formatting."""
    from honeypot_mcp.webhooks import render_slack, render_teams

    nasty = [("Network", "<!channel> Evil & Co `x`")]
    slack = render_slack(_event(), _sub(), nasty)[0].decode()
    assert "<!channel>" not in slack and "&lt;!channel&gt;" in slack
    teams = json.loads(render_teams(_event(), _sub("teams"), nasty)[0])
    assert any(f["name"] == "Network" for f in teams["sections"][0]["facts"])


def test_email_gets_a_threat_intel_section_and_no_section_without_one():
    from honeypot_mcp.webhooks import render_email, reputation_facts

    _subject, with_rep = render_email(_event(), _sub("email"), reputation_facts(FULL))
    _subject, without = render_email(_event(), _sub("email"))
    assert "Threat intel:" in with_rep and "AbuseIPDB   : 100/100" in with_rep
    assert "Threat intel:" not in without


@pytest.mark.asyncio
async def test_no_lookup_for_a_private_address_or_when_switched_off(monkeypatch):
    from honeypot_mcp import webhooks
    from honeypot_mcp.config import get_settings

    calls: list[str] = []

    async def lookup(ip):
        calls.append(ip)
        return FULL

    monkeypatch.setattr(webhooks, "lookup_enrichment", lookup)
    assert await webhooks.reputation_for(_event("10.0.0.5")) == []
    assert await webhooks.reputation_for(_event("203.0.113.9")) == [], "TEST-NET is not enrichable"
    monkeypatch.setattr(get_settings(), "notify_enrich_timeout_seconds", 0.0, raising=False)
    assert await webhooks.reputation_for(_event("8.8.8.8")) == []
    assert calls == []


@pytest.mark.asyncio
async def test_a_slow_or_failing_third_party_never_blocks_the_alert(monkeypatch):
    from honeypot_mcp import webhooks
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "notify_enrich_timeout_seconds", 0.2, raising=False)

    async def slow(ip):
        await asyncio.sleep(30)

    async def broken(ip):
        raise RuntimeError("VirusTotal is down")

    for lookup in (slow, broken):
        monkeypatch.setattr(webhooks, "lookup_enrichment", lookup)
        started = asyncio.get_running_loop().time()
        assert await webhooks.reputation_for(_event("8.8.8.8")) == []
        assert asyncio.get_running_loop().time() - started < 1.0


@pytest.mark.asyncio
async def test_only_messages_that_are_really_sent_cost_a_lookup(monkeypatch):
    """Five identical CRITICALs: the first is sent (with reputation); the four the throttle swallows
    must not trigger a lookup, which is what keeps the API usage tiny."""
    from honeypot_mcp import webhooks

    looked_up: list[str] = []
    posted: list[bytes] = []

    async def lookup(ip):
        looked_up.append(ip)
        return FULL

    async def destination(sub, fmt):
        return None, []

    async def post(client, url, body, headers):
        posted.append(body)
        return True, None

    monkeypatch.setattr(webhooks, "lookup_enrichment", lookup)
    monkeypatch.setattr(webhooks, "_post_with_retry", post)
    delivery = webhooks.WebhookDelivery()
    monkeypatch.setattr(delivery, "_checked_destination", destination)
    delivery._client = object()  # type: ignore[assignment]

    sub = _sub()
    for _ in range(5):
        await delivery._dispatch(_event("8.8.8.8"), sub)

    assert len(looked_up) == 1 and len(posted) == 1
    assert "AbuseIPDB" in posted[0].decode()
