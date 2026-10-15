"""The optional providers in Slack / Teams / email reputation blocks, and nowhere else.

A person triaging wants one short line per provider that actually said something: GreyNoise's
verdict, an abuse.ch malware family, an OTX pulse count, InternetDB's open ports. "Never seen" and
"not configured" are noise. The block must not make a notification wait past
`notify_enrich_timeout_seconds`, and the machine formats (JSON / ECS / CEF / ...) must not carry or
trigger any of it.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import UTC, datetime
from typing import Any

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.config import get_settings  # noqa: E402
from honeypot_mcp.intel import _cache, greynoise, otx  # noqa: E402

CORE = {
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
EXTRA = {
    "greynoise": {
        "available": True,
        "seen": True,
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "unknown",
    },
    "abusech": {
        "available": True,
        "listed": True,
        "malware": ["Mirai", "Gafgyt"],
        "threatfox": {"listed": True, "match_count": 3},
        "urlhaus": {"listed": True, "url_count": 120},
    },
    "otx": {
        "available": True,
        "pulse_count": 7,
        "pulses": [{"name": "Mirai C2 list"}, {"name": "Botnet IPs Oct"}, {"name": "third"}],
    },
    "internetdb": {
        "available": True,
        "known": True,
        "ports": [22, 80, 443],
        "vulns": ["CVE-2017-15906", "CVE-2018-15473"],
    },
}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    _cache.clear()
    settings = get_settings()
    for name, value in (
        ("greynoise_api_key", ""),
        ("abusech_auth_key", ""),
        ("otx_api_key", ""),
        ("shodan_internetdb_enabled", False),
        ("intel_provider_timeout_seconds", 3.0),
        ("notify_enrich_timeout_seconds", 4.0),
    ):
        monkeypatch.setattr(settings, name, value, raising=False)
    yield
    _cache.clear()


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


def test_each_provider_gets_one_short_line_when_it_said_something():
    from honeypot_mcp.webhooks import reputation_facts

    facts = dict(reputation_facts({**CORE, **EXTRA}))

    assert facts["GreyNoise"] == "malicious · internet-wide scanner · unknown"
    assert facts["abuse.ch"] == "Mirai, Gafgyt · 3 ThreatFox IOC(s) · 120 URLhaus URL(s)"
    assert facts["OTX"] == "7 pulse(s): Mirai C2 list, Botnet IPs Oct"
    assert facts["InternetDB"] == "ports 22, 80, 443 · 2 CVE(s)"
    assert list(facts)[:4] == ["Location", "Network", "AbuseIPDB", "VirusTotal"], "core lines first"


def test_a_benign_service_is_labelled_as_one():
    from honeypot_mcp.webhooks import reputation_facts

    riot = {
        "greynoise": {
            "available": True,
            "riot": True,
            "noise": False,
            "classification": "benign",
            "name": "Cloudflare",
        }
    }

    assert reputation_facts(riot) == [("GreyNoise", "benign · known benign service · Cloudflare")]


def test_never_seen_not_configured_and_failed_providers_leave_no_line():
    from honeypot_mcp.webhooks import reputation_facts

    silent = {
        "greynoise": {"available": True, "seen": False, "noise": False, "riot": False},
        "abusech": {"available": True, "listed": False, "threatfox": {}, "urlhaus": {}},
        "otx": {"available": True, "pulse_count": 0, "pulses": []},
        "internetdb": {"available": True, "known": False, "ports": []},
    }
    broken = {
        "greynoise": {"available": False, "note": "GreyNoise is not configured"},
        "abusech": {"available": False, "error": "abuse.ch rate limit exceeded."},
        "otx": {"available": False, "error": "timed out after 3s"},
        "internetdb": {"available": False, "note": "not enabled"},
    }

    assert reputation_facts(silent) == [] and reputation_facts(broken) == []
    assert reputation_facts({**CORE, **silent}) == reputation_facts(CORE)


def test_many_ports_are_summarised_not_listed():
    from honeypot_mcp.webhooks import reputation_facts

    many = {"internetdb": {"available": True, "ports": list(range(1000, 1020)), "vulns": []}}

    ((_label, text),) = reputation_facts(many)

    assert text == "ports 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007 (+12)"


def test_slack_shows_all_eight_lines_within_its_ten_field_limit():
    from honeypot_mcp.webhooks import render_slack, reputation_facts

    facts = reputation_facts({**CORE, **EXTRA})
    assert len(facts) == 8

    doc = json.loads(render_slack(_event(), _sub(), facts)[0])
    section = next(
        b
        for b in doc["attachments"][0]["blocks"]
        if any("GreyNoise" in f["text"] for f in b.get("fields", []))
    )
    labels = [f["text"].split("*")[1] for f in section["fields"]]

    assert len(section["fields"]) == 8 <= 10
    assert labels == [label for label, _ in facts], "none of the new lines may be cut off"


def test_teams_and_email_carry_the_new_lines_and_vendor_text_is_escaped():
    from honeypot_mcp.webhooks import render_email, render_slack, render_teams, reputation_facts

    hostile = {
        "otx": {
            "available": True,
            "pulse_count": 1,
            "pulses": [{"name": "<!channel> Evil & Co `x`"}],
        }
    }
    facts = reputation_facts({**CORE, **EXTRA, **hostile})

    teams = json.loads(render_teams(_event(), _sub("teams"), facts)[0])
    names = {f["name"] for f in teams["sections"][0]["facts"]}
    _subject, mail = render_email(_event(), _sub("email"), facts)
    slack = render_slack(_event(), _sub(), facts)[0].decode()

    assert {"GreyNoise", "abuse.ch", "OTX", "InternetDB"} <= names
    assert "GreyNoise" in mail and "InternetDB" in mail and "Threat intel:" in mail
    assert "<!channel>" not in slack and "&lt;!channel&gt;" in slack


async def test_the_notification_waits_no_longer_for_a_slow_provider_and_keeps_the_core_lines(
    monkeypatch,
):
    """OTX hangs. The core lines (already quick) must still reach the message, and the whole
    lookup must end by the provider deadline, far inside `notify_enrich_timeout_seconds`."""
    from honeypot_mcp import webhooks

    settings = get_settings()
    monkeypatch.setattr(settings, "otx_api_key", "k", raising=False)
    monkeypatch.setattr(settings, "greynoise_api_key", "k", raising=False)
    monkeypatch.setattr(settings, "intel_provider_timeout_seconds", 0.3, raising=False)
    monkeypatch.setattr(settings, "notify_enrich_timeout_seconds", 4.0, raising=False)

    async def core(name: str, ip: str) -> dict[str, Any]:
        return CORE[name]

    async def geo(ip):
        return await core("geoip", ip)

    async def vt(ip):
        return await core("virustotal", ip)

    async def abuse(ip, max_age_days=90):
        return await core("abuseipdb", ip)

    async def gn(ip):
        return EXTRA["greynoise"]

    async def hang(ip):
        await asyncio.sleep(30)
        return EXTRA["otx"]

    monkeypatch.setattr("honeypot_mcp.intel.geoip.lookup_geoip", geo)
    monkeypatch.setattr("honeypot_mcp.intel.virustotal.lookup_virustotal", vt)
    monkeypatch.setattr("honeypot_mcp.intel.abuseipdb.lookup_abuseipdb", abuse)
    monkeypatch.setattr(greynoise, "lookup_greynoise", gn)
    monkeypatch.setattr(otx, "lookup_otx", hang)

    started = time.monotonic()
    facts = dict(await webhooks.reputation_for(_event("8.8.8.8")))
    elapsed = time.monotonic() - started

    assert elapsed < 1.5, f"took {elapsed:.1f}s with a hung provider"
    assert facts["Location"] == "Netherlands (Amsterdam)" and facts["VirusTotal"]
    assert "GreyNoise" in facts and "OTX" not in facts


async def test_machine_formats_neither_call_the_providers_nor_carry_their_text(monkeypatch):
    from honeypot_mcp import webhooks

    settings = get_settings()
    monkeypatch.setattr(settings, "greynoise_api_key", "k", raising=False)
    monkeypatch.setattr(settings, "shodan_internetdb_enabled", True, raising=False)
    calls: list[str] = []

    async def gn(ip):
        calls.append(ip)
        return EXTRA["greynoise"]

    async def enrichment(ip):
        calls.append(ip)
        return {**CORE, **EXTRA}

    monkeypatch.setattr(greynoise, "lookup_greynoise", gn)
    monkeypatch.setattr(webhooks, "lookup_enrichment", enrichment)
    posted: list[bytes] = []

    async def destination(sub, fmt):
        return None, []

    async def post(client, url, body, headers):
        posted.append(body)
        return True, None

    monkeypatch.setattr(webhooks, "_post_with_retry", post)
    delivery = webhooks.WebhookDelivery()
    monkeypatch.setattr(delivery, "_checked_destination", destination)
    delivery._client = object()  # type: ignore[assignment]

    for fmt in ("json", "splunk_hec", "elastic_ecs", "cef", "loki", "datadog"):
        await delivery._dispatch(_event("8.8.8.8"), _sub(fmt))

    assert calls == [] and len(posted) == 6
    for body in posted:
        text = body.decode().lower()
        assert "greynoise" not in text and "internetdb" not in text and "threat intel" not in text
