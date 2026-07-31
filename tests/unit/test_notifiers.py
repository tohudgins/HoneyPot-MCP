"""Slack, Teams and email — the channels that interrupt a person.

Different failure mode from the SIEM formats: a SIEM that receives a slightly
wrong document still stores it, and an analyst finds it later. A notification
that is malformed, or that arrives four thousand times, is simply not read —
and the operator believes they have alerting either way.

So these tests cover two things: the message is *shaped* the way the platform
requires (Slack drops a blocks-only message on mobile, Teams rejects a card
with no `summary`), and the volume is survivable.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _event(severity: str = "high", event_type: str = "ssh_login_failed", **overrides):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    fields = dict(
        honeypot_id=3,
        source_ip="203.0.113.44",
        source_port=51234,
        event_type=event_type,
        payload={"username": "root", "password": "hunter2", "country": "Russia"},
        severity=AlertSeverity(severity),
        timestamp=datetime(2026, 7, 30, 4, 45, 0, tzinfo=UTC),
    )
    fields.update(overrides)
    return PendingEvent(**fields)


def _sub(fmt: str, url: str = "https://hooks.example/x"):
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    return Subscription(
        id=1,
        label="soc",
        url=url,
        severity_threshold=AlertSeverity.LOW,
        format=fmt,
        active=True,
    )


# ── Slack ───────────────────────────────────────────────────────────────────


def test_slack_sets_text_as_well_as_blocks():
    """Slack uses `text` for the mobile push and the tab preview. A blocks-only
    message arrives on a phone as "This content can't be displayed", which
    defeats the purpose of alerting someone away from their desk."""
    from honeypot_mcp.webhooks import render_slack

    body, _ = render_slack(_event(), _sub("slack"))
    doc = json.loads(body)
    assert doc["text"], "missing fallback text"
    assert "203.0.113.44" in doc["text"]
    assert doc["attachments"][0]["blocks"]


def test_slack_stays_within_the_ten_field_section_limit():
    """Slack rejects the *entire* message above 10 fields in a section, so a
    verbose payload would silently stop the channel working."""
    from honeypot_mcp.webhooks import render_slack

    payload = {
        "username": "root",
        "password": "x",
        "command": "wget evil",
        "path": "/a",
        "method": "POST",
        "exploit_categories": ["sqli"],
        "reasons": ["host mount"],
        "country": "CN",
        "asn_org": "Example",
        "abuse_score": 100,
        "vt_malicious": 9,
        "user_agent": "curl/8",
    }
    body, _ = render_slack(_event(payload=payload), _sub("slack"))
    for block in json.loads(body)["attachments"][0]["blocks"]:
        assert len(block.get("fields", [])) <= 10


def test_slack_colours_by_severity():
    from honeypot_mcp.webhooks import render_slack

    critical = json.loads(render_slack(_event("critical"), _sub("slack"))[0])
    low = json.loads(render_slack(_event("low"), _sub("slack"))[0])
    assert critical["attachments"][0]["color"] != low["attachments"][0]["color"]


def test_slack_calls_out_a_honeytoken_trip():
    """The highest-fidelity signal the platform produces — it must not read as
    just another line in the channel."""
    from honeypot_mcp.webhooks import render_slack

    body, _ = render_slack(_event("critical", honeytoken_id=7), _sub("slack"))
    assert "Honeytoken 7 triggered" in json.dumps(body.decode())


# ── Teams ───────────────────────────────────────────────────────────────────


def test_teams_card_has_the_mandatory_summary():
    """Teams returns HTTP 400 "Summary or Text is required" without it — an
    easy way to ship a notifier that never posts anything."""
    from honeypot_mcp.webhooks import render_teams

    doc = json.loads(render_teams(_event(), _sub("teams"))[0])
    assert doc["summary"]
    assert doc["@type"] == "MessageCard"


def test_teams_theme_colour_has_no_leading_hash():
    """`themeColor` is a bare hex triplet; a leading # renders as the default
    grey, losing the severity signal entirely."""
    from honeypot_mcp.webhooks import render_teams

    doc = json.loads(render_teams(_event("critical"), _sub("teams"))[0])
    assert not doc["themeColor"].startswith("#")
    int(doc["themeColor"], 16)  # must parse as hex


def test_teams_leads_with_source_ip_and_time():
    from honeypot_mcp.webhooks import render_teams

    facts = json.loads(render_teams(_event(), _sub("teams"))[0])["sections"][0]["facts"]
    assert facts[0]["name"] == "Source IP"
    assert facts[1]["name"] == "Time"


# ── Email ───────────────────────────────────────────────────────────────────


def test_email_subject_carries_severity_ip_and_event():
    """Subject lines are what someone triages from a phone lock screen."""
    from honeypot_mcp.webhooks import render_email

    subject, _ = render_email(_event("critical"), _sub("email"))
    assert "CRITICAL" in subject
    assert "203.0.113.44" in subject
    assert "SSH Login Failed" in subject


def test_email_body_is_plain_text():
    """Attacker-controlled content in an HTML mail is an injection surface for
    no benefit a honeypot alert needs."""
    from honeypot_mcp.webhooks import render_email

    _, body = render_email(_event(payload={"username": "<script>alert(1)</script>"}), _sub("email"))
    assert "<html" not in body.lower()
    # The value is shown verbatim — it is evidence, not markup.
    assert "<script>alert(1)</script>" in body


@pytest.mark.parametrize(
    "url,expected",
    [
        ("smtp://mail.example.com/?to=soc@example.com", 587),
        ("smtps://mail.example.com/?to=soc@example.com", 465),
        ("smtp://mail.example.com:2525/?to=soc@example.com", 2525),
    ],
)
def test_smtp_url_port_defaults_follow_the_tls_mode(url: str, expected: int):
    from honeypot_mcp.webhooks import _parse_smtp_url

    assert _parse_smtp_url(url)["port"] == expected


def test_smtp_url_parses_multiple_recipients():
    from honeypot_mcp.webhooks import _parse_smtp_url

    cfg = _parse_smtp_url(
        "smtp://user:pw@mail.example.com:587/?from=hp@example.com&to=a@x.com,b@y.com"
    )
    assert cfg["recipients"] == ["a@x.com", "b@y.com"]
    assert cfg["sender"] == "hp@example.com"
    assert cfg["username"] == "user"
    assert cfg["tls"] == "starttls"


@pytest.mark.parametrize(
    "url,fragment",
    [
        ("https://mail.example.com/?to=a@b.com", "smtp://"),
        ("smtp://mail.example.com/", "recipient"),
        ("smtp:///?to=a@b.com", "host"),
    ],
)
def test_smtp_url_errors_say_what_is_wrong(url: str, fragment: str):
    """A mistyped notification target that fails silently is exactly how people
    end up believing they have alerting when they do not."""
    from honeypot_mcp.webhooks import _parse_smtp_url

    with pytest.raises(ValueError, match=fragment):
        _parse_smtp_url(url)


# ── Throttling ──────────────────────────────────────────────────────────────


def test_repeat_events_are_coalesced():
    """One scanner produces thousands of events an hour. A channel that relays
    them one-to-one gets muted, leaving an integration that is worse than none
    because everyone believes they are covered."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=300)
    assert throttle.check(1, _event())[0] is True
    for _ in range(50):
        assert throttle.check(1, _event())[0] is False


def test_critical_is_never_throttled():
    """A triggered honeytoken or a container escape must reach someone even if
    the same IP fired something a minute ago."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=300)
    for _ in range(10):
        assert throttle.check(1, _event("critical"))[0] is True


def test_suppressed_count_rides_on_the_next_message():
    """Throttling must not hide volume — it only stops volume being the
    delivery mechanism."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=0.05)
    assert throttle.check(1, _event())[0] is True
    for _ in range(7):
        throttle.check(1, _event())

    import time

    time.sleep(0.06)
    send, suppressed = throttle.check(1, _event())
    assert send is True
    assert suppressed == 7


def test_different_ips_and_event_types_are_independent():
    """Coalescing a scanner must not silence a different attacker."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=300)
    assert throttle.check(1, _event(source_ip="203.0.113.1"))[0] is True
    assert throttle.check(1, _event(source_ip="203.0.113.2"))[0] is True
    assert throttle.check(1, _event(event_type="http_exploit_attempt"))[0] is True


def test_throttle_is_per_subscription():
    """Two channels with different audiences must not starve each other."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=300)
    assert throttle.check(1, _event())[0] is True
    assert throttle.check(2, _event())[0] is True


def test_throttle_key_map_stays_bounded():
    """A wide IP spread would otherwise leak memory in a long-running process."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=3600, max_keys=64)
    for i in range(500):
        throttle.check(1, _event(source_ip=f"203.0.113.{i % 250}", event_type=f"t{i}"))
    assert len(throttle._last_sent) <= 64


def test_eviction_does_not_silently_discard_a_pending_suppressed_count():
    """Eviction used to pick victims purely by age, with no regard for
    whether a key had events suppressed on it waiting to ride out on the
    next send — discarding that count is exactly what this class's own
    guarantee ("suppressed volume is never hidden, only delayed") forbids.
    A key with pending suppressed events must survive eviction ahead of an
    idle key, even if the pending key is older."""
    from honeypot_mcp.webhooks import _NotifyThrottle

    throttle = _NotifyThrottle(window_seconds=3600, max_keys=8)

    # Fill to capacity — 8 distinct keys, oldest (index 0) first.
    for i in range(8):
        assert throttle.check(1, _event(event_type=f"t{i}"))[0] is True

    # The oldest key gets hit again inside the window: throttled, and now
    # carries a pending suppressed count of 1.
    send, _ = throttle.check(1, _event(event_type="t0"))
    assert send is False
    oldest_key = (1, "t0", "203.0.113.44")
    assert throttle._suppressed[oldest_key] == 1

    # A 9th distinct key pushes the map over max_keys and triggers eviction.
    throttle.check(1, _event(event_type="t8"))

    assert oldest_key in throttle._suppressed, (
        "a key with a pending suppressed count must not be evicted while "
        "zero-suppressed keys are still available to evict instead"
    )
    assert throttle._suppressed[oldest_key] == 1


# ── Subscription validation ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_subscribe_rejects_an_email_url_with_no_recipient():
    """Validated at subscribe time, not at first delivery — a subscription that
    only fails when an attack happens is the worst time to find out."""
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.integrations import alert_subscribe

    await init_db()
    try:
        result = await alert_subscribe(
            url="smtp://mail.example.com/", label="soc-mail", format="email"
        )
        assert "error" in result
        assert "recipient" in result["error"]
    finally:
        await close_db()


@pytest.mark.asyncio
async def test_subscribe_rejects_an_http_url_for_email():
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.integrations import alert_subscribe

    await init_db()
    try:
        result = await alert_subscribe(
            url="https://mail.example.com/send", label="soc-mail", format="email"
        )
        assert "error" in result and "smtp" in result["error"]
    finally:
        await close_db()


@pytest.mark.asyncio
async def test_subscribe_accepts_a_slack_webhook():
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.integrations import alert_subscribe

    await init_db()
    try:
        result = await alert_subscribe(
            url="https://hooks.slack.com/services/T/B/xxx",
            label="soc-slack",
            format="slack",
            severity_threshold="high",
        )
        assert "error" not in result
        assert result["format"] == "slack"
    finally:
        await close_db()


# ── End-to-end delivery ─────────────────────────────────────────────────────
#
# Renderers producing the right bytes says nothing about whether the bytes
# arrive. These drive a real HTTP receiver and a real SMTP conversation.


@pytest.mark.asyncio
async def test_slack_and_teams_deliver_over_http():
    """Through the actual delivery worker, so the dispatch wiring is covered
    too — a renderer that is never reached is the same as no renderer."""
    import asyncio

    from aiohttp import web

    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery, invalidate_subscription_cache

    received: list[dict] = []

    async def handler(request: web.Request) -> web.Response:
        received.append({"path": request.path, "body": await request.json()})
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/slack", handler)
    app.router.add_post("/teams", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    await init_db()
    delivery = WebhookDelivery()
    try:
        from honeypot_mcp.storage.database import get_session

        async with get_session() as session:
            for fmt in ("slack", "teams"):
                session.add(
                    Subscription(
                        label=fmt,
                        url=f"http://127.0.0.1:{port}/{fmt}",
                        severity_threshold=AlertSeverity.LOW,
                        format=fmt,
                        active=True,
                    )
                )
        invalidate_subscription_cache()

        await delivery.start()
        await delivery.enqueue_batch([_event("critical")])
        for _ in range(40):
            await asyncio.sleep(0.05)
            if len(received) >= 2:
                break
    finally:
        await delivery.stop()
        await runner.cleanup()
        await close_db()

    paths = sorted(r["path"] for r in received)
    assert paths == ["/slack", "/teams"], f"got {paths}"
    slack = next(r["body"] for r in received if r["path"] == "/slack")
    teams = next(r["body"] for r in received if r["path"] == "/teams")
    assert slack["text"]
    assert teams["@type"] == "MessageCard"


@pytest.mark.asyncio
async def test_email_delivers_through_a_real_smtp_conversation():
    """`smtplib` blocks, so delivery runs it in a thread; this proves the
    handoff works and the message body actually arrives."""
    import asyncio

    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import _send_email, render_email

    transcript: list[bytes] = []

    async def smtp_server(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 test.local ESMTP\r\n")
        await writer.drain()
        in_data = False
        while True:
            line = await reader.readline()
            if not line:
                break
            transcript.append(line)
            if in_data:
                if line.strip() == b".":
                    in_data = False
                    writer.write(b"250 OK queued\r\n")
                    await writer.drain()
                continue
            upper = line.upper()
            if upper.startswith(b"EHLO") or upper.startswith(b"HELO"):
                writer.write(b"250-test.local\r\n250 SIZE 10240000\r\n")
            elif upper.startswith((b"MAIL", b"RCPT")):
                writer.write(b"250 OK\r\n")
            elif upper.startswith(b"DATA"):
                in_data = True
                writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif upper.startswith(b"QUIT"):
                writer.write(b"221 Bye\r\n")
                await writer.drain()
                break
            else:
                writer.write(b"250 OK\r\n")
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(smtp_server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        sub = Subscription(
            id=1,
            label="soc-mail",
            # tls=none: this stub speaks no TLS, and a local relay often doesn't either.
            url=f"smtp://127.0.0.1:{port}/?from=hp@example.com&to=soc@example.com&tls=none",
            severity_threshold=AlertSeverity.LOW,
            format="email",
            active=True,
        )
        subject, body = render_email(_event("critical"), sub)
        ok, err = await _send_email(sub, subject, body)

    assert ok is True, err
    # smtplib sends verbs lowercase; SMTP verbs are case-insensitive.
    joined = b"".join(transcript).lower()
    assert b"rcpt to:<soc@example.com>" in joined
    assert b"203.0.113.44" in joined, "the alert content must actually be in the message"
