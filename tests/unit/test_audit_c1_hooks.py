"""Regression tests for the webhook delivery and integration-tool audit findings:
destination policy, redaction, suppression-rule validation, bounded delivery."""

import asyncio
import os
import time
from types import SimpleNamespace

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import webhooks
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    webhooks.invalidate_subscription_cache()
    yield
    event_buffer.reset_for_tests()
    await close_db()


def _event(severity: str = "medium", honeypot_id=None, event_type: str = "ssh_login_attempt"):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=honeypot_id,
        source_ip="203.0.113.7",
        event_type=event_type,
        payload={"username": "root", "password": "x"},
        severity=AlertSeverity(severity),
    )


# ── Subscription destinations ───────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://[fe80::1]/x",
        "http://127.0.0.1:9/x",  # loopback: refused unless opted in
        "http://10.0.0.5/x",
        "http://0.0.0.0/x",
    ],
)
async def test_subscribe_refuses_internal_destinations(url):
    from honeypot_mcp.tools.integrations import alert_subscribe

    result = await alert_subscribe(url=url, label="ssrf", format="json")
    assert "error" in result
    assert "refused" in result["error"]


@pytest.mark.asyncio
async def test_link_local_stays_refused_even_when_private_destinations_are_allowed(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.integrations import alert_subscribe

    monkeypatch.setattr(get_settings(), "webhook_allow_private_destinations", True)
    metadata = await alert_subscribe(url="http://169.254.169.254/x", label="m", format="json")
    assert "error" in metadata
    local = await alert_subscribe(url="http://127.0.0.1:9/x", label="ok", format="json")
    assert local.get("active") is True


@pytest.mark.asyncio
async def test_subscription_list_redacts_destination_credentials(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.integrations import alert_subscribe, alert_subscriptions_list

    monkeypatch.setattr(get_settings(), "webhook_allow_private_destinations", True)
    await alert_subscribe(
        url="https://127.0.0.1:8443/services/T000/B000/SECRETTOKEN?k=v",
        label="slackish",
        format="slack",
    )
    listed = await alert_subscriptions_list()
    assert listed
    assert listed[0]["url"] == "https://127.0.0.1:8443"
    assert "SECRETTOKEN" not in str(listed)


@pytest.mark.asyncio
async def test_delivery_refuses_a_stored_subscription_whose_destination_is_internal(monkeypatch):
    """The gate must sit on the delivery path, not only in alert_subscribe: a row
    created before the policy existed (or under a looser setting, or whose name
    later re-resolves to an internal address) must not be posted to."""
    from aiohttp import web

    from honeypot_mcp import webhooks
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    received: list[bytes] = []

    async def hook(request: web.Request) -> web.Response:
        received.append(await request.read())
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/hook", hook)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    sub = Subscription(
        label="stored",
        url=f"http://127.0.0.1:{port}/hook",
        format="json",
        severity_threshold=AlertSeverity.LOW,
        hmac_secret="s" * 20,
        active=True,
    )
    sub.id = 1
    delivery = webhooks.WebhookDelivery()
    await delivery.start()
    try:
        monkeypatch.setattr(get_settings(), "webhook_allow_private_destinations", False)
        ok, err = await delivery._dispatch(_event("high"), sub)
        assert ok is False and err and "refused" in err
        assert received == [], "an event was POSTed to a refused destination"

        # The same subscription is delivered once the operator opts in.
        monkeypatch.setattr(get_settings(), "webhook_allow_private_destinations", True)
        ok, err = await delivery._dispatch(_event("high"), sub)
        assert ok is True, err
        assert len(received) == 1
    finally:
        await delivery.stop()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_delivery_refuses_link_local_even_when_private_is_allowed(monkeypatch):
    from honeypot_mcp import webhooks
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    monkeypatch.setattr(get_settings(), "webhook_allow_private_destinations", True)
    sub = Subscription(
        label="meta",
        url="http://169.254.169.254/latest/meta-data/",
        format="json",
        severity_threshold=AlertSeverity.LOW,
        hmac_secret="s" * 20,
        active=True,
    )
    sub.id = 2
    delivery = webhooks.WebhookDelivery()
    await delivery.start()
    try:
        ok, err = await delivery._dispatch(_event("high"), sub)
    finally:
        await delivery.stop()
    assert ok is False and err and "refused" in err


def test_smtp_url_rejects_typoed_tls_and_cleartext_auth_to_remote_hosts():
    from honeypot_mcp.webhooks import _parse_smtp_url

    with pytest.raises(ValueError, match="tls="):
        _parse_smtp_url("smtp://mail.example.com/?to=a@b.co&tls=startls")
    with pytest.raises(ValueError, match="clear text"):
        _parse_smtp_url("smtp://u:p@mail.example.com/?to=a@b.co&tls=none")
    assert _parse_smtp_url("smtp://u:p@localhost/?to=a@b.co&tls=none")["tls"] == "none"
    assert _parse_smtp_url("smtp://mail.example.com/?to=a@b.co&tls=none")["tls"] == "none"


# ── Suppression rules ───────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"event_type_pattern": "*"},
        {"event_type_pattern": "**"},
        {"event_type_pattern": "?*"},
        {"ip_pattern": "0.0.0.0/0"},
        {"ip_pattern": "::/0"},
        {"ip_pattern": "0.0.0.0/0", "event_type_pattern": "*"},
    ],
)
async def test_suppression_refuses_match_everything_rules(kwargs):
    from honeypot_mcp.tools.integrations import suppression_add

    result = await suppression_add(label="oops", **kwargs)
    assert "error" in result and "every event" in result["error"]


@pytest.mark.asyncio
async def test_suppression_match_all_needs_explicit_confirmation():
    from honeypot_mcp.tools.integrations import suppression_add

    result = await suppression_add(
        label="everything", event_type_pattern="*", confirm_match_all=True
    )
    assert result.get("active") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs",
    [
        {"ip_pattern": "not-an-ip"},
        {"ip_pattern": "300.1.1.1"},
        {"event_type_pattern": "ssh_*", "action": "explode"},
        {
            "event_type_pattern": "ssh_*",
            "action": "rate_limit",
            "rate_limit_count": 0,
            "rate_limit_window_seconds": 60,
        },
        {"event_type_pattern": "ssh_*", "action": "rate_limit", "rate_limit_count": 5},
    ],
)
async def test_suppression_rejects_unparseable_or_invalid_rules(kwargs):
    from honeypot_mcp.tools.integrations import suppression_add

    result = await suppression_add(label="bad", **kwargs)
    assert "error" in result


@pytest.mark.asyncio
async def test_suppression_accepts_narrow_rules():
    from honeypot_mcp.tools.integrations import suppression_add

    assert (await suppression_add(label="net", ip_pattern="10.0.0.0/8")).get("active") is True
    assert (await suppression_add(label="ssh", event_type_pattern="ssh_*")).get("active") is True


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["../../etc/passwd", "a/b", "x\x00y", "", "a" * 65, "..", "a.b"])
async def test_preset_names_cannot_reach_the_filesystem(name):
    from honeypot_mcp.tools.integrations import _read_preset, suppression_load_preset

    assert _read_preset(name) is None
    result = await suppression_load_preset(name)
    assert "error" in result


@pytest.mark.asyncio
async def test_malformed_preset_yaml_is_an_error_not_a_crash(tmp_path, monkeypatch):
    from honeypot_mcp.tools import integrations

    presets = tmp_path / "config" / "suppression_presets"
    presets.mkdir(parents=True)
    (presets / "broken.yaml").write_text("- just\n- a list\n")
    (presets / "matchall.yaml").write_text(
        "rules:\n  - label: sweep\n    event_type_pattern: '*'\n  - label: ok\n    ip_pattern: 10.0.0.0/8\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        integrations, "_LOCAL_PRESET_DIR", integrations.Path("config") / "suppression_presets"
    )

    assert "error" in await integrations.suppression_load_preset("broken")
    result = await integrations.suppression_load_preset("matchall")
    assert [r["label"] for r in result["applied"]] == ["ok"]
    assert any(s["label"] == "sweep" for s in result["skipped"])


# ── Delivery queue ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delivery_queue_sheds_low_severity_first_and_counts_drops(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.webhooks import WebhookDelivery

    monkeypatch.setattr(get_settings(), "webhook_queue_max", 3)
    d = WebhookDelivery()
    await d.enqueue_batch([_event("low") for _ in range(5)])
    assert d.pending == 3
    assert d.dropped_count == 2

    d2 = WebhookDelivery()
    await d2.enqueue_batch([_event("high", event_type=f"h{i}") for i in range(3)])
    await d2.enqueue_batch([_event("low")])  # full of HIGH: the newcomer is shed
    assert d2.pending == 3 and d2.dropped_count == 1
    await d2.enqueue_batch([_event("critical", event_type="crit")])
    kept = [j.event.event_type for j in d2._high]
    assert "crit" in kept and d2.pending == 3 and d2.dropped_count == 2


@pytest.mark.asyncio
async def test_one_slow_subscription_does_not_delay_the_others(monkeypatch):
    from honeypot_mcp import webhooks
    from honeypot_mcp.storage.models import AlertSeverity

    subs = [
        SimpleNamespace(id=1, severity_threshold=AlertSeverity.LOW),
        SimpleNamespace(id=2, severity_threshold=AlertSeverity.LOW),
    ]

    async def fake_subs():
        return subs

    delivered: list[tuple[int, float]] = []

    async def fake_dispatch(self, event, sub):
        if sub.id == 1:
            await asyncio.sleep(5)  # the slow destination
        delivered.append((sub.id, time.monotonic()))
        return True, None

    async def fake_record(self, sub_id, ok, err):
        return None

    monkeypatch.setattr(webhooks, "_active_subscriptions", fake_subs)
    monkeypatch.setattr(webhooks.WebhookDelivery, "_dispatch", fake_dispatch)
    monkeypatch.setattr(webhooks.WebhookDelivery, "_record_outcome", fake_record)

    d = webhooks.WebhookDelivery()
    await d.start()
    try:
        start = time.monotonic()
        await d.enqueue_batch([_event("high", event_type=f"e{i}") for i in range(3)])
        for _ in range(40):
            if sum(1 for sid, _t in delivered if sid == 2) == 3:
                break
            await asyncio.sleep(0.05)
        fast = [t for sid, t in delivered if sid == 2]
        assert len(fast) == 3
        assert max(fast) - start < 2.0
    finally:
        for task in list(d._inflight):
            task.cancel()
        await d.stop()


def test_critical_events_are_capped_per_event_type_and_the_count_rides_along():
    from honeypot_mcp.webhooks import _NotifyThrottle

    # The per-source repeat window is off here: this pins the per-type cap on its own, the backstop
    # for floods whose source address rotates (so no per-source window can see them).
    throttle = _NotifyThrottle(critical_cap=3, critical_window=0.15, critical_repeat_window=0)
    # A spoofed-source flood rotates source_ip but not the event type.
    sent = [throttle.check(1, _event("critical", event_type="snmp_flood"))[0] for _ in range(8)]
    assert sent == [True, True, True, False, False, False, False, False]
    # A different event type is unaffected.
    assert throttle.check(1, _event("critical", event_type="honeytoken_trip"))[0] is True
    time.sleep(0.2)
    ok, suppressed = throttle.check(1, _event("critical", event_type="snmp_flood"))
    assert ok is True and suppressed == 5


# ── honeypot-less events (canary / token triggers) ──────────────────────────


def test_every_renderer_tolerates_an_event_with_no_honeypot():
    from honeypot_mcp import webhooks
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    sub = Subscription(
        label="t",
        url="https://hooks.example.com/x",
        format="json",
        severity_threshold=AlertSeverity.LOW,
        hmac_secret="s" * 20,
        active=True,
    )
    ev = _event("critical", honeypot_id=None, event_type="honeytoken_triggered_canary")
    ev.honeytoken_id = 7
    for name in (
        "render_json",
        "render_splunk_hec",
        "render_elastic_ecs",
        "render_cef",
        "render_loki",
        "render_datadog",
        "render_slack",
        "render_teams",
        "render_email",
    ):
        assert getattr(webhooks, name)(ev, sub), name
    assert webhooks.render_syslog(ev, sub)


async def test_webhook_drops_reach_the_metrics_endpoint():
    """Two halves of the same feature were written apart: the delivery queue counted
    drops as `dropped` while the metrics code read `dropped_count`, so the
    `honeypot_webhook_dropped_total` series was silently never exported — a shed
    notification was invisible to the operator who needed to know."""
    from honeypot_mcp import webhooks
    from honeypot_mcp.metrics import _gather_metrics

    delivery = webhooks.get_delivery()
    before = delivery.dropped_count
    delivery.dropped_count = before + 7
    try:
        body = await _gather_metrics()
    finally:
        delivery.dropped_count = before
    assert f"honeypot_webhook_dropped_total {before + 7}" in body
