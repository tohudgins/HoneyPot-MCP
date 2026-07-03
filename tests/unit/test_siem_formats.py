"""SIEM format renderer + transport tests.

Covers the five subscription formats:
* json — current default, HMAC-signed body
* splunk_hec — Splunk HTTP Event Collector envelope + Authorization: Splunk
* elastic_ecs — Elastic Common Schema field re-mapping
* cef — ArcSight Common Event Format pipe-delimited text
* syslog — RFC 5424 framed message over UDP or TCP

For HTTP formats we drive an aiohttp test server and assert what hit it.
For syslog we listen on a real UDP socket / TCP server and verify the
framed bytes that arrive.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
from datetime import UTC, datetime
from typing import Any

import pytest
from aiohttp import web

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _free_port(kind: int = socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


def _make_event(
    *,
    severity: str = "high",
    honeytoken_id: int | None = None,
) -> Any:
    """Build a PendingEvent with realistic fields."""
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=42,
        source_ip="203.0.113.7",
        source_port=54321,
        event_type="ssh_login_failed",
        payload={"username": "root", "password": "hunter2"},
        severity=AlertSeverity(severity),
        honeytoken_id=honeytoken_id,
        timestamp=datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC),
    )


def _make_sub(*, fmt: str, hmac_secret: str | None = None, url: str = "http://x/x") -> Any:
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    return Subscription(
        id=1,
        label="test",
        url=url,
        severity_threshold=AlertSeverity.LOW,
        format=fmt,
        hmac_secret=hmac_secret,
        active=True,
    )


# ── Renderer unit tests ────────────────────────────────────────────────────


def test_json_renderer_matches_legacy_shape():
    from honeypot_mcp.webhooks import render_json

    body, headers = render_json(_make_event(), _make_sub(fmt="json"))
    doc = json.loads(body)
    assert doc["source_ip"] == "203.0.113.7"
    assert doc["event_type"] == "ssh_login_failed"
    assert doc["severity"] == "high"
    assert headers["Content-Type"] == "application/json"
    # No HMAC header when secret is None
    assert "X-HoneyPot-Signature" not in headers


def test_json_renderer_signs_body_when_hmac_secret_set():
    from honeypot_mcp.webhooks import render_json

    body, headers = render_json(_make_event(), _make_sub(fmt="json", hmac_secret="topsecret"))
    sig = headers.get("X-HoneyPot-Signature", "")
    assert sig.startswith("sha256=")
    # Recompute and compare
    import hashlib
    import hmac

    expected = "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    assert sig == expected


def test_splunk_hec_renderer_envelope_and_auth():
    """Body must be `{"time":..., "host":..., "sourcetype":..., "event":{...}}`
    and the HEC token must ride in `Authorization: Splunk <token>`."""
    from honeypot_mcp.webhooks import render_splunk_hec

    body, headers = render_splunk_hec(
        _make_event(), _make_sub(fmt="splunk_hec", hmac_secret="hec-token-xyz")
    )
    doc = json.loads(body)
    assert doc["sourcetype"] == "honeypot:alert"
    assert doc["host"] == "honeypot-mcp"
    assert doc["event"]["source_ip"] == "203.0.113.7"
    assert isinstance(doc["time"], float)  # epoch seconds
    assert headers["Authorization"] == "Splunk hec-token-xyz"
    assert headers["Content-Type"] == "application/json"


def test_elastic_ecs_renderer_remaps_to_ecs_fields():
    """Source IP under `source.ip`, action under `event.action`, severity
    as numeric per ECS scale (high=7)."""
    from honeypot_mcp.webhooks import render_elastic_ecs

    body, _headers = render_elastic_ecs(_make_event(severity="high"), _make_sub(fmt="elastic_ecs"))
    doc = json.loads(body)
    assert doc["@timestamp"] == "2026-05-20T12:00:00+00:00"
    assert doc["source"]["ip"] == "203.0.113.7"
    assert doc["source"]["port"] == 54321
    assert doc["event"]["action"] == "ssh_login_failed"
    assert doc["event"]["kind"] == "alert"
    assert doc["event"]["severity"] == 7  # high
    assert doc["event"]["dataset"] == "honeypot.mcp"
    # event.category should classify ssh_login_failed as authentication
    assert "authentication" in doc["event"]["category"]
    # Native payload preserved in event.original
    original = json.loads(doc["event.original"])
    assert original["payload"]["username"] == "root"


def test_elastic_ecs_critical_uses_severity_9():
    from honeypot_mcp.webhooks import render_elastic_ecs

    body, _ = render_elastic_ecs(_make_event(severity="critical"), _make_sub(fmt="elastic_ecs"))
    assert json.loads(body)["event"]["severity"] == 9


def test_cef_renderer_emits_pipe_delimited_header_and_extensions():
    """CEF:0|Vendor|Product|Version|EventID|EventName|Severity|extension"""
    from honeypot_mcp.webhooks import render_cef

    body, headers = render_cef(_make_event(), _make_sub(fmt="cef"))
    text = body.decode("utf-8")
    assert text.startswith("CEF:0|HoneyPotMCP|server|1.0|ssh_login_failed|ssh_login_failed|")
    # Extension fields after the 7th pipe
    parts = text.split("|", 7)
    ext = parts[7]
    assert "src=203.0.113.7" in ext
    assert "spt=54321" in ext
    assert "cs1=42" in ext
    assert "cs1Label=honeypot_id" in ext
    assert headers["Content-Type"].startswith("text/plain")


def test_cef_escapes_pipes_in_event_type():
    """A pipe in the event_type field would break CEF parsing — must escape."""
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.webhooks import render_cef

    ev = PendingEvent(
        honeypot_id=1,
        source_ip="1.1.1.1",
        source_port=80,
        event_type="weird|event",
        payload={},
        severity=AlertSeverity.LOW,
        honeytoken_id=None,
        timestamp=datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC),
    )
    body, _ = render_cef(ev, _make_sub(fmt="cef"))
    text = body.decode()
    # The escaped form `weird\|event` MUST appear in the raw output.
    # We can't split on `|` to check structure here — that's the whole
    # point: a CEF parser walks the string and skips `\|` sequences, so
    # splitting on the raw delimiter would also chunk the value.
    assert r"weird\|event" in text
    # And the unescaped form must NOT appear by itself — i.e. there's
    # no `|weird|event|` in the header that would confuse a parser.
    assert "|weird|event|" not in text


def test_syslog_renderer_emits_rfc5424_framed_message():
    """<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG"""
    from honeypot_mcp.webhooks import render_syslog

    body = render_syslog(_make_event(severity="critical"), _make_sub(fmt="syslog"))
    text = body.decode("utf-8")
    # PRI for facility=16, severity=2 (critical) → 16*8+2 = 130
    assert text.startswith("<130>1 ")
    parts = text.split(" ", 7)
    assert parts[0] == "<130>1"
    # Timestamp section is RFC 3339 — must end in 'Z' or have +HH:MM
    assert parts[1].endswith("Z") or parts[1].endswith("+00:00")
    assert parts[2] == "honeypot-mcp"
    assert parts[3] == "honeypot"
    assert parts[5] == "ssh_login_failed"  # MSGID
    # MSG body is a JSON object with the native fields
    msg_doc = json.loads(parts[7])
    assert msg_doc["event_type"] == "ssh_login_failed"


def test_loki_renderer_envelope_uses_string_nanoseconds():
    """Loki silently 400s if the timestamp is a number — must be a string of
    nanoseconds. Stream labels carry severity, event_type, source_ip."""
    from honeypot_mcp.webhooks import render_loki

    body, headers = render_loki(_make_event(severity="critical"), _make_sub(fmt="loki"))
    doc = json.loads(body)
    streams = doc["streams"]
    assert len(streams) == 1
    stream = streams[0]
    assert stream["stream"]["job"] == "honeypot-mcp"
    assert stream["stream"]["severity"] == "critical"
    assert stream["stream"]["event_type"] == "ssh_login_failed"
    assert stream["stream"]["source_ip"] == "203.0.113.7"
    # Values: [[<ns string>, <payload string>], ...]
    assert len(stream["values"]) == 1
    ts_ns, payload_line = stream["values"][0]
    assert isinstance(ts_ns, str), "Loki timestamp MUST be a string of nanoseconds"
    # Reconstruct expected ns from the same datetime to avoid hardcoding wrong epoch
    expected_ns = str(int(datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC).timestamp() * 1_000_000_000))
    assert ts_ns == expected_ns
    # Payload is JSON-encoded native dict
    payload = json.loads(payload_line)
    assert payload["event_type"] == "ssh_login_failed"
    assert headers["Content-Type"] == "application/json"
    # No auth header without hmac_secret
    assert "Authorization" not in headers


def test_loki_renderer_basic_auth_header_when_secret_set():
    """Operators pre-encode `<userid>:<token>` for Grafana Cloud; we pass it
    through unchanged in the Basic auth header."""
    from honeypot_mcp.webhooks import render_loki

    pre_encoded = "ZGVtbzpHRkNfc2VjcmV0X3Rva2VuMTIz"
    _, headers = render_loki(_make_event(), _make_sub(fmt="loki", hmac_secret=pre_encoded))
    assert headers["Authorization"] == f"Basic {pre_encoded}"


def test_datadog_renderer_status_mapping_table_driven():
    """Datadog status: low→info, medium→warning, high→error, critical→critical."""
    from honeypot_mcp.webhooks import render_datadog

    expected = {
        "low": "info",
        "medium": "warning",
        "high": "error",
        "critical": "critical",
    }
    for severity, dd_status in expected.items():
        body, _ = render_datadog(_make_event(severity=severity), _make_sub(fmt="datadog"))
        entries = json.loads(body)
        assert isinstance(entries, list), "Datadog v2 logs intake expects a JSON array"
        assert len(entries) == 1
        assert entries[0]["status"] == dd_status, f"severity={severity} → status={dd_status}"
        assert entries[0]["ddsource"] == "honeypot-mcp"
        assert entries[0]["service"] == "honeypot"


def test_datadog_renderer_api_key_header():
    """DD-API-KEY header carries the API key (stored in hmac_secret)."""
    from honeypot_mcp.webhooks import render_datadog

    _, headers = render_datadog(_make_event(), _make_sub(fmt="datadog", hmac_secret="dd-api-xyz"))
    assert headers["DD-API-KEY"] == "dd-api-xyz"
    assert headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_loki_format():
    """End-to-end: subscribe a loki format, deliver an event, assert the
    captured POST has the streams envelope + Basic auth header."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port()
    runner, captures = await _start_http_capture(port)
    try:
        async with get_session() as session:
            sub = Subscription(
                label="loki-test",
                url=f"http://127.0.0.1:{port}/loki/api/v1/push",
                severity_threshold=AlertSeverity.LOW,
                format="loki",
                hmac_secret="dXNlcjpwYXNz",  # base64("user:pass")
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event(severity="high")])
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()
    finally:
        await runner.cleanup()

    assert len(captures) == 1
    cap = captures[0]
    assert cap["path"] == "/loki/api/v1/push"
    assert cap["headers"].get("Authorization") == "Basic dXNlcjpwYXNz"
    doc = json.loads(cap["body"])
    assert doc["streams"][0]["stream"]["severity"] == "high"


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_datadog_format():
    """End-to-end: subscribe a datadog format, deliver an event, assert the
    captured POST has the v2 logs envelope + DD-API-KEY header."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port()
    runner, captures = await _start_http_capture(port)
    try:
        async with get_session() as session:
            sub = Subscription(
                label="dd-test",
                url=f"http://127.0.0.1:{port}/api/v2/logs",
                severity_threshold=AlertSeverity.LOW,
                format="datadog",
                hmac_secret="dd-api-test-key",
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event(severity="critical")])
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()
    finally:
        await runner.cleanup()

    assert len(captures) == 1
    cap = captures[0]
    assert cap["path"] == "/api/v2/logs"
    assert cap["headers"].get("DD-API-KEY") == "dd-api-test-key"
    entries = json.loads(cap["body"])
    assert isinstance(entries, list)
    assert entries[0]["status"] == "critical"


# ── Transport integration tests ────────────────────────────────────────────


async def _start_http_capture(port: int) -> tuple[web.AppRunner, list[dict]]:
    """Aiohttp test server that records every POST. Returns (runner, captures)."""
    captures: list[dict] = []

    async def _handle(request: web.Request) -> web.Response:
        body = await request.read()
        captures.append(
            {
                "path": request.path,
                "headers": dict(request.headers),
                "body": body,
            }
        )
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", _handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner, captures


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_splunk_hec_format():
    """End-to-end: subscribe a splunk_hec format, deliver an event, assert
    the captured POST has the HEC envelope + auth header."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port()
    runner, captures = await _start_http_capture(port)

    try:
        async with get_session() as session:
            sub = Subscription(
                label="splunk-test",
                url=f"http://127.0.0.1:{port}/services/collector/event",
                severity_threshold=AlertSeverity.LOW,
                format="splunk_hec",
                hmac_secret="hec-token-test",
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event()])
            # Give the worker a beat to drain
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()
    finally:
        await runner.cleanup()

    assert len(captures) == 1
    cap = captures[0]
    assert cap["path"] == "/services/collector/event"
    assert cap["headers"].get("Authorization") == "Splunk hec-token-test"
    doc = json.loads(cap["body"])
    assert doc["sourcetype"] == "honeypot:alert"
    assert doc["event"]["event_type"] == "ssh_login_failed"

    async with get_session() as session:
        row = (
            await session.execute(select(Subscription).where(Subscription.label == "splunk-test"))
        ).scalar_one()
    assert row.delivery_count == 1
    assert row.failure_count == 0


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_elastic_ecs_format():

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port()
    runner, captures = await _start_http_capture(port)
    try:
        async with get_session() as session:
            sub = Subscription(
                label="elastic-test",
                url=f"http://127.0.0.1:{port}/bulk",
                severity_threshold=AlertSeverity.LOW,
                format="elastic_ecs",
                hmac_secret=None,
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event(severity="critical")])
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()
    finally:
        await runner.cleanup()

    assert len(captures) == 1
    doc = json.loads(captures[0]["body"])
    assert doc["source"]["ip"] == "203.0.113.7"
    assert doc["event"]["severity"] == 9  # critical → ECS 9
    assert doc["event"]["action"] == "ssh_login_failed"


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_cef_format():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port()
    runner, captures = await _start_http_capture(port)
    try:
        async with get_session() as session:
            sub = Subscription(
                label="cef-test",
                url=f"http://127.0.0.1:{port}/cef",
                severity_threshold=AlertSeverity.LOW,
                format="cef",
                hmac_secret=None,
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event()])
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()
    finally:
        await runner.cleanup()

    assert len(captures) == 1
    text = captures[0]["body"].decode("utf-8")
    assert text.startswith("CEF:0|HoneyPotMCP|server|")


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_syslog_udp():
    """Bind a real UDP socket and assert the framed message arrives."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    port = _free_port(socket.SOCK_DGRAM)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", port))
    udp_sock.setblocking(False)

    try:
        async with get_session() as session:
            sub = Subscription(
                label="syslog-test",
                url=f"udp://127.0.0.1:{port}",
                severity_threshold=AlertSeverity.LOW,
                format="syslog",
                hmac_secret=None,
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event(severity="critical")])
            # Wait for the worker to send
            await asyncio.sleep(1.5)
        finally:
            await delivery.stop()

        # Drain the receive socket
        loop = asyncio.get_event_loop()
        received = await loop.run_in_executor(None, lambda: udp_sock.recvfrom(65536))
        payload = received[0].decode("utf-8")
    finally:
        udp_sock.close()

    assert payload.startswith("<130>1 ")  # facility 16, severity 2 (critical)
    assert "ssh_login_failed" in payload


@pytest.mark.asyncio
async def test_webhook_delivery_dispatches_syslog_tcp():
    """TCP syslog uses octet-counting framing per RFC 6587."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import WebhookDelivery

    received: list[bytes] = []
    server_ready = asyncio.Event()

    async def _on_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(65536)
        received.append(data)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    server = await asyncio.start_server(_on_conn, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_ready.set()

    try:
        async with get_session() as session:
            sub = Subscription(
                label="syslog-tcp-test",
                url=f"tcp://127.0.0.1:{port}",
                severity_threshold=AlertSeverity.LOW,
                format="syslog",
                hmac_secret=None,
                active=True,
            )
            session.add(sub)
            await session.flush()

        delivery = WebhookDelivery()
        await delivery.start()
        try:
            await delivery.enqueue_batch([_make_event()])
            # Wait for the worker to send
            for _ in range(20):
                if received:
                    break
                await asyncio.sleep(0.1)
        finally:
            await delivery.stop()
    finally:
        server.close()
        await server.wait_closed()

    assert received
    blob = received[0]
    # RFC 6587 octet-counted: `<length> <message>`
    sp = blob.find(b" ")
    assert sp > 0
    msg_len = int(blob[:sp])
    msg = blob[sp + 1 : sp + 1 + msg_len].decode("utf-8")
    assert msg.startswith("<")  # PRI prefix
    assert "ssh_login_failed" in msg


@pytest.mark.asyncio
async def test_webhook_delivery_records_format_in_subscriptions_list():
    """alert_subscriptions_list should surface the chosen format so an
    operator can see at a glance which integration is configured."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.tools.integrations import alert_subscriptions_list

    async with get_session() as session:
        for fmt, label in (("json", "json-sub"), ("cef", "cef-sub")):
            session.add(
                Subscription(
                    label=label,
                    url="http://x/x",
                    severity_threshold=AlertSeverity.LOW,
                    format=fmt,
                    active=True,
                )
            )
        await session.flush()

    out = await alert_subscriptions_list(active_only=True)
    by_label = {s["label"]: s for s in out}
    assert by_label["json-sub"]["format"] == "json"
    assert by_label["cef-sub"]["format"] == "cef"


def _enriched_event() -> Any:
    """An event carrying auto-enrichment + new-engine capture data, exactly as
    a CRITICAL alert would after the buffer merges enrichment into payload."""
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=7,
        source_ip="203.0.113.7",
        source_port=443,
        event_type="redis_rce_dropper",
        payload={
            "target_path": "/root/.ssh/authorized_keys",
            "planted_keys": [{"key": "crackit", "payload_kind": "ssh_authorized_key"}],
            "enrichment": {
                "geoip": {"country": "Germany", "asn": 24940, "as_org": "Hetzner",
                          "reverse_dns": "static.example.your-server.de"},
                "abuseipdb": {"abuse_confidence_score": 100},
            },
        },
        severity=AlertSeverity.CRITICAL,
        timestamp=datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC),
    )


def test_enrichment_and_capture_survive_json_renderer():
    import json

    from honeypot_mcp.webhooks import render_json

    body, _ = render_json(_enriched_event(), _make_sub(fmt="json"))
    doc = json.loads(body)
    assert doc["event_type"] == "redis_rce_dropper"
    assert doc["payload"]["target_path"] == "/root/.ssh/authorized_keys"
    # Enrichment (ASN, reputation, reverse DNS) rides along in the payload.
    assert doc["payload"]["enrichment"]["geoip"]["asn"] == 24940
    assert doc["payload"]["enrichment"]["abuseipdb"]["abuse_confidence_score"] == 100


def test_enrichment_survives_ecs_event_original():
    import json

    from honeypot_mcp.webhooks import render_elastic_ecs

    body, _ = render_elastic_ecs(_enriched_event(), _make_sub(fmt="elastic_ecs"))
    doc = json.loads(body)
    # ECS stashes the full native payload (incl. enrichment) under event.original.
    original = json.loads(doc["event.original"])
    assert original["payload"]["enrichment"]["geoip"]["as_org"] == "Hetzner"
    assert doc["event"]["action"] == "redis_rce_dropper"


def test_capture_survives_cef_payload_field():
    from honeypot_mcp.webhooks import render_cef

    body, _ = render_cef(_enriched_event(), _make_sub(fmt="cef"))
    text = body.decode()
    # CEF stows the payload JSON in cs4 — the target path must be present.
    assert "authorized_keys" in text
    assert "redis_rce_dropper" in text


@pytest.mark.asyncio
async def test_subscription_cache_avoids_requery_and_honours_invalidation():
    """The active-subscription cache serves repeat reads without a DB round-trip
    and only reflects new rows after invalidation — the contract that keeps
    delivery off the DB on the ingest hot path."""
    from honeypot_mcp import webhooks
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription

    webhooks.invalidate_subscription_cache()

    # Empty to start — cached.
    assert await webhooks._active_subscriptions() == []

    # Insert directly (not via the tool, so no invalidation) — the cache still
    # returns the stale empty list within the TTL.
    async with get_session() as session:
        session.add(
            Subscription(
                label="siem",
                url="http://x/y",
                severity_threshold=AlertSeverity.LOW,
                format="json",
                active=True,
            )
        )
    assert await webhooks._active_subscriptions() == []

    # After explicit invalidation the new subscription is visible.
    webhooks.invalidate_subscription_cache()
    subs = await webhooks._active_subscriptions()
    assert len(subs) == 1
    assert subs[0].url == "http://x/y"
