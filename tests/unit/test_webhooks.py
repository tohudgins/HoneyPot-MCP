"""Tests for the webhook delivery layer.

Verifies: HMAC signature is correct + verifiable; severity threshold filters
events below the configured floor; serialised payload contains all fields a
SOC consumer needs.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime


def test_sign_body_produces_verifiable_signature():
    from honeypot_mcp.webhooks import sign_body

    secret = "shared-secret-123"
    body = b'{"event_type":"ssh_login_failed"}'
    sig = sign_body(secret, body)

    assert sig.startswith("sha256=")
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"


def test_signature_changes_when_body_changes():
    from honeypot_mcp.webhooks import sign_body

    a = sign_body("x", b"body-1")
    b = sign_body("x", b"body-2")
    assert a != b


def test_signature_changes_when_secret_changes():
    from honeypot_mcp.webhooks import sign_body

    a = sign_body("secret-a", b"same body")
    b = sign_body("secret-b", b"same body")
    assert a != b


def test_meets_threshold_drops_below():
    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.webhooks import _meets_threshold

    assert _meets_threshold(AlertSeverity.HIGH, AlertSeverity.MEDIUM) is True
    assert _meets_threshold(AlertSeverity.LOW, AlertSeverity.HIGH) is False
    assert _meets_threshold(AlertSeverity.CRITICAL, AlertSeverity.CRITICAL) is True


def test_serialise_emits_consumer_fields():
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.webhooks import _serialise

    ev = PendingEvent(
        honeypot_id=42,
        source_ip="1.2.3.4",
        event_type="ssh_login_failed",
        payload={"username": "root"},
        severity=AlertSeverity.HIGH,
        source_port=1234,
        timestamp=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
    )
    body = _serialise(ev)
    # Round-trip JSON to confirm everything is serialisable.
    json.dumps(body)

    assert body["source_ip"] == "1.2.3.4"
    assert body["severity"] == "high"
    assert body["honeypot_id"] == 42
    assert body["payload"]["username"] == "root"
    assert body["timestamp"].startswith("2024-06-01T12:00")
