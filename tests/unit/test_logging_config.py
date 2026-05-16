"""Tests for the centralised logging config + JSON formatter."""

import io
import json
import logging


def test_json_formatter_emits_valid_json():
    from honeypot_mcp.logging_config import JsonFormatter

    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="honeypot_mcp.test",
        level=logging.INFO,
        pathname="/path/test.py",
        lineno=42,
        msg="test message %s",
        args=("value",),
        exc_info=None,
    )
    out = formatter.format(record)
    decoded = json.loads(out)

    assert decoded["level"] == "INFO"
    assert decoded["logger"] == "honeypot_mcp.test"
    assert decoded["msg"] == "test message value"
    assert decoded["line"] == 42
    assert "ts" in decoded


def test_json_formatter_picks_up_extras():
    from honeypot_mcp.logging_config import JsonFormatter

    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="honeypot_mcp.test",
        level=logging.WARNING,
        pathname="/path/test.py",
        lineno=1,
        msg="alert",
        args=(),
        exc_info=None,
    )
    record.attacker_ip = "1.2.3.4"
    record.severity = "high"

    out = formatter.format(record)
    decoded = json.loads(out)

    assert decoded["attacker_ip"] == "1.2.3.4"
    assert decoded["severity"] == "high"


def test_json_formatter_handles_exc_info():
    from honeypot_mcp.logging_config import JsonFormatter

    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        exc_info = sys.exc_info()

    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="honeypot_mcp.test",
        level=logging.ERROR,
        pathname="/path/test.py",
        lineno=1,
        msg="failed",
        args=(),
        exc_info=exc_info,
    )
    out = formatter.format(record)
    decoded = json.loads(out)
    assert "exc" in decoded
    assert "ValueError" in decoded["exc"]


def test_configure_logging_json_emits_json_lines():
    """End-to-end: configure JSON logging, log a message, captured output
    parses as JSON."""
    from honeypot_mcp.logging_config import configure_logging

    buf = io.StringIO()
    configure_logging(level="DEBUG", format_style="json")

    # Redirect root handler stream to our buffer
    root = logging.getLogger()
    for h in root.handlers:
        h.stream = buf

    log = logging.getLogger("honeypot_mcp.test_json")
    log.warning("hello %s", "world")

    raw = buf.getvalue().strip()
    assert raw, "expected at least one log line"
    parsed = json.loads(raw)
    assert parsed["msg"] == "hello world"
    assert parsed["level"] == "WARNING"


def test_configure_logging_text_emits_human_readable():
    """Default text format is still readable."""
    from honeypot_mcp.logging_config import configure_logging

    buf = io.StringIO()
    configure_logging(level="DEBUG", format_style="text")
    root = logging.getLogger()
    for h in root.handlers:
        h.stream = buf

    log = logging.getLogger("honeypot_mcp.test_text")
    log.info("simple message")

    raw = buf.getvalue()
    assert "INFO" in raw
    assert "simple message" in raw
    assert "honeypot_mcp.test_text" in raw
    # Should NOT be JSON
    try:
        json.loads(raw.strip())
        raise AssertionError("text format unexpectedly parsed as JSON")
    except json.JSONDecodeError:
        pass
