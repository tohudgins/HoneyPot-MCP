"""Centralised logging configuration with optional JSON output.

Why this exists: production deployments ship logs through Loki / Splunk /
CloudWatch / Datadog. All of those parse JSON significantly better than the
default `%(asctime)s | %(levelname)s | %(name)s | %(message)s` format.

Set `LOG_FORMAT=json` in `.env` (or `log_format: json` in YAML) to switch.
Default stays `text` so local dev output remains readable.

No external dependencies — uses stdlib `logging` only. The formatter
includes any extra `LogRecord` attributes (passed via `logger.log(...,
extra={"key": ...})` or via structured logging adapters) so the format is
extensible without changing this module.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

# Standard LogRecord attributes that should NOT be serialised as "extra"
# context — they're already covered by other fields in our output.
_STANDARD_LOGRECORD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


class JsonFormatter(logging.Formatter):
    """One JSON object per log line.

    Fields:
        ts       — ISO-8601 UTC timestamp
        level    — log level name (INFO, WARNING, etc.)
        logger   — logger name (e.g. honeypot_mcp.engines.ssh)
        msg      — formatted log message
        module   — Python module that emitted the log
        line     — line number in that module
        + any `extra={...}` keys passed to the logger call
        + exc_info as `exc` if an exception was attached
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build message body — preserves printf-style formatting.
        message = record.getMessage()

        payload: dict[str, Any] = {
            "ts": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": message,
            "module": record.module,
            "line": record.lineno,
        }

        # Pull through any structured-logging extras attached via
        # logger.log(..., extra={"foo": "bar"}).
        for key, value in record.__dict__.items():
            if key in _STANDARD_LOGRECORD_ATTRS or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str = "INFO", format_style: str = "text") -> None:
    """Configure the root logger.

    Safe to call multiple times — clears existing handlers each call to
    avoid duplicate output across reload / lifespan-restart scenarios.
    """
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    if format_style.lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
    root.addHandler(handler)
    root.setLevel(level.upper() if isinstance(level, str) else level)
