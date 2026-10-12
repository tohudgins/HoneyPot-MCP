"""Audit slice D: Cowrie ingestion must survive hostile/odd log lines, a dead
ingest task must be noticed, and the infra files must keep their security
posture (cheap static checks, no Docker)."""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

ROOT = Path(__file__).resolve().parents[2]


def _engine():
    from honeypot_mcp.engines.ssh import SSHEngine

    engine = SSHEngine()
    engine._client = MagicMock()
    return engine


def _good(**over):
    line = {
        "eventid": "cowrie.login.failed",
        "src_ip": "203.0.113.9",
        "src_port": 40000,
        "session": "abc123",
        "username": "root",
        "password": "x",
    }
    line.update(over)
    return json.dumps(line)


@pytest.fixture
def submitted(monkeypatch):
    events = []

    async def _fake_submit(event):
        if event.payload.get("session") == "boom":
            raise RuntimeError("downstream failure")
        events.append(event)

    monkeypatch.setattr("honeypot_mcp.engines.ssh.submit_event", _fake_submit)
    return events


async def _feed(engine, line):
    await engine._handle_line(line, 1, set(), deque(maxlen=8))


@pytest.mark.parametrize(
    "line",
    [
        "[1, 2, 3]",
        '"just a string"',
        "null",
        json.dumps({"eventid": ["cowrie.login.failed"]}),
        json.dumps({"eventid": {"a": 1}}),
        json.dumps({"eventid": 7}),
        "{not json",
        _good(src_ip="not-an-ip"),
        _good(src_ip="1.2.3.4\nforged"),
        _good(src_ip=["203.0.113.9"]),
        _good(src_ip="fe80::1%eth0"),
    ],
)
async def test_odd_lines_are_dropped_without_raising(line, submitted):
    await _feed(_engine(), line)
    assert submitted == []


async def test_valid_line_is_still_recorded(submitted):
    await _feed(_engine(), _good())
    assert len(submitted) == 1
    ev = submitted[0]
    assert ev.source_ip == "203.0.113.9"
    assert ev.event_type == "ssh_login_failed"
    assert ev.source_port == 40000


async def test_bad_port_and_session_types_do_not_crash(submitted):
    await _feed(_engine(), _good(src_port=["x"], session=["y"]))
    assert len(submitted) == 1
    assert submitted[0].source_port is None


async def test_ingest_loop_survives_a_poisoned_line_and_keeps_going(monkeypatch, submitted):
    engine = _engine()
    container = MagicMock()
    container.status = "running"
    batches = [
        # A poison line, a line with a unicode line separator inside a string
        # value (must not be sheared), then a good line.
        "\n".join(
            [
                json.dumps({"eventid": ["unhashable"]}),
                _good(session="boom"),
                _good(username="a\u2028b"),
                _good(session="s2"),
            ]
        ).encode(),
    ]

    def _logs(since=None, timestamps=False):
        if batches:
            return batches.pop(0)
        container.status = "exited"
        return b""

    container.logs = _logs
    engine._client.containers.get = MagicMock(return_value=container)

    @asynccontextmanager
    async def _session():
        yield MagicMock()

    monkeypatch.setattr("honeypot_mcp.engines.ssh.get_session", _session)
    monkeypatch.setattr(
        "honeypot_mcp.engines.ssh.queries.get_honeypot_by_name",
        AsyncMock(return_value=MagicMock(id=1)),
    )
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda _s: real_sleep(0))

    await asyncio.wait_for(engine._ingest_logs("hp", "cid"), timeout=10)
    assert len(submitted) == 2
    assert submitted[0].payload["username"] == "a\u2028b"


async def test_supervisor_restarts_a_crashed_ingest_task(monkeypatch):
    engine = _engine()
    calls = []

    async def _flaky(name, cid):
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("boom")

    engine._ingest_logs = _flaky
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda _s: real_sleep(0))
    await asyncio.wait_for(engine._supervise_ingest("hp", "cid"), timeout=10)
    assert len(calls) == 3


async def test_health_check_flags_and_heals_a_dead_ingest_task(monkeypatch):
    engine = _engine()
    container = MagicMock()
    container.status = "running"
    container.attrs = {"NetworkSettings": {"Networks": {}}}
    engine._client.containers.get = MagicMock(return_value=container)
    engine._ingest_logs = AsyncMock(return_value=None)

    async def _alive_probe(port, host="127.0.0.1", timeout=2.0, also_as=()):
        return {"alive": True, "detail": "ok"}

    monkeypatch.setattr("honeypot_mcp.engines.base.tcp_probe", _alive_probe)

    # Ingestion was started once, then died (no live task registered).
    engine._ingest_names["cid"] = "hp"
    result = await engine.health_check("cid", 2222)
    assert result["alive"] is False
    assert "ingestion" in result["detail"]
    # ... and it was respawned, so the next probe passes once the task is live.
    assert "cid" in engine._ingest_tasks


# ── static infra checks ──────────────────────────────────────────────────────


def test_cowrie_image_is_pinned():
    from honeypot_mcp.engines.ssh import COWRIE_IMAGE

    assert not COWRIE_IMAGE.endswith(":latest")
    assert re.search(r":\d+\.\d+\.\d+$", COWRIE_IMAGE)


def test_compose_does_not_publish_grafana_on_all_interfaces():
    for name in ("docker-compose.yml", "docker-compose.observability.yml"):
        text = (ROOT / "docker" / name).read_text()
        assert "${GRAFANA_PORT:-3000}:3000" in text
        assert not re.search(r'^\s*- "\$\{GRAFANA_PORT:-3000\}:3000"', text, re.M), name
        assert "GRAFANA_ADMIN_PASSWORD:-" not in text, name
        assert "--web.enable-lifecycle" not in text, name
