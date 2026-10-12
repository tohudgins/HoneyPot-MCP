"""Agent-facing tools must stay bounded however much the honeypot has collected.

An MCP tool result lands directly in a model's context window. `analyze_attacker_journey`
loaded every alert for an IP and returned them all: for the busiest scanner on a
250,000-alert database that was 12.2 MB (millions of tokens) and five seconds. These
tests pin the contract that replaced it — totals exact, detail a representative
sample, output bounded.
"""

import json
import os
import time
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

IP = "198.51.100.23"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(count: int, ip: str = IP) -> datetime:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    start = datetime.now(UTC) - timedelta(hours=2)
    kinds = [
        ("ssh_login_failed", AlertSeverity.LOW),
        ("ssh_command_input", AlertSeverity.HIGH),
        ("http_probe", AlertSeverity.LOW),
    ]
    async with get_session() as session:
        for i in range(count):
            event_type, severity = kinds[i % len(kinds)]
            session.add(
                Alert(
                    source_ip=ip,
                    event_type=event_type,
                    severity=severity,
                    timestamp=start + timedelta(seconds=i),
                    payload={"username": "root", "password": f"p{i}", "input": "uname -a" * 3},
                )
            )
    return start


async def test_a_small_history_is_returned_in_full_and_exact():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    await _seed(30)
    out = await analyze_attacker_journey(IP)
    assert out["total_alerts"] == 30 and out["sampled"] is False
    assert "note" not in out
    assert sum(p["event_count"] for p in out["phases"]) == 30


async def test_a_huge_history_is_sampled_with_exact_totals_and_a_bounded_response():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    await _seed(4000)
    started = time.monotonic()
    out = await analyze_attacker_journey(IP)
    elapsed = time.monotonic() - started

    assert out["total_alerts"] == 4000, "the headline figure must be the real count"
    assert out["sampled"] is True and "sample" in out["note"]
    assert sum(p["event_count"] for p in out["phases"]) == 4000, "per-phase counts must be exact"
    assert all(
        p["events_shown"] <= 10 and len(p["events"]) == p["events_shown"] for p in out["phases"]
    )
    assert len(out["chronological"]) <= 40 and len(out["transitions"]) <= 30
    assert len(json.dumps(out, default=str)) < 60_000, "far too much for a model's context"
    assert elapsed < 5.0


async def test_sampling_keeps_the_start_the_end_and_the_most_severe_events():
    """The story needs when it began, where it ended up, and the worst thing it did."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    start = await _seed(3000)
    async with get_session() as session:
        session.add(
            Alert(
                source_ip=IP,
                event_type="honeytoken_triggered_credential_via_ssh_login_failed",
                severity=AlertSeverity.CRITICAL,
                timestamp=start + timedelta(seconds=1500, milliseconds=500),
                payload={"username": "svc-backup"},
            )
        )
    out = await analyze_attacker_journey(IP)
    assert out["total_alerts"] == 3001

    shown = {e["event_type"] for p in out["phases"] for e in p["events"]}
    assert "honeytoken_triggered_credential_via_ssh_login_failed" in shown, (
        "the single most severe event was dropped by sampling"
    )
    chrono_types = [e["event_type"] for e in out["chronological"]]
    assert chrono_types[0] == "ssh_login_failed"  # the very first alert is still there
    assert out["first_seen"] < out["last_seen"]


async def test_other_ips_are_not_swept_into_the_journey():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    await _seed(700, ip="203.0.113.77")
    await _seed(5, ip=IP)
    out = await analyze_attacker_journey(IP)
    assert out["total_alerts"] == 5 and out["sampled"] is False


async def test_no_activity_is_reported_not_errored():
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    out = await analyze_attacker_journey("192.0.2.200")
    assert out["total_alerts"] == 0 and "No activity" in out["summary"]


async def test_sampled_phase_counts_never_claim_more_exactness_than_they_have():
    """Per-phase counts in a sampled journey classify by event type; the sample also reads
    payload text, so it can find a phase (a command that edits authorized_keys is
    Persistence) the exact counts cannot. Summing both double-counted: 700 alerts came
    back as 816 phase events. Exact phases must sum to the total; any other phase must
    say it is not exact."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    start = datetime.now(UTC) - timedelta(hours=2)
    async with get_session() as session:
        for i in range(700):
            session.add(
                Alert(
                    source_ip=IP,
                    event_type="ssh_command_input",
                    severity=AlertSeverity.HIGH,
                    timestamp=start + timedelta(seconds=i),
                    payload={"input": f"echo key{i} >> ~/.ssh/authorized_keys"},
                )
            )
    out = await analyze_attacker_journey(IP)
    assert out["sampled"] is True and out["total_alerts"] == 700
    exact = [p for p in out["phases"] if p["event_count_exact"]]
    assert sum(p["event_count"] for p in exact) == 700
    assert out["transitions_basis"] == "sample"
    assert out["by_event_type"] == {"ssh_command_input": 700}


async def test_a_padded_ip_or_absurd_window_is_handled_not_misreported():
    """`validate_ip` tolerates surrounding whitespace, but the query used the raw string,
    so ' 9.9.9.9' reported 'no activity' for an attacker with hundreds of alerts."""
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    await _seed(12)
    out = await analyze_attacker_journey(f"  {IP} ")
    assert out["total_alerts"] == 12
    huge = await analyze_attacker_journey(IP, hours=10**9)  # was OverflowError
    assert huge["total_alerts"] == 12


async def test_a_phase_proven_by_exact_counts_names_its_technique_even_when_the_sample_missed_it():
    """The journey's sample is the earliest, latest and most severe events. A run of low-severity
    brute-force attempts in the middle of a long history is therefore absent from it, yet the exact
    per-type counts say the phase happened. It used to be listed with 2,570 events and no ATT&CK
    technique, which reads as an unmapped phase in a report."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity
    from honeypot_mcp.tools.analysis import analyze_attacker_journey

    start = datetime.now(UTC) - timedelta(hours=2)
    async with get_session() as session:
        for i in range(700):
            brute = 300 <= i < 305
            session.add(
                Alert(
                    source_ip=IP,
                    event_type="ssh_login_failed" if brute else "ssh_command_input",
                    severity=AlertSeverity.LOW if brute else AlertSeverity.HIGH,
                    timestamp=start + timedelta(seconds=i),
                    payload={"username": "root"} if brute else {"input": "uname -a"},
                )
            )
    out = await analyze_attacker_journey(IP)

    credential = next(p for p in out["phases"] if p["phase"] == "Credential Access")
    assert credential["event_count"] == 5 and credential["event_count_exact"] is True
    assert credential["events_shown"] == 0, (
        "the sample must not contain them, or this proves nothing"
    )
    assert {t["technique_id"] for t in credential["techniques"]} >= {"T1110.001"}
