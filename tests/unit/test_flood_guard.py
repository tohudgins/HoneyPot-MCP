"""The flood guard bounds what one source writes without hiding that it happened."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def _event(
    ip: str = "203.0.113.9",
    event_type: str = "sip_extension_probe",
    severity: str = "medium",
    honeypot_id: int | None = 7,
):
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    return PendingEvent(
        honeypot_id=honeypot_id,
        source_ip=ip,
        source_port=5060,
        event_type=event_type,
        payload={},
        severity=AlertSeverity(severity),
        timestamp=datetime.now(UTC),
    )


def test_a_source_is_stored_up_to_its_budget_then_counted():
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=5)
    verdicts = [guard.admit(_event(), now=100.0 + i * 0.01) for i in range(12)]
    assert verdicts == [True] * 5 + [False] * 7


def test_sources_and_event_types_are_independent():
    """A scanner that also tries a login still has the login recorded."""
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=2)
    for _ in range(10):
        guard.admit(_event(), now=100.0)
    assert guard.admit(_event(event_type="sip_register_attempt"), now=100.0) is True
    assert guard.admit(_event(ip="198.51.100.4"), now=100.0) is True


def test_the_window_rolls_over_and_the_drops_are_summarised_not_lost():
    from honeypot_mcp.flood_guard import SUMMARY_EVENT_TYPE, FloodGuard

    guard = FloodGuard(per_minute=3)
    for _ in range(10):
        guard.admit(_event(), now=100.0)
    # Next minute: a fresh budget, and the previous window's drops are owed as one summary.
    assert guard.admit(_event(), now=161.0) is True
    (summary,) = guard.due_summaries(now=161.0, force=True)
    assert summary.event_type == SUMMARY_EVENT_TYPE
    assert summary.payload["suppressed"] == 7 and summary.payload["stored"] == 3
    assert summary.payload["total"] == 10 and summary.payload["event_type"] == "sip_extension_probe"
    assert summary.source_ip == "203.0.113.9" and summary.honeypot_id == 7


def test_a_source_that_goes_quiet_still_gets_its_summary():
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=1)
    for _ in range(4):
        guard.admit(_event(), now=10.0)
    assert guard.due_summaries(now=20.0) == [], "the window has not ended yet"
    (summary,) = guard.due_summaries(now=80.0)
    assert summary.payload["suppressed"] == 3


def test_a_window_that_dropped_nothing_costs_no_summary_and_no_memory():
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=10)
    guard.admit(_event(), now=1.0)
    assert guard.due_summaries(now=100.0, force=True) == []
    assert guard._windows == {}


def test_zero_disables_the_guard():
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=0)
    assert all(guard.admit(_event()) for _ in range(1000))


def test_memory_is_bounded_and_eviction_never_discards_a_pending_count():
    from honeypot_mcp.flood_guard import FloodGuard

    guard = FloodGuard(per_minute=1, max_sources=8)
    for _ in range(5):
        guard.admit(_event(ip="203.0.113.1"), now=1.0)  # 4 dropped
    for i in range(2, 60):  # many other sources push the table past its bound
        guard.admit(_event(ip=f"198.51.100.{i}"), now=2.0 + i * 0.001)
    assert len(guard._windows) <= 8
    owed = guard.due_summaries(now=3.0, force=True)
    assert any(s.source_ip == "203.0.113.1" and s.payload["suppressed"] == 4 for s in owed)


@pytest.fixture
async def stored(monkeypatch):
    """submit_event with a capturing buffer, so the guard's effect on what is *stored* is visible."""
    from honeypot_mcp import flood_guard
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(get_settings(), "flood_guard_per_minute", 5, raising=False)
    flood_guard.reset_for_tests()
    event_buffer.reset_for_tests()
    await init_db()
    kept: list = []

    class _Capture:
        async def submit(self, event):
            kept.append(event)

    monkeypatch.setattr(event_buffer, "get_buffer", lambda: _Capture())

    async def _no_match(_event):
        return False

    monkeypatch.setattr(event_buffer, "_match_honeytokens", _no_match)
    yield kept
    flood_guard.reset_for_tests()
    # submit_event consults the suppression rules, which are read from the database. On PostgreSQL that
    # opens a pooled connection bound to THIS test's event loop; left open it poisoned the next test
    # ("Future attached to a different loop"). SQLite's in-memory database hid it.
    await close_db()


@pytest.mark.asyncio
async def test_submit_event_stores_the_budget_and_never_drops_critical_or_a_token_hit(stored):
    from honeypot_mcp.storage import event_buffer

    for _ in range(40):
        await event_buffer.submit_event(_event(ip="203.0.113.50"))
    assert len(stored) == 5, "the flood is cut to the per-minute budget"

    before = len(stored)
    for _ in range(40):
        await event_buffer.submit_event(_event(ip="203.0.113.50", severity="critical"))
    assert len(stored) - before == 40, "CRITICAL is never dropped"


@pytest.mark.asyncio
async def test_a_honeytoken_hit_is_never_dropped_by_the_guard(stored, monkeypatch):
    from honeypot_mcp.storage import event_buffer

    for _ in range(20):
        await event_buffer.submit_event(_event(ip="203.0.113.60"))
    assert len(stored) == 5

    async def _tripped(event):
        event.honeytoken_id = 1
        return True

    monkeypatch.setattr(event_buffer, "_match_honeytokens", _tripped)
    await event_buffer.submit_event(_event(ip="203.0.113.60"))
    assert len(stored) == 6, "a planted credential used by a flooder must still be recorded"
