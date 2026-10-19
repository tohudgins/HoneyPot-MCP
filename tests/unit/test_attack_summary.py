"""`attack_summary`: the whole run's ATT&CK picture from exact rollup counts."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(rows: list[tuple[str, int, timedelta]]) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    now = datetime.now(UTC)
    async with get_session() as session:
        for event_type, count, age in rows:
            for i in range(count):
                session.add(
                    Alert(
                        source_ip=f"198.51.100.{i % 5 + 1}",
                        event_type=event_type,
                        severity=AlertSeverity.MEDIUM,
                        timestamp=now - age,
                        payload={},
                    )
                )


async def test_every_event_type_is_mapped_with_exact_counts_in_kill_chain_order():
    from honeypot_mcp.intel.mitre import TACTIC_ORDER
    from honeypot_mcp.tools.analysis import attack_summary

    await _seed(
        [
            ("sip_request", 40, timedelta(0)),  # Discovery, T1046
            ("redis_config_set", 7, timedelta(0)),  # Initial Access, T1190
            ("ssh_login_failed", 12, timedelta(0)),  # Credential Access, T1110.001
        ]
    )
    out = await attack_summary()

    by_tactic = {t["tactic"]: t for t in out["tactics"]}
    assert by_tactic["Discovery"]["alerts"] == 40
    assert by_tactic["Initial Access"]["alerts"] == 7
    assert by_tactic["Credential Access"]["alerts"] == 12
    discovery = {t["technique_id"]: t for t in by_tactic["Discovery"]["techniques"]}
    assert discovery["T1046"]["alerts"] == 40
    assert discovery["T1046"]["top_event_types"] == [{"type": "sip_request", "alerts": 40}]
    order = [TACTIC_ORDER.index(t["tactic"]) for t in out["tactics"]]
    assert order == sorted(order), "tactics must follow the kill chain, not the alphabet"
    assert out["total_alerts"] == out["mapped_alerts"] == 59 and out["mapped_share"] == 1.0


async def test_bookkeeping_is_reported_as_unmapped_and_lowers_the_mapped_share():
    """Mapping a TCP connection to a technique would inflate every tactic; the summary must say how
    much of the run it left out instead of presenting a flattering coverage figure."""
    from honeypot_mcp.tools.analysis import attack_summary

    await _seed(
        [("redis_config_set", 5, timedelta(0)), ("telnet_session_connect", 15, timedelta(0))]
    )
    out = await attack_summary()

    assert out["total_alerts"] == 20 and out["mapped_alerts"] == 5
    assert out["mapped_share"] == 0.25
    assert out["unmapped"] == [{"type": "telnet_session_connect", "alerts": 15}]
    assert all(
        t["technique_id"] != "T1190" or t["alerts"] == 5
        for tactic in out["tactics"]
        for t in tactic["techniques"]
    )


async def test_the_window_excludes_older_alerts_and_a_bad_window_is_refused():
    from honeypot_mcp.tools.analysis import attack_summary

    await _seed([("redis_config_set", 4, timedelta(0)), ("redis_config_set", 6, timedelta(days=3))])
    recent = await attack_summary(since_hours=24)
    everything = await attack_summary()

    assert recent["total_alerts"] == 4 and everything["total_alerts"] == 10
    assert "error" in await attack_summary(since_hours=0)


async def test_an_empty_database_is_an_empty_summary_not_an_error():
    from honeypot_mcp.tools.analysis import attack_summary

    out = await attack_summary()

    assert out["total_alerts"] == 0 and out["tactics"] == [] and out["mapped_share"] == 0.0
