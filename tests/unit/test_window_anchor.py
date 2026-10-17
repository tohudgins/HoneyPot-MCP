"""Windowed tools in `ANALYSIS_MODE`: a backup is a frozen run, so "the last 24 hours" ends at the
newest alert, not at the wall clock. With the mode off the same call over the same database keeps
its live meaning and finds nothing, which is what pins the live behaviour.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import _window

    event_buffer.reset_for_tests()
    _window.reset_for_tests()
    await init_db()
    yield
    _window.reset_for_tests()
    event_buffer.reset_for_tests()
    await close_db()


def _newest() -> datetime:
    return (datetime.now(UTC) - timedelta(days=10)).replace(minute=30, second=0, microsecond=0)


async def _seed_frozen_run() -> None:
    """Five alerts: four in the final 24 h of the data, one 30 h before its end. Newest last."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    end = _newest()
    rows = [
        ("ssh_login_failed", "192.0.2.5", AlertSeverity.MEDIUM, end - timedelta(hours=30)),
        ("ssh_login_failed", "192.0.2.1", AlertSeverity.MEDIUM, end - timedelta(hours=2)),
        ("ssh_login_failed", "192.0.2.2", AlertSeverity.MEDIUM, end - timedelta(hours=2)),
        ("ssh_login_failed", "192.0.2.3", AlertSeverity.MEDIUM, end - timedelta(hours=2)),
        ("http_exploit_attempt", "198.51.100.4", AlertSeverity.HIGH, end),
    ]
    async with get_session() as session:
        for event_type, ip, severity, ts in rows:
            session.add(
                Alert(
                    source_ip=ip, event_type=event_type, severity=severity, payload={}, timestamp=ts
                )
            )


def _analysis_mode(monkeypatch: pytest.MonkeyPatch, on: bool) -> None:
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "analysis_mode", on)


async def _every_tool() -> dict[str, dict[str, Any]]:
    from honeypot_mcp.tools.alerts import alerts_recent, alerts_search, alerts_stats
    from honeypot_mcp.tools.analysis import analyze_campaign, attack_summary, threat_timeline
    from honeypot_mcp.tools.deception import soc_brief
    from honeypot_mcp.tools.patterns import attack_patterns

    return {
        "alerts_stats": await alerts_stats(since_hours=24),
        "soc_brief": await soc_brief(since_hours=24),
        "alerts_recent": await alerts_recent(since_hours=24),
        "alerts_search": await alerts_search("ssh_login", since_hours=24),
        "threat_timeline": await threat_timeline(hours=24),
        "analyze_campaign": await analyze_campaign(since_hours=24, min_sources=3),
        "attack_summary": await attack_summary(since_hours=24),
        "attack_patterns": await attack_patterns("concentration", since_hours=24),
    }


def _counts(out: dict[str, dict[str, Any]]) -> dict[str, int]:
    return {
        "alerts_stats": out["alerts_stats"]["total_alerts"],
        "soc_brief": out["soc_brief"]["volume"]["total_events"],
        "alerts_recent": out["alerts_recent"]["count"],
        "alerts_search": out["alerts_search"]["count"],
        "threat_timeline": out["threat_timeline"]["count"],
        "analyze_campaign": out["analyze_campaign"]["campaigns_total"],
        "attack_summary": out["attack_summary"]["total_alerts"],
        "attack_patterns": out["attack_patterns"].get("total_events", 0),
    }


async def test_analysis_mode_windows_end_at_the_newest_alert(monkeypatch):
    await _seed_frozen_run()
    _analysis_mode(monkeypatch, True)

    out = await _every_tool()

    assert _counts(out) == {
        "alerts_stats": 4,
        "soc_brief": 4,
        "alerts_recent": 4,
        "alerts_search": 3,
        "threat_timeline": 4,
        "analyze_campaign": 1,
        "attack_summary": 4,
        "attack_patterns": 4,
    }
    assert out["soc_brief"]["needs_attention_total"] == 1
    end = _newest().isoformat()
    for name, result in out.items():
        info = result["window"] if isinstance(result.get("window"), dict) else result
        assert info["window_anchor"] == "newest alert", name
        assert info["window_end"] == end, name
        assert (
            "newest alert" in info["window_anchor_note"]
            or "Analysis mode" in (info["window_anchor_note"])
        ), name


async def test_live_mode_keeps_the_wall_clock_window_and_finds_nothing(monkeypatch):
    await _seed_frozen_run()
    _analysis_mode(monkeypatch, False)

    out = await _every_tool()

    assert set(_counts(out).values()) == {0}
    for name, result in out.items():
        info = result["window"] if isinstance(result.get("window"), dict) else result
        assert "window_anchor" not in info, name


async def test_reset_for_tests_drops_the_cached_newest_alert(monkeypatch):
    from honeypot_mcp.tools import _window

    await _seed_frozen_run()
    _analysis_mode(monkeypatch, True)
    assert await _window.window_end() == _newest()

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    later = _newest() + timedelta(days=1)
    async with get_session() as session:
        session.add(
            Alert(
                source_ip="192.0.2.9",
                event_type="x",
                severity=AlertSeverity.LOW,
                payload={},
                timestamp=later,
            )
        )
    assert await _window.window_end() == _newest(), "cached while nothing is capturing"
    _window.reset_for_tests()
    assert await _window.window_end() == later


async def test_journey_fingerprint_and_blocklist_use_the_anchored_end(monkeypatch):
    from honeypot_mcp.tools.analysis import analyze_attacker_journey, fingerprint_clusters

    await _seed_frozen_run()
    _analysis_mode(monkeypatch, True)

    journey = await analyze_attacker_journey("192.0.2.1", hours=24)
    assert journey["total_alerts"] == 1
    assert journey["window_anchor"] == "newest alert"

    clusters = await fingerprint_clusters(hours=24)
    assert clusters["window_anchor"] == "newest alert"

    _analysis_mode(monkeypatch, False)
    assert (await analyze_attacker_journey("192.0.2.1", hours=24))["total_alerts"] == 0


# ── no tool may reintroduce a wall-clock window ───────────────────────────────

_SRC = Path(__file__).resolve().parents[2] / "src" / "honeypot_mcp"
_WALL_CLOCK_WINDOW = re.compile(
    r"datetime\.now\([^)]*\)(?:\.replace\([^)]*\))?\s*-\s*timedelta\(\s*(?:hours|minutes|days)\s*="
)

# (file, stripped source line) -> why a wall-clock cutoff is correct there.
_ALLOWED = {
    ("tools/_window.py", None): "the helper itself",
    (
        "tools/alerts.py",
        "cutoff = datetime.now(UTC) - timedelta(days=older_than_days)",
    ): "retention: deletes by real age, and pruning is refused in analysis mode",
    (
        "tools/alerts.py",
        "since = datetime.now(UTC) - timedelta(hours=since_hours)",
    ): "audit_log_search: audit rows are written at real time, not data time",
}


def test_no_tool_computes_a_window_from_the_wall_clock():
    offenders: list[str] = []
    files = [
        *sorted((_SRC / "tools").glob("*.py")),
        *sorted((_SRC / "analysis").glob("*.py")),
        _SRC / "storage" / "queries.py",
        _SRC / "storage" / "rollups.py",
    ]
    for path in files:
        rel = path.relative_to(_SRC).as_posix()
        if (rel, None) in _ALLOWED:
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            if _WALL_CLOCK_WINDOW.search(line) and (rel, line.strip()) not in _ALLOWED:
                offenders.append(f"{rel}:{number}: {line.strip()}")
    assert not offenders, (
        "a `since_hours` window must end at `await window_end()` (tools/_window.py), or the tool "
        "returns an empty window on a frozen backup. Offending lines:\n" + "\n".join(offenders)
    )
