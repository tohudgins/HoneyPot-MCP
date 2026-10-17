"""`analyze_campaign` ranks campaigns instead of listing them largest-first.

On the real 116-hour run the tool returned 2,070 campaigns sorted by source count and showed 50:
mostly three sources sweeping one service in the same hour, with the ones that mattered (commands
run, exploit attempts, planted credentials) buried. These tests pin that the order is by an
explainable score that puts behaviour first, that `rank_by` reorders, and that every term of the
score is reported.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.analysis.correlator import (  # noqa: E402
    RANK_BY_VALUES,
    classify_kind,
    detect_campaigns,
)

BASE = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)


def _item(ip, event_type, *, hour=0, minute=0, weight=1, severity="medium"):
    return SimpleNamespace(
        source_ip=ip,
        event_type=event_type,
        honeypot_id=1,
        timestamp=BASE + timedelta(hours=hour, minutes=minute),
        weight=weight,
        severity=severity,
    )


def _many(prefix, count, event_type, **kwargs):
    return [_item(f"{prefix}.{n}", event_type, **kwargs) for n in range(1, count + 1)]


def _mixed() -> list[SimpleNamespace]:
    """Three campaigns that every ranking orders differently.

    behavioural: 3 sources run commands (high), earliest, 60 events
    mid:         6 sources authenticate over SMB (high), in the middle, 54 events
    sweep:       40 sources only connect (low), the latest, the most sources and events (80)
    """
    return (
        _many("192.0.2", 3, "ssh_command_input", hour=0, weight=20, severity="high")
        + _many("198.51.100", 6, "smb_ntlm_auth", hour=3, weight=9, severity="high")
        + _many("203.0.113", 40, "telnet_session_connect", hour=5, weight=2, severity="low")
    )


def _order(campaigns) -> list[str]:
    return [c["event_type"] for c in campaigns]


# ── kind ─────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("event_type", "severity", "kind"),
    [
        ("telnet_session_connect", "low", "sweep"),
        ("sip_extension_probe", "medium", "sweep"),
        ("smb_negotiate", "medium", "sweep"),
        ("rdp_handshake", "high", "sweep"),  # rated high, but only a handshake
        ("elasticsearch_query_probe", "medium", "sweep"),  # "probe" wins over "query"
        ("ssh_command_input", "high", "behavioural"),
        ("ssh_login_success", "high", "behavioural"),
        ("http_exploit_attempt", "medium", "behavioural"),
        ("redis_config_set", "high", "behavioural"),
        ("docker_api_container_create", "high", "behavioural"),
        ("some_new_probe", "critical", "behavioural"),  # critical is never a sweep
        ("mystery_event", "high", "behavioural"),
        ("mystery_event", "low", "sweep"),
        ("mystery_event", None, "sweep"),
    ],
)
def test_kind_separates_sweeps_from_behaviour(event_type, severity, kind):
    assert classify_kind(event_type, severity) == kind


# ── the default order ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_small_behavioural_campaign_outranks_a_big_connection_sweep_by_default():
    found = await detect_campaigns(_mixed(), window_minutes=60, min_sources=3)

    assert _order(found) == ["smb_ntlm_auth", "ssh_command_input", "telnet_session_connect"]
    by_type = {c["event_type"]: c for c in found}
    assert by_type["ssh_command_input"]["unique_source_ips"] == 3
    assert by_type["telnet_session_connect"]["unique_source_ips"] == 40
    assert by_type["ssh_command_input"]["kind"] == "behavioural"
    assert by_type["telnet_session_connect"]["kind"] == "sweep"
    assert by_type["ssh_command_input"]["score"] > by_type["telnet_session_connect"]["score"]
    # The old default (most sources first) would have put the sweep on top.
    assert max(found, key=lambda c: c["unique_source_ips"])["kind"] == "sweep"


@pytest.mark.asyncio
async def test_rank_by_changes_the_order():
    alerts = _mixed()
    orders = {
        rank_by: _order(await detect_campaigns(alerts, window_minutes=60, rank_by=rank_by))
        for rank_by in RANK_BY_VALUES
    }

    assert orders["score"] == ["smb_ntlm_auth", "ssh_command_input", "telnet_session_connect"]
    assert orders["sources"] == ["telnet_session_connect", "smb_ntlm_auth", "ssh_command_input"]
    assert orders["events"] == ["telnet_session_connect", "ssh_command_input", "smb_ntlm_auth"]
    assert orders["recent"] == ["telnet_session_connect", "smb_ntlm_auth", "ssh_command_input"]
    assert len({tuple(o) for o in orders.values()}) == 3
    # score is the default
    assert _order(await detect_campaigns(alerts, window_minutes=60)) == orders["score"]


@pytest.mark.asyncio
async def test_an_unknown_rank_by_is_rejected():
    with pytest.raises(ValueError, match="rank_by"):
        await detect_campaigns(_mixed(), rank_by="largest")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_a_behavioural_campaign_beats_even_the_best_possible_sweep_that_is_not_high():
    """The formula's own bound: a sweep that is rated medium and maxes breadth, duration,
    intensity and shared types still scores below the weakest behavioural campaign."""
    sweep = []
    for hour in range(4):  # 4 hours, 20 sources, 100k events each, two more shared types
        for n in range(1, 21):
            for etype in ("vnc_connection", "vnc_handshake", "vnc_security_selected"):
                sweep.append(_item(f"203.0.113.{n}", etype, hour=hour, weight=100_000))
    weakest = _many("192.0.2", 3, "ftp_command", severity="low")  # behavioural, low, 1 event each

    found = await detect_campaigns(sweep + weakest, window_minutes=240, min_sources=3)

    by_type = {c["event_type"]: c for c in found}
    top_sweep = by_type["vnc_connection"]
    assert top_sweep["kind"] == "sweep" and by_type["ftp_command"]["kind"] == "behavioural"
    assert top_sweep["score"] > 30, "the sweep really is near its ceiling"
    assert by_type["ftp_command"]["score"] > top_sweep["score"]
    assert found[0]["event_type"] == "ftp_command"


# ── the score is explainable ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_every_campaign_reports_its_score_terms_and_why():
    found = await detect_campaigns(_mixed(), window_minutes=60)

    for c in found:
        breakdown = c["score_breakdown"]
        assert set(breakdown) == {
            "kind",
            "severity",
            "breadth",
            "shared_types",
            "duration",
            "recurrence",
            "intensity",
        }
        assert c["score"] == pytest.approx(sum(breakdown.values()), abs=0.15)
        assert 0 <= c["score"] <= 100
        assert c["kind"] in ("sweep", "behavioural")
        assert c["event_type"] in c["why"] and c["kind"] in c["why"]
        assert f"{c['unique_source_ips']} sources" in c["why"]
    # Original fields are all still there.
    for key in (
        "event_type",
        "start_time",
        "end_time",
        "duration_minutes",
        "unique_source_ips",
        "total_events",
        "source_ips",
        "targeted_honeypots",
        "campaign_id",
    ):
        assert all(key in c for c in found)


@pytest.mark.asyncio
async def test_the_formula_terms_are_what_the_docstring_says():
    """Three sources, commands (high), one hour, 500 events each: kind 45 + severity 10 +
    breadth 3*log2(3) + intensity 2.25*log10(500), no shared types, duration or recurrence."""
    found = await detect_campaigns(
        _many("192.0.2", 3, "ssh_command_input", weight=500, severity="high"), min_sources=3
    )

    b = found[0]["score_breakdown"]
    assert b["kind"] == 45.0
    assert b["severity"] == 10.0
    assert b["breadth"] == pytest.approx(4.8, abs=0.05)
    assert b["intensity"] == pytest.approx(6.1, abs=0.05)
    assert b["shared_types"] == 0.0 and b["duration"] == 0.0 and b["recurrence"] == 0.0
    assert found[0]["events_per_source"] == 500.0


@pytest.mark.asyncio
async def test_terms_are_capped():
    alerts = []
    for hour in range(10):
        for n in range(1, 101):
            alerts.append(_item(f"203.0.113.{n}", "ssh_command_input", hour=hour, weight=10**7))
    found = await detect_campaigns(alerts, window_minutes=600, min_sources=3)

    b = found[0]["score_breakdown"]
    assert b["breadth"] == 12.0 and b["intensity"] == 9.0 and b["duration"] == 4.0


@pytest.mark.asyncio
async def test_sources_that_also_ran_other_event_types_share_them():
    """Four sources attack; three also ran commands and one also scanned. A type counts when at
    least half the sources produced it in the campaign's hours."""
    alerts = _many("192.0.2", 4, "ssh_login_failed", severity="medium")
    alerts += [_item(f"192.0.2.{n}", "ssh_command_input", severity="high") for n in (1, 2, 3)]
    alerts += [_item("192.0.2.1", "ssh_port_forward", severity="high")]
    alerts += [_item("192.0.2.1", "ssh_command_input", hour=9, severity="high")]  # outside hours

    found = await detect_campaigns(alerts, window_minutes=60, min_sources=3)

    login = next(c for c in found if c["event_type"] == "ssh_login_failed")
    assert login["shared_event_types"] == ["ssh_command_input"]
    assert login["score_breakdown"]["shared_types"] == 3.0
    assert "ssh_command_input" in login["why"]


@pytest.mark.asyncio
async def test_severity_is_the_highest_recorded_on_the_campaign():
    alerts = _many("192.0.2", 3, "http_probe", severity="low")
    alerts.append(_item("192.0.2.1", "http_probe", minute=5, severity="high"))

    found = await detect_campaigns(alerts, min_sources=3)

    assert found[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_alerts_without_a_severity_still_rank():
    """Alert-shaped objects that carry no severity (older callers) fall back to the name alone."""
    alerts = [
        SimpleNamespace(
            source_ip=f"192.0.2.{n}",
            event_type="ssh_command_input",
            honeypot_id=1,
            timestamp=BASE,
        )
        for n in range(1, 4)
    ]

    found = await detect_campaigns(alerts, min_sources=3)

    assert found[0]["severity"] is None
    assert found[0]["kind"] == "behavioural" and found[0]["score_breakdown"]["severity"] == 0.0


# ── recurring windows are one campaign ───────────────────────────────────────


def _hourly(ips, event_type, hours, weight=10, severity="high", rotate=None):
    """`ips` in each hour; with `rotate`, one extra address per hour, so no hour's sources are a
    subset of another's (identical sets are dropped by the unmerged de-duplication)."""
    items = []
    for h in hours:
        extra = [f"{rotate}.{100 + h}"] if rotate else []
        items += [
            _item(ip, event_type, hour=h, weight=weight, severity=severity) for ip in ips + extra
        ]
    return items


@pytest.mark.asyncio
async def test_the_same_sources_returning_every_hour_are_one_campaign():
    ips = [f"192.0.2.{n}" for n in range(1, 5)]
    alerts = _hourly(ips, "telnet_command_input", range(5), weight=10, rotate="192.0.2")

    merged = await detect_campaigns(alerts, window_minutes=0, min_sources=3)
    windows = await detect_campaigns(alerts, window_minutes=0, min_sources=3, merge_recurring=False)

    assert len(windows) == 5 and all(w["occurrences"] == 1 for w in windows)
    assert len(merged) == 1
    c = merged[0]
    assert c["occurrences"] == 5
    assert c["unique_source_ips"] == 9 and c["sources_per_window"] == 5
    assert c["max_sources_per_window"] == 5
    assert c["total_events"] == 5 * 5 * 10
    assert c["first_window"] == BASE.isoformat()
    assert c["last_window"] == (BASE + timedelta(hours=4)).isoformat()
    assert c["start_time"] == c["first_window"]
    assert c["end_time"] == c["last_window"] and c["duration_minutes"] == 4 * 60
    assert "recurred in 5 windows" in c["why"]
    assert c["score_breakdown"]["recurrence"] == pytest.approx(3.5, abs=0.05)  # 1.5 * log2(5)
    assert c["score_breakdown"]["duration"] == 4.0
    assert c["source_ips"][:4] == ips, "the sources seen in every hour are listed first"


@pytest.mark.asyncio
async def test_merging_keeps_the_events_and_hours_the_unmerged_dedup_dropped():
    """Five identical windows: the unmerged list keeps one (the others are subsets of it) and its
    event total, hours and recurrence are those of one hour. Merged, nothing is lost."""
    ips = [f"192.0.2.{n}" for n in range(1, 5)]
    alerts = _hourly(ips, "telnet_command_input", range(5), weight=10)

    unmerged = await detect_campaigns(alerts, window_minutes=0, merge_recurring=False)
    merged = await detect_campaigns(alerts, window_minutes=0)

    assert len(unmerged) == 1 and unmerged[0]["total_events"] == 40
    assert len(merged) == 1 and merged[0]["occurrences"] == 5 and merged[0]["total_events"] == 200


@pytest.mark.asyncio
async def test_windows_that_mostly_share_sources_merge_and_others_do_not():
    alerts = (
        _hourly(["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"], "ssh_command_input", [0])
        # 3 of its 4 sources were in the first window: the same actors, one new address
        + _hourly(["192.0.2.1", "192.0.2.2", "192.0.2.3", "198.51.100.9"], "ssh_command_input", [3])
        # 2 of 4 is exactly the threshold: joins
        + _hourly(
            ["192.0.2.1", "192.0.2.4", "198.51.100.1", "198.51.100.2"], "ssh_command_input", [6]
        )
        # 1 of 4 is a different set of actors
        + _hourly(
            ["192.0.2.1", "198.51.100.5", "198.51.100.6", "198.51.100.7"], "ssh_command_input", [9]
        )
    )

    found = await detect_campaigns(alerts, window_minutes=0, min_sources=3)

    assert sorted(c["occurrences"] for c in found) == [1, 3]
    big = next(c for c in found if c["occurrences"] == 3)
    assert big["unique_source_ips"] == 7 and big["sources_per_window"] == 4
    assert sum(c["occurrences"] for c in found) == 4, "every window is in exactly one campaign"


@pytest.mark.asyncio
async def test_a_small_window_mostly_inside_a_big_campaign_joins_it_but_never_across_types():
    big = _hourly([f"192.0.2.{n}" for n in range(1, 11)], "ssh_command_input", [0])
    small = _hourly(["192.0.2.1", "192.0.2.2", "198.51.100.1"], "ssh_command_input", [5])
    other_type = _hourly([f"192.0.2.{n}" for n in range(1, 11)], "ssh_login_success", [0])

    found = await detect_campaigns(big + small + other_type, window_minutes=0, min_sources=3)

    commands = [c for c in found if c["event_type"] == "ssh_command_input"]
    assert len(commands) == 1 and commands[0]["occurrences"] == 2
    assert commands[0]["unique_source_ips"] == 11 and commands[0]["sources_per_window"] == 3
    logins = [c for c in found if c["event_type"] == "ssh_login_success"]
    assert len(logins) == 1 and logins[0]["occurrences"] == 1


@pytest.mark.asyncio
async def test_source_ips_are_capped_most_persistent_first_with_the_full_count_kept():
    regulars = [f"192.0.2.{n}" for n in range(200, 205)]
    crowd = [f"198.51.100.{n}" for n in range(1, 60)]
    alerts = _hourly(regulars + crowd, "telnet_session_connect", [0], severity="low")
    alerts += _hourly(regulars + crowd[:10], "telnet_session_connect", [2, 4], severity="low")

    found = await detect_campaigns(alerts, window_minutes=0, min_sources=3)

    assert len(found) == 1
    c = found[0]
    assert c["unique_source_ips"] == 64 and c["occurrences"] == 3
    assert len(c["source_ips"]) == 20 and c["source_ips_shown"] == 20
    # everyone in all three windows (the 5 regulars and 10 of the crowd) before anyone in one
    assert set(c["source_ips"][:15]) == set(regulars + crowd[:10])


@pytest.mark.asyncio
async def test_a_single_window_lists_at_most_twenty_sources_too():
    alerts = _hourly(
        [f"198.51.100.{n}" for n in range(1, 41)], "vnc_connection", [0], severity="low"
    )

    found = await detect_campaigns(alerts, window_minutes=0, min_sources=3, merge_recurring=False)

    assert found[0]["unique_source_ips"] == 40 and len(found[0]["source_ips"]) == 20


@pytest.mark.asyncio
async def test_recurrence_term_is_capped_and_one_botnet_no_longer_fills_the_top():
    botnet = [f"192.0.2.{n}" for n in range(1, 18)]
    alerts = _hourly(botnet, "telnet_command_input", range(30), weight=100, rotate="192.0.2")
    alerts += _hourly(["198.51.100.1", "198.51.100.2", "198.51.100.3"], "redis_config_set", [4])
    alerts += _hourly(["203.0.113.1", "203.0.113.2", "203.0.113.3"], "ssh_login_success", [7])

    merged = await detect_campaigns(alerts, window_minutes=0, min_sources=3)
    raw = await detect_campaigns(alerts, window_minutes=0, min_sources=3, merge_recurring=False)

    assert len(raw) == 32 and len(merged) == 3
    assert {c["event_type"] for c in merged[:3]} == {
        "telnet_command_input",
        "redis_config_set",
        "ssh_login_success",
    }
    top = next(c for c in merged if c["event_type"] == "telnet_command_input")
    assert top["occurrences"] == 30 and top["score_breakdown"]["recurrence"] == 6.0
    assert top["score_breakdown"]["duration"] == 4.0
    assert sum(c["occurrences"] for c in merged) == 32
    top3_unmerged = sorted(raw, key=lambda c: -c["score"])[:3]
    assert len({c["event_type"] for c in top3_unmerged}) == 1, "unmerged, the top is one botnet"


# ── through the tool, on a real database ─────────────────────────────────────


@pytest.fixture
async def db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


def _hours_ago(n: int) -> datetime:
    return datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=n)


async def _seed(rows: list[tuple[str, str, str, datetime, int]]) -> None:
    """(ip, event type, severity, hour, alert count)."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for ip, event_type, severity, at, count in rows:
            for i in range(count):
                session.add(
                    Alert(
                        source_ip=ip,
                        event_type=event_type,
                        severity=AlertSeverity(severity),
                        timestamp=at + timedelta(seconds=i % 3000),
                        payload={},
                        honeypot_id=None,
                    )
                )


def _scenario() -> list[tuple[str, str, str, datetime, int]]:
    rows = [
        (f"203.0.113.{n}", "telnet_session_connect", "low", _hours_ago(2), 4) for n in range(1, 31)
    ]
    rows += [
        (f"198.51.100.{n}", "ssh_command_input", "high", _hours_ago(6), 1) for n in range(1, 4)
    ]
    rows += [(f"192.0.2.{n}", "smb_ntlm_auth", "high", _hours_ago(4), 2) for n in range(1, 7)]
    return rows


@pytest.mark.asyncio
async def test_the_tool_puts_behaviour_first_and_rank_by_reorders(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    await _seed(_scenario())

    default = await analyze_campaign()
    by_sources = await analyze_campaign(rank_by="sources")
    recent = await analyze_campaign(rank_by="recent")

    assert default["rank_by"] == "score"
    assert _order(default["campaigns"]) == [
        "smb_ntlm_auth",
        "ssh_command_input",
        "telnet_session_connect",
    ]
    assert _order(by_sources["campaigns"]) == [
        "telnet_session_connect",
        "smb_ntlm_auth",
        "ssh_command_input",
    ]
    assert _order(recent["campaigns"]) == [
        "telnet_session_connect",
        "smb_ntlm_auth",
        "ssh_command_input",
    ]
    top = default["campaigns"][0]
    assert top["kind"] == "behavioural" and top["severity"] == "high"
    assert top["unique_source_ips"] == 6 and top["total_events"] == 12
    for key in ("window", "resolution", "campaigns_total", "count"):
        assert key in default
    assert default["campaigns_total"] == default["count"] == 3
    assert "note" not in default


@pytest.mark.asyncio
async def test_the_severity_comes_from_the_rollups_of_the_campaign_hours(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = [(f"192.0.2.{n}", "http_probe", "low", _hours_ago(3), 2) for n in range(1, 4)]
    rows.append(("192.0.2.1", "http_probe", "critical", _hours_ago(3), 1))
    await _seed(rows)

    out = await analyze_campaign()

    campaign = out["campaigns"][0]
    assert campaign["severity"] == "critical" and campaign["kind"] == "behavioural"
    assert campaign["total_events"] == 7


@pytest.mark.asyncio
async def test_the_note_says_what_the_cut_off_list_is_ordered_by(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    await _seed(_scenario())

    out = await analyze_campaign(limit=1, rank_by="events")

    assert out["campaigns_total"] == 3 and out["count"] == 1 and len(out["campaigns"]) == 1
    assert "top 1 of 3" in out["note"] and "events" in out["note"]


@pytest.mark.asyncio
async def test_the_tool_rejects_an_unknown_rank_by(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    out = await analyze_campaign(rank_by="biggest")  # type: ignore[arg-type]

    assert "error" in out and "rank_by" in out["error"]


@pytest.mark.asyncio
async def test_shared_event_types_come_from_the_rollups(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = []
    for n in range(1, 4):
        rows.append((f"192.0.2.{n}", "ssh_login_failed", "medium", _hours_ago(3), 2))
        rows.append((f"192.0.2.{n}", "ssh_command_input", "high", _hours_ago(3), 2))
    await _seed(rows)

    out = await analyze_campaign()

    by_type = {c["event_type"]: c for c in out["campaigns"]}
    assert by_type["ssh_login_failed"]["shared_event_types"] == ["ssh_command_input"]
    assert by_type["ssh_command_input"]["shared_event_types"] == ["ssh_login_failed"]


@pytest.mark.asyncio
async def test_the_tool_merges_recurring_windows_and_counts_both(db):
    from honeypot_mcp.tools.analysis import analyze_campaign

    rows = [
        (f"203.0.113.{n}", "telnet_command_input", "high", _hours_ago(h), 2)
        for h in range(2, 8)
        for n in range(1, 5)
    ]
    # one more address each hour, so no hour is a subset of another
    rows += [
        (f"198.51.100.{h}", "telnet_command_input", "high", _hours_ago(h), 2) for h in range(2, 8)
    ]
    rows += [(f"192.0.2.{n}", "redis_config_set", "high", _hours_ago(3), 1) for n in range(1, 4)]
    await _seed(rows)

    out = await analyze_campaign()
    raw = await analyze_campaign(merge_recurring=False, limit=100)

    assert out["campaigns_total"] == 2 and out["windows_total"] == 7
    assert out["count"] == 2 and out["merge_recurring"] is True
    telnet = next(c for c in out["campaigns"] if c["event_type"] == "telnet_command_input")
    assert telnet["occurrences"] == 6 and telnet["unique_source_ips"] == 10
    assert telnet["sources_per_window"] == 5
    assert telnet["total_events"] == 6 * 5 * 2
    assert telnet["source_ips_shown"] == 10 and len(telnet["source_ips"]) == 10
    assert raw["campaigns_total"] == 7 == raw["windows_total"]
    assert all(c["occurrences"] == 1 for c in raw["campaigns"])
