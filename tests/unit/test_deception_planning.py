"""Intent-level planning, coverage and the shift brief.

These three tools are the reason a natural-language interface beats a thinner
wrapper over an API, so the tests concentrate on the judgement they encode
rather than on their plumbing.

The coherence checks matter most. Deception fails on mismatched detail far more
often than on missing detail — an attacker who touches two decoys and finds
they disagree has learned more than one who finds nothing. Every check pinned
here corresponds to a seam somebody would actually notice, or to a token that
could never fire.
"""

from __future__ import annotations

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


# ── The capability registry is the single source of truth ───────────────────


async def test_every_deployable_type_has_a_capability_entry():
    """A type you can deploy but cannot plan for is invisible to the planner.

    `honeypot_templates` previously carried its own hand-maintained copy of this
    list and silently described fourteen types after five more had shipped.
    """
    from honeypot_mcp.deception.capabilities import BY_TYPE
    from honeypot_mcp.storage.models import HoneypotType

    deployable = {t.value for t in HoneypotType}
    assert deployable == set(BY_TYPE), (
        f"registry out of sync — missing {sorted(deployable - set(BY_TYPE))}, "
        f"extra {sorted(set(BY_TYPE) - deployable)}"
    )


async def test_honeypot_templates_reads_from_the_registry():
    from honeypot_mcp.deception.capabilities import BY_TYPE
    from honeypot_mcp.tools.honeypot import honeypot_templates

    templates = await honeypot_templates()
    assert {t["type"] for t in templates} == set(BY_TYPE)


async def test_profiles_only_reference_real_sensor_types():
    from honeypot_mcp.deception.capabilities import BY_TYPE, all_profiles

    for profile in all_profiles():
        for sensor in profile.core + profile.optional:
            assert sensor in BY_TYPE, f"profile {profile.id} references unknown sensor {sensor}"


async def test_credential_service_labels_match_what_the_matcher_understands():
    """A capability claiming a service the matcher cannot infer is a dead token."""
    from honeypot_mcp.credential_match import _SERVICE_PREFIXES
    from honeypot_mcp.deception.capabilities import credential_services

    known = set(_SERVICE_PREFIXES.values())
    for engine_type, service in credential_services().items():
        assert service in known, (
            f"{engine_type} claims credentials as '{service}', which credential_match "
            f"cannot infer — a token planted for it would never cross-reference"
        )


# ── Planning ────────────────────────────────────────────────────────────────


async def test_a_windows_plan_is_internally_consistent():
    """The LDAP base DN, hostnames and domain have to agree with each other."""
    from honeypot_mcp.deception.planner import build_plan

    plan = build_plan(profile_id="corporate_windows", identity_prefix="corp", domain="corp.local")

    assert plan["identity"]["domain"] == "corp.local"
    by_type = {s["type"]: s for s in plan["sensors"]}
    assert by_type["ldap"]["config"]["base_dn"] == "dc=corp,dc=local"
    for sensor in plan["sensors"]:
        assert sensor["hostname"].startswith("corp-"), sensor
    assert plan["coherence"]["consistent"]


async def test_plan_avoids_ports_and_names_already_in_use():
    from honeypot_mcp.deception.planner import build_plan

    plan = build_plan(
        profile_id="linux_web",
        identity_prefix="web",
        existing_ports={8080: "demo-http", 2222: "demo-ssh"},
        existing_names={"web-http"},
    )
    ports = [s["port"] for s in plan["sensors"]]
    assert 8080 not in ports and 2222 not in ports
    assert len(ports) == len(set(ports)), "planner assigned the same port twice"
    assert "web-http" not in [s["name"] for s in plan["sensors"]]
    assert len(plan["port_conflicts_resolved"]) == 2


async def test_plan_deploys_nothing():
    """A question must not bring up network listeners as a side effect."""
    from sqlalchemy import select

    from honeypot_mcp.deception.planner import build_plan
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot

    build_plan(profile_id="mixed_enterprise")
    async with get_session() as session:
        assert (await session.execute(select(Honeypot))).scalars().all() == []


async def test_unknown_profile_returns_the_valid_options():
    from honeypot_mcp.deception.planner import build_plan

    result = build_plan(profile_id="not-a-profile")
    assert "error" in result
    assert result["valid_profiles"], "an error must say what would have worked"


async def test_unknown_service_is_reported_not_silently_dropped():
    from honeypot_mcp.deception.planner import build_plan

    plan = build_plan(services=["http", "banana"])
    assert [s["type"] for s in plan["sensors"]] == ["http"]
    assert any("banana" in w for w in plan["warnings"])


# ── Coherence: the part that makes deception convincing ─────────────────────


async def test_a_directory_with_nothing_behind_it_is_flagged():
    from honeypot_mcp.deception.planner import build_plan

    issues = build_plan(services=["ldap"], identity_prefix="acme")["coherence"]["issues"]
    assert any("directory" in i["issue"].lower() for i in issues)


async def test_a_credential_token_for_an_undeployed_service_is_an_error():
    """The failure that silently loses data: a token nothing can detect."""
    from honeypot_mcp.deception.planner import PlannedSensor, PlannedToken, check_coherence

    result = check_coherence(
        [PlannedSensor(type="http", name="x-http", port=8080)],
        [PlannedToken(type="credential", label="db-svc", metadata={"service": "postgresql"})],
    )
    assert result["consistent"] is False
    error = next(i for i in result["issues"] if i["severity"] == "error")
    assert "can never fire" in error["issue"]
    assert "postgresql" in error["fix"]


async def test_planned_tokens_always_target_a_deployed_service():
    """The planner must never generate the error above for its own output."""
    from honeypot_mcp.deception.capabilities import all_profiles
    from honeypot_mcp.deception.planner import build_plan

    for profile in all_profiles():
        plan = build_plan(profile_id=profile.id, include_optional=True)
        errors = [i for i in plan["coherence"]["issues"] if i["severity"] == "error"]
        assert not errors, f"profile {profile.id} plans an undetectable token: {errors}"


async def test_mixed_os_estate_is_informational_not_an_error():
    """A varied estate is realistic; only undetectable tokens are errors."""
    from honeypot_mcp.deception.planner import build_plan

    plan = build_plan(profile_id="mixed_enterprise")
    assert plan["coherence"]["consistent"] is True


# ── Coverage ────────────────────────────────────────────────────────────────


async def test_coverage_is_derived_from_real_attack_mappings():
    from honeypot_mcp.deception.coverage import build_coverage

    result = await build_coverage(["ssh", "smb", "docker_api"], ["credential"])
    covered = {t["id"] for tactic in result["tactics"] for t in tactic["techniques"]}
    # Each of these comes from a different engine's real event types.
    assert "T1110.001" in covered, "ssh brute force"
    assert "T1210" in covered, "smb exploitation"
    assert "T1611" in covered, "docker escape"
    assert "T1078" in covered, "the planted credential"


async def test_two_independent_sources_reads_as_strong():
    from honeypot_mcp.deception.coverage import build_coverage

    one = await build_coverage(["ssh"], [], include_recommendations=False)
    many = await build_coverage(["ssh", "rdp", "ldap"], [], include_recommendations=False)

    def level(result, tactic):
        return next(t["level"] for t in result["tactics"] if t["tactic"] == tactic)

    assert level(one, "Credential Access") == "partial"
    assert level(many, "Credential Access") == "strong"


async def test_blind_spots_name_a_concrete_next_step():
    """ "No coverage" is a fact; a command is a next step."""
    from honeypot_mcp.deception.coverage import build_coverage

    result = await build_coverage(["http"], [])
    assert result["blind_spots"]
    for recommendation in result["blind_spots"]:
        assert recommendation["command"], "a recommendation without a command is not actionable"
        assert recommendation["new_technique_count"] >= 1

    # Sensor recommendations are ranked by how much they add. The credential
    # token is pinned above them on fidelity rather than breadth, and says so.
    sensors = [b for b in result["blind_spots"] if not b.get("pinned")]
    counts = [b["new_technique_count"] for b in sensors]
    assert counts == sorted(counts, reverse=True), "sensor recommendations must be ranked"
    pinned = [b for b in result["blind_spots"] if b.get("pinned")]
    assert pinned and result["blind_spots"][0] is pinned[0]


async def test_docker_api_is_recommended_when_container_coverage_is_missing():
    from honeypot_mcp.deception.coverage import build_coverage

    result = await build_coverage(["ssh", "http", "smb"], [])
    actions = " ".join(b["action"] for b in result["blind_spots"])
    assert "docker_api" in actions


async def test_coverage_of_an_empty_deployment_points_at_the_planner():
    from honeypot_mcp.tools.deception import deception_coverage

    result = await deception_coverage()
    assert result["coverage"] == "none"
    assert "deception_plan" in result["note"]


# ── SOC brief ───────────────────────────────────────────────────────────────


async def _alert(event_type: str, severity, source_ip: str = "192.0.2.10"):
    """Submit an alert from a TEST-NET address, deliberately.

    A CRITICAL event from a *globally routable* IP schedules a fire-and-forget
    `_enrich_alert_async` task. That task outlives the test, re-opens a session
    after the fixture has closed the database, and poisons whichever module
    happens to run next — which is how this file broke `test_vnc.py` on one
    Python version and nothing else. `_is_enrichable_ip` filters TEST-NET, so
    no background task is created and the test owns its own lifetime.
    """
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event

    await submit_event(
        PendingEvent(
            honeypot_id=None,
            source_ip=source_ip,
            source_port=4444,
            event_type=event_type,
            payload={"note": "x"},
            severity=severity,
        )
    )


async def test_quiet_shift_says_so_plainly():
    from honeypot_mcp.tools.deception import soc_brief

    brief = await soc_brief(since_hours=12)
    assert brief["needs_attention"] == []
    assert "Nothing needs a decision" in brief["headline"][0]


async def test_brief_separates_what_needs_a_human_from_noise():
    """Volume must never bury the one thing that matters."""
    import asyncio

    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.tools.deception import soc_brief

    for i in range(25):
        await _alert("ssh_login_failed", AlertSeverity.LOW, f"10.0.0.{i}")
    await _alert("docker_api_container_escape", AlertSeverity.CRITICAL)
    await asyncio.sleep(1.0)

    brief = await soc_brief(since_hours=12)
    assert brief["volume"]["total_events"] == 26
    assert len(brief["needs_attention"]) == 1
    assert brief["needs_attention"][0]["event_type"] == "docker_api_container_escape"


async def test_brief_surfaces_triggered_tokens_and_unhealthy_sensors():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Honeypot,
        HoneypotStatus,
        HoneypotType,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )
    from honeypot_mcp.tools.deception import soc_brief

    async with get_session() as session:
        session.add(
            Honeypot(
                name="dead-one",
                type=HoneypotType.HTTP,
                port=18080,
                status=HoneypotStatus.ERROR,
                config={},
            )
        )
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="prod-db-svc",
                token_value="tok-abc",
                status=HoneytokenStatus.TRIGGERED,
                token_meta={},
            )
        )

    brief = await soc_brief(since_hours=12)
    assert [t["label"] for t in brief["triggered_tokens"]] == ["prod-db-svc"]
    assert [s["name"] for s in brief["sensors"]["unhealthy"]] == ["dead-one"]
    joined = " ".join(brief["headline"])
    assert "honeytoken" in joined and "ERROR" in joined


async def test_brief_digests_payloads_rather_than_returning_them_whole():
    """An MCP result lands in a context window; captures can be 64 KB each."""
    import asyncio

    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import AlertSeverity
    from honeypot_mcp.tools.deception import soc_brief

    await submit_event(
        PendingEvent(
            honeypot_id=None,
            source_ip="192.0.2.10",
            event_type="http_exploit_attempt",
            payload={"raw_body_b64": "A" * 50_000, "path": "/admin"},
            severity=AlertSeverity.CRITICAL,
        )
    )
    await asyncio.sleep(1.0)

    brief = await soc_brief(since_hours=12)
    payload = brief["needs_attention"][0]["payload"]
    assert "raw_body_b64" not in payload
    assert payload.get("path") == "/admin"


async def test_brief_headline_reports_real_totals_not_the_display_cap():
    """The worst possible error in a shift handover.

    `needs_attention` is capped at `max_highlights`, and the headline counted
    that list — so a queue of 841 untriaged CRITICAL/HIGH alerts was announced
    as "8 untriaged high-severity alert(s)". An analyst reads that as a quiet
    night and moves on.
    """
    from datetime import UTC, datetime, timedelta

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity
    from honeypot_mcp.tools.deception import soc_brief

    recent = datetime.now(UTC) - timedelta(minutes=5)
    async with get_session() as session:
        for i in range(30):
            session.add(
                Alert(
                    source_ip=f"203.0.113.{i}",
                    event_type="ssh_login_failed",
                    payload={},
                    severity=AlertSeverity.HIGH,
                    acknowledged=False,
                    timestamp=recent,
                )
            )
        for i in range(3):
            session.add(
                Alert(
                    source_ip=f"198.51.100.{i}",
                    event_type="honeytoken_triggered_credential_via_ssh",
                    payload={},
                    severity=AlertSeverity.CRITICAL,
                    acknowledged=False,
                    timestamp=recent,
                )
            )

    brief = await soc_brief(since_hours=12, max_highlights=5)

    assert brief["needs_attention_showing"] == 5
    assert brief["needs_attention_total"] == 33
    assert brief["untriaged_by_severity"] == {"critical": 3, "high": 30}

    joined = " ".join(brief["headline"])
    assert "3 untriaged CRITICAL" in joined, "CRITICAL must be called out on its own"
    assert "30 untriaged HIGH" in joined, "the headline must state the real total"
    assert "5 untriaged" not in joined, "the display cap must never be reported as the total"
    assert "showing 5 of 33" in brief["note"]


async def test_brief_note_does_not_claim_truncation_when_nothing_was_cut():
    """A permanent "there may be more" hedge trains people to ignore it."""
    from datetime import UTC, datetime, timedelta

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity
    from honeypot_mcp.tools.deception import soc_brief

    async with get_session() as session:
        session.add(
            Alert(
                source_ip="203.0.113.1",
                event_type="ssh_login_failed",
                payload={},
                severity=AlertSeverity.HIGH,
                acknowledged=False,
                timestamp=datetime.now(UTC) - timedelta(minutes=1),
            )
        )

    brief = await soc_brief(since_hours=12, max_highlights=8)
    assert brief["needs_attention_total"] == brief["needs_attention_showing"] == 1
    assert "raise `max_highlights`" not in brief["note"]
