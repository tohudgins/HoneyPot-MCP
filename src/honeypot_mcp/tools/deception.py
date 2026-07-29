"""Intent-level tools: plan a deployment, measure coverage, hand over a shift.

The other tool modules are operations — deploy this, list that, export the
other. These three are the questions a SOC actually opens and closes with, and
they are the reason a natural-language interface is worth having rather than a
thinner way to call an API:

* `deception_plan` — "cover an environment that looks like ours." Turns intent
  into a coherent, conflict-checked set of sensors and tokens. Deploying one
  sensor at a time is what everything else in this space asks of you, and it is
  where hand-built deception goes wrong: mismatched hostnames, a directory with
  nothing behind it, credentials planted for a service nobody is watching.
* `deception_coverage` — "what can we actually detect, and where are we blind?"
  Derived from the same ATT&CK mappings the alerts use.
* `soc_brief` — "what happened overnight?" One call that separates what needs a
  human from what is background radiation.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import func, select

from honeypot_mcp.deception.capabilities import BY_TYPE, all_capabilities, all_profiles
from honeypot_mcp.deception.coverage import build_coverage
from honeypot_mcp.deception.planner import build_plan
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    Alert,
    AlertSeverity,
    Honeypot,
    HoneypotStatus,
    Honeytoken,
    HoneytokenStatus,
)
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import digest_payload


@mcp.tool
async def deception_profiles() -> dict[str, Any]:
    """List environment profiles and every deployable sensor type.

    Call this before `deception_plan` to pick a profile that matches how the
    user described their estate. Each profile is a shape of environment (a
    Windows domain, a Linux web app, a container platform) and the sensors that
    make that shape believable together.
    """
    return {
        "profiles": [
            {
                "id": p.id,
                "display_name": p.display_name,
                "description": p.description,
                "os_family": p.os_family,
                "core_sensors": list(p.core),
                "optional_sensors": list(p.optional),
            }
            for p in all_profiles()
        ],
        "sensor_types": [
            {
                "type": c.type,
                "display_name": c.display_name,
                "default_port": c.default_port,
                "real_world_port": c.real_world_port,
                "os_family": c.os_family,
                "roles": list(c.roles),
                "summary": c.summary,
                "requires_docker": c.requires_docker,
                "captures_credentials_as": c.captures_credentials_as,
            }
            for c in all_capabilities()
        ],
        "note": (
            "Pick a profile when the user described an environment; pass an explicit "
            "`services` list when they named specific technologies."
        ),
    }


@mcp.tool
async def deception_plan(
    profile: Literal[
        "corporate_windows",
        "linux_web",
        "cloud_native",
        "data_platform",
        "network_edge",
        "mixed_enterprise",
    ]
    | None = None,
    services: list[str] | None = None,
    identity_prefix: str | None = None,
    domain: str | None = None,
    include_optional: bool = False,
    include_tokens: bool = True,
    use_real_ports: bool = False,
) -> dict[str, Any]:
    """Design a coherent deception deployment for an environment. Deploys nothing.

    Use this when someone describes what they run rather than naming a protocol
    and a port — "we have a customer portal and a Postgres warehouse", "a
    Windows domain with file shares", "everything is containers". Translate that
    description into a `profile` (or an explicit `services` list) and this
    returns a full plan: sensors with non-conflicting ports, hostnames and
    identities that agree with each other, and honeytokens tied to sensors that
    can actually detect them.

    Review the `coherence` block with the user before deploying — it names the
    seams an attacker would notice, and any credential token that could never
    fire. Then pass the returned plan to `deception_deploy_plan`.

    Args:
        profile: Environment shape. Call `deception_profiles` to see the options.
        services: Explicit sensor types, overriding the profile's list. Use when
                  the user named specific technologies.
        identity_prefix: Hostname prefix tying the estate together (e.g. "corp"
                         gives corp-dc1, corp-fs01). Defaults from the profile.
        domain: AD/DNS domain for Windows-style estates (e.g. "corp.local").
                Used for the LDAP base DN and mail domain so they agree.
        include_optional: Include the profile's optional sensors for wider
                          coverage at the cost of a larger footprint.
        include_tokens: Plan honeytokens alongside the sensors.
        use_real_ports: Use real-world ports (22, 445, 3389) instead of the
                        unprivileged defaults. Needs root or a container mapping.
    """
    async with get_session() as session:
        rows = (
            await session.execute(
                select(Honeypot.name, Honeypot.port, Honeypot.status).where(
                    Honeypot.status != HoneypotStatus.STOPPED
                )
            )
        ).all()
    existing_ports = {port: name for name, port, _status in rows}
    existing_names = {name for name, _port, _status in rows}

    plan = build_plan(
        profile_id=profile,
        services=services,
        identity_prefix=identity_prefix,
        domain=domain,
        include_optional=include_optional,
        include_tokens=include_tokens,
        use_real_ports=use_real_ports,
        existing_ports=existing_ports,
        existing_names=existing_names,
    )
    if "error" in plan:
        return plan

    plan["coverage_preview"] = await build_coverage(
        [s["type"] for s in plan["sensors"]],
        [t["type"] for t in plan["tokens"]],
        include_recommendations=False,
    )
    plan["coverage_preview"].pop("tactics", None)
    return plan


@mcp.tool
async def deception_deploy_plan(
    sensors: list[dict[str, Any]],
    tokens: list[dict[str, Any]] | None = None,
    stop_on_error: bool = True,
) -> dict[str, Any]:
    """Deploy a plan from `deception_plan`.

    Pass the `sensors` and `tokens` lists straight through from the plan. Each
    sensor is brought up in turn and each token created after.

    `stop_on_error` defaults to True and rolls back: if a sensor fails to start,
    everything already deployed by this call is stopped and removed, so a failed
    deployment leaves nothing half-built. Set it to False to deploy whatever
    works and report the rest — reasonable when one port is unavailable and the
    remaining sensors are still worth having.

    Args:
        sensors: Sensor entries from the plan (type, name, port, config).
        tokens: Token entries from the plan (type, label, metadata).
        stop_on_error: Roll back everything on the first failure.
    """
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    deployed: list[str] = []
    created_tokens: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []

    for sensor in sensors:
        sensor_type = sensor.get("type")
        name = sensor.get("name")
        if sensor_type not in BY_TYPE:
            failures.append({"sensor": str(name), "error": f"unknown sensor type '{sensor_type}'"})
            if stop_on_error:
                break
            continue
        result = await honeypot_deploy(
            type=sensor_type,  # type: ignore[arg-type]
            name=name,
            port=sensor.get("port"),
            config=sensor.get("config") or {},
        )
        if "error" in result:
            failures.append({"sensor": str(name), "error": result["error"]})
            if stop_on_error:
                break
        else:
            deployed.append(str(name))

    rolled_back = False
    if failures and stop_on_error and deployed:
        for name in deployed:
            await honeypot_stop(name=name, remove=True)
        rolled_back = True
        deployed = []

    if not rolled_back:
        for token in tokens or []:
            token_type = token.get("type")
            try:
                created = await honeytoken_create(
                    type=token_type,  # type: ignore[arg-type]
                    label=str(token.get("label")),
                    metadata=token.get("metadata") or {},
                )
            except Exception as e:  # a bad token must not undo working sensors
                failures.append({"token": str(token.get("label")), "error": str(e)})
                continue
            if "error" in created:
                failures.append({"token": str(token.get("label")), "error": created["error"]})
            else:
                created_tokens.append(
                    {
                        "id": created.get("id"),
                        "type": token_type,
                        "label": token.get("label"),
                        "plant_location": token.get("plant_location", ""),
                        "token_value": created.get("token_value"),
                        "plant_instructions": created.get("plant_instructions"),
                    }
                )

    await record_action(
        "deception_deploy_plan",
        summary=(
            f"deployed {len(deployed)} sensors and {len(created_tokens)} tokens"
            + (" — rolled back after failure" if rolled_back else "")
        ),
        arguments={"sensor_count": len(sensors), "token_count": len(tokens or [])},
        outcome="error" if rolled_back else "success",
        error="; ".join(f["error"] for f in failures) if failures else None,
    )

    return {
        "deployed_sensors": deployed,
        "created_tokens": created_tokens,
        "failures": failures,
        "rolled_back": rolled_back,
        "status": "ok" if not failures else ("rolled_back" if rolled_back else "partial"),
        "next_step": (
            "Plant each token at its `plant_location`, then call `deception_coverage` "
            "to confirm what this now detects."
            if deployed
            else "Nothing is running. Fix the failures above and retry."
        ),
    }


@mcp.tool
async def deception_coverage(include_recommendations: bool = True) -> dict[str, Any]:
    """What the live deployment can detect, per ATT&CK tactic, and where it is blind.

    Answers "is our deception any good?" — the question a list of running
    containers cannot. Coverage is computed from each sensor's real event types
    through the same ATT&CK mappings the alerts use, so it reflects what would
    actually be caught rather than what was intended.

    `blind_spots` names the cheapest concrete action that closes each gap,
    ranked by how many new techniques it adds.

    Args:
        include_recommendations: Include the ranked blind-spot list.
    """
    async with get_session() as session:
        sensor_rows = (
            await session.execute(
                select(Honeypot.type).where(Honeypot.status == HoneypotStatus.RUNNING)
            )
        ).all()
        token_rows = (
            await session.execute(
                select(Honeytoken.type).where(Honeytoken.status != HoneytokenStatus.REVOKED)
            )
        ).all()

    deployed = [row[0].value for row in sensor_rows]
    tokens = [row[0].value for row in token_rows]

    if not deployed and not tokens:
        return {
            "sensors_live": [],
            "tokens_live": [],
            "coverage": "none",
            "note": (
                "Nothing is deployed, so nothing is detectable. Call `deception_plan` "
                "with a profile matching the environment to get a starting deployment."
            ),
            "profiles": [{"id": p.id, "display_name": p.display_name} for p in all_profiles()],
        }

    return await build_coverage(deployed, tokens, include_recommendations=include_recommendations)


@mcp.tool
async def soc_brief(since_hours: float = 12.0, max_highlights: int = 8) -> dict[str, Any]:
    """Shift handover: what happened, what needs a human, what was noise.

    The everyday entry point — use it for "what happened overnight?", "anything
    I should look at?", "brief me". It separates events that need a decision
    (untriaged CRITICAL/HIGH, honeytoken trips, sensor failures) from the
    background radiation that makes up most honeypot traffic, so volume never
    buries the one thing that matters.

    Args:
        since_hours: Window to summarise. 12 covers a shift, 24 a day.
        max_highlights: Cap on individual items returned in `needs_attention`.
    """
    cutoff = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=since_hours)

    async with get_session() as session:
        totals = (
            await session.execute(
                select(Alert.severity, func.count(Alert.id))
                .where(Alert.timestamp >= cutoff)
                .group_by(Alert.severity)
            )
        ).all()
        unique_ips = (
            await session.execute(
                select(func.count(func.distinct(Alert.source_ip))).where(Alert.timestamp >= cutoff)
            )
        ).scalar() or 0

        urgent = (
            (
                await session.execute(
                    select(Alert)
                    .where(
                        Alert.timestamp >= cutoff,
                        Alert.severity.in_([AlertSeverity.CRITICAL, AlertSeverity.HIGH]),
                        Alert.acknowledged.is_(False),
                    )
                    .order_by(Alert.severity.desc(), Alert.timestamp.desc())
                    .limit(max_highlights)
                )
            )
            .scalars()
            .all()
        )

        token_trips = (
            (
                await session.execute(
                    select(Honeytoken)
                    .where(Honeytoken.status == HoneytokenStatus.TRIGGERED)
                    .order_by(Honeytoken.id.desc())
                    .limit(10)
                )
            )
            .scalars()
            .all()
        )

        busiest = (
            await session.execute(
                select(Alert.source_ip, func.count(Alert.id).label("n"))
                .where(Alert.timestamp >= cutoff)
                .group_by(Alert.source_ip)
                .order_by(func.count(Alert.id).desc())
                .limit(5)
            )
        ).all()

        sensors = (
            await session.execute(select(Honeypot.name, Honeypot.type, Honeypot.status))
        ).all()
        untriaged_total = (
            await session.execute(
                select(func.count(Alert.id)).where(
                    Alert.timestamp >= cutoff, Alert.acknowledged.is_(False)
                )
            )
        ).scalar() or 0

    counts = {severity.value: n for severity, n in totals}
    total_events = sum(counts.values())
    unhealthy = [
        {"name": name, "type": hp_type.value, "status": status.value}
        for name, hp_type, status in sensors
        if status is HoneypotStatus.ERROR
    ]

    needs_attention = [
        {
            "alert_id": alert.id,
            "severity": alert.severity.value,
            "event_type": alert.event_type,
            "source_ip": alert.source_ip,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "payload": digest_payload(alert.payload or {}),
        }
        for alert in urgent
    ]

    headline: list[str] = []
    if unhealthy:
        headline.append(f"{len(unhealthy)} sensor(s) in ERROR — collection may be interrupted.")
    if token_trips:
        headline.append(
            f"{len(token_trips)} honeytoken(s) triggered — the highest-fidelity signal here."
        )
    if needs_attention:
        headline.append(f"{len(needs_attention)} untriaged high-severity alert(s).")
    if not headline:
        headline.append(
            f"Nothing needs a decision. {total_events} events from {unique_ips} addresses, "
            "all routine."
        )

    return {
        "window_hours": since_hours,
        "headline": headline,
        "volume": {
            "total_events": total_events,
            "unique_source_ips": unique_ips,
            "by_severity": counts,
            "untriaged": untriaged_total,
        },
        "needs_attention": needs_attention,
        "triggered_tokens": [
            {"id": t.id, "type": t.type.value, "label": t.label} for t in token_trips
        ],
        "sensors": {
            "total": len(sensors),
            "running": sum(1 for _n, _t, s in sensors if s is HoneypotStatus.RUNNING),
            "unhealthy": unhealthy,
        },
        "busiest_sources": [{"source_ip": ip, "events": n} for ip, n in busiest],
        "note": (
            "`needs_attention` is untriaged CRITICAL/HIGH only. Use `alerts_get` for the "
            "full payload of any item, `analyze_attacker` to profile a source, and "
            "`alerts_acknowledge` to record a disposition once handled."
        ),
    }
