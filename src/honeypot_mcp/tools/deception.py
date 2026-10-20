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

from datetime import timedelta
from typing import Any, Literal

from sqlalchemy import select

from honeypot_mcp import instance_lock
from honeypot_mcp.deception.capabilities import BY_TYPE, all_capabilities, all_profiles
from honeypot_mcp.deception.coverage import build_coverage
from honeypot_mcp.deception.planner import build_plan
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import rollups
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    Alert,
    AlertSeverity,
    Honeypot,
    HoneypotStatus,
    Honeytoken,
    HoneytokenStatus,
)
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import digest_payload
from honeypot_mcp.tools._window import annotate_window, window_bounds


@mcp.tool(**hints("deception_profiles"))
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


@mcp.tool(**hints("deception_plan"))
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
    fire — and any `caution` on a sensor (SMTP and DNS: leave them off a public
    cloud VPS, where they look like an open relay and an open resolver). The
    same text is in `warnings`. Then pass the returned plan to `deception_deploy_plan`.

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


@mcp.tool(auth=require_role("operator"), **hints("deception_deploy_plan"))
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
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    deployed: list[str] = []
    deployed_types: dict[str, str] = {}
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
            deployed_types[str(name)] = sensor_type

    rolled_back = False
    aborted = bool(failures and stop_on_error)
    if aborted and deployed:
        for name in deployed:
            await honeypot_stop(name=name, remove=True)
        rolled_back = True
        deployed = []
        deployed_types = {}

    # No tokens after a failed deployment, whether or not anything had been
    # deployed yet: a credential token whose target service has no sensor can
    # never fire, and a retry would create a second set.
    if not aborted:
        for token in tokens or []:
            token_type = token.get("type")
            try:
                created = await honeytoken_create(
                    type=token_type,  # type: ignore[arg-type]
                    label=str(token.get("label")),
                    metadata=token.get("metadata") or {},
                    # The plan already says where this belongs; recording it
                    # now means a trigger months later arrives with its
                    # location attached.
                    planted_at=token.get("plant_location") or None,
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
        outcome="error" if rolled_back or failures else "ok",
        error="; ".join(f["error"] for f in failures) if failures else None,
    )

    cautions = [
        f"{name}: {BY_TYPE[sensor_type].public_cloud_caution}"
        for name, sensor_type in deployed_types.items()
        if BY_TYPE[sensor_type].public_cloud_caution
    ]
    return {
        "deployed_sensors": deployed,
        "created_tokens": created_tokens,
        "failures": failures,
        "rolled_back": rolled_back,
        "status": "ok" if not failures else ("rolled_back" if rolled_back else "partial"),
        **({"cautions": cautions} if cautions else {}),
        "next_step": (
            "Plant each token at its `plant_location`, then call `deception_coverage` "
            "to confirm what this now detects."
            if deployed
            else "Nothing is running. Fix the failures above and retry."
        ),
    }


@mcp.tool(**hints("deception_coverage"))
async def deception_coverage(include_recommendations: bool = True) -> dict[str, Any]:
    """What the live deployment can detect, per ATT&CK tactic, and where it is blind.

    Answers "is our deception any good?" — the question a list of running
    containers cannot. Coverage is computed from each sensor's real event types
    through the same ATT&CK mappings the alerts use, so it reflects what would
    actually be caught rather than what was intended.

    `blind_spots` names the cheapest concrete action that closes each gap,
    ranked by how many new techniques it adds. A recommendation for a sensor the
    project advises against on a public cloud VPS (`dns`, `smtp`: they look like an
    open resolver and an open relay to automated checks, and several providers'
    acceptable-use policies prohibit both) carries a `caution` saying so; check
    where the deployment runs before acting on it.

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


# How many event types `soc_brief` lists in `urgent_by_event_type` (the full count is reported).
_MAX_URGENT_TYPES = 30
# A few event types holding this share of the urgent queue is called out in the headline.
_FLOOD_SHARE = 0.9
_FLOOD_TYPES_MAX = 5


def _type_totals(entry: dict[str, Any] | None) -> dict[str, Any]:
    """Per-example context: how big the event type behind this example is."""
    if entry is None:
        return {}
    return {"event_type_alerts": entry["alerts"], "event_type_sources": entry["sources"]}


def _flood_line(ranked: list[dict[str, Any]]) -> str | None:
    """Say so when a few event types are nearly the whole urgent queue.

    HIGH is the severity of every successful Telnet login and SIP REGISTER, which a public host
    sees by the million, so "7.8M untriaged HIGH alerts" is a fact about floods, not a queue. The
    line names the types that make it up and how much is left once they are set aside."""
    total = sum(t["alerts"] for t in ranked)
    if total <= 0 or len(ranked) <= _FLOOD_TYPES_MAX:
        return None
    biggest = sorted(ranked, key=lambda t: -t["alerts"])
    head: list[dict[str, Any]] = []
    running = 0
    for entry in biggest:
        if len(head) >= _FLOOD_TYPES_MAX or running >= _FLOOD_SHARE * total:
            break
        head.append(entry)
        running += entry["alerts"]
    if running < _FLOOD_SHARE * total:
        return None
    rest = total - running
    names = ", ".join(f"{t['event_type']} ({t['alerts']:,})" for t in head)
    return (
        f"{running / total:.0%} of the CRITICAL/HIGH queue is {len(head)} event type(s): {names}. "
        f"Set them aside and {rest:,} alert(s) across {len(ranked) - len(head)} other event "
        "type(s) remain: see `needs_attention` and `urgent_by_event_type`."
    )


@mcp.tool(**hints("soc_brief"))
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
    cutoff, window_to = await window_bounds(since_hours)

    async with get_session() as session:
        stats = await rollups.stats(session, cutoff, top=5, now=window_to)
        totals = [(AlertSeverity(name), n) for name, n in stats["by_severity"].items()]
        unique_ips = stats["unique_source_ips"]

        # What the urgent queue is made of, by event type. A handful of flood types (successful
        # Telnet logins, SIP REGISTERs) are "high" by design and can be millions of rows, so the
        # newest-first sample the brief used to show was always one of them and the rare,
        # interesting types never appeared. Highlights are now one example per event type, CRITICAL
        # before HIGH, and within a severity the rarest type first.
        urgent_types = await rollups.urgent_by_type(session, cutoff, now=window_to)
        ranked = sorted(
            urgent_types,
            key=lambda t: (0 if t["severity"] == "critical" else 1, t["alerts"], t["event_type"]),
        )
        urgent: list[Alert] = []
        for entry in ranked:
            if len(urgent) >= max_highlights:
                break
            severity = AlertSeverity(entry["severity"])
            hour = entry["newest_hour"]
            # One hour of the alerts table (the newest hour this type was seen in), so a rare type
            # is found without scanning the flood in front of it.
            example = (
                await session.execute(
                    select(Alert)
                    .where(
                        Alert.severity == severity,
                        Alert.event_type == entry["event_type"],
                        Alert.acknowledged.is_(False),
                        Alert.timestamp >= hour,
                        Alert.timestamp < hour + timedelta(hours=1),
                    )
                    .order_by(Alert.timestamp.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if example is not None:
                urgent.append(example)

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

        busiest = [(row["ip"], row["count"]) for row in stats["top_source_ips"]]

        sensors = (
            await session.execute(select(Honeypot.name, Honeypot.type, Honeypot.status))
        ).all()
        # Untriaged = everything in the window minus what a human acknowledged. Acknowledgement is
        # a deliberate act and so is rare, which is what makes this cheap: the acknowledged rows are
        # read from a tiny partial index instead of counting the (flood-sized) unacknowledged rest.
        acked = await rollups.acknowledged_by_severity(session, cutoff)
        untriaged_total = max(stats["total_alerts"] - sum(acked.values()), 0)
        # The true size of the queue `needs_attention` samples from. Counting
        # the returned list instead reports the `max_highlights` cap as if it
        # were the total — "8 untriaged high-severity alerts" when there are
        # 841 — which is the worst possible error in a shift handover.
        urgent_counts: dict[AlertSeverity, int] = {}
        for severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
            open_count = stats["by_severity"].get(severity.value, 0) - acked.get(severity.value, 0)
            if open_count > 0:
                urgent_counts[severity] = open_count

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

    untriaged_critical = urgent_counts.get(AlertSeverity.CRITICAL, 0)
    untriaged_high = urgent_counts.get(AlertSeverity.HIGH, 0)
    urgent_total = untriaged_critical + untriaged_high

    by_key = {(t["severity"], t["event_type"]): t for t in ranked}
    needs_attention = [
        {**item, **_type_totals(by_key.get((item["severity"], item["event_type"])))}
        for item in needs_attention
    ]
    flood_line = _flood_line(ranked)

    headline: list[str] = []
    if unhealthy:
        headline.append(f"{len(unhealthy)} sensor(s) in ERROR — collection may be interrupted.")
    if token_trips:
        headline.append(
            f"{len(token_trips)} honeytoken(s) triggered — the highest-fidelity signal here."
        )
    # CRITICAL is called out on its own line. Folding it into a combined
    # "high-severity" figure is how the one alert that mattered gets read as
    # part of a big number nobody has time to work through.
    if untriaged_critical:
        headline.append(f"{untriaged_critical} untriaged CRITICAL alert(s) — triage these first.")
    if untriaged_high:
        headline.append(f"{untriaged_high} untriaged HIGH alert(s).")
    if flood_line:
        headline.append(flood_line)
    if not headline:
        headline.append(
            f"Nothing needs a decision. {total_events} events from {unique_ips} addresses, "
            "all routine."
        )

    brief: dict[str, Any] = {
        "window_hours": since_hours,
        "headline": headline,
        "volume": {
            "total_events": total_events,
            "unique_source_ips": unique_ips,
            "by_severity": counts,
            "untriaged": untriaged_total,
        },
        "needs_attention": needs_attention,
        # Explicit, so neither a model nor a human can mistake the sample for
        # the queue. `showing` equals `total` when nothing was cut.
        "needs_attention_total": urgent_total,
        "needs_attention_showing": len(needs_attention),
        "untriaged_by_severity": {"critical": untriaged_critical, "high": untriaged_high},
        # The whole urgent queue by event type, rarest first within a severity, so the shape of
        # the queue is visible: a few flood types usually hold nearly all of it. Counts are every
        # CRITICAL/HIGH alert in the window (acknowledged ones included).
        "urgent_by_event_type": [
            {k: t[k] for k in ("severity", "event_type", "alerts", "sources")}
            for t in ranked[:_MAX_URGENT_TYPES]
        ],
        "urgent_event_types_total": len(ranked),
        "triggered_tokens": [
            {
                "id": t.id,
                "type": t.type.value,
                "label": t.label,
                # The operator's free-text plant location, None when none was recorded.
                "planted_at": (t.token_meta or {}).get("planted_at") or None,
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
            }
            for t in token_trips
        ],
        "sensors": {
            "total": len(sensors),
            "running": sum(1 for _n, _t, s in sensors if s is HoneypotStatus.RUNNING),
            "unhealthy": unhealthy,
        },
        "busiest_sources": [{"source_ip": ip, "events": n} for ip, n in busiest],
        "note": (
            f"`needs_attention` is one example per event type from the untriaged CRITICAL/HIGH "
            f"queue (CRITICAL first, rarest type first), showing {len(needs_attention)} of "
            f"{len(ranked)} event types and {urgent_total} alerts"
            + (
                " — raise `max_highlights`, read `urgent_by_event_type`, or use `alerts_search` "
                "to work the rest. "
                if len(ranked) > len(needs_attention)
                else ". "
            )
            + "Use `alerts_get` for the full payload of any item, `analyze_attacker` to "
            "profile a source, and `alerts_acknowledge` to record a disposition once handled."
        ),
    }
    await annotate_window(brief)
    return brief
