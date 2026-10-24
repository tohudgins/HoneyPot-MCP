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
from typing import Any

from sqlalchemy import select

from honeypot_mcp import instance_lock
from honeypot_mcp.deception.capabilities import (
    BY_TYPE,
    all_capabilities,
    all_profiles,
    resolve_profile,
    resolve_type,
    suggest_types,
)
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
from honeypot_mcp.tools._sources import (
    make_matcher,
    parse_source_filters,
    source_scope,
)
from honeypot_mcp.tools._window import annotate_window, window_bounds


def _one_line(text: str, limit: int = 110) -> str:
    sentence = text.strip().split(". ")[0].rstrip(".")
    if len(sentence) <= limit:
        return sentence
    return sentence[: limit - 1].rsplit(" ", 1)[0] + "…"


@mcp.tool(**hints("deception_profiles"))
async def deception_profiles(profile: str | None = None, type: str | None = None) -> dict[str, Any]:
    """What can be deployed: environment profiles, sensor types, and what each one catches?

    Use it for "what can you protect?", "what honeypots can I run?", "what does the redis
    honeypot capture?". No argument: every profile and every sensor type, one line each. With a
    profile: its sensors. With a type: everything about it, including its `config` settings.
    `deception_plan` turns a profile into a deployment; `honeypot_deploy` runs one sensor.

    Args:
        profile: One profile (an id, or words like "windows", "containers", "databases").
        type: One sensor type (ssh, postgres, k8s, ...) for its full details and settings.
    """
    if type:
        # Deferred: tools.honeypot imports server, which imports this module (a load-time cycle).
        from honeypot_mcp.tools.honeypot import _CHECKS, _CONFIG_KEYS, _type_error

        kind = resolve_type(type)
        if kind is None:
            return _type_error(type)
        c = BY_TYPE[kind]
        return {
            "type": c.type,
            "name": c.display_name,
            "what_it_captures": c.summary,
            "default_port": c.default_port,
            "real_world_port": c.real_world_port,
            "transport": c.transport,
            "os_family": c.os_family,
            "roles": list(c.roles),
            "needs_docker": c.requires_docker,
            "credentials_recorded_as": c.captures_credentials_as,
            "detects": list(c.signature_events),
            "settings": {k: _CHECKS[k][1] for k in sorted(_CONFIG_KEYS.get(c.type, ()))},
            "pairs_well_with": list(c.pairs_well_with),
            **({"caution": c.public_cloud_caution} if c.public_cloud_caution else {}),
            "note": f"Deploy it with honeypot_deploy(type='{c.type}'). Settings go in `config`.",
        }
    if profile:
        chosen, near = resolve_profile(profile)
        if chosen is None:
            return {
                "error": f"No profile matches '{profile}'.",
                "hint": (f"Closest: {', '.join(near)}. " if near else "")
                + "Valid profiles: "
                + ", ".join(p.id for p in all_profiles())
                + ". Call without a profile for what each is for.",
            }
        return {
            "id": chosen.id,
            "name": chosen.display_name,
            "description": chosen.description,
            "os_family": chosen.os_family,
            "core_sensors": [
                {"type": t, "port": BY_TYPE[t].default_port, "what": _one_line(BY_TYPE[t].summary)}
                for t in chosen.core
            ],
            "optional_sensors": [
                {"type": t, "port": BY_TYPE[t].default_port, "what": _one_line(BY_TYPE[t].summary)}
                for t in chosen.optional
            ],
            "note": f"Plan it with deception_plan(profile='{chosen.id}'); include_optional adds "
            "the optional sensors.",
        }
    return {
        "count": len(all_profiles()),
        "profiles": [
            {
                "id": p.id,
                "for": _one_line(p.description),
                "core_sensors": list(p.core),
                "optional_sensors": list(p.optional),
            }
            for p in all_profiles()
        ],
        "sensor_types": [
            {
                "type": c.type,
                "port": c.default_port,
                "what": _one_line(c.summary),
                **({"needs_docker": True} if c.requires_docker else {}),
            }
            for c in all_capabilities()
        ],
        "note": "Pick the profile closest to what the user runs, or name sensor types with "
        "`services` in deception_plan. `port` is the default; a free one is chosen if taken. "
        "Ask with `type` for one sensor's detail and settings.",
    }


@mcp.tool(**hints("deception_plan"))
async def deception_plan(
    profile: str | None = None,
    services: list[str] | None = None,
    identity_prefix: str | None = None,
    domain: str | None = None,
    include_optional: bool = False,
    include_tokens: bool = True,
    use_real_ports: bool = False,
) -> dict[str, Any]:
    """Design a believable set of decoys and bait for an environment. Deploys nothing.

    Use it for "protect a Windows domain with a Postgres warehouse", "we run containers", "cover
    our web app". With no arguments a broad mixed estate is planned. The plan has sensors with free
    ports and matching identities, plus honeytokens tied to sensors that can catch them. Read
    `coherence` and `warnings` (seams an attacker would notice; SMTP and DNS look like an open
    relay or resolver on a cloud VPS) with the user, then pass `sensors` and `tokens` to
    `deception_deploy_plan`.

    Args:
        profile: The kind of environment, as an id or the user's words: corporate_windows,
            linux_web, cloud_native, data_platform, network_edge, mixed_enterprise ("windows",
            "containers" work). `deception_profiles` explains each.
        services: Sensor types to include or add to the profile ("postgres", "ssh", "redis").
        identity_prefix: Hostname prefix, if the user names one ("acme" gives acme-dc1).
        domain: Windows/AD domain, if named ("corp.local").
        include_optional: True when the user wants wider coverage or "everything".
        include_tokens: False if the user wants no honeytokens.
        use_real_ports: True for standard ports (22, 445, 3389); needs root or a port mapping.
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
    """Bring up the decoys and bait from a `deception_plan`.

    Use it after the user approves a plan ("deploy that"). Pass the plan's `sensors` and `tokens`
    lists straight through. Each sensor is started and each token created. By default a failure
    rolls everything back so nothing is left half-built; set `stop_on_error` false only if the
    user wants whatever can start to start.

    Args:
        sensors: The plan's `sensors` list (each has type, name, port, config).
        tokens: The plan's `tokens` list (type, label, metadata); omit for no tokens.
        stop_on_error: False to keep what deployed and report the rest.
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    if not sensors or not all(isinstance(s, dict) for s in sensors):
        return {
            "error": "`sensors` must be the plan's list of sensor objects.",
            "hint": "Call `deception_plan` first and pass its `sensors` (and `tokens`) unchanged.",
        }
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    deployed: list[str] = []
    deployed_types: dict[str, str] = {}
    deployed_ports: dict[str, int] = {}
    created_tokens: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []

    for sensor in sensors:
        name = sensor.get("name")
        sensor_type = resolve_type(sensor.get("type"))
        if sensor_type is None:
            near = suggest_types(sensor.get("type")) if sensor.get("type") else []
            failures.append(
                {
                    "sensor": str(name),
                    "error": f"unknown sensor type '{sensor.get('type')}'",
                    "hint": (f"Did you mean {', '.join(near)}? " if near else "")
                    + f"Valid types: {', '.join(BY_TYPE)}.",
                }
            )
            if stop_on_error:
                break
            continue
        result = await honeypot_deploy(
            type=sensor_type,
            name=name,
            port=sensor.get("port"),
            config=sensor.get("config") or {},
        )
        if "error" in result:
            failures.append(
                {
                    "sensor": str(name),
                    "error": result["error"],
                    **({"hint": result["hint"]} if "hint" in result else {}),
                }
            )
            if stop_on_error:
                break
        else:
            deployed.append(result["name"])
            deployed_types[result["name"]] = sensor_type
            deployed_ports[result["name"]] = result["port"]

    rolled_back = False
    aborted = bool(failures and stop_on_error)
    if aborted and deployed:
        for name in deployed:
            await honeypot_stop(name=name, remove=True)
        rolled_back = True
        deployed = []
        deployed_types = {}
        deployed_ports = {}

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
                failures.append(
                    {
                        "token": str(token.get("label")),
                        "error": created["error"],
                        **({"hint": created["hint"]} if "hint" in created else {}),
                    }
                )
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
        "ports": deployed_ports,
        "created_tokens": created_tokens,
        "failures": failures,
        "rolled_back": rolled_back,
        "status": "ok" if not failures else ("rolled_back" if rolled_back else "partial"),
        **({"cautions": cautions} if cautions else {}),
        "next_step": (
            "Plant each token at its `plant_location`, run `honeypot_self_test` on the sensors, "
            "then `deception_coverage` to confirm what this now detects."
            if deployed
            else "Nothing is running. Fix the failures above (each has a hint) and retry."
        ),
    }


@mcp.tool(**hints("deception_coverage"))
async def deception_coverage() -> dict[str, Any]:
    """What can the running decoys detect, per MITRE ATT&CK tactic, and where are they blind?

    Use it for "is our deception any good?", "what are we missing?". It maps each running
    sensor's real event types and each live honeytoken to ATT&CK, and `blind_spots` names the
    cheapest sensor or token that would close each gap. A sensor advised against on a public cloud
    VPS (dns, smtp) carries a `caution`.
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

    return await build_coverage(deployed, tokens, include_recommendations=True)


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


def _flood_line(group: list[dict[str, Any]], label: str) -> str | None:
    """Say so when a few event types are nearly the whole of one severity's queue.

    HIGH is the severity of every successful Telnet login and SIP REGISTER, which a public host
    sees by the million, so "7.8M untriaged HIGH alerts" is a fact about floods, not a queue; the
    CRITICAL queue can be just as lopsided. Share-based, with no event type named in advance: the
    line names whichever types make up the bulk and how much is left once they are set aside."""
    total = sum(t["alerts"] for t in group)
    if total <= 0 or len(group) <= _FLOOD_TYPES_MAX:
        return None
    biggest = sorted(group, key=lambda t: -t["alerts"])
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
        f"{running / total:.0%} of the {label} queue is {len(head)} event type(s): {names}. "
        f"Set them aside and {rest:,} alert(s) across {len(group) - len(head)} other event "
        "type(s) remain: see `urgent_by_event_type`."
    )


def _flood_lines(ranked: list[dict[str, Any]]) -> list[str]:
    """One flood line per severity that needs one, CRITICAL first."""
    lines = []
    for severity in ("critical", "high"):
        group = [t for t in ranked if t["severity"] == severity]
        line = _flood_line(group, severity.upper())
        if line:
            lines.append(line)
    return lines


@mcp.tool(**hints("soc_brief"))
async def soc_brief(
    since_hours: float = 12.0,
    max_highlights: int = 8,
    exclude_sources: list[str] | None = None,
) -> dict[str, Any]:
    """Shift handover: what happened, what needs a human, what was noise.

    The everyday entry point: use it for "what happened overnight?", "anything I should look
    at?", "brief me". It separates events that need a decision (untriaged CRITICAL/HIGH, honeytoken
    trips, sensor failures) from the background radiation that makes up most honeypot traffic.
    With no arguments it summarises the last 12 hours.

    Args:
        since_hours: The window: "overnight" 12, "today" 24, "this week" 168, "the whole run" a
            large number.
        max_highlights: Items to show in `needs_attention` (default 8); raise it for more detail.
        exclude_sources: IP addresses or CIDR ranges to leave out of the urgent queue, only when the
            user says some traffic is theirs ("ignore my scanner at 203.0.113.7"). The result
            states what was excluded and how many alerts that hid.
    """
    requested, bad = parse_source_filters(exclude_sources)
    if bad:
        return {
            "error": "; ".join(bad),
            "hint": "exclude_sources takes IP addresses and CIDR ranges, for example 203.0.113.7 "
            "or 198.51.100.0/24.",
        }
    exclude = make_matcher(requested) if requested else None
    cutoff, window_to = await window_bounds(since_hours)

    async with get_session() as session:
        stats = await rollups.stats(session, cutoff, top=5, now=window_to)
        totals = [(AlertSeverity(name), n) for name, n in stats["by_severity"].items()]
        unique_ips = stats["unique_source_ips"]

        # What the urgent queue is made of, by event type. A handful of flood types are "high" by
        # design and can be millions of rows, so a newest-first sample is always one of them and
        # the rare, interesting types never appear. Highlights are one example per event type,
        # CRITICAL before HIGH, and within a severity the rarest type first.
        excluded_result = None
        if exclude is not None:
            excluded_result = await rollups.urgent_by_type_excluding(
                session, exclude, cutoff, now=window_to
            )
            urgent_types = excluded_result["types"]
        else:
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
            # With sources set aside, only the kept ones may supply the example.
            kept = entry.get("example_sources")
            source_clause = [Alert.source_ip.in_(kept)] if kept else []
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
                        *source_clause,
                    )
                    .order_by(Alert.timestamp.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if example is None:
                # The newest hour held only acknowledged rows (a partly triaged type): take the
                # newest open alert of the type. Rare, and bounded by the type's own rows.
                example = (
                    await session.execute(
                        select(Alert)
                        .where(
                            Alert.severity == severity,
                            Alert.event_type == entry["event_type"],
                            Alert.acknowledged.is_(False),
                            Alert.timestamp >= cutoff,
                            *source_clause,
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
        if excluded_result is not None:
            # Counted from the kept sources, at hour resolution, like the per-type list.
            for sev, n in excluded_result["open_by_severity"].items():
                if n > 0:
                    urgent_counts[AlertSeverity(sev)] = n
        else:
            for severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
                open_count = stats["by_severity"].get(severity.value, 0) - acked.get(
                    severity.value, 0
                )
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
            "source_scope": source_scope(alert.source_ip),
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
    flood_lines = _flood_lines(ranked)
    scopes: list[str] = [str(item["source_scope"]) for item in needs_attention]
    non_public = sorted({s for s in scopes if s != "public"})
    non_public_count = sum(1 for s in scopes if s != "public")
    non_public_note = (
        f"{non_public_count} example(s) come from non-public addresses ({', '.join(non_public)}): "
        "on an internet-facing host that is usually the user's own testing or monitoring, on an "
        "internal network it can be the whole signal. Ask whether they are the user's own; if so, "
        "call again with `exclude_sources` set to those addresses. "
        if non_public_count
        else ""
    )
    excluded_info = None
    if excluded_result is not None:
        excluded_info = {
            "requested": [str(n) for n in requested],
            "alerts_excluded": excluded_result["excluded_open_alerts"],
            "sources_excluded": excluded_result["excluded_sources"],
            "applies_to": (
                "the urgent queue: headline counts, needs_attention, urgent_by_event_type "
                "(hour resolution); volume and busiest_sources are unfiltered"
            ),
        }

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
    for line in flood_lines:
        headline.append(line)
    if excluded_info is not None:
        headline.append(
            f"{excluded_info['alerts_excluded']:,} open CRITICAL/HIGH alert(s) from "
            f"{excluded_info['sources_excluded']:,} excluded source(s) are left out of the queue "
            "above (see `excluded`)."
        )
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
        # The open (unacknowledged) urgent queue by event type, rarest first within a severity, so
        # the shape of the queue is visible: a few flood types usually hold nearly all of it. Types
        # whose every alert was acknowledged are not listed; `acknowledged` says how many alerts of
        # a listed type were already triaged.
        "urgent_by_event_type": [
            {k: t[k] for k in ("severity", "event_type", "alerts", "acknowledged", "sources")}
            for t in ranked[:_MAX_URGENT_TYPES]
        ],
        "urgent_event_types_total": len(ranked),
        "excluded": excluded_info,
        "non_public_examples": non_public_count,
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
            + non_public_note
            + "Use `alerts_get` for the full payload of any item, `analyze_attacker` to "
            "profile a source, and `alerts_acknowledge` to record a disposition once handled."
        ),
    }
    await annotate_window(brief)
    return brief
