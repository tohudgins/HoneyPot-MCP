"""What the current deployment can actually detect, and what it cannot.

Every other analysis path in this codebase is attacker-centric and looks
backwards: who hit us, what did they do, how do we rate them. That leaves the
question a SOC lead actually opens with unanswered — *is our deception any
good?* — and there is no way to answer it from a list of running containers.

Coverage is computed by pushing each sensor's real event types through
`intel.mitre`, so it is derived from the same mappings the alerts use rather
than a second table that would drift the first time an engine changed. If a new
engine's events are unmapped it shows up here as missing coverage, which is the
correct signal: an unmapped capture is invisible on the ATT&CK dashboard too.

The gap list is deliberately actionable. "No Privilege Escalation coverage" is
a fact; "deploy `docker_api` to cover T1611 Escape to Host" is a next step, and
the difference is whether the report changes anything.
"""

from __future__ import annotations

from typing import Any

from honeypot_mcp.deception.capabilities import BY_TYPE, all_capabilities
from honeypot_mcp.intel.mitre import map_to_attack

# Tactics in roughly kill-chain order, so the report reads like an attack does
# rather than alphabetically.
_TACTIC_ORDER = (
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)

# Honeytoken types map to techniques directly — a token has no event stream
# until it fires, so its coverage comes from what triggering it would mean.
_TOKEN_TECHNIQUES: dict[str, tuple[str, str, str]] = {
    "credential": ("T1078", "Valid Accounts", "Initial Access"),
    "api_key": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "aws_key": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "azure_credential": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "gcp_service_account": ("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "ssh_key": ("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence"),
    "jwt": (
        "T1550.001",
        "Use Alternate Authentication Material: Application Access Token",
        "Defense Evasion",
    ),
    "kubeconfig": ("T1613", "Container and Resource Discovery", "Discovery"),
    "slack_webhook": ("T1567", "Exfiltration Over Web Service", "Exfiltration"),
    "canary_url": ("T1005", "Data from Local System", "Collection"),
    "file": ("T1005", "Data from Local System", "Collection"),
    "db_row": ("T1213", "Data from Information Repositories", "Collection"),
}


async def techniques_for_engine(engine_type: str) -> list[dict[str, Any]]:
    """ATT&CK techniques a given engine can evidence, via its real event types."""
    capability = BY_TYPE.get(engine_type)
    if capability is None:
        return []
    return await map_to_attack(list(capability.signature_events))


async def build_coverage(
    deployed_types: list[str],
    token_types: list[str],
    *,
    include_recommendations: bool = True,
) -> dict[str, Any]:
    """Coverage for what is live now, plus what deploying more would add."""
    covered: dict[str, dict[str, Any]] = {}

    for engine_type in dict.fromkeys(deployed_types):
        for technique in await techniques_for_engine(engine_type):
            entry = covered.setdefault(
                technique["technique_id"],
                {
                    "technique_id": technique["technique_id"],
                    "technique_name": technique["technique_name"],
                    "tactic": technique["tactic"],
                    "sources": [],
                },
            )
            if engine_type not in entry["sources"]:
                entry["sources"].append(engine_type)

    for token_type in dict.fromkeys(token_types):
        mapped = _TOKEN_TECHNIQUES.get(token_type)
        if mapped is None:
            continue
        technique_id, name, tactic = mapped
        entry = covered.setdefault(
            technique_id,
            {"technique_id": technique_id, "technique_name": name, "tactic": tactic, "sources": []},
        )
        label = f"token:{token_type}"
        if label not in entry["sources"]:
            entry["sources"].append(label)

    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for technique in covered.values():
        by_tactic.setdefault(technique["tactic"], []).append(technique)

    tactics: list[dict[str, Any]] = []
    for tactic in _TACTIC_ORDER:
        techniques = sorted(by_tactic.get(tactic, []), key=lambda t: t["technique_id"])
        # Two independent sources is the difference between "we would probably
        # see it" and "we would see it even if one sensor is down or the
        # attacker skips that protocol".
        distinct_sources = {s for t in techniques for s in t["sources"]}
        if not techniques:
            level = "none"
        elif len(distinct_sources) >= 2:
            level = "strong"
        else:
            level = "partial"
        tactics.append(
            {
                "tactic": tactic,
                "level": level,
                "technique_count": len(techniques),
                "techniques": [
                    {
                        "id": t["technique_id"],
                        "name": t["technique_name"],
                        "detected_by": sorted(t["sources"]),
                    }
                    for t in techniques
                ],
            }
        )

    result: dict[str, Any] = {
        "sensors_live": sorted(set(deployed_types)),
        "tokens_live": sorted(set(token_types)),
        "techniques_covered": len(covered),
        "tactics": tactics,
        "summary": {
            "strong": [t["tactic"] for t in tactics if t["level"] == "strong"],
            "partial": [t["tactic"] for t in tactics if t["level"] == "partial"],
            "none": [t["tactic"] for t in tactics if t["level"] == "none"],
        },
    }

    if include_recommendations:
        result["blind_spots"] = await _recommend(deployed_types, token_types, covered)
    return result


async def _recommend(
    deployed_types: list[str], token_types: list[str], covered: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Name each gap with the single cheapest thing that closes it.

    Candidates are scored by how many *new* techniques they add, so the advice
    is "this one buys you the most", not an undifferentiated list of everything
    not yet deployed.
    """
    deployed = set(deployed_types)
    recommendations: list[dict[str, Any]] = []

    for capability in all_capabilities():
        if capability.type in deployed:
            continue
        techniques = await techniques_for_engine(capability.type)
        new = [t for t in techniques if t["technique_id"] not in covered]
        if not new:
            continue
        recommendations.append(
            {
                "action": f"deploy a `{capability.type}` sensor",
                "adds_techniques": [
                    {"id": t["technique_id"], "name": t["technique_name"], "tactic": t["tactic"]}
                    for t in sorted(new, key=lambda t: t["technique_id"])
                ],
                "new_technique_count": len(new),
                "tactics_opened": sorted({t["tactic"] for t in new}),
                "why": capability.summary,
                "command": f'honeypot_deploy(type="{capability.type}")',
            }
        )

    recommendations.sort(key=lambda r: r["new_technique_count"], reverse=True)

    recommendations = recommendations[:5]

    # Pinned above the ranking rather than sorted into it. Technique count is
    # the right yardstick for sensors, which all produce the same kind of
    # evidence; it undersells a planted credential, whose single technique is
    # near-zero-false-positive and is the only detection here that fires on an
    # attacker who never touches a sensor directly. Marking it `pinned` keeps
    # the ordering contract honest instead of pretending one technique
    # outranks four.
    if not any(t in token_types for t in ("credential", "api_key", "aws_key")):
        recommendations.insert(
            0,
            {
                "action": "plant a credential honeytoken",
                "adds_techniques": [
                    {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}
                ],
                "new_technique_count": 1,
                "tactics_opened": ["Initial Access"],
                "pinned": True,
                "why": (
                    "Ranked first on fidelity rather than breadth: nobody replays a "
                    "planted password by accident, so this is the platform's lowest "
                    "false-positive signal and the only one that catches an attacker "
                    "who never touches a sensor."
                ),
                "command": 'honeytoken_generate_credentials(service="<a deployed service>")',
            },
        )

    return recommendations
