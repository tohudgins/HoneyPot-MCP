"""Turn an intent into a coherent, conflict-free deception deployment.

The division of labour matters here. A language model reads "we run a customer
portal on nginx and a Postgres warehouse behind it, plus a Windows file server"
perfectly well; what it cannot do reliably is the part that makes deception
*work*:

* Know which ports are already taken by existing honeypots.
* Keep an identity consistent across sensors — a Windows SMB share, an RDP host
  and an LDAP directory have to agree on a domain and a hostname family, or an
  attacker who touches two of them sees the seam.
* Know that a planted credential is inert unless a sensor that captures that
  service is actually deployed.
* Remember that some sensors are unconvincing alone (a directory with nothing
  behind it).

So the model supplies the language and this module supplies the domain
reasoning and validation. It builds a plan and returns it; nothing is deployed
until the operator agrees, because deploying network listeners is not something
to do as a side effect of a question.

Coherence checks are the point. Hand-built deception fails on mismatched detail
far more often than on missing detail, and every check here corresponds to a
seam a real attacker would notice.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from honeypot_mcp.deception.capabilities import (
    BY_TYPE,
    PROFILES,
    EnvironmentProfile,
    all_profiles,
)

# Hostname pools per identity family. Names have to look assigned by an
# infrastructure team, not generated: `corp-dc1` reads as real, `honeypot-3`
# does not.
_HOSTNAME_ROLES = {
    "smb": ("fs01", "fileshare", "share01"),
    "ldap": ("dc1", "dc01", "ad1"),
    "rdp": ("term1", "rds01", "jump1"),
    "mssql": ("sql01", "sqlprod", "db01"),
    "postgresql": ("pg01", "warehouse", "db02"),
    "mysql": ("mysql01", "db03", "app-db"),
    "http": ("web01", "portal", "www01"),
    "ssh": ("bastion", "jump01", "app01"),
    "telnet": ("sw01", "edge01", "iot-gw"),
    "redis": ("cache01", "redis01"),
    "elasticsearch": ("search01", "es01"),
    "mongodb": ("mongo01", "docstore"),
    "docker_api": ("node01", "worker01"),
    "snmp": ("sw-core", "rtr01"),
    "dns": ("ns1", "resolver01"),
    "ftp": ("ftp01", "transfer"),
    "smtp": ("mail01", "mx1"),
    "vnc": ("kiosk01", "console01"),
    "memcached": ("mc01", "cache02"),
}


@dataclass
class PlannedSensor:
    type: str
    name: str
    port: int
    config: dict[str, Any] = field(default_factory=dict)
    hostname: str = ""
    rationale: str = ""


@dataclass
class PlannedToken:
    type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)
    plant_location: str = ""
    cross_references: str = ""
    rationale: str = ""


def _pick_hostname(engine_type: str, prefix: str, taken: set[str]) -> str:
    for role in _HOSTNAME_ROLES.get(engine_type, (engine_type,)):
        candidate = f"{prefix}-{role}"
        if candidate not in taken:
            taken.add(candidate)
            return candidate
    candidate = f"{prefix}-{engine_type}{secrets.randbelow(90) + 10}"
    taken.add(candidate)
    return candidate


def resolve_services(
    profile_id: str | None, services: list[str] | None, include_optional: bool
) -> tuple[list[str], EnvironmentProfile | None, list[str]]:
    """Work out the sensor list. Returns (types, profile, warnings)."""
    warnings: list[str] = []
    if services:
        known = [s for s in services if s in BY_TYPE]
        unknown = [s for s in services if s not in BY_TYPE]
        if unknown:
            warnings.append(
                f"Ignored unknown service(s): {', '.join(sorted(unknown))}. "
                f"Valid types: {', '.join(sorted(BY_TYPE))}."
            )
        return known, PROFILES.get(profile_id or ""), warnings

    profile = PROFILES.get(profile_id or "")
    if profile is None:
        warnings.append(
            f"Unknown profile '{profile_id}'. Valid profiles: "
            f"{', '.join(p.id for p in all_profiles())}."
        )
        return [], None, warnings

    chosen = list(profile.core) + (list(profile.optional) if include_optional else [])
    return chosen, profile, warnings


def build_plan(
    *,
    profile_id: str | None = None,
    services: list[str] | None = None,
    identity_prefix: str | None = None,
    domain: str | None = None,
    include_optional: bool = False,
    include_tokens: bool = True,
    use_real_ports: bool = False,
    existing_ports: dict[int, str] | None = None,
    existing_names: set[str] | None = None,
) -> dict[str, Any]:
    """Build (but do not deploy) a coherent deception plan."""
    existing_ports = existing_ports or {}
    existing_names = existing_names or set()

    types, profile, warnings = resolve_services(profile_id, services, include_optional)
    if not types:
        return {
            "error": "No sensors resolved — supply a valid `profile` or an explicit `services` list.",
            "valid_profiles": [
                {"id": p.id, "display_name": p.display_name, "description": p.description}
                for p in all_profiles()
            ],
            "valid_services": sorted(BY_TYPE),
        }

    prefix = identity_prefix or (profile.hostname_prefix if profile else "srv")
    resolved_domain = domain or (profile.domain if profile else None)
    if resolved_domain is None and any(BY_TYPE[t].os_family == "windows" for t in types):
        resolved_domain = f"{prefix}.local"

    taken_hostnames: set[str] = set()
    used_ports = dict(existing_ports)
    sensors: list[PlannedSensor] = []
    conflicts: list[str] = []

    for engine_type in dict.fromkeys(types):  # de-dup, preserve order
        cap = BY_TYPE[engine_type]
        port = cap.real_world_port if use_real_ports else cap.default_port
        original_port = port
        while port in used_ports:
            port += 1
        if port != original_port:
            conflicts.append(
                f"{cap.display_name}: port {original_port} already used by "
                f"'{used_ports[original_port]}' — moved to {port}."
            )
        used_ports[port] = f"planned {engine_type}"

        hostname = _pick_hostname(engine_type, prefix, taken_hostnames)
        name = f"{prefix}-{engine_type}"
        suffix = 2
        while name in existing_names:
            name = f"{prefix}-{engine_type}{suffix}"
            suffix += 1
        existing_names.add(name)

        config: dict[str, Any] = {}
        if engine_type in ("ssh", "telnet"):
            config["fake_hostname"] = hostname
        elif engine_type in ("smtp",):
            config["fake_domain"] = resolved_domain or f"{prefix}.com"
        elif engine_type == "ldap" and resolved_domain:
            config["base_dn"] = "dc=" + ",dc=".join(resolved_domain.split("."))
        elif engine_type in ("rdp", "smb", "mssql", "vnc", "ftp"):
            config["fake_hostname"] = hostname

        sensors.append(
            PlannedSensor(
                type=engine_type,
                name=name,
                port=port,
                config=config,
                hostname=hostname,
                rationale=cap.summary,
            )
        )

    tokens = _plan_tokens(sensors, prefix, resolved_domain) if include_tokens else []
    coherence = check_coherence(sensors, tokens)

    return {
        "identity": {
            "hostname_prefix": prefix,
            "domain": resolved_domain,
            "os_family": profile.os_family if profile else "neutral",
        },
        "profile": profile.id if profile else None,
        "sensors": [
            {
                "type": s.type,
                "name": s.name,
                "port": s.port,
                "config": s.config,
                "hostname": s.hostname,
                "detects": list(BY_TYPE[s.type].signature_events),
                "rationale": s.rationale,
            }
            for s in sensors
        ],
        "tokens": [
            {
                "type": t.type,
                "label": t.label,
                "metadata": t.metadata,
                "plant_location": t.plant_location,
                "cross_references": t.cross_references,
                "rationale": t.rationale,
            }
            for t in tokens
        ],
        "port_conflicts_resolved": conflicts,
        "coherence": coherence,
        "warnings": warnings,
        "next_step": (
            "Review, then call `deception_deploy_plan` with this plan to bring it up. "
            "Nothing has been deployed yet."
        ),
    }


def _plan_tokens(
    sensors: list[PlannedSensor], prefix: str, domain: str | None
) -> list[PlannedToken]:
    """Plant tokens that the deployed sensors can actually detect.

    A credential token is inert unless a sensor capturing that service is in the
    plan, and a file token needs somewhere plausible to sit. Tying each token to
    a specific sensor is what stops the usual failure — tokens scattered
    somewhere nothing watches.
    """
    by_type = {s.type: s for s in sensors}
    tokens: list[PlannedToken] = []

    # A credential that is valid on a deployed database is the highest-fidelity
    # signal available: nobody guesses a planted password by accident.
    for db in ("postgresql", "mysql", "mssql", "redis"):
        if db in by_type:
            tokens.append(
                PlannedToken(
                    type="credential",
                    label=f"{prefix}-{db}-svc-account",
                    metadata={"service": db, "username": "svc_backup"},
                    plant_location=(
                        "a config file, password manager entry or wiki page an "
                        "intruder would find after initial access"
                    ),
                    cross_references=by_type[db].name,
                    rationale=(
                        f"Auto-escalates to CRITICAL and names the token if replayed "
                        f"against the {db} sensor."
                    ),
                )
            )
            break

    if "http" in by_type:
        tokens.append(
            PlannedToken(
                type="api_key",
                label=f"{prefix}-aws-decoy",
                metadata={"service": "aws"},
                plant_location="served by the HTTP sensor's decoy /.env endpoint",
                cross_references=by_type["http"].name,
                rationale=(
                    "Scanners that scrape .env files and try the key elsewhere become "
                    "visibly hostile. Needs a cloud forwarder to detect actual use — "
                    "see examples/cloud-forwarders/."
                ),
            )
        )

    if "smb" in by_type:
        tokens.append(
            PlannedToken(
                type="file",
                label=f"{prefix}-q3-forecast.docx",
                metadata={"file_type": "docx", "document_title": "Q3 Forecast (Confidential)"},
                plant_location=f"the {by_type['smb'].name} file share, alongside real-looking documents",
                cross_references="canary callback server",
                rationale=(
                    "Opening it calls home and fires CRITICAL. Requires CANARY_PUBLIC_URL "
                    "to be reachable from wherever the document is opened."
                ),
            )
        )

    if "ssh" in by_type or "telnet" in by_type:
        tokens.append(
            PlannedToken(
                type="ssh_key",
                label=f"{prefix}-deploy-key",
                metadata={},
                plant_location="a fake CI/CD or backup host's ~/.ssh/",
                cross_references=(by_type.get("ssh") or by_type["telnet"]).name,
                rationale="Fingerprint match on any SSH auth attempt using the planted key.",
            )
        )

    if "kubernetes" in by_type:
        tokens.append(
            PlannedToken(
                type="kubeconfig",
                label=f"{prefix}-cluster-admin-kubeconfig",
                metadata={},
                plant_location="a developer workstation or CI runner's ~/.kube/config",
                cross_references="canary callback server",
                rationale=(
                    "A stolen kubeconfig is used before it is understood — the first "
                    "`kubectl get pods` reaches the cluster URL in the file, which is "
                    "the canary. Pairs with the Kubernetes sensor: one catches an "
                    "attacker who found the API server, the other catches one who "
                    "found the credentials for it."
                ),
            )
        )

    tokens.append(
        PlannedToken(
            type="canary_url",
            label=f"{prefix}-internal-wiki-link",
            metadata={},
            plant_location="an internal wiki page, README or bookmark file",
            cross_references="canary callback server",
            rationale="Any HTTP GET fires CRITICAL with full request metadata.",
        )
    )
    return tokens


def check_coherence(sensors: list[PlannedSensor], tokens: list[PlannedToken]) -> dict[str, Any]:
    """Find the seams an attacker would notice, and the tokens that can't fire.

    Every issue here is something that has to be *inconsistent* to be wrong —
    which is exactly what a scanner correlating two ports will spot, and what a
    per-sensor view can never surface.
    """
    issues: list[dict[str, str]] = []
    types = {s.type for s in sensors}

    families = {BY_TYPE[t].os_family for t in types} - {"neutral"}
    if "windows" in families and "linux" in families:
        issues.append(
            {
                "severity": "info",
                "issue": "Windows and Linux sensors share one identity prefix.",
                "fix": (
                    "Realistic for a mixed estate, but if these are meant to be one "
                    "host, split them into two plans with different prefixes."
                ),
            }
        )

    if "ldap" in types and not ({"smb", "rdp", "mssql"} & types):
        issues.append(
            {
                "severity": "warning",
                "issue": "A directory server with no Windows services behind it is not a convincing domain.",
                "fix": "Add `smb` and/or `rdp` so the directory has something to be the directory of.",
            }
        )
    if "rdp" in types and "smb" not in types:
        issues.append(
            {
                "severity": "info",
                "issue": "RDP with no SMB is unusual — Windows hosts almost always expose 445 as well.",
                "fix": "Add `smb` to make the host read as a normal Windows machine.",
            }
        )

    # The failure that actually loses data: a token nothing can detect.
    deployed_credential_services: set[str] = {
        service for t in types if (service := BY_TYPE[t].captures_credentials_as) is not None
    }
    for token in tokens:
        if token.type != "credential":
            continue
        service = token.metadata.get("service")
        if service and service not in deployed_credential_services:
            issues.append(
                {
                    "severity": "error",
                    "issue": (
                        f"Credential token '{token.label}' targets service '{service}', "
                        "which no sensor in this plan captures — it can never fire."
                    ),
                    "fix": f"Deploy a `{service}` sensor, or retarget the token to one of: "
                    + ", ".join(sorted(deployed_credential_services)),
                }
            )
        elif not service and not deployed_credential_services:
            # An unset (or "any") service normally means "matches whichever
            # credential-capturing sensor is deployed" — but if none are
            # deployed at all (e.g. a DNS + Elasticsearch plan), there is no
            # login-attempt-shaped event for credential_match.py to ever
            # cross-reference this against, silently the same way an
            # explicit service mismatch is.
            issues.append(
                {
                    "severity": "error",
                    "issue": (
                        f"Credential token '{token.label}' has no explicit service, but no "
                        "sensor in this plan captures credentials at all — it can never fire."
                    ),
                    "fix": (
                        "Deploy a credential-capturing sensor (e.g. ssh, http, ftp) for it to "
                        "cross-reference."
                    ),
                }
            )

    return {
        "consistent": not any(i["severity"] == "error" for i in issues),
        "issues": issues,
        "identity_summary": (
            f"{len(sensors)} sensors sharing one hostname family; "
            f"{len(tokens)} tokens, each tied to a sensor that can detect it."
        ),
    }
