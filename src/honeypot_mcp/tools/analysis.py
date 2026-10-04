"""Analysis and intelligence MCP tools."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Literal

from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import validate_ip, write_artifact

_MAX_ABUSE_COMMENT_CHARS = 500
_MAX_REPORT_ALERTS = 1000


@mcp.tool
async def enrich_ip(ip: str) -> dict[str, Any]:
    """Enrich an IP address with threat intelligence from multiple sources.
    Queries VirusTotal, AbuseIPDB, and MaxMind GeoIP in parallel.

    Args:
        ip: IPv4 or IPv6 address to look up.
    """
    import asyncio

    if err := validate_ip(ip):
        return {"error": err}

    from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
    from honeypot_mcp.intel.geoip import lookup_geoip
    from honeypot_mcp.intel.virustotal import lookup_virustotal

    # gather() with return_exceptions=True has an inscrutable union return
    # type that confuses mypy at the tuple-unpack site. Annotate explicitly.
    results: list[Any] = await asyncio.gather(
        lookup_geoip(ip),
        lookup_virustotal(ip),
        lookup_abuseipdb(ip),
        return_exceptions=True,
    )
    geo, vt, abuse = results[0], results[1], results[2]

    return {
        "ip": ip,
        "geoip": geo if not isinstance(geo, Exception) else {"error": str(geo)},
        "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
        "abuseipdb": abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
    }


@mcp.tool(auth=require_role("operator"))
async def report_ip_abuse(
    ip: str,
    categories: list[int] | None = None,
    comment: str = "",
) -> dict[str, Any]:
    """Submit an IP abuse report to AbuseIPDB directly from a honeypot alert.

    Common category codes: 14=Port Scan, 18=Brute-Force, 22=SSH, 21=Web App Attack.

    Args:
        ip: The attacker's IP address.
        categories: AbuseIPDB category codes (defaults to [14, 18] — port scan + brute force).
        comment: Description of the activity observed.
    """
    from honeypot_mcp.intel.abuseipdb import report_ip

    if err := validate_ip(ip):
        return {"error": err}
    ip = ip.strip()
    addr = ipaddress.ip_address(ip)
    if not addr.is_global:
        # Reporting a private/loopback/link-local address publishes nothing
        # useful and, worse, lets an injected instruction use this tool to
        # fingerprint the operator's own network in a public database.
        return {"error": f"{ip} is not a globally routable address; refusing to report it."}
    if len(comment) > _MAX_ABUSE_COMMENT_CHARS:
        return {"error": f"comment is too long (max {_MAX_ABUSE_COMMENT_CHARS} characters)."}
    resolved_cats = categories or [14, 18]
    if not all(
        isinstance(c, int) and not isinstance(c, bool) and 1 <= c <= 23 for c in resolved_cats
    ):
        return {"error": "categories must be AbuseIPDB category codes (integers 1-23)."}

    # Only addresses this system has actually observed attacking it: the tool
    # files a report under the operator's API key, and an IP that was merely
    # typed (or injected via captured data) is not ours to accuse.
    async with get_session() as session:
        seen = await queries.get_recent_alerts(session, limit=1, source_ip=ip)
    if not seen:
        return {"error": f"No captured alerts from {ip}; refusing to report an unobserved IP."}

    result = await report_ip(ip, resolved_cats, comment)
    await record_action(
        "report_ip_abuse",
        summary=f"submitted AbuseIPDB report for {addr}",
        arguments={"ip": str(addr), "categories": resolved_cats, "comment_chars": len(comment)},
        target=str(addr),
        outcome="ok" if result.get("reported") else "error",
        error=None if result.get("reported") else str(result.get("note") or result.get("error")),
    )
    return result


@mcp.tool
async def analyze_attacker(ip: str) -> dict[str, Any]:
    """Build a full attacker profile for an IP: all honeypot events, token triggers,
    threat intel enrichment, and MITRE ATT&CK technique mapping.

    Args:
        ip: The attacker's IP address.
    """
    import asyncio

    if err := validate_ip(ip):
        return {"error": err}

    from honeypot_mcp.analysis.profiler import build_profile
    from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
    from honeypot_mcp.intel.geoip import lookup_geoip
    from honeypot_mcp.intel.virustotal import lookup_virustotal

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=200, source_ip=ip)
        events = await queries.get_events_for_ip(session, ip, limit=200)

    results: list[Any] = await asyncio.gather(
        lookup_geoip(ip),
        lookup_virustotal(ip),
        lookup_abuseipdb(ip),
        return_exceptions=True,
    )
    geo, vt, abuse = results[0], results[1], results[2]

    profile = await build_profile(
        ip=ip,
        alerts=alerts,
        events=events,
        geoip=geo if not isinstance(geo, Exception) else {},
        vt=vt if not isinstance(vt, Exception) else {},
        abuse=abuse if not isinstance(abuse, Exception) else {},
    )
    return profile


@mcp.tool
async def analyze_campaign(
    window_minutes: int = 60,
    min_sources: int = 3,
) -> list[dict[str, Any]]:
    """Detect coordinated attack campaigns: groups of IPs hitting similar targets
    within the same time window.

    Args:
        window_minutes: Time window to consider events correlated (default 60).
        min_sources: Minimum distinct source IPs to constitute a campaign (default 3).
    """
    from honeypot_mcp.analysis.correlator import detect_campaigns

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=5000)

    campaigns = await detect_campaigns(
        alerts=alerts,
        window_minutes=window_minutes,
        min_sources=min_sources,
    )
    return campaigns


@mcp.tool
async def map_ttps(
    ip: str | None = None,
    event_types: list[str] | None = None,
    raw_text: str | None = None,
) -> list[dict[str, Any]]:
    """Map observed attacker behaviours to MITRE ATT&CK techniques.

    Provide one or more inputs:
    - ip: look up all events for this IP
    - event_types: list of event type strings to map directly
    - raw_text: freeform text to scan for technique indicators

    Args:
        ip: Attacker IP to pull events for.
        event_types: Explicit event type strings (e.g. ['ssh_brute_force', 'web_scan']).
        raw_text: Arbitrary text to scan for ATT&CK indicators.
    """
    from honeypot_mcp.intel.mitre import map_to_attack

    terms: list[str] = list(event_types or [])

    if ip:
        async with get_session() as session:
            alerts = await queries.get_recent_alerts(session, limit=200, source_ip=ip)
        terms.extend(a.event_type for a in alerts)
        terms.extend(str(v) for a in alerts for v in a.payload.values() if isinstance(v, str))

    if raw_text:
        terms.append(raw_text)

    return await map_to_attack(terms)


@mcp.tool
async def generate_report(
    title: str = "Attack Analysis Report",
    ip: str | None = None,
    format: Literal["html", "markdown"] = "html",
    since_hours: float | None = None,
    limit: int = 500,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Write an attack report — timeline, top attackers, MITRE TTPs — to a file.

    Returns the path plus the headline figures, so the report can be opened or
    sent on without spending the conversation on rendered HTML. Scoping to an
    `ip` additionally attaches the full intelligence picture (geo/ASN, VT and
    AbuseIPDB reputation, risk score, recommendations).

    Args:
        title: Report title.
        ip: Scope the report to a single attacker IP (omit for all activity).
        format: Output format — html or markdown.
        since_hours: Only include activity from the last N hours (e.g. 168 for a
              weekly write-up). Omit for all available history.
        limit: Maximum alerts to analyse (default 500, max 1000).
        output_path: Where to write — a name inside the reports directory ending in
              `.html` / `.md` to match the format. An existing file is never overwritten.
              Defaults to `reports/report-<timestamp>.<ext>`.
    """
    from datetime import timedelta

    from honeypot_mcp.analysis.reporter import generate

    limit = max(1, min(limit, _MAX_REPORT_ALERTS))
    extension = "html" if format == "html" else "md"
    if output_path and not output_path.lower().endswith(f".{extension}"):
        return {
            "error": (
                f"output_path must end in .{extension} for format={format!r} "
                f"(got {output_path!r}) — reports are written exactly as named, "
                "so the extension has to match the content."
            )
        }
    if ip and (err := validate_ip(ip)):
        return {"error": err}
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=limit, source_ip=ip, since=since)
        stats = await queries.get_alert_stats(session, since=since)
        events = await queries.get_events_for_ip(session, ip) if ip else []

    # For an IP-scoped report, attach the full intelligence picture (geo/ASN/
    # reverse-DNS + VT/AbuseIPDB reputation + risk score + recommendations) so
    # the report is actionable, not just a count of events.
    intel: dict[str, Any] | None = None
    if ip:
        import asyncio

        from honeypot_mcp.analysis.profiler import build_profile
        from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
        from honeypot_mcp.intel.geoip import lookup_geoip
        from honeypot_mcp.intel.virustotal import lookup_virustotal

        results: list[Any] = await asyncio.gather(
            lookup_geoip(ip),
            lookup_virustotal(ip),
            lookup_abuseipdb(ip),
            return_exceptions=True,
        )
        geo, vt, abuse = (r if not isinstance(r, Exception) else {} for r in results)
        intel = await build_profile(
            ip=ip, alerts=alerts, events=events, geoip=geo, vt=vt, abuse=abuse
        )

    content = await generate(
        title=title,
        alerts=alerts,
        stats=stats,
        target_ip=ip,
        format=format,
        intel=intel,
    )
    written = write_artifact(
        content,
        prefix="report",
        extension=extension,
        output_path=output_path,
    )
    if "error" in written:
        return written
    await record_action(
        "generate_report",
        summary=f"wrote {format} report ({len(alerts)} alert(s))"
        + (f" scoped to {ip}" if ip else ""),
        arguments={
            "format": format,
            "ip": ip,
            "since_hours": since_hours,
            "limit": limit,
            "output_path": output_path,
        },
        target=ip or written["path"],
    )
    return {
        **written,
        "title": title,
        "format": format,
        "alerts_analysed": len(alerts),
        "scoped_to_ip": ip,
        "window_hours": since_hours,
        "unique_source_ips": stats.get("unique_source_ips"),
        "by_severity": stats.get("by_severity"),
    }


# MITRE kill-chain order — used to lay out journey phases left-to-right.
_KILL_CHAIN_ORDER = (
    "Reconnaissance",
    "Resource Development",
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
    "Unmapped",
)
_KILL_CHAIN_RANK = {phase: i for i, phase in enumerate(_KILL_CHAIN_ORDER)}


def _primary_tactic(ttps: list[dict[str, Any]]) -> str:
    """Pick the meaningful 'where is this attacker now' phase.

    An event can match multiple ATT&CK techniques across multiple tactics
    (e.g. `ls /` triggers both Execution and Initial Access via path-
    traversal regex). For journey reconstruction, the LATEST kill-chain
    phase is the most informative — it shows the attacker's current
    progression, not the earliest pattern that happened to match."""
    if not ttps:
        return "Unmapped"
    tactics = {t["tactic"] for t in ttps}
    return max(tactics, key=lambda t: _KILL_CHAIN_RANK.get(t, -1))


def _summarize_payload(payload: dict[str, Any]) -> str:
    """One-line summary for journey display — picks the fields a SOC analyst
    actually wants to see (credentials tried, command run, path requested)."""
    if not payload:
        return ""
    bits = []
    for k in ("username", "password", "input", "command", "qname", "path", "method"):
        if k in payload and payload[k] not in (None, ""):
            v = str(payload[k])[:80]
            bits.append(f"{k}={v}")
    if bits:
        return ", ".join(bits)
    return f"{len(payload)} fields"


@mcp.tool
async def analyze_attacker_journey(ip: str, hours: int = 168) -> dict[str, Any]:
    """Reconstruct an attacker's full activity across all honeypots and tokens.

    Pulls every alert + token trigger for the IP, maps each to a MITRE ATT&CK
    tactic, groups by phase in kill-chain order, and shows the transitions
    between phases. This is the 'what's the story of this attacker' view —
    the multi-honeypot complement to `analyze_session` (which is per-Cowrie-session).

    Args:
        ip: The attacker's IP address.
        hours: Look-back window in hours (default 168 = 7 days).
    """
    if err := validate_ip(ip):
        return {"error": err}

    from datetime import datetime, timedelta

    from sqlalchemy import select

    from honeypot_mcp.intel.mitre import map_to_attack
    from honeypot_mcp.storage.models import (
        Alert,
        AttackerEvent,
        Honeypot,
        Honeytoken,
    )

    since = datetime.now(UTC) - timedelta(hours=hours)

    async with get_session() as session:
        alerts_result = await session.execute(
            select(Alert)
            .where(Alert.source_ip == ip, Alert.timestamp >= since)
            .order_by(Alert.timestamp)
        )
        alerts = list(alerts_result.scalars().all())

        events_result = await session.execute(
            select(AttackerEvent)
            .where(AttackerEvent.ip == ip, AttackerEvent.timestamp >= since)
            .order_by(AttackerEvent.timestamp)
        )
        events = list(events_result.scalars().all())

        hp_ids = {a.honeypot_id for a in alerts if a.honeypot_id is not None}
        honeypot_names: dict[int, str] = {}
        if hp_ids:
            hp_result = await session.execute(
                select(Honeypot.id, Honeypot.name).where(Honeypot.id.in_(hp_ids))
            )
            honeypot_names = {row[0]: row[1] for row in hp_result.all()}

        token_ids = {e.honeytoken_id for e in events if e.honeytoken_id is not None}
        tokens_triggered: list[dict[str, Any]] = []
        if token_ids:
            tok_result = await session.execute(
                select(Honeytoken).where(Honeytoken.id.in_(token_ids))
            )
            for t in tok_result.scalars().all():
                tokens_triggered.append(
                    {
                        "id": t.id,
                        "type": t.type.value,
                        "label": t.label,
                        "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
                    }
                )

    if not alerts and not events:
        return {
            "ip": ip,
            "total_alerts": 0,
            "total_events": 0,
            "summary": f"No activity for {ip} in the last {hours}h.",
        }

    chronological: list[dict[str, Any]] = []
    for a in alerts:
        terms = [a.event_type]
        for v in a.payload.values():
            if isinstance(v, str):
                terms.append(v)
        ttps = await map_to_attack(terms)
        chronological.append(
            {
                "_ts": a.timestamp,
                "timestamp": a.timestamp.isoformat(),
                "event_type": a.event_type,
                "severity": a.severity.value,
                "honeypot": honeypot_names.get(a.honeypot_id, "—")
                if a.honeypot_id is not None
                else "—",
                "summary": _summarize_payload(a.payload),
                "techniques": ttps,
                "primary_tactic": _primary_tactic(ttps),
            }
        )
    chronological.sort(key=lambda x: x["_ts"])

    # Group by primary tactic. Each phase aggregates the events and the
    # unique technique IDs observed within it.
    phases: dict[str, dict[str, Any]] = {}
    for e in chronological:
        pt = e["primary_tactic"]
        if pt not in phases:
            phases[pt] = {"phase": pt, "events": [], "_tech_ids": set(), "techniques": []}
        phases[pt]["events"].append(
            {
                "timestamp": e["timestamp"],
                "event_type": e["event_type"],
                "severity": e["severity"],
                "honeypot": e["honeypot"],
                "summary": e["summary"],
            }
        )
        for t in e["techniques"]:
            tid = t["technique_id"]
            if tid not in phases[pt]["_tech_ids"]:
                phases[pt]["_tech_ids"].add(tid)
                phases[pt]["techniques"].append(
                    {
                        "technique_id": tid,
                        "technique_name": t["technique_name"],
                    }
                )

    # Order phases by kill-chain progression.
    phases_list = []
    for _phase_name, data in phases.items():
        data.pop("_tech_ids", None)
        data["event_count"] = len(data["events"])
        phases_list.append(data)
    phases_list.sort(
        key=lambda p: _KILL_CHAIN_ORDER.index(p["phase"]) if p["phase"] in _KILL_CHAIN_ORDER else 99
    )

    # Detect phase transitions in chronological order.
    transitions: list[dict[str, Any]] = []
    last_phase: str | None = None
    for e in chronological:
        if last_phase is not None and e["primary_tactic"] != last_phase:
            transitions.append(
                {
                    "at": e["timestamp"],
                    "from": last_phase,
                    "to": e["primary_tactic"],
                    "via": e["event_type"],
                }
            )
        last_phase = e["primary_tactic"]

    first_seen = chronological[0]["_ts"]
    last_seen = chronological[-1]["_ts"]

    summary_bits = [
        f"Attacker {ip} active from {first_seen.isoformat()} to {last_seen.isoformat()}",
        f"touched {len(honeypot_names)} honeypot(s)",
        f"{len(alerts)} alert(s) across {len(phases_list)} ATT&CK phase(s)",
    ]
    if tokens_triggered:
        summary_bits.append(f"triggered {len(tokens_triggered)} honeytoken(s)")
    if len(phases_list) > 1:
        summary_bits.append("phase progression: " + " → ".join(p["phase"] for p in phases_list))
    summary = ". ".join(summary_bits) + "."

    return {
        "ip": ip,
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "duration_seconds": (last_seen - first_seen).total_seconds(),
        "honeypots_touched": sorted(honeypot_names.values()),
        "tokens_triggered": tokens_triggered,
        "total_alerts": len(alerts),
        "total_events": len(events),
        "phases": phases_list,
        "transitions": transitions,
        "summary": summary,
        "chronological": [
            {k: v for k, v in e.items() if k not in ("_ts", "techniques", "primary_tactic")}
            for e in chronological[:200]
        ],
    }


@mcp.tool
async def analyze_session(session_id: str) -> dict[str, Any]:
    """Reconstruct a single SSH attack session into a coherent timeline.

    Cowrie tags every event with a session ID — this tool pulls every alert
    whose payload contains that session, sorted chronologically, and extracts
    the credentials tried and commands run. This is the unit of analysis a
    real SOC works in: 'show me what this attacker actually did'.

    Args:
        session_id: The Cowrie session ID (found in any SSH alert's payload.session field).
    """
    from sqlalchemy import String, cast, select

    from honeypot_mcp.storage.models import Alert

    needle = f'"session": "{session_id}"'
    async with get_session() as session:
        result = await session.execute(
            select(Alert)
            .where(cast(Alert.payload, String).contains(needle))
            .order_by(Alert.timestamp)
        )
        alerts = list(result.scalars().all())

    if not alerts:
        return {"error": f"No alerts found for session_id={session_id}"}

    timeline: list[dict[str, Any]] = []
    commands: list[str] = []
    login_attempts: list[dict[str, Any]] = []
    successful_login: dict[str, Any] | None = None

    for a in alerts:
        entry: dict[str, Any] = {
            "timestamp": a.timestamp.isoformat(),
            "event_type": a.event_type,
            "severity": a.severity.value,
        }
        p = a.payload or {}
        if a.event_type == "ssh_command_input":
            cmd = p.get("input", "")
            commands.append(cmd)
            entry["command"] = cmd
        elif a.event_type in ("ssh_login_failed", "ssh_login_success"):
            attempt = {
                "username": p.get("username"),
                "password": p.get("password"),
                "success": a.event_type == "ssh_login_success",
            }
            login_attempts.append(attempt)
            if attempt["success"]:
                successful_login = attempt
            entry["credentials"] = f"{p.get('username') or ''}:{p.get('password') or ''}"
        elif a.event_type == "ssh_file_download":
            entry["url"] = p.get("url", "")
            entry["outfile"] = p.get("outfile", "")
        timeline.append(entry)

    duration = (alerts[-1].timestamp - alerts[0].timestamp).total_seconds()
    return {
        "session_id": session_id,
        "source_ip": alerts[0].source_ip,
        "first_event": alerts[0].timestamp.isoformat(),
        "last_event": alerts[-1].timestamp.isoformat(),
        "duration_seconds": duration,
        "total_events": len(alerts),
        "login_attempts": login_attempts,
        "successful_login": successful_login,
        "commands_executed": commands,
        "timeline": timeline,
    }


def _usable_offenders(
    offenders: list[tuple[str, int]],
) -> list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]]:
    """Parse offender strings with `ipaddress`; drop anything that is not an IP.

    The source is a captured string column, so a malformed value must not reach
    a firewall rule or a STIX pattern. Global-only filtering is done by the
    query (and re-asserted here, so the artifact stays safe even if a caller
    hands in an unfiltered list).
    """
    # The same never-block set the push tools use (BLOCKLIST_ALLOWLIST plus this
    # server's own canary address). A ready-made `iptables -A INPUT -s <ip> -j
    # DROP` file is exactly as dangerous as a push if it contains the operator's
    # own gateway. A malformed allowlist raises ValueError, as it does for pushes.
    from honeypot_mcp.tools.blocklist_push import _never_push

    never = _never_push()
    usable: list[tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]] = []
    for raw, count in offenders:
        try:
            addr = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        if not addr.is_global or any(addr in net for net in never):
            continue
        usable.append((addr, count))
    return usable


def _stix_object_type(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    return "ipv6-addr" if addr.version == 6 else "ipv4-addr"


def _stix_escape(value: str) -> str:
    """Escape a string for a STIX pattern literal (backslash and single quote)."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


@mcp.tool(auth=require_role("operator"))
async def export_blocklist(
    format: Literal["plain", "iptables", "fail2ban", "cidr"] = "plain",
    hours: int = 24,
    min_hits: int = 5,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Export attacker IPs above a hit threshold as a blocklist file.

    Writes the list to disk and returns the path plus the top offenders —
    the content is destined for a firewall, a fail2ban jail or a Cloudflare
    list, and it grows one line per offending IP, so a busy sensor produces
    far more than is useful to read back.

    Args:
        format: 'plain' (one IP per line), 'iptables' (DROP rules),
                'fail2ban' (jail-friendly), or 'cidr' (one IP per line, /32 suffix).
        hours: Time window — only count alerts in the last N hours (default 24).
        min_hits: Only include IPs with at least this many alerts (default 5).
        output_path: Where to write. Defaults to `reports/blocklist-<timestamp>.txt`.
    """
    async with get_session() as session:
        raw_offenders = await queries.get_top_offenders(
            session, hours, min_hits, global_only=True, exclude_udp_only=True
        )
    try:
        offenders = _usable_offenders(raw_offenders)
    except ValueError as e:
        return {"error": str(e)}

    if not offenders:
        return {
            "ip_count": 0,
            "note": f"No attackers met the threshold (>= {min_hits} hits in {hours}h).",
        }

    header = (
        f"# HoneyPot MCP blocklist — generated {datetime.now(UTC).isoformat()}\n"
        f"# {len(offenders)} IPs with >= {min_hits} alerts in the last {hours}h.\n"
    )
    if format == "iptables":
        lines = [
            f"{'ip6tables' if addr.version == 6 else 'iptables'} -A INPUT -s {addr} -j DROP"
            f"  # {cnt} hits"
            for addr, cnt in offenders
        ]
    elif format == "fail2ban":
        lines = [f"{addr}  # {cnt} hits" for addr, cnt in offenders]
    elif format == "cidr":
        lines = [f"{addr}/{addr.max_prefixlen}" for addr, _ in offenders]
    else:
        lines = [str(addr) for addr, _ in offenders]
    content = header + "\n".join(lines) + "\n"

    written = write_artifact(content, prefix="blocklist", extension="txt", output_path=output_path)
    if "error" in written:
        return written
    return {
        **written,
        "format": format,
        "ip_count": len(offenders),
        "window_hours": hours,
        "min_hits": min_hits,
        "top_offenders": [{"ip": str(addr), "hits": cnt} for addr, cnt in offenders[:10]],
    }


@mcp.tool(auth=require_role("operator"))
async def export_stix(
    hours: int = 24,
    min_hits: int = 1,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Export attacker IPs as a STIX 2.1 bundle file for sharing with other SOCs.

    Writes the bundle to disk and returns the path. STIX is verbose by design —
    a few hundred alerts produce well over 100 KB of JSON — and it is meant to
    be loaded into a TIP or MISP instance, not read back in conversation.

    Each unique attacker IP becomes an Indicator SDO with the standard
    `[ipv4-addr:value = '...']` pattern and the 'malicious-activity' label.

    Args:
        hours: Time window — only IPs seen in the last N hours.
        min_hits: Minimum alert count for inclusion.
        output_path: Where to write. Defaults to `reports/stix-<timestamp>.json`.
    """
    import json
    import uuid
    from datetime import datetime

    async with get_session() as session:
        raw_offenders = await queries.get_top_offenders(
            session, hours, min_hits, global_only=True, exclude_udp_only=True
        )
    try:
        offenders = _usable_offenders(raw_offenders)
    except ValueError as e:
        return {"error": str(e)}

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    objects = [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": f"Honeypot-detected attacker {addr}",
            "description": f"Source IP observed in {cnt} honeypot alerts within the last {hours}h.",
            "pattern": f"[{_stix_object_type(addr)}:value = '{_stix_escape(str(addr))}']",
            "pattern_type": "stix",
            "valid_from": now,
            "labels": ["malicious-activity"],
        }
        for addr, cnt in offenders
    ]
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    written = write_artifact(
        json.dumps(bundle, indent=2), prefix="stix", extension="json", output_path=output_path
    )
    if "error" in written:
        return written
    return {
        **written,
        "bundle_id": bundle["id"],
        "indicator_count": len(objects),
        "window_hours": hours,
        "min_hits": min_hits,
    }


@mcp.tool
async def threat_timeline(
    ip: str | None = None,
    hours: int = 24,
    limit: int = 200,
) -> dict[str, Any]:
    """Get a chronological event timeline for a time range or specific IP.

    Args:
        ip: Filter to a specific attacker IP (omit for all sources).
        hours: How many hours back to look (default 24).
        limit: Maximum events to return (default 200). When a window has more
              matching events than this, the most recent `limit` are kept —
              not the oldest — since recency is what a caller filtering to
              "the last N hours" almost always wants.
    """
    from datetime import datetime, timedelta

    from sqlalchemy import select

    from honeypot_mcp.storage.models import Alert

    since = datetime.now(UTC) - timedelta(hours=hours)

    async with get_session() as session:
        q = select(Alert).where(Alert.timestamp >= since)
        if ip:
            q = q.where(Alert.source_ip == ip)
        # Order DESC to select the most recent `limit` rows when the window
        # holds more than that; re-sorted ASC below for chronological display.
        q = q.order_by(Alert.timestamp.desc()).limit(limit)
        result = await session.execute(q)
        alerts = sorted(result.scalars().all(), key=lambda a: a.timestamp)

    events = [
        {
            "timestamp": a.timestamp.isoformat(),
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "honeypot_id": a.honeypot_id,
        }
        for a in alerts
    ]
    out: dict[str, Any] = {"count": len(events), "events": events, "window": f"last {hours}h"}
    if len(events) == limit:
        out["note"] = (
            f"Hit the limit of {limit} — there may be more (and older) events in "
            f"this window. Narrow with `ip`, shrink `hours`, or raise `limit`."
        )
    return out
