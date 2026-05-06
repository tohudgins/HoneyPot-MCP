"""Analysis and intelligence MCP tools."""

from __future__ import annotations

from typing import Any

from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries


@mcp.tool
async def enrich_ip(ip: str) -> dict[str, Any]:
    """Enrich an IP address with threat intelligence from multiple sources.
    Queries VirusTotal, AbuseIPDB, GreyNoise, and MaxMind GeoIP in parallel.

    Args:
        ip: IPv4 or IPv6 address to look up.
    """
    import asyncio
    from honeypot_mcp.intel.geoip import lookup_geoip
    from honeypot_mcp.intel.virustotal import lookup_virustotal
    from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
    from honeypot_mcp.intel.greynoise import lookup_greynoise

    geo, vt, abuse, noise = await asyncio.gather(
        lookup_geoip(ip),
        lookup_virustotal(ip),
        lookup_abuseipdb(ip),
        lookup_greynoise(ip),
        return_exceptions=True,
    )

    return {
        "ip": ip,
        "geoip": geo if not isinstance(geo, Exception) else {"error": str(geo)},
        "virustotal": vt if not isinstance(vt, Exception) else {"error": str(vt)},
        "abuseipdb": abuse if not isinstance(abuse, Exception) else {"error": str(abuse)},
        "greynoise": noise if not isinstance(noise, Exception) else {"error": str(noise)},
    }


@mcp.tool
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

    resolved_cats = categories or [14, 18]
    return await report_ip(ip, resolved_cats, comment)


@mcp.tool
async def analyze_attacker(ip: str) -> dict[str, Any]:
    """Build a full attacker profile for an IP: all honeypot events, token triggers,
    threat intel enrichment, and MITRE ATT&CK technique mapping.

    Args:
        ip: The attacker's IP address.
    """
    import asyncio
    from honeypot_mcp.intel.geoip import lookup_geoip
    from honeypot_mcp.intel.virustotal import lookup_virustotal
    from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb
    from honeypot_mcp.intel.greynoise import lookup_greynoise
    from honeypot_mcp.analysis.profiler import build_profile

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=200, source_ip=ip)
        events = await queries.get_events_for_ip(session, ip, limit=200)

    geo, vt, abuse, noise = await asyncio.gather(
        lookup_geoip(ip),
        lookup_virustotal(ip),
        lookup_abuseipdb(ip),
        lookup_greynoise(ip),
        return_exceptions=True,
    )

    profile = await build_profile(
        ip=ip,
        alerts=alerts,
        events=events,
        geoip=geo if not isinstance(geo, Exception) else {},
        vt=vt if not isinstance(vt, Exception) else {},
        abuse=abuse if not isinstance(abuse, Exception) else {},
        noise=noise if not isinstance(noise, Exception) else {},
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
    format: str = "html",
    limit: int = 500,
) -> str:
    """Generate a comprehensive attack report with timeline, top attackers, and MITRE TTPs.

    Args:
        title: Report title.
        ip: Scope the report to a single attacker IP (omit for all activity).
        format: Output format — html or markdown.
        limit: Maximum number of alerts to include in the analysis.
    """
    from honeypot_mcp.analysis.reporter import generate

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=limit, source_ip=ip)
        stats = await queries.get_alert_stats(session)

    return await generate(
        title=title,
        alerts=alerts,
        stats=stats,
        target_ip=ip,
        format=format,
    )


@mcp.tool
async def threat_timeline(
    ip: str | None = None,
    hours: int = 24,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Get a chronological event timeline for a time range or specific IP.

    Args:
        ip: Filter to a specific attacker IP (omit for all sources).
        hours: How many hours back to look (default 24).
        limit: Maximum events to return.
    """
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select, desc
    from honeypot_mcp.storage.models import Alert

    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    async with get_session() as session:
        q = select(Alert).where(Alert.timestamp >= since)
        if ip:
            q = q.where(Alert.source_ip == ip)
        q = q.order_by(Alert.timestamp).limit(limit)
        result = await session.execute(q)
        alerts = list(result.scalars().all())

    return [
        {
            "timestamp": a.timestamp.isoformat(),
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "honeypot_id": a.honeypot_id,
        }
        for a in alerts
    ]
