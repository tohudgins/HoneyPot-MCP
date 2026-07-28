"""Alert and monitoring MCP tools."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import AlertSeverity
from honeypot_mcp.tools._format import digest_payload, truncate_payload


@mcp.tool
async def alerts_recent(
    limit: int = 25,
    since_hours: float | None = None,
    source_ip: str | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    honeypot_name: str | None = None,
    event_type: str | None = None,
    include_payload: bool = False,
) -> dict[str, Any]:
    """Triage recent honeypot alerts, newest first.

    The primary triage tool. Each alert comes back with a compact `digest` of
    the fields that matter for triage — credentials tried, path requested,
    command run, exploit category matched, country/ASN — rather than the full
    capture. Use `alerts_get(alert_id)` to pull everything on one alert, or
    `alerts_search` to find alerts by payload content.

    Args:
        limit: Maximum alerts to return (default 25, max 200).
        since_hours: Only alerts from the last N hours (e.g. 1 for "the last
              hour", 24 for "today"). Omit for no time limit.
        source_ip: Filter to one attacker IP.
        severity: Filter by severity — low, medium, high, or critical.
        honeypot_name: Filter to alerts from one honeypot.
        event_type: Filter by exact event type (e.g. ssh_login_failed).
        include_payload: Return each alert's complete captured payload instead
              of the digest. Off by default because honeypot payloads carry
              full request headers and up to 64 KB of body per alert — enabling
              this on a large limit returns megabytes.
    """
    limit = max(1, min(limit, 200))
    sev = AlertSeverity(severity) if severity else None

    honeypot_id: int | None = None
    if honeypot_name:
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, honeypot_name)
            if not hp:
                return {"error": f"No honeypot named '{honeypot_name}' found."}
            honeypot_id = hp.id

    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(
            session,
            limit=limit,
            source_ip=source_ip,
            severity=sev,
            honeypot_id=honeypot_id,
            event_type=event_type,
            since=since,
        )
        names = await queries.get_honeypot_names(session)

    rows: list[dict[str, Any]] = []
    for a in alerts:
        row: dict[str, Any] = {
            "id": a.id,
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "honeypot": names.get(a.honeypot_id) if a.honeypot_id else None,
            "timestamp": a.timestamp.isoformat(),
        }
        if a.acknowledged:
            row["acknowledged"] = True
        if include_payload:
            row["payload"] = truncate_payload(a.payload)
        elif digest := digest_payload(a.payload):
            row["digest"] = digest
        rows.append(row)

    result: dict[str, Any] = {"count": len(rows), "alerts": rows}
    if since is not None:
        result["window"] = f"last {since_hours}h (since {since.isoformat()})"
    if len(rows) == limit:
        result["note"] = (
            f"Hit the limit of {limit} — there may be more. Narrow with "
            f"since_hours/severity/source_ip, or raise limit (max 200)."
        )
    return result


@mcp.tool
async def alerts_get(alert_id: int) -> dict[str, Any]:
    """Get the complete captured payload for one alert.

    The drill-down companion to `alerts_recent` — returns everything the engine
    captured (full request headers, decoded bodies, command input, enrichment),
    with only individually oversized values clipped.

    Args:
        alert_id: The numeric alert ID, as returned by alerts_recent or alerts_search.
    """
    from sqlalchemy import select

    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": f"No alert with id={alert_id}."}
        names = await queries.get_honeypot_names(session)

        return {
            "id": alert.id,
            "honeypot": names.get(alert.honeypot_id) if alert.honeypot_id else None,
            "honeypot_id": alert.honeypot_id,
            "source_ip": alert.source_ip,
            "source_port": alert.source_port,
            "event_type": alert.event_type,
            "severity": alert.severity.value,
            "payload": truncate_payload(alert.payload),
            "acknowledged": alert.acknowledged,
            "timestamp": alert.timestamp.isoformat(),
        }


@mcp.tool
async def alerts_search(
    query: str,
    limit: int = 50,
    since_hours: float | None = None,
) -> dict[str, Any]:
    """Search alerts by content — including inside captured payloads.

    Substring-matches the attacker IP, the event type, AND the serialised
    payload, so this finds alerts by what the attacker actually sent: a
    command (`wget`), a username (`root`), a URL path (`/.env`), a
    User-Agent, an uploaded filename, or a hash. Use this when you know what
    you're looking for; use `alerts_recent` to browse by time and severity.

    Args:
        query: Substring to look for anywhere in the IP, event type, or payload.
        limit: Maximum results (default 50, max 200).
        since_hours: Only search alerts from the last N hours. Omit for all time.
    """
    limit = max(1, min(limit, 200))
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        alerts = await queries.search_alerts(session, query=query, limit=limit, since=since)
        names = await queries.get_honeypot_names(session)

    rows = [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "honeypot": names.get(a.honeypot_id) if a.honeypot_id else None,
            "timestamp": a.timestamp.isoformat(),
            **({"digest": d} if (d := digest_payload(a.payload)) else {}),
        }
        for a in alerts
    ]
    result: dict[str, Any] = {"query": query, "count": len(rows), "alerts": rows}
    if not rows:
        result["note"] = (
            "No matches. The search is a literal substring match — try a shorter "
            "or more distinctive fragment."
        )
    return result


@mcp.tool
async def alerts_stats(since_hours: float | None = None) -> dict[str, Any]:
    """Aggregate alert statistics: totals by severity, top attacker IPs, top event types.

    The fastest way to answer "what's the current picture?" without pulling
    individual alerts.

    Args:
        since_hours: Restrict the stats to the last N hours (e.g. 24 for today's
              activity). Omit for all-time totals.
    """
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        stats = await queries.get_alert_stats(session, since=since)
    if since is not None:
        stats["window"] = f"last {since_hours}h (since {since.isoformat()})"
    return stats


@mcp.tool
async def alerts_acknowledge(alert_id: int) -> dict[str, Any]:
    """Mark an alert as reviewed/acknowledged.

    Args:
        alert_id: The alert ID to acknowledge.
    """
    async with get_session() as session:
        updated = await queries.acknowledge_alert(session, alert_id)
    if not updated:
        return {"error": f"No alert with id={alert_id}."}
    return {"alert_id": alert_id, "acknowledged": True}


@mcp.tool
async def alerts_prune(older_than_days: int = 90) -> dict[str, Any]:
    """Delete alerts and attacker_events older than the cutoff. Useful for
    keeping the DB bounded — by default retains the last 90 days.

    Args:
        older_than_days: Cutoff age in days (default 90).
    """
    from datetime import datetime, timedelta

    if older_than_days < 1:
        return {"error": "older_than_days must be at least 1 to avoid deleting current data."}

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    async with get_session() as session:
        result = await queries.prune_alerts_before(session, cutoff)
    return {
        "older_than_days": older_than_days,
        "cutoff": cutoff.isoformat(),
        **result,
    }


@mcp.tool
async def alerts_export(
    format: Literal["json", "csv"] = "json",
    limit: int = 1000,
    since_hours: float | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Export full alert records to a file for SIEM ingestion or offline analysis.

    Writes to disk and returns the path plus a preview — exports include
    complete payloads, so returning the content inline would flood the
    conversation (5,000 alerts of real HTTP capture is tens of megabytes).
    For reading alerts in conversation use `alerts_recent` or `alerts_search`.

    Args:
        format: Output format — json or csv.
        limit: Maximum alerts to export (default 1000, max 50000).
        since_hours: Only export alerts from the last N hours. Omit for all.
        severity: Only export alerts at this severity.
        output_path: Where to write. Defaults to
              `reports/alerts-<timestamp>.<format>` under the project root.
    """
    from pathlib import Path

    from honeypot_mcp.config import get_settings

    limit = max(1, min(limit, 50_000))
    sev = AlertSeverity(severity) if severity else None
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=limit, severity=sev, since=since)

    rows = [
        {
            "id": a.id,
            "honeypot_id": a.honeypot_id,
            "source_ip": a.source_ip,
            "source_port": a.source_port,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "acknowledged": a.acknowledged,
            "timestamp": a.timestamp.isoformat(),
            "payload": json.dumps(a.payload),
        }
        for a in alerts
    ]

    if format == "json":
        content = json.dumps(rows, indent=2)
    else:
        buf = io.StringIO()
        if rows:
            writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        content = buf.getvalue()

    if output_path:
        dest = Path(output_path).expanduser()
    else:
        settings = get_settings()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = settings.reports_dir / f"alerts-{stamp}.{format}"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    except OSError as e:
        return {"error": f"Could not write export to {dest}: {e}"}

    return {
        "path": str(dest),
        "format": format,
        "alerts_exported": len(rows),
        "bytes": len(content.encode("utf-8")),
        "preview": [
            {k: r[k] for k in ("id", "source_ip", "event_type", "severity", "timestamp")}
            for r in rows[:5]
        ],
    }
