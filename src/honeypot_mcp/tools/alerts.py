"""Alert and monitoring MCP tools."""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Literal

from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import AlertSeverity


@mcp.tool
async def alerts_recent(
    limit: int = 25,
    source_ip: str | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    honeypot_name: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    """Get recent alerts from all honeypots.

    Args:
        limit: Maximum number of alerts to return (default 25, max 200).
        source_ip: Filter to a specific attacker IP address.
        severity: Filter by severity level (low, medium, high, critical).
        honeypot_name: Filter to alerts from a specific honeypot.
        event_type: Filter by event type (e.g. login_attempt, port_scan).
    """
    limit = min(limit, 200)
    sev = AlertSeverity(severity) if severity else None

    honeypot_id: int | None = None
    if honeypot_name:
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, honeypot_name)
            if not hp:
                return [{"error": f"No honeypot named '{honeypot_name}' found."}]
            honeypot_id = hp.id

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(
            session,
            limit=limit,
            source_ip=source_ip,
            severity=sev,
            honeypot_id=honeypot_id,
            event_type=event_type,
        )

    return [
        {
            "id": a.id,
            "honeypot_id": a.honeypot_id,
            "source_ip": a.source_ip,
            "source_port": a.source_port,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "payload": a.payload,
            "acknowledged": a.acknowledged,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in alerts
    ]


@mcp.tool
async def alerts_get(alert_id: int) -> dict[str, Any]:
    """Get full details for a specific alert by ID.

    Args:
        alert_id: The numeric alert ID.
    """
    from sqlalchemy import select
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.id == alert_id))
        alert = result.scalar_one_or_none()
        if not alert:
            return {"error": f"No alert with id={alert_id}."}

        return {
            "id": alert.id,
            "honeypot_id": alert.honeypot_id,
            "source_ip": alert.source_ip,
            "source_port": alert.source_port,
            "event_type": alert.event_type,
            "severity": alert.severity.value,
            "payload": alert.payload,
            "acknowledged": alert.acknowledged,
            "timestamp": alert.timestamp.isoformat(),
        }


@mcp.tool
async def alerts_search(query: str, limit: int = 50) -> list[dict[str, Any]]:
    """Full-text search across alerts (matches IP addresses and event types).

    Args:
        query: Search string — matched against source_ip and event_type.
        limit: Maximum results to return (default 50).
    """
    async with get_session() as session:
        alerts = await queries.search_alerts(session, query=query, limit=min(limit, 200))

    return [
        {
            "id": a.id,
            "source_ip": a.source_ip,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "timestamp": a.timestamp.isoformat(),
        }
        for a in alerts
    ]


@mcp.tool
async def alerts_stats() -> dict[str, Any]:
    """Get aggregated alert statistics: total count, top attacker IPs, top event types."""
    async with get_session() as session:
        return await queries.get_alert_stats(session)


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
async def alerts_export(
    format: Literal["json", "csv"] = "json",
    limit: int = 1000,
) -> str:
    """Export alerts as JSON or CSV for SIEM ingestion or reporting.

    Args:
        format: Output format — json or csv.
        limit: Maximum number of alerts to export.
    """
    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=min(limit, 5000))

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
        return json.dumps(rows, indent=2)

    buf = io.StringIO()
    if rows:
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return buf.getvalue()
