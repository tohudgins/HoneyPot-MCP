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
from honeypot_mcp.storage.models import AlertDisposition, AlertSeverity
from honeypot_mcp.tools._audit import record_action
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
            # Surfacing the verdict here is what lets a shift skip what the
            # previous one already resolved.
            if a.disposition is not None:
                row["disposition"] = a.disposition.value
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
            "disposition": alert.disposition.value if alert.disposition else None,
            "triage_note": alert.triage_note,
            "triaged_by": alert.triaged_by,
            "triaged_at": alert.triaged_at.isoformat() if alert.triaged_at else None,
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
async def alerts_acknowledge(
    alert_ids: list[int] | None = None,
    disposition: Literal["true_positive", "false_positive", "benign", "duplicate"] | None = None,
    note: str | None = None,
    analyst: str | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    since_hours: float | None = None,
    max_alerts: int = 500,
) -> dict[str, Any]:
    """Triage alerts — acknowledge them, individually or in bulk, with a verdict.

    Either pass explicit `alert_ids`, or describe a set with the filters and
    every matching alert is triaged at once ("mark today's Shodan scanner hits
    as benign"). One-at-a-time acknowledgement does not survive contact with a
    scanner sweep, which produces hundreds of alerts in minutes.

    Recording a `disposition` is what makes triage useful later: it separates
    "nobody has looked at this" from "we looked and it was nothing", and lets
    you ask what is being dismissed and whether it should be suppressed instead.

    Args:
        alert_ids: Explicit alert IDs to triage. Omit to use the filters below.
        disposition: The verdict — `true_positive` (a real attack),
              `false_positive` (the detection was wrong), `benign` (fired
              correctly on authorised activity, e.g. your own pentest), or
              `duplicate`.
        note: Why. Free text, shown to whoever reviews this later.
        analyst: Who triaged it. Defaults to "mcp-client".
        source_ip: Triage every alert from this IP (filter mode).
        event_type: Triage every alert of this exact event type (filter mode).
        severity: Triage every alert at this severity (filter mode).
        since_hours: Restrict the filters to the last N hours.
        max_alerts: Safety cap on how many a single filtered call may triage
              (default 500). Prevents an over-broad filter clearing the board.
    """
    has_filters = any((source_ip, event_type, severity, since_hours is not None))
    if not alert_ids and not has_filters:
        return {
            "error": (
                "Nothing selected. Pass alert_ids, or at least one of "
                "source_ip / event_type / severity / since_hours."
            )
        }

    disp = AlertDisposition(disposition) if disposition else None
    sev = AlertSeverity(severity) if severity else None
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    async with get_session() as session:
        result = await queries.triage_alerts(
            session,
            alert_ids=alert_ids,
            disposition=disp,
            note=note,
            analyst=analyst or "mcp-client",
            source_ip=source_ip,
            event_type=event_type,
            severity=sev,
            since=since,
            max_alerts=max(1, min(max_alerts, 10_000)),
        )

    await record_action(
        "alerts_acknowledge",
        summary=(
            f"triaged {result['acknowledged']} alert(s)"
            + (f" as {disposition}" if disposition else "")
        ),
        arguments={
            "alert_ids": alert_ids,
            "disposition": disposition,
            "source_ip": source_ip,
            "event_type": event_type,
            "severity": severity,
            "since_hours": since_hours,
        },
        target=source_ip,
    )

    if result["acknowledged"] == 0:
        result["note"] = "No alerts matched — nothing was changed."
    elif result.get("capped"):
        result["note"] = (
            f"Stopped at max_alerts={max_alerts}; more alerts still match. "
            f"Re-run to continue, or narrow the filters."
        )
    return result


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
    await record_action(
        "alerts_prune",
        summary=(
            f"deleted {result.get('alerts_deleted', 0)} alert(s) and "
            f"{result.get('events_deleted', 0)} event(s) older than {older_than_days}d"
        ),
        arguments={"older_than_days": older_than_days, "cutoff": cutoff.isoformat()},
    )
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


@mcp.tool
async def audit_log_search(
    tool: str | None = None,
    target: str | None = None,
    since_hours: float | None = None,
    outcome: Literal["ok", "error"] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Review what the control plane did — every honeypot deployed or stopped,
    every prune, every token revoked.

    This server's control plane is driven by a language model, so "what did the
    agent actually do, and when?" is a question you will eventually need
    answered — after an unexpected gap in collection, or when alerts you
    expected to find have been pruned. The log is append-only and is not
    touched by the retention sweep.

    Args:
        tool: Filter to one tool name (e.g. alerts_prune, honeypot_stop).
        target: Filter to what was acted on — a honeypot name, IP, or token id.
        since_hours: Only actions from the last N hours.
        outcome: Filter to successful (`ok`) or failed (`error`) actions.
        limit: Maximum entries to return (default 50, max 500).
    """
    from sqlalchemy import desc, select

    from honeypot_mcp.storage.models import AuditLog

    limit = max(1, min(limit, 500))
    since = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0."}
        since = datetime.now(UTC) - timedelta(hours=since_hours)

    q = select(AuditLog)
    if tool:
        q = q.where(AuditLog.tool == tool)
    if target:
        q = q.where(AuditLog.target == target)
    if outcome:
        q = q.where(AuditLog.outcome == outcome)
    if since is not None:
        q = q.where(AuditLog.timestamp >= since)

    async with get_session() as session:
        rows = (
            (await session.execute(q.order_by(desc(AuditLog.timestamp)).limit(limit)))
            .scalars()
            .all()
        )

    entries = [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "tool": r.tool,
            "summary": r.summary,
            "target": r.target,
            "outcome": r.outcome,
            **({"error": r.error} if r.error else {}),
            **({"arguments": r.arguments} if r.arguments else {}),
        }
        for r in rows
    ]
    result: dict[str, Any] = {"count": len(entries), "actions": entries}
    if not entries:
        result["note"] = (
            "No matching control-plane actions. Note that auditing records "
            "state-changing calls only — reads like alerts_recent are not logged."
        )
    return result
