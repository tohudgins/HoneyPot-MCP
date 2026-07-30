from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import String, cast, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_mcp.storage.models import (
    Alert,
    AlertDisposition,
    AlertSeverity,
    AttackerEvent,
    AttackerProfile,
    Honeypot,
    HoneypotStatus,
    Honeytoken,
    HoneytokenStatus,
)

# ── Honeypot queries ──────────────────────────────────────────────────────────


async def get_honeypot_by_name(session: AsyncSession, name: str) -> Honeypot | None:
    result = await session.execute(select(Honeypot).where(Honeypot.name == name))
    return result.scalar_one_or_none()


async def get_honeypot_by_id(session: AsyncSession, hp_id: int) -> Honeypot | None:
    return await session.get(Honeypot, hp_id)


async def list_honeypots(
    session: AsyncSession, status: HoneypotStatus | None = None
) -> list[Honeypot]:
    q = select(Honeypot)
    if status:
        q = q.where(Honeypot.status == status)
    result = await session.execute(q.order_by(Honeypot.created_at.desc()))
    return list(result.scalars().all())


async def get_honeypot_hit_count(session: AsyncSession, honeypot_id: int) -> int:
    result = await session.execute(select(func.count()).where(Alert.honeypot_id == honeypot_id))
    return result.scalar_one() or 0


async def get_hit_counts(
    session: AsyncSession, honeypot_ids: list[int] | None = None
) -> dict[int, int]:
    """Bulk hit count by honeypot — single GROUP BY query instead of N round-trips.
    Returns {honeypot_id: count}. Honeypots with zero hits are absent."""
    q = (
        select(Alert.honeypot_id, func.count().label("c"))
        .where(Alert.honeypot_id.is_not(None))
        .group_by(Alert.honeypot_id)
    )
    if honeypot_ids is not None:
        q = q.where(Alert.honeypot_id.in_(honeypot_ids))
    result = await session.execute(q)
    return {row[0]: row[1] for row in result.all()}


# ── Alert queries ─────────────────────────────────────────────────────────────


async def create_alert(session: AsyncSession, **kwargs) -> Alert:
    alert = Alert(**kwargs)
    session.add(alert)
    await session.flush()
    return alert


async def get_recent_alerts(
    session: AsyncSession,
    limit: int = 50,
    source_ip: str | None = None,
    severity: AlertSeverity | None = None,
    honeypot_id: int | None = None,
    event_type: str | None = None,
    since: datetime | None = None,
) -> list[Alert]:
    q = select(Alert)
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    if severity:
        q = q.where(Alert.severity == severity)
    if honeypot_id:
        q = q.where(Alert.honeypot_id == honeypot_id)
    if event_type:
        q = q.where(Alert.event_type == event_type)
    if since is not None:
        q = q.where(Alert.timestamp >= since)
    q = q.order_by(desc(Alert.timestamp)).limit(limit)
    result = await session.execute(q)
    return list(result.scalars().all())


async def get_honeypot_by_port(session: AsyncSession, port: int) -> Honeypot | None:
    """Find a honeypot bound to `port`, preferring a RUNNING one — a stopped
    row on the same port is not a conflict."""
    result = await session.execute(
        select(Honeypot)
        .where(Honeypot.port == port)
        .order_by(desc(Honeypot.status == HoneypotStatus.RUNNING))
    )
    return result.scalars().first()


async def get_honeypot_names(session: AsyncSession) -> dict[int, str]:
    """Map honeypot id → name, so alert rows can name their source without an
    N+1 lookup per row."""
    result = await session.execute(select(Honeypot.id, Honeypot.name))
    return {row[0]: row[1] for row in result.all()}


async def search_alerts(
    session: AsyncSession,
    query: str,
    limit: int = 50,
    since: datetime | None = None,
) -> list[Alert]:
    """Substring search across IP, event type, AND payload contents.
    Payload search uses TEXT cast — works on SQLite (JSON-as-TEXT) and
    Postgres (JSON-cast-to-text). Matches anywhere in the serialised JSON,
    so an analyst can search for commands, usernames, passwords, headers, etc."""
    q = select(Alert).where(
        Alert.source_ip.contains(query)
        | Alert.event_type.contains(query)
        | cast(Alert.payload, String).contains(query)
    )
    if since is not None:
        q = q.where(Alert.timestamp >= since)
    result = await session.execute(q.order_by(desc(Alert.timestamp)).limit(limit))
    return list(result.scalars().all())


async def triage_alerts(
    session: AsyncSession,
    *,
    alert_ids: list[int] | None = None,
    disposition: AlertDisposition | None = None,
    note: str | None = None,
    analyst: str = "mcp-client",
    source_ip: str | None = None,
    event_type: str | None = None,
    severity: AlertSeverity | None = None,
    since: datetime | None = None,
    max_alerts: int = 500,
) -> dict:
    """Acknowledge alerts by id or by filter, recording the triage verdict.

    Selection happens as an explicit SELECT rather than a bare UPDATE…WHERE so
    the caller learns exactly how many alerts matched and whether the safety cap
    truncated the set — an over-broad filter silently clearing thousands of
    alerts is not a recoverable mistake.
    """
    q = select(Alert.id)
    if alert_ids:
        q = q.where(Alert.id.in_(alert_ids))
    if source_ip:
        q = q.where(Alert.source_ip == source_ip)
    if event_type:
        q = q.where(Alert.event_type == event_type)
    if severity:
        q = q.where(Alert.severity == severity)
    if since is not None:
        q = q.where(Alert.timestamp >= since)

    # Fetch one beyond the cap so we can tell "exactly at the limit" from
    # "there is more".
    rows = (await session.execute(q.order_by(desc(Alert.timestamp)).limit(max_alerts + 1))).all()
    matched = [r[0] for r in rows]
    capped = len(matched) > max_alerts
    matched = matched[:max_alerts]

    if not matched:
        return {"acknowledged": 0, "alert_ids": [], "capped": False}

    values: dict = {
        "acknowledged": True,
        "triaged_by": analyst,
        "triaged_at": datetime.now(UTC),
    }
    if disposition is not None:
        values["disposition"] = disposition
    if note is not None:
        values["triage_note"] = note

    await session.execute(update(Alert).where(Alert.id.in_(matched)).values(**values))
    return {
        "acknowledged": len(matched),
        "alert_ids": matched[:50],
        "disposition": disposition.value if disposition else None,
        "analyst": analyst,
        "capped": capped,
    }


async def acknowledge_alert(session: AsyncSession, alert_id: int) -> bool:
    result = await session.execute(
        update(Alert).where(Alert.id == alert_id).values(acknowledged=True)
    )
    # SQLAlchemy's stubs declare execute() → Result, but UPDATE/DELETE results
    # are actually CursorResult which exposes rowcount. The runtime call is
    # correct; mypy needs the hint.
    return result.rowcount > 0  # type: ignore[attr-defined]


async def get_alert_stats(session: AsyncSession, since: datetime | None = None) -> dict:
    def _scoped(q):  # type: ignore[no-untyped-def]
        return q.where(Alert.timestamp >= since) if since is not None else q

    total = await session.execute(_scoped(select(func.count()).select_from(Alert)))
    unique_ips = await session.execute(
        _scoped(select(func.count(func.distinct(Alert.source_ip))).select_from(Alert))
    )
    # Severity breakdown is the first thing an analyst wants — "how bad is it"
    # before "who and what".
    severity_result = await session.execute(
        _scoped(select(Alert.severity, func.count().label("cnt"))).group_by(Alert.severity)
    )
    top_ips_result = await session.execute(
        _scoped(select(Alert.source_ip, func.count().label("cnt")))
        .group_by(Alert.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_types_result = await session.execute(
        _scoped(select(Alert.event_type, func.count().label("cnt")))
        .group_by(Alert.event_type)
        .order_by(desc("cnt"))
        .limit(10)
    )
    return {
        "total_alerts": total.scalar_one(),
        "unique_source_ips": unique_ips.scalar_one(),
        "by_severity": {
            (r[0].value if hasattr(r[0], "value") else str(r[0])): r[1]
            for r in severity_result.all()
        },
        "top_source_ips": [{"ip": r[0], "count": r[1]} for r in top_ips_result.all()],
        "top_event_types": [{"type": r[0], "count": r[1]} for r in top_types_result.all()],
    }


# ── Honeytoken queries ────────────────────────────────────────────────────────


async def get_honeytoken_by_value(session: AsyncSession, value: str) -> Honeytoken | None:
    result = await session.execute(select(Honeytoken).where(Honeytoken.token_value == value))
    return result.scalar_one_or_none()


async def list_honeytokens(
    session: AsyncSession, status: HoneytokenStatus | None = None
) -> list[Honeytoken]:
    q = select(Honeytoken)
    if status:
        q = q.where(Honeytoken.status == status)
    result = await session.execute(q.order_by(desc(Honeytoken.created_at)))
    return list(result.scalars().all())


async def mark_honeytoken_triggered(
    session: AsyncSession, token_id: int, trigger_meta: dict
) -> None:
    await session.execute(
        update(Honeytoken)
        .where(Honeytoken.id == token_id)
        .values(
            status=HoneytokenStatus.TRIGGERED,
            triggered_at=datetime.now(UTC),
            trigger_metadata=trigger_meta,
        )
    )


# ── Attacker profile queries ──────────────────────────────────────────────────


async def get_or_create_profile(session: AsyncSession, ip: str) -> AttackerProfile:
    result = await session.execute(select(AttackerProfile).where(AttackerProfile.ip == ip))
    profile = result.scalar_one_or_none()
    if not profile:
        profile = AttackerProfile(ip=ip)
        session.add(profile)
        await session.flush()
    return profile


async def get_events_for_ip(
    session: AsyncSession, ip: str, limit: int = 200
) -> list[AttackerEvent]:
    result = await session.execute(
        select(AttackerEvent)
        .where(AttackerEvent.ip == ip)
        .order_by(desc(AttackerEvent.timestamp))
        .limit(limit)
    )
    return list(result.scalars().all())


# ── Retention ─────────────────────────────────────────────────────────────────


async def prune_alerts_before(session: AsyncSession, cutoff) -> dict[str, int]:
    """Delete alerts and attacker_events older than `cutoff`. Returns the count
    of rows removed from each table — a SOC analyst can confirm scope before
    re-running."""
    from sqlalchemy import delete

    alert_result = await session.execute(delete(Alert).where(Alert.timestamp < cutoff))
    event_result = await session.execute(
        delete(AttackerEvent).where(AttackerEvent.timestamp < cutoff)
    )
    return {
        "alerts_deleted": alert_result.rowcount or 0,  # type: ignore[attr-defined]
        "attacker_events_deleted": event_result.rowcount or 0,  # type: ignore[attr-defined]
    }


async def get_top_offenders(
    session: AsyncSession, hours: int, min_hits: int
) -> list[tuple[str, int]]:
    """Return [(ip, count), ...] for IPs with at least `min_hits` alerts in
    the last `hours`. Used by export_blocklist."""
    from datetime import datetime, timedelta

    since = datetime.now(UTC) - timedelta(hours=hours)
    result = await session.execute(
        select(Alert.source_ip, func.count().label("c"))
        .where(Alert.timestamp >= since)
        .group_by(Alert.source_ip)
        .having(func.count() >= min_hits)
        .order_by(desc("c"))
    )
    return [(row[0], row[1]) for row in result.all()]


async def serialise_alerts_before(session: AsyncSession, cutoff) -> str:
    """JSON Lines of every alert older than `cutoff`, for archival.

    One JSON object per line rather than one big array: an archive of a busy
    year is large, and JSONL streams into `jq`, Splunk, an S3 upload or a
    `for line in open(...)` loop without loading the whole file. Full payloads
    are kept — the point of an archive is that it is the record of last resort,
    so digesting it the way the list tools do would defeat it.
    """
    import json

    from honeypot_mcp.storage.models import Alert

    rows = (
        (await session.execute(select(Alert).where(Alert.timestamp < cutoff).order_by(Alert.id)))
        .scalars()
        .all()
    )
    return "\n".join(
        json.dumps(
            {
                "id": a.id,
                "honeypot_id": a.honeypot_id,
                "source_ip": a.source_ip,
                "source_port": a.source_port,
                "event_type": a.event_type,
                "severity": a.severity.value,
                "payload": a.payload,
                "acknowledged": a.acknowledged,
                "disposition": a.disposition.value if a.disposition else None,
                "triage_note": a.triage_note,
                "triaged_by": a.triaged_by,
                "triaged_at": a.triaged_at.isoformat() if a.triaged_at else None,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            },
            default=str,
        )
        for a in rows
    )
