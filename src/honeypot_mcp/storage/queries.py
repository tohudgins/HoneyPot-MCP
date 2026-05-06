from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_mcp.storage.models import (
    Alert,
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


async def list_honeypots(session: AsyncSession, status: HoneypotStatus | None = None) -> list[Honeypot]:
    q = select(Honeypot)
    if status:
        q = q.where(Honeypot.status == status)
    result = await session.execute(q.order_by(Honeypot.created_at.desc()))
    return list(result.scalars().all())


async def get_honeypot_hit_count(session: AsyncSession, honeypot_id: int) -> int:
    result = await session.execute(
        select(func.count()).where(Alert.honeypot_id == honeypot_id)
    )
    return result.scalar_one() or 0


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
    q = q.order_by(desc(Alert.timestamp)).limit(limit)
    result = await session.execute(q)
    return list(result.scalars().all())


async def search_alerts(session: AsyncSession, query: str, limit: int = 50) -> list[Alert]:
    result = await session.execute(
        select(Alert)
        .where(Alert.source_ip.contains(query) | Alert.event_type.contains(query))
        .order_by(desc(Alert.timestamp))
        .limit(limit)
    )
    return list(result.scalars().all())


async def acknowledge_alert(session: AsyncSession, alert_id: int) -> bool:
    result = await session.execute(
        update(Alert).where(Alert.id == alert_id).values(acknowledged=True)
    )
    return result.rowcount > 0


async def get_alert_stats(session: AsyncSession) -> dict:
    total = await session.execute(select(func.count()).select_from(Alert))
    top_ips_result = await session.execute(
        select(Alert.source_ip, func.count().label("cnt"))
        .group_by(Alert.source_ip)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_types_result = await session.execute(
        select(Alert.event_type, func.count().label("cnt"))
        .group_by(Alert.event_type)
        .order_by(desc("cnt"))
        .limit(10)
    )
    return {
        "total_alerts": total.scalar_one(),
        "top_source_ips": [{"ip": r[0], "count": r[1]} for r in top_ips_result.all()],
        "top_event_types": [{"type": r[0], "count": r[1]} for r in top_types_result.all()],
    }


# ── Honeytoken queries ────────────────────────────────────────────────────────

async def get_honeytoken_by_value(session: AsyncSession, value: str) -> Honeytoken | None:
    result = await session.execute(
        select(Honeytoken).where(Honeytoken.token_value == value)
    )
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
            triggered_at=datetime.now(timezone.utc),
            trigger_metadata=trigger_meta,
        )
    )


# ── Attacker profile queries ──────────────────────────────────────────────────

async def get_or_create_profile(session: AsyncSession, ip: str) -> AttackerProfile:
    result = await session.execute(
        select(AttackerProfile).where(AttackerProfile.ip == ip)
    )
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
