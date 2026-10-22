from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import String, cast, desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from honeypot_mcp.storage import rollups
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
    return (await rollups.hit_counts(session, [honeypot_id])).get(honeypot_id, 0)


async def get_hit_counts(
    session: AsyncSession, honeypot_ids: list[int] | None = None
) -> dict[int, int]:
    """Bulk lifetime hit count by honeypot, from the rollups (one small query, no table scan).
    Returns {honeypot_id: count}. Honeypots with zero hits are absent."""
    return await rollups.hit_counts(session, honeypot_ids)


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


# Ids per slice of the alert table a search reads, and how long a search may keep slicing. A
# substring over payload JSON cannot use an index, so a term that matches nothing reads every row:
# 33 s on 17.7M rows. Slicing newest-first stops as soon as enough matches are found and gives up
# with an honest "searched back to <time>" once the budget is spent.
SEARCH_SLICE_IDS = 250_000
SEARCH_SECONDS = 8.0


@dataclass
class AlertSearch:
    alerts: list[Alert] = field(default_factory=list)
    more: bool = False  # more matches exist than were returned
    complete: bool = True  # the whole range was read (False: stopped at the time budget)
    searched_back_to: datetime | None = None  # when incomplete: the oldest time actually read


async def search_alerts(
    session: AsyncSession,
    query: str,
    limit: int = 20,
    since: datetime | None = None,
    seconds: float | None = None,
) -> AlertSearch:
    """Substring search across IP, event type, AND payload contents, newest first.

    Payload search uses a TEXT cast, which works on SQLite (JSON-as-TEXT) and PostgreSQL, so it
    finds commands, usernames, passwords, headers and so on. Read in id slices from the newest
    alert backwards (ids rise with time): it returns once `limit` matches are found, and stops
    at `seconds` (default `SEARCH_SECONDS`) with `complete=False` and how far back it got.
    """
    budget = SEARCH_SECONDS if seconds is None else seconds
    top = (await session.execute(select(func.max(Alert.id)))).scalar_one()
    if top is None:
        return AlertSearch()
    if since is not None:
        # First alert inside the window, by index seek: ids rise with time, so it bounds the scan.
        floor = (
            await session.execute(
                select(Alert.id).where(Alert.timestamp >= since).order_by(Alert.timestamp).limit(1)
            )
        ).scalar_one_or_none()
        if floor is None:
            return AlertSearch()
    else:
        floor = (await session.execute(select(func.min(Alert.id)))).scalar_one()
    match = (
        Alert.source_ip.contains(query, autoescape=True)
        | Alert.event_type.contains(query, autoescape=True)
        | cast(Alert.payload, String).contains(query, autoescape=True)
    )
    if since is not None:
        match = match & (Alert.timestamp >= since)

    out = AlertSearch()
    deadline = time.monotonic() + budget
    high = top + 1
    while high > floor:
        low = max(floor, high - SEARCH_SLICE_IDS)
        rows = (
            await session.execute(
                select(Alert)
                .where(match, Alert.id >= low, Alert.id < high)
                .order_by(desc(Alert.id))
                .limit(limit + 1 - len(out.alerts))
            )
        ).scalars()
        out.alerts.extend(rows)
        if len(out.alerts) > limit:
            out.alerts = out.alerts[:limit]
            out.more = True
            return out
        high = low
        if high > floor and time.monotonic() > deadline:
            out.complete = False
            out.searched_back_to = (
                await session.execute(
                    select(Alert.timestamp).where(Alert.id >= high).order_by(Alert.id).limit(1)
                )
            ).scalar_one_or_none()
            return out
    return out


async def count_alerts(
    session: AsyncSession,
    *,
    since: datetime | None = None,
    now: datetime | None = None,
    source_ip: str | None = None,
    severity: AlertSeverity | None = None,
    honeypot_id: int | None = None,
    event_type: str | None = None,
) -> int:
    """How many alerts match, from the hourly rollups (exact, and a small read however large the
    alert table is). Counts what was recorded, including alerts since pruned from the table."""
    w = rollups.window(since, source_ip, now)
    q = select(func.coalesce(func.sum(w.c.n), 0))
    if severity is not None:
        q = q.where(w.c.severity == severity)
    if honeypot_id is not None:
        q = q.where(w.c.honeypot_id == honeypot_id)
    if event_type:
        q = q.where(w.c.event_type == event_type)
    return int((await session.execute(q)).scalar_one())


async def triage_alerts(
    session: AsyncSession,
    *,
    alert_ids: list[int] | None = None,
    disposition: AlertDisposition | None = None,
    note: str | None = None,
    triaged_by: str = "stdio",
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
    if not alert_ids:
        # A filter selects the untriaged alerts only. Without this, triaging a noisy source twice
        # re-selected the 500 newest matches (already triaged) and overwrote the first analyst's
        # disposition, note and name; and with the cap, a repeat run never reached the older
        # untriaged ones. Naming ids explicitly is the deliberate way to re-triage.
        q = q.where(Alert.acknowledged.is_(False))

    # Fetch one beyond the cap so we can tell "exactly at the limit" from
    # "there is more".
    rows = (await session.execute(q.order_by(desc(Alert.timestamp)).limit(max_alerts + 1))).all()
    matched = [r[0] for r in rows]
    capped = len(matched) > max_alerts
    matched = matched[:max_alerts]

    found = set(matched)
    not_matched = (
        [i for i in dict.fromkeys(alert_ids) if i not in found][:20]
        if alert_ids and not capped
        else []
    )
    if not matched:
        return {
            "acknowledged": 0,
            "alert_ids": [],
            "capped": False,
            **({"not_matched_ids": not_matched} if not_matched else {}),
        }

    values: dict = {
        "acknowledged": True,
        "triaged_by": triaged_by,
        "triaged_at": datetime.now(UTC),
    }
    if disposition is not None:
        values["disposition"] = disposition
    if note is not None:
        values["triage_note"] = note

    await session.execute(update(Alert).where(Alert.id.in_(matched)).values(**values))
    result: dict = {
        "acknowledged": len(matched),
        "alert_ids": matched[:50],
        "disposition": disposition.value if disposition else None,
        "triaged_by": triaged_by,
        "capped": capped,
        **({"not_matched_ids": not_matched} if not_matched else {}),
    }
    return result


async def acknowledge_alert(session: AsyncSession, alert_id: int) -> bool:
    result = await session.execute(
        update(Alert).where(Alert.id == alert_id).values(acknowledged=True)
    )
    # SQLAlchemy's stubs declare execute() → Result, but UPDATE/DELETE results
    # are actually CursorResult which exposes rowcount. The runtime call is
    # correct; mypy needs the hint.
    return result.rowcount > 0  # type: ignore[attr-defined]


async def get_alert_stats(
    session: AsyncSession, since: datetime | None = None, now: datetime | None = None
) -> dict:
    """Totals, unique sources, severity split, top sources and event types for a window.

    Read from the hourly rollups (plus the alert rows for the window's partial edges), so the cost
    follows the number of distinct (hour, kind, source, sensor) combinations, not the number of
    alerts: on the live VPS the same five aggregates over the alert table took 27 s all-time
    and over 100 s for one hour, at 4.9M rows.
    """
    return await rollups.stats(session, since, now=now)


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


# How many trigger records a token keeps in `token_meta["triggers"]`. A scanner
# can hit a planted credential thousands of times; the history is for "has this
# fired more than once, from where, and when" — Alert/AttackerEvent rows hold
# the full record of every hit.
_MAX_TRIGGER_HISTORY = 20
_MAX_TRIGGER_FIELD_CHARS = 256


def _trigger_history_entry(trigger_meta: dict, at: datetime) -> dict:
    """A compact, scalar-only record of one trigger. The full payload is
    deliberately not copied: it can be tens of KB and this list lives in a JSON
    column that is rewritten whole on every trigger."""
    entry: dict = {"at": at.isoformat()}
    for key, value in trigger_meta.items():
        if isinstance(value, str):
            entry[key] = value[:_MAX_TRIGGER_FIELD_CHARS]
        elif value is None or isinstance(value, bool | int | float):
            entry[key] = value
    return entry


async def mark_honeytoken_triggered(
    session: AsyncSession, token_id: int, trigger_meta: dict
) -> None:
    """Record a trigger on a token.

    `triggered_at` / `trigger_metadata` keep meaning "the latest trigger", as
    they always have. On top of that the trigger is appended to
    `token_meta["triggers"]` (newest last, capped at `_MAX_TRIGGER_HISTORY`), so
    a second hit no longer erases the first. A REVOKED token keeps its status —
    flipping it to TRIGGERED would re-arm a token the operator retired.
    """
    row = (
        await session.execute(
            select(Honeytoken.status, Honeytoken.token_meta).where(Honeytoken.id == token_id)
        )
    ).first()
    if row is None:
        return
    status, meta = row

    now = datetime.now(UTC)
    new_meta = dict(meta or {})
    history = new_meta.get("triggers")
    history = list(history) if isinstance(history, list) else []
    history.append(_trigger_history_entry(trigger_meta, now))
    new_meta["triggers"] = history[-_MAX_TRIGGER_HISTORY:]

    values: dict = {
        "triggered_at": now,
        "trigger_metadata": trigger_meta,
        "token_meta": new_meta,
    }
    if status is not HoneytokenStatus.REVOKED:
        values["status"] = HoneytokenStatus.TRIGGERED
    await session.execute(update(Honeytoken).where(Honeytoken.id == token_id).values(**values))


# ── Attacker profile queries ──────────────────────────────────────────────────


async def get_or_create_profile(session: AsyncSession, ip: str) -> AttackerProfile:
    result = await session.execute(select(AttackerProfile).where(AttackerProfile.ip == ip))
    profile = result.scalar_one_or_none()
    if not profile:
        profile = AttackerProfile(ip=ip)
        session.add(profile)
        await session.flush()
    return profile


# ── Retention ─────────────────────────────────────────────────────────────────

# Rows per archive read / per delete transaction. Small enough that a chunk's
# write lock is released well inside SQLite's busy_timeout, large enough that a
# year of alerts does not take a year.
RETENTION_CHUNK_ROWS = 2000


async def delete_alerts_chunk(
    session: AsyncSession,
    cutoff,
    *,
    limit: int = RETENTION_CHUNK_ROWS,
    max_id: int | None = None,
) -> int:
    """Delete at most `limit` alerts older than `cutoff` (oldest ids first) and
    return how many went. `max_id` confines the delete to rows at or below an id
    — the retention sweep passes the last id it archived, so a row that landed
    after the archive was read can never be deleted unarchived."""
    from sqlalchemy import delete

    q = select(Alert.id).where(Alert.timestamp < cutoff)
    if max_id is not None:
        q = q.where(Alert.id <= max_id)
    ids = [r[0] for r in (await session.execute(q.order_by(Alert.id).limit(limit))).all()]
    if not ids:
        return 0
    result = await session.execute(delete(Alert).where(Alert.id.in_(ids)))
    return result.rowcount or 0  # type: ignore[attr-defined]


async def delete_attacker_events_chunk(
    session: AsyncSession, cutoff, *, limit: int = RETENTION_CHUNK_ROWS
) -> int:
    """Delete at most `limit` attacker_events older than `cutoff`."""
    from sqlalchemy import delete

    ids = [
        r[0]
        for r in (
            await session.execute(
                select(AttackerEvent.id)
                .where(AttackerEvent.timestamp < cutoff)
                .order_by(AttackerEvent.id)
                .limit(limit)
            )
        ).all()
    ]
    if not ids:
        return 0
    result = await session.execute(delete(AttackerEvent).where(AttackerEvent.id.in_(ids)))
    return result.rowcount or 0  # type: ignore[attr-defined]


async def get_top_offenders(
    session: AsyncSession,
    hours: int,
    min_hits: int,
    *,
    exclude_udp_only: bool = False,
    global_only: bool = False,
    now: datetime | None = None,
) -> list[tuple[str, int]]:
    """Return [(ip, count), ...] for IPs with at least `min_hits` alerts in
    the last `hours` (ending at `now`, default the wall clock). Used by export_blocklist and the blocklist pushes.

    The result feeds firewalls, so two optional filters guard against blocking
    the wrong thing (both default off, preserving the plain behaviour):

    * `global_only` drops anything that is not a globally routable IP —
      unparsable strings, RFC1918, loopback, link-local, CGNAT, reserved. A
      private address in a blocklist is at best noise and at worst the
      operator's own gateway.
    * `exclude_udp_only` drops sources whose every alert in the window came from
      a UDP honeypot (DNS/SNMP/SIP). UDP source addresses are trivially
      spoofed, so blocking them lets an attacker get a victim blocked by
      sending forged packets at the sensor. A source that also hit anything
      non-UDP (or an alert with no honeypot, like a canary callback) is kept.
    """
    from datetime import timedelta

    now = now or datetime.now(UTC)
    since = now - timedelta(hours=hours)
    w = rollups.window(since, now=now)
    result = await session.execute(
        select(w.c.source_ip, func.sum(w.c.n).label("c"))
        .group_by(w.c.source_ip)
        .having(func.sum(w.c.n) >= min_hits)
        .order_by(desc("c"))
    )
    offenders = [(row[0], int(row[1])) for row in result.all()]

    if global_only:
        import ipaddress

        def _is_global(ip: str) -> bool:
            try:
                return ipaddress.ip_address(ip).is_global
            except (ValueError, TypeError):
                return False

        offenders = [(ip, n) for ip, n in offenders if _is_global(ip)]

    if exclude_udp_only and offenders:
        from honeypot_mcp.deception.capabilities import source_is_spoofable

        candidates = {ip for ip, _ in offenders}
        w = rollups.window(since, now=now)
        rows = (
            await session.execute(
                select(w.c.source_ip, Honeypot.type)
                .select_from(w)
                .outerjoin(Honeypot, w.c.honeypot_id == Honeypot.id)
                .group_by(w.c.source_ip, Honeypot.type)
            )
        ).all()
        has_non_udp: set[str] = set()
        for ip, hp_type in rows:
            if ip not in candidates or ip in has_non_udp:
                continue
            type_value = getattr(hp_type, "value", hp_type)
            if type_value is None or not source_is_spoofable(str(type_value)):
                has_non_udp.add(ip)
        offenders = [(ip, n) for ip, n in offenders if ip in has_non_udp]

    return offenders


def _alert_json_line(a: Alert) -> str:
    import json

    return json.dumps(
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


async def iter_alert_archive_chunks(
    session: AsyncSession, cutoff, *, chunk_rows: int = RETENTION_CHUNK_ROWS
) -> AsyncIterator[tuple[list[str], int]]:
    """Yield `(json_lines, last_alert_id)` for alerts older than `cutoff`, in id
    order, `chunk_rows` at a time (keyset pagination on the primary key).

    Shared by the manual `alerts_prune` tool and the unattended retention sweep
    (`retention.archive_alerts`): memory stays flat however large the archive is, and the caller
    learns the highest id it has seen so a following delete can be confined to exactly what was
    archived.
    """
    last_id = 0
    while True:
        rows = (
            (
                await session.execute(
                    select(Alert)
                    .where(Alert.timestamp < cutoff, Alert.id > last_id)
                    .order_by(Alert.id)
                    .limit(chunk_rows)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return
        last_id = rows[-1].id
        lines = [_alert_json_line(a) for a in rows]
        # Read-only session: drop the ORM objects so the identity map does not
        # grow with the archive.
        session.expunge_all()
        yield lines, last_id
