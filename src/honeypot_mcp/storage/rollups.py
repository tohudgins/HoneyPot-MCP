"""Hourly alert rollups: statistics whose cost depends on the answer, not on the table.

Writes: `record()` runs in the flusher's transaction and upserts one row per distinct (hour,
severity, event type, source, sensor) in the batch, so a rollup can never disagree with the alerts
stored beside it.

Reads: a window is answered from three pieces, none of which scans the alert table beyond a bounded
edge. Whole hours come from the rollups; the partial hour at the start of the window and the
current (still-filling) hour come from the alert rows by timestamp. The pieces are combined with a
UNION ALL and aggregated in the database, so exactness is kept to the second at the window's edges.
After `alerts_prune` the raw rows are gone but the rollups remain, so lifetime figures stay right.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import event, func, literal_column, select, text, union_all
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session

from honeypot_mcp.storage.models import Alert, AlertRollup

if TYPE_CHECKING:
    from sqlalchemy import Table
    from sqlalchemy.ext.asyncio import AsyncSession

# Rows per INSERT: far under SQLite's bound-parameter limit (6 columns each).
_UPSERT_CHUNK = 100
_installed = False


def hour_floor(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _rows(alerts: list[Alert]) -> list[dict[str, Any]]:
    now = datetime.now(UTC)
    counts: Counter[tuple[datetime, Any, str, str, int]] = Counter()
    for a in alerts:
        counts[
            (
                hour_floor(a.timestamp or now),
                a.severity,
                a.event_type,
                a.source_ip,
                a.honeypot_id or 0,
            )
        ] += 1
    return [
        {
            "bucket": bucket,
            "severity": severity,
            "event_type": event_type,
            "source_ip": source_ip,
            "honeypot_id": honeypot_id,
            "count": n,
        }
        for (bucket, severity, event_type, source_ip, honeypot_id), n in counts.items()
    ]


def _count_new_alerts(session: Session, _flush_context: Any, _instances: Any) -> None:
    """Count every Alert about to be flushed, in the transaction that stores it.

    Hooking the flush, instead of asking each writer to call a helper, is what keeps the rollups
    equal to the alerts by construction: the flusher, the watchdog's disk-full alert, tests and any
    future writer are all covered, and a failed flush rolls the counts back with the rows.
    """
    alerts = [obj for obj in session.new if isinstance(obj, Alert)]
    if not alerts:
        return
    # Plain Core on the table, through the session's own connection: an ORM-enabled INSERT executed
    # from inside a flush goes through the ORM's bulk-persistence path, which is the wrong layer
    # for a statement that must not interact with the unit of work being flushed.
    connection = session.connection()
    insert = postgresql.insert if connection.dialect.name == "postgresql" else sqlite.insert
    table = cast("Table", AlertRollup.__table__)
    rows = _rows(alerts)
    for start in range(0, len(rows), _UPSERT_CHUNK):
        stmt = insert(table).values(rows[start : start + _UPSERT_CHUNK])
        stmt = stmt.on_conflict_do_update(
            index_elements=[
                table.c.bucket,
                table.c.severity,
                table.c.event_type,
                table.c.source_ip,
                table.c.honeypot_id,
            ],
            set_={"count": table.c.count + stmt.excluded.count},
        )
        connection.execute(stmt)


def install() -> None:
    """Register the flush hook once per process (called from `init_db`)."""
    global _installed
    if not _installed:
        event.listen(Session, "before_flush", _count_new_alerts)
        _installed = True


def _raw(lo: datetime | None, hi: datetime | None, ip: str | None):  # type: ignore[no-untyped-def]
    # A literal 0, not a bound parameter: PostgreSQL treats `coalesce(x, $3)` in the SELECT list and
    # `coalesce(x, $5)` in GROUP BY as different expressions and rejects the query, while SQLite
    # accepts it. The same expression object is used for both so they render identically.
    sensor = func.coalesce(Alert.honeypot_id, literal_column("0"))
    q = select(
        Alert.severity.label("severity"),
        Alert.event_type.label("event_type"),
        Alert.source_ip.label("source_ip"),
        sensor.label("honeypot_id"),
        func.count().label("n"),
    ).group_by(Alert.severity, Alert.event_type, Alert.source_ip, sensor)
    if lo is not None:
        q = q.where(Alert.timestamp >= lo)
    if hi is not None:
        q = q.where(Alert.timestamp < hi)
    if ip is not None:
        q = q.where(Alert.source_ip == ip)
    return q


def _rolled(lo: datetime | None, hi: datetime, ip: str | None):  # type: ignore[no-untyped-def]
    q = select(
        AlertRollup.severity.label("severity"),
        AlertRollup.event_type.label("event_type"),
        AlertRollup.source_ip.label("source_ip"),
        AlertRollup.honeypot_id.label("honeypot_id"),
        AlertRollup.count.label("n"),
    ).where(AlertRollup.bucket < hi)
    if lo is not None:
        q = q.where(AlertRollup.bucket >= lo)
    if ip is not None:
        q = q.where(AlertRollup.source_ip == ip)
    return q


def window(since: datetime | None, ip: str | None = None, now: datetime | None = None):  # type: ignore[no-untyped-def]
    """A subquery of (severity, event_type, source_ip, honeypot_id, n) covering `since` to now."""
    now = now or datetime.now(UTC)
    current_hour = hour_floor(now)
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    pieces = []
    if since is None:
        pieces.append(_rolled(None, current_hour, ip))
    else:
        first_whole = hour_floor(since)
        if first_whole < since:
            first_whole += timedelta(hours=1)
        if first_whole >= current_hour:
            # The window lies inside the current hour: raw rows only.
            return union_all(_raw(since, None, ip)).subquery("w")
        if since < first_whole:
            pieces.append(_raw(since, first_whole, ip))
        pieces.append(_rolled(first_whole, current_hour, ip))
    pieces.append(_raw(current_hour, None, ip))
    return union_all(*pieces).subquery("w")


async def stats(
    session: AsyncSession,
    since: datetime | None = None,
    ip: str | None = None,
    top: int = 10,
) -> dict[str, Any]:
    """Totals, unique sources, severity split, top sources and top event types for a window."""
    w = window(since, ip)
    total = (await session.execute(select(func.coalesce(func.sum(w.c.n), 0)))).scalar_one()
    unique = (await session.execute(select(func.count(func.distinct(w.c.source_ip))))).scalar_one()
    severity = (
        await session.execute(select(w.c.severity, func.sum(w.c.n)).group_by(w.c.severity))
    ).all()
    top_ips = (
        await session.execute(
            select(w.c.source_ip, func.sum(w.c.n).label("c"))
            .group_by(w.c.source_ip)
            .order_by(func.sum(w.c.n).desc())
            .limit(top)
        )
    ).all()
    top_types = (
        await session.execute(
            select(w.c.event_type, func.sum(w.c.n).label("c"))
            .group_by(w.c.event_type)
            .order_by(func.sum(w.c.n).desc())
            .limit(top)
        )
    ).all()
    return {
        "total_alerts": int(total),
        "unique_source_ips": int(unique),
        "by_severity": {
            (r[0].value if hasattr(r[0], "value") else str(r[0])): int(r[1]) for r in severity
        },
        "top_source_ips": [{"ip": r[0], "count": int(r[1])} for r in top_ips],
        "top_event_types": [{"type": r[0], "count": int(r[1])} for r in top_types],
    }


async def hit_counts(
    session: AsyncSession, honeypot_ids: list[int] | None = None
) -> dict[int, int]:
    """{honeypot_id: lifetime alert count}; sensors with none are absent."""
    w = window(None)
    q = (
        select(w.c.honeypot_id, func.sum(w.c.n))
        .where(w.c.honeypot_id != 0)
        .group_by(w.c.honeypot_id)
    )
    if honeypot_ids is not None:
        q = q.where(w.c.honeypot_id.in_(honeypot_ids))
    return {int(r[0]): int(r[1]) for r in (await session.execute(q)).all()}


async def acknowledged_by_severity(session: AsyncSession, since: datetime) -> dict[str, int]:
    """Acknowledged alerts in the window, by severity: read from the tiny partial index.

    `untriaged = total - acknowledged`: acknowledgement is a deliberate human act and so is rare,
    which is what makes this count cheap where counting the unacknowledged ones is not.
    """
    rows = (
        await session.execute(
            select(Alert.severity, func.count())
            .where(Alert.acknowledged.is_(True), Alert.timestamp >= since)
            .group_by(Alert.severity)
        )
    ).all()
    return {(r[0].value if hasattr(r[0], "value") else str(r[0])): int(r[1]) for r in rows}


async def honeypot_ids(session: AsyncSession, since: datetime | None, ip: str | None) -> set[int]:
    """The sensors (ids) that recorded anything in the window, for one source or for all."""
    w = window(since, ip)
    rows = await session.execute(select(w.c.honeypot_id).where(w.c.honeypot_id != 0).distinct())
    return {int(r[0]) for r in rows.all()}


async def first_last_seen(
    session: AsyncSession, ip: str
) -> tuple[datetime | None, datetime | None]:
    """Exact first and last time a source was recorded, by index seek (no scan).

    Uses the alert rows while they exist; if they were pruned, falls back to the rollup buckets,
    which are hour-accurate but outlive the raw rows.
    """
    first, last = (
        await session.execute(
            select(func.min(Alert.timestamp), func.max(Alert.timestamp)).where(
                Alert.source_ip == ip
            )
        )
    ).one()
    if first is None:
        first, last = (
            await session.execute(
                select(func.min(AlertRollup.bucket), func.max(AlertRollup.bucket)).where(
                    AlertRollup.source_ip == ip
                )
            )
        ).one()
    return first, last


async def detach_sensor(session: AsyncSession, honeypot_id: int) -> None:
    """Re-file a removed sensor's rollup rows under "no sensor" (id 0), merging counts.

    Removing a sensor sets `alerts.honeypot_id` to NULL; the rollups must follow or they stop
    agreeing with the alerts (per-sensor hit counts, and any statistic keyed by sensor, would keep
    crediting an id that no longer exists). Two set-based statements, constant memory, and the
    upsert merges with rows that already exist under id 0.
    """
    await session.execute(
        text(
            "INSERT INTO alert_rollups (bucket, severity, event_type, source_ip, honeypot_id, count) "
            "SELECT bucket, severity, event_type, source_ip, 0, count FROM alert_rollups "
            "WHERE honeypot_id = :id "
            "ON CONFLICT (bucket, severity, event_type, source_ip, honeypot_id) "
            "DO UPDATE SET count = alert_rollups.count + excluded.count"
        ),
        {"id": honeypot_id},
    )
    await session.execute(
        text("DELETE FROM alert_rollups WHERE honeypot_id = :id"), {"id": honeypot_id}
    )
