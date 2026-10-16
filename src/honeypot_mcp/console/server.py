"""Console HTTP server: one HTML page plus the JSON feed it polls."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aiohttp import web
from sqlalchemy import BigInteger, Integer, and_, cast, desc, func, literal_column, select, text

from honeypot_mcp.config import get_settings
from honeypot_mcp.http_identity import identity_runner, server_identity_middleware
from honeypot_mcp.storage import rollups
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    Alert,
    AlertRollup,
    AlertSeverity,
    Honeypot,
    HoneypotStatus,
    Honeytoken,
    HoneytokenStatus,
)
from honeypot_mcp.tools._format import digest_payload

log = logging.getLogger(__name__)

_STATIC = Path(__file__).parent / "static"
_CONSOLE_BANNER = "HoneyPot MCP Console"

# Severities that an analyst is expected to act on, as opposed to the
# background radiation a public IP collects continuously.
_SERIOUS = (AlertSeverity.HIGH, AlertSeverity.CRITICAL)


def _bucket_size(hours: float) -> timedelta:
    """Pick a bucket that yields roughly 12-48 columns for any window.

    The tiers are chosen for cost as well as looks. Sub-hour columns cannot come from the hourly
    rollups, so they scan raw alerts: that is bounded here to windows of two hours or less (about
    300k rows at the heaviest rate seen, 1.3 s on the droplet). Everything longer reads the rollups,
    whose cost does not depend on how many alerts there are. A 30-minute tier for windows up to 12 h
    used to sit in between and scanned about a million rows every 5 s (6.7 s per poll on the droplet)."""
    if hours <= 2:
        return timedelta(minutes=5)
    if hours <= 48:
        return timedelta(hours=1)
    return timedelta(hours=6)


# Rows the feed actually shows. The query is LIMITed to this, so a busy window
# never loads more than this many payloads per poll.
_FEED_ROWS = 40


def _country_expr() -> Any:
    """`payload.enrichment.geoip.country` as a SQL expression (json_extract on
    SQLite, `#>>` on PostgreSQL) so geography is grouped in the database
    instead of by loading every payload in the window."""
    return Alert.payload[("enrichment", "geoip", "country")].as_string()


def _bucket_starts(start: datetime, now: datetime, bucket: timedelta) -> list[datetime]:
    """The bucket boundaries covering `start`..`now`.

    Sub-hour buckets run from `start` (the window is short, so exactness at the left edge matters).
    Hour-and-longer buckets are aligned to the clock (whole hours, or 6-hour blocks), because they are
    read from the hourly rollups: a bucket then is a sum of whole rollup rows, and the chart's columns
    do not shift every time the page polls."""
    if bucket < timedelta(hours=1):
        first = start
    else:
        first = rollups.hour_floor(start)
        step = int(bucket.total_seconds() // 3600)
        first -= timedelta(hours=first.hour % step)
    out = [first]
    while out[-1] + bucket <= now:
        out.append(out[-1] + bucket)
    return out


def _epoch(column: Any, dialect: str) -> Any:
    if dialect == "sqlite":
        return cast(func.strftime("%s", column), Integer)
    return cast(func.extract("epoch", column), BigInteger)


async def _series(
    session: Any, start: datetime, now: datetime, bucket: timedelta, ordered: list[datetime]
) -> dict[int, dict[str, int]]:
    """{bucket index: {"routine": n, "serious": n}} for the chart.

    Short windows (buckets under an hour, so windows up to 12 h) group the raw alerts in SQL by integer
    arithmetic on the timestamp: one pass, where the old 48-branch CASE was evaluated per row. Longer
    windows sum the hourly rollups for whole hours and read raw rows only for the two partial edge
    hours (the same definition `rollups.window` uses), so the chart's total equals the headline count
    and the cost does not grow with the size of the run."""
    counts: dict[int, dict[str, int]] = {}
    serious = {s.value for s in _SERIOUS}

    def add(idx: int, severity: Any, n: int) -> None:
        if 0 <= idx < len(ordered):
            key = "serious" if _enum_value(severity) in serious else "routine"
            counts.setdefault(idx, {"routine": 0, "serious": 0})[key] += int(n)

    if bucket < timedelta(hours=1):
        dialect = session.bind.dialect.name
        # Literal integers, not bound parameters: PostgreSQL rejects a GROUP BY expression that renders
        # with different placeholders than the SELECT list.
        index = (
            _epoch(Alert.timestamp, dialect) - literal_column(str(int(start.timestamp())))
        ) // literal_column(str(int(bucket.total_seconds())))
        rows = (
            select(index.label("b"), Alert.severity.label("s")).where(Alert.timestamp >= start)
        ).subquery()
        for idx, severity, n in (
            await session.execute(
                select(rows.c.b, rows.c.s, func.count()).group_by(rows.c.b, rows.c.s)
            )
        ).all():
            if idx is not None:
                add(int(idx), severity, n)
        return counts

    def slot(moment: datetime) -> int:
        return int((rollups.hour_floor(moment) - ordered[0]) // bucket)

    first_whole = rollups.hour_floor(start)
    if first_whole < start:
        first_whole += timedelta(hours=1)
    current_hour = rollups.hour_floor(now)
    rolled = (
        select(AlertRollup.bucket, AlertRollup.severity, func.sum(AlertRollup.count))
        .where(AlertRollup.bucket >= first_whole, AlertRollup.bucket < current_hour)
        .group_by(AlertRollup.bucket, AlertRollup.severity)
    )
    for hour, severity, n in (await session.execute(rolled)).all():
        hour = hour if hour.tzinfo else hour.replace(tzinfo=UTC)
        add(slot(hour), severity, n)
    for lo, hi in ((start, first_whole), (current_hour, None)):
        if hi is not None and lo >= hi:
            continue
        edge = (
            select(Alert.severity, func.count())
            .where(Alert.timestamp >= lo)
            .group_by(Alert.severity)
        )
        if hi is not None:
            edge = edge.where(Alert.timestamp < hi)
        for severity, n in (await session.execute(edge)).all():
            add(slot(lo), severity, n)
    return counts


def _critical_rows(start: datetime) -> Any:
    """(source_ip, country, ts) for CRITICAL alerts since `start`, as a subquery.

    Geography: enrichment (GeoIP) is attached to CRITICAL alerts only (event_buffer enriches exactly
    those), so scanning every alert's JSON for a country only ever found these rows.

    The `IN ('critical', 'high')` term is not redundant: it is the predicate of the partial index
    `ix_alerts_urgent`, and SQLite only uses a partial index when the query states the predicate as
    LITERAL text. A bound parameter (which is how SQLAlchemy sends `.in_([...])`) hides it, and the
    planner then walks the timestamp index and loads every row in the window to test its severity:
    12.7 s for 7 days of a 17.5M-alert table, against 0.47 s for the literal form (27,686 rows both
    ways). `test_console_rollups.py` pins the query plan."""
    return (
        select(
            Alert.source_ip.label("source_ip"),
            _country_expr().label("country"),
            Alert.timestamp.label("ts"),
        )
        .where(
            text("alerts.severity IN ('critical', 'high')"),
            Alert.severity == AlertSeverity.CRITICAL,
            Alert.timestamp >= start,
        )
        .subquery()
    )


async def _overview(hours: float) -> dict[str, Any]:
    """Everything the page draws, from the rollups.

    The first version ran about ten separate scans of the raw alert window per poll (one with a 48-way
    CASE and one extracting JSON from every row), which was fine for thousands of alerts and did not
    return in 120 s on 17.6M. Now: one grouped pass over `rollups.window` (whole hours from the hourly
    rollups, partial edge hours from the raw table) yields the totals, unique sources, severity split,
    top sources and per-sensor counts; the chart reads the rollups (or one arithmetic GROUP BY for
    short windows); geography reads CRITICAL alerts only, the only ones that carry enrichment."""
    now = datetime.now(UTC)
    start = now - timedelta(hours=hours)
    bucket = _bucket_size(hours)
    ordered = _bucket_starts(start, now, bucket)
    w = rollups.window(start, now=now)

    critical_rows = _critical_rows(start)
    has_country = and_(critical_rows.c.country.is_not(None), critical_rows.c.country != "")

    async with get_session() as session:
        grouped = (
            await session.execute(
                select(w.c.severity, w.c.source_ip, w.c.honeypot_id, func.sum(w.c.n)).group_by(
                    w.c.severity, w.c.source_ip, w.c.honeypot_id
                )
            )
        ).all()
        acknowledged = sum((await rollups.acknowledged_by_severity(session, start)).values())
        series_counts = await _series(session, start, now, bucket, ordered)
        country_rows = (
            await session.execute(
                select(critical_rows.c.country, func.count().label("n"))
                .where(has_country)
                .group_by(critical_rows.c.country)
                .order_by(desc("n"), critical_rows.c.country)
                .limit(6)
            )
        ).all()
        feed_rows = (
            (
                await session.execute(
                    select(Alert)
                    .where(Alert.timestamp >= start)
                    .order_by(desc(Alert.timestamp))
                    .limit(_FEED_ROWS)
                )
            )
            .scalars()
            .all()
        )
        honeypots = (await session.execute(select(Honeypot))).scalars().all()
        token_rows = (
            await session.execute(
                select(Honeytoken.status, func.count()).group_by(Honeytoken.status)
            )
        ).all()

    events = 0
    sev_counts: dict[str, int] = {}
    per_ip: dict[str, int] = {}
    hits: dict[int, int] = {}
    for severity, source_ip, sensor, n in grouped:
        n = int(n)
        events += n
        sev_counts[_enum_value(severity)] = sev_counts.get(_enum_value(severity), 0) + n
        per_ip[source_ip] = per_ip.get(source_ip, 0) + n
        hits[int(sensor)] = hits.get(int(sensor), 0) + n
    unique_ips = len(per_ip)
    untriaged = max(events - acknowledged, 0)
    ip_rows = sorted(per_ip.items(), key=lambda kv: (-kv[1], kv[0]))[:8]
    token_counts = {_enum_value(status): int(n) for status, n in token_rows}

    # The most recent country seen for each top attacker (known only if it ever raised a CRITICAL).
    top_ips = [ip for ip, _ in ip_rows]
    ip_country_rows: Sequence[Any] = []
    if top_ips:
        async with get_session() as session:
            ip_country_rows = (
                await session.execute(
                    select(
                        critical_rows.c.source_ip,
                        critical_rows.c.country,
                        func.max(critical_rows.c.ts),
                    )
                    .where(critical_rows.c.source_ip.in_(top_ips), has_country)
                    .group_by(critical_rows.c.source_ip, critical_rows.c.country)
                )
            ).all()
    latest: dict[str, tuple[datetime, str]] = {}
    for ip, c, ts in ip_country_rows:
        if ts is None:
            continue
        aware = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        if ip not in latest or aware > latest[ip][0]:
            latest[ip] = (aware, str(c))

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "window_hours": hours,
        "stats": {
            "events": events,
            "unique_ips": unique_ips,
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "untriaged": untriaged,
            "honeypots_running": sum(1 for h in honeypots if h.status == HoneypotStatus.RUNNING),
            "honeypots_total": len(honeypots),
            "honeypots_error": sum(1 for h in honeypots if h.status == HoneypotStatus.ERROR),
            "tokens_active": token_counts.get(HoneytokenStatus.ACTIVE.value, 0),
            "tokens_triggered": token_counts.get(HoneytokenStatus.TRIGGERED.value, 0),
        },
        "series": {
            "bucket_minutes": int(bucket.total_seconds() // 60),
            "points": [
                {
                    "t": ts.isoformat(),
                    "routine": series_counts.get(i, {}).get("routine", 0),
                    "serious": series_counts.get(i, {}).get("serious", 0),
                }
                for i, ts in enumerate(ordered)
            ],
        },
        "top_attackers": [
            {"ip": ip, "hits": int(n), "country": latest[ip][1] if ip in latest else None}
            for ip, n in ip_rows
        ],
        "top_countries": [{"country": str(c), "hits": int(n)} for c, n in country_rows],
        "honeypots": [
            {
                "name": h.name,
                "type": h.type.value,
                "port": h.port,
                "status": h.status.value,
                "hits": hits.get(h.id, 0),
            }
            for h in sorted(honeypots, key=lambda x: (-hits.get(x.id, 0), x.name))
        ],
        "feed": [
            {
                "id": a.id,
                "t": a.timestamp.isoformat(),
                "ip": a.source_ip,
                "event_type": a.event_type,
                "severity": a.severity.value,
                "acknowledged": a.acknowledged,
                "digest": digest_payload(a.payload),
            }
            for a in feed_rows
        ],
    }


def _enum_value(value: Any) -> str:
    return str(value.value) if hasattr(value, "value") else str(value)


# ── Host validation ─────────────────────────────────────────────────────────
#
# The console has no authentication; it relies on being reachable only from
# where it is bound. DNS rebinding defeats that from a browser: a page on
# attacker.example re-resolves its own name to 127.0.0.1 and then reads
# /api/overview same-origin. The request still carries `Host: attacker.example`,
# so refusing unknown host names closes it. IP-literal hosts cannot be rebound
# and are accepted, so a console bound to 0.0.0.0 stays reachable by address.

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain"})


def _host_name(header: str) -> str:
    """The name part of a Host header, lowercased, without port or brackets."""
    h = header.strip().lower()
    if h.startswith("["):
        end = h.find("]")
        return h[1:end] if end > 0 else h
    if h.count(":") == 1:
        h = h.rsplit(":", 1)[0]
    return h.rstrip(".")


def _allowed_host_names() -> frozenset[str]:
    settings = get_settings()
    names = set(_LOOPBACK_NAMES)
    names.add(_host_name(settings.console_host))
    names.update(
        _host_name(n) for n in (settings.console_allowed_hosts or "").split(",") if n.strip()
    )
    return frozenset(names)


def _host_allowed(header: str | None) -> bool:
    if not header:
        return False
    name = _host_name(header)
    if not name:
        return False
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        pass
    return name in _allowed_host_names()


@web.middleware
async def _host_check_middleware(request: web.Request, handler: Any) -> web.StreamResponse:
    if not _host_allowed(request.headers.get("Host")):
        return web.Response(status=421, text="Misdirected Request")
    resp: web.StreamResponse = await handler(request)
    return resp


# ── Response cache ──────────────────────────────────────────────────────────
#
# Every open console polls every 5 s; several screens (or a hostile page that
# made it past the Host check) must not multiply the aggregation load.
_CACHE_TTL_SECONDS = 3.0
_CACHE_MAX_KEYS = 16
_overview_cache: dict[float, tuple[float, dict[str, Any]]] = {}


async def _cached_overview(hours: float) -> dict[str, Any]:
    now = time.monotonic()
    hit = _overview_cache.get(hours)
    if hit is not None and now - hit[0] < _CACHE_TTL_SECONDS:
        return hit[1]
    data = await _overview(hours)
    if len(_overview_cache) >= _CACHE_MAX_KEYS:
        _overview_cache.clear()
    _overview_cache[hours] = (time.monotonic(), data)
    return data


async def _handle_index(_request: web.Request) -> web.Response:
    try:
        html = (_STATIC / "index.html").read_text(encoding="utf-8")
    except OSError:
        return web.Response(status=500, text="Console assets missing.")
    return web.Response(text=html, content_type="text/html")


async def _handle_overview(request: web.Request) -> web.Response:
    try:
        hours = float(request.query.get("hours", "24"))
    except ValueError:
        hours = 24.0
    hours = max(0.25, min(hours, 24 * 30))
    # Quantise so arbitrary `hours` values cannot each force a fresh query.
    hours = max(0.25, round(hours * 4) / 4)
    return web.json_response(await _cached_overview(hours))


def build_console_app() -> web.Application:
    # GET-only by design: this page is a view, not a second control plane.
    # Identity middleware stays first so even a 421 wears the console banner.
    app = web.Application(
        middlewares=[
            server_identity_middleware("HoneyPot MCP Console"),
            _host_check_middleware,
        ]
    )
    app.router.add_get("/", _handle_index)
    app.router.add_get("/api/overview", _handle_overview)
    return app


async def start_console_server(host: str, port: int) -> web.AppRunner | None:
    """Start the console. A bind failure is logged, never fatal — losing the
    wall display must not take down attack collection."""
    if _host_name(host) not in _LOOPBACK_NAMES:
        try:
            loopback = ipaddress.ip_address(_host_name(host)).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            log.warning(
                "Console bound to non-loopback %s: it has no authentication and shows "
                "captured attack data to anyone who can reach port %d. Host names other "
                "than loopback/IP literals must be listed in CONSOLE_ALLOWED_HOSTS.",
                host,
                port,
            )
    runner = identity_runner(build_console_app(), _CONSOLE_BANNER)
    try:
        await runner.setup()
        await web.TCPSite(runner, host, port).start()
        log.info("Console listening on http://%s:%d", host, port)
        return runner
    except OSError as e:
        log.warning("Console could not bind %s:%d (%s)", host, port, e)
        await runner.cleanup()
        return None
