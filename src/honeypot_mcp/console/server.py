"""Console HTTP server: one HTML page plus the JSON feed it polls."""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aiohttp import web
from sqlalchemy import and_, case, desc, distinct, func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.http_identity import identity_runner, server_identity_middleware
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    Alert,
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
    """Pick a bucket that yields roughly 24-48 columns for any window."""
    if hours <= 2:
        return timedelta(minutes=5)
    if hours <= 12:
        return timedelta(minutes=30)
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


async def _overview(hours: float) -> dict[str, Any]:
    now = datetime.now(UTC)
    start = now - timedelta(hours=hours)
    in_window = Alert.timestamp >= start

    # Bucket boundaries, computed once. Every alert in the window lands in
    # bucket k where start + k*bucket <= ts < start + (k+1)*bucket.
    bucket = _bucket_size(hours)
    ordered: list[datetime] = []
    cursor = start
    while cursor <= now:
        ordered.append(cursor)
        cursor += bucket
    bucket_expr = case(
        *[(Alert.timestamp < ts + bucket, idx) for idx, ts in enumerate(ordered)],
        else_=len(ordered),
    )
    # Expressions that carry bound parameters (the bucket CASE, the JSON path)
    # are grouped through a subquery: PostgreSQL treats the same expression
    # rendered twice with different placeholders as two expressions, so a
    # direct GROUP BY on them is rejected there.
    window_rows = (
        select(
            bucket_expr.label("bucket"),
            Alert.severity.label("severity"),
            Alert.source_ip.label("source_ip"),
            _country_expr().label("country"),
            Alert.timestamp.label("ts"),
        )
        .where(in_window)
        .subquery()
    )
    has_country = and_(window_rows.c.country.is_not(None), window_rows.c.country != "")

    async with get_session() as session:
        totals = (
            await session.execute(
                select(
                    func.count(Alert.id),
                    func.count(distinct(Alert.source_ip)),
                    func.coalesce(func.sum(case((Alert.acknowledged.is_(False), 1), else_=0)), 0),
                ).where(in_window)
            )
        ).one()
        sev_rows = (
            await session.execute(
                select(Alert.severity, func.count()).where(in_window).group_by(Alert.severity)
            )
        ).all()
        series_rows = (
            await session.execute(
                select(window_rows.c.bucket, window_rows.c.severity, func.count()).group_by(
                    window_rows.c.bucket, window_rows.c.severity
                )
            )
        ).all()
        ip_rows = (
            await session.execute(
                select(Alert.source_ip, func.count().label("n"))
                .where(in_window)
                .group_by(Alert.source_ip)
                .order_by(desc("n"), Alert.source_ip)
                .limit(8)
            )
        ).all()
        country_rows = (
            await session.execute(
                select(window_rows.c.country, func.count().label("n"))
                .where(has_country)
                .group_by(window_rows.c.country)
                .order_by(desc("n"), window_rows.c.country)
                .limit(6)
            )
        ).all()
        top_ips = [row[0] for row in ip_rows]
        ip_country_rows = (
            (
                await session.execute(
                    select(
                        window_rows.c.source_ip,
                        window_rows.c.country,
                        func.max(window_rows.c.ts),
                    )
                    .where(window_rows.c.source_ip.in_(top_ips), has_country)
                    .group_by(window_rows.c.source_ip, window_rows.c.country)
                )
            ).all()
            if top_ips
            else []
        )
        feed_rows = (
            (
                await session.execute(
                    select(Alert).where(in_window).order_by(desc(Alert.timestamp)).limit(_FEED_ROWS)
                )
            )
            .scalars()
            .all()
        )
        honeypots = (await session.execute(select(Honeypot))).scalars().all()
        hit_rows = (
            await session.execute(
                select(Alert.honeypot_id, func.count()).where(in_window).group_by(Alert.honeypot_id)
            )
        ).all()
        token_rows = (
            await session.execute(
                select(Honeytoken.status, func.count()).group_by(Honeytoken.status)
            )
        ).all()

    events, unique_ips, untriaged = (int(totals[0]), int(totals[1]), int(totals[2] or 0))
    sev_counts = {_enum_value(sev): int(n) for sev, n in sev_rows}
    hits = {row[0]: row[1] for row in hit_rows}
    token_counts = {_enum_value(status): int(n) for status, n in token_rows}

    # Time series: two series, because the decision an analyst makes is
    # "routine noise or something I act on", not a four-way split. Four
    # severity bands cannot be told apart reliably as adjacent stacked marks.
    buckets: dict[datetime, dict[str, int]] = {ts: {"routine": 0, "serious": 0} for ts in ordered}
    serious_values = {s.value for s in _SERIOUS}
    for idx, sev, n in series_rows:
        if idx is not None and 0 <= int(idx) < len(ordered):
            key = "serious" if _enum_value(sev) in serious_values else "routine"
            buckets[ordered[int(idx)]][key] += int(n)

    # Most recent country seen for each top attacker.
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
                    "routine": buckets[ts]["routine"],
                    "serious": buckets[ts]["serious"],
                }
                for ts in ordered
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
