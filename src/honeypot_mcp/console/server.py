"""Console HTTP server: one HTML page plus the JSON feed it polls."""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from aiohttp import web
from sqlalchemy import desc, func, select

from honeypot_mcp.http_identity import server_identity_middleware
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


async def _overview(hours: float) -> dict[str, Any]:
    since = datetime.now(UTC) - timedelta(hours=hours)

    async with get_session() as session:
        alerts = (
            (
                await session.execute(
                    select(Alert).where(Alert.timestamp >= since).order_by(desc(Alert.timestamp))
                )
            )
            .scalars()
            .all()
        )
        honeypots = (await session.execute(select(Honeypot))).scalars().all()
        hit_rows = (
            await session.execute(
                select(Alert.honeypot_id, func.count())
                .where(Alert.timestamp >= since)
                .group_by(Alert.honeypot_id)
            )
        ).all()
        tokens = (await session.execute(select(Honeytoken))).scalars().all()

    hits = {row[0]: row[1] for row in hit_rows}
    sev_counts: Counter[str] = Counter(a.severity.value for a in alerts)
    unique_ips = {a.source_ip for a in alerts}

    # Time series: two series, because the decision an analyst makes is
    # "routine noise or something I act on", not a four-way split. Four
    # severity bands cannot be told apart reliably as adjacent stacked marks.
    bucket = _bucket_size(hours)
    buckets: dict[datetime, dict[str, int]] = {}
    start = datetime.now(UTC) - timedelta(hours=hours)
    cursor = start
    while cursor <= datetime.now(UTC):
        buckets[cursor] = {"routine": 0, "serious": 0}
        cursor += bucket
    ordered = sorted(buckets)
    for a in alerts:
        ts = a.timestamp if a.timestamp.tzinfo else a.timestamp.replace(tzinfo=UTC)
        idx = int((ts - start) / bucket)
        if 0 <= idx < len(ordered):
            key = "serious" if a.severity in _SERIOUS else "routine"
            buckets[ordered[idx]][key] += 1

    # Geography, from whatever enrichment landed on the payload.
    countries: Counter[str] = Counter()
    for a in alerts:
        payload = a.payload if isinstance(a.payload, dict) else {}
        geo = (payload.get("enrichment") or {}).get("geoip") or {}
        if isinstance(geo, dict) and (c := geo.get("country")):
            countries[str(c)] += 1

    ip_counts = Counter(a.source_ip for a in alerts)
    triaged = sum(1 for a in alerts if a.acknowledged)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "window_hours": hours,
        "stats": {
            "events": len(alerts),
            "unique_ips": len(unique_ips),
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "untriaged": len(alerts) - triaged,
            "honeypots_running": sum(1 for h in honeypots if h.status == HoneypotStatus.RUNNING),
            "honeypots_total": len(honeypots),
            "honeypots_error": sum(1 for h in honeypots if h.status == HoneypotStatus.ERROR),
            "tokens_active": sum(1 for t in tokens if t.status == HoneytokenStatus.ACTIVE),
            "tokens_triggered": sum(1 for t in tokens if t.status == HoneytokenStatus.TRIGGERED),
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
            {"ip": ip, "hits": n, "country": _country_for(alerts, ip)}
            for ip, n in ip_counts.most_common(8)
        ],
        "top_countries": [{"country": c, "hits": n} for c, n in countries.most_common(6)],
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
            for a in alerts[:40]
        ],
    }


def _country_for(alerts: Sequence[Alert], ip: str) -> str | None:
    for a in alerts:
        if a.source_ip != ip:
            continue
        payload = a.payload if isinstance(a.payload, dict) else {}
        geo = (payload.get("enrichment") or {}).get("geoip") or {}
        if isinstance(geo, dict) and (c := geo.get("country")):
            return str(c)
    return None


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
    return web.json_response(await _overview(hours))


def build_console_app() -> web.Application:
    # GET-only by design: this page is a view, not a second control plane.
    app = web.Application(middlewares=[server_identity_middleware("HoneyPot MCP Console")])
    app.router.add_get("/", _handle_index)
    app.router.add_get("/api/overview", _handle_overview)
    return app


async def start_console_server(host: str, port: int) -> web.AppRunner | None:
    """Start the console. A bind failure is logged, never fatal — losing the
    wall display must not take down attack collection."""
    runner = web.AppRunner(build_console_app())
    try:
        await runner.setup()
        await web.TCPSite(runner, host, port).start()
        log.info("Console listening on http://%s:%d", host, port)
        return runner
    except OSError as e:
        log.warning("Console could not bind %s:%d (%s)", host, port, e)
        await runner.cleanup()
        return None
