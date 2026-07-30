"""Prometheus-compatible /metrics endpoint.

A minimal text-format exporter — counter-only — that doesn't pull in
prometheus_client as a hard dep. The output is parseable by Prometheus
1.x scrapers, Grafana Agent, Loki, OpenTelemetry Collector, etc.

Metrics exposed (all from a single DB scan):

  honeypot_alerts_total{severity=...}              counter
  honeypot_alerts_by_engine_total{engine=...}      counter
  honeypot_alerts_by_event_type_total{type=...}    counter
  honeypot_active_honeypots                        gauge
  honeypot_active_tokens{type=...}                 gauge
  honeypot_suppression_drops_total{label=...}      counter
  honeypot_webhook_failures_total                  counter
  honeypot_webhook_deliveries_total                counter

The aiohttp server starts alongside the canary callback in `server.py:lifespan`
on a separate port (`metrics_port`, default 9090) so it can be scraped
independently of the honeypot ports.
"""

from __future__ import annotations

import logging
from typing import Any

from aiohttp import web
from sqlalchemy import func, select

from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    Alert,
    Honeypot,
    HoneypotStatus,
    Honeytoken,
    HoneytokenStatus,
    Subscription,
    SuppressionRule,
)

log = logging.getLogger(__name__)


def _line(name: str, labels: dict[str, str] | None, value: float | int) -> str:
    if labels:
        rendered = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
        return f"{name}{{{rendered}}} {value}\n"
    return f"{name} {value}\n"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


async def _gather_metrics() -> str:
    """Run the metrics-collection queries in a single session and format
    the result as Prometheus text exposition."""
    out: list[str] = []

    async with get_session() as session:
        # Alerts by severity
        sev_rows = (
            await session.execute(select(Alert.severity, func.count()).group_by(Alert.severity))
        ).all()
        out.append("# HELP honeypot_alerts_total Total alerts grouped by severity.\n")
        out.append("# TYPE honeypot_alerts_total counter\n")
        for severity, count in sev_rows:
            sev_value = severity.value if hasattr(severity, "value") else str(severity)
            out.append(_line("honeypot_alerts_total", {"severity": sev_value}, count))

        # Alerts by event type (top 50 to keep cardinality bounded)
        et_rows = (
            await session.execute(
                select(Alert.event_type, func.count())
                .group_by(Alert.event_type)
                .order_by(func.count().desc())
                .limit(50)
            )
        ).all()
        out.append("# HELP honeypot_alerts_by_event_type_total Alerts by event_type (top 50).\n")
        out.append("# TYPE honeypot_alerts_by_event_type_total counter\n")
        for et, count in et_rows:
            out.append(_line("honeypot_alerts_by_event_type_total", {"type": et}, count))

        # Alerts by honeypot (engine) — joined through honeypots.type
        eng_rows = (
            await session.execute(
                select(Honeypot.type, func.count(Alert.id))
                .join(Honeypot, Alert.honeypot_id == Honeypot.id)
                .group_by(Honeypot.type)
            )
        ).all()
        out.append(
            "# HELP honeypot_alerts_by_engine_total Alerts grouped by honeypot engine type.\n"
        )
        out.append("# TYPE honeypot_alerts_by_engine_total counter\n")
        for engine, count in eng_rows:
            engine_value = engine.value if hasattr(engine, "value") else str(engine)
            out.append(_line("honeypot_alerts_by_engine_total", {"engine": engine_value}, count))

        # Active honeypots (gauge)
        active_hp = (
            await session.execute(
                select(func.count()).where(Honeypot.status == HoneypotStatus.RUNNING)
            )
        ).scalar_one()
        out.append("# HELP honeypot_active_honeypots Number of honeypots in RUNNING state.\n")
        out.append("# TYPE honeypot_active_honeypots gauge\n")
        out.append(_line("honeypot_active_honeypots", None, active_hp))

        # Active tokens by type (gauge)
        tok_rows = (
            await session.execute(
                select(Honeytoken.type, func.count())
                .where(Honeytoken.status == HoneytokenStatus.ACTIVE)
                .group_by(Honeytoken.type)
            )
        ).all()
        out.append("# HELP honeypot_active_tokens Active honeytokens by type.\n")
        out.append("# TYPE honeypot_active_tokens gauge\n")
        for ttype, count in tok_rows:
            type_value = ttype.value if hasattr(ttype, "value") else str(ttype)
            out.append(_line("honeypot_active_tokens", {"type": type_value}, count))

        # Suppression drops by rule label (counter)
        supp_rows = (
            await session.execute(select(SuppressionRule.label, SuppressionRule.suppressed_count))
        ).all()
        out.append("# HELP honeypot_suppression_drops_total Events dropped per suppression rule.\n")
        out.append("# TYPE honeypot_suppression_drops_total counter\n")
        for label, count in supp_rows:
            out.append(_line("honeypot_suppression_drops_total", {"label": label}, count or 0))

        # Webhook delivery counters (counter)
        wh_rows = (
            await session.execute(
                select(
                    func.coalesce(func.sum(Subscription.delivery_count), 0),
                    func.coalesce(func.sum(Subscription.failure_count), 0),
                )
            )
        ).one()
        delivered, failed = wh_rows
        out.append("# HELP honeypot_webhook_deliveries_total Total webhook deliveries.\n")
        out.append("# TYPE honeypot_webhook_deliveries_total counter\n")
        out.append(_line("honeypot_webhook_deliveries_total", None, delivered or 0))
        out.append("# HELP honeypot_webhook_failures_total Total webhook delivery failures.\n")
        out.append("# TYPE honeypot_webhook_failures_total counter\n")
        out.append(_line("honeypot_webhook_failures_total", None, failed or 0))

    # Ingest backlog. Outside the session block because it reads in-process
    # state, not the database.
    #
    # This is the leading indicator for the one way captured data gets lost:
    # the queue is unbounded, so events are never dropped on the way in, but a
    # backlog that outlives the shutdown drain is discarded. Depth normally
    # sits at roughly one flush interval's worth of traffic (200 at 200
    # events/sec); a number that climbs instead of oscillating means ingest is
    # outrunning the database, and it is visible here long before a restart
    # turns it into loss.
    from honeypot_mcp.storage.event_buffer import get_buffer

    out.append("# HELP honeypot_event_queue_depth Events awaiting commit in the ingest buffer.\n")
    out.append("# TYPE honeypot_event_queue_depth gauge\n")
    out.append(_line("honeypot_event_queue_depth", None, get_buffer().qsize()))

    return "".join(out)


async def _handle_metrics(_request: web.Request) -> web.Response:
    try:
        body = await _gather_metrics()
    except Exception as e:
        log.warning("Metrics collection failed: %s", e)
        body = f"# metrics_error: {e!r}\n"
    # aiohttp wants content_type and charset as separate kwargs; the version
    # parameter is Prometheus convention surfaced via the response body
    # itself (Prometheus scrapers don't require it in the Content-Type).
    return web.Response(text=body, content_type="text/plain", charset="utf-8")


async def _handle_healthz(_request: web.Request) -> web.Response:
    """Liveness: the process is up and the event loop is turning."""
    return web.json_response({"status": "ok"})


async def _handle_readyz(_request: web.Request) -> web.Response:
    """Readiness: the pieces that must work for collection to be real.

    Liveness alone is not enough here. A honeypot whose database has gone away
    keeps accepting connections and answering attackers perfectly — the
    listeners are in-process and do not need the DB — while every captured
    event silently fails to persist. Deleting the database file underneath a
    running server reproduces exactly that: engines keep serving, a deploy even
    reports success, and nothing is stored. A liveness probe sees a healthy
    process throughout.

    So readiness actually queries a real table. That distinguishes "running"
    from "collecting", which is the only distinction that matters for a sensor.
    """
    from sqlalchemy import func, select

    from honeypot_mcp.storage.event_buffer import get_buffer

    checks: dict[str, Any] = {}
    ready = True
    try:
        async with get_session() as session:
            # A real query against a real table — not `SELECT 1`, which passes
            # against an empty database file that lost its schema.
            await session.execute(select(func.count(Honeypot.id)))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"unavailable: {type(e).__name__}: {e}"
        ready = False

    depth = get_buffer().qsize()
    checks["event_queue_depth"] = depth
    # A backlog this size means ingest has been outrunning the database for a
    # while; the queue is unbounded, so it is a memory problem before it is a
    # data-loss one.
    if depth > 50_000:
        checks["event_queue"] = "backlog — ingest is outrunning the database"
        ready = False

    return web.json_response(
        {"status": "ready" if ready else "not ready", "checks": checks},
        status=200 if ready else 503,
    )


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/metrics", _handle_metrics)
    app.router.add_get("/healthz", _handle_healthz)
    app.router.add_get("/readyz", _handle_readyz)
    return app


async def start_metrics_server(host: str, port: int) -> web.AppRunner | None:
    """Start the /metrics server on (host, port). Returns the runner so
    caller can shut it down. Bind failures are logged but non-fatal — a
    busy port shouldn't take down honeypot ingest."""
    runner = web.AppRunner(build_app())
    try:
        await runner.setup()
        site = web.TCPSite(runner, host, port)
        await site.start()
        log.info("Prometheus /metrics server listening on %s:%d", host, port)
        return runner
    except OSError as e:
        log.warning("Metrics server could not bind %s:%d (%s)", host, port, e)
        await runner.cleanup()
        return None
