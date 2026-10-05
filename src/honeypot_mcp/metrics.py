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

import ipaddress
import logging
from typing import Any

from aiohttp import web
from sqlalchemy import func, select

from honeypot_mcp.http_identity import identity_runner
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

# Server banner for protocol-level errors on this listener.
_METRICS_BANNER = "HoneyPot MCP Metrics"


def _pending_suppression_counts() -> dict[int, int]:
    from honeypot_mcp import suppression

    fn = getattr(suppression, "pending_suppression_counts", None)
    return fn() if callable(fn) else {}


def _line(name: str, labels: dict[str, str] | None, value: float | int) -> str:
    if labels:
        rendered = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
        return f"{name}{{{rendered}}} {value}\n"
    return f"{name} {value}\n"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


async def _database_size_bytes() -> int | None:
    """On-disk size of the database, or None when it cannot be determined."""
    from sqlalchemy import text
    from sqlalchemy.engine import make_url

    from honeypot_mcp.config import get_settings

    url = get_settings().database_url
    try:
        backend = make_url(url).get_backend_name()
        if backend == "postgresql":
            async with get_session() as session:
                return int(
                    (
                        await session.execute(text("SELECT pg_database_size(current_database())"))
                    ).scalar_one()
                )
        if backend == "sqlite" and ":memory:" not in url:
            database = make_url(url).database
            if database:
                import os

                # The write-ahead log is part of the database: a busy one holds tens of MB
                # that the main file does not show until a checkpoint.
                return sum(
                    os.stat(path).st_size
                    for path in (database, f"{database}-wal", f"{database}-shm")
                    if os.path.exists(path)
                )
    except Exception:
        return None
    return None


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

        # One series per sensor that is supposed to be up (RUNNING, or ERROR after a failed
        # probe), so `honeypot_sensor_up == 0` is an alert rule. Sensors an operator
        # stopped or paused are left out: a deliberate stop must not page anyone.
        sensors = (
            await session.execute(
                select(Honeypot.name, Honeypot.type, Honeypot.status)
                .where(Honeypot.status.in_([HoneypotStatus.RUNNING, HoneypotStatus.ERROR]))
                .order_by(Honeypot.id)
            )
        ).all()
        out.append("# HELP honeypot_sensor_up 1 when the honeypot is RUNNING, else 0.\n")
        out.append("# TYPE honeypot_sensor_up gauge\n")
        for name, hp_type, status in sensors:
            type_value = hp_type.value if hasattr(hp_type, "value") else str(hp_type)
            up = 1 if status == HoneypotStatus.RUNNING else 0
            out.append(_line("honeypot_sensor_up", {"name": name, "type": type_value}, up))

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

        # Suppression drops by rule id (counter). Ids, not the operator-written
        # labels: a label routinely names the scanner ranges or partner hosts
        # being silenced, which an unauthenticated scrape must not disclose.
        supp_rows = (
            await session.execute(select(SuppressionRule.id, SuppressionRule.suppressed_count))
        ).all()
        pending = _pending_suppression_counts()
        out.append("# HELP honeypot_suppression_drops_total Events dropped per suppression rule.\n")
        out.append("# TYPE honeypot_suppression_drops_total counter\n")
        for rule_id, count in supp_rows:
            total = (count or 0) + pending.get(rule_id, 0)
            out.append(_line("honeypot_suppression_drops_total", {"rule_id": str(rule_id)}, total))

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
    from honeypot_mcp.storage import event_buffer

    out.append("# HELP honeypot_event_queue_depth Events awaiting commit in the ingest buffer.\n")
    out.append("# TYPE honeypot_event_queue_depth gauge\n")
    out.append(_line("honeypot_event_queue_depth", None, event_buffer.get_buffer().qsize()))

    # Events shed by the ingest queue's high-water policy, by severity.
    by_sev = getattr(event_buffer, "dropped_event_counts_by_severity", None)
    if callable(by_sev):
        out.append(
            "# HELP honeypot_event_queue_dropped_total Events shed by the ingest queue "
            "high-water policy.\n"
        )
        out.append("# TYPE honeypot_event_queue_dropped_total counter\n")
        for sev, n in sorted(by_sev().items()):
            out.append(_line("honeypot_event_queue_dropped_total", {"severity": sev}, n))

    # Free space where the server writes. A full disk ends collection silently.
    from honeypot_mcp.storage import disk

    volumes = disk.sample()
    if volumes:
        out.append("# HELP honeypot_disk_free_bytes Free bytes on a volume the server writes to.\n")
        out.append("# TYPE honeypot_disk_free_bytes gauge\n")
        for v in volumes:
            out.append(_line("honeypot_disk_free_bytes", {"volume": v.label}, v.free_bytes))

    # Database size: the one number that predicts a full disk on a volume this process
    # cannot see (a remote PostgreSQL's own).
    size = await _database_size_bytes()
    if size is not None:
        out.append("# HELP honeypot_database_size_bytes Size of the alert database.\n")
        out.append("# TYPE honeypot_database_size_bytes gauge\n")
        out.append(_line("honeypot_database_size_bytes", None, size))

    # Webhook events dropped by the bounded delivery queues. Read the existing
    # singleton only — a scrape must not be what instantiates the worker.
    from honeypot_mcp import webhooks

    delivery = getattr(webhooks, "_delivery", None)
    wh_dropped = getattr(delivery, "dropped_count", None) if delivery is not None else 0
    if isinstance(wh_dropped, int):
        out.append(
            "# HELP honeypot_webhook_dropped_total Webhook events dropped by a full "
            "delivery queue.\n"
        )
        out.append("# TYPE honeypot_webhook_dropped_total counter\n")
        out.append(_line("honeypot_webhook_dropped_total", None, wh_dropped))

    return "".join(out)


async def _handle_metrics(_request: web.Request) -> web.Response:
    try:
        body = await _gather_metrics()
    except Exception:
        # Detail stays in the server log: the scrape endpoint is reachable by
        # whatever can reach the port, and exception text carries DB URLs/paths.
        log.exception("Metrics collection failed")
        body = "# metrics_error: collection failed\n"
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
    except Exception:
        log.exception("Readiness database check failed")
        checks["database"] = "unavailable"
        ready = False

    depth = get_buffer().qsize()
    checks["event_queue_depth"] = depth
    # A backlog this size means ingest has been outrunning the database for a
    # while; the queue is unbounded, so it is a memory problem before it is a
    # data-loss one.
    if depth > 50_000:
        checks["event_queue"] = "backlog — ingest is outrunning the database"
        ready = False

    from honeypot_mcp.storage import disk

    # Only the database volume decides readiness: it is the one whose exhaustion stops
    # events persisting. A full reports or pcap volume is alerted on (watchdog,
    # honeypot_disk_free_bytes) but must not mark a collecting server unhealthy.
    low = [v for v in disk.low_volumes() if v.label == "database"]
    if low:
        checks["disk"] = "; ".join(f"low on {v.label}: {v.free_mb} MB free" for v in low)
        ready = False
    else:
        checks["disk"] = "ok"

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


def _is_loopback_host(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


async def start_metrics_server(host: str, port: int) -> web.AppRunner | None:
    """Start the /metrics server on (host, port). Returns the runner so
    caller can shut it down. Bind failures are logged but non-fatal — a
    busy port shouldn't take down honeypot ingest."""
    if not _is_loopback_host(host):
        log.warning(
            "Metrics server bound to non-loopback %s: /metrics, /healthz and /readyz are "
            "unauthenticated. Set METRICS_HOST=127.0.0.1 unless a firewall restricts %d.",
            host,
            port,
        )
    runner = identity_runner(build_app(), _METRICS_BANNER)
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
