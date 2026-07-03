"""HoneyPot MCP server entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastmcp import FastMCP

from honeypot_mcp.canary import start_canary_server
from honeypot_mcp.config import get_settings
from honeypot_mcp.metrics import start_metrics_server
from honeypot_mcp.reconcile import reconcile_running_honeypots
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import close_db, get_session, init_db
from honeypot_mcp.storage.event_buffer import get_buffer
from honeypot_mcp.storage.models import HoneypotStatus, HoneytokenStatus
from honeypot_mcp.watchdog import get_watchdog
from honeypot_mcp.webhooks import get_delivery

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastMCP):
    settings = get_settings()
    from honeypot_mcp.logging_config import configure_logging

    configure_logging(level=settings.log_level, format_style=settings.log_format)
    log.info("HoneyPot MCP starting — initialising database…")
    await init_db()
    log.info("Database ready.")
    buffer = get_buffer()
    delivery = get_delivery()
    watchdog = get_watchdog()
    await delivery.start()
    buffer.set_on_flush(delivery.enqueue_batch)
    await buffer.start()
    canary_runner = await start_canary_server()
    metrics_runner = None
    if settings.metrics_port > 0:
        metrics_runner = await start_metrics_server(settings.metrics_host, settings.metrics_port)
    # Re-establish honeypots the previous process left RUNNING — must happen
    # before the watchdog starts, or it races us to mark them dead.
    try:
        await reconcile_running_honeypots()
    except Exception:
        log.exception("Startup reconciliation failed — continuing anyway.")
    await watchdog.start()
    try:
        yield
    finally:
        log.info("HoneyPot MCP shutting down…")
        await watchdog.stop()
        if canary_runner is not None:
            await canary_runner.cleanup()
        if metrics_runner is not None:
            await metrics_runner.cleanup()
        await buffer.stop()
        await delivery.stop()
        await close_db()


mcp = FastMCP(
    name="HoneyPot MCP",
    instructions=(
        "You are connected to the HoneyPot MCP server. "
        "You can deploy honeypots, manage honeytokens, monitor alerts, "
        "and analyse attacker behaviour. "
        "All operations are scoped to the local Docker environment by default."
    ),
    lifespan=lifespan,
)

# ── Register tool modules ─────────────────────────────────────────────────────
# Import here so the @mcp.tool decorators execute at module load time.
import honeypot_mcp.tools.alerts  # noqa: E402, F401
import honeypot_mcp.tools.analysis  # noqa: E402, F401
import honeypot_mcp.tools.blocklist_push  # noqa: E402, F401
import honeypot_mcp.tools.honeypot  # noqa: E402, F401
import honeypot_mcp.tools.honeytoken  # noqa: E402, F401
import honeypot_mcp.tools.integrations  # noqa: E402, F401

# ── Built-in diagnostic tools ─────────────────────────────────────────────────


@mcp.tool
async def ping() -> dict[str, Any]:
    """Verify the MCP server is running and the database is reachable."""
    async with get_session() as session:
        from sqlalchemy import text

        await session.execute(text("SELECT 1"))
    return {
        "status": "ok",
        "server": "HoneyPot MCP",
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ── MCP Resources ─────────────────────────────────────────────────────────────


@mcp.resource("honeypot://active")
async def resource_active_honeypots() -> str:
    """Live list of all running honeypots with hit counts."""
    async with get_session() as session:
        honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)
        ids = [hp.id for hp in honeypots]
        counts = await queries.get_hit_counts(session, ids) if ids else {}
    if not honeypots:
        return "No honeypots currently running."
    rows = [
        f"  [{hp.type.value}] {hp.name} :{hp.port}  hits={counts.get(hp.id, 0)}" for hp in honeypots
    ]
    return "Active honeypots:\n" + "\n".join(rows)


@mcp.resource("alerts://stream")
async def resource_alert_stream() -> str:
    """The 25 most recent alerts across all honeypots."""
    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=25)
    if not alerts:
        return "No alerts recorded yet."
    lines = [
        f"[{a.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
        f"{a.severity.value.upper():8s} | {a.source_ip:15s} | {a.event_type}"
        for a in alerts
    ]
    return "\n".join(lines)


@mcp.resource("honeytoken://triggered")
async def resource_triggered_tokens() -> str:
    """All honeytokens that have been triggered."""
    async with get_session() as session:
        tokens = await queries.list_honeytokens(session, status=HoneytokenStatus.TRIGGERED)
    if not tokens:
        return "No honeytokens have been triggered yet."
    lines = [f"[{t.type.value}] {t.label} — triggered at {t.triggered_at}" for t in tokens]
    return "\n".join(lines)


@mcp.resource("stats://dashboard")
async def resource_stats_dashboard() -> str:
    """Aggregated statistics snapshot."""
    async with get_session() as session:
        stats = await queries.get_alert_stats(session)
        all_honeypots = await queries.list_honeypots(session)
        running = sum(1 for h in all_honeypots if h.status == HoneypotStatus.RUNNING)
        triggered_tokens = await queries.list_honeytokens(
            session, status=HoneytokenStatus.TRIGGERED
        )

    top_ips = "\n".join(f"  {r['ip']:20s} {r['count']} hits" for r in stats["top_source_ips"][:5])
    top_types = "\n".join(f"  {r['type']:30s} {r['count']}" for r in stats["top_event_types"][:5])
    return (
        f"=== HoneyPot MCP Dashboard ===\n"
        f"Honeypots:        {len(all_honeypots)} total  ({running} running)\n"
        f"Total alerts:     {stats['total_alerts']}\n"
        f"Tokens triggered: {len(triggered_tokens)}\n\n"
        f"Top attacker IPs:\n{top_ips or '  (none)'}\n\n"
        f"Top event types:\n{top_types or '  (none)'}"
    )


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
