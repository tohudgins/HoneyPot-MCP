"""HoneyPot MCP server entry point."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal, cast

from fastmcp import FastMCP

from honeypot_mcp.canary import start_canary_server
from honeypot_mcp.config import get_settings
from honeypot_mcp.console import start_console_server
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
    console_runner = None
    if settings.console_port > 0:
        console_runner = await start_console_server(settings.console_host, settings.console_port)
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
        if console_runner is not None:
            await console_runner.cleanup()
        await buffer.stop()
        await delivery.stop()
        await close_db()


def _build_auth() -> Any:
    """Build the auth provider for the control plane, or None.

    stdio needs no auth (it's a local per-chat subprocess). A networked
    transport authenticates clients with a static bearer token when
    `mcp_auth_token` is set. The fail-closed check (refuse to run a networked
    transport with no token) lives in `main()`, so importing this module — and
    the test suite, which runs over in-memory stdio — never trips it.
    """
    settings = get_settings()
    if settings.mcp_transport == "stdio" or not settings.mcp_auth_token:
        return None
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

    return StaticTokenVerifier(
        tokens={settings.mcp_auth_token: {"client_id": "honeypot-operator", "scopes": []}}
    )


mcp = FastMCP(
    name="HoneyPot MCP",
    instructions=(
        "You are connected to the HoneyPot MCP server. "
        "You can deploy honeypots, manage honeytokens, monitor alerts, "
        "and analyse attacker behaviour. "
        "All operations are scoped to the local Docker environment by default."
    ),
    lifespan=lifespan,
    auth=_build_auth(),
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


def _networked_auth_error(settings: Any) -> str | None:
    """Return a fail-closed error message if a networked control plane would be
    exposed without authentication, else None. stdio needs no auth, and `none`
    exposes no control plane to authenticate."""
    if settings.mcp_transport in ("stdio", "none"):
        return None
    if settings.mcp_auth_token or settings.mcp_allow_unauthenticated:
        return None
    return (
        f"Refusing to start the '{settings.mcp_transport}' control plane without "
        "authentication.\n"
        "Set MCP_AUTH_TOKEN (generate one with `openssl rand -hex 32`) so clients must\n"
        "present it as `Authorization: Bearer <token>`. If you intentionally front the\n"
        "server with your own auth (reverse proxy / trusted SSH tunnel), set\n"
        "MCP_ALLOW_UNAUTHENTICATED=true to override."
    )


async def _run_collector() -> None:
    """Run the capture plane with no MCP transport, until signalled to stop.

    Everything that collects attacks — honeypot engines, the canary callback
    server, the watchdog, webhook delivery, /metrics — lives in the lifespan.
    The MCP transport is only the control plane layered on top, so dropping it
    leaves a fully functional headless collector.
    """
    async with lifespan(mcp):
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            # Not available on Windows; KeyboardInterrupt still unwinds there.
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, stop.set)
        log.info("Collector mode — capture plane running, no MCP control plane.")
        await stop.wait()


def main() -> None:
    settings = get_settings()
    # Validated by Settings.validate_mcp_transport to one of these literals.
    transport = cast(
        'Literal["stdio", "http", "sse", "streamable-http", "none"]',
        settings.mcp_transport,
    )
    if transport == "stdio":
        # Per-chat subprocess launched by Claude Desktop / Claude Code.
        mcp.run()
        return

    if transport == "none":
        # Collector mode. Also the only correct mode for a detached container:
        # stdio would read EOF from an unattached stdin and exit at once.
        asyncio.run(_run_collector())
        return

    # Networked control plane can deploy honeypots and read all captured data,
    # so refuse to expose it without authentication (fail-closed).
    gate_error = _networked_auth_error(settings)
    if gate_error is not None:
        raise SystemExit(gate_error)
    if not settings.mcp_auth_token:
        log.warning(
            "MCP control plane running WITHOUT authentication (MCP_ALLOW_UNAUTHENTICATED=true). "
            "Ensure an external auth layer protects %s:%d.",
            settings.mcp_host,
            settings.mcp_port,
        )
    else:
        log.info("MCP control plane authentication enabled (bearer token).")

    # Persistent networked server — clients connect to
    # http://<mcp_host>:<mcp_port>/mcp with the bearer token.
    mcp.run(transport=transport, host=settings.mcp_host, port=settings.mcp_port)


if __name__ == "__main__":
    main()
