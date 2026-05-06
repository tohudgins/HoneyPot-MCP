"""Honeypot management MCP tools."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Literal

from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType
from honeypot_mcp.engines import get_engine, list_engine_types


@mcp.tool
async def honeypot_deploy(
    type: Literal["ssh", "http", "smtp", "ftp", "dns"],
    port: int | None = None,
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a new honeypot container.

    Args:
        type: Protocol type — ssh, http, smtp, ftp, or dns.
        port: Host port to bind (defaults to the configured default for each type).
        name: Unique name for this honeypot (auto-generated if omitted).
        config: Optional engine-specific overrides (e.g. fake_hostname, endpoints).
    """
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    default_ports = {
        "ssh": settings.default_ssh_port,
        "http": settings.default_http_port,
        "ftp": settings.default_ftp_port,
        "smtp": settings.default_smtp_port,
        "dns": settings.default_dns_port,
    }
    resolved_port = port or default_ports[type]
    resolved_name = name or f"{type}-{secrets.token_hex(4)}"
    resolved_config = config or {}

    hp_type = HoneypotType(type)
    engine = get_engine(hp_type)

    async with get_session() as session:
        existing = await queries.get_honeypot_by_name(session, resolved_name)
        if existing:
            return {"error": f"Honeypot named '{resolved_name}' already exists (id={existing.id})."}

        hp = Honeypot(
            name=resolved_name,
            type=hp_type,
            port=resolved_port,
            status=HoneypotStatus.STOPPED,
            config=resolved_config,
        )
        session.add(hp)
        await session.flush()
        hp_id = hp.id

    container_id = await engine.start(resolved_name, resolved_port, resolved_config)

    async with get_session() as session:
        hp = await queries.get_honeypot_by_id(session, hp_id)
        if hp:
            hp.status = HoneypotStatus.RUNNING
            hp.container_id = container_id

    return {
        "id": hp_id,
        "name": resolved_name,
        "type": type,
        "port": resolved_port,
        "status": "running",
        "container_id": container_id,
    }


@mcp.tool
async def honeypot_list(
    status: Literal["running", "stopped", "paused", "error"] | None = None,
) -> list[dict[str, Any]]:
    """List all honeypots with their current status and hit counts.

    Args:
        status: Filter by status (running, stopped, paused, error). Omit for all.
    """
    hp_status = HoneypotStatus(status) if status else None
    async with get_session() as session:
        honeypots = await queries.list_honeypots(session, status=hp_status)
        result = []
        for hp in honeypots:
            hits = await queries.get_honeypot_hit_count(session, hp.id)
            result.append({
                "id": hp.id,
                "name": hp.name,
                "type": hp.type.value,
                "port": hp.port,
                "status": hp.status.value,
                "hits": hits,
                "container_id": hp.container_id,
                "created_at": hp.created_at.isoformat() if hp.created_at else None,
            })
    return result


@mcp.tool
async def honeypot_status(name: str) -> dict[str, Any]:
    """Get detailed status and recent events for a specific honeypot.

    Args:
        name: The honeypot name.
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}

        hits = await queries.get_honeypot_hit_count(session, hp.id)
        recent = await queries.get_recent_alerts(session, limit=10, honeypot_id=hp.id)

        engine = get_engine(hp.type)
        engine_status = {}
        if hp.container_id:
            engine_status = await engine.status(hp.container_id)

        return {
            "id": hp.id,
            "name": hp.name,
            "type": hp.type.value,
            "port": hp.port,
            "status": hp.status.value,
            "container_id": hp.container_id,
            "total_hits": hits,
            "config": hp.config,
            "created_at": hp.created_at.isoformat() if hp.created_at else None,
            "engine_status": engine_status,
            "recent_alerts": [
                {
                    "id": a.id,
                    "source_ip": a.source_ip,
                    "event_type": a.event_type,
                    "severity": a.severity.value,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in recent
            ],
        }


@mcp.tool
async def honeypot_stop(name: str, remove: bool = False) -> dict[str, Any]:
    """Stop a running honeypot.

    Args:
        name: The honeypot name.
        remove: If True, also remove the container and DB record entirely.
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}

        if hp.status == HoneypotStatus.STOPPED:
            return {"error": f"Honeypot '{name}' is already stopped."}

        engine = get_engine(hp.type)
        if hp.container_id:
            await engine.stop(hp.container_id, remove=remove)

        if remove:
            await session.delete(hp)
        else:
            hp.status = HoneypotStatus.STOPPED
            hp.container_id = None

    return {"name": name, "action": "removed" if remove else "stopped", "status": "ok"}


@mcp.tool
async def honeypot_pause(name: str) -> dict[str, Any]:
    """Pause a running honeypot without removing it.

    Args:
        name: The honeypot name.
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}
        if hp.status != HoneypotStatus.RUNNING:
            return {"error": f"Honeypot '{name}' is not running (status={hp.status.value})."}

        engine = get_engine(hp.type)
        if hp.container_id:
            await engine.pause(hp.container_id)
        hp.status = HoneypotStatus.PAUSED

    return {"name": name, "status": "paused"}


@mcp.tool
async def honeypot_resume(name: str) -> dict[str, Any]:
    """Resume a paused honeypot.

    Args:
        name: The honeypot name.
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}
        if hp.status != HoneypotStatus.PAUSED:
            return {"error": f"Honeypot '{name}' is not paused (status={hp.status.value})."}

        engine = get_engine(hp.type)
        if hp.container_id:
            await engine.resume(hp.container_id)
        hp.status = HoneypotStatus.RUNNING

    return {"name": name, "status": "running"}


@mcp.tool
async def honeypot_configure(name: str, config: dict[str, Any]) -> dict[str, Any]:
    """Update the configuration for an existing honeypot.
    Changes take effect after the next stop/start cycle.

    Args:
        name: The honeypot name.
        config: Key-value pairs to merge into the current config.
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}
        hp.config = {**hp.config, **config}

    return {"name": name, "config": hp.config, "note": "Restart honeypot to apply changes."}


@mcp.tool
async def honeypot_logs(name: str, lines: int = 50) -> dict[str, Any]:
    """Fetch recent raw logs from a honeypot container.

    Args:
        name: The honeypot name.
        lines: Number of log lines to return (default 50).
    """
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}' found."}
        if not hp.container_id:
            return {"error": f"Honeypot '{name}' has no running container."}

        engine = get_engine(hp.type)
        log_data = await engine.get_logs(hp.container_id, lines=lines)

    return {"name": name, "lines": lines, "logs": log_data}


@mcp.tool
async def honeypot_templates() -> list[dict[str, Any]]:
    """List available pre-built honeypot profiles for each protocol type."""
    return [
        {
            "type": "ssh",
            "description": "SSH/Telnet honeypot using Cowrie. Captures credentials, commands, and file uploads.",
            "default_port": 2222,
            "config_options": ["fake_hostname", "fake_kernel", "max_sessions"],
        },
        {
            "type": "http",
            "description": "HTTP honeypot with configurable fake endpoints (admin panel, phpMyAdmin, .env, WordPress).",
            "default_port": 8080,
            "config_options": ["endpoints", "fake_server_header", "enable_ssl"],
        },
        {
            "type": "smtp",
            "description": "SMTP honeypot that captures spam/relay attempts and credential brute-force.",
            "default_port": 2525,
            "config_options": ["fake_banner", "fake_domain"],
        },
        {
            "type": "ftp",
            "description": "FTP honeypot capturing login attempts and file transfer activity.",
            "default_port": 2121,
            "config_options": ["fake_banner", "fake_users"],
        },
        {
            "type": "dns",
            "description": "DNS honeypot logging all queries — useful for detecting C2 callbacks.",
            "default_port": 5353,
            "config_options": ["fake_records"],
        },
    ]


@mcp.tool
async def honeypot_clone(source_name: str, new_port: int, new_name: str | None = None) -> dict[str, Any]:
    """Clone an existing honeypot with a new port (and optionally a new name).

    Args:
        source_name: Name of the honeypot to clone.
        new_port: Port for the cloned honeypot.
        new_name: Name for the clone (auto-generated if omitted).
    """
    async with get_session() as session:
        source = await queries.get_honeypot_by_name(session, source_name)
        if not source:
            return {"error": f"No honeypot named '{source_name}' found."}
        clone_name = new_name or f"{source.type.value}-{secrets.token_hex(4)}"
        clone_config = dict(source.config)
        clone_type = source.type.value

    return await honeypot_deploy(
        type=clone_type,  # type: ignore[arg-type]
        port=new_port,
        name=clone_name,
        config=clone_config,
    )
