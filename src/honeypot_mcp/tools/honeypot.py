"""Honeypot management MCP tools."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
from datetime import UTC, datetime
from typing import Any, Literal

from honeypot_mcp.engines import get_engine
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType


@mcp.tool
async def honeypot_deploy(
    type: Literal[
        "ssh",
        "http",
        "smtp",
        "ftp",
        "dns",
        "rdp",
        "vnc",
        "redis",
        "mysql",
        "elasticsearch",
    ],
    port: int | None = None,
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a new honeypot container.

    Args:
        type: Protocol type — ssh, http, smtp, ftp, dns, rdp, vnc, redis,
              mysql, or elasticsearch.
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
        "rdp": settings.default_rdp_port,
        "vnc": settings.default_vnc_port,
        "redis": settings.default_redis_port,
        "mysql": settings.default_mysql_port,
        "elasticsearch": settings.default_elasticsearch_port,
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
        hp_refresh = await queries.get_honeypot_by_id(session, hp_id)
        if hp_refresh:
            hp_refresh.status = HoneypotStatus.RUNNING
            hp_refresh.container_id = container_id

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
        ids = [hp.id for hp in honeypots]
        counts = await queries.get_hit_counts(session, ids) if ids else {}
        result = [
            {
                "id": hp.id,
                "name": hp.name,
                "type": hp.type.value,
                "port": hp.port,
                "status": hp.status.value,
                "hits": counts.get(hp.id, 0),
                "container_id": hp.container_id,
                "created_at": hp.created_at.isoformat() if hp.created_at else None,
            }
            for hp in honeypots
        ]
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
async def honeypot_health(name: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
    """Check whether honeypots are actually responding (port probe + container status).

    A honeypot whose process or container has died will still appear 'running'
    in `honeypot_list` because the DB row says so. This tool actually probes the
    port and (for SSH) the Docker container, surfacing silent failures.

    Args:
        name: Specific honeypot to check. Omit to check all running honeypots.
    """
    async with get_session() as session:
        if name:
            hp = await queries.get_honeypot_by_name(session, name)
            if not hp:
                return {"error": f"No honeypot named '{name}'."}
            honeypots = [hp]
        else:
            honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)

    results: list[dict[str, Any]] = []
    for hp in honeypots:
        entry: dict[str, Any] = {
            "name": hp.name,
            "type": hp.type.value,
            "port": hp.port,
            "status": hp.status.value,
        }
        if hp.container_id is None:
            entry.update(
                {"alive": False, "detail": "No container_id — never started?", "method": "none"}
            )
        else:
            try:
                engine = get_engine(hp.type)
                health = await engine.health_check(hp.container_id, hp.port)
                entry.update(health)
            except Exception as e:
                entry.update(
                    {"alive": False, "detail": f"Health check error: {e}", "method": "error"}
                )
        results.append(entry)

    if name and len(results) == 1:
        return results[0]
    return results


@mcp.tool
async def honeypot_self_test(name: str, timeout_seconds: int = 15) -> dict[str, Any]:
    """End-to-end smoke test: send a synthetic probe to the honeypot's port and
    confirm an alert with our unique marker shows up in the DB. Catches subtle
    pipeline breakage that `honeypot_health` can miss — e.g. event buffer dead,
    suppression eating events, or an engine that accepts connections but never
    logs them.

    The probe is protocol-appropriate (SSH banner / HTTP request / SMTP AUTH /
    FTP USER / DNS query) and embeds a random marker in a field that lands in
    the alert payload. We then poll for an alert containing that marker.

    Args:
        name: The honeypot name to probe.
        timeout_seconds: How long to wait for the probe alert to appear
                         (default 15 — SSH needs ~5-10s due to Cowrie log polling).
    """
    from sqlalchemy import String, cast, select

    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, name)
        if not hp:
            return {"error": f"No honeypot named '{name}'."}
        if hp.status != HoneypotStatus.RUNNING:
            return {"error": f"Honeypot '{name}' is not running (status={hp.status.value})."}
        hp_id = hp.id
        hp_type = hp.type.value
        hp_port = hp.port

    marker = f"selftest_{secrets.token_hex(6)}"
    probe_start = datetime.now(UTC)

    sent_ok, send_detail = await _send_probe(hp_type, hp_port, marker)
    if not sent_ok:
        return {
            "name": name,
            "type": hp_type,
            "probe_sent": False,
            "alert_received": False,
            "detail": send_detail,
        }

    deadline_loops = max(1, timeout_seconds)
    for _ in range(deadline_loops):
        await asyncio.sleep(1)
        async with get_session() as session:
            result = await session.execute(
                select(Alert)
                .where(
                    Alert.honeypot_id == hp_id,
                    Alert.timestamp >= probe_start,
                    cast(Alert.payload, String).contains(marker),
                )
                .limit(1)
            )
            match = result.scalar_one_or_none()
            if match:
                duration = (datetime.now(UTC) - probe_start).total_seconds()
                return {
                    "name": name,
                    "type": hp_type,
                    "probe_marker": marker,
                    "probe_sent": True,
                    "probe_detail": send_detail,
                    "alert_received": True,
                    "alert_id": match.id,
                    "alert_event_type": match.event_type,
                    "duration_seconds": round(duration, 2),
                    "detail": "End-to-end pipeline working — probe was captured as an alert.",
                }

    return {
        "name": name,
        "type": hp_type,
        "probe_marker": marker,
        "probe_sent": True,
        "probe_detail": send_detail,
        "alert_received": False,
        "detail": (
            f"Probe sent but no matching alert within {timeout_seconds}s. "
            "Possible causes: honeypot crashed (run honeypot_health), suppression "
            "rule is dropping the event, or the event buffer flusher has stalled."
        ),
    }


async def _send_probe(hp_type: str, port: int, marker: str) -> tuple[bool, str]:
    """Dispatch to the per-protocol probe. Each probe embeds `marker` in a
    field that the engine writes into the alert payload."""
    try:
        if hp_type == "ssh":
            return await _ssh_probe(port, marker)
        if hp_type == "http":
            return await _http_probe(port, marker)
        if hp_type == "smtp":
            return await _smtp_probe(port, marker)
        if hp_type == "ftp":
            return await _ftp_probe(port, marker)
        if hp_type == "dns":
            return await _dns_probe(port, marker)
        return False, f"No self-test probe defined for honeypot type {hp_type}"
    except Exception as e:
        return False, f"Probe failed: {e}"


async def _ssh_probe(port: int, marker: str) -> tuple[bool, str]:
    """Open a TCP connection and send an SSH banner containing the marker.
    Cowrie logs `cowrie.client.version` with the banner — the marker lands in
    the version field of the alert payload."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(f"SSH-2.0-{marker}\r\n".encode())
        await writer.drain()
        # Give Cowrie a beat to log the version event before we tear down.
        await asyncio.sleep(0.5)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "SSH banner sent"


async def _http_probe(port: int, marker: str) -> tuple[bool, str]:
    """HTTP GET with marker in the User-Agent — lands in payload['user_agent']."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"http://127.0.0.1:{port}/.env",
            headers={"User-Agent": f"HoneyPotSelfTest/{marker}"},
        )
    return True, f"HTTP {resp.status_code}"


async def _smtp_probe(port: int, marker: str) -> tuple[bool, str]:
    """AUTH PLAIN with marker as the credentials blob — lands in payload['command']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"EHLO selftest.local\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=3.0)
        writer.write(f"AUTH PLAIN {marker}\r\n".encode())
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "SMTP AUTH sent"


async def _ftp_probe(port: int, marker: str) -> tuple[bool, str]:
    """USER + PASS — marker goes in the username, lands in payload['username']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(f"USER {marker}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"PASS x\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "FTP USER+PASS sent"


async def _dns_probe(port: int, marker: str) -> tuple[bool, str]:
    """DNS query for `<marker>.selftest` — marker lands in payload['qname']."""
    try:
        import dnslib
    except ImportError:
        return False, "dnslib not installed — cannot self-test DNS"

    class _Probe(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.received = asyncio.Event()

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            self.received.set()

    loop = asyncio.get_event_loop()
    proto = _Probe()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: proto, remote_addr=("127.0.0.1", port)
    )
    try:
        query = dnslib.DNSRecord.question(f"{marker}.selftest").pack()
        transport.sendto(query)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proto.received.wait(), timeout=2.0)
    finally:
        transport.close()
    return True, "DNS query sent"


@mcp.tool
async def honeypot_clone(
    source_name: str, new_port: int, new_name: str | None = None
) -> dict[str, Any]:
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
