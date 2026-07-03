"""Startup reconciliation of honeypot state.

MCP clients launch this server as a stdio subprocess per session, so every
new chat is a process restart. Anything the DB says is RUNNING needs to be
re-established:

* In-process engines (HTTP/SMTP/FTP/DNS/RDP/VNC/Redis/MySQL/Elasticsearch)
  died with the previous process — restart them on their recorded port.
* Cowrie SSH containers survive (restart_policy=unless-stopped), but the
  log-ingestion task must be re-attached or attacks are captured by Cowrie
  and never become alerts — while health checks keep passing.

Each engine's `reattach()` encapsulates the right behaviour; this module
just drives it across the fleet. Failures flip the honeypot to ERROR and
emit a CRITICAL alert through the normal pipeline (same signal path as the
watchdog), never abort startup.

Runs from `server.py:lifespan` after the event buffer starts and BEFORE the
watchdog, so the watchdog doesn't race us to mark restartable honeypots dead.
"""

from __future__ import annotations

import logging

from sqlalchemy import update

from honeypot_mcp.engines import get_engine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity, Honeypot, HoneypotStatus

log = logging.getLogger(__name__)


async def reconcile_running_honeypots() -> dict[str, list[str]]:
    """Re-establish every DB-RUNNING honeypot. Returns {"reattached": [names], "failed": [names]}."""
    async with get_session() as session:
        honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)
        targets = [
            (hp.id, hp.name, hp.type, hp.port, dict(hp.config or {}), hp.container_id)
            for hp in honeypots
        ]

    reattached: list[str] = []
    failed: list[str] = []
    for hp_id, name, hp_type, port, config, container_id in targets:
        try:
            engine = get_engine(hp_type)
            new_cid = await engine.reattach(name, port, config, container_id or "")
        except Exception as e:
            log.warning("Could not re-establish honeypot '%s' after restart: %s", name, e)
            failed.append(name)
            await _mark_failed(hp_id, name, str(e))
            continue

        if new_cid != container_id:
            async with get_session() as session:
                await session.execute(
                    update(Honeypot).where(Honeypot.id == hp_id).values(container_id=new_cid)
                )
        reattached.append(name)
        log.info("Honeypot '%s' (%s :%d) re-established after restart.", name, hp_type.value, port)

    if reattached or failed:
        log.info(
            "Startup reconciliation: %d re-established, %d failed.", len(reattached), len(failed)
        )
    return {"reattached": reattached, "failed": failed}


async def _mark_failed(hp_id: int, name: str, detail: str) -> None:
    async with get_session() as session:
        await session.execute(
            update(Honeypot).where(Honeypot.id == hp_id).values(status=HoneypotStatus.ERROR)
        )
    await submit_event(
        PendingEvent(
            honeypot_id=hp_id,
            source_ip="0.0.0.0",
            event_type="honeypot_restart_failed",
            payload={"name": name, "detail": detail},
            severity=AlertSeverity.CRITICAL,
        )
    )
