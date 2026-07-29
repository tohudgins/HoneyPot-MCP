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

import contextlib
import logging

from sqlalchemy import update

from honeypot_mcp.engines import get_engine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import (
    AlertSeverity,
    Honeypot,
    HoneypotStatus,
    HoneypotType,
)

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


async def adopt_labelled_containers() -> list[str]:
    """Attach ingestion to honeypot containers this process did not start.

    A Cowrie container is only ever a source of alerts if something is tailing
    its logs, and that only happens for containers with a `Honeypot` row
    pointing at them. Anything started outside the tool — most visibly the
    `cowrie-ssh` service in `docker/docker-compose.yml` — captures the attack
    perfectly in its own logs and produces nothing, while `docker ps` and the
    port both look healthy. Following the README (`docker compose up`, then SSH
    to :2222) reproduced exactly that: a full interactive session, zero alerts.

    So containers labelled `honeypot-mcp=true` are adopted here: a row is
    created (or an existing row is re-pointed) and the engine's `reattach`
    starts ingestion. Matching is by the `honeypot-name` label, falling back to
    the container name.

    Only SSH is adopted. It is the sole Docker-backed engine; every other type
    runs in-process and cannot exist as a container we did not start.
    """
    try:
        import docker
    except ImportError:
        return []

    try:
        client = docker.from_env()  # type: ignore[attr-defined]
        containers = client.containers.list(filters={"label": "honeypot-mcp=true"})
    except Exception as e:
        log.debug("Container adoption skipped — Docker unavailable: %s", e)
        return []

    adopted: list[str] = []
    for container in containers:
        labels = container.labels or {}
        name = labels.get("honeypot-name") or container.name
        try:
            port = _published_port(container)
            if port is None:
                continue

            async with get_session() as session:
                existing = await queries.get_honeypot_by_port(session, port)
                # Already wired to this container *and* healthy — nothing to
                # do. A row left in ERROR is re-adopted rather than skipped:
                # otherwise a honeypot the watchdog marked dead once could
                # never be brought back, because the container id already
                # matched and adoption bailed out before fixing the status.
                if (
                    existing is not None
                    and existing.container_id == container.id
                    and existing.status is HoneypotStatus.RUNNING
                ):
                    continue
                target_id = existing.id if existing is not None else None
                config = dict(existing.config or {}) if existing is not None else {}
                if existing is None:
                    hp = Honeypot(
                        name=name,
                        type=HoneypotType.SSH,
                        port=port,
                        status=HoneypotStatus.RUNNING,
                        container_id=container.id,
                        config={},
                    )
                    session.add(hp)
                    await session.flush()
                    target_id = hp.id

            engine = get_engine(HoneypotType.SSH)
            await engine.reattach(name, port, config, container.id)

            async with get_session() as session:
                await session.execute(
                    update(Honeypot)
                    .where(Honeypot.id == target_id)
                    .values(container_id=container.id, status=HoneypotStatus.RUNNING)
                )
            adopted.append(name)
            log.info("Adopted externally-started honeypot container '%s' (ssh :%d).", name, port)
        except Exception as e:
            log.warning("Could not adopt container '%s': %s", name, e)

    return adopted


def _published_port(container: object) -> int | None:
    """Host port mapped to Cowrie's 2222/tcp, or None if it isn't published.

    An unpublished container is unreachable from outside Docker, so adopting
    it would register a honeypot nothing can attack.
    """
    try:
        ports = container.attrs["NetworkSettings"]["Ports"] or {}  # type: ignore[attr-defined]
    except Exception:
        return None
    bindings = ports.get("2222/tcp") or []
    for binding in bindings:
        with contextlib.suppress(TypeError, ValueError):
            return int(binding["HostPort"])
    return None


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
