"""SSH/Telnet honeypot engine — wraps the Cowrie Docker image."""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any

import docker
import docker.errors

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

COWRIE_IMAGE = "cowrie/cowrie:latest"

# Cowrie JSON log patterns we care about
_EVENT_MAP = {
    "cowrie.login.failed": ("ssh_login_failed", AlertSeverity.MEDIUM),
    "cowrie.login.success": ("ssh_login_success", AlertSeverity.HIGH),
    "cowrie.command.input": ("ssh_command_input", AlertSeverity.HIGH),
    "cowrie.session.connect": ("ssh_session_connect", AlertSeverity.LOW),
    "cowrie.session.closed": ("ssh_session_closed", AlertSeverity.LOW),
    "cowrie.session.file_download": ("ssh_file_download", AlertSeverity.CRITICAL),
    "cowrie.direct-tcpip.request": ("ssh_port_forward", AlertSeverity.HIGH),
}


class SSHEngine(HoneypotEngine):
    def __init__(self) -> None:
        try:
            self._client = docker.from_env()
        except docker.errors.DockerException as e:
            log.warning("Docker not available: %s — SSH engine will be non-functional.", e)
            self._client = None

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        if not self._client:
            raise RuntimeError("Docker is not available on this system.")

        loop = asyncio.get_event_loop()

        def _run() -> str:
            try:
                self._client.images.get(COWRIE_IMAGE)
            except docker.errors.ImageNotFound:
                log.info("Pulling Cowrie image (first run — this may take a minute)…")
                self._client.images.pull(COWRIE_IMAGE)

            env = {
                "COWRIE_HOSTNAME": config.get("fake_hostname", "ubuntu-server"),
                "COWRIE_KERNEL_VERSION": config.get("fake_kernel", "5.15.0-91-generic"),
            }
            container = self._client.containers.run(
                COWRIE_IMAGE,
                detach=True,
                name=f"honeypot-{name}",
                ports={"2222/tcp": port},
                environment=env,
                labels={"honeypot-mcp": "true", "honeypot-name": name},
                restart_policy={"Name": "unless-stopped"},
            )
            return container.id

        container_id = await loop.run_in_executor(None, _run)
        log.info("Cowrie SSH honeypot '%s' started on port %d (container=%s)", name, port, container_id[:12])
        asyncio.create_task(self._ingest_logs(name, container_id))
        return container_id

    async def stop(self, container_id: str, remove: bool = False) -> None:
        if not self._client:
            return
        loop = asyncio.get_event_loop()

        def _stop() -> None:
            try:
                c = self._client.containers.get(container_id)
                c.stop(timeout=5)
                if remove:
                    c.remove()
            except docker.errors.NotFound:
                pass

        await loop.run_in_executor(None, _stop)

    async def status(self, container_id: str) -> dict[str, Any]:
        if not self._client:
            return {"available": False}
        loop = asyncio.get_event_loop()

        def _status() -> dict:
            try:
                c = self._client.containers.get(container_id)
                return {
                    "docker_status": c.status,
                    "image": c.image.tags[0] if c.image.tags else COWRIE_IMAGE,
                    "started_at": c.attrs.get("State", {}).get("StartedAt"),
                }
            except docker.errors.NotFound:
                return {"docker_status": "not_found"}

        return await loop.run_in_executor(None, _status)

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        if not self._client:
            return []
        loop = asyncio.get_event_loop()

        def _logs() -> list[str]:
            try:
                c = self._client.containers.get(container_id)
                raw = c.logs(tail=lines, timestamps=True).decode("utf-8", errors="replace")
                return raw.splitlines()
            except docker.errors.NotFound:
                return []

        return await loop.run_in_executor(None, _logs)

    async def pause(self, container_id: str) -> None:
        if not self._client:
            return
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self._client.containers.get(container_id).pause())

    async def resume(self, container_id: str) -> None:
        if not self._client:
            return
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self._client.containers.get(container_id).unpause())

    async def _ingest_logs(self, honeypot_name: str, container_id: str) -> None:
        """Background task: tail Cowrie JSON logs and write alerts to the DB."""
        import json as _json

        if not self._client:
            return

        loop = asyncio.get_event_loop()

        def _get_container():
            try:
                return self._client.containers.get(container_id)
            except docker.errors.NotFound:
                return None

        # Look up honeypot DB id
        hp_db_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, honeypot_name)
            if hp:
                hp_db_id = hp.id

        log.debug("Starting log ingestion for SSH honeypot '%s'", honeypot_name)

        seen_lines: set[str] = set()
        while True:
            await asyncio.sleep(5)
            container = await loop.run_in_executor(None, _get_container)
            if container is None:
                break
            if container.status not in ("running",):
                break

            raw_logs = await loop.run_in_executor(
                None, lambda: container.logs(tail=20, timestamps=False).decode("utf-8", errors="replace")
            )
            for line in raw_logs.splitlines():
                if not line or line in seen_lines:
                    continue
                seen_lines.add(line)
                try:
                    entry = _json.loads(line)
                except ValueError:
                    continue

                event_id = entry.get("eventid", "")
                if event_id not in _EVENT_MAP:
                    continue

                event_type, severity = _EVENT_MAP[event_id]
                src_ip = entry.get("src_ip", "0.0.0.0")
                src_port = entry.get("src_port")

                payload = {k: v for k, v in entry.items() if k not in ("eventid", "src_ip", "src_port")}

                async with get_session() as session:
                    await queries.create_alert(
                        session,
                        honeypot_id=hp_db_id,
                        source_ip=src_ip,
                        source_port=src_port,
                        event_type=event_type,
                        payload=payload,
                        severity=severity,
                    )
                    from honeypot_mcp.storage.models import AttackerEvent
                    session.add(AttackerEvent(ip=src_ip, event_type=event_type, extra=payload))
