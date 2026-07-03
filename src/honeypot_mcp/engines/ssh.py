"""SSH/Telnet honeypot engine — wraps the Cowrie Docker image."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import docker.errors

import docker
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
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
    # Client banner exchange — useful for fingerprinting attacker tools
    # (e.g. libssh / Paramiko / OpenSSH variants) and for the self-test probe.
    "cowrie.client.version": ("ssh_client_version", AlertSeverity.LOW),
}


class SSHEngine(HoneypotEngine):
    def __init__(self) -> None:
        try:
            self._client = docker.from_env()  # type: ignore[attr-defined]
        except docker.errors.DockerException as e:
            log.warning("Docker not available: %s — SSH engine will be non-functional.", e)
            self._client = None
        # asyncio only holds weak references to tasks — without a strong ref
        # here, a running ingestion task is eligible for GC and event capture
        # stops silently. Keyed by container_id so reattach can dedup.
        self._ingest_tasks: dict[str, asyncio.Task] = {}

    def _spawn_ingest_task(self, name: str, container_id: str) -> None:
        existing = self._ingest_tasks.get(container_id)
        if existing is not None and not existing.done():
            return
        task = asyncio.create_task(
            self._ingest_logs(name, container_id), name=f"ssh-ingest-{name}"
        )
        self._ingest_tasks[container_id] = task

        def _cleanup(_task: asyncio.Task, cid: str = container_id) -> None:
            self._ingest_tasks.pop(cid, None)

        task.add_done_callback(_cleanup)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        if not self._client:
            raise RuntimeError("Docker is not available on this system.")

        from honeypot_mcp.engines.ssh_personas import (
            cowrie_env_vars,
            get_persona,
            pick_hostname,
            pick_random_persona_id,
        )

        # Pick + persist a persona on first start. Stable across restarts so the
        # same honeypot always presents the same identity.
        if "ssh_persona" not in config:
            persona_id = pick_random_persona_id()
            persona_obj = get_persona(persona_id)
            config["ssh_persona"] = persona_id
            config["ssh_hostname"] = pick_hostname(persona_obj)
            async with get_session() as session:
                from sqlalchemy import update

                from honeypot_mcp.storage.models import Honeypot

                await session.execute(
                    update(Honeypot).where(Honeypot.name == name).values(config=config)
                )

        persona = get_persona(config.get("ssh_persona"))
        hostname = config.get("ssh_hostname") or persona.hostname_pool[0]

        # Allow user-config to override the persona's choice (escape hatch).
        if "fake_hostname" in config:
            hostname = config["fake_hostname"]

        env = cowrie_env_vars(persona, hostname)
        if "fake_kernel" in config:
            env["COWRIE_KERNEL_VERSION"] = config["fake_kernel"]
            env["COWRIE_HONEYPOT_KERNEL_VERSION"] = config["fake_kernel"]

        log.info(
            "SSH honeypot '%s' deploying as persona=%s hostname=%s",
            name,
            persona.id,
            hostname,
        )

        # Opt-in Telnet: setting `telnet_enabled=True` (or `telnet_port=<int>`)
        # in config exposes Cowrie's Telnet listener too. Telnet on 23 catches
        # the Mirai-class population that ignores SSH entirely — very high
        # volume on a public IP.
        telnet_enabled = bool(config.get("telnet_enabled")) or "telnet_port" in config
        telnet_port = int(config.get("telnet_port", 23))
        port_map: dict[str, int] = {"2222/tcp": port}
        if telnet_enabled:
            port_map["2223/tcp"] = telnet_port
            env["COWRIE_TELNET_ENABLED"] = "yes"

        loop = asyncio.get_event_loop()

        def _run() -> str:
            try:
                self._client.images.get(COWRIE_IMAGE)
            except docker.errors.ImageNotFound:
                log.info("Pulling Cowrie image (first run — this may take a minute)…")
                self._client.images.pull(COWRIE_IMAGE)

            container = self._client.containers.run(
                COWRIE_IMAGE,
                detach=True,
                name=f"honeypot-{name}",
                ports=port_map,
                environment=env,
                labels={
                    "honeypot-mcp": "true",
                    "honeypot-name": name,
                    "honeypot-persona": persona.id,
                    "honeypot-telnet": "yes" if telnet_enabled else "no",
                },
                restart_policy={"Name": "unless-stopped"},
            )
            return container.id

        container_id = await loop.run_in_executor(None, _run)
        log.info(
            "Cowrie SSH honeypot '%s' started on port %d (container=%s, persona=%s)",
            name,
            port,
            container_id[:12],
            persona.id,
        )
        self._spawn_ingest_task(name, container_id)
        return container_id

    async def reattach(self, name: str, port: int, config: dict[str, Any], container_id: str) -> str:
        """The Cowrie container survives an MCP server restart
        (restart_policy=unless-stopped), but the log-ingestion task dies with
        the process — without re-attaching it, attacks land in Cowrie's logs
        and never become alerts while every health check still passes."""
        if not self._client:
            raise RuntimeError("Docker is not available on this system.")
        loop = asyncio.get_event_loop()

        def _container_status() -> str:
            try:
                return self._client.containers.get(container_id).status
            except docker.errors.NotFound:
                return "not_found"

        status = await loop.run_in_executor(None, _container_status)
        if status == "not_found":
            raise RuntimeError(f"Container {container_id[:12]} no longer exists.")
        if status != "running":
            # exited/created — bring the existing container (and its persona
            # identity + captured state) back rather than deploying a new one.
            await loop.run_in_executor(None, self._client.containers.get(container_id).start)
        self._spawn_ingest_task(name, container_id)
        log.info("Re-attached log ingestion for SSH honeypot '%s' (container=%s)", name, container_id[:12])
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

    async def health_check(self, container_id: str, port: int) -> dict[str, Any]:
        """SSH health: container is running AND the port is responsive.
        Catches Cowrie crashing inside an otherwise-running container."""
        if not self._client:
            return {"alive": False, "detail": "Docker not available", "method": "docker"}

        loop = asyncio.get_event_loop()

        def _docker_state() -> dict[str, Any]:
            try:
                c = self._client.containers.get(container_id)
                return {"docker_status": c.status, "running": c.status == "running"}
            except docker.errors.NotFound:
                return {"docker_status": "not_found", "running": False}

        state = await loop.run_in_executor(None, _docker_state)
        if not state["running"]:
            return {
                "alive": False,
                "detail": f"Container {state['docker_status']}",
                "method": "docker",
                "docker_status": state["docker_status"],
            }

        from honeypot_mcp.engines.base import tcp_probe

        tcp = await tcp_probe(port)
        return {
            "alive": tcp["alive"],
            "detail": "container running, port responsive"
            if tcp["alive"]
            else f"container running but {tcp['detail']}",
            "method": "docker+tcp",
            "docker_status": state["docker_status"],
        }

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
        await loop.run_in_executor(
            None, lambda: self._client.containers.get(container_id).unpause()
        )

    async def _ingest_logs(self, honeypot_name: str, container_id: str) -> None:
        """Background task: tail Cowrie JSON logs and write alerts to the DB.

        Uses the Docker `since` parameter to fetch only new lines per poll, so we
        don't lose events under burst load and don't re-process history. A small
        bounded deque dedups boundary cases (when `since` returns a line we just
        saw on the previous poll due to docker's per-second timestamp granularity).
        """
        import json as _json
        from collections import deque
        from datetime import timedelta

        if not self._client:
            return

        loop = asyncio.get_event_loop()

        def _get_container():
            try:
                return self._client.containers.get(container_id)
            except docker.errors.NotFound:
                return None

        hp_db_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, honeypot_name)
            if hp:
                hp_db_id = hp.id

        log.debug("Starting log ingestion for SSH honeypot '%s'", honeypot_name)

        recent_hashes: deque[int] = deque(maxlen=512)
        seen: set[int] = set()
        # Start two seconds in the past to avoid missing logs written between
        # container start and the first poll.
        last_check = datetime.now(UTC) - timedelta(seconds=2)

        while True:
            await asyncio.sleep(2)
            container = await loop.run_in_executor(None, _get_container)
            if container is None:
                break
            if container.status != "running":
                break

            now = datetime.now(UTC)
            try:

                def _fetch_logs(c: Any = container, s: Any = last_check) -> str:
                    return c.logs(since=s, timestamps=False).decode("utf-8", errors="replace")

                raw_logs = await loop.run_in_executor(None, _fetch_logs)
            except Exception as e:
                log.debug("Log fetch error for %s: %s", honeypot_name, e)
                continue
            last_check = now

            for line in raw_logs.splitlines():
                if not line:
                    continue
                h = hash(line)
                if h in seen:
                    continue
                if len(recent_hashes) == recent_hashes.maxlen:
                    seen.discard(recent_hashes[0])
                recent_hashes.append(h)
                seen.add(h)

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
                payload = {
                    k: v for k, v in entry.items() if k not in ("eventid", "src_ip", "src_port")
                }

                await submit_event(
                    PendingEvent(
                        honeypot_id=hp_db_id,
                        source_ip=src_ip,
                        source_port=src_port,
                        event_type=event_type,
                        payload=payload,
                        severity=severity,
                    )
                )
