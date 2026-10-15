"""SSH/Telnet honeypot engine — wraps the Cowrie Docker image."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.resources
import io
import ipaddress
import json
import logging
import tarfile
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

import docker.errors
import docker.types

import docker
from honeypot_mcp import self_probe
from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.cowrie_fs import (
    BASE_PICKLE_PATH,
    PERSONA_DIR,
    PERSONA_PICKLE_PATH,
    build_persona_fs,
    persona_tar,
)
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# The bundled filesystem is ~1.2 MB; anything much larger is not the file we expect.
_MAX_BASE_PICKLE_BYTES = 16 * 1024 * 1024


def _sitecustomize_source() -> bytes:
    """`cowrie_sitecustomize.py` as bytes, read through the package so it works from a wheel."""
    return (
        importlib.resources.files("honeypot_mcp.engines")
        .joinpath("cowrie_sitecustomize.py")
        .read_bytes()
    )


def _deliver_persona_fs(
    container: Any,
    persona: Any,
    hostname: str,
    seed: str,
    credential: tuple[str, str] | None = None,
) -> None:
    """Copy a persona-specific filesystem into a created (not yet started) container.

    Reads Cowrie's own bundled `fs.pickle` out of the container, rewrites it so
    /etc/hostname, /etc/issue, /etc/os-release, /proc/version, the accounts and
    /home describe `persona` (see `cowrie_fs`), and puts the result back under
    `PERSONA_PICKLE_PATH`, which `COWRIE_SHELL_FILESYSTEM` points at. Raises on any
    problem; the caller falls back to Cowrie's default rather than failing a deploy.
    """
    stream, _stat = container.get_archive(BASE_PICKLE_PATH)
    raw = b""
    for chunk in stream:
        raw += chunk
        if len(raw) > _MAX_BASE_PICKLE_BYTES + 1_000_000:
            raise ValueError("Cowrie's filesystem pickle is far larger than expected")
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        member = next((m for m in tar.getmembers() if m.isfile()), None)
        extracted = tar.extractfile(member) if member is not None else None
        if extracted is None or member is None or member.size > _MAX_BASE_PICKLE_BYTES:
            raise ValueError("no usable filesystem pickle in the Cowrie image")
        base = extracted.read()
    built = build_persona_fs(base, persona, hostname, seed, credential)
    if not container.put_archive(PERSONA_DIR, persona_tar(built, _sitecustomize_source())):
        raise RuntimeError("Docker refused the persona filesystem archive")


from honeypot_mcp.engines.cowrie_limits import (  # noqa: E402 (a spec shared with the Docker guard)
    COWRIE_IMAGE,
    COWRIE_INTERNAL_PORT,
    COWRIE_LOG_MAX_FILES,
    COWRIE_LOG_MAX_SIZE,
    COWRIE_MEM_LIMIT,
    COWRIE_NANO_CPUS,
    COWRIE_PIDS_LIMIT,
    COWRIE_TELNET_PORT,
    COWRIE_TMPFS,
)

# Cowrie JSON log patterns we care about
_EVENT_MAP = {
    "cowrie.login.failed": ("ssh_login_failed", AlertSeverity.MEDIUM),
    "cowrie.login.success": ("ssh_login_success", AlertSeverity.HIGH),
    "cowrie.command.input": ("ssh_command_input", AlertSeverity.HIGH),
    "cowrie.session.connect": ("ssh_session_connect", AlertSeverity.LOW),
    "cowrie.session.closed": ("ssh_session_closed", AlertSeverity.LOW),
    "cowrie.session.file_download": ("ssh_file_download", AlertSeverity.CRITICAL),
    # SCP/SFTP push of a payload into the honeypot — same value as a wget
    # download and previously dropped on the floor, because an unmapped
    # eventid is skipped entirely by the ingester.
    "cowrie.session.file_upload": ("ssh_file_upload", AlertSeverity.CRITICAL),
    "cowrie.direct-tcpip.request": ("ssh_port_forward", AlertSeverity.HIGH),
    # Client banner exchange — useful for fingerprinting attacker tools
    # (e.g. libssh / Paramiko / OpenSSH variants) and for the self-test probe.
    "cowrie.client.version": ("ssh_client_version", AlertSeverity.LOW),
    # The client's key-exchange offer. Its HASSH (an MD5 of the algorithm lists, in
    # the offer's order) identifies the SSH *implementation* behind a connection, not
    # the address: the same botnet binary produces the same HASSH from every IP it
    # runs on, which is what lets an analyst cluster scattered sources into one
    # campaign. Cowrie computes it; it was being discarded as an unmapped eventid.
    "cowrie.client.kex": ("ssh_client_kex", AlertSeverity.LOW),
    # A public key offered for authentication: the fingerprint ties together logins
    # by the same attacker key (and is what a planted key's trip-wire matches on).
    "cowrie.client.fingerprint": ("ssh_pubkey_attempt", AlertSeverity.MEDIUM),
    # What an attacker pushes through the SSH proxy once a direct-tcpip channel is
    # open: the request line / payload (spam relays, scan traffic, C2 hops) and its
    # JA4H fingerprint. The channel *request* was recorded; its content was not.
    "cowrie.direct-tcpip.data": ("ssh_port_forward_data", AlertSeverity.HIGH),
    "cowrie.direct-tcpip.ja4h": ("ssh_port_forward_ja4h", AlertSeverity.LOW),
}

# Fields kept from a key-exchange event: the fingerprint and the algorithm offers
# it was computed from, each list capped (a real offer is ~10-30 names).
_KEX_KEEP = ("hassh", "hasshAlgorithms", "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS")
_KEX_LIST_CAP = 40
_FORWARDED_DATA_CAP = 2048


def _shape_payload(event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Trim fields that are bulky and add nothing once the fingerprint is recorded."""
    if event_type.endswith("_client_kex"):
        shaped = {k: v for k, v in payload.items() if k not in _KEX_KEEP and k != "langCS"}
        for key in _KEX_KEEP:
            value = payload.get(key)
            if isinstance(value, list):
                value = [str(v)[:64] for v in value[:_KEX_LIST_CAP]]
            elif isinstance(value, str):
                value = value[:1024]
            if value is not None:
                shaped[key] = value
        return shaped
    if event_type.endswith("_port_forward_data") and isinstance(payload.get("data"), str):
        data = payload["data"]
        return {
            **payload,
            "data": data[:_FORWARDED_DATA_CAP],
            "data_bytes": len(data),
            "data_truncated": len(data) > _FORWARDED_DATA_CAP,
        }
    return payload


def _retag_for_protocol(event_type: str, protocol: str | None) -> str:
    """Rewrite an `ssh_*` event type to `telnet_*` when Cowrie says so.

    One Cowrie container serves both protocols, and its event ids are shared —
    a Telnet login emits `cowrie.login.success` exactly like an SSH one, with
    only the `protocol` field to tell them apart. Taking the mapping at face
    value filed every Telnet capture under `ssh_*`, which quietly mattered:
    Telnet disappeared as a distinct attack surface in every dashboard and
    statistic, ATT&CK mapped it as SSH brute force, and planted credentials
    tried over Telnet were cross-referenced against the wrong service.

    Telnet on port 23 is a large share of internet background radiation —
    Mirai and its descendants — so it is worth counting separately.
    """
    if protocol == "telnet" and event_type.startswith("ssh_"):
        return f"telnet_{event_type[4:]}"
    return event_type


class SSHEngine(HoneypotEngine):
    # Docker can freeze the container, so pause/resume below are real. Every in-process engine
    # leaves this False and the tools pause it by closing its listener instead.
    native_pause = True

    # Which of Cowrie's two listeners this engine publishes as its primary
    # service. `TelnetEngine` flips it to 2223 rather than duplicating the
    # whole container-launch path — one image serves both protocols, and the
    # only real differences are which port is mapped and whether Cowrie's
    # telnet listener is switched on.
    _PRIMARY_CONTAINER_PORT = COWRIE_INTERNAL_PORT
    _PRIMARY_IS_TELNET = False

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
        # container_id -> honeypot name, for every container we have started
        # ingestion for. Lets health_check tell "no ingestion expected" from
        # "ingestion died" and respawn it.
        self._ingest_names: dict[str, str] = {}
        # container_id -> how far its logs have been read. Survives task
        # restarts so a respawn resumes instead of skipping the gap.
        self._ingest_cursor: dict[str, datetime] = {}

    def _spawn_ingest_task(self, name: str, container_id: str) -> None:
        self._ingest_names[container_id] = name
        existing = self._ingest_tasks.get(container_id)
        if existing is not None and not existing.done():
            return
        task = spawn(self._supervise_ingest(name, container_id), name=f"ssh-ingest-{name}")
        self._ingest_tasks[container_id] = task

        def _cleanup(done: asyncio.Task, cid: str = container_id) -> None:
            # Only drop our own entry: a respawn may already have replaced it.
            if self._ingest_tasks.get(cid) is done:
                self._ingest_tasks.pop(cid, None)

        task.add_done_callback(_cleanup)

    def _ingest_alive(self, container_id: str) -> bool:
        task = self._ingest_tasks.get(container_id)
        return task is not None and not task.done()

    async def _supervise_ingest(self, name: str, container_id: str) -> None:
        """Run `_ingest_logs`, restarting it with backoff if it raises.

        A clean return means the container is gone or stopped — nothing left to
        tail. An exception used to end ingestion permanently while health
        checks stayed green, so every later attack went unrecorded.
        """
        delay = 1.0
        while True:
            started = time.monotonic()
            try:
                await self._ingest_logs(name, container_id)
                return
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception(
                    "Log ingestion for SSH honeypot '%s' crashed; restarting in %.0fs", name, delay
                )
            if time.monotonic() - started > 60.0:
                delay = 1.0  # it ran fine for a while: this is a fresh failure, not a crash loop
            await asyncio.sleep(delay)
            delay = min(delay * 2, 60.0)

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

        env = cowrie_env_vars(persona, hostname, allow_egress=get_settings().cowrie_allow_egress)
        if "fake_kernel" in config:
            env["COWRIE_SHELL_KERNEL_VERSION"] = config["fake_kernel"]
        # Cowrie reads the persona's filesystem (hostname, issue, os-release,
        # /proc/version, accounts, home directory) from here once it is delivered
        # into the container; see `_deliver_persona_fs`.
        env["COWRIE_SHELL_FILESYSTEM"] = PERSONA_PICKLE_PATH
        # Artifact clean-up runs inside the container (see cowrie_sitecustomize.prune_artifacts).
        env["HONEYPOT_JANITOR_INTERVAL"] = str(get_settings().cowrie_janitor_interval_seconds)
        env["HONEYPOT_MAX_TTY"] = str(get_settings().cowrie_max_tty_files)
        # A tracked MySQL credential (if a token exists) is planted in the home directory as
        # bait; an attacker who replays it against our MySQL honeypot trips CRITICAL.
        from honeypot_mcp.credential_match import planted_credential

        try:
            bait = await planted_credential("mysql")
        except Exception:
            log.warning("Could not look up a bait credential for '%s'", name, exc_info=True)
            bait = None

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
        telnet_enabled = (
            self._PRIMARY_IS_TELNET or bool(config.get("telnet_enabled")) or "telnet_port" in config
        )
        port_map: dict[str, int] = {f"{self._PRIMARY_CONTAINER_PORT}/tcp": port}
        if telnet_enabled:
            env["COWRIE_TELNET_ENABLED"] = "yes"
        # On a Telnet honeypot the primary mapping already is the telnet
        # listener; only add a second mapping when SSH is primary and telnet
        # was requested as an extra.
        if telnet_enabled and not self._PRIMARY_IS_TELNET:
            port_map[f"{COWRIE_TELNET_PORT}/tcp"] = int(config.get("telnet_port", 23))

        loop = asyncio.get_event_loop()

        def _run() -> str:
            try:
                self._client.images.get(COWRIE_IMAGE)
            except docker.errors.ImageNotFound:
                log.info("Pulling Cowrie image (first run — this may take a minute)…")
                self._client.images.pull(COWRIE_IMAGE)

            def _create(container_env: dict[str, str], persona_volume: bool) -> Any:
                return self._client.containers.create(
                    COWRIE_IMAGE,
                    **(
                        {
                            "mounts": [
                                # An anonymous volume: writable to the Docker API (an
                                # archive cannot be extracted into a read-only rootfs),
                                # removed with the container by `remove(v=True)`.
                                docker.types.Mount(
                                    target=PERSONA_DIR,
                                    source=None,  # type: ignore[arg-type]
                                    type="volume",
                                )
                            ]
                        }
                        if persona_volume
                        else {}
                    ),
                    name=f"honeypot-{name}",
                    ports=port_map,
                    environment=container_env,
                    labels={
                        "honeypot-mcp": "true",
                        "honeypot-name": name,
                        "honeypot-persona": persona.id,
                        "honeypot-telnet": "yes" if telnet_enabled else "no",
                    },
                    restart_policy={"Name": "unless-stopped"},
                    # Attacker-facing: bound what a compromised/abused Cowrie can
                    # consume or do. Cowrie listens on unprivileged ports, so it
                    # needs no capabilities at all.
                    mem_limit=COWRIE_MEM_LIMIT,
                    pids_limit=COWRIE_PIDS_LIMIT,
                    nano_cpus=COWRIE_NANO_CPUS,
                    cap_drop=["ALL"],
                    # With egress closed, also stop wget/curl from emitting real DNS
                    # queries (a side channel: the sensor's resolver becomes visible and
                    # internal names probe-able by output differences) by pointing the
                    # container's resolver at its own loopback, where nothing listens.
                    **({} if get_settings().cowrie_allow_egress else {"dns": ["127.0.0.1"]}),
                    read_only=True,
                    tmpfs=COWRIE_TMPFS,
                    security_opt=["no-new-privileges:true"],
                    log_config=docker.types.LogConfig(
                        type=docker.types.LogConfig.types.JSON,
                        config={"max-size": COWRIE_LOG_MAX_SIZE, "max-file": COWRIE_LOG_MAX_FILES},
                    ),
                )

            # Created first, started after: the persona filesystem is copied in
            # while the container is stopped, so it is in place from Cowrie's first
            # instruction. It goes onto an anonymous volume, not the root filesystem:
            # Docker refuses to extract an archive into a read-only rootfs ("container
            # rootfs is marked read-only"), and a volume is writable to the Docker API
            # while Cowrie itself can still not alter its own root.
            container = _create(env, persona_volume=True)
            try:
                _deliver_persona_fs(container, persona, hostname, name, bait)
            except Exception as e:
                log.warning(
                    "Could not install the persona filesystem for SSH honeypot '%s' (%s). "
                    "Falling back to Cowrie's bundled one: its /etc and /home will not "
                    "match the %s persona, and the fingerprint hardening in "
                    "cowrie_sitecustomize (SSH key-exchange/host-key offer, telnet opening) "
                    "is not installed.",
                    name,
                    e,
                    persona.id,
                )
                with contextlib.suppress(Exception):
                    container.remove(force=True, v=True)
                container = _create(
                    {k: v for k, v in env.items() if k != "COWRIE_SHELL_FILESYSTEM"},
                    persona_volume=False,
                )
            container.start()
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

    def _warn_if_egress_open(self, container: Any) -> None:
        """An adopted container keeps the environment it was created with, so one
        made before the egress control existed still lets an attacker drive its
        wget/curl at the internet. Say so, once, rather than silently trusting it."""
        if get_settings().cowrie_allow_egress:
            return
        env = (container.attrs.get("Config") or {}).get("Env") or []
        if not any(str(e).startswith("COWRIE_HONEYPOT_OUT_ADDR=127.") for e in env):
            log.warning(
                "Cowrie container %s was created without COWRIE_HONEYPOT_OUT_ADDR=127.0.0.1: "
                "its wget/curl can still reach the internet. Recreate it (honeypot_stop "
                "with remove, then redeploy) to apply the egress control.",
                str(container.id)[:12],
            )

    async def reattach(
        self, name: str, port: int, config: dict[str, Any], container_id: str
    ) -> str:
        """The Cowrie container survives an MCP server restart
        (restart_policy=unless-stopped), but the log-ingestion task dies with
        the process — without re-attaching it, attacks land in Cowrie's logs
        and never become alerts while every health check still passes."""
        if not self._client:
            raise RuntimeError("Docker is not available on this system.")
        loop = asyncio.get_event_loop()

        def _prepare() -> str:
            """Make the container run again; return its prior status."""
            try:
                c = self._client.containers.get(container_id)
            except docker.errors.NotFound:
                return "not_found"
            previous = str(c.status)
            if previous == "paused":
                c.unpause()  # `start` on a paused container is an error
            elif previous != "running":
                # exited/created — bring the existing container (and its persona
                # identity + captured state) back rather than deploying a new one.
                c.start()
            self._warn_if_egress_open(c)
            return previous

        status = await loop.run_in_executor(None, _prepare)
        if status == "not_found":
            raise RuntimeError(f"Container {container_id[:12]} no longer exists.")
        self._spawn_ingest_task(name, container_id)
        log.info(
            "Re-attached log ingestion for SSH honeypot '%s' (container=%s)",
            name,
            container_id[:12],
        )
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
                    c.remove(v=True)  # also drops the anonymous persona volume
            except docker.errors.NotFound:
                pass

        await loop.run_in_executor(None, _stop)
        self._ingest_names.pop(container_id, None)
        self._ingest_cursor.pop(container_id, None)
        task = self._ingest_tasks.pop(container_id, None)
        if task is not None and not task.done():
            task.cancel()

    async def health_check(self, container_id: str, port: int) -> dict[str, Any]:
        """SSH health: container is running AND the port is responsive.
        Catches Cowrie crashing inside an otherwise-running container.

        The port is probed twice, because "the port" means different things
        depending on where this process runs. `port` is the *host* published
        port, reachable on loopback only when the server runs on the host. In
        the compose stack the server is itself a container and Cowrie is a
        sibling: `127.0.0.1:2222` there is the server's own empty loopback, and
        probing it declared a perfectly healthy honeypot dead every 30s —
        ERROR status plus a CRITICAL alert, while the honeypot went on
        capturing attacks. The fallback probes the container's own address on
        Cowrie's internal port, which is what a sibling can actually reach.
        """
        if not self._client:
            return {"alive": False, "detail": "Docker not available", "method": "docker"}

        loop = asyncio.get_event_loop()

        def _docker_state() -> dict[str, Any]:
            try:
                c = self._client.containers.get(container_id)
                networks = (c.attrs.get("NetworkSettings", {}) or {}).get("Networks", {}) or {}
                ips = [n.get("IPAddress") for n in networks.values() if n.get("IPAddress")]
                gateways = [n.get("Gateway") for n in networks.values() if n.get("Gateway")]
                return {
                    "docker_status": c.status,
                    "running": c.status == "running",
                    "container_ips": ips,
                    "gateways": gateways,
                }
            except docker.errors.NotFound:
                return {
                    "docker_status": "not_found",
                    "running": False,
                    "container_ips": [],
                    "gateways": [],
                }

        state = await loop.run_in_executor(None, _docker_state)
        if not state["running"]:
            return {
                "alive": False,
                "detail": f"Container {state['docker_status']}",
                "method": "docker",
                "docker_status": state["docker_status"],
            }

        from honeypot_mcp.engines.base import tcp_probe

        tcp = await tcp_probe(port, also_as=tuple(state.get("gateways", ())))
        if not tcp["alive"]:
            for ip in state["container_ips"]:
                tcp = await tcp_probe(self._PRIMARY_CONTAINER_PORT, host=ip)
                if tcp["alive"]:
                    break

        # A running, answering container whose log tailer has died is capturing
        # attacks into logs nobody reads. That is a failed honeypot, not a
        # healthy one. Restart the tailer so it heals, but still report the gap.
        ingest_name = self._ingest_names.get(container_id)
        if tcp["alive"] and ingest_name is not None and not self._ingest_alive(container_id):
            self._spawn_ingest_task(ingest_name, container_id)
            return {
                "alive": False,
                "detail": "container running but log ingestion was not running (restarted)",
                "method": "docker+tcp+ingest",
                "docker_status": state["docker_status"],
            }

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
                # Everything comes from the container's own record: `c.image` would make the SDK
                # fetch the image (`GET /images/<id>/json`), which the host's Docker guard refuses,
                # so this tool failed on every Docker-backed sensor in the hardened deployment.
                attrs = c.attrs
                state = attrs.get("State", {})
                return {
                    "docker_status": c.status,
                    "image": attrs.get("Config", {}).get("Image") or COWRIE_IMAGE,
                    "started_at": state.get("StartedAt"),
                    # A sensor that keeps getting OOM-killed still shows "running" between kills.
                    "restart_count": attrs.get("RestartCount", 0),
                    "oom_killed": bool(state.get("OOMKilled")),
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

        def _unpause() -> str | None:
            c = self._client.containers.get(container_id)
            c.unpause()
            return str((c.labels or {}).get("honeypot-name") or "") or None

        label_name = await loop.run_in_executor(None, _unpause)
        # Ingestion must be running after a resume. A server restart while the
        # container was paused skips it in reconcile, and the old code only
        # unpaused — the honeypot then read healthy while nothing was recorded.
        name = self._ingest_names.get(container_id) or label_name
        if name:
            self._spawn_ingest_task(name, container_id)

    async def _ingest_logs(self, honeypot_name: str, container_id: str) -> None:
        """Background task: tail Cowrie JSON logs and write alerts to the DB.

        Uses the Docker `since` parameter to fetch only new lines per poll, so we
        don't lose events under burst load and don't re-process history. A small
        bounded deque dedups boundary cases (when `since` returns a line we just
        saw on the previous poll due to docker's per-second timestamp granularity).
        """
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
        # Cowrie sessions belonging to our own health probes. Bounded the same
        # way as `seen` so a long-lived honeypot can't grow them without limit.
        probe_sessions: set[str] = set()
        probe_session_order: deque[str] = deque(maxlen=128)
        # Start two seconds in the past to avoid missing logs written between
        # container start and the first poll.
        # Resume where the previous incarnation of this task stopped. A fixed
        # "two seconds ago" on every (re)start silently skipped everything logged
        # while the task was down — a Docker hiccup, a pause, a supervisor
        # restart — which is exactly when attacks are happening.
        last_check = self._ingest_cursor.get(container_id) or (
            datetime.now(UTC) - timedelta(seconds=2)
        )

        while True:
            await asyncio.sleep(2)
            try:
                container = await loop.run_in_executor(None, _get_container)
            except Exception as e:
                # A Docker/socket-proxy error is not "the container is gone";
                # keep the cursor where it is and try again.
                log.debug("Docker lookup failed for %s: %s", honeypot_name, e)
                continue
            if container is None:
                break
            if container.status in ("paused", "restarting", "created"):
                # Not producing logs right now, but coming back; stopping here
                # used to leave ingestion dead until the next health check.
                continue
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
            self._ingest_cursor[container_id] = last_check

            # Split on "\n" only: str.splitlines() also breaks on \x85, \u2028
            # and friends, which can legitimately sit inside a JSON string
            # value an attacker controls — that would shear one event in two.
            for line in raw_logs.split("\n"):
                if not line:
                    continue
                h = hash(line)
                if h in seen:
                    continue
                if len(recent_hashes) == recent_hashes.maxlen:
                    seen.discard(recent_hashes[0])
                recent_hashes.append(h)
                seen.add(h)

                # One odd line must never end ingestion: every later attack
                # would go unrecorded while health checks stayed green.
                try:
                    await self._handle_line(line, hp_db_id, probe_sessions, probe_session_order)
                except Exception as e:
                    log.debug("Skipping unprocessable Cowrie line for %s: %s", honeypot_name, e)

    async def _handle_line(
        self,
        line: str,
        hp_db_id: int | None,
        probe_sessions: set[str],
        probe_session_order: deque[str],
    ) -> None:
        """Turn one Cowrie JSON log line into an event (or drop it)."""
        try:
            entry = json.loads(line)
        except ValueError:
            return
        if not isinstance(entry, dict):
            return

        event_id = entry.get("eventid")
        if not isinstance(event_id, str) or event_id not in _EVENT_MAP:
            return

        event_type, severity = _EVENT_MAP[event_id]
        protocol = entry.get("protocol")
        proto = protocol if isinstance(protocol, str) else None
        event_type = _retag_for_protocol(event_type, proto)

        # The source address becomes the attacker identity everything downstream
        # keys on (blocklists, profiles, enrichment). Cowrie emits a real peer
        # address, so anything else is a malformed or forged line — drop it
        # rather than record an event attributed to an arbitrary string.
        raw_ip = entry.get("src_ip", "0.0.0.0")
        try:
            addr = ipaddress.ip_address(raw_ip) if isinstance(raw_ip, str) else None
        except ValueError:
            addr = None
        if addr is None or getattr(addr, "scope_id", None):
            log.debug("Dropping Cowrie event with invalid src_ip %r", raw_ip)
            return
        src_ip = str(addr)

        raw_port = entry.get("src_port")
        src_port = (
            raw_port
            if isinstance(raw_port, int)
            and not isinstance(raw_port, bool)
            and 0 <= raw_port <= 65535
            else None
        )
        raw_session = entry.get("session")
        session_id = raw_session if isinstance(raw_session, str) else None

        # Self-probe filtering has to be session-scoped here, not just
        # socket-scoped. Only `cowrie.session.connect` carries
        # `src_port`; `session.closed` and `client.version` identify
        # the connection by `session` alone, so matching on the socket
        # dropped the watchdog's connect event and let its
        # `ssh_session_closed` through every 30 seconds.
        if session_id is not None and session_id in probe_sessions:
            return
        if src_port is not None and self_probe.claim(src_ip, src_port):
            if session_id is not None:
                if len(probe_session_order) == probe_session_order.maxlen:
                    probe_sessions.discard(probe_session_order[0])
                probe_session_order.append(session_id)
                probe_sessions.add(session_id)
            return

        payload = _shape_payload(
            event_type,
            {k: v for k, v in entry.items() if k not in ("eventid", "src_ip", "src_port")},
        )

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
