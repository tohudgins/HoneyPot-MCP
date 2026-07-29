"""Docker Engine API honeypot — tcp/2375, unauthenticated daemon.

An exposed Docker daemon is not a foothold, it is game over. The API has no
authentication when it is bound to a TCP port without TLS, and `POST
/containers/create` accepts a `Binds` entry — so any client that can reach 2375
can start a container with the host filesystem mounted at `/mnt`, chroot into
it, and own the machine. It is one of the most reliably exploited cloud
misconfigurations, and automated cryptominer campaigns (Kinsing, TeamTNT,
Watchdog) scan for it continuously.

The attack is stereotyped enough to detect precisely rather than generically:

1. `GET /version` or `/info` — confirm an unauthenticated daemon.
2. `POST /images/create?fromImage=…` — pull a miner or an `alpine` base.
3. `POST /containers/create` — with `HostConfig.Binds` mounting `/`, or
   `Privileged: true`, or `PidMode: host`.
4. `POST /containers/{id}/start`, then `/exec` to run the payload.

So container creation is inspected rather than merely counted: a bind of the
host root, `Privileged`, host PID/network namespace, or a known miner image
each escalate the event to CRITICAL with the specific reason attached. That is
the difference between "someone touched the Docker API" and "someone attempted
a container escape", and only the second is worth waking up for.

Responses are shaped like a real daemon (correct JSON schemas, `Api-Version`
and `Docker-Experimental` headers, 201 with an `Id` on create) so the campaign
runs to completion and the whole chain is captured. Nothing is executed and no
container is ever created — the ids handed out are random and every later
reference to them is answered from the same fiction.

API reference: Docker Engine API v1.43.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
import uuid
from typing import Any

from aiohttp import web

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.http_identity import server_identity_middleware
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_DOCKER_VERSION = "24.0.7"
_API_VERSION = "1.43"
_MIN_API_VERSION = "1.12"
_GO_VERSION = "go1.20.10"
_KERNEL_VERSION = "5.15.0-88-generic"
_SERVER_BANNER = f"Docker/{_DOCKER_VERSION} (linux)"

# Image names that only appear in cryptomining and botnet campaigns. Matching
# the image is what separates "pulled alpine" from "pulled a miner".
_MALICIOUS_IMAGE = re.compile(
    r"(xmrig|monero|minerd|cpuminer|kinsing|kdevtmpfsi|teamtnt|watchdog|"
    r"docker\.io/alpine.*(curl|wget).*sh|pocosow|coinhive|nanopool|minergate|"
    r"cetus|dofloo|tornado|zoolu)",
    re.I,
)

# Commands that indicate the payload stage rather than legitimate use.
_MALICIOUS_COMMAND = re.compile(
    r"(chroot\s+/mnt|nsenter|curl[^|]*\|\s*(sh|bash)|wget[^|]*\|\s*(sh|bash)|"
    r"base64\s+-d[^|]*\|\s*(sh|bash)|/etc/shadow|authorized_keys|crontab|"
    r"xmrig|stratum\+tcp)",
    re.I,
)

_MAX_BODY_BYTES = 64 * 1024


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000000000Z", time.gmtime())


def analyse_container_create(spec: dict[str, Any]) -> list[str]:
    """Return the escape indicators present in a container-create body.

    Empty list means the request looked like ordinary container creation. Each
    string is a specific, human-readable reason, because "CRITICAL: docker" is
    not actionable and "mounts host / at /mnt" is.
    """
    reasons: list[str] = []
    host_config = spec.get("HostConfig") or {}

    binds = host_config.get("Binds") or []
    if isinstance(binds, list):
        for bind in binds:
            if not isinstance(bind, str):
                continue
            source = bind.split(":", 1)[0]
            if source == "/":
                reasons.append(f"mounts host root filesystem ({bind})")
            elif source in ("/etc", "/root", "/home", "/var/run", "/proc", "/sys", "/boot"):
                reasons.append(f"mounts sensitive host path ({bind})")
            elif source.endswith("docker.sock"):
                reasons.append(f"mounts the Docker socket ({bind}) — daemon takeover")

    mounts = spec.get("Mounts") or host_config.get("Mounts") or []
    if isinstance(mounts, list):
        for mount in mounts:
            if isinstance(mount, dict) and mount.get("Source") == "/":
                reasons.append("mounts host root filesystem via Mounts")

    if host_config.get("Privileged"):
        reasons.append("privileged container — full host capability set")
    if host_config.get("PidMode") == "host":
        reasons.append("host PID namespace")
    if host_config.get("NetworkMode") == "host":
        reasons.append("host network namespace")
    if host_config.get("IpcMode") == "host":
        reasons.append("host IPC namespace")
    caps = host_config.get("CapAdd") or []
    if isinstance(caps, list):
        dangerous = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
        hit = sorted({c for c in caps if isinstance(c, str) and c.upper() in dangerous})
        if hit:
            reasons.append(f"dangerous capabilities added ({', '.join(hit)})")

    image = str(spec.get("Image", ""))
    if _MALICIOUS_IMAGE.search(image):
        reasons.append(f"known malicious/mining image ({image[:80]})")

    command = spec.get("Cmd") or spec.get("Entrypoint") or []
    if isinstance(command, str):
        command = [command]
    if isinstance(command, list):
        joined = " ".join(str(c) for c in command)
        if _MALICIOUS_COMMAND.search(joined):
            reasons.append(f"payload-stage command ({joined[:120]})")

    return reasons


class DockerAPIEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._runners: dict[str, web.AppRunner] = {}

    # ── request recording ────────────────────────────────────────────────

    @staticmethod
    async def _read_json(request: web.Request) -> dict[str, Any]:
        try:
            raw = await request.content.read(_MAX_BODY_BYTES)
            if not raw:
                return {}
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_body": parsed}
        except Exception:
            return {}

    @staticmethod
    async def _record(
        hp_id: int | None,
        request: web.Request,
        event_type: str,
        severity: AlertSeverity,
        payload: dict[str, Any],
    ) -> None:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        src_ip = peer[0] if peer else (request.remote or "0.0.0.0")
        src_port = peer[1] if peer and len(peer) > 1 else None
        await submit_event(
            PendingEvent(
                honeypot_id=hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload={
                    "method": request.method,
                    "path": request.path_qs[:512],
                    "user_agent": request.headers.get("User-Agent", "")[:200],
                    **payload,
                },
                severity=severity,
            )
        )

    # ── handlers ─────────────────────────────────────────────────────────

    def _build_app(self, name: str, hp_id: int | None) -> web.Application:
        engine_id = f"{uuid.uuid4().hex[:12].upper()}"
        node_id = secrets.token_hex(10)
        started = time.time()

        def headers() -> dict[str, str]:
            return {
                "Api-Version": _API_VERSION,
                "Docker-Experimental": "false",
                "Ostype": "linux",
                "Cache-Control": "no-cache, no-store, must-revalidate",
            }

        async def version(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {
                    "Platform": {"Name": "Docker Engine - Community"},
                    "Components": [
                        {
                            "Name": "Engine",
                            "Version": _DOCKER_VERSION,
                            "Details": {
                                "ApiVersion": _API_VERSION,
                                "Arch": "amd64",
                                "BuildTime": "2023-10-26T09:08:01.000000000+00:00",
                                "Experimental": "false",
                                "GitCommit": "311b9ff",
                                "GoVersion": _GO_VERSION,
                                "KernelVersion": _KERNEL_VERSION,
                                "MinAPIVersion": _MIN_API_VERSION,
                                "Os": "linux",
                            },
                        }
                    ],
                    "Version": _DOCKER_VERSION,
                    "ApiVersion": _API_VERSION,
                    "MinAPIVersion": _MIN_API_VERSION,
                    "GitCommit": "311b9ff",
                    "GoVersion": _GO_VERSION,
                    "Os": "linux",
                    "Arch": "amd64",
                    "KernelVersion": _KERNEL_VERSION,
                    "BuildTime": "2023-10-26T09:08:01.000000000+00:00",
                },
                headers=headers(),
            )

        async def info(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {
                    "ID": engine_id,
                    "Containers": 3,
                    "ContainersRunning": 2,
                    "ContainersPaused": 0,
                    "ContainersStopped": 1,
                    "Images": 11,
                    "Driver": "overlay2",
                    "MemoryLimit": True,
                    "SwapLimit": True,
                    "CpuCfsPeriod": True,
                    "KernelVersion": _KERNEL_VERSION,
                    "OperatingSystem": "Ubuntu 22.04.3 LTS",
                    "OSVersion": "22.04",
                    "OSType": "linux",
                    "Architecture": "x86_64",
                    "NCPU": 4,
                    "MemTotal": 8232558592,
                    "DockerRootDir": "/var/lib/docker",
                    "Name": "docker-prod-01",
                    "ServerVersion": _DOCKER_VERSION,
                    "SecurityOptions": ["name=apparmor", "name=seccomp,profile=builtin"],
                    "Swarm": {"NodeID": node_id, "LocalNodeState": "inactive"},
                    "SystemTime": _now_iso(),
                },
                headers=headers(),
            )

        async def ping(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_recon", AlertSeverity.MEDIUM, {})
            return web.Response(text="OK", headers=headers())

        async def list_containers(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_enumerate", AlertSeverity.MEDIUM, {})
            return web.json_response(
                [
                    {
                        "Id": secrets.token_hex(32),
                        "Names": ["/billing-api"],
                        "Image": "registry.internal/billing-api:1.9.2",
                        "ImageID": f"sha256:{secrets.token_hex(32)}",
                        "Command": "/usr/local/bin/billing-api",
                        "Created": int(started) - 864_000,
                        "Ports": [{"PrivatePort": 8080, "Type": "tcp"}],
                        "State": "running",
                        "Status": "Up 10 days",
                    },
                    {
                        "Id": secrets.token_hex(32),
                        "Names": ["/postgres"],
                        "Image": "postgres:15.4",
                        "ImageID": f"sha256:{secrets.token_hex(32)}",
                        "Command": "docker-entrypoint.sh postgres",
                        "Created": int(started) - 1_728_000,
                        "Ports": [{"PrivatePort": 5432, "Type": "tcp"}],
                        "State": "running",
                        "Status": "Up 20 days",
                    },
                ],
                headers=headers(),
            )

        async def list_images(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_enumerate", AlertSeverity.MEDIUM, {})
            return web.json_response(
                [
                    {
                        "Id": f"sha256:{secrets.token_hex(32)}",
                        "RepoTags": ["postgres:15.4"],
                        "Created": int(started) - 2_000_000,
                        "Size": 379_000_000,
                    },
                    {
                        "Id": f"sha256:{secrets.token_hex(32)}",
                        "RepoTags": ["registry.internal/billing-api:1.9.2"],
                        "Created": int(started) - 900_000,
                        "Size": 142_000_000,
                    },
                ],
                headers=headers(),
            )

        async def create_image(request: web.Request) -> web.Response:
            image = request.query.get("fromImage", "") + (
                f":{request.query['tag']}" if request.query.get("tag") else ""
            )
            malicious = bool(_MALICIOUS_IMAGE.search(image))
            await self._record(
                hp_id,
                request,
                "docker_api_image_pull",
                AlertSeverity.CRITICAL if malicious else AlertSeverity.HIGH,
                {
                    "image": image[:200],
                    "malicious_image": malicious,
                    **(
                        {"note": "known cryptomining/botnet image"}
                        if malicious
                        else {"note": "image pull on an unauthenticated daemon"}
                    ),
                },
            )
            # Streamed pull progress, as the real endpoint returns.
            body = (
                json.dumps({"status": f"Pulling from {image or 'library/alpine'}", "id": "latest"})
                + "\r\n"
                + json.dumps({"status": "Pulling fs layer", "id": secrets.token_hex(6)})
                + "\r\n"
                + json.dumps({"status": f"Status: Downloaded newer image for {image}"})
                + "\r\n"
            )
            return web.Response(text=body, content_type="application/json", headers=headers())

        async def create_container(request: web.Request) -> web.Response:
            spec = await self._read_json(request)
            reasons = analyse_container_create(spec)
            container_id = secrets.token_hex(32)
            await self._record(
                hp_id,
                request,
                "docker_api_container_escape" if reasons else "docker_api_container_create",
                AlertSeverity.CRITICAL if reasons else AlertSeverity.HIGH,
                {
                    "image": str(spec.get("Image", ""))[:200],
                    "cmd": str(spec.get("Cmd", ""))[:300],
                    "escape_indicators": reasons,
                    "container_id": container_id[:12],
                    "spec": json.dumps(spec)[:2000],
                },
            )
            return web.json_response(
                {"Id": container_id, "Warnings": []}, status=201, headers=headers()
            )

        async def start_container(request: web.Request) -> web.Response:
            await self._record(
                hp_id,
                request,
                "docker_api_container_start",
                AlertSeverity.CRITICAL,
                {"container_id": request.match_info.get("cid", "")[:12]},
            )
            return web.Response(status=204, headers=headers())

        async def create_exec(request: web.Request) -> web.Response:
            spec = await self._read_json(request)
            command = spec.get("Cmd") or []
            joined = (
                " ".join(str(c) for c in command) if isinstance(command, list) else str(command)
            )
            malicious = bool(_MALICIOUS_COMMAND.search(joined))
            await self._record(
                hp_id,
                request,
                "docker_api_exec",
                AlertSeverity.CRITICAL,
                {
                    "container_id": request.match_info.get("cid", "")[:12],
                    "cmd": joined[:500],
                    "payload_command": malicious,
                },
            )
            return web.json_response({"Id": secrets.token_hex(32)}, status=201, headers=headers())

        async def start_exec(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_exec_start", AlertSeverity.CRITICAL, {})
            return web.Response(body=b"", headers=headers())

        async def catch_all(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "docker_api_probe", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {"message": f"page not found: {request.path}"}, status=404, headers=headers()
            )

        app = web.Application(middlewares=[server_identity_middleware(_SERVER_BANNER)])
        router = app.router
        # Docker clients prefix every call with /v1.43; both forms must work.
        for prefix in ("", "/v{api:[0-9.]+}"):
            router.add_get(prefix + "/version", version)
            router.add_get(prefix + "/info", info)
            # `add_get` registers HEAD too (allow_head defaults to True), and
            # Docker clients probe `/_ping` with HEAD — adding it explicitly
            # raises "Added route will never be matched" at startup.
            router.add_get(prefix + "/_ping", ping)
            router.add_get(prefix + "/containers/json", list_containers)
            router.add_get(prefix + "/images/json", list_images)
            router.add_post(prefix + "/images/create", create_image)
            router.add_post(prefix + "/containers/create", create_container)
            router.add_post(prefix + "/containers/{cid}/start", start_container)
            router.add_post(prefix + "/containers/{cid}/exec", create_exec)
            router.add_post(prefix + "/exec/{eid}/start", start_exec)
        router.add_route("*", "/{tail:.*}", catch_all)
        return app

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        runner = web.AppRunner(self._build_app(name, hp_id))
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()

        cid = f"dockerapi-{secrets.token_hex(8)}"
        self._runners[cid] = runner
        log.info("Docker API honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        runner = self._runners.pop(container_id, None)
        if runner:
            await runner.cleanup()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._runners, "type": "aiohttp_docker_api"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["Docker API honeypot is in-process — events are stored directly in the database."]
