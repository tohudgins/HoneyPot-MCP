"""Kubernetes API server honeypot — tcp/6443, anonymous cluster access.

A kube-apiserver that binds `system:anonymous` to a permissive role is the
cloud-native equivalent of an open Docker socket, and it is a recurring real
misconfiguration: `--anonymous-auth=true` is the default, and it only becomes
dangerous when someone also creates a ClusterRoleBinding for
`system:unauthenticated` — which plenty of quick-start guides and Helm charts
have done. The result is a cluster anyone on the internet can read and, often,
schedule workloads on.

The attack has a recognisable shape, and each step means something different:

1. `GET /version` and `/api` — confirm an API server and learn the release,
   which decides which CVEs are worth trying.
2. `GET /api/v1/namespaces/*/secrets` — this is the prize. Kubernetes secrets
   hold service-account tokens, registry credentials and database passwords,
   and reading them is usually game over for the whole cluster rather than one
   pod. Treated as CRITICAL on its own.
3. `POST .../pods` with `hostPath: /`, `privileged: true` or a host namespace —
   scheduling a pod that mounts the node's filesystem is a container escape
   onto the node, exactly as with Docker's `Binds`.
4. `POST .../pods/{name}/exec` — running commands in an existing workload.

`analyse_pod_spec` names the specific reason a pod is an escape rather than
returning a verdict, for the same reason the Docker engine does: "someone
created a pod" is not actionable, "this pod mounts the node's root filesystem
and runs privileged" is an incident.

Responses carry the headers a real API server always sends — `Audit-Id` and the
`X-Kubernetes-Pf-*` flow-control UIDs — because their absence is a one-request
tell. Nothing is scheduled and no cluster exists; object names and UIDs are
generated and every later reference is answered from the same fiction.

API reference: Kubernetes API v1.28.
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
from honeypot_mcp.http_identity import identity_runner, server_identity_middleware
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_K8S_MAJOR, _K8S_MINOR = "1", "28"
_K8S_VERSION = f"v{_K8S_MAJOR}.{_K8S_MINOR}.4"
_GO_VERSION = "go1.20.8"
# kube-apiserver sets no Server header of its own; nginx-ingress in front of it
# is by far the most common thing on 6443 that does.
_SERVER_BANNER = "nginx/1.25.3"

_MAX_BODY_BYTES = 128 * 1024

_MINER_IMAGE = re.compile(
    r"(xmrig|monero|minerd|cpuminer|kinsing|kdevtmpfsi|teamtnt|coinhive|nanopool|"
    r"minergate|stratum)",
    re.I,
)
_PAYLOAD_COMMAND = re.compile(
    r"(chroot\s+/host|nsenter|curl[^|]*\|\s*(sh|bash)|wget[^|]*\|\s*(sh|bash)|"
    r"base64\s+-d[^|]*\|\s*(sh|bash)|/etc/shadow|authorized_keys|crontab|"
    r"kubectl\s+.*cluster-admin)",
    re.I,
)
_SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/var/run", "/var/lib/kubelet", "/proc", "/sys")


def _as_dict(value: Any) -> dict[str, Any]:
    """`value.get("X") or {}` still leaves `value` as whatever the attacker
    sent if it was a non-empty non-dict (e.g. spec: "pwned") — `or {}` only
    replaces falsy values (None, "", missing), not wrong types. The next
    `.get()` on that then raises AttributeError, uncaught, before the request
    ever reaches _record() — a real pod-escape attempt with one malformed
    field goes completely uncaptured instead of alerting. Mirrors
    docker_api.py's identical helper."""
    return value if isinstance(value, dict) else {}


def analyse_pod_spec(body: dict[str, Any]) -> list[str]:
    """Named reasons a pod definition is an escape, or an empty list.

    Mirrors `docker_api.analyse_container_create`: the value is in naming the
    specific property, not in returning a boolean.
    """
    reasons: list[str] = []
    spec = _as_dict(body.get("spec"))

    for volume in spec.get("volumes") or []:
        if not isinstance(volume, dict):
            continue
        host_path = _as_dict(volume.get("hostPath")).get("path")
        if host_path == "/":
            reasons.append("mounts the node's root filesystem (hostPath: /)")
        elif host_path in _SENSITIVE_HOST_PATHS:
            reasons.append(f"mounts a sensitive node path (hostPath: {host_path})")
        elif isinstance(host_path, str) and host_path.endswith("docker.sock"):
            reasons.append(f"mounts the node's container runtime socket ({host_path})")

    if spec.get("hostPID"):
        reasons.append("host PID namespace — can see and enter node processes")
    if spec.get("hostNetwork"):
        reasons.append("host network namespace")
    if spec.get("hostIPC"):
        reasons.append("host IPC namespace")

    containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
    for container in containers:
        if not isinstance(container, dict):
            continue
        security = _as_dict(container.get("securityContext"))
        if security.get("privileged"):
            reasons.append("privileged container — full node capability set")
        if security.get("allowPrivilegeEscalation"):
            reasons.append("allowPrivilegeEscalation enabled")
        if security.get("runAsUser") == 0:
            reasons.append("runs as root (runAsUser: 0)")
        capabilities = _as_dict(security.get("capabilities")).get("add") or []
        dangerous = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "ALL"}
        hit = sorted({c for c in capabilities if isinstance(c, str) and c.upper() in dangerous})
        if hit:
            reasons.append(f"dangerous capabilities added ({', '.join(hit)})")

        image = str(container.get("image", ""))
        if _MINER_IMAGE.search(image):
            reasons.append(f"known mining image ({image[:80]})")

        command = list(container.get("command") or []) + list(container.get("args") or [])
        joined = " ".join(str(c) for c in command)
        if _PAYLOAD_COMMAND.search(joined):
            reasons.append(f"payload-stage command ({joined[:120]})")

    # Not an escape on its own, so only noted when something else already is.
    if reasons and spec.get("serviceAccountName") in (
        "default",
        "cluster-admin",
        "kubernetes-admin",
    ):
        reasons.append(f"runs as service account '{spec.get('serviceAccountName')}'")

    return reasons


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _status(message: str, reason: str, code: int) -> dict[str, Any]:
    """A Kubernetes `Status` object — the shape every k8s error uses."""
    return {
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code,
    }


class KubernetesEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._runners: dict[str, web.AppRunner] = {}

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
        # An attacker who already has a stolen service-account token will send
        # it here, and capturing it is how that theft gets attributed.
        authorization = request.headers.get("Authorization", "")
        extra: dict[str, Any] = {}
        if authorization:
            extra["authorization_presented"] = authorization[:120]
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
                    **extra,
                    **payload,
                },
                severity=severity,
            )
        )

    def _build_app(self, name: str, hp_id: int | None) -> web.Application:
        def headers() -> dict[str, str]:
            # Real API servers always send these. Their absence identifies a
            # decoy in a single request.
            return {
                "Audit-Id": str(uuid.uuid4()),
                "Cache-Control": "no-cache, private",
                "X-Kubernetes-Pf-Flowschema-Uid": str(uuid.uuid4()),
                "X-Kubernetes-Pf-Prioritylevel-Uid": str(uuid.uuid4()),
            }

        async def version(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {
                    "major": _K8S_MAJOR,
                    "minor": _K8S_MINOR,
                    "gitVersion": _K8S_VERSION,
                    "gitCommit": secrets.token_hex(20),
                    "gitTreeState": "clean",
                    "buildDate": "2023-11-15T16:48:54Z",
                    "goVersion": _GO_VERSION,
                    "compiler": "gc",
                    "platform": "linux/amd64",
                },
                headers=headers(),
            )

        async def api_root(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": []},
                headers=headers(),
            )

        async def api_groups(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            groups = [
                {
                    "name": group,
                    "versions": [{"groupVersion": f"{group}/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": f"{group}/v1", "version": "v1"},
                }
                for group in ("apps", "batch", "rbac.authorization.k8s.io", "networking.k8s.io")
            ]
            return web.json_response(
                {"kind": "APIGroupList", "apiVersion": "v1", "groups": groups}, headers=headers()
            )

        async def list_namespaces(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_enumerate", AlertSeverity.HIGH, {})
            items = [
                {
                    "metadata": {
                        "name": ns,
                        "uid": str(uuid.uuid4()),
                        "creationTimestamp": _now_iso(),
                    },
                    "status": {"phase": "Active"},
                }
                for ns in ("default", "kube-system", "production", "payments", "monitoring")
            ]
            return web.json_response(
                {"kind": "NamespaceList", "apiVersion": "v1", "items": items}, headers=headers()
            )

        async def list_pods(request: web.Request) -> web.Response:
            namespace = request.match_info.get("ns", "default")
            await self._record(
                hp_id,
                request,
                "kubernetes_enumerate",
                AlertSeverity.HIGH,
                {"namespace": namespace[:64], "resource": "pods"},
            )
            items = [
                {
                    "metadata": {
                        "name": f"{app}-{secrets.token_hex(4)}",
                        "namespace": namespace,
                        "uid": str(uuid.uuid4()),
                    },
                    "spec": {
                        "containers": [{"name": app, "image": image}],
                        "nodeName": "ip-10-0-1-42.ec2.internal",
                        "serviceAccountName": "default",
                    },
                    "status": {"phase": "Running", "podIP": f"10.244.1.{n + 10}"},
                }
                for n, (app, image) in enumerate(
                    (
                        ("payments-api", "registry.internal/payments-api:2.4.1"),
                        ("postgres", "postgres:15.4"),
                        ("redis", "redis:7.2-alpine"),
                    )
                )
            ]
            return web.json_response(
                {"kind": "PodList", "apiVersion": "v1", "items": items}, headers=headers()
            )

        async def list_secrets(request: web.Request) -> web.Response:
            # The prize. Secrets hold service-account tokens, registry pull
            # credentials and database passwords — reading them is usually the
            # whole cluster, not one workload.
            namespace = request.match_info.get("ns", "default")
            await self._record(
                hp_id,
                request,
                "kubernetes_secret_access",
                AlertSeverity.CRITICAL,
                {
                    "namespace": namespace[:64],
                    "note": (
                        "read cluster secrets anonymously — service-account tokens and "
                        "registry credentials, typically full cluster compromise"
                    ),
                },
            )
            items = [
                {
                    "metadata": {"name": nm, "namespace": namespace, "uid": str(uuid.uuid4())},
                    "type": kind,
                    "data": {key: secrets.token_urlsafe(32)},
                }
                for nm, kind, key in (
                    ("default-token-x7k2p", "kubernetes.io/service-account-token", "token"),
                    ("registry-pull-secret", "kubernetes.io/dockerconfigjson", ".dockerconfigjson"),
                    ("postgres-credentials", "Opaque", "password"),
                )
            ]
            return web.json_response(
                {"kind": "SecretList", "apiVersion": "v1", "items": items}, headers=headers()
            )

        async def list_rbac(request: web.Request) -> web.Response:
            await self._record(
                hp_id,
                request,
                "kubernetes_rbac_enumerate",
                AlertSeverity.HIGH,
                {"note": "mapping permissions — looking for a path to cluster-admin"},
            )
            return web.json_response(
                {
                    "kind": "ClusterRoleBindingList",
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "items": [
                        {
                            "metadata": {"name": "cluster-admin"},
                            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                            "subjects": [{"kind": "Group", "name": "system:masters"}],
                        }
                    ],
                },
                headers=headers(),
            )

        async def create_pod(request: web.Request) -> web.Response:
            body = await self._read_json(request)
            namespace = request.match_info.get("ns", "default")
            reasons = analyse_pod_spec(body)
            pod_name = (body.get("metadata") or {}).get("name") or f"pod-{secrets.token_hex(4)}"
            await self._record(
                hp_id,
                request,
                "kubernetes_pod_escape" if reasons else "kubernetes_pod_create",
                AlertSeverity.CRITICAL if reasons else AlertSeverity.HIGH,
                {
                    "namespace": namespace[:64],
                    "pod_name": str(pod_name)[:120],
                    "escape_indicators": reasons,
                    "spec": json.dumps(body)[:2000],
                },
            )
            return web.json_response(
                {
                    "kind": "Pod",
                    "apiVersion": "v1",
                    "metadata": {
                        "name": pod_name,
                        "namespace": namespace,
                        "uid": str(uuid.uuid4()),
                        "creationTimestamp": _now_iso(),
                    },
                    "spec": body.get("spec", {}),
                    "status": {"phase": "Pending"},
                },
                status=201,
                headers=headers(),
            )

        async def pod_exec(request: web.Request) -> web.Response:
            command = request.query.getall("command", [])
            await self._record(
                hp_id,
                request,
                "kubernetes_pod_exec",
                AlertSeverity.CRITICAL,
                {
                    "namespace": request.match_info.get("ns", "")[:64],
                    "pod": request.match_info.get("pod", "")[:120],
                    "command": " ".join(command)[:500],
                },
            )
            # A real exec upgrades to SPDY/WebSocket; refusing the upgrade is
            # what an API server does when the client does not ask for one.
            return web.json_response(
                _status("Upgrade request required", "BadRequest", 400),
                status=400,
                headers=headers(),
            )

        async def catch_all(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_probe", AlertSeverity.MEDIUM, {})
            return web.json_response(
                _status(
                    f"the server could not find the requested resource: {request.path}",
                    "NotFound",
                    404,
                ),
                status=404,
                headers=headers(),
            )

        app = web.Application(middlewares=[server_identity_middleware(_SERVER_BANNER)])
        router = app.router
        router.add_get("/version", version)
        router.add_get("/api", api_root)
        router.add_get("/apis", api_groups)
        router.add_get("/api/v1/namespaces", list_namespaces)
        router.add_get("/api/v1/pods", list_pods)
        router.add_get("/api/v1/secrets", list_secrets)
        router.add_get("/api/v1/namespaces/{ns}/pods", list_pods)
        router.add_get("/api/v1/namespaces/{ns}/secrets", list_secrets)
        router.add_get("/api/v1/namespaces/{ns}/serviceaccounts", list_secrets)
        router.add_get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", list_rbac)
        router.add_get("/apis/rbac.authorization.k8s.io/v1/clusterroles", list_rbac)
        router.add_post("/api/v1/namespaces/{ns}/pods", create_pod)
        router.add_post("/api/v1/namespaces/{ns}/pods/{pod}/exec", pod_exec)
        router.add_get("/api/v1/namespaces/{ns}/pods/{pod}/exec", pod_exec)
        router.add_route("*", "/{tail:.*}", catch_all)
        return app

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        runner = identity_runner(self._build_app(name, hp_id), _SERVER_BANNER)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", port).start()
        cid = f"k8s-{secrets.token_hex(8)}"
        self._runners[cid] = runner
        log.info("Kubernetes API honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        runner = self._runners.pop(container_id, None)
        if runner:
            await runner.cleanup()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._runners, "type": "aiohttp_kubernetes"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["Kubernetes honeypot is in-process — events are stored directly in the database."]
