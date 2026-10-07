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
tell. Nothing is scheduled and no cluster exists, but the fiction is stable: object
UIDs, pod names, secret values, the build commit and the flow-control UIDs derive
from the honeypot's name and never change between requests, because a scanner
that asks twice and gets two identities has found the decoy. Discovery
(`/api/v1`, `/apis/{group}/{version}`, `/healthz`) answers as kubectl expects, so
`kubectl get pods|nodes|secrets` works against it; resources the decoy has no
data for (deployments, services, ...) return valid empty lists.

API reference: Kubernetes API v1.28.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from typing import Any

from aiohttp import web

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.http_identity import (
    MAX_REQUEST_BYTES,
    compact_dumps,
    identity_runner,
    read_body,
    server_identity_middleware,
)
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_K8S_MAJOR, _K8S_MINOR = "1", "28"
_K8S_VERSION = f"v{_K8S_MAJOR}.{_K8S_MINOR}.4"
_GO_VERSION = "go1.20.8"
# The real v1.28.4 build identity: a version with a random commit is a decoy.
_K8S_GIT_COMMIT = "bae2c62678db2b5053817bc97181fcc2e8388103"
_K8S_BUILD_DATE = "2023-11-15T16:58:20Z"
# When the fictional cluster was created; every object's age is measured from here.
_CREATED = "2026-06-03T09:12:44Z"
_NODE = "ip-10-0-1-42.ec2.internal"
# kube-apiserver sets no Server header of its own; nginx-ingress in front of it
# is by far the most common thing on 6443 that does.
_SERVER_BANNER = "nginx/1.25.3"

# Reading is bounded by the request cap (also the Application `client_max_size`),
# so a manifest padded past 128 KB is still parsed instead of silently ignored.
_MAX_BODY_BYTES = MAX_REQUEST_BYTES

# Kubernetes object names cap at 253 characters, so only an image reference's
# head is ever matched or echoed.
_MAX_IMAGE_CHARS = 256

# Window fed to the command regex: a long command keeps its head and tail,
# which is where padding-based evasion has to put the payload.
_SCAN_WINDOW_CHARS = 4096

# A hostile manifest can name tens of thousands of containers or volumes; the
# indicators beyond this many say nothing the first ones did not.
_MAX_REASONS = 64

_MINER_IMAGE = re.compile(
    r"(xmrig|monero|minerd|cpuminer|kinsing|kdevtmpfsi|teamtnt|coinhive|nanopool|"
    r"minergate|stratum)",
    re.I,
)
# Every gap is bounded and the input is clipped (`_scan_window`) before matching:
# `kubectl\s+.*cluster-admin` and `curl[^|]*\|…` are quadratic on attacker input,
# which at 128 KB held the event loop for ~11 s before anything was recorded.
_PAYLOAD_COMMAND = re.compile(
    r"(chroot\s+/host|nsenter|curl[^|]{0,512}\|\s*(sh|bash)|wget[^|]{0,512}\|\s*(sh|bash)|"
    r"base64\s+-d[^|]{0,512}\|\s*(sh|bash)|/etc/shadow|authorized_keys|crontab|"
    r"kubectl\s+.{0,200}cluster-admin)",
    re.I,
)
_SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/var/run", "/var/lib/kubelet", "/proc", "/sys")


def _scan_window(text: str) -> str:
    """`text` clipped to its head and tail windows, for regex matching."""
    if len(text) <= 2 * _SCAN_WINDOW_CHARS:
        return text
    return text[:_SCAN_WINDOW_CHARS] + " " + text[-_SCAN_WINDOW_CHARS:]


def _as_dict(value: Any) -> dict[str, Any]:
    """`value.get("X") or {}` still leaves `value` as whatever the attacker
    sent if it was a non-empty non-dict (e.g. spec: "pwned") — `or {}` only
    replaces falsy values (None, "", missing), not wrong types. The next
    `.get()` on that then raises AttributeError, uncaught, before the request
    ever reaches _record() — a real pod-escape attempt with one malformed
    field goes completely uncaptured instead of alerting. Mirrors
    docker_api.py's identical helper."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    """The list-typed counterpart of `_as_dict`: `volumes: 5` or
    `containers: 5` made `list(...)`/`for` raise TypeError before `_record()`."""
    return value if isinstance(value, list) else []


def _command_words(value: Any) -> list[Any]:
    """A `command`/`args` field as a list: a bare string is one word."""
    if isinstance(value, str):
        return [value]
    return _as_list(value)


def analyse_pod_spec(body: dict[str, Any]) -> list[str]:
    """Named reasons a pod definition is an escape, or an empty list.

    Mirrors `docker_api.analyse_container_create`: the value is in naming the
    specific property, not in returning a boolean.
    """
    reasons: list[str] = []
    spec = _as_dict(body.get("spec"))

    for volume in _as_list(spec.get("volumes")):
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

    containers = _as_list(spec.get("containers")) + _as_list(spec.get("initContainers"))
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
        capabilities = _as_list(_as_dict(security.get("capabilities")).get("add"))
        dangerous = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "ALL"}
        hit = sorted({c for c in capabilities if isinstance(c, str) and c.upper() in dangerous})
        if hit:
            reasons.append(f"dangerous capabilities added ({', '.join(hit)})")

        image = str(container.get("image", ""))[:_MAX_IMAGE_CHARS]
        if _MINER_IMAGE.search(image):
            reasons.append(f"known mining image ({image[:80]})")

        command = _command_words(container.get("command")) + _command_words(container.get("args"))
        joined = " ".join(str(c)[:_SCAN_WINDOW_CHARS] for c in command)
        if _PAYLOAD_COMMAND.search(_scan_window(joined)):
            reasons.append(f"payload-stage command ({joined[:120]})")
        if len(reasons) >= _MAX_REASONS:
            break

    # Not an escape on its own, so only noted when something else already is.
    if reasons and spec.get("serviceAccountName") in (
        "default",
        "cluster-admin",
        "kubernetes-admin",
    ):
        reasons.append(f"runs as service account '{spec.get('serviceAccountName')}'")

    return reasons[:_MAX_REASONS]


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


def _uid(seed: str, *parts: str) -> str:
    """A UID that is the same on every request: UIDs identify an object for its lifetime."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "/".join((seed, *parts))))


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _secret_data(seed: str, secret: str, key: str) -> str:
    """Base64 secret value (as the API returns it), fixed per honeypot and secret."""
    digest = hashlib.sha256(f"{seed}/{secret}/{key}".encode()).digest()
    if key == "token":
        head = _b64url(json.dumps({"alg": "RS256", "kid": digest[:12].hex()}).encode())
        body = _b64url(
            json.dumps(
                {
                    "iss": "kubernetes/serviceaccount",
                    "sub": "system:serviceaccount:default:default",
                }
            ).encode()
        )
        value = f"{head}.{body}.{_b64url(digest * 8)}".encode()
    elif key == ".dockerconfigjson":
        auth = base64.b64encode(b"svc-pull:" + digest[:12].hex().encode()).decode()
        value = json.dumps({"auths": {"registry.internal": {"auth": auth}}}).encode()
    else:
        value = digest[:9].hex().encode()
    return base64.b64encode(value).decode()


# group/version -> (resource, kind, namespaced). The discovery document and the generic list
# handler both read this, so what `kubectl api-resources` advertises is what answers.
_RESOURCES: dict[str, tuple[tuple[str, str, bool], ...]] = {
    "v1": (
        ("namespaces", "Namespace", False),
        ("nodes", "Node", False),
        ("pods", "Pod", True),
        ("secrets", "Secret", True),
        ("serviceaccounts", "ServiceAccount", True),
        ("services", "Service", True),
        ("configmaps", "ConfigMap", True),
    ),
    "apps/v1": (
        ("deployments", "Deployment", True),
        ("daemonsets", "DaemonSet", True),
        ("statefulsets", "StatefulSet", True),
        ("replicasets", "ReplicaSet", True),
    ),
    "batch/v1": (("jobs", "Job", True), ("cronjobs", "CronJob", True)),
    "networking.k8s.io/v1": (
        ("ingresses", "Ingress", True),
        ("networkpolicies", "NetworkPolicy", True),
    ),
    "rbac.authorization.k8s.io/v1": (
        ("clusterroles", "ClusterRole", False),
        ("clusterrolebindings", "ClusterRoleBinding", False),
        ("roles", "Role", True),
        ("rolebindings", "RoleBinding", True),
    ),
    "authorization.k8s.io/v1": (
        ("selfsubjectaccessreviews", "SelfSubjectAccessReview", False),
        ("selfsubjectrulesreviews", "SelfSubjectRulesReview", False),
    ),
}
_CREATE_ONLY = frozenset({"selfsubjectaccessreviews", "selfsubjectrulesreviews"})
_SHORT_NAMES = {
    "namespaces": ["ns"],
    "nodes": ["no"],
    "pods": ["po"],
    "serviceaccounts": ["sa"],
    "services": ["svc"],
    "configmaps": ["cm"],
    "deployments": ["deploy"],
    "daemonsets": ["ds"],
    "statefulsets": ["sts"],
    "replicasets": ["rs"],
    "cronjobs": ["cj"],
    "ingresses": ["ing"],
    "networkpolicies": ["netpol"],
}
_VERBS = ["create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"]


def _resource_list(group_version: str) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    for resource, kind, namespaced in _RESOURCES[group_version]:
        entry: dict[str, Any] = {
            "name": resource,
            "singularName": "",
            "namespaced": namespaced,
            "kind": kind,
            "verbs": ["create"] if resource in _CREATE_ONLY else _VERBS,
        }
        if resource in _SHORT_NAMES:
            entry["shortNames"] = _SHORT_NAMES[resource]
        resources.append(entry)
    if group_version == "v1":
        resources.append(
            {
                "name": "pods/exec",
                "singularName": "",
                "namespaced": True,
                "kind": "PodExecOptions",
                "verbs": ["create", "get"],
            }
        )
    return {
        "kind": "APIResourceList",
        "groupVersion": group_version,
        "resources": resources,
    }


def _age(timestamp: str) -> str:
    """An age in `kubectl`'s own format (the server computes the Age column, not the client)."""
    created = calendar.timegm(time.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ"))
    seconds = max(0, int(time.time()) - created)
    minutes, hours = seconds // 60, seconds // 3600
    days = hours // 24
    if seconds < 120:
        return f"{seconds}s"
    if minutes < 10:
        return f"{minutes}m{seconds % 60}s"
    if minutes < 180:
        return f"{minutes}m"
    if hours < 8:
        return f"{hours}h{minutes % 60}m"
    if hours < 48:
        return f"{hours}h"
    if days < 8:
        return f"{days}d{hours % 24}h"
    if days < 730:
        return f"{days}d"
    return f"{days // 365}y{days % 365}d"


def _pod_cells(o: dict[str, Any]) -> list[Any]:
    statuses = o["status"]["containerStatuses"]
    return [
        o["metadata"]["name"],
        f"{sum(1 for s in statuses if s['ready'])}/{len(statuses)}",
        o["status"]["phase"],
        sum(s["restartCount"] for s in statuses),
        _age(o["metadata"]["creationTimestamp"]),
        o["status"]["podIP"],
        o["spec"]["nodeName"],
        "<none>",
        "<none>",
    ]


def _node_cells(o: dict[str, Any]) -> list[Any]:
    labels = o["metadata"]["labels"]
    roles = [k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")]
    info = o["status"]["nodeInfo"]
    return [
        o["metadata"]["name"],
        "Ready",
        ",".join(roles) or "<none>",
        _age(o["metadata"]["creationTimestamp"]),
        info["kubeletVersion"],
        o["status"]["addresses"][0]["address"],
        "<none>",
        info["osImage"],
        info["kernelVersion"],
        info["containerRuntimeVersion"],
    ]


_Column = tuple[str, str, int]  # name, type, priority (1 = shown by `-o wide`)
_NAME_AGE: tuple[list[_Column], Any] = (
    [("Name", "string", 0), ("Age", "string", 0)],
    lambda o: [o["metadata"]["name"], _age(o["metadata"]["creationTimestamp"])],
)
# resource -> (columns, cells). What the API server returns when `kubectl` asks for
# `as=Table`; without it kubectl falls back to a bare `NAME AGE` listing no real cluster prints.
_TABLES: dict[str, tuple[list[_Column], Any]] = {
    "pods": (
        [
            ("Name", "string", 0),
            ("Ready", "string", 0),
            ("Status", "string", 0),
            ("Restarts", "integer", 0),
            ("Age", "string", 0),
            ("IP", "string", 1),
            ("Node", "string", 1),
            ("Nominated Node", "string", 1),
            ("Readiness Gates", "string", 1),
        ],
        _pod_cells,
    ),
    "nodes": (
        [
            ("Name", "string", 0),
            ("Status", "string", 0),
            ("Roles", "string", 0),
            ("Age", "string", 0),
            ("Version", "string", 0),
            ("Internal-IP", "string", 1),
            ("External-IP", "string", 1),
            ("OS-Image", "string", 1),
            ("Kernel-Version", "string", 1),
            ("Container-Runtime", "string", 1),
        ],
        _node_cells,
    ),
    "namespaces": (
        [("Name", "string", 0), ("Status", "string", 0), ("Age", "string", 0)],
        lambda o: [
            o["metadata"]["name"],
            o["status"]["phase"],
            _age(o["metadata"]["creationTimestamp"]),
        ],
    ),
    "secrets": (
        [
            ("Name", "string", 0),
            ("Type", "string", 0),
            ("Data", "integer", 0),
            ("Age", "string", 0),
        ],
        lambda o: [
            o["metadata"]["name"],
            o["type"],
            len(o["data"]),
            _age(o["metadata"]["creationTimestamp"]),
        ],
    ),
    "serviceaccounts": (
        [("Name", "string", 0), ("Secrets", "integer", 0), ("Age", "string", 0)],
        lambda o: [o["metadata"]["name"], 0, _age(o["metadata"]["creationTimestamp"])],
    ),
    "clusterroles": (
        [("Name", "string", 0), ("Created At", "date", 0)],
        lambda o: [o["metadata"]["name"], o["metadata"]["creationTimestamp"]],
    ),
    "clusterrolebindings": (
        [
            ("Name", "string", 0),
            ("Role", "string", 0),
            ("Age", "string", 0),
            ("Users", "string", 1),
            ("Groups", "string", 1),
            ("ServiceAccounts", "string", 1),
        ],
        lambda o: [
            o["metadata"]["name"],
            f"{o['roleRef']['kind']}/{o['roleRef']['name']}",
            _age(o["metadata"]["creationTimestamp"]),
            "",
            ",".join(s["name"] for s in o["subjects"] if s["kind"] == "Group"),
            "",
        ],
    ),
}


def _list_response(
    request: web.Request,
    resource: str,
    kind: str,
    api_version: str,
    items: list[dict[str, Any]],
    headers: dict[str, str],
) -> web.Response:
    """The list as kubectl asked for it: a Table when `Accept` says `as=Table`, else the List."""
    if "as=Table" in request.headers.get("Accept", ""):
        columns, cells = _TABLES.get(resource, _NAME_AGE)
        body: dict[str, Any] = {
            "kind": "Table",
            "apiVersion": "meta.k8s.io/v1",
            "metadata": {"resourceVersion": "48211"},
            "columnDefinitions": [
                {
                    "name": col,
                    "type": kind_,
                    "format": "name" if col == "Name" else "",
                    "description": col,
                    "priority": priority,
                }
                for col, kind_, priority in columns
            ],
            "rows": [
                {
                    "cells": cells(item),
                    "object": {
                        "kind": "PartialObjectMetadata",
                        "apiVersion": "meta.k8s.io/v1",
                        "metadata": item["metadata"],
                    },
                }
                for item in items
            ],
        }
    else:
        body = {
            "kind": f"{kind}List",
            "apiVersion": api_version,
            "metadata": {"resourceVersion": "48211"},
            "items": items,
        }
    return web.json_response(body, headers=headers, dumps=compact_dumps)


class KubernetesEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._runners: dict[str, web.AppRunner] = {}

    @staticmethod
    async def _read_json(request: web.Request) -> dict[str, Any]:
        # Loop to EOF: `content.read(n)` returns after the first chunk, so a
        # manifest sent in two writes arrived as half a JSON document and the
        # escape it carried was filed as an ordinary pod create.
        try:
            body = await read_body(request, _MAX_BODY_BYTES)
            if not body.data:
                return {}
            parsed = json.loads(body.data)
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
            # decoy in a single request. Audit-Id is per request; the flow-control UIDs name
            # the server's FlowSchema/PriorityLevel objects, so they are constant.
            return {
                "Audit-Id": str(uuid.uuid4()),
                "Cache-Control": "no-cache, private",
                "X-Kubernetes-Pf-Flowschema-Uid": _uid(name, "flowschema"),
                "X-Kubernetes-Pf-Prioritylevel-Uid": _uid(name, "prioritylevel"),
            }

        async def version(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {
                    "major": _K8S_MAJOR,
                    "minor": _K8S_MINOR,
                    "gitVersion": _K8S_VERSION,
                    "gitCommit": _K8S_GIT_COMMIT,
                    "gitTreeState": "clean",
                    "buildDate": _K8S_BUILD_DATE,
                    "goVersion": _GO_VERSION,
                    "compiler": "gc",
                    "platform": "linux/amd64",
                },
                headers=headers(),
                dumps=compact_dumps,
            )

        async def health(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.Response(text="ok", content_type="text/plain", headers=headers())

        async def resource_list(request: web.Request) -> web.Response:
            group_version = request.match_info.get("gv", "")
            if "group" in request.match_info:
                group_version = f"{request.match_info['group']}/{request.match_info['version']}"
            elif not group_version:
                group_version = "v1"
            if group_version not in _RESOURCES:
                return await catch_all(request)
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                _resource_list(group_version), headers=headers(), dumps=compact_dumps
            )

        async def api_root(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            return web.json_response(
                {"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": []},
                headers=headers(),
                dumps=compact_dumps,
            )

        async def api_groups(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_recon", AlertSeverity.MEDIUM, {})
            groups = [
                {
                    "name": group,
                    "versions": [{"groupVersion": f"{group}/v1", "version": "v1"}],
                    "preferredVersion": {"groupVersion": f"{group}/v1", "version": "v1"},
                }
                for group in (
                    "apps",
                    "batch",
                    "rbac.authorization.k8s.io",
                    "networking.k8s.io",
                    "authorization.k8s.io",
                )
            ]
            return web.json_response(
                {"kind": "APIGroupList", "apiVersion": "v1", "groups": groups},
                headers=headers(),
                dumps=compact_dumps,
            )

        async def list_namespaces(request: web.Request) -> web.Response:
            await self._record(hp_id, request, "kubernetes_enumerate", AlertSeverity.HIGH, {})
            items = [
                {
                    "metadata": {
                        "name": ns,
                        "uid": _uid(name, "namespace", ns),
                        "resourceVersion": str(40 + n),
                        "creationTimestamp": _CREATED,
                        "labels": {"kubernetes.io/metadata.name": ns},
                    },
                    "spec": {"finalizers": ["kubernetes"]},
                    "status": {"phase": "Active"},
                }
                for n, ns in enumerate(
                    ("default", "kube-system", "production", "payments", "monitoring")
                )
            ]
            return _list_response(request, "namespaces", "Namespace", "v1", items, headers())

        async def list_nodes(request: web.Request) -> web.Response:
            await self._record(
                hp_id,
                request,
                "kubernetes_enumerate",
                AlertSeverity.HIGH,
                {"resource": "nodes"},
            )
            node = {
                "metadata": {
                    "name": _NODE,
                    "uid": _uid(name, "node", _NODE),
                    "resourceVersion": "48190",
                    "creationTimestamp": _CREATED,
                    "labels": {
                        "kubernetes.io/hostname": _NODE,
                        "kubernetes.io/os": "linux",
                        "kubernetes.io/arch": "amd64",
                        "node-role.kubernetes.io/control-plane": "",
                    },
                },
                "spec": {"providerID": f"aws:///us-east-1a/i-{_uid(name, 'instance')[:17]}"},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True", "reason": "KubeletReady"}],
                    "addresses": [
                        {"type": "InternalIP", "address": "10.0.1.42"},
                        {"type": "Hostname", "address": _NODE},
                    ],
                    "nodeInfo": {
                        "kubeletVersion": _K8S_VERSION,
                        "osImage": "Ubuntu 22.04.3 LTS",
                        "kernelVersion": "5.15.0-1051-aws",
                        "containerRuntimeVersion": "containerd://1.7.8",
                        "operatingSystem": "linux",
                        "architecture": "amd64",
                    },
                },
            }
            return _list_response(request, "nodes", "Node", "v1", [node], headers())

        async def list_serviceaccounts(request: web.Request) -> web.Response:
            namespace = request.match_info.get("ns", "default")
            await self._record(
                hp_id,
                request,
                "kubernetes_enumerate",
                AlertSeverity.HIGH,
                {"namespace": namespace[:64], "resource": "serviceaccounts"},
            )
            items = [
                {
                    "metadata": {
                        "name": "default",
                        "namespace": namespace,
                        "uid": _uid(name, "serviceaccount", namespace, "default"),
                        "creationTimestamp": _CREATED,
                    }
                }
            ]
            return _list_response(
                request, "serviceaccounts", "ServiceAccount", "v1", items, headers()
            )

        async def list_empty(request: web.Request) -> web.Response:
            # A resource the decoy advertises but has no objects for: a valid empty list, which
            # is what a cluster with none of them returns.
            info = request.match_info
            group_version = f"{info['group']}/{info['version']}" if "group" in info else "v1"
            resource = info["resource"]
            kind = next((k for r, k, _ in _RESOURCES.get(group_version, ()) if r == resource), None)
            if kind is None:
                return await catch_all(request)
            if resource in _CREATE_ONLY:
                return web.json_response(
                    _status(
                        "the server does not allow this method on the requested resource",
                        "MethodNotAllowed",
                        405,
                    ),
                    status=405,
                    headers=headers(),
                    dumps=compact_dumps,
                )
            await self._record(
                hp_id,
                request,
                "kubernetes_enumerate",
                AlertSeverity.HIGH,
                {"resource": resource[:64]},
            )
            return _list_response(request, resource, kind, group_version, [], headers())

        async def access_review(request: web.Request) -> web.Response:
            # `kubectl auth can-i`: what a holder of a stolen token runs first. The decoy's
            # persona is a permissive cluster, so every check is allowed.
            body = await self._read_json(request)
            await self._record(
                hp_id,
                request,
                "kubernetes_recon",
                AlertSeverity.MEDIUM,
                {"note": "checking own permissions"},
            )
            rules = request.path.endswith("selfsubjectrulesreviews")
            status: dict[str, Any] = (
                {
                    "resourceRules": [{"verbs": ["*"], "apiGroups": ["*"], "resources": ["*"]}],
                    "nonResourceRules": [{"verbs": ["*"], "nonResourceURLs": ["*"]}],
                    "incomplete": False,
                }
                if rules
                else {"allowed": True}
            )
            return web.json_response(
                {
                    "kind": "SelfSubjectRulesReview" if rules else "SelfSubjectAccessReview",
                    "apiVersion": "authorization.k8s.io/v1",
                    "metadata": {"creationTimestamp": None},
                    "spec": _as_dict(body.get("spec")),
                    "status": status,
                },
                status=201,
                headers=headers(),
                dumps=compact_dumps,
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

            def pod(n: int, app: str, image: str) -> dict[str, Any]:
                suffix = hashlib.sha256(f"{name}/{namespace}/{app}".encode()).hexdigest()
                pod_name = f"{app}-{suffix[:10]}-{suffix[10:15]}"
                return {
                    "metadata": {
                        "name": pod_name,
                        "namespace": namespace,
                        "uid": _uid(name, "pod", namespace, app),
                        "resourceVersion": str(30000 + n),
                        "creationTimestamp": _CREATED,
                        "labels": {"app": app},
                    },
                    "spec": {
                        "containers": [{"name": app, "image": image}],
                        "nodeName": _NODE,
                        "serviceAccountName": "default",
                    },
                    "status": {
                        "phase": "Running",
                        "hostIP": "10.0.1.42",
                        "podIP": f"10.244.1.{n + 10}",
                        "startTime": _CREATED,
                        "conditions": [{"type": "Ready", "status": "True"}],
                        "containerStatuses": [
                            {
                                "name": app,
                                "image": image,
                                "ready": True,
                                "restartCount": 0,
                                "started": True,
                                "state": {"running": {"startedAt": _CREATED}},
                            }
                        ],
                    },
                }

            items = [
                pod(n, app, image)
                for n, (app, image) in enumerate(
                    (
                        ("payments-api", "registry.internal/payments-api:2.4.1"),
                        ("postgres", "postgres:15.4"),
                        ("redis", "redis:7.2-alpine"),
                    )
                )
            ]
            return _list_response(request, "pods", "Pod", "v1", items, headers())

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
                    "metadata": {
                        "name": nm,
                        "namespace": namespace,
                        "uid": _uid(name, "secret", namespace, nm),
                        "creationTimestamp": _CREATED,
                    },
                    "type": kind,
                    "data": {key: _secret_data(name, nm, key)},
                }
                for nm, kind, key in (
                    ("default-token-x7k2p", "kubernetes.io/service-account-token", "token"),
                    ("registry-pull-secret", "kubernetes.io/dockerconfigjson", ".dockerconfigjson"),
                    ("postgres-credentials", "Opaque", "password"),
                )
            ]
            return _list_response(request, "secrets", "Secret", "v1", items, headers())

        async def list_rbac(request: web.Request) -> web.Response:
            await self._record(
                hp_id,
                request,
                "kubernetes_rbac_enumerate",
                AlertSeverity.HIGH,
                {"note": "mapping permissions — looking for a path to cluster-admin"},
            )
            clusterroles = request.path.endswith("clusterroles")
            if clusterroles:
                items: list[dict[str, Any]] = [
                    {
                        "metadata": {
                            "name": "cluster-admin",
                            "uid": _uid(name, "clusterrole", "cluster-admin"),
                            "creationTimestamp": _CREATED,
                        },
                        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                    }
                ]
            else:
                items = [
                    {
                        "metadata": {
                            "name": "cluster-admin",
                            "uid": _uid(name, "clusterrolebinding", "cluster-admin"),
                            "creationTimestamp": _CREATED,
                        },
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "ClusterRole",
                            "name": "cluster-admin",
                        },
                        "subjects": [
                            {
                                "apiGroup": "rbac.authorization.k8s.io",
                                "kind": "Group",
                                "name": "system:masters",
                            }
                        ],
                    }
                ]
            return _list_response(
                request,
                "clusterroles" if clusterroles else "clusterrolebindings",
                "ClusterRole" if clusterroles else "ClusterRoleBinding",
                "rbac.authorization.k8s.io/v1",
                items,
                headers(),
            )

        async def create_pod(request: web.Request) -> web.Response:
            body = await self._read_json(request)
            namespace = request.match_info.get("ns", "default")
            try:
                reasons = analyse_pod_spec(body)
            except Exception:
                # Analysis is a bonus on top of capture: a manifest that trips it
                # must still reach `_record()`, never a raw 500.
                log.exception("analyse_pod_spec failed; recording the attempt unanalysed")
                reasons = []
            pod_name = _as_dict(body.get("metadata")).get("name") or f"pod-{secrets.token_hex(4)}"
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
                dumps=compact_dumps,
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
                dumps=compact_dumps,
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
                dumps=compact_dumps,
            )

        app = web.Application(
            middlewares=[server_identity_middleware(_SERVER_BANNER)],
            client_max_size=MAX_REQUEST_BYTES,
        )
        router = app.router
        router.add_get("/version", version)
        router.add_get("/healthz", health)
        router.add_get("/livez", health)
        router.add_get("/readyz", health)
        router.add_get("/api", api_root)
        router.add_get("/apis", api_groups)
        router.add_get("/api/v1", resource_list)
        router.add_get("/apis/{group}/{version}", resource_list)
        router.add_get("/api/v1/namespaces", list_namespaces)
        router.add_get("/api/v1/nodes", list_nodes)
        router.add_get("/api/v1/pods", list_pods)
        router.add_get("/api/v1/secrets", list_secrets)
        router.add_get("/api/v1/namespaces/{ns}/pods", list_pods)
        router.add_get("/api/v1/namespaces/{ns}/secrets", list_secrets)
        router.add_get("/api/v1/namespaces/{ns}/serviceaccounts", list_serviceaccounts)
        router.add_get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", list_rbac)
        router.add_get("/apis/rbac.authorization.k8s.io/v1/clusterroles", list_rbac)
        router.add_post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", access_review)
        router.add_post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", access_review)
        router.add_post("/api/v1/namespaces/{ns}/pods", create_pod)
        router.add_post("/api/v1/namespaces/{ns}/pods/{pod}/exec", pod_exec)
        router.add_get("/api/v1/namespaces/{ns}/pods/{pod}/exec", pod_exec)
        router.add_get("/api/v1/{resource}", list_empty)
        router.add_get("/api/v1/namespaces/{ns}/{resource}", list_empty)
        router.add_get("/apis/{group}/{version}/{resource}", list_empty)
        router.add_get("/apis/{group}/{version}/namespaces/{ns}/{resource}", list_empty)
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
        # kube-apiserver has no plaintext listener: kubectl, client-go and every scanner open
        # TLS first, so an API that answers plain HTTP on 6443 is identified (and unusable by
        # kubectl) before the first request. The self-signed cert persists across restarts.
        from honeypot_mcp.engines.tls import build_server_ssl_context_async

        ssl_context = await build_server_ssl_context_async(name, common_name="kube-apiserver")
        await web.TCPSite(runner, "0.0.0.0", port, ssl_context=ssl_context).start()
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
