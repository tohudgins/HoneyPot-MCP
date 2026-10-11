"""A validating proxy between the honeypot service and the Docker daemon.

Access to the Docker socket is root on the host: anything that can ask the daemon for a
privileged container with `/` bind-mounted owns the machine. The honeypot service needs Docker
for exactly one job, running Cowrie containers, and it parses attacker-controlled bytes all day,
so a bug in it that reaches arbitrary Docker calls would be a root compromise. Putting the
service in the `docker` group makes that the default; this guard removes it.

The service is *not* in the `docker` group. It talks to this guard's socket instead, and the
guard (a separate, tiny process that does hold Docker access) forwards a request only if it is
one of the handful of operations the SSH engine performs, with arguments the engine would use:

* create a container from exactly the pinned Cowrie image, named ``honeypot-*``, labelled
  ``honeypot-mcp=true``, with the engine's own security settings (every capability dropped,
  read-only root, no-new-privileges, bridge network, memory/PID/CPU ceilings, the two Cowrie
  ports published, the engine's tmpfs mounts and one anonymous volume): no privileged mode, no
  host paths, no host namespaces, no devices, no other image;
* start, stop, restart, kill, pause, unpause, inspect, read logs of, remove, and copy the
  persona archive into/out of containers that carry that label, and no others;
* list containers filtered to that label; pull the pinned image; ping and version.

Everything else (exec, attach, networks, volumes, builds, `info`, events, other images, other
containers, the daemon's own endpoints) is refused with 403 before it reaches Docker. A
compromised service can therefore still manage Cowrie containers, which it could always do, but
cannot turn that into root.

Wire handling is deliberately minimal: one request per connection (``Connection: close`` is
forced upstream), bounded head and body, no chunked request bodies, no protocol upgrades, and
the response is relayed byte for byte. The caller must be on the socket's owning group (file
mode) and, on Linux, one of the allowed UIDs (``SO_PEERCRED``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import grp
import ipaddress
import json
import logging
import os
import pwd
import re
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

from honeypot_mcp.engines.cowrie_fs import BASE_PICKLE_PATH, PERSONA_DIR
from honeypot_mcp.engines.cowrie_limits import (
    COWRIE_IMAGE,
    COWRIE_INTERNAL_PORT,
    COWRIE_MEM_LIMIT_BYTES,
    COWRIE_NANO_CPUS,
    COWRIE_PIDS_LIMIT,
    COWRIE_TELNET_PORT,
    COWRIE_TMPFS,
)

log = logging.getLogger("honeypot_mcp.docker_guard")

LABEL = "honeypot-mcp"
NAME_PREFIX = "honeypot-"
MAX_HEAD = 16 * 1024
MAX_JSON_BODY = 64 * 1024
MAX_ARCHIVE_BODY = 8 * 1024 * 1024
HEAD_TIMEOUT = 10.0
BODY_TIMEOUT = 30.0
MAX_CONCURRENT = 64

_VERSION_PREFIX = re.compile(r"^/v\d{1,2}\.\d{1,3}(?=/)")
_CONTAINER_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CONTAINER_NAME = re.compile(r"^honeypot-[A-Za-z0-9][A-Za-z0-9_.-]{0,100}$")
_IMAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,200}$")
_PORTS = {f"{COWRIE_INTERNAL_PORT}/tcp", f"{COWRIE_TELNET_PORT}/tcp"}
_SIGNALS = {"KILL", "SIGKILL", "TERM", "SIGTERM", "INT", "SIGINT", "9", "15", "2"}

# Headers that are not forwarded: the guard sets its own framing and never upgrades.
_DROP_HEADERS = {
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "expect",
    "upgrade",
    "keep-alive",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
}


class Denied(Exception):
    """The request is not one the honeypot service may make."""

    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True)
class Verdict:
    """What the guard decided: forward, and whether the target container needs a label check."""

    container: str | None = None  # a container reference whose label must be checked


# ── the policy ───────────────────────────────────────────────────────────────────────────────


def _empty(value: Any) -> bool:
    return value in (None, "", 0, False, [], {}, ())


def _require_empty(obj: dict[str, Any], keys: set[str] | tuple[str, ...], where: str) -> None:
    for key in keys:
        if key in obj and not _empty(obj[key]):
            raise Denied(f"{where}.{key} is not permitted")


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise Denied(f"{what} must be an integer")
    return value


def _validate_port_bindings(bindings: Any) -> None:
    if _empty(bindings):
        return
    if not isinstance(bindings, dict):
        raise Denied("HostConfig.PortBindings must be an object")
    for port, targets in bindings.items():
        if port not in _PORTS:
            raise Denied(f"port {port} may not be published")
        if not isinstance(targets, list) or not targets:
            raise Denied("HostConfig.PortBindings entries must be non-empty lists")
        for target in targets:
            if not isinstance(target, dict) or set(target) - {"HostIp", "HostPort"}:
                raise Denied("HostConfig.PortBindings entry has unexpected fields")
            host_port = str(target.get("HostPort", ""))
            if not host_port.isdigit() or not 1 <= int(host_port) <= 65535:
                raise Denied("HostConfig.PortBindings host port is not a valid port")
            host_ip = target.get("HostIp", "")
            if host_ip:
                try:
                    ipaddress.ip_address(host_ip)
                except ValueError as exc:
                    raise Denied("HostConfig.PortBindings host address is not an IP") from exc


def _validate_mounts(mounts: Any) -> None:
    if _empty(mounts):
        return
    if not isinstance(mounts, list) or len(mounts) != 1 or not isinstance(mounts[0], dict):
        raise Denied("HostConfig.Mounts may only hold the persona volume")
    mount = mounts[0]
    if (
        mount.get("Type") != "volume"
        or mount.get("Target") != PERSONA_DIR
        or mount.get("Source")
        or mount.get("ReadOnly")
        or set(mount) - {"Type", "Target", "Source", "ReadOnly", "VolumeOptions"}
        or not _empty(mount.get("VolumeOptions"))
    ):
        raise Denied("HostConfig.Mounts may only be one anonymous volume at the persona path")


def _validate_host_config(host: Any) -> None:
    if not isinstance(host, dict):
        raise Denied("HostConfig is required")

    # Isolation: the container may not share, reach into or manage the host.
    if host.get("Privileged"):
        raise Denied("HostConfig.Privileged is not permitted")
    if host.get("NetworkMode") not in (None, "", "default", "bridge"):
        raise Denied("HostConfig.NetworkMode must be the default bridge")
    _require_empty(
        host,
        (
            "Binds", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "Cgroup", "CgroupnsMode",
            "CapAdd", "Devices", "DeviceCgroupRules", "DeviceRequests", "VolumesFrom", "Links",
            "ExtraHosts", "Sysctls", "StorageOpt", "CgroupParent", "GroupAdd", "PublishAllPorts",
            "MaskedPaths", "ReadonlyPaths", "OomScoreAdj", "VolumeDriver", "ConsoleSize",
            "Isolation", "Runtime",
        ),
        "HostConfig",
    )  # fmt: skip
    cap_drop = host.get("CapDrop")
    if not isinstance(cap_drop, list) or "ALL" not in cap_drop:
        raise Denied("HostConfig.CapDrop must drop ALL capabilities")
    security_opt = host.get("SecurityOpt")
    if not _empty(security_opt) and security_opt != ["no-new-privileges:true"]:
        raise Denied("HostConfig.SecurityOpt may only be no-new-privileges")
    if host.get("ReadonlyRootfs") is not True:
        raise Denied("HostConfig.ReadonlyRootfs must be true")

    # Resource ceilings: at or below the engine's own.
    memory = _int(host.get("Memory", 0), "HostConfig.Memory")
    if not 0 < memory <= COWRIE_MEM_LIMIT_BYTES:
        raise Denied("HostConfig.Memory must be set and within the honeypot ceiling")
    swap = host.get("MemorySwap")
    if (
        not _empty(swap)
        and not 0 < _int(swap, "HostConfig.MemorySwap") <= 2 * COWRIE_MEM_LIMIT_BYTES
    ):
        raise Denied("HostConfig.MemorySwap exceeds the honeypot ceiling")
    pids = _int(host.get("PidsLimit", 0), "HostConfig.PidsLimit")
    if not 0 < pids <= COWRIE_PIDS_LIMIT:
        raise Denied("HostConfig.PidsLimit must be set and within the honeypot ceiling")
    cpus = _int(host.get("NanoCpus", 0), "HostConfig.NanoCpus")
    if not 0 < cpus <= COWRIE_NANO_CPUS:
        raise Denied("HostConfig.NanoCpus must be set and within the honeypot ceiling")

    _validate_port_bindings(host.get("PortBindings"))
    _validate_mounts(host.get("Mounts"))

    tmpfs = host.get("Tmpfs")
    if not _empty(tmpfs) and (
        not isinstance(tmpfs, dict)
        or any(
            path not in COWRIE_TMPFS or options != COWRIE_TMPFS[path]
            for path, options in tmpfs.items()
        )
    ):
        raise Denied("HostConfig.Tmpfs may only be the honeypot's own mounts")

    dns = host.get("Dns")
    if not _empty(dns):
        if not isinstance(dns, list):
            raise Denied("HostConfig.Dns must be a list")
        for server in dns:
            try:
                ipaddress.ip_address(server)
            except (ValueError, TypeError) as exc:
                raise Denied("HostConfig.Dns entries must be IP addresses") from exc

    restart = host.get("RestartPolicy")
    if not _empty(restart) and (
        not isinstance(restart, dict)
        or restart.get("Name") not in ("", "no", "unless-stopped", "on-failure", "always")
    ):
        raise Denied("HostConfig.RestartPolicy is not permitted")

    log_config = host.get("LogConfig")
    if not _empty(log_config):
        config = log_config.get("Config") if isinstance(log_config, dict) else None
        if (
            not isinstance(log_config, dict)
            or log_config.get("Type") != "json-file"
            or (config and set(config) - {"max-size", "max-file"})
        ):
            raise Denied("HostConfig.LogConfig must be json-file with size limits")

    # Anything else is refused if it does something. Settings that merely tune the container
    # (logging, restart, Init, OomKillDisable, AutoRemove, ShmSize ...) are in this set.
    known = {
        "Binds", "PidMode", "IpcMode", "UTSMode", "UsernsMode", "Cgroup", "CgroupnsMode", "CapAdd",
        "Devices", "DeviceCgroupRules", "DeviceRequests", "VolumesFrom", "Links", "ExtraHosts",
        "Sysctls", "StorageOpt", "CgroupParent", "GroupAdd", "PublishAllPorts", "MaskedPaths",
        "ReadonlyPaths", "OomScoreAdj", "VolumeDriver", "ConsoleSize", "Isolation", "Runtime",
        "Privileged", "NetworkMode", "CapDrop", "SecurityOpt", "ReadonlyRootfs", "Memory",
        "MemorySwap", "PidsLimit", "NanoCpus", "PortBindings", "Mounts", "Tmpfs", "Dns",
        "RestartPolicy", "LogConfig", "AutoRemove", "Init", "OomKillDisable", "ShmSize",
        "DnsOptions", "DnsSearch", "CpuShares", "CpuPeriod", "CpuQuota", "CpusetCpus",
        "CpusetMems", "BlkioWeight", "MemoryReservation", "MemorySwappiness", "KernelMemory",
        "Ulimits", "LogDriver",
    }  # fmt: skip
    extra = [key for key, value in host.items() if key not in known and not _empty(value)]
    if extra:
        raise Denied(f"HostConfig.{extra[0]} is not permitted")


def validate_create(body: Any, query: dict[str, list[str]]) -> None:
    """Refuse any container-create request that is not a Cowrie honeypot as the engine builds it."""
    if not isinstance(body, dict):
        raise Denied("container create body must be a JSON object")
    name = (query.get("name") or [""])[0]
    if not _CONTAINER_NAME.match(name):
        raise Denied(f"container name must match {NAME_PREFIX}*")
    if body.get("Image") != COWRIE_IMAGE:
        raise Denied("only the pinned Cowrie image may be run")
    labels = body.get("Labels")
    if not isinstance(labels, dict) or labels.get(LABEL) != "true":
        raise Denied(f"container must be labelled {LABEL}=true")

    # The engine runs the image's own entrypoint as the image's own user, with no stdin.
    _require_empty(
        body,
        (
            "Cmd", "Entrypoint", "User", "WorkingDir", "Volumes", "Healthcheck", "Shell",
            "OnBuild", "MacAddress", "NetworkDisabled", "AttachStdin", "OpenStdin", "StdinOnce",
            "Tty", "ArgsEscaped", "Domainname",
        ),
        "container",
    )  # fmt: skip
    networking = body.get("NetworkingConfig")
    if not _empty(networking) and networking not in (
        {"EndpointsConfig": {}},
        {"EndpointsConfig": None},
    ):
        raise Denied("container.NetworkingConfig is not permitted")
    env = body.get("Env")
    if not _empty(env) and (
        not isinstance(env, list) or len(env) > 200 or not all(isinstance(e, str) for e in env)
    ):
        raise Denied("container.Env must be a list of KEY=VALUE strings")
    exposed = body.get("ExposedPorts")
    if not _empty(exposed) and (not isinstance(exposed, dict) or set(exposed) - _PORTS):
        raise Denied("container.ExposedPorts may only be the Cowrie ports")
    allowed = {
        "Image", "Labels", "Env", "ExposedPorts", "HostConfig", "NetworkingConfig", "Hostname",
        "StopSignal", "StopTimeout", "AttachStdout", "AttachStderr",
        "Cmd", "Entrypoint", "User", "WorkingDir", "Volumes", "Healthcheck", "Shell", "OnBuild",
        "MacAddress", "NetworkDisabled", "AttachStdin", "OpenStdin", "StdinOnce", "Tty",
        "ArgsEscaped", "Domainname",
    }  # fmt: skip
    extra = [key for key, value in body.items() if key not in allowed and not _empty(value)]
    if extra:
        raise Denied(f"container.{extra[0]} is not permitted")
    _validate_host_config(body.get("HostConfig"))


def _label_filter_ok(raw: str) -> bool:
    try:
        filters = json.loads(raw)
    except ValueError:
        return False
    if not isinstance(filters, dict):
        return False
    wanted = f"{LABEL}=true"
    labels = filters.get("label")
    if isinstance(labels, list):
        return wanted in labels
    if isinstance(labels, dict):
        return bool(labels.get(wanted))
    return labels == wanted


def _image_matches(name: str, tag: str | None = None) -> bool:
    ref = f"{name}:{tag}" if tag else name
    return ref == COWRIE_IMAGE


def check(method: str, target: str, body: bytes = b"") -> Verdict:
    """Decide whether `method target` (with its body) is a request the honeypot service may make.

    Raises `Denied` otherwise. Pure: nothing here touches Docker or the network, so every rule
    is exercised by the unit tests.
    """
    parts = urlsplit(target)
    path = _VERSION_PREFIX.sub("", parts.path, count=1)
    if (
        not path.startswith("/")
        or "%" in path
        or "//" in path
        or "/." in path
        or any(ord(ch) < 33 or ord(ch) > 126 for ch in path)
    ):
        raise Denied("malformed request path", 400)
    query = parse_qs(parts.query, keep_blank_values=True)
    segments = path.strip("/").split("/")

    if path == "/_ping" and method in ("GET", "HEAD"):
        return Verdict()
    if path == "/version" and method == "GET":
        return Verdict()

    if segments[0] == "containers":
        if path == "/containers/json" and method == "GET":
            if not _label_filter_ok((query.get("filters") or [""])[0]):
                raise Denied(f"container listings must be filtered to {LABEL}=true")
            return Verdict()
        if path == "/containers/create" and method == "POST":
            if len(body) > MAX_JSON_BODY:
                raise Denied("request body too large", 413)
            try:
                parsed = json.loads(body.decode("utf-8"))
            except ValueError as exc:
                raise Denied("container create body is not valid JSON", 400) from exc
            validate_create(parsed, query)
            return Verdict()
        if len(segments) >= 2 and _CONTAINER_REF.match(segments[1]):
            ref, action = segments[1], "/".join(segments[2:])
            allowed = {
                ("GET", "json"),
                ("GET", "logs"),
                ("POST", "start"),
                ("POST", "stop"),
                ("POST", "restart"),
                ("POST", "pause"),
                ("POST", "unpause"),
                ("POST", "kill"),
                ("DELETE", ""),
                ("PUT", "archive"),
                ("GET", "archive"),
                ("HEAD", "archive"),
            }
            if (method, action) in allowed:
                if action == "kill" and (query.get("signal") or ["KILL"])[0] not in _SIGNALS:
                    raise Denied("signal not permitted")
                if action == "archive":
                    wanted = PERSONA_DIR if method == "PUT" else BASE_PICKLE_PATH
                    if (query.get("path") or [""])[0] != wanted:
                        raise Denied("archive path not permitted")
                    if method == "PUT" and len(body) > MAX_ARCHIVE_BODY:
                        raise Denied("request body too large", 413)
                return Verdict(container=ref)

    if segments[0] == "images":
        if path == "/images/create" and method == "POST":
            image = (query.get("fromImage") or [""])[0]
            tag = (query.get("tag") or [""])[0] or None
            if (query.get("fromSrc") or query.get("repo")) or not _image_matches(image, tag):
                raise Denied("only the pinned Cowrie image may be pulled")
            return Verdict()
        if method == "GET" and len(segments) >= 3 and segments[-1] == "json":
            name = "/".join(segments[1:-1])
            if _IMAGE_REF.match(name) and name == COWRIE_IMAGE:
                return Verdict()

    raise Denied(f"{method} {path} is not permitted through the honeypot Docker guard")


# ── the proxy ────────────────────────────────────────────────────────────────────────────────


def _deny_response(status: int, message: str) -> bytes:
    body = json.dumps({"message": f"honeypot docker guard: {message}"}).encode()
    reason = {
        400: "Bad Request",
        403: "Forbidden",
        411: "Length Required",
        413: "Payload Too Large",
    }
    return (
        f"HTTP/1.1 {status} {reason.get(status, 'Error')}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body


def _clean(text: str, what: str, *, allow_tab: bool = False) -> None:
    """Refuse bare CR/LF, NUL and other control characters. Everything is split on CRLF, so a
    stray LF inside a value would be read by the daemon as a *new header line*: one that is not
    subject to the guard's own framing rules (it could carry its own Content-Length)."""
    for ch in text:
        if (ord(ch) < 32 and not (allow_tab and ch == "\t")) or ord(ch) == 127:
            raise Denied(f"control character in the {what}", 400)


def _parse_head(head: bytes) -> tuple[str, str, list[tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    _clean(lines[0], "request line")
    request_line = lines[0].split(" ")
    if len(request_line) != 3 or not request_line[2].startswith("HTTP/1."):
        raise Denied("malformed request line", 400)
    method, target, _version = request_line
    if not re.fullmatch(r"[A-Z]{3,7}", method):
        raise Denied("malformed method", 400)
    if any(ord(ch) > 126 for ch in target):
        raise Denied("non-ASCII character in the request target", 400)
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        _clean(line, "headers", allow_tab=True)
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise Denied("malformed header", 400)
        headers.append((name, value.strip()))
    return method, target, headers


async def _label_ok(upstream: str, ref: str) -> bool | None:
    """True if container `ref` carries the honeypot label, False if it exists without it, None
    if it does not exist (the request is forwarded so Docker answers 404 itself)."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(upstream), 5)
        writer.write(
            f"GET /containers/{ref}/json HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), 10)
        writer.close()
    except (OSError, TimeoutError):
        raise Denied("docker daemon unavailable", 403) from None
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
    if status == 404:
        return None
    if status != 200:
        return False
    if b"\r\ntransfer-encoding: chunked" in head.lower():
        payload = _dechunk(payload)
    try:
        labels = (json.loads(payload).get("Config") or {}).get("Labels") or {}
    except ValueError:
        return False
    return labels.get(LABEL) == "true"


def _dechunk(data: bytes) -> bytes:
    out = b""
    while data:
        size_line, _, rest = data.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            return out
        if size == 0:
            break
        out += rest[:size]
        data = rest[size + 2 :]
    return out


def _peer_uid(writer: asyncio.StreamWriter) -> int | None:
    sock = writer.get_extra_info("socket")
    if sock is None or not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        _pid, uid, _gid = struct.unpack(
            "3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
    except OSError:
        return None
    return uid


class Guard:
    def __init__(self, upstream: str, allowed_uids: set[int] | None = None) -> None:
        self.upstream = upstream
        self.allowed_uids = allowed_uids or set()
        self._slots = asyncio.Semaphore(MAX_CONCURRENT)
        self.denied = 0
        self.forwarded = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            async with self._slots:
                await self._serve(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.CancelledError):
            pass
        except Exception:
            log.exception("docker guard failed handling a request")
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.allowed_uids:
            uid = _peer_uid(writer)
            if uid is not None and uid not in self.allowed_uids:
                log.warning("denied connection from uid %s", uid)
                self.denied += 1
                return
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
            method, target, headers = _parse_head(head[:-4])
            lengths = [v for k, v in headers if k.lower() == "content-length"]
            if any(k.lower() == "transfer-encoding" for k, _ in headers):
                raise Denied("chunked request bodies are not supported", 411)
            if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
                raise Denied("bad Content-Length", 400)
            length = int(lengths[0]) if lengths else 0
            if length > MAX_ARCHIVE_BODY:
                raise Denied("request body too large", 413)
            body = (
                await asyncio.wait_for(reader.readexactly(length), BODY_TIMEOUT) if length else b""
            )
            verdict = check(method, target, body)
            if verdict.container is not None:
                ok = await _label_ok(self.upstream, verdict.container)
                if ok is False:
                    raise Denied(f"container is not a {LABEL} honeypot")
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            await self._reply(writer, Denied("request head too large or truncated", 400))
            return
        except TimeoutError:
            return
        except Denied as denial:
            log.warning("denied %s", denial.message)
            await self._reply(writer, denial)
            return
        await self._forward(reader, writer, method, target, headers, body)

    async def _reply(self, writer: asyncio.StreamWriter, denial: Denied) -> None:
        self.denied += 1
        with contextlib.suppress(Exception):
            writer.write(_deny_response(denial.status, denial.message))
            await writer.drain()

    async def _forward(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        try:
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.upstream, limit=2**20), 5
            )
        except (OSError, TimeoutError):
            await self._reply(writer, Denied("docker daemon unavailable", 403))
            return
        self.forwarded += 1
        out = [f"{method} {target} HTTP/1.1", "Host: docker", "Connection: close"]
        out += [f"{k}: {v}" for k, v in headers if k.lower() not in _DROP_HEADERS]
        if body or method in ("POST", "PUT"):
            out.append(f"Content-Length: {len(body)}")
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await up_writer.drain()

        async def pump() -> None:
            while chunk := await up_reader.read(65536):
                writer.write(chunk)
                await writer.drain()

        # A client that goes away mid-stream (a log follow) must end the relay.
        relay = asyncio.ensure_future(pump())
        watch = asyncio.ensure_future(reader.read(1))
        try:
            await asyncio.wait({relay, watch}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (relay, watch):
                task.cancel()
            with contextlib.suppress(Exception):
                up_writer.close()


async def serve(
    listen: str,
    upstream: str,
    *,
    group: str | None = None,
    mode: int = 0o660,
    allowed_uids: set[int] | None = None,
) -> asyncio.AbstractServer:
    """Start the guard on the unix socket `listen`."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(listen)
    guard = Guard(upstream, allowed_uids)
    old_umask = os.umask(0o117)  # never world-accessible, not even for an instant
    try:
        server = await asyncio.start_unix_server(guard.handle, path=listen, limit=MAX_HEAD)
    finally:
        os.umask(old_umask)
    os.chmod(listen, mode)
    if group:
        gid = grp.getgrnam(group).gr_gid
        # A socket is created with the creating process's group, so under systemd (Group=honeypot)
        # it is already right, and the unit's syscall filter forbids chown: ask only when needed.
        if os.stat(listen).st_gid != gid:
            os.chown(listen, -1, gid)
    server.guard = guard  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Validating proxy for the Docker socket")
    parser.add_argument("--listen", required=True, help="socket the honeypot service connects to")
    parser.add_argument("--upstream", default="/var/run/docker.sock")
    parser.add_argument("--group", help="group that owns the listening socket")
    parser.add_argument("--allow-user", action="append", default=[], help="user allowed to connect")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s docker-guard %(levelname)s %(message)s"
    )
    uids = {pwd.getpwnam(user).pw_uid for user in args.allow_user}

    async def run() -> None:
        server = await serve(args.listen, args.upstream, group=args.group, allowed_uids=uids)
        log.info("guarding %s -> %s", args.listen, args.upstream)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
