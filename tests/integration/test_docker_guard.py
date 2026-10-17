"""The real SSH engine, deployed through the Docker guard, against a real Docker daemon.

`tests/unit/test_docker_guard.py` proves the policy on synthetic requests and that the request the
engine builds passes it. Only a real daemon can show that the whole conversation works through the
guard (image check, create, persona archive in and out, start, log ingestion, stop, remove) and
that the calls a hijacked service would make are refused by the guard rather than by luck.
Opt-in via `RUN_DOCKER_TESTS=1`, like the other Docker-gated tests.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.asyncio


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytest.importorskip("docker", reason="docker SDK not installed")

skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs Docker and RUN_DOCKER_TESTS=1 (pulls the Cowrie image)",
)


def _upstream_socket() -> str:
    """The real daemon's socket, honouring DOCKER_HOST and Docker Desktop's location."""
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        return host[len("unix://") :]
    for candidate in ("/var/run/docker.sock", os.path.expanduser("~/.docker/run/docker.sock")):
        if os.path.exists(candidate):
            return candidate
    pytest.skip("cannot find the Docker socket")


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _raw(sock: str, method: str, target: str, body: bytes, content_type: str | None) -> bytes:
    """One hand-written HTTP request to the guard: the docker SDK will not send these."""
    import socket

    head = f"{method} {target} HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n"
    if content_type:
        head += f"Content-Type: {content_type}\r\n"
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(20)
        conn.connect(sock)
        conn.sendall(head.encode() + b"\r\n" + body)
        data = b""
        while chunk := conn.recv(65536):
            data += chunk
    return data


@skip_docker
async def test_the_ssh_engine_works_through_the_guard_and_a_hijacked_service_is_refused():
    import docker
    from honeypot_mcp import config
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_self_test, honeypot_stop

    upstream = _upstream_socket()  # before DOCKER_HOST is pointed at the guard
    work = tempfile.mkdtemp(prefix="hpg-it-")
    sock = os.path.join(work, "g.sock")
    guard = subprocess.Popen(
        [sys.executable, "-m", "honeypot_mcp.hardening.docker_guard", "--listen", sock,
         "--upstream", upstream],
        stderr=subprocess.PIPE,
    )  # fmt: skip
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    assert os.path.exists(sock), "the guard did not start"

    previous = {k: os.environ.get(k) for k in ("DOCKER_HOST", "DATABASE_URL")}
    await close_db()
    os.environ["DOCKER_HOST"] = f"unix://{sock}"
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(work) / 'it.db'}"
    config._settings = None
    event_buffer.reset_for_tests()
    await init_db()
    await event_buffer.get_buffer().start()

    name = f"it-guard-{uuid.uuid4().hex[:8]}"
    deployed = False
    try:
        deploy = await honeypot_deploy(
            type="ssh", name=name, port=_free_port(), config={"ssh_persona": "debian_12"}
        )
        assert "error" not in deploy, deploy
        deployed = True
        await asyncio.sleep(6)
        probe = await honeypot_self_test(name=name)
        assert probe.get("alert_received") is True, probe

        client = docker.from_env()  # DOCKER_HOST is the guard
        attempts = {
            "privileged with a host mount": lambda: client.containers.create(
                "cowrie/cowrie:3.0.15",
                name="honeypot-evil",
                labels={"honeypot-mcp": "true"},
                privileged=True,
                volumes={"/": {"bind": "/host", "mode": "rw"}},
            ),
            "another image": lambda: client.containers.create("alpine", name="honeypot-evil2"),
            "an unfiltered listing": lambda: client.containers.list(all=True),
            "exec in the honeypot": lambda: client.containers.get(f"honeypot-{name}").exec_run(
                "id"
            ),
            "pull another image": lambda: client.images.pull("alpine"),
            "daemon info": lambda: client.info(),
            "volumes": lambda: client.volumes.list(),
            "networks": lambda: client.networks.create("x"),
        }
        for what, attempt in attempts.items():
            with pytest.raises(docker.errors.APIError) as refused:
                attempt()
            assert refused.value.status_code == 403, what
        # And what the engine needs still works.
        listed = client.containers.list(filters={"label": "honeypot-mcp=true"})
        assert f"honeypot-{name}" in [c.name for c in listed]

        # A permitted query with a form-encoded body: the daemon merges that body into the same
        # parameters, ahead of the query, so it must never get there (the daemon is the proof).
        form = "application/x-www-form-urlencoded"
        import_repo = f"hpg-it-import-{uuid.uuid4().hex[:8]}/x"
        for target, body in (
            (
                "/images/create?fromImage=cowrie/cowrie&tag=3.0.15",
                f"fromImage=&fromSrc=http://192.0.2.1/x.tar&repo={import_repo}&tag=t".encode(),
            ),
            (f"/containers/honeypot-{name}/kill?signal=TERM", b"signal=HUP"),
            (f"/containers/honeypot-{name}/kill", b"signal=HUP"),
            (f"/containers/honeypot-{name}/stop", b"signal=HUP"),
        ):
            reply = _raw(sock, "POST", target, body, form)
            assert reply.startswith(b"HTTP/1.1 400"), (target, reply[:120])
        # A repeated HostConfig: the daemon would merge Privileged into the validated one.
        dup = (
            b'{"Image": "cowrie/cowrie:3.0.15", "Labels": {"honeypot-mcp": "true"}, '
            b'"HostConfig": {"Privileged": true}, "HostConfig": {"CapDrop": ["ALL"]}}'
        )
        reply = _raw(sock, "POST", "/containers/create?name=honeypot-dup", dup, "application/json")
        assert reply.startswith(b"HTTP/1.1 400"), reply[:120]

        direct = docker.DockerClient(base_url=f"unix://{upstream}")
        assert direct.images.list(name=import_repo) == [], "nothing was imported"
        assert direct.containers.get(f"honeypot-{name}").status == "running"
        with pytest.raises(docker.errors.NotFound):
            direct.containers.get("honeypot-dup")
    finally:
        if deployed:
            await honeypot_stop(name=name, remove=True)
        await event_buffer.get_buffer().stop()
        await close_db()
        guard.terminate()
        guard.wait(10)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        config._settings = None
        event_buffer.reset_for_tests()
