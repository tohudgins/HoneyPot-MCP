"""POP3 and the Kubernetes API server.

The two that complete the catalogue at 25. POP3 closes the mail pair — the same
botnets sweep 110 and 143 together, and a host answering one but refusing the
other is an odd configuration a scanner notices. Kubernetes is the cloud
sibling of the Docker API engine: anonymous access to a cluster is the same
class of misconfiguration, and reading Secrets is usually the whole cluster
rather than one workload.

As with the Docker engine, the tests concentrate on the difference between
"someone made a request" and a named, actionable finding.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import socket

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

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
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def _register(name: str, hp_type) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    port = _free_port()
    async with get_session() as session:
        session.add(
            Honeypot(name=name, type=hp_type, port=port, status=HoneypotStatus.RUNNING, config={})
        )
    return port


async def _of_type(event_type: str) -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        rows = (await session.execute(select(Alert))).scalars().all()
    return [a for a in rows if a.event_type == event_type]


# ── POP3 ────────────────────────────────────────────────────────────────────


async def test_pop3_captures_cleartext_password():
    from honeypot_mcp.engines.pop3 import POP3Engine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pop3-1", HoneypotType.POP3)
    engine = POP3Engine()
    cid = await engine.start("pop3-1", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        greeting = await reader.read(200)
        writer.write(b"USER svc_backup\r\n")
        await writer.drain()
        await asyncio.sleep(0.2)
        await reader.read(200)
        writer.write(b"PASS Wint3r2024!\r\n")
        await writer.drain()
        await asyncio.sleep(1.6)
        rejection = await reader.read(200)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    assert b"+OK Dovecot ready" in greeting
    assert b"-ERR" in rejection

    logins = await _of_type("pop3_login_attempt")
    assert logins and logins[0].severity.value == "high"
    payload = logins[0].payload
    assert payload["username"] == "svc_backup"
    assert payload["password"] == "Wint3r2024!"
    assert payload["service"] == "pop3"


async def test_pop3_apop_digest_is_stored_with_its_challenge():
    """A digest without the challenge it was computed over is not crackable."""
    from honeypot_mcp.engines.pop3 import POP3Engine, apop_digest
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pop3-2", HoneypotType.POP3)
    engine = POP3Engine()
    cid = await engine.start("pop3-2", port, {})
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        greeting = (await reader.read(200)).decode()
        challenge = greeting.strip().split(" ")[-1]
        digest = apop_digest(challenge, "hunter2")
        writer.write(f"APOP admin {digest}\r\n".encode())
        await writer.drain()
        await asyncio.sleep(1.6)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        await asyncio.sleep(0.4)
    finally:
        await engine.stop(cid)

    attempts = await _of_type("pop3_login_attempt")
    assert attempts
    payload = attempts[0].payload
    assert payload["method"] == "APOP"
    assert payload["digest_response"] == digest
    assert payload["challenge"] == challenge
    # And the pair really is verifiable, which is the point of keeping both.
    assert (
        hashlib.md5((payload["challenge"] + "hunter2").encode(), usedforsecurity=False).hexdigest()
        == payload["digest_response"]
    )


async def test_pop3_challenge_is_unique_per_connection():
    """A fixed APOP timestamp would make every captured digest interchangeable."""
    from honeypot_mcp.engines.pop3 import POP3Engine
    from honeypot_mcp.storage.models import HoneypotType

    port = await _register("pop3-3", HoneypotType.POP3)
    engine = POP3Engine()
    cid = await engine.start("pop3-3", port, {})
    try:
        greetings = []
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            greetings.append((await reader.read(200)).decode())
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
    finally:
        await engine.stop(cid)

    assert greetings[0] != greetings[1]


# ── Kubernetes ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ({"spec": {"volumes": [{"hostPath": {"path": "/"}}]}}, "root filesystem"),
        ({"spec": {"volumes": [{"hostPath": {"path": "/etc"}}]}}, "sensitive node path"),
        ({"spec": {"hostPID": True}}, "host PID"),
        ({"spec": {"hostNetwork": True}}, "host network"),
        (
            {"spec": {"containers": [{"securityContext": {"privileged": True}}]}},
            "privileged container",
        ),
        (
            {
                "spec": {
                    "containers": [{"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}]
                }
            },
            "dangerous capabilities",
        ),
        ({"spec": {"containers": [{"image": "xmrig/xmrig:latest"}]}}, "mining image"),
        (
            {"spec": {"containers": [{"command": ["chroot", "/host", "sh"]}]}},
            "payload-stage command",
        ),
    ],
)
async def test_pod_spec_escape_indicators_are_named(spec, expected):
    from honeypot_mcp.engines.kubernetes import analyse_pod_spec

    reasons = analyse_pod_spec(spec)
    assert any(expected in r for r in reasons), reasons


@pytest.mark.parametrize(
    "spec",
    [
        {"spec": {"containers": [{"name": "web", "image": "nginx:1.25"}]}},
        {
            "spec": {
                "containers": [{"name": "api", "image": "registry.internal/api:2.1"}],
                "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": "data"}}],
            }
        },
        {"spec": {"serviceAccountName": "default", "containers": [{"image": "redis:7"}]}},
    ],
)
async def test_ordinary_pods_are_not_flagged_as_escapes(spec):
    """A CRITICAL that fires on normal workloads is worthless."""
    from honeypot_mcp.engines.kubernetes import analyse_pod_spec

    assert analyse_pod_spec(spec) == []


async def test_kubernetes_responses_carry_the_headers_a_real_apiserver_sends():
    """Their absence identifies a decoy in one request."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine

    engine = KubernetesEngine()
    client = TestClient(TestServer(engine._build_app("k8s", None)))
    await client.start_server()
    try:
        response = await client.get("/version")
        assert response.status == 200
        assert "Audit-Id" in response.headers
        assert "X-Kubernetes-Pf-Flowschema-Uid" in response.headers
        body = await response.json()
        assert body["gitVersion"] == f"v{body['major']}.{body['minor']}.4"
    finally:
        await client.close()


async def test_kubernetes_errors_use_the_status_object_shape():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine

    engine = KubernetesEngine()
    client = TestClient(TestServer(engine._build_app("k8s", None)))
    await client.start_server()
    try:
        response = await client.get("/no/such/thing")
        assert response.status == 404
        body = await response.json()
        assert body["kind"] == "Status"
        assert body["reason"] == "NotFound"
        assert body["apiVersion"] == "v1"
    finally:
        await client.close()


async def test_kubernetes_secret_read_is_critical_on_its_own():
    """Secrets hold service-account tokens — that is the whole cluster."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("k8s-1", HoneypotType.KUBERNETES)
    engine = KubernetesEngine()
    client = TestClient(TestServer(engine._build_app("k8s-1", None)))
    await client.start_server()
    try:
        response = await client.get("/api/v1/namespaces/production/secrets")
        assert response.status == 200
        await asyncio.sleep(0.5)
    finally:
        await client.close()

    events = await _of_type("kubernetes_secret_access")
    assert events and events[0].severity.value == "critical"
    assert events[0].payload["namespace"] == "production"


async def test_kubernetes_escape_pod_is_critical_and_benign_pod_is_not():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("k8s-2", HoneypotType.KUBERNETES)
    engine = KubernetesEngine()
    client = TestClient(TestServer(engine._build_app("k8s-2", None)))
    await client.start_server()
    try:
        escape = await client.post(
            "/api/v1/namespaces/default/pods",
            json={
                "metadata": {"name": "pwn"},
                "spec": {
                    "hostPID": True,
                    "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
                    "containers": [
                        {"name": "c", "image": "alpine", "securityContext": {"privileged": True}}
                    ],
                },
            },
        )
        assert escape.status == 201
        await client.post(
            "/api/v1/namespaces/default/pods",
            json={"metadata": {"name": "web"}, "spec": {"containers": [{"image": "nginx:1.25"}]}},
        )
        await asyncio.sleep(0.5)
    finally:
        await client.close()

    escapes = await _of_type("kubernetes_pod_escape")
    assert escapes and escapes[0].severity.value == "critical"
    assert len(escapes[0].payload["escape_indicators"]) >= 3

    creates = await _of_type("kubernetes_pod_create")
    assert creates and creates[0].severity.value == "high"


async def test_kubernetes_captures_a_presented_bearer_token():
    """An attacker replaying a stolen service-account token hands it to us."""
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.engines.kubernetes import KubernetesEngine
    from honeypot_mcp.storage.models import HoneypotType

    await _register("k8s-3", HoneypotType.KUBERNETES)
    engine = KubernetesEngine()
    client = TestClient(TestServer(engine._build_app("k8s-3", None)))
    await client.start_server()
    try:
        await client.get(
            "/api/v1/namespaces", headers={"Authorization": "Bearer eyJhbGciOi.stolen"}
        )
        await asyncio.sleep(0.5)
    finally:
        await client.close()

    events = await _of_type("kubernetes_enumerate")
    assert events
    assert "eyJhbGciOi.stolen" in events[0].payload["authorization_presented"]


# ── Registry consistency ────────────────────────────────────────────────────


async def test_catalogue_is_twenty_five_and_fully_registered():
    """Every deployable type must be plannable and coverage-mappable."""
    from honeypot_mcp.deception.capabilities import BY_TYPE
    from honeypot_mcp.storage.models import HoneypotType

    deployable = {t.value for t in HoneypotType}
    assert len(deployable) == 25
    assert deployable == set(BY_TYPE)
    for capability in BY_TYPE.values():
        assert capability.signature_events, f"{capability.type} would show zero ATT&CK coverage"


@pytest.mark.parametrize("service", ["pop3", "imap"])
async def test_mail_credential_services_are_matchable(service):
    from honeypot_mcp.credential_match import _infer_service

    assert _infer_service(f"{service}_login_attempt") == service
