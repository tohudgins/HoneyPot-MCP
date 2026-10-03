"""Regression tests for audit slice C2: canary server, honeytoken providers, TLS,
deception planner."""

from __future__ import annotations

import asyncio
import os
import stat
from typing import Any

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def pipeline(tmp_path, monkeypatch):
    """A started event buffer whose on_flush hook records what webhook
    delivery would have been handed."""
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp import canary
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    canary.invalidate_token_index()
    canary._rate_state.clear()
    canary._global_hits.clear()
    await init_db()
    delivered: list[Any] = []

    async def _spy(events: list[Any]) -> None:
        delivered.extend(events)

    buffer = event_buffer.get_buffer()
    buffer.set_on_flush(_spy)
    await buffer.start()
    yield delivered
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()
    canary.invalidate_token_index()


async def _wait_for(predicate: Any, timeout: float = 5.0) -> None:
    async def _poll() -> None:
        while not await predicate():
            await asyncio.sleep(0.05)

    await asyncio.wait_for(_poll(), timeout)


async def _token_status(token_pk: int) -> Any:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken

    async with get_session() as session:
        token = await session.get(Honeytoken, token_pk)
        assert token is not None
        return token.status


# ── 1/4: canary triggers go through the pipeline, and re-arm ────────────────


async def test_canary_hit_reaches_webhook_delivery_and_rearms(pipeline):
    from urllib.parse import urlparse

    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.canary import build_app
    from honeypot_mcp.storage.models import HoneytokenStatus
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    delivered = pipeline
    token = await honeytoken_create(type="canary_url", label="wiki-link")
    path = urlparse(token["token_value"]).path

    client = TestClient(TestServer(build_app()))
    await client.start_server()
    try:
        resp = await client.get(path)
        assert resp.status == 200
        assert await resp.text() == "OK"

        async def _one_delivered() -> bool:
            return len(delivered) == 1

        await _wait_for(_one_delivered)
        assert delivered[0].honeytoken_id == token["id"]
        assert delivered[0].event_type == "honeytoken_triggered_canary_url"
        assert delivered[0].severity.value == "critical"
        assert await _token_status(token["id"]) is HoneytokenStatus.TRIGGERED

        # A TRIGGERED token still alerts: the first hit may have been a prefetcher.
        await client.get(path)

        async def _two_delivered() -> bool:
            return len(delivered) == 2

        await _wait_for(_two_delivered)
    finally:
        await client.close()


async def test_revoked_canary_does_not_fire(pipeline):
    from urllib.parse import urlparse

    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.canary import build_app
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_revoke

    delivered = pipeline
    token = await honeytoken_create(type="canary_url", label="revoked-link")
    await honeytoken_revoke(token["id"])

    client = TestClient(TestServer(build_app()))
    await client.start_server()
    try:
        resp = await client.get(urlparse(token["token_value"]).path)
        assert resp.status == 200
        await asyncio.sleep(0.3)
        assert delivered == []
    finally:
        await client.close()


# ── 3: kubectl paths under a kubeconfig token fire it ───────────────────────


async def test_kubectl_version_request_fires_kubeconfig_token(pipeline):
    from urllib.parse import urlparse

    import yaml
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.canary import build_app
    from honeypot_mcp.storage.models import HoneytokenStatus
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    delivered = pipeline
    token = await honeytoken_create(type="kubeconfig", label="ci-kubeconfig")
    kubeconfig = yaml.safe_load(token["token_value"])
    server_url = kubeconfig["clusters"][0]["cluster"]["server"]

    client = TestClient(TestServer(build_app()))
    await client.start_server()
    try:
        resp = await client.get(urlparse(server_url).path + "/version")
        assert resp.status == 200
        doc = await resp.json()
        assert doc["gitVersion"].startswith("v1.")

        api = await (await client.get(urlparse(server_url).path + "/api")).json()
        assert api["kind"] == "APIVersions"

        async def _triggered() -> bool:
            return await _token_status(token["id"]) is HoneytokenStatus.TRIGGERED

        await _wait_for(_triggered)
        assert any(ev.honeytoken_id == token["id"] for ev in delivered)
    finally:
        await client.close()


async def test_kubeconfig_cluster_name_cannot_inject_yaml():
    import yaml

    from honeypot_mcp.tokens.kubeconfig import KubeconfigProvider

    provider = KubeconfigProvider()
    with pytest.raises(ValueError):
        await provider.create({"cluster_name": "prod\n  insecure: true"})
    value, _meta = await provider.create({"cluster_name": "prod: {x: 1}"})
    parsed = yaml.safe_load(value)
    assert parsed["current-context"] == "prod: {x: 1}"


# ── 2: cloud-event hardening ────────────────────────────────────────────────


class _FakeContent:
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def iter_chunked(self, _n: int) -> Any:
        yield self._body


class _FakeRequest:
    def __init__(self, headers: dict[str, str], body: bytes, length: int | None) -> None:
        self.headers = headers
        self.content = _FakeContent(body)
        self.content_length = length
        self.remote = "203.0.113.1"


async def test_non_ascii_signature_is_401_not_500(monkeypatch):
    import honeypot_mcp.config as cfg
    from honeypot_mcp import canary

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "s3cret")
    cfg._settings = None
    try:
        req = _FakeRequest({"X-HoneyPot-Signature": "sha256=\u00e9\u00e9"}, b"{}", 2)
        response = await canary._handle_cloud_event(req)  # type: ignore[arg-type]
        assert response.status == 401
    finally:
        cfg._settings = None


async def test_oversized_cloud_event_rejected_before_reading(monkeypatch):
    import honeypot_mcp.config as cfg
    from honeypot_mcp import canary

    monkeypatch.setenv("CLOUD_EVENT_HMAC_SECRET", "s3cret")
    cfg._settings = None
    try:
        req = _FakeRequest({"X-HoneyPot-Signature": "sha256=00"}, b"", 10 * 1024 * 1024)
        response = await canary._handle_cloud_event(req)  # type: ignore[arg-type]
        assert response.status == 413
    finally:
        cfg._settings = None


async def test_rate_limit_buckets_ipv6_by_64():
    from honeypot_mcp import canary

    assert canary._rate_key("2001:db8:1:2::1") == canary._rate_key("2001:db8:1:2:ffff::9")
    assert canary._rate_key("2001:db8:1:2::1") != canary._rate_key("2001:db8:1:3::1")
    assert canary._rate_key("::ffff:198.51.100.4") == "198.51.100.4"


# ── 5: private keys are 0600 from creation ──────────────────────────────────


def _spy_open_modes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    from honeypot_mcp import secure_io

    modes: list[int] = []
    real_open = os.open

    def _open(path: Any, flags: int, mode: int = 0o777, *a: Any, **kw: Any) -> int:
        if str(path).endswith(".tmp"):
            modes.append(mode)
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(secure_io.os, "open", _open)
    return modes


async def test_ssh_key_file_is_owner_only_from_creation(tmp_path, monkeypatch):
    from pathlib import Path

    from honeypot_mcp.tokens.ssh_key import SSHKeyProvider

    monkeypatch.chdir(tmp_path)
    modes = _spy_open_modes(monkeypatch)
    old = os.umask(0)
    try:
        _value, meta = await SSHKeyProvider().create({})
    finally:
        os.umask(old)
    assert modes and all(m == 0o600 for m in modes)
    assert stat.S_IMODE(Path(meta["private_key_path"]).stat().st_mode) == 0o600


async def test_tls_key_is_owner_only_from_creation(tmp_path, monkeypatch):
    from honeypot_mcp.engines.tls import ensure_cert

    monkeypatch.chdir(tmp_path)
    modes = _spy_open_modes(monkeypatch)
    old = os.umask(0)
    try:
        cert, key = ensure_cert("audit-c2")
    finally:
        os.umask(old)
    assert modes and all(m == 0o600 for m in modes)
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert cert.exists()


# ── 6: injection into generated artifacts ───────────────────────────────────


async def test_ssh_key_comment_with_newline_is_rejected(tmp_path, monkeypatch):
    from honeypot_mcp.tokens.ssh_key import SSHKeyProvider

    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError):
        await SSHKeyProvider().create({"comment": "x\nssh-rsa AAAA attacker"})


async def test_db_row_rejects_unsafe_table_and_domain():
    from honeypot_mcp.tokens.db_row import DBRowProvider

    provider = DBRowProvider()
    with pytest.raises(ValueError):
        await provider.create({"table": "users; DROP TABLE users"})
    with pytest.raises(ValueError):
        await provider.create({"domain": "evil.example\nBcc: x"})


# ── 7: planted credentials are not guessable ────────────────────────────────


async def test_planted_credentials_are_strong_and_honour_username():
    from honeypot_mcp.tokens.credential import CredentialProvider

    provider = CredentialProvider()
    _value, meta = await provider.create({"service": "ssh", "count": 5})
    for cred in meta["credentials"]:
        pw = cred["password"]
        assert len(pw) >= 16
        assert any(c.isupper() for c in pw) and any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert not set(pw) & set("0O1lI")
    _value, meta = await provider.create({"service": "postgresql", "username": "svc_backup"})
    assert meta["credentials"][0]["username"] == "svc_backup"
    with pytest.raises(ValueError):
        await provider.create({"count": 0})


# ── 8: planner ports and identity ───────────────────────────────────────────


async def test_planner_reserves_own_ports_and_bounds_the_search(monkeypatch):
    import honeypot_mcp.config as cfg
    from honeypot_mcp.deception.planner import build_plan

    # Put the canary server exactly where the HTTP sensor would go.
    monkeypatch.setenv("CANARY_CALLBACK_PORT", "8080")
    cfg._settings = None
    try:
        plan = build_plan(services=["http"])
        assert plan["sensors"][0]["port"] != 8080
        assert "canary" in plan["port_conflicts_resolved"][0]

        every_port = {p: "x" for p in range(1, 65536)}
        exhausted = build_plan(services=["http"], existing_ports=every_port)
        assert "error" in exhausted and "65535" in exhausted["error"]
    finally:
        cfg._settings = None


async def test_planner_rejects_unsafe_identity_and_drops_ignored_keys():
    from honeypot_mcp.deception.planner import build_plan

    assert "error" in build_plan(services=["ssh"], identity_prefix="../etc")
    assert "error" in build_plan(services=["ssh"], domain="corp.local\nx")

    plan = build_plan(services=["rdp", "smb", "smtp", "ssh"], identity_prefix="corp")
    by_type = {s["type"]: s for s in plan["sensors"]}
    assert by_type["rdp"]["config"] == {}
    assert by_type["smb"]["config"] == {}
    assert by_type["smtp"]["config"] == {}
    assert by_type["ssh"]["config"]["fake_hostname"].startswith("corp-")
