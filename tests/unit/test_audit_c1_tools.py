"""Regression tests for audit slice C1, findings 7 and 8.

Finding 7 — blocklist pushes could ship private/allowlisted/own addresses,
interpolate unvalidated ids into Cloudflare URLs, send a pfSense API key over
plain http, emit `/32` for IPv6 and left no audit trail.

Finding 8 — honeypot pause/resume/configure and honeytoken creation were not
audited, `honeypot_configure` accepted anything (including a telnet port that
collides with another sensor), `honeypot_stop` could hang on an engine that
never finishes stopping, and `honeytoken_status` handed viewers the secret.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


@dataclass
class _Token:
    claims: dict


def _as(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    import fastmcp.server.dependencies as deps

    monkeypatch.setattr(deps, "get_access_token", lambda: _Token(claims={"role": role}))


async def _audit_rows(tool: str) -> list[Any]:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    async with get_session() as session:
        rows = (await session.execute(select(AuditLog).where(AuditLog.tool == tool))).scalars()
        return list(rows.all())


async def _insert_offenders(ips: list[str], count: int = 10) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    now = datetime.now(UTC)
    async with get_session() as session:
        for ip in ips:
            for _ in range(count):
                session.add(
                    Alert(
                        timestamp=now,
                        source_ip=ip,
                        event_type="ssh_login_failed",
                        severity=AlertSeverity.MEDIUM,
                        payload={},
                    )
                )


class _FakeCFClient:
    def __init__(self) -> None:
        self.requested_urls: list[str] = []

    async def __aenter__(self) -> _FakeCFClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(self, url: str, headers: Any = None, params: Any = None) -> MagicMock:  # noqa: ARG002
        self.requested_urls.append(url)
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={"result": [], "result_info": {"cursors": {}}})
        return resp


def _settings_override(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    for key, value in values.items():
        monkeypatch.setattr(settings, key, value)


# ── Finding 7: blocklist pushes ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocklist_never_pushes_private_allowlisted_or_own_ip(monkeypatch):
    from honeypot_mcp.tools import blocklist_push

    _settings_override(
        monkeypatch,
        blocklist_allowlist="8.8.8.0/24, 2001:4860::/32",
        canary_public_url="http://203.0.113.77:8888",
        canary_callback_host="0.0.0.0",
    )
    await _insert_offenders(
        [
            "1.1.1.1",  # global → pushed
            "10.0.0.5",  # RFC1918
            "127.0.0.1",  # loopback
            "8.8.8.8",  # allowlisted CIDR
            "2001:4860:4860::8888",  # allowlisted IPv6 CIDR
            "203.0.113.77",  # our own canary host (TEST-NET, so also non-global)
            "9.9.9.9",  # global → pushed
        ]
    )
    fake = _FakeCFClient()
    with patch("httpx.AsyncClient", return_value=fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok-SECRET", dry_run=True
        )

    assert sorted(result["added"]) == ["1.1.1.1", "9.9.9.9"]
    assert result["failed"] == []


@pytest.mark.asyncio
async def test_blocklist_excludes_own_public_ip_even_when_global(monkeypatch):
    """The canary filter must not rely on the address happening to be non-global."""
    from honeypot_mcp.tools import blocklist_push

    _settings_override(monkeypatch, canary_public_url="https://[2606:4700::1111]:8443/x")
    await _insert_offenders(["2606:4700::1111", "1.0.0.1"])
    with patch("httpx.AsyncClient", return_value=_FakeCFClient()):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", dry_run=True
        )
    assert result["added"] == ["1.0.0.1"]


@pytest.mark.asyncio
async def test_malformed_allowlist_refuses_to_push(monkeypatch):
    from honeypot_mcp.tools import blocklist_push

    _settings_override(monkeypatch, blocklist_allowlist="1.1.1.1,not-an-ip")
    await _insert_offenders(["1.1.1.1"])
    client_factory = MagicMock()
    with patch("httpx.AsyncClient", client_factory):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok"
        )
    assert result["added"] == []
    assert "not-an-ip" in result["failed"][0]["error"]
    client_factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("account_id", "list_id"),
    [("acct/../../zones", "list"), ("acct", "list?x=1"), ("", "list"), ("a" * 65, "list")],
)
async def test_cloudflare_rejects_ids_that_would_alter_the_url(account_id, list_id):
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders(["1.1.1.1"])
    client_factory = MagicMock()
    with patch("httpx.AsyncClient", client_factory):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id=account_id, list_id=list_id, api_token="tok"
        )
    assert result["added"] == []
    assert result["failed"][0]["ip"] == "*"
    client_factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    ["http://pfsense.example", "http://192.168.1.1", "ftp://pf.local", "pfsense.local"],
)
async def test_pfsense_refuses_cleartext_or_relative_urls(base_url):
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders(["1.1.1.1"])
    client_factory = MagicMock()
    with patch("httpx.AsyncClient", client_factory):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url=base_url, api_key="k", alias_name="block"
        )
    assert result["added"] == []
    assert result["failed"][0]["ip"] == "*"
    client_factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("base_url", ["http://127.0.0.1:8443", "http://localhost", "http://[::1]"])
async def test_pfsense_allows_http_to_loopback(base_url):
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders(["1.1.1.1"])

    class _PfClient:
        async def __aenter__(self) -> _PfClient:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def get(self, _url: str, headers: Any = None, params: Any = None) -> MagicMock:  # noqa: ARG002
            resp = MagicMock()
            resp.status_code = 200
            resp.json = MagicMock(return_value={"data": {"address": ""}})
            return resp

    with patch("httpx.AsyncClient", return_value=_PfClient()):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url=base_url, api_key="k", alias_name="block", dry_run=True
        )
    assert result["added"] == ["1.1.1.1"]


@pytest.mark.asyncio
async def test_waf_uses_host_prefix_per_address_family():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders(["1.1.1.1", "2606:4700:4700::1111"])
    boto_client = MagicMock()
    boto_client.get_ip_set.return_value = {"IPSet": {"Addresses": []}, "LockToken": "l"}
    with patch("boto3.client", return_value=boto_client):
        result = await blocklist_push.blocklist_push_aws_waf(
            ip_set_id="x", ip_set_name="x", region="us-east-1", dry_run=True
        )
    assert sorted(result["added"]) == ["1.1.1.1/32", "2606:4700:4700::1111/128"]


@pytest.mark.asyncio
async def test_blocklist_push_is_audited_without_the_credential():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders(["1.1.1.1"])
    with patch("httpx.AsyncClient", return_value=_FakeCFClient()):
        await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok-SUPERSECRET", dry_run=True
        )

    rows = await _audit_rows("blocklist_push_cloudflare")
    assert len(rows) == 1
    row = rows[0]
    assert row.target == "api.cloudflare.com"
    assert row.arguments["dry_run"] is True
    assert "1 IP" in row.summary
    flat = f"{row.summary} {row.arguments} {row.target} {row.error}"
    assert "SUPERSECRET" not in flat


@pytest.mark.asyncio
async def test_pfsense_audit_records_host_not_url_credentials():
    from honeypot_mcp.tools import blocklist_push

    await blocklist_push.blocklist_push_pfsense(
        base_url="https://admin:hunter2@pf.example:8443/", api_key="KEY-XYZ", alias_name="b"
    )
    rows = await _audit_rows("blocklist_push_pfsense")
    assert len(rows) == 1
    assert rows[0].target == "pf.example"
    flat = f"{rows[0].summary} {rows[0].arguments} {rows[0].target}"
    assert "hunter2" not in flat
    assert "KEY-XYZ" not in flat


# ── Finding 8: honeypot tools ───────────────────────────────────────────────


async def _insert_honeypot(
    name: str, hp_type: str, port: int, status: str = "running", container_id: str | None = "c1"
) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        session.add(
            Honeypot(
                name=name,
                type=HoneypotType(hp_type),
                port=port,
                status=HoneypotStatus(status),
                container_id=container_id,
                config={},
            )
        )


@pytest.mark.asyncio
async def test_configure_rejects_keys_the_engine_does_not_read():
    from honeypot_mcp.tools.honeypot import honeypot_configure

    await _insert_honeypot("ssh-a", "ssh", 2222)
    result = await honeypot_configure("ssh-a", {"fake_hostname": "web01", "image": "evil:latest"})
    assert "image" in result["error"]
    # Nothing is half-applied.
    ok = await honeypot_configure("ssh-a", {"fake_hostname": "web01"})
    assert ok["config"] == {"fake_hostname": "web01"}


@pytest.mark.asyncio
async def test_configure_rejects_non_dict_and_bad_values():
    from honeypot_mcp.tools.honeypot import honeypot_configure

    await _insert_honeypot("ftp-a", "ftp", 2121)
    assert "error" in await honeypot_configure("ftp-a", ["fake_banner"])  # type: ignore[arg-type]
    banner = await honeypot_configure("ftp-a", {"fake_banner": "ok\r\n230 Login successful"})
    assert "fake_banner" in banner["error"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [0, 65536, -1, "23", True, 23.0])
async def test_configure_telnet_port_must_be_a_valid_int(value):
    from honeypot_mcp.tools.honeypot import honeypot_configure

    await _insert_honeypot("ssh-b", "ssh", 2222)
    result = await honeypot_configure("ssh-b", {"telnet_port": value})
    assert "telnet_port" in result["error"]


@pytest.mark.asyncio
async def test_configure_telnet_port_conflict_names_the_other_honeypot():
    from honeypot_mcp.tools.honeypot import honeypot_configure

    await _insert_honeypot("ssh-c", "ssh", 2222)
    await _insert_honeypot("http-c", "http", 8080)
    result = await honeypot_configure("ssh-c", {"telnet_port": 8080})
    assert "http-c" in result["error"]
    own = await honeypot_configure("ssh-c", {"telnet_port": 2222})
    assert "error" in own
    ok = await honeypot_configure("ssh-c", {"telnet_port": 2323, "telnet_enabled": True})
    assert ok["config"]["telnet_port"] == 2323


@pytest.mark.asyncio
async def test_configure_pause_resume_are_audited():
    from honeypot_mcp.tools import honeypot as hp_tools

    await _insert_honeypot("http-d", "http", 8081)
    engine = MagicMock()

    async def _noop(*_a: object, **_k: object) -> None:
        return None

    engine.pause = _noop
    engine.resume = _noop
    with patch.object(hp_tools, "get_engine", return_value=engine):
        await hp_tools.honeypot_configure("http-d", {"tls": True})
        assert (await hp_tools.honeypot_pause("http-d"))["status"] == "paused"
        assert (await hp_tools.honeypot_resume("http-d"))["status"] == "running"

    for tool in ("honeypot_configure", "honeypot_pause", "honeypot_resume"):
        rows = await _audit_rows(tool)
        assert len(rows) == 1, tool
        assert rows[0].target == "http-d"


@pytest.mark.asyncio
async def test_stop_does_not_hang_on_an_engine_that_never_finishes(monkeypatch):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus
    from honeypot_mcp.tools import honeypot as hp_tools

    monkeypatch.setattr(hp_tools, "_ENGINE_STOP_TIMEOUT_SECONDS", 0.2)
    await _insert_honeypot("redis-e", "redis", 6380)

    engine = MagicMock()

    async def _hang(*_a: object, **_k: object) -> None:
        await asyncio.sleep(3600)

    engine.stop = _hang
    with patch.object(hp_tools, "get_engine", return_value=engine):
        result = await asyncio.wait_for(hp_tools.honeypot_stop(name="redis-e"), timeout=5)

    assert result["stopped"] == ["redis-e"]
    assert result["timed_out"] == ["redis-e"]
    async with get_session() as session:
        row = (
            await session.execute(select(Honeypot).where(Honeypot.name == "redis-e"))
        ).scalar_one()
        assert row.status is HoneypotStatus.STOPPED
        assert row.container_id is None


# ── Finding 8: honeytoken tools ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_honeytoken_status_masks_secret_for_viewers(monkeypatch):
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_status

    created = await honeytoken_create(type="canary_url", label="wiki", planted_at="IT-114")
    full = created["token_value"]

    as_admin = await honeytoken_status(created["id"])
    assert as_admin["token_value"] == full
    assert as_admin["metadata"]["planted_at"] == "IT-114"

    _as(monkeypatch, "operator")
    assert (await honeytoken_status(created["id"]))["token_value"] == full

    _as(monkeypatch, "viewer")
    masked = await honeytoken_status(created["id"])
    assert masked["token_value"] == f"{full[:4]}…"
    assert masked["metadata"] == {"redacted": True}
    assert full not in repr(masked)


@pytest.mark.asyncio
async def test_honeytoken_creation_paths_are_audited_once_without_secret():
    from honeypot_mcp.tools import honeytoken as ht

    created = await ht.honeytoken_create(
        type="credential", label="db creds", metadata={"service": "ssh"}
    )
    generated = await ht.honeytoken_generate_credentials(label="gen", service="ftp")

    rows = await _audit_rows("honeytoken_create")
    assert len(rows) == 1
    assert rows[0].target == str(created["id"])
    gen_rows = await _audit_rows("honeytoken_generate_credentials")
    assert len(gen_rows) == 1
    assert gen_rows[0].target == str(generated["id"])

    for row, token in ((rows[0], created), (gen_rows[0], generated)):
        flat = f"{row.summary} {row.arguments} {row.target}"
        assert token["token_value"] not in flat
        password = token["metadata"].get("password")
        if password:
            assert password not in flat


@pytest.mark.asyncio
async def test_rotate_still_writes_a_single_rotate_row():
    from honeypot_mcp.tools import honeytoken as ht

    created = await ht.honeytoken_create(type="canary_url", label="r")
    rotated = await ht.honeytoken_rotate(created["id"])
    assert rotated["rotated_from"] == created["id"]
    assert len(await _audit_rows("honeytoken_create")) == 1
    assert len(await _audit_rows("honeytoken_rotate")) == 1
