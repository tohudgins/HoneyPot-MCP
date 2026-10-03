"""Audit regressions for the control plane (slice C1): prune archive guard,
networked auth gate, report/export hardening, API-key labels and the
revocation race in the API-key cache."""

from __future__ import annotations

import contextlib
import os
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select, update

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.rbac import invalidate_api_key_cache
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    invalidate_api_key_cache()
    yield
    invalidate_api_key_cache()
    await close_db()


@pytest.fixture
def reports_dir(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path, raising=False)
    return tmp_path


async def _seed(ip: str, count: int, *, days_ago: float = 0.05) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ts = datetime.now(UTC) - timedelta(days=days_ago)
    async with get_session() as session:
        for _ in range(count):
            session.add(
                Alert(
                    honeypot_id=None,
                    source_ip=ip,
                    source_port=None,
                    event_type="ssh_login_failed",
                    payload={"username": "root"},
                    severity=AlertSeverity.HIGH,
                    timestamp=ts,
                )
            )


async def _alert_count() -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return int((await session.execute(select(func.count(Alert.id)))).scalar_one())


# ── 1. alerts_prune never deletes when the archive fails ─────────────────────


@pytest.mark.asyncio
async def test_prune_with_archive_outside_reports_dir_deletes_nothing(reports_dir):
    from honeypot_mcp.tools.alerts import alerts_prune

    await _seed("8.8.8.8", 3, days_ago=200)
    result = await alerts_prune(older_than_days=90, archive_path="../../escape.jsonl")

    assert "error" in result
    assert await _alert_count() == 3


@pytest.mark.asyncio
async def test_prune_refuses_to_overwrite_an_existing_archive(reports_dir):
    from honeypot_mcp.tools.alerts import alerts_prune

    (reports_dir / "keep.jsonl").write_text("previous archive\n")
    await _seed("8.8.8.8", 2, days_ago=200)
    result = await alerts_prune(older_than_days=90, archive_path="keep.jsonl")

    assert "error" in result
    assert (reports_dir / "keep.jsonl").read_text() == "previous archive\n"
    assert await _alert_count() == 2


# ── 2. networked auth gate decides on the parsed token map ───────────────────


def _ns(transport: str, token: str = "", tokens: str = "", allow: bool = False):
    return SimpleNamespace(
        mcp_transport=transport,
        mcp_auth_token=token,
        mcp_auth_tokens=tokens,
        mcp_allow_unauthenticated=allow,
    )


@pytest.mark.parametrize("tokens", [",", " , ", "   "])
def test_tokens_that_parse_to_nothing_do_not_count_as_auth(tokens):
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_ns("http", tokens=tokens)) is not None


@pytest.mark.parametrize(
    "tokens",
    ["0123456789abcdef0123:superuser", "no-role-separator-0123456789", ":admin"],
)
def test_malformed_token_entries_refuse_startup(tokens):
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_ns("http", tokens=tokens)) is not None


def test_same_token_with_two_roles_is_rejected():
    from honeypot_mcp.rbac import parse_auth_tokens

    with pytest.raises(ValueError):
        parse_auth_tokens("", "0123456789abcdef:viewer,0123456789abcdef:admin")


def test_short_static_token_refused_on_network_but_fine_on_stdio():
    from honeypot_mcp.server import _networked_auth_error

    err = _networked_auth_error(_ns("http", token="short"))
    assert err is not None and "openssl rand" in err
    assert _networked_auth_error(_ns("stdio", token="short")) is None
    assert _networked_auth_error(_ns("http", token="x" * 16)) is None


# ── 6. report / export hardening ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_generate_report_never_overwrites_a_caller_named_file(reports_dir):
    from honeypot_mcp.tools.analysis import generate_report

    await _seed("8.8.8.8", 2)
    (reports_dir / "r.md").write_text("ORIGINAL")
    result = await generate_report(format="markdown", output_path="r.md")

    assert "error" in result
    assert (reports_dir / "r.md").read_text() == "ORIGINAL"


@pytest.mark.asyncio
async def test_generate_report_extension_must_match_format(reports_dir):
    from honeypot_mcp.tools.analysis import generate_report

    result = await generate_report(format="markdown", output_path="r.html")
    assert "error" in result
    assert not (reports_dir / "r.html").exists()


@pytest.mark.asyncio
async def test_generate_report_auto_names_still_work(reports_dir):
    from honeypot_mcp.tools.analysis import generate_report

    await _seed("8.8.8.8", 2)
    first = await generate_report(format="markdown")
    assert "path" in first


@pytest.mark.asyncio
async def test_export_blocklist_drops_non_global_and_uses_v6_syntax(reports_dir):
    from honeypot_mcp.tools.analysis import export_blocklist

    await _seed("10.0.0.5", 6)
    await _seed("2606:4700::1111", 6)
    await _seed("8.8.8.8", 6)
    result = await export_blocklist(format="iptables", min_hits=5, output_path="bl.rules")
    text = (reports_dir / "bl.rules").read_text()

    assert result["ip_count"] == 2
    assert "10.0.0.5" not in text
    assert "ip6tables -A INPUT -s 2606:4700::1111 -j DROP" in text


@pytest.mark.asyncio
async def test_export_stix_types_ipv6_indicators_correctly(reports_dir):
    import json

    from honeypot_mcp.tools.analysis import export_stix

    await _seed("2606:4700::1111", 2)
    await export_stix(min_hits=1, output_path="s.json")
    patterns = [o["pattern"] for o in json.loads((reports_dir / "s.json").read_text())["objects"]]

    assert patterns == ["[ipv6-addr:value = '2606:4700::1111']"]


@pytest.mark.asyncio
async def test_report_ip_abuse_rejects_private_and_unobserved_ips(monkeypatch):
    import honeypot_mcp.intel.abuseipdb as abuse
    from honeypot_mcp.tools.analysis import report_ip_abuse

    calls: list[str] = []

    async def fake_report(ip, categories, comment=""):
        calls.append(ip)
        return {"reported": True}

    monkeypatch.setattr(abuse, "report_ip", fake_report)

    assert "error" in await report_ip_abuse("10.1.2.3")
    assert "error" in await report_ip_abuse("8.8.4.4")  # never seen
    assert "error" in await report_ip_abuse("8.8.8.8", comment="x" * 501)
    assert calls == []

    await _seed("8.8.8.8", 1)
    assert (await report_ip_abuse("8.8.8.8"))["reported"] is True
    assert calls == ["8.8.8.8"]


# ── 9. API-key labels and the revocation race ────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("label", ["alice (admin)", "bob\nadmin", "x" * 65])
async def test_api_key_label_rejects_impersonation_shapes(label):
    from honeypot_mcp.tools.api_keys import api_key_create

    assert "error" in await api_key_create(label=label, role="viewer")


@pytest.mark.asyncio
async def test_api_key_label_unique_among_active_keys():
    from honeypot_mcp.tools.api_keys import api_key_create, api_key_revoke

    first = await api_key_create(label="alice", role="viewer")
    assert "error" in await api_key_create(label="alice", role="admin")
    await api_key_revoke(first["id"])
    assert "token" in await api_key_create(label="alice", role="viewer")


@pytest.mark.asyncio
async def test_revoke_during_cache_load_is_not_republished(monkeypatch):
    """A load that read the key set before a revoke must not publish it."""
    import honeypot_mcp.storage.database as database
    from honeypot_mcp.rbac import invalidate_api_key_cache, verify_db_token
    from honeypot_mcp.storage.models import ApiKey
    from honeypot_mcp.tools.api_keys import api_key_create

    created = await api_key_create(label="alice", role="operator")
    real_get_session = database.get_session
    raced = False

    @contextlib.asynccontextmanager
    async def racing_session():
        nonlocal raced
        async with real_get_session() as session:
            yield session
        if not raced:
            raced = True
            # The revoke lands after the loader queried, before it publishes.
            async with real_get_session() as s:
                await s.execute(
                    update(ApiKey)
                    .where(ApiKey.id == created["id"])
                    .values(revoked_at=datetime.now(UTC))
                )
            invalidate_api_key_cache()

    monkeypatch.setattr(database, "get_session", racing_session)
    invalidate_api_key_cache()

    assert await verify_db_token(created["token"]) is None
    assert raced
