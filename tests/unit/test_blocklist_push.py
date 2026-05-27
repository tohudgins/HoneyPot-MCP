"""Tests for blocklist push integrations.

Covers all three destinations (Cloudflare / pfSense / AWS WAFv2) with the
same matrix:
- empty offenders → no-op
- full overlap → all skipped
- partial overlap → only the new IPs pushed
- dry_run → diff returned, no API mutation
- API failure → recorded in `failed`, not raised

HTTP destinations are tested by mocking `httpx.AsyncClient`. WAFv2 uses
boto3 — we mock the client directly.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _insert_offenders(rows: list[tuple[str, int]]) -> None:
    """Insert Alerts so `get_top_offenders` returns the given (ip, count) shape.

    `get_top_offenders` groups by `source_ip` and filters by count >= min_hits.
    We insert `count` rows per IP so each appears at the right hit volume.
    """
    from datetime import UTC, datetime

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    now = datetime.now(UTC)
    async with get_session() as session:
        for ip, count in rows:
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


# ── Cloudflare ──────────────────────────────────────────────────────────────


class _FakeCFClient:
    """Minimal httpx.AsyncClient stand-in for Cloudflare API."""

    def __init__(self, existing_ips: list[str], post_status: int = 200):
        self._existing = existing_ips
        self._post_status = post_status
        self.posted: list[list[dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def get(self, _url: str, headers=None, params=None) -> MagicMock:  # noqa: ARG002
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(
            return_value={
                "result": [{"ip": ip} for ip in self._existing],
                "result_info": {"cursors": {}},
            }
        )
        return resp

    async def post(self, _url: str, headers=None, json=None) -> MagicMock:  # noqa: ARG002
        self.posted.append(json or [])
        resp = MagicMock()
        resp.status_code = self._post_status
        return resp


@pytest.mark.asyncio
async def test_cloudflare_push_partial_overlap_adds_only_new():
    """Two offenders, one already on the list → that one is skipped, the
    other is POSTed."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])

    fake = _FakeCFClient(existing_ips=["1.1.1.1"])
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", min_hits=5
        )

    assert result["dry_run"] is False
    assert sorted(result["added"]) == ["2.2.2.2"]
    assert sorted(result["skipped"]) == ["1.1.1.1"]
    assert result["failed"] == []
    # One POST happened with one item
    assert len(fake.posted) == 1
    assert fake.posted[0][0]["ip"] == "2.2.2.2"


@pytest.mark.asyncio
async def test_cloudflare_push_full_overlap_no_post():
    """All offenders already on the list → no POST."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])

    fake = _FakeCFClient(existing_ips=["1.1.1.1", "2.2.2.2"])
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", min_hits=5
        )

    assert result["added"] == []
    assert sorted(result["skipped"]) == ["1.1.1.1", "2.2.2.2"]
    assert fake.posted == []


@pytest.mark.asyncio
async def test_cloudflare_push_empty_offenders_no_op():
    """No offenders meeting threshold → uniform empty shape, no API call."""
    from honeypot_mcp.tools import blocklist_push

    # Insert only 1 hit, but min_hits=5 → filtered out
    await _insert_offenders([("1.1.1.1", 1)])

    fake = _FakeCFClient(existing_ips=[])
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", min_hits=5
        )

    assert result == {"added": [], "skipped": [], "failed": [], "dry_run": False}


@pytest.mark.asyncio
async def test_cloudflare_push_dry_run_returns_diff_without_post():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("3.3.3.3", 10)])

    fake = _FakeCFClient(existing_ips=[])
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", min_hits=5, dry_run=True
        )

    assert result["dry_run"] is True
    assert result["added"] == ["3.3.3.3"]
    assert fake.posted == []  # no mutation despite computed diff


@pytest.mark.asyncio
async def test_cloudflare_push_records_api_failure():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("4.4.4.4", 10)])

    fake = _FakeCFClient(existing_ips=[], post_status=500)
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_cloudflare(
            account_id="acct", list_id="list", api_token="tok", min_hits=5
        )

    assert result["added"] == []
    assert result["failed"] == [{"ip": "4.4.4.4", "error": "HTTP 500"}]


# ── pfSense ─────────────────────────────────────────────────────────────────


class _FakePfClient:
    def __init__(
        self,
        existing_addresses: str,
        get_status: int = 200,
        put_status: int = 200,
        apply_status: int = 200,
    ):
        self.existing_addresses = existing_addresses
        self.get_status = get_status
        self.put_status = put_status
        self.apply_status = apply_status
        self.put_calls: list[dict] = []
        self.apply_called = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def get(self, _url, headers=None, params=None):  # noqa: ARG002
        resp = MagicMock()
        resp.status_code = self.get_status
        resp.json = MagicMock(
            return_value={"data": {"name": "honeypot_block", "address": self.existing_addresses}}
        )
        return resp

    async def put(self, _url, headers=None, json=None):  # noqa: ARG002
        self.put_calls.append(json)
        resp = MagicMock()
        resp.status_code = self.put_status
        return resp

    async def post(self, _url, headers=None):  # noqa: ARG002
        self.apply_called = True
        resp = MagicMock()
        resp.status_code = self.apply_status
        return resp


@pytest.mark.asyncio
async def test_pfsense_push_unions_with_existing_address_list():
    """Two offenders, one already in the alias → PUT body should be the
    union; apply must be called to commit."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])

    fake = _FakePfClient(existing_addresses="1.1.1.1 9.9.9.9")
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local",
            api_key="key",
            alias_name="honeypot_block",
            min_hits=5,
        )

    assert result["added"] == ["2.2.2.2"]
    assert result["skipped"] == ["1.1.1.1"]
    assert result["failed"] == []
    assert len(fake.put_calls) == 1
    # PUT body should be the union, sorted, space-joined
    put_addrs = set(fake.put_calls[0]["address"].split())
    assert put_addrs == {"1.1.1.1", "2.2.2.2", "9.9.9.9"}
    assert fake.apply_called, "must call /apply to commit"


@pytest.mark.asyncio
async def test_pfsense_push_dry_run_skips_put_and_apply():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10)])

    fake = _FakePfClient(existing_addresses="")
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local",
            api_key="key",
            alias_name="honeypot_block",
            min_hits=5,
            dry_run=True,
        )

    assert result["dry_run"] is True
    assert result["added"] == ["1.1.1.1"]
    assert fake.put_calls == []
    assert not fake.apply_called


@pytest.mark.asyncio
async def test_pfsense_push_records_apply_failure():
    """Alias updated but /apply failed → must surface as `failed` so operator
    knows to retry."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("5.5.5.5", 10)])

    fake = _FakePfClient(existing_addresses="", apply_status=500)
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", lambda **_: fake):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local",
            api_key="key",
            alias_name="honeypot_block",
            min_hits=5,
        )

    assert result["added"] == []
    assert result["failed"] == [{"ip": "5.5.5.5", "error": "apply HTTP 500"}]


# ── AWS WAFv2 ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_waf_push_converts_bare_ip_to_cidr_and_unions():
    """Bare IPs become /32. PUTs the union and respects the LockToken."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])

    boto_client = MagicMock()
    boto_client.get_ip_set.return_value = {
        "IPSet": {"Addresses": ["1.1.1.1/32", "9.9.9.9/32"]},
        "LockToken": "lock-abc",
    }

    with patch("boto3.client", return_value=boto_client):
        result = await blocklist_push.blocklist_push_aws_waf(
            ip_set_id="ips-id",
            ip_set_name="honeypot-blocklist",
            region="us-east-1",
            min_hits=5,
        )

    assert sorted(result["added"]) == ["2.2.2.2/32"]
    assert sorted(result["skipped"]) == ["1.1.1.1/32"]
    boto_client.update_ip_set.assert_called_once()
    call_kwargs = boto_client.update_ip_set.call_args.kwargs
    assert call_kwargs["LockToken"] == "lock-abc"
    assert call_kwargs["Scope"] == "REGIONAL"
    assert set(call_kwargs["Addresses"]) == {"1.1.1.1/32", "2.2.2.2/32", "9.9.9.9/32"}


@pytest.mark.asyncio
async def test_waf_push_records_get_failure():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10)])

    boto_client = MagicMock()
    boto_client.get_ip_set.side_effect = RuntimeError("AccessDenied")

    with patch("boto3.client", return_value=boto_client):
        result = await blocklist_push.blocklist_push_aws_waf(
            ip_set_id="ips-id",
            ip_set_name="x",
            region="us-east-1",
            min_hits=5,
        )

    assert result["added"] == []
    assert result["failed"][0]["error"].startswith("get_ip_set:")
    boto_client.update_ip_set.assert_not_called()


@pytest.mark.asyncio
async def test_waf_push_dry_run_returns_diff_without_update_call():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("7.7.7.7", 10)])

    boto_client = MagicMock()
    boto_client.get_ip_set.return_value = {
        "IPSet": {"Addresses": []},
        "LockToken": "lock",
    }

    with patch("boto3.client", return_value=boto_client):
        result = await blocklist_push.blocklist_push_aws_waf(
            ip_set_id="x",
            ip_set_name="x",
            region="us-east-1",
            min_hits=5,
            dry_run=True,
        )

    assert result["dry_run"] is True
    assert result["added"] == ["7.7.7.7/32"]
    boto_client.update_ip_set.assert_not_called()


@pytest.mark.asyncio
async def test_waf_push_empty_offenders_no_op():
    from honeypot_mcp.tools import blocklist_push

    boto_client = MagicMock()

    with patch("boto3.client", return_value=boto_client):
        result = await blocklist_push.blocklist_push_aws_waf(
            ip_set_id="x",
            ip_set_name="x",
            region="us-east-1",
            min_hits=5,
        )

    assert result == {"added": [], "skipped": [], "failed": [], "dry_run": False}
    # No API calls if no offenders
    boto_client.get_ip_set.assert_not_called()
