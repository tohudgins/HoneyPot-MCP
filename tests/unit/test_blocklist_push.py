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

import json
import os
from unittest.mock import MagicMock, patch

import httpx
import pytest

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


_REAL_ASYNC_CLIENT = httpx.AsyncClient


class _CloudflareListStub:
    """Cloudflare's Lists API as documented: creating items is an asynchronous bulk operation.

    POST returns an `operation_id` and 200 only means "accepted". An account may have ONE pending
    operation, so a second POST before the first has finished is refused. Status moves
    pending -> running -> completed (or failed) as the operation is polled, and the items appear on
    the list only once it completes.
    """

    def __init__(
        self, existing=(), polls_to_finish=2, outcome="completed", read_status=200, page_size=2
    ):
        self.items = list(existing)
        self.polls_to_finish = polls_to_finish
        self.outcome = outcome
        self.read_status = read_status
        self.page_size = page_size
        self.posts: list[list[str]] = []
        self.refused = 0
        self._pending: dict[str, dict] = {}
        self._counter = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != "Bearer tok":
            return httpx.Response(403, json={"success": False})
        path = request.url.path
        base = "/client/v4/accounts/acct/rules/lists"
        if request.method == "GET" and path == f"{base}/list/items":
            if self.read_status != 200:
                return httpx.Response(self.read_status, json={"success": False})
            start = int(request.url.params.get("cursor") or 0)
            page = self.items[start : start + self.page_size]
            after = (
                str(start + self.page_size) if start + self.page_size < len(self.items) else None
            )
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "result": [{"ip": ip} for ip in page],
                    "result_info": {"cursors": {"after": after} if after else {}},
                },
            )
        if request.method == "POST" and path == f"{base}/list/items":
            if self._pending:
                self.refused += 1
                return httpx.Response(400, json={"success": False, "errors": [{"code": 10102}]})
            ips = [item["ip"] for item in json.loads(request.content)]
            self.posts.append(ips)
            self._counter += 1
            op = f"{self._counter:032x}"
            self._pending[op] = {"ips": ips, "polls": 0}
            return httpx.Response(200, json={"success": True, "result": {"operation_id": op}})
        if request.method == "GET" and path.startswith(f"{base}/bulk_operations/"):
            op = path.rsplit("/", 1)[1]
            state = self._pending.get(op)
            if state is None:
                return httpx.Response(404, json={"success": False})
            state["polls"] += 1
            if state["polls"] < self.polls_to_finish:
                return httpx.Response(200, json={"result": {"id": op, "status": "running"}})
            if self.outcome == "never":
                return httpx.Response(200, json={"result": {"id": op, "status": "pending"}})
            del self._pending[op]
            if self.outcome == "failed":
                return httpx.Response(
                    200, json={"result": {"id": op, "status": "failed", "error": "list is full"}}
                )
            self.items += state["ips"]
            return httpx.Response(200, json={"result": {"id": op, "status": "completed"}})
        return httpx.Response(404, json={"success": False})

    def client_factory(self):
        return lambda **_: _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(self.handle))


@pytest.fixture(autouse=True)
def _fast_cloudflare_polling(monkeypatch):
    from honeypot_mcp.tools import blocklist_push

    monkeypatch.setattr(blocklist_push, "_CF_POLL_INTERVAL", 0.001)


async def _push_cf(stub: _CloudflareListStub, **kwargs):
    from honeypot_mcp.tools import blocklist_push

    params = {"account_id": "acct", "list_id": "list", "api_token": "tok", "min_hits": 5, **kwargs}
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", stub.client_factory()):
        return await blocklist_push.blocklist_push_cloudflare(**params)


@pytest.mark.asyncio
async def test_cloudflare_push_adds_only_new_ips_and_reports_them_once_on_the_list():
    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])
    stub = _CloudflareListStub(existing=["1.1.1.1"])

    result = await _push_cf(stub)

    assert result == {"added": ["2.2.2.2"], "skipped": ["1.1.1.1"], "failed": [], "dry_run": False}
    assert stub.items == ["1.1.1.1", "2.2.2.2"], "added must mean actually on the list"


@pytest.mark.asyncio
async def test_cloudflare_push_reads_every_page_of_the_existing_list():
    """With the list paged, an IP on page two must still count as already present."""
    await _insert_offenders([("5.5.5.5", 10)])
    stub = _CloudflareListStub(existing=["1.1.1.1", "2.2.2.2", "3.3.3.3", "5.5.5.5"], page_size=2)

    result = await _push_cf(stub)

    assert result["skipped"] == ["5.5.5.5"] and result["added"] == []
    assert stub.posts == []


@pytest.mark.asyncio
async def test_cloudflare_push_waits_for_each_operation_before_sending_the_next_chunk(monkeypatch):
    """Cloudflare refuses a second create while one is pending. Posting chunks back to back
    lost every chunk after the first for any list change over 1,000 addresses."""
    from honeypot_mcp.tools import blocklist_push

    monkeypatch.setattr(blocklist_push, "_CF_CHUNK", 2)
    await _insert_offenders([(f"7.7.7.{n}", 10) for n in range(1, 6)])
    stub = _CloudflareListStub(polls_to_finish=3)

    result = await _push_cf(stub)

    assert stub.refused == 0, "a chunk was sent while the previous operation was still pending"
    assert [len(p) for p in stub.posts] == [2, 2, 1]
    assert sorted(result["added"]) == sorted(stub.items) and result["failed"] == []


@pytest.mark.asyncio
async def test_cloudflare_push_does_not_claim_success_for_an_operation_that_failed_later():
    await _insert_offenders([("4.4.4.4", 10)])
    stub = _CloudflareListStub(outcome="failed")

    result = await _push_cf(stub)

    assert result["added"] == []
    assert result["failed"] == [{"ip": "4.4.4.4", "error": "operation failed: list is full"}]
    assert stub.items == []


@pytest.mark.asyncio
async def test_cloudflare_push_reports_an_operation_that_never_finishes(monkeypatch):
    from honeypot_mcp.tools import blocklist_push

    monkeypatch.setattr(blocklist_push, "_CF_OPERATION_TIMEOUT", 0.05)
    await _insert_offenders([("4.4.4.4", 10)])
    stub = _CloudflareListStub(outcome="never")

    result = await _push_cf(stub)

    assert result["added"] == []
    assert result["failed"][0]["ip"] == "4.4.4.4"
    assert "still" in result["failed"][0]["error"]


@pytest.mark.asyncio
async def test_cloudflare_push_full_overlap_makes_no_change():
    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])
    stub = _CloudflareListStub(existing=["1.1.1.1", "2.2.2.2"])

    result = await _push_cf(stub)

    assert result["added"] == [] and sorted(result["skipped"]) == ["1.1.1.1", "2.2.2.2"]
    assert stub.posts == []


@pytest.mark.asyncio
async def test_cloudflare_push_empty_offenders_no_op():
    await _insert_offenders([("1.1.1.1", 1)])  # below min_hits

    result = await _push_cf(_CloudflareListStub())

    assert result == {"added": [], "skipped": [], "failed": [], "dry_run": False}


@pytest.mark.asyncio
async def test_cloudflare_push_dry_run_returns_the_diff_without_posting():
    await _insert_offenders([("3.3.3.3", 10)])
    stub = _CloudflareListStub()

    result = await _push_cf(stub, dry_run=True)

    assert result["dry_run"] is True and result["added"] == ["3.3.3.3"]
    assert stub.posts == [] and stub.items == []


@pytest.mark.asyncio
async def test_cloudflare_push_records_a_list_read_failure():
    await _insert_offenders([("4.4.4.4", 10)])

    result = await _push_cf(_CloudflareListStub(read_status=403))

    assert result["added"] == []
    assert result["failed"] == [{"ip": "*", "error": "list read HTTP 403"}]


# ── pfSense ─────────────────────────────────────────────────────────────────


class _PfRestStub:
    """The pfSense REST API package's alias contract (openapi.json from pfrest.org, v2).

    Strict on purpose: it rejects what the real API rejects, so a request that only a mock would
    accept fails here. `GET /firewall/alias` needs an integer `id` (not a name), the list endpoint
    is `/firewall/aliases`, an update is `PATCH` with the `id` in the body (there is no PUT), and
    the key travels in `X-API-Key`.
    """

    def __init__(
        self,
        address=(),
        detail=(),
        alias_name="honeypot_block",
        apply_status=200,
        patch_status=200,
        extra_aliases=(),
    ):
        self.alias = {
            "id": 7,
            "name": alias_name,
            "type": "host",
            "address": list(address),
            "detail": list(detail),
        }
        self.others = list(extra_aliases)
        self.apply_status = apply_status
        self.patch_status = patch_status
        self.requests: list[tuple[str, str]] = []
        self.patches: list[dict] = []
        self.applied = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append((request.method, request.url.path))
        if request.headers.get("x-api-key") != "key":
            return httpx.Response(401, json={"code": 401, "message": "Authentication failed"})
        route = (request.method, request.url.path)
        if route == ("GET", "/api/v2/firewall/aliases"):
            name = request.url.params.get("name")
            rows = [self.alias, *self.others]
            rows = [r for r in rows if name is None or r["name"] == name]
            return httpx.Response(200, json={"code": 200, "status": "ok", "data": rows})
        if route == ("PATCH", "/api/v2/firewall/alias"):
            body = json.loads(request.content)
            if body.get("id") != self.alias["id"]:
                return httpx.Response(400, json={"code": 400, "message": "unknown id"})
            if len(body.get("detail", [])) != len(body.get("address", [])):
                return httpx.Response(400, json={"code": 400, "message": "detail must match"})
            self.patches.append(body)
            if self.patch_status == 200:
                self.alias.update(address=body["address"], detail=body["detail"])
            return httpx.Response(self.patch_status, json={"code": self.patch_status})
        if route == ("POST", "/api/v2/firewall/apply"):
            self.applied = self.apply_status == 200
            return httpx.Response(self.apply_status, json={"code": self.apply_status})
        return httpx.Response(404, json={"code": 404, "message": "no such endpoint"})

    def client_factory(self, seen: dict | None = None):
        def make(**kwargs):
            if seen is not None:
                seen.update(kwargs)
            return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(self.handle))

        return make


async def _push_pf(stub: _PfRestStub, **kwargs):
    from honeypot_mcp.tools import blocklist_push

    params = {
        "base_url": "https://pf.local",
        "api_key": "key",
        "alias_name": "honeypot_block",
        "min_hits": 5,
        **kwargs,
    }
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", stub.client_factory()):
        return await blocklist_push.blocklist_push_pfsense(**params)


@pytest.mark.asyncio
async def test_pfsense_push_speaks_the_real_rest_api_and_commits():
    """Union with what is already in the alias, PATCH by id, then apply; no mock-only shortcuts."""
    await _insert_offenders([("1.1.1.1", 10), ("2.2.2.2", 10)])
    stub = _PfRestStub(address=["1.1.1.1", "9.9.9.9"], detail=["old", "keep"])

    result = await _push_pf(stub)

    assert result["added"] == ["2.2.2.2"] and result["skipped"] == ["1.1.1.1"]
    assert result["failed"] == []
    assert stub.alias["address"] == ["1.1.1.1", "9.9.9.9", "2.2.2.2"]
    assert stub.alias["detail"] == ["old", "keep", "honeypot-mcp"], "comments must stay aligned"
    assert stub.applied, "must call /apply to commit"


@pytest.mark.asyncio
async def test_pfsense_push_pads_missing_descriptions_instead_of_misaligning_them():
    await _insert_offenders([("2.2.2.2", 10)])
    stub = _PfRestStub(address=["9.9.9.9", "8.8.8.8"], detail=["only one"])

    await _push_pf(stub)

    assert stub.alias["detail"] == ["only one", "", "honeypot-mcp"]


@pytest.mark.asyncio
async def test_pfsense_push_takes_only_the_alias_that_was_named():
    """A filter that matches loosely must never get another alias patched."""
    await _insert_offenders([("2.2.2.2", 10)])
    stub = _PfRestStub(alias_name="honeypot_block_v2", extra_aliases=[])
    stub.others = [{"id": 8, "name": "lan_hosts", "type": "host", "address": [], "detail": []}]
    real_handle = stub.handle

    def loose(request):  # a server that ignores the name filter and returns everything
        if request.url.path.endswith("/aliases"):
            return httpx.Response(200, json={"data": [stub.others[0], stub.alias]})
        return real_handle(request)

    stub.handle = loose
    result = await _push_pf(stub, alias_name="honeypot_block_v2")

    assert result["added"] == ["2.2.2.2"]
    assert [p["id"] for p in stub.patches] == [7]


@pytest.mark.asyncio
async def test_pfsense_push_reports_a_missing_alias_instead_of_creating_one():
    await _insert_offenders([("2.2.2.2", 10)])
    stub = _PfRestStub()

    result = await _push_pf(stub, alias_name="does_not_exist")

    assert result["added"] == []
    assert result["failed"] == [{"ip": "*", "error": "alias 'does_not_exist' not found"}]
    assert stub.patches == []


@pytest.mark.asyncio
async def test_pfsense_push_a_wrong_key_is_a_clean_failure():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("2.2.2.2", 10)])
    stub = _PfRestStub()
    with patch("honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", stub.client_factory()):
        result = await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local", api_key="wrong", alias_name="honeypot_block", min_hits=5
        )

    assert result["added"] == []
    assert result["failed"] == [{"ip": "*", "error": "alias read HTTP 401"}]


@pytest.mark.asyncio
async def test_pfsense_push_verifies_tls_by_default():
    """pfSense's REST API commonly runs on a self-signed cert, but the default must still be
    secure: an operator has to opt out (verify_tls=False) explicitly."""
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10)])
    seen: dict = {}
    with patch(
        "honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", _PfRestStub().client_factory(seen)
    ):
        await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local", api_key="key", alias_name="honeypot_block", min_hits=5
        )

    assert seen["verify"] is True


@pytest.mark.asyncio
async def test_pfsense_push_verify_tls_false_is_an_explicit_opt_in():
    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10)])
    seen: dict = {}
    with patch(
        "honeypot_mcp.tools.blocklist_push.httpx.AsyncClient", _PfRestStub().client_factory(seen)
    ):
        await blocklist_push.blocklist_push_pfsense(
            base_url="https://pf.local",
            api_key="key",
            alias_name="honeypot_block",
            min_hits=5,
            verify_tls=False,
        )

    assert seen["verify"] is False


@pytest.mark.asyncio
async def test_pfsense_push_dry_run_changes_nothing():
    await _insert_offenders([("1.1.1.1", 10)])
    stub = _PfRestStub()

    result = await _push_pf(stub, dry_run=True)

    assert result["dry_run"] is True and result["added"] == ["1.1.1.1"]
    assert stub.patches == [] and not stub.applied
    assert {m for m, _ in stub.requests} == {"GET"}


@pytest.mark.asyncio
async def test_pfsense_push_records_apply_failure():
    """Alias updated but /apply failed: surface it so the operator knows to retry."""
    await _insert_offenders([("5.5.5.5", 10)])
    stub = _PfRestStub(apply_status=500)

    result = await _push_pf(stub)

    assert result["added"] == []
    assert result["failed"] == [{"ip": "5.5.5.5", "error": "apply HTTP 500"}]


@pytest.mark.asyncio
async def test_pfsense_push_records_patch_failure():
    await _insert_offenders([("5.5.5.5", 10)])
    stub = _PfRestStub(patch_status=403)

    result = await _push_pf(stub)

    assert result["failed"] == [{"ip": "5.5.5.5", "error": "PATCH HTTP 403"}]
    assert not stub.applied, "a failed update must not be committed"


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
async def test_waf_push_does_not_block_the_event_loop():
    """boto3 is synchronous; every in-process engine (HTTP, SMTP, FTP, Redis,
    MySQL, ...) shares this one event loop, so a bare boto3 call would stall
    all of them for the duration of the AWS round trip — worse under
    throttling, where boto3's own retry/backoff can take seconds. Proves the
    blocking call is actually offloaded to a thread: a concurrent asyncio
    task must keep making progress while a slow, synchronous get_ip_set is
    "in flight"."""
    import asyncio
    import time

    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("1.1.1.1", 10)])

    def _slow_get_ip_set(**kwargs):
        time.sleep(0.3)  # a slow/throttled synchronous AWS call
        return {"IPSet": {"Addresses": []}, "LockToken": "lock-abc"}

    boto_client = MagicMock()
    boto_client.get_ip_set.side_effect = _slow_get_ip_set
    boto_client.update_ip_set.return_value = {}

    progress = 0

    async def _ticker():
        nonlocal progress
        while True:
            await asyncio.sleep(0.01)
            progress += 1

    with patch("boto3.client", return_value=boto_client):
        ticker_task = asyncio.create_task(_ticker())
        try:
            await blocklist_push.blocklist_push_aws_waf(
                ip_set_id="ips-id",
                ip_set_name="honeypot-blocklist",
                region="us-east-1",
                min_hits=5,
            )
        finally:
            ticker_task.cancel()

    # If the boto3 call blocked the event loop, the ticker would have made
    # essentially zero progress during the ~0.3s the call was "in flight".
    assert progress >= 10, f"event loop was blocked during the AWS call (progress={progress})"


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


@pytest.mark.asyncio
async def test_waf_push_makes_calls_the_real_wafv2_api_accepts_and_keeps_the_description():
    """botocore's Stubber validates every call against the real WAFv2 service model, so a missing
    required parameter or a misspelt one fails here instead of in production. UpdateIPSet replaces
    the description with whatever it is given, so the operator's own must be sent back."""
    import boto3
    from botocore.stub import Stubber

    from honeypot_mcp.tools import blocklist_push

    await _insert_offenders([("2.2.2.2", 10)])
    client = boto3.client(
        "wafv2", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    base = {
        "Name": "honeypot-block",
        "Id": "a1b2c3d4-0000-4000-8000-000000000000",
        "Scope": "REGIONAL",
    }
    with Stubber(client) as stub:
        stub.add_response(
            "get_ip_set",
            {
                "IPSet": {
                    "Name": base["Name"],
                    "Id": base["Id"],
                    "ARN": "arn:aws:wafv2:us-east-1:1:regional/ipset/honeypot-block/x",
                    "Description": "owned by the SOC",
                    "IPAddressVersion": "IPV4",
                    "Addresses": ["9.9.9.9/32"],
                },
                "LockToken": "11111111-2222-3333-4444-555555555555",
            },
            base,
        )
        stub.add_response(
            "update_ip_set",
            {"NextLockToken": "66666666-7777-8888-9999-000000000000"},
            {
                **base,
                "Description": "owned by the SOC",
                "Addresses": ["2.2.2.2/32", "9.9.9.9/32"],
                "LockToken": "11111111-2222-3333-4444-555555555555",
            },
        )
        with patch("boto3.client", return_value=client):
            result = await blocklist_push.blocklist_push_aws_waf(
                ip_set_name=base["Name"],
                ip_set_id=base["Id"],
                scope="REGIONAL",
                region="us-east-1",
                min_hits=5,
            )
        stub.assert_no_pending_responses()

    assert result["added"] == ["2.2.2.2/32"] and result["failed"] == []
