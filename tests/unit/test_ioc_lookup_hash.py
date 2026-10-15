"""`lookup_hash`: one SHA-256 through abuse.ch MalwareBazaar, via the real httpx client.

The stub enforces MalwareBazaar's documented request (POST form `query=get_info&hash=...`, header
`Auth-Key`) and answers in its documented shapes, so the tool is exercised end to end — validation,
provider call, result — without a key or the network.
"""

from __future__ import annotations

import json
import os
from urllib.parse import parse_qs

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp._loop_bound import LoopBound  # noqa: E402
from honeypot_mcp.config import get_settings  # noqa: E402
from honeypot_mcp.intel import _cache, abusech  # noqa: E402

KEY = "mb-secret"
KNOWN = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    _cache.clear()
    monkeypatch.setattr(get_settings(), "abusech_auth_key", "", raising=False)
    yield
    _cache.clear()


def _install(monkeypatch) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        ok = (
            request.method == "POST"
            and request.url.host == "mb-api.abuse.ch"
            and request.url.path == "/api/v1/"
            and request.headers.get("Auth-Key") == KEY
            and "x-www-form-urlencoded" in request.headers.get("content-type", "")
        )
        if not ok:
            return httpx.Response(200, json={"query_status": "no_api_key"})
        form = parse_qs(request.content.decode())
        if form.get("query") != ["get_info"]:
            return httpx.Response(200, json={"query_status": "http_post_expected"})
        if form["hash"] == [KNOWN]:
            return httpx.Response(
                200,
                json={
                    "query_status": "ok",
                    "data": [
                        {
                            "sha256_hash": KNOWN,
                            "signature": "Mirai",
                            "file_type": "elf",
                            "file_name": "x.arm",
                            "first_seen": "2020-02-28 05:57:01",
                            "tags": ["Mirai"],
                        }
                    ],
                },
            )
        return httpx.Response(200, json={"query_status": "hash_not_found"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(
        abusech, "_client", LoopBound(lambda: httpx.AsyncClient(transport=transport, timeout=3.0))
    )
    return seen


async def test_without_a_key_it_is_a_note_not_an_error_and_nothing_is_sent(monkeypatch):
    from honeypot_mcp.tools.ioc import lookup_hash

    seen = _install(monkeypatch)

    result = await lookup_hash(KNOWN)

    assert result["available"] is False and "ABUSECH_AUTH_KEY" in result["note"]
    assert "error" not in result and seen == []


async def test_a_known_hash_returns_the_family_and_the_request_is_the_documented_one(monkeypatch):
    from honeypot_mcp.tools.ioc import lookup_hash

    monkeypatch.setattr(get_settings(), "abusech_auth_key", KEY, raising=False)
    seen = _install(monkeypatch)

    result = await lookup_hash(f"  {KNOWN.upper()}  ")

    assert result["available"] is True and result["known"] is True
    assert result["signature"] == "Mirai" and result["file_type"] == "elf"
    assert parse_qs(seen[0].content.decode()) == {"query": ["get_info"], "hash": [KNOWN]}
    assert KEY not in json.dumps(result)


async def test_an_unknown_hash_is_a_clean_negative_answer(monkeypatch):
    from honeypot_mcp.tools.ioc import lookup_hash

    monkeypatch.setattr(get_settings(), "abusech_auth_key", KEY, raising=False)
    _install(monkeypatch)

    result = await lookup_hash("1" * 64)

    assert result["available"] is True and result["known"] is False


async def test_a_wrong_key_is_reported_as_a_credential_problem(monkeypatch):
    from honeypot_mcp.tools.ioc import lookup_hash

    monkeypatch.setattr(get_settings(), "abusech_auth_key", "wrong", raising=False)
    _install(monkeypatch)

    result = await lookup_hash(KNOWN)

    assert result["available"] is False and "Auth-Key" in result["error"]
    assert "wrong" not in json.dumps(result)


@pytest.mark.parametrize(
    "bad", ["", "abc", "g" * 64, KNOWN[:-1], KNOWN + "0", "a" * 32, "../../etc/passwd", f"{KNOWN}x"]
)
async def test_anything_but_exactly_64_hex_digits_is_refused_before_any_lookup(monkeypatch, bad):
    from honeypot_mcp.tools.ioc import lookup_hash

    monkeypatch.setattr(get_settings(), "abusech_auth_key", KEY, raising=False)
    seen = _install(monkeypatch)

    result = await lookup_hash(bad)

    assert "error" in result and "64 hexadecimal" in result["error"] and seen == []


async def test_the_tool_is_viewer_tier_and_marked_open_world():
    from honeypot_mcp import rbac
    from honeypot_mcp.server import mcp

    tools = {t.name: t for t in await mcp.list_tools()}

    assert "lookup_hash" in rbac.VIEWER_TOOLS
    assert tools["lookup_hash"].annotations.openWorldHint is True
    assert tools["lookup_hash"].annotations.readOnlyHint is True
