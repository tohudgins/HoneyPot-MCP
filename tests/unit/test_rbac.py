"""RBAC tests: role hierarchy, token parsing, and tool-classification
completeness.

The completeness check mirrors `test_honeytoken_create_offers_every_
registered_type` (test_honeytoken_and_provider.py) — a tool nobody
classified is a tool nobody deliberately decided was safe to leave open,
so an unclassified tool fails the build rather than defaulting to viewer
access.
"""

from __future__ import annotations

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


# ── Tool classification is exhaustive and non-overlapping ───────────────────


async def test_rbac_covers_every_registered_tool():
    from honeypot_mcp.rbac import ADMIN_TOOLS, OPERATOR_TOOLS, VIEWER_TOOLS
    from honeypot_mcp.server import mcp

    registered = {t.name for t in await mcp.list_tools(run_middleware=False)}
    classified = VIEWER_TOOLS | OPERATOR_TOOLS | ADMIN_TOOLS

    missing = registered - classified
    assert not missing, f"tool(s) registered but not classified by rbac.py: {missing}"

    stale = classified - registered
    assert not stale, f"rbac.py names tool(s) that no longer exist: {stale}"


def test_rbac_tool_sets_do_not_overlap():
    from honeypot_mcp.rbac import ADMIN_TOOLS, OPERATOR_TOOLS, VIEWER_TOOLS

    assert not (VIEWER_TOOLS & OPERATOR_TOOLS)
    assert not (VIEWER_TOOLS & ADMIN_TOOLS)
    assert not (OPERATOR_TOOLS & ADMIN_TOOLS)


async def test_operator_and_admin_tools_actually_carry_an_auth_check():
    """Catches the mistake of adding a name to OPERATOR_TOOLS/ADMIN_TOOLS
    without also adding the matching `@mcp.tool(auth=require_role(...))` —
    the set membership alone enforces nothing."""
    from honeypot_mcp.rbac import ADMIN_TOOLS, OPERATOR_TOOLS, VIEWER_TOOLS
    from honeypot_mcp.server import mcp

    for tool in await mcp.list_tools(run_middleware=False):
        if tool.name in OPERATOR_TOOLS or tool.name in ADMIN_TOOLS:
            assert tool.auth is not None, f"{tool.name} is gated but has no auth= check"
        elif tool.name in VIEWER_TOOLS:
            assert tool.auth is None, f"{tool.name} is viewer-tier but has an auth= check"


# ── Role hierarchy ────────────────────────────────────────────────────────


def _ctx(role: str | None):
    from dataclasses import dataclass
    from typing import Any

    @dataclass
    class _Token:
        claims: dict

    @dataclass
    class _Ctx:
        token: Any

    return _Ctx(token=None if role is None else _Token(claims={"role": role}))


def test_no_token_is_allowed_stdio_or_explicit_unauthenticated():
    """See rbac.py module docstring: stdio never reaches this check at all
    (FastMCP short-circuits earlier), and a networked transport with no
    token configured only happens via MCP_ALLOW_UNAUTHENTICATED."""
    from honeypot_mcp.rbac import require_role

    assert require_role("admin")(_ctx(None)) is True


@pytest.mark.parametrize(
    "token_role,required,expected",
    [
        ("viewer", "viewer", True),
        ("viewer", "operator", False),
        ("viewer", "admin", False),
        ("operator", "viewer", True),
        ("operator", "operator", True),
        ("operator", "admin", False),
        ("admin", "viewer", True),
        ("admin", "operator", True),
        ("admin", "admin", True),
    ],
)
def test_role_hierarchy(token_role, required, expected):
    from honeypot_mcp.rbac import require_role

    assert require_role(required)(_ctx(token_role)) is expected


def test_unrecognised_role_claim_is_denied():
    from honeypot_mcp.rbac import require_role

    assert require_role("viewer")(_ctx("superuser")) is False


# ── Token parsing ─────────────────────────────────────────────────────────


def test_legacy_single_token_becomes_an_implicit_admin_token():
    from honeypot_mcp.rbac import parse_auth_tokens

    assert parse_auth_tokens("s3cret", "") == {"s3cret": "admin"}


def test_no_tokens_configured_parses_empty():
    from honeypot_mcp.rbac import parse_auth_tokens

    assert parse_auth_tokens("", "") == {}


def test_multi_token_format_parses_each_role():
    from honeypot_mcp.rbac import parse_auth_tokens

    result = parse_auth_tokens("", "tok-a:admin, tok-b:operator ,tok-c:viewer")
    assert result == {"tok-a": "admin", "tok-b": "operator", "tok-c": "viewer"}


def test_multi_tokens_take_priority_over_the_legacy_single_token():
    from honeypot_mcp.rbac import parse_auth_tokens

    result = parse_auth_tokens("legacy-token", "tok-a:viewer")
    assert result == {"tok-a": "viewer"}
    assert "legacy-token" not in result


@pytest.mark.parametrize(
    "bad_entry",
    [
        "no-colon-here",
        "tok:superuser",
        ":admin",
        "tok:",
    ],
)
def test_malformed_multi_token_entry_raises(bad_entry):
    from honeypot_mcp.rbac import parse_auth_tokens

    with pytest.raises(ValueError, match="Invalid MCP_AUTH_TOKENS"):
        parse_auth_tokens("", bad_entry)


# ── End-to-end: the real registered tool, the real check function ──────────


@pytest.mark.parametrize(
    "tool_name,role,should_allow",
    [
        ("alerts_prune", "operator", False),
        ("alerts_prune", "admin", True),
        ("honeypot_deploy", "viewer", False),
        ("honeypot_deploy", "operator", True),
        ("honeypot_list", "viewer", True),
        ("blocklist_push_cloudflare", "operator", False),
        ("blocklist_push_cloudflare", "admin", True),
    ],
)
async def test_real_registered_tool_enforces_its_declared_role(tool_name, role, should_allow):
    """Exercises the actual auth check object FastMCP stores on the actual
    registered tool — not a re-implementation of the logic under test."""
    from fastmcp.utilities.authorization import AuthContext, run_auth_checks

    from honeypot_mcp.server import mcp

    tool = await mcp.get_tool(tool_name)
    if tool.auth is None:
        allowed = True  # viewer tier: no check object at all
    else:
        ctx = AuthContext(token=_ctx(role).token, component=tool)
        allowed = await run_auth_checks(tool.auth, ctx)
    assert allowed is should_allow


# ── main()/_build_auth() wiring ─────────────────────────────────────────────


def test_networked_auth_error_accepts_mcp_auth_tokens_alone():
    """MCP_AUTH_TOKENS without the legacy MCP_AUTH_TOKEN must satisfy the
    fail-closed startup gate — this regressed once already when the gate
    only checked the singular setting."""
    from types import SimpleNamespace

    from honeypot_mcp.server import _networked_auth_error

    settings = SimpleNamespace(
        mcp_transport="http",
        mcp_auth_token="",
        mcp_auth_tokens="tok:viewer",
        mcp_allow_unauthenticated=False,
    )
    assert _networked_auth_error(settings) is None
