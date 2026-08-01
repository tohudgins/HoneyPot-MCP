"""Role-based access control for the networked MCP control plane.

Only meaningful for networked transports (http/sse/streamable-http) with a
token configured. stdio is a per-chat local subprocess with no client
identity to gate — FastMCP itself short-circuits every per-tool `auth` check
there (`server.py:_get_auth_context`), so nothing here ever runs against it,
matching every other auth decision in this codebase (see
`server.py:_build_auth`). A networked transport running via
`MCP_ALLOW_UNAUTHENTICATED` (no token configured at all — the operator fronts
it with their own auth) is treated the same way: `require_role` allows a
request that carries no token, because by construction
(`server.py:_networked_auth_error`) the server never reaches that state
*with* a token configured — if a token is required, the transport itself
rejects an untokened request with 401 before any per-tool check like this one
ever runs.

Three roles, each a strict superset of the one before it:
  - viewer:   read-only — list/get/search/analyse/report. No state changes.
  - operator: viewer + manage this system's own resources: deploy/stop
              honeypots, create/rotate/revoke honeytokens, acknowledge
              alerts, suppression rules, webhook subscriptions, pcap,
              deception plan deployment. Every effect is contained to, and
              reversible within, this system's own data.
  - admin:    operator + the handful of tools whose blast radius reaches
              outside this system's own database: `alerts_prune` (permanent
              evidence deletion), the `blocklist_push_*` tools (write to a
              real external firewall/WAF — production infrastructure this
              codebase doesn't own), and `audit_log_search` (oversight of
              what every other role did).

New tools MUST be added to exactly one of the three sets below AND decorated
with the matching `@mcp.tool(auth=require_role(...))` — viewer tools need no
decorator at all (no `auth=` means "any authenticated caller"`).
`test_rbac_covers_every_registered_tool` in `tests/unit/test_rbac.py` fails
the build otherwise: the same fail-closed pattern
`test_honeytoken_create_offers_every_registered_type` already uses for
`HoneytokenType`. A tool nobody classified is a tool nobody deliberately
decided was safe to leave open — treat that as a bug, not a default.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from fastmcp.utilities.authorization import AuthCheck, AuthContext

Role = Literal["viewer", "operator", "admin"]

_ROLE_RANK: dict[Role, int] = {"viewer": 0, "operator": 1, "admin": 2}


def require_role(role: Role) -> AuthCheck:
    """Build an `auth=` check for `@mcp.tool` requiring `role` or higher.

    Reads the role from the access token's `claims["role"]` — set by
    `_build_auth()` when it constructs the `StaticTokenVerifier` token
    dict — rather than OAuth scope-subset matching, since a single
    `"role"` claim compared by rank is simpler to reason about than keeping
    a per-role scope list in sync with the hierarchy.
    """
    required = _ROLE_RANK[role]

    def check(ctx: AuthContext) -> bool:
        if ctx.token is None:
            # stdio never reaches here (short-circuited earlier). A
            # networked transport with no token means MCP_ALLOW_UNAUTHENTICATED
            # was explicitly set — see module docstring.
            return True
        claims = ctx.token.claims or {}
        token_role = claims.get("role")
        return token_role in _ROLE_RANK and _ROLE_RANK[token_role] >= required

    return check


def parse_auth_tokens(single_token: str, multi_tokens: str) -> dict[str, Role]:
    """Parse auth tokens into `{token: role}`.

    `multi_tokens` (`MCP_AUTH_TOKENS`) is `token:role,token:role,...` and
    takes priority when set, so an operator can hand out differently-scoped
    tokens. When it's unset, `single_token` (the original `MCP_AUTH_TOKEN`)
    becomes one implicit `admin` token — existing single-token deployments
    keep exactly the full access they already have; this is additive, not a
    breaking change.

    Raises `ValueError` on a malformed `MCP_AUTH_TOKENS` entry — deliberately
    fails startup loudly (this runs at `server.py` import time, building the
    auth provider) rather than silently dropping a misconfigured token, which
    would otherwise look like a working deployment with one fewer operator
    able to log in.
    """
    if multi_tokens:
        tokens: dict[str, Role] = {}
        for entry in multi_tokens.split(","):
            entry = entry.strip()
            if not entry:
                continue
            token, sep, role = entry.rpartition(":")
            if not sep or not token or role not in _ROLE_RANK:
                raise ValueError(
                    f"Invalid MCP_AUTH_TOKENS entry {entry!r}; expected "
                    f"'<token>:<viewer|operator|admin>'"
                )
            tokens[token] = role  # type: ignore[assignment]
        return tokens
    if single_token:
        return {single_token: "admin"}
    return {}


# ── Tool → role map ──────────────────────────────────────────────────────────
#
# Grep-verified against every `@mcp.tool`-decorated function in
# `tools/*.py` and `server.py` (61 total as of this writing). Viewer tools
# carry no `auth=` kwarg at all, so this set exists purely so the
# completeness test has something to check them against.

VIEWER_TOOLS: frozenset[str] = frozenset(
    {
        "alerts_recent",
        "alerts_get",
        "alerts_search",
        "alerts_stats",
        "enrich_ip",
        "analyze_attacker",
        "analyze_campaign",
        "map_ttps",
        "generate_report",
        "analyze_attacker_journey",
        "analyze_session",
        "threat_timeline",
        "deception_profiles",
        "deception_plan",
        "deception_coverage",
        "soc_brief",
        "honeypot_list",
        "honeypot_status",
        "honeypot_logs",
        "honeypot_templates",
        "honeypot_health",
        "honeytoken_list",
        "honeytoken_status",
        "alert_subscriptions_list",
        "suppression_list",
        "suppression_list_presets",
        "pcap_status",
        "pcap_files",
        "ping",
    }
)

OPERATOR_TOOLS: frozenset[str] = frozenset(
    {
        "honeypot_deploy",
        "honeypot_stop",
        "honeypot_pause",
        "honeypot_resume",
        "honeypot_configure",
        "honeypot_clone",
        "honeypot_self_test",
        "honeytoken_create",
        "honeytoken_rotate",
        "honeytoken_revoke",
        "honeytoken_generate_aws",
        "honeytoken_generate_credentials",
        "honeytoken_embed_file",
        "honeytoken_export",
        "alerts_acknowledge",
        "alerts_export",
        "alert_subscribe",
        "alert_unsubscribe",
        "suppression_add",
        "suppression_remove",
        "suppression_load_preset",
        "deception_deploy_plan",
        "pcap_control",
        "pcap_extract",
        "export_blocklist",
        "export_stix",
        "report_ip_abuse",
    }
)

ADMIN_TOOLS: frozenset[str] = frozenset(
    {
        "alerts_prune",
        "blocklist_push_cloudflare",
        "blocklist_push_pfsense",
        "blocklist_push_aws_waf",
        "audit_log_search",
    }
)
