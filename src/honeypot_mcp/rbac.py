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
              codebase doesn't own), `audit_log_search` (oversight of what
              every other role did), and `api_key_create`/`api_key_revoke`/
              `api_key_list` (granting or revoking someone else's access is
              itself an admin-tier action).

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

import hashlib
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from fastmcp.server.auth import AccessToken
    from fastmcp.utilities.authorization import AuthCheck, AuthContext

log = logging.getLogger(__name__)

Role = Literal["viewer", "operator", "admin"]

_ROLE_RANK: dict[Role, int] = {"viewer": 0, "operator": 1, "admin": 2}


def current_actor() -> str:
    """Best-effort identity string for the audit log's `actor` column.

    stdio has no token at all — a per-chat local subprocess, trusted by
    design (see `server.py:_build_auth`) — and gets a fixed label rather
    than empty/None, so a reader never has to wonder whether the caller was
    missed vs. genuinely local. A networked caller is labelled by its
    token's `label` claim (an `ApiKey`'s name) when it has one, falling back
    to its bare role — an unlabelled legacy `MCP_AUTH_TOKEN`/`MCP_AUTH_TOKENS`
    entry still gets a recognisable actor string ("admin") instead of
    nothing.
    """
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        return "stdio"
    claims = token.claims or {}
    role = claims.get("role", "unknown")
    label = claims.get("label")
    return f"{label} ({role})" if label else role


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


def hash_token(token: str) -> str:
    """SHA-256 hex digest — what `ApiKey.token_hash` stores and looks up by.

    Tokens are high-entropy random strings (`api_key_create` mints them with
    `secrets.token_hex`), not low-entropy secrets like passwords, so a fast
    hash is the right tool here: there's nothing to dictionary-attack, and a
    slow password hash (bcrypt/argon2) would just tax every single tool call
    for no security benefit. Same reasoning GitHub/AWS use for API-key-shaped
    credentials.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── Live-provisioned API keys ─────────────────────────────────────────────────
#
# Mirrors suppression.py's rule cache exactly: an in-memory dict refreshed at
# most every API_KEY_REFRESH_SECONDS, invalidated immediately on
# create/revoke so a change is never stale for longer than one refresh
# window on THIS process (multi-process deployments still wait out the TTL
# on the others — acceptable for a credential change, unlike a suppression
# rule, since accidentally-still-valid access for at most 30s is not a hole
# an attacker can reliably time against).

API_KEY_REFRESH_SECONDS = 30

_api_keys: dict[str, dict[str, Any]] = {}  # token_hash -> {id, role, label, expires_at}
_api_keys_loaded_at: float = 0.0


def invalidate_api_key_cache() -> None:
    """Force the next verification to reload keys from the DB."""
    global _api_keys_loaded_at
    _api_keys_loaded_at = 0.0


async def _load_api_keys() -> None:
    global _api_keys, _api_keys_loaded_at
    now = time.monotonic()
    if now - _api_keys_loaded_at < API_KEY_REFRESH_SECONDS:
        return

    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import ApiKey

    async with get_session() as session:
        result = await session.execute(select(ApiKey).where(ApiKey.revoked_at.is_(None)))
        rows = result.scalars().all()

    _api_keys = {
        row.token_hash: {
            "id": row.id,
            "role": row.role,
            "label": row.label,
            "expires_at": row.expires_at,
        }
        for row in rows
    }
    _api_keys_loaded_at = now


async def verify_db_token(token: str) -> AccessToken | None:
    """Look up `token` against live-provisioned `ApiKey` rows.

    Returns None for anything not found, revoked (excluded by the query
    itself), or past its `expires_at` — indistinguishable from an unknown
    token to the caller, same as `StaticTokenVerifier`'s own behaviour.
    """
    await _load_api_keys()
    data = _api_keys.get(hash_token(token))
    if data is None:
        return None
    expires_at = data["expires_at"]
    if expires_at is not None and expires_at < datetime.now(UTC):
        return None

    from fastmcp.server.auth import AccessToken

    return AccessToken(
        token=token,
        client_id=data["label"],
        scopes=[data["role"]],
        claims={"role": data["role"], "label": data["label"], "api_key_id": data["id"]},
    )


def build_combined_verifier(static_tokens: dict[str, dict[str, Any]]) -> Any:
    """A `TokenVerifier` checking static env-configured tokens first, then
    live `ApiKey` rows.

    Static tokens (`MCP_AUTH_TOKEN`/`MCP_AUTH_TOKENS`) stay in-memory and
    restart-only — a deliberate break-glass credential, and the only way to
    bootstrap the very first `ApiKey` row (`api_key_create` is itself
    admin-gated). Everything provisioned afterwards can go through
    `api_key_create`/`api_key_revoke` instead, which take effect live.

    A factory function rather than a module-level class so the `fastmcp`
    import (needed to subclass `TokenVerifier`, not just duck-type it — it
    carries OAuth-metadata/route scaffolding from `AuthProvider` that a bare
    class wouldn't have) stays deferred to call time, same as every other
    `fastmcp`-touching function in this module.
    """
    from fastmcp.server.auth import AccessToken, TokenVerifier

    class _CombinedTokenVerifier(TokenVerifier):
        async def verify_token(self, token: str) -> AccessToken | None:
            if token in static_tokens:
                data = static_tokens[token]
                return AccessToken(
                    token=token,
                    client_id=data["client_id"],
                    scopes=data["scopes"],
                    claims=data,
                )
            return await verify_db_token(token)

    return _CombinedTokenVerifier()


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
        "api_key_create",
        "api_key_revoke",
        "api_key_list",
    }
)
