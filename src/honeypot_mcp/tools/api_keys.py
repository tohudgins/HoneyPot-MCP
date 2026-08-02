"""Live-provisioned, per-person API keys for the networked control plane.

The static `MCP_AUTH_TOKEN`/`MCP_AUTH_TOKENS` settings (`rbac.parse_auth_tokens`)
require a process restart to add, change, or revoke, and carry no identity
beyond a role — every operator sharing one looks identical in the audit log.
These three tools are the live counterpart: `api_key_create`/`api_key_revoke`
take effect within `rbac.API_KEY_REFRESH_SECONDS` (30s) with no restart, and
`label` gives each key a real identity that `audit_log_search` can attribute
actions to via `rbac.current_actor()`.

All three are admin-only — granting or revoking someone else's access to a
system that can deploy honeypots and read all captured data is itself an
admin-tier action, the same reasoning that puts `audit_log_search` at admin.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from honeypot_mcp.rbac import current_actor, hash_token, invalidate_api_key_cache, require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import ApiKey
from honeypot_mcp.tools._audit import record_action


@mcp.tool(auth=require_role("admin"))
async def api_key_create(
    label: str,
    role: Literal["viewer", "operator", "admin"],
    expires_in_days: int | None = None,
) -> dict[str, Any]:
    """Issue a new API key for a team member or automation.

    Takes effect within 30 seconds on every server process, no restart
    needed — unlike adding a token to MCP_AUTH_TOKENS.

    The plaintext token is returned exactly once, in this response. Only its
    SHA-256 digest is stored; if it's lost, revoke it (api_key_revoke) and
    issue a new one — there is no way to retrieve the original.

    Args:
        label: Human-readable identity, e.g. "alice" or "ci-pipeline". This
              is what shows up as the actor on audit_log_search entries this
              key makes, so pick something that identifies a real person or
              system, not "key1".
        role: viewer, operator, or admin — see rbac.py for exactly what each
              can do. Prefer the lowest role that covers what this person
              actually needs to do.
        expires_in_days: Optional — the key stops working after this many
              days, checked on every use. Omit for a key valid until
              explicitly revoked.
    """
    if not label.strip():
        return {"error": "label must not be empty."}
    if expires_in_days is not None and expires_in_days <= 0:
        return {"error": "expires_in_days must be greater than 0."}

    token = secrets.token_hex(32)
    expires_at = datetime.now(UTC) + timedelta(days=expires_in_days) if expires_in_days else None

    async with get_session() as session:
        key = ApiKey(
            label=label,
            role=role,
            token_hash=hash_token(token),
            created_by=current_actor(),
            expires_at=expires_at,
        )
        session.add(key)
        await session.flush()
        key_id = key.id

    invalidate_api_key_cache()
    await record_action(
        "api_key_create",
        f"issued {role} key '{label}'"
        + (f", expires in {expires_in_days}d" if expires_in_days else ""),
        arguments={"label": label, "role": role, "expires_in_days": expires_in_days},
        target=label,
    )

    return {
        "id": key_id,
        "label": label,
        "role": role,
        "token": token,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "warning": (
            "Save this token now — it cannot be retrieved again. "
            "If it's lost, revoke this key and create a new one."
        ),
    }


@mcp.tool(auth=require_role("admin"))
async def api_key_revoke(key_id: int) -> dict[str, Any]:
    """Revoke a live-provisioned API key. Takes effect within 30 seconds on
    every server process, no restart needed.

    Does not touch MCP_AUTH_TOKEN/MCP_AUTH_TOKENS — those are static,
    restart-only credentials, not ApiKey rows, and this tool has no way to
    reach them (removing the last one would also remove the ability to
    manage keys at all, since api_key_create/revoke are themselves
    admin-gated).

    Args:
        key_id: The numeric id from api_key_create or api_key_list.
    """
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(select(ApiKey).where(ApiKey.id == key_id))
        key = result.scalar_one_or_none()
        if not key:
            return {"error": f"No API key with id={key_id}."}
        if key.revoked_at is not None:
            return {
                "error": (
                    f"API key {key_id} ('{key.label}') was already revoked "
                    f"at {key.revoked_at.isoformat()}."
                )
            }
        key.revoked_at = datetime.now(UTC)
        label = key.label

    invalidate_api_key_cache()
    await record_action("api_key_revoke", f"revoked {label}'s API key", target=label)
    return {"id": key_id, "label": label, "status": "revoked"}


@mcp.tool(auth=require_role("admin"))
async def api_key_list(include_revoked: bool = False) -> list[dict[str, Any]]:
    """List live-provisioned API keys — metadata only, never the tokens
    themselves (only their hash is ever stored, and this doesn't return
    that either).

    Args:
        include_revoked: Include revoked keys too, for a historical view of
              who has ever had access. Off by default.
    """
    from sqlalchemy import select

    q = select(ApiKey)
    if not include_revoked:
        q = q.where(ApiKey.revoked_at.is_(None))

    async with get_session() as session:
        rows = (await session.execute(q.order_by(ApiKey.created_at.desc()))).scalars().all()

    return [
        {
            "id": r.id,
            "label": r.label,
            "role": r.role,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
        }
        for r in rows
    ]
