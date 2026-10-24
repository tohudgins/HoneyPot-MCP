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

import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from honeypot_mcp.rbac import current_actor, hash_token, invalidate_api_key_cache, require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import ApiKey
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action

_LABEL_RE = re.compile(r"[A-Za-z0-9_.@ -]{1,64}")


def _error(message: str, hint: str) -> dict[str, Any]:
    return {"error": message, "hint": hint}


@mcp.tool(auth=require_role("admin"), **hints("api_key_create"))
async def api_key_create(
    label: str,
    role: Literal["viewer", "operator", "admin"] = "viewer",
    expires_in_days: int | None = None,
) -> dict[str, Any]:
    """Give a person or automation their own login for this server.

    Use it for "make a read-only key for alice", "an operator key for the CI job for 30 days". Live within 30 seconds, no restart. The token is shown once and cannot be recovered; if it is lost, revoke the key and make another.

    Args:
        label: Who or what it is for ("alice", "ci-pipeline"); shown as the actor in the audit log. Letters, digits, space and ._@- only.
        role: "viewer" (default: read only), "operator" (also deploy, stop, triage), or "admin" (also keys, firewall pushes, pruning). Use the lowest that fits.
        expires_in_days: Days until the key stops working ("for a month" is 30). Omit for none.
    """
    label = label.strip()
    if not label:
        return _error("label must not be empty.", "Say who the key is for, e.g. label='alice'.")
    if not _LABEL_RE.fullmatch(label):
        return _error(
            "label may only contain letters, digits, space and ._@- (max 64 characters): it is "
            "written into the audit log as the actor, and a label with parentheses or control "
            "characters could impersonate another actor there.",
            "Use a plain name such as 'alice' or 'ci-pipeline'.",
        )
    if expires_in_days is not None and expires_in_days <= 0:
        return _error(
            "expires_in_days must be greater than 0.",
            "Omit it for a key that lasts until revoked; a month is 30, a year 365.",
        )

    from sqlalchemy import select

    async with get_session() as session:
        taken = (
            await session.execute(
                select(ApiKey.id).where(ApiKey.label == label, ApiKey.revoked_at.is_(None))
            )
        ).first()
    if taken is not None:
        return _error(
            f"An active API key labelled {label!r} already exists. Labels identify the actor in "
            "the audit log, so they must be unique among non-revoked keys.",
            "Pick another label, or revoke the existing key first (api_key_list shows its id; "
            "api_key_revoke removes it).",
        )

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
            "Save this token now: it cannot be retrieved again. If it is lost, revoke this key "
            "and create a new one. The holder sends it as `Authorization: Bearer <token>`."
        ),
    }


@mcp.tool(auth=require_role("admin"), **hints("api_key_revoke"))
async def api_key_revoke(key_id: int) -> dict[str, Any]:
    """Take a person's or automation's login away.

    Use it for "revoke alice's key". It stops working within 30 seconds, no restart. Keys set in the server's own environment (MCP_AUTH_TOKEN/MCP_AUTH_TOKENS) are not listed and cannot be revoked here.

    Args:
        key_id: The key's id, from api_key_list (or api_key_create).
    """
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(select(ApiKey).where(ApiKey.id == key_id))
        key = result.scalar_one_or_none()
        if not key:
            return _error(
                f"No API key with id={key_id}.",
                "Call api_key_list (it shows each key's id and label).",
            )
        if key.revoked_at is not None:
            return _error(
                f"API key {key_id} ('{key.label}') was already revoked at "
                f"{key.revoked_at.isoformat()}.",
                "Nothing to do; api_key_list(include_revoked=true) shows the history.",
            )
        key.revoked_at = datetime.now(UTC)
        label = key.label

    invalidate_api_key_cache()
    await record_action("api_key_revoke", f"revoked {label}'s API key", target=label)
    return {
        "id": key_id,
        "label": label,
        "status": "revoked",
        "note": "The key stops working within 30 seconds.",
    }


@mcp.tool(auth=require_role("admin"), **hints("api_key_list"))
async def api_key_list(include_revoked: bool = False) -> dict[str, Any]:
    """Who has a login to this server, and with what role?

    Use it for "who has access?", "which keys expire soon?". Shows labels, roles and dates only, never tokens.

    Args:
        include_revoked: Also show revoked keys, for the history of who ever had access.
    """
    from sqlalchemy import func, select

    q = select(ApiKey)
    if not include_revoked:
        q = q.where(ApiKey.revoked_at.is_(None))

    async with get_session() as session:
        found = (await session.execute(q.order_by(ApiKey.created_at.desc()))).scalars().all()

    now = datetime.now(UTC)
    rows = [
        {
            "id": r.id,
            "label": r.label,
            "role": r.role,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "expired": bool(r.expires_at and r.expires_at <= now),
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
        }
        for r in found
    ]
    note = (
        f"{len(rows)} key(s). Keys configured through MCP_AUTH_TOKEN(S) in the server's "
        "environment are not listed here."
    )
    if not rows:
        async with get_session() as session:
            revoked = (
                await session.execute(select(func.count()).where(ApiKey.revoked_at.is_not(None)))
            ).scalar_one()
        note = (
            f"No active API keys ({revoked} revoked; include_revoked shows them). Make one with "
            "api_key_create(label=...)."
            if revoked
            else "No API keys have been created. Make one with api_key_create(label=...)."
        )
    return {"count": len(rows), "keys": rows, "note": note}
