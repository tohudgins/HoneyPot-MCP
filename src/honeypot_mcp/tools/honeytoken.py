"""Honeytoken management MCP tools."""

from __future__ import annotations

import json
from typing import Any, Literal

from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType
from honeypot_mcp.tokens import get_provider
from honeypot_mcp.tools._audit import record_action


def _invalidate_matcher_caches(token_type: HoneytokenType | None = None) -> None:
    """Drop the in-memory cross-reference caches after a token changes.

    Over-invalidating is deliberate: the caches rebuild lazily on the next
    match attempt, so the cost is negligible, and missing one means a revoked
    token keeps firing or a fresh one silently does not.
    """
    from honeypot_mcp.credential_match import invalidate_cache as invalidate_creds
    from honeypot_mcp.token_matchers import invalidate_cache as invalidate_token_match

    invalidate_creds()
    invalidate_token_match()


@mcp.tool(auth=require_role("operator"))
async def honeytoken_create(
    type: Literal[
        "api_key",
        "canary_url",
        "credential",
        "file",
        "ssh_key",
        "jwt",
        "db_row",
        "kubeconfig",
        "slack_webhook",
        "azure_credential",
        "gcp_service_account",
    ],
    label: str,
    metadata: dict[str, Any] | None = None,
    planted_at: str | None = None,
) -> dict[str, Any]:
    """Create a new honeytoken.

    Args:
        type: Token type. Options:
              - api_key: fake AWS credentials (decoy-only, see KNOWN_LIMITATIONS.md)
              - canary_url: unique URL that fires on HTTP GET
              - credential: fake username/password pair (auto-matched on any honeypot)
              - file: PDF/DOCX with embedded tracker
              - ssh_key: planted SSH private key (fingerprint match on SSH auth)
              - jwt: signed JWT (jti match on HTTP Authorization header)
              - db_row: canary database row with unique email (match on SMTP RCPT TO)
              - kubeconfig: cluster credentials for a decoy API server
              - slack_webhook: incoming-webhook URL that fires when posted to
              - azure_credential: service-principal client id/secret pair
              - gcp_service_account: service-account JSON key
        label: Human-readable label to identify this token (e.g. 'prod-server .env backup').
        metadata: Optional type-specific settings (e.g. {'service': 'aws', 'region': 'us-east-1'}).
        planted_at: Where this token is being placed — "the finance file share",
                    "wiki page IT-114", "~/.aws/credentials on the build server".
                    Strongly recommended. When a token fires months later the
                    alert says *which* token, and this is what says which system
                    the attacker actually reached; without it a CRITICAL arrives
                    with no location and triage starts from nothing.
    """
    provider = get_provider(HoneytokenType(type))
    token_value, extra_meta = await provider.create(metadata or {})

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType(type),
            label=label,
            token_value=token_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                **(metadata or {}),
                **extra_meta,
                **({"planted_at": planted_at} if planted_at else {}),
            },
        )
        session.add(token)
        await session.flush()
        token_id = token.id

    _invalidate_matcher_caches(HoneytokenType(type))

    return {
        "id": token_id,
        "type": type,
        "label": label,
        "token_value": token_value,
        "status": "active",
        "metadata": {
            **(metadata or {}),
            **extra_meta,
            **({"planted_at": planted_at} if planted_at else {}),
        },
        "plant_instructions": provider.plant_instructions(
            token_value, {**(metadata or {}), **extra_meta}
        ),
    }


@mcp.tool
async def honeytoken_list(
    status: Literal["active", "triggered", "revoked"] | None = None,
) -> list[dict[str, Any]]:
    """List all honeytokens, optionally filtered by status.

    Args:
        status: Filter by status (active, triggered, revoked). Omit for all.
    """
    ht_status = HoneytokenStatus(status) if status else None
    async with get_session() as session:
        tokens = await queries.list_honeytokens(session, status=ht_status)

    return [
        {
            "id": t.id,
            "type": t.type.value,
            "label": t.label,
            "status": t.status.value,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
        }
        for t in tokens
    ]


@mcp.tool
async def honeytoken_status(token_id: int) -> dict[str, Any]:
    """Get detailed status and trigger history for a specific honeytoken.

    Args:
        token_id: The numeric honeytoken ID.
    """
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        token = result.scalar_one_or_none()
        if not token:
            return {"error": f"No honeytoken with id={token_id}."}

        from sqlalchemy import select as sa_select

        from honeypot_mcp.storage.models import AttackerEvent

        ev_result = await session.execute(
            sa_select(AttackerEvent)
            .where(AttackerEvent.honeytoken_id == token_id)
            .order_by(AttackerEvent.timestamp.desc())
            .limit(20)
        )
        token_events = list(ev_result.scalars().all())

    return {
        "id": token.id,
        "type": token.type.value,
        "label": token.label,
        "token_value": token.token_value,
        "status": token.status.value,
        "metadata": token.token_meta,
        "created_at": token.created_at.isoformat() if token.created_at else None,
        "triggered_at": token.triggered_at.isoformat() if token.triggered_at else None,
        "trigger_metadata": token.trigger_metadata,
        "trigger_events": [
            {
                "ip": e.ip,
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "extra": e.extra,
            }
            for e in token_events
        ],
    }


@mcp.tool(auth=require_role("operator"))
async def honeytoken_rotate(token_id: int, planted_at: str | None = None) -> dict[str, Any]:
    """Replace a honeytoken with a fresh one, keeping its identity and history.

    Rotation is routine: a token fires and has to be replaced, or a planted
    secret has simply been in place long enough. Doing it as revoke-then-create
    loses the thread — the new token is unrelated to the old one, so "this
    credential has now fired three times over eight months" becomes three
    unconnected incidents, and the old value stops being attributable.

    This keeps both. The old token is marked REVOKED and stays in the database,
    so historical triggers still resolve to it; the new one carries the same
    label, type and metadata and records `rotated_from`, with the old one
    recording `rotated_to`. Where it is planted carries over unless you give a
    new location.

    The new secret is different, so the planted copy has to be replaced
    wherever it lives — `plant_instructions` in the response says how.

    Args:
        token_id: The honeytoken to rotate.
        planted_at: New location, if it is moving. Defaults to the old one.
    """
    from sqlalchemy import select

    from honeypot_mcp.storage.models import Honeytoken

    async with get_session() as session:
        old = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one_or_none()
        if old is None:
            return {"error": f"No honeytoken with id={token_id}."}
        if old.status is HoneytokenStatus.REVOKED:
            return {
                "error": f"Honeytoken {token_id} is already revoked — create a new one instead.",
            }
        old_type = old.type
        old_label = old.label
        old_meta = dict(old.token_meta or {})

    # Anything the provider generated is regenerated; only the operator's
    # own settings carry across, or the "new" token would be the old one.
    _GENERATED = {
        "token_id",
        "token_uid",
        "tracking_url",
        "dns_canary",
        "file_path",
        "url",
        "password",
        "access_key_id",
        "secret_access_key",
        "private_key",
        "public_key",
        "fingerprint",
        "jti",
        "token",
        "rotated_from",
        "rotated_to",
        "planted_at",
    }
    carried = {k: v for k, v in old_meta.items() if k not in _GENERATED}

    created = await honeytoken_create(
        type=old_type.value,  # type: ignore[arg-type]
        label=old_label,
        metadata=carried,
        planted_at=planted_at or old_meta.get("planted_at"),
    )
    if "error" in created:
        return created

    async with get_session() as session:
        new_token = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == created["id"]))
        ).scalar_one()
        new_token.token_meta = {**(new_token.token_meta or {}), "rotated_from": token_id}
        old = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one()
        old.status = HoneytokenStatus.REVOKED
        old.token_meta = {**(old.token_meta or {}), "rotated_to": created["id"]}

    _invalidate_matcher_caches(old_type)

    await record_action(
        "honeytoken_rotate",
        summary=f"rotated honeytoken {token_id} ('{old_label}') into {created['id']}",
        arguments={"token_id": token_id, "planted_at": planted_at},
        target=old_label,
    )
    created["metadata"] = {**created.get("metadata", {}), "rotated_from": token_id}
    return {
        "rotated_from": token_id,
        "new_token": created,
        "note": (
            "The old token is REVOKED but retained, so past triggers still resolve to "
            "it. The secret has changed — replace the planted copy at "
            f"'{planted_at or old_meta.get('planted_at') or 'its recorded location'}'."
        ),
    }


@mcp.tool(auth=require_role("operator"))
async def honeytoken_revoke(token_id: int) -> dict[str, Any]:
    """Deactivate a honeytoken so it no longer triggers alerts.

    Args:
        token_id: The numeric honeytoken ID.
    """
    from sqlalchemy import update

    from honeypot_mcp.storage.models import Honeytoken

    async with get_session() as session:
        result = await session.execute(
            update(Honeytoken)
            .where(Honeytoken.id == token_id)
            .values(status=HoneytokenStatus.REVOKED)
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            return {"error": f"No honeytoken with id={token_id}."}

    _invalidate_matcher_caches()

    await record_action(
        "honeytoken_revoke",
        summary=f"revoked honeytoken id={token_id} — it will no longer match",
        arguments={"token_id": token_id},
        target=str(token_id),
    )
    return {"token_id": token_id, "status": "revoked"}


@mcp.tool(auth=require_role("operator"))
async def honeytoken_generate_aws(
    label: str,
    region: str = "us-east-1",
    service_prefix: str = "AKIA",
) -> dict[str, Any]:
    """Generate a believable fake AWS access key pair and store it as a honeytoken.

    Args:
        label: Human-readable label (e.g. 'leaked-in-github-repo').
        region: Fake AWS region to embed in the credentials file.
        service_prefix: AWS key prefix — AKIA (long-term) or ASIA (temporary).
    """
    return await honeytoken_create(
        type="api_key",
        label=label,
        metadata={"service": "aws", "region": region, "prefix": service_prefix},
    )


@mcp.tool(auth=require_role("operator"))
async def honeytoken_generate_credentials(
    label: str,
    count: int = 5,
    service: str = "ssh",
) -> dict[str, Any]:
    """Generate believable fake username/password pairs as honeytokens.

    Args:
        label: Label for this credential set.
        count: Number of credential pairs to generate (default 5).
        service: Target service context (ssh, mysql, ftp, admin).
    """
    return await honeytoken_create(
        type="credential",
        label=label,
        metadata={"service": service, "count": count},
    )


@mcp.tool(auth=require_role("operator"))
async def honeytoken_embed_file(
    label: str,
    file_type: Literal["pdf", "docx"] = "pdf",
    document_title: str = "Confidential Report",
) -> dict[str, Any]:
    """Create a document (PDF or DOCX) with an embedded tracking token.
    The document phones home via a DNS request when opened.

    Args:
        label: Label for this file token.
        file_type: Document format — pdf or docx.
        document_title: Title shown in the document.
    """
    return await honeytoken_create(
        type="file",
        label=label,
        metadata={"file_type": file_type, "document_title": document_title},
    )


@mcp.tool(auth=require_role("operator"))
async def honeytoken_export(
    token_id: int, context: Literal["env_file", "aws_credentials", "bash", "json"] = "json"
) -> str:
    """Export a honeytoken formatted for planting in a specific context.

    Args:
        token_id: The honeytoken ID to export.
        context: Output format — env_file (.env format), aws_credentials (~/.aws/credentials),
                 bash (export statements), or json (raw JSON).
    """
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        token = result.scalar_one_or_none()
        if not token:
            return f"Error: No honeytoken with id={token_id}."

    meta = token.token_meta or {}
    val = token.token_value

    if context == "json":
        return json.dumps(
            {"label": token.label, "type": token.type.value, "value": val, "metadata": meta},
            indent=2,
        )

    if token.type == HoneytokenType.API_KEY and meta.get("service") == "aws":
        key_id = meta.get("access_key_id", val[:20])
        secret = meta.get("secret_access_key", val[20:])
        region = meta.get("region", "us-east-1")

        if context == "aws_credentials":
            return f"[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\nregion = {region}\n"
        if context == "env_file":
            return f"AWS_ACCESS_KEY_ID={key_id}\nAWS_SECRET_ACCESS_KEY={secret}\nAWS_DEFAULT_REGION={region}\n"
        if context == "bash":
            return f'export AWS_ACCESS_KEY_ID="{key_id}"\nexport AWS_SECRET_ACCESS_KEY="{secret}"\nexport AWS_DEFAULT_REGION="{region}"\n'

    return json.dumps({"label": token.label, "type": token.type.value, "value": val}, indent=2)
