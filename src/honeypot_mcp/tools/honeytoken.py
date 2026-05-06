"""Honeytoken management MCP tools."""

from __future__ import annotations

import json
from typing import Any, Literal

from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType
from honeypot_mcp.tokens import get_provider


@mcp.tool
async def honeytoken_create(
    type: Literal["api_key", "canary_url", "credential", "file"],
    label: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a new honeytoken.

    Args:
        type: Token type — api_key (fake AWS credentials), canary_url (tracking URL),
              credential (fake username/password), or file (document with embedded tracker).
        label: Human-readable label to identify this token (e.g. 'prod-server .env backup').
        metadata: Optional type-specific settings (e.g. {'service': 'aws', 'region': 'us-east-1'}).
    """
    provider = get_provider(HoneytokenType(type))
    token_value, extra_meta = await provider.create(metadata or {})

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType(type),
            label=label,
            token_value=token_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta={**(metadata or {}), **extra_meta},
        )
        session.add(token)
        await session.flush()
        token_id = token.id

    return {
        "id": token_id,
        "type": type,
        "label": label,
        "token_value": token_value,
        "status": "active",
        "metadata": {**(metadata or {}), **extra_meta},
        "plant_instructions": provider.plant_instructions(token_value, {**(metadata or {}), **extra_meta}),
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
        result = await session.execute(
            select(Honeytoken).where(Honeytoken.id == token_id)
        )
        token = result.scalar_one_or_none()
        if not token:
            return {"error": f"No honeytoken with id={token_id}."}

        events = await queries.get_events_for_ip(session, "", limit=0)  # placeholder
        # Get events tied to this token
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


@mcp.tool
async def honeytoken_revoke(token_id: int) -> dict[str, Any]:
    """Deactivate a honeytoken so it no longer triggers alerts.

    Args:
        token_id: The numeric honeytoken ID.
    """
    from sqlalchemy import select, update
    from honeypot_mcp.storage.models import Honeytoken

    async with get_session() as session:
        result = await session.execute(
            update(Honeytoken)
            .where(Honeytoken.id == token_id)
            .values(status=HoneytokenStatus.REVOKED)
        )
        if result.rowcount == 0:
            return {"error": f"No honeytoken with id={token_id}."}

    return {"token_id": token_id, "status": "revoked"}


@mcp.tool
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


@mcp.tool
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


@mcp.tool
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


@mcp.tool
async def honeytoken_export(token_id: int, context: Literal["env_file", "aws_credentials", "bash", "json"] = "json") -> str:
    """Export a honeytoken formatted for planting in a specific context.

    Args:
        token_id: The honeytoken ID to export.
        context: Output format — env_file (.env format), aws_credentials (~/.aws/credentials),
                 bash (export statements), or json (raw JSON).
    """
    from sqlalchemy import select

    async with get_session() as session:
        result = await session.execute(
            select(Honeytoken).where(Honeytoken.id == token_id)
        )
        token = result.scalar_one_or_none()
        if not token:
            return f"Error: No honeytoken with id={token_id}."

    meta = token.token_meta or {}
    val = token.token_value

    if context == "json":
        return json.dumps({"label": token.label, "type": token.type.value, "value": val, "metadata": meta}, indent=2)

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
