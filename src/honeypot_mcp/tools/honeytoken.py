"""Honeytoken management MCP tools."""

from __future__ import annotations

import json
from typing import Any, Literal

from sqlalchemy.exc import IntegrityError

from honeypot_mcp.rbac import require_role, role_at_least
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType
from honeypot_mcp.tokens import get_provider
from honeypot_mcp.tool_hints import hints
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


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_create"))
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
    """Create a honeytoken: a fake credential, key, link or document that raises a CRITICAL alert
    the moment anyone uses it. `type` selects the kind (canary_url, file, credential, ssh_key,
    api_key, jwt, db_row, kubeconfig, slack_webhook, azure_credential, gcp_service_account).
    Afterwards call `honeytoken_export` for planting instructions. A token only fires when the
    attacker uses it where this deployment can see it: a canary URL being fetched, a planted
    credential being tried against one of your honeypots, or (cloud keys) a forwarder you set up.
    Prefer `honeytoken_generate_credentials` / `honeytoken_generate_aws` for those common cases.

    Args:
        type: Token type. Options:
              - api_key: AWS credentials. Generated ones are lookalikes that leave no CloudTrail
                trail; pass a real decoy IAM user's access_key_id + secret_access_key in
                `metadata` to adopt it (see examples/cloud-forwarders/aws)
              - canary_url: unique URL that fires on HTTP GET
              - credential: fake username/password pair (auto-matched on any honeypot)
              - file: PDF/DOCX with embedded tracker
              - ssh_key: planted SSH private key (fingerprint match on SSH auth)
              - jwt: signed JWT (jti match on HTTP Authorization header)
              - db_row: canary database row with unique email (match on SMTP RCPT TO)
              - kubeconfig: cluster credentials for a decoy API server
              - slack_webhook: incoming-webhook URL that fires when posted to
              - azure_credential: service-principal client id/secret pair (adopt a real decoy
                with metadata client_id, client_secret, tenant_id)
              - gcp_service_account: service-account JSON key (adopt a real decoy key with
                metadata service_account_json)
        label: Human-readable label to identify this token (e.g. 'prod-server .env backup').
        metadata: Optional type-specific settings (e.g. {'service': 'aws', 'region': 'us-east-1'}).
        planted_at: Where this token is being placed — "the finance file share",
                    "wiki page IT-114", "~/.aws/credentials on the build server".
                    Strongly recommended. When a token fires months later the
                    alert says *which* token, and this is what says which system
                    the attacker actually reached; without it a CRITICAL arrives
                    with no location and triage starts from nothing.
    """
    try:
        created = await _create_token(type, label, metadata, planted_at)
    except ValueError as e:
        return {"error": str(e)}
    except IntegrityError:
        # Deliberately not the driver's message: it quotes the bound parameters, i.e. the secret.
        return {"error": "A honeytoken with this value already exists."}
    await _audit_creation("honeytoken_create", created, metadata, planted_at)
    return created


async def _audit_creation(
    tool: str,
    created: dict[str, Any],
    metadata: dict[str, Any] | None,
    planted_at: str | None,
) -> None:
    """Record a token creation. The secret itself never reaches the log; the
    metadata is recorded by key only, since provider settings can carry
    planted passwords under names the redactor would not recognise."""
    await record_action(
        tool,
        summary=f"created {created['type']} honeytoken {created['id']} ('{created['label']}')",
        arguments={
            "type": created["type"],
            "label": created["label"],
            "planted_at": planted_at,
            "metadata_keys": sorted((metadata or {}).keys()),
        },
        target=str(created["id"]),
    )


# Inputs consumed by a provider that must not be kept as given.
_NEVER_STORE = {"service_account_json"}


def _cloud_identifiers(meta: dict[str, Any]) -> set[str]:
    """The names a cloud audit-log event can carry for a token. Matching is by these across
    all three clouds in one index, so two tokens sharing one (or a GCP key id equal to an AWS
    key id) would shadow each other."""
    found = {
        str(meta[k]).lower()
        for k in ("access_key_id", "client_id", "client_email", "private_key_id")
        if isinstance(meta.get(k), str | int) and meta.get(k)
    }
    return found


async def _refuse_duplicate_identity(extra_meta: dict[str, Any]) -> None:
    """Raise ValueError if another live cloud token already answers to the same identifier."""
    wanted = _cloud_identifiers(extra_meta)
    if not wanted:
        return
    from sqlalchemy import select

    async with get_session() as session:
        rows = (
            await session.execute(
                select(Honeytoken).where(
                    Honeytoken.type.in_(
                        [
                            HoneytokenType.API_KEY,
                            HoneytokenType.AZURE_CREDENTIAL,
                            HoneytokenType.GCP_SERVICE_ACCOUNT,
                        ]
                    ),
                    Honeytoken.status != HoneytokenStatus.REVOKED,
                )
            )
        ).scalars()
        for existing in rows:
            if wanted & _cloud_identifiers(existing.token_meta or {}):
                raise ValueError(
                    f"That cloud identity is already registered as honeytoken {existing.id}."
                )


async def _create_token(
    type: str,
    label: str,
    metadata: dict[str, Any] | None,
    planted_at: str | None,
) -> dict[str, Any]:
    """Create and persist a token. Unaudited — every caller records its own action."""
    provider = get_provider(HoneytokenType(type))
    token_value, extra_meta = await provider.create(metadata or {})
    await _refuse_duplicate_identity(extra_meta)

    # What the operator passed in is not stored verbatim: a service-account key file would
    # be kept a second time, private key and all, next to the parsed fields extracted from it.
    supplied = {k: v for k, v in (metadata or {}).items() if k not in _NEVER_STORE}

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType(type),
            label=label,
            token_value=token_value,
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                **supplied,
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
            **supplied,
            **extra_meta,
            **({"planted_at": planted_at} if planted_at else {}),
        },
        "plant_instructions": provider.plant_instructions(token_value, {**supplied, **extra_meta}),
    }


@mcp.tool(**hints("honeytoken_list"))
async def honeytoken_list(
    status: Literal["active", "triggered", "revoked"] | None = None,
) -> list[dict[str, Any]]:
    """List honeytokens with their type, label and status (active, triggered, revoked), optionally
    filtered by status. Use `honeytoken_status` for who triggered one and when.

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


@mcp.tool(**hints("honeytoken_status"))
async def honeytoken_status(token_id: int) -> dict[str, Any]:
    """Details for one honeytoken: its type, label, status and trigger history (which attacker IP
    used it, when, and through what).

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

    token_value = token.token_value
    metadata: dict[str, Any] | None = token.token_meta
    if not role_at_least("operator"):
        # A viewer can see that a token exists and whether it fired, but not
        # the planted secret: the viewer tier is read-only and a full value
        # here would let it plant (or burn) the credential itself.
        token_value = f"{token_value[:4]}…" if token_value else token_value
        metadata = {"redacted": True}

    return {
        "id": token.id,
        "type": token.type.value,
        "label": token.label,
        "token_value": token_value,
        "status": token.status.value,
        "metadata": metadata,
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


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_rotate"))
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
    if old_meta.get("adopted"):
        return {
            "error": (
                f"Honeytoken {token_id} is a real identity from your cloud account, so it "
                "cannot be rotated here: a generated replacement would not exist in the cloud "
                "and would silently stop detecting. Issue a new key in the cloud, create a new "
                "token from it, then revoke this one."
            )
        }

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
        "client_id",
        "client_secret",
        "tenant_id",
        "subscription_id",
        "client_email",
        "private_key_id",
        "adopted",
        "private_key",
        "public_key",
        "fingerprint",
        "jti",
        "token",
        "rotated_from",
        "rotated_to",
        "planted_at",
        # Trigger history belongs to the old secret; the new token starts clean.
        "triggers",
    }
    carried = {k: v for k, v in old_meta.items() if k not in _GENERATED}

    created = await _create_token(
        type=old_type.value,
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


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_revoke"))
async def honeytoken_revoke(token_id: int) -> dict[str, Any]:
    """Deactivate a honeytoken so it no longer alerts. There is no un-revoke: create a new token
    (or use `honeytoken_rotate`, which keeps the history and issues a fresh secret) if you still want one.

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


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_generate_aws"))
async def honeytoken_generate_aws(
    label: str,
    region: str = "us-east-1",
    service_prefix: str = "AKIA",
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
) -> dict[str, Any]:
    """Create an AWS access-key honeytoken. With no key given it is a lookalike that does NOT
    exist in AWS, so using it leaves no CloudTrail event: it is only bait for scanners that grep
    for AKIA strings. For real detection create a decoy IAM user (Terraform in
    `examples/cloud-forwarders/aws/terraform/decoy_user.tf`), deploy the forwarder, and pass that
    user's `access_key_id` and `secret_access_key` here: its use is then logged by CloudTrail,
    forwarded, and raises a CRITICAL alert with the attacker's source IP.

    Args:
        label: Human-readable label (e.g. 'leaked-in-github-repo').
        region: AWS region to embed in the credentials file.
        service_prefix: AKIA (long-term) or ASIA (temporary); ignored when adopting a key.
        access_key_id: A real decoy user's access key ID (adopt it instead of generating one).
        secret_access_key: The matching secret. Required with access_key_id.
    """
    metadata: dict[str, Any] = {"service": "aws", "region": region, "prefix": service_prefix}
    if access_key_id is not None or secret_access_key is not None:
        metadata["access_key_id"] = access_key_id
        metadata["secret_access_key"] = secret_access_key
    try:
        created = await _create_token("api_key", label, metadata, None)
    except ValueError as e:
        return {"error": str(e)}
    except IntegrityError:
        # Deliberately not the driver's message: it quotes the bound parameters, i.e. the secret.
        return {"error": "A honeytoken with this value already exists."}
    await _audit_creation("honeytoken_generate_aws", created, metadata, None)
    return created


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_generate_credentials"))
async def honeytoken_generate_credentials(
    label: str,
    count: int = 5,
    service: str = "ssh",
) -> dict[str, Any]:
    """Generate believable fake username/password pairs for a service (ssh, ftp, http, smtp, rdp, ...)
    and store them as honeytokens. They fire when an attacker tries them against one of your own
    honeypots for that service, with a CRITICAL alert naming the token. Returned once: plant them.

    Args:
        label: Label for this credential set.
        count: Number of credential pairs to generate (default 5).
        service: Target service context (ssh, mysql, ftp, admin).
    """
    metadata: dict[str, Any] = {"service": service, "count": count}
    created = await _create_token("credential", label, metadata, None)
    await _audit_creation("honeytoken_generate_credentials", created, metadata, None)
    return created


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_embed_file"))
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
    metadata: dict[str, Any] = {"file_type": file_type, "document_title": document_title}
    created = await _create_token("file", label, metadata, None)
    await _audit_creation("honeytoken_embed_file", created, metadata, None)
    return created


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_export"))
async def honeytoken_export(
    token_id: int, context: Literal["env_file", "aws_credentials", "bash", "json"] = "json"
) -> str:
    """Format an existing honeytoken for planting in a given context (env file, config snippet,
    authorized_keys, ...). The output contains the secret value, so treat it as sensitive.

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
