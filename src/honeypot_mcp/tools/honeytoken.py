"""Honeytoken management MCP tools."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from honeypot_mcp.rbac import require_role, role_at_least
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import (
    AttackerEvent,
    Honeytoken,
    HoneytokenStatus,
    HoneytokenType,
)
from honeypot_mcp.tokens import get_provider
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import digest_payload, mark_untrusted
from honeypot_mcp.tools._labels import label_matches, label_words
from honeypot_mcp.tools._planted import Planted, load_planted


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
    label: str | None = None,
    metadata: dict[str, Any] | None = None,
    planted_at: str | None = None,
) -> dict[str, Any]:
    """Create a honeytoken: a fake credential, key, link or document that raises a CRITICAL alert
    when someone uses it. Returns the secret once, with instructions for planting it.

    Use it for "make me a fake AWS key / SSH key / passwords / Kubernetes config / canary link / PDF".
    It only fires where this server can see it used (a canary URL fetched, a credential tried on
    its honeypots, a cloud key through a forwarder).

    Args:
        type: What to create: api_key (AWS-style), canary_url (fires when fetched), credential
            (username/password), file (PDF/DOCX), ssh_key, jwt, db_row (canary e-mail), or a cloud
            type.
        label: A name the user will recognise ("backup server .env"). Defaults to the type.
        metadata: Type-specific settings, normally omitted. api_key: region, plus access_key_id +
            secret_access_key of a real decoy IAM user to adopt (CloudTrail then logs its use; a
            generated lookalike leaves no trace). credential: count 1-20 (default 5), service
            (default ssh; any honeypot service, or any). file: file_type pdf|docx, document_title.
            azure_credential: client_id, client_secret, tenant_id; gcp_service_account:
            service_account_json.
        planted_at: Where it is placed ("finance share", "~/.aws/credentials on the build server");
            when it fires, this says which system was reached.
    """
    try:
        metadata = _prepare_metadata(type, metadata)
        label = _label(label, _default_label(type, metadata))
        created = await _create_token(type, label, metadata, planted_at)
    except ValueError as e:
        return {"error": str(e), "hint": _METADATA_HINTS.get(type, _GENERIC_HINT.format(type=type))}
    except IntegrityError:
        # Deliberately not the driver's message: it quotes the bound parameters, i.e. the secret.
        return {
            "error": "A honeytoken with this value already exists.",
            "hint": "Leave `metadata` out so a fresh value is generated, or use honeytoken_list to "
            "find the existing token.",
        }
    await _audit_creation("honeytoken_create", created, metadata, planted_at)
    return created


_GENERIC_HINT = "Check `metadata` for type '{type}', or leave it out to have the values generated."
_METADATA_HINTS = {
    "api_key": "To adopt a real decoy key give both access_key_id (AKIA/ASIA + 16 characters) "
    "and secret_access_key (40 characters); leave both out to generate a lookalike.",
    "credential": "Pick the service of the honeypot they should catch; count is 1 to 20.",
    "file": "file_type is pdf or docx.",
}


def _prepare_metadata(type: str, metadata: dict[str, Any] | None) -> dict[str, Any] | None:
    """Apply the per-type defaults and bounds; raise ValueError on a value that makes a dead token."""
    if type == "credential":
        out = dict(metadata or {})
        out["service"] = str(out.get("service") or "ssh").strip().lower()
        count = out.setdefault("count", 5)
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 20:
            raise ValueError(f"count must be between 1 and 20, got {count!r}.")
        return out
    if type == "api_key":
        out = dict(metadata or {})
        out.setdefault("service", "aws")
        if out["service"] == "aws":
            out.setdefault("region", "us-east-1")
        return out
    if type == "file":
        out = dict(metadata or {})
        out.setdefault("file_type", "pdf")
        out.setdefault("document_title", "Confidential Report")
        if out["file_type"] not in ("pdf", "docx"):
            raise ValueError(f"file_type must be pdf or docx, got {out['file_type']!r}.")
        return out
    return metadata


def _default_label(type: str, metadata: dict[str, Any] | None) -> str:
    """The label used when the caller gives none."""
    meta = metadata or {}
    if type == "api_key" and meta.get("service") == "aws":
        return "AWS key"
    if type == "credential":
        return f"{meta.get('service', 'ssh')} credentials"
    if type == "file":
        return f"{meta.get('file_type', 'pdf')} document"
    return type


def _label(label: str | None, kind: str) -> str:
    """The label given, or one made from what is being created."""
    return label.strip() if label and label.strip() else kind.replace("_", " ")


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
    if type == "credential":
        _check_credential_service((metadata or {}).get("service", "ssh"))
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


_LIST_ROWS = 40
_TRAIL_ROWS = 10
# A trigger is recorded when the token's alert is flushed, a moment after the event's own time.
_TRAIL_BEFORE = timedelta(seconds=120)
_TRAIL_AFTER = timedelta(seconds=10)


def _check_credential_service(service: Any) -> None:
    """Raise ValueError unless `service` is one a planted credential can be matched on: any other
    value makes a token that no honeypot will ever recognise, and nothing says so."""
    from honeypot_mcp.credential_match import _SERVICE_PREFIXES

    valid = sorted({*_SERVICE_PREFIXES.values(), "any"})
    if service not in valid:
        raise ValueError(
            f"Unknown service {service!r}: a credential for it would never match a login. "
            f"Use one of: {', '.join(valid)}."
        )


@mcp.tool(**hints("honeytoken_list"))
async def honeytoken_list(
    status: Literal["active", "triggered", "revoked"] | None = None,
    label: str | None = None,
    token_id: int | None = None,
) -> dict[str, Any]:
    """List the honeytokens: id, type, label, where planted and whether each has fired. One token,
    picked by id or name, comes back in full with its trail (which address used it, when, and
    through which service).

    Use it for "what bait have I planted?", "which tokens fired?", "has the backup server token
    fired?" or "who used token 21?".

    Args:
        status: Only active, triggered (fired) or revoked tokens; leave out for all.
        label: Part of a token's name, when the user names it (case-insensitive).
        token_id: One token's id: returns that token in full with its trail.
    """
    ht_status = HoneytokenStatus(status) if status else None
    async with get_session() as session:
        if token_id is not None:
            tokens = list(
                (
                    await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
                ).scalars()
            )
            if ht_status is not None:
                tokens = [t for t in tokens if t.status is ht_status]
        else:
            tokens = await queries.list_honeytokens(session, status=ht_status)
    wanted = (label or "").strip().lower()
    if wanted:
        words = label_words(wanted)
        tokens = [t for t in tokens if label_matches(t.label, t.type.value, words)]

    if token_id is not None and not tokens:
        return {
            "error": f"No honeytoken with id={token_id}.",
            "hint": "honeytoken_list without an id shows every token's id and label.",
        }
    if len(tokens) == 1 and (token_id is not None or wanted):
        return await _token_detail(tokens[0])

    by_status = Counter(t.status.value for t in tokens)
    # Live bait first (fired, then waiting), retired tokens last; newest first within each.
    rank = {HoneytokenStatus.TRIGGERED: 0, HoneytokenStatus.ACTIVE: 1, HoneytokenStatus.REVOKED: 2}
    tokens = sorted(tokens, key=lambda t: rank[t.status])
    shown = tokens[:_LIST_ROWS]
    notes = []
    if not tokens:
        notes.append(
            "No honeytokens match."
            if (status or wanted)
            else "No honeytokens yet. honeytoken_create plants one."
        )
    if len(tokens) > len(shown):
        notes.append(
            f"Showing {len(shown)} of {len(tokens)} (triggered, then active, then revoked; newest "
            "first); ask for only active, triggered or revoked tokens, or name one, to narrow it."
        )
    elif len(tokens) > 1 and wanted:
        notes.append("Several honeytokens match; ask about one by token_id for its trail.")
    return {
        "count": len(shown),
        "total": len(tokens),
        "by_status": dict(by_status),
        "tokens": [
            {
                "id": t.id,
                "type": t.type.value,
                "label": t.label,
                "status": t.status.value,
                "planted_at": (t.token_meta or {}).get("planted_at"),
                "created_at": t.created_at.isoformat() if t.created_at else None,
                "triggered_at": t.triggered_at.isoformat() if t.triggered_at else None,
            }
            for t in shown
        ],
        "note": " ".join(notes) or None,
    }


async def _trail(token_id: int, triggers: list[Any], triggered_at: datetime | None) -> list[Any]:
    """The newest events linked to a token, found around its recorded triggers.

    `attacker_events.honeytoken_id` has no index, and an older database still holds a copy of
    every event ever captured there (millions of rows), so filtering on it alone reads the whole
    table. Each trigger carries the time it fired, and `timestamp` is indexed, so only a narrow
    window around each of the newest triggers is read."""
    moments: list[datetime] = []
    for entry in reversed(triggers):
        at = entry.get("at") if isinstance(entry, dict) else None
        try:
            moments.append(datetime.fromisoformat(str(at)))
        except ValueError:
            continue
        if len(moments) == _TRAIL_ROWS:
            break
    if not moments and triggered_at is not None:
        moments.append(triggered_at)
    found: dict[int, AttackerEvent] = {}
    async with get_session() as session:
        for moment in moments:
            moment = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
            rows = (
                await session.execute(
                    select(AttackerEvent).where(
                        AttackerEvent.honeytoken_id == token_id,
                        AttackerEvent.timestamp >= moment - _TRAIL_BEFORE,
                        AttackerEvent.timestamp <= moment + _TRAIL_AFTER,
                    )
                )
            ).scalars()
            found.update({e.id: e for e in rows})
    newest = sorted(found.values(), key=lambda e: e.timestamp, reverse=True)
    return newest[:_TRAIL_ROWS]


async def _token_detail(token: Honeytoken) -> dict[str, Any]:
    """One token in full: its value (masked for viewers), metadata and the trail of its uses."""

    meta = dict(token.token_meta or {})
    triggers = meta.pop("triggers", None)
    triggers = triggers if isinstance(triggers, list) else []
    planted = await load_planted()
    trail = await _trail(token.id, triggers, token.triggered_at)
    if trail:
        trail_out = [
            {
                "at": e.timestamp.isoformat(),
                "source_ip": e.ip,
                "event_type": e.event_type,
                "detail": _redacted(digest_payload(e.extra), planted),
            }
            for e in trail
        ]
    else:
        trail_out = [
            {
                "at": t.get("at"),
                "source_ip": t.get("trigger_ip"),
                "event_type": t.get("trigger_event_type"),
            }
            for t in reversed(triggers[-_TRAIL_ROWS:])
            if isinstance(t, dict)
        ]

    token_value = token.token_value
    metadata: dict[str, Any] | None = meta
    if not role_at_least("operator"):
        # A viewer can see that a token exists and whether it fired, but not
        # the planted secret: the viewer tier is read-only and a full value
        # here would let it plant (or burn) the credential itself.
        token_value = f"{token_value[:4]}…" if token_value else token_value
        metadata = {"redacted": True}

    notes = []
    if token.status is HoneytokenStatus.ACTIVE and not trail_out:
        notes.append("Not triggered: nothing has used this token yet.")
    if len(triggers) >= queries._MAX_TRIGGER_HISTORY:
        notes.append(
            f"The token has fired at least {len(triggers)} times; its record keeps the last "
            f"{queries._MAX_TRIGGER_HISTORY}. bait_trips shows who used it and what they did first."
        )
    return mark_untrusted(
        {
            "id": token.id,
            "type": token.type.value,
            "label": token.label,
            "token_value": token_value,
            "status": token.status.value,
            "metadata": metadata,
            "created_at": token.created_at.isoformat() if token.created_at else None,
            "triggered_at": token.triggered_at.isoformat() if token.triggered_at else None,
            "times_triggered": len(triggers),
            "trail": trail_out,
            "note": " ".join(notes) or None,
        }
    )


def _redacted(value: Any, planted: Planted) -> Any:
    """`value` with every planted secret in its strings masked."""
    if isinstance(value, str):
        return planted.redact(value)
    if isinstance(value, dict):
        return {k: _redacted(v, planted) for k, v in value.items()}
    if isinstance(value, list):
        return [_redacted(v, planted) for v in value]
    return value


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_rotate"))
async def honeytoken_rotate(token_id: int, planted_at: str | None = None) -> dict[str, Any]:
    """Replace a honeytoken with a fresh secret, keeping its label, type and history.

    Use it for "rotate the bait credential" or "that token fired, issue a new one". The old token
    is revoked but kept, so past triggers still resolve to it, and the two are linked
    (`rotated_from` / `rotated_to`). The planted copy has to be replaced with the new secret;
    `plant_instructions` in the response says how.

    Args:
        token_id: The honeytoken to rotate (honeytoken_list shows ids).
        planted_at: New location if it is moving; defaults to the old one.
    """
    async with get_session() as session:
        old = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one_or_none()
        if old is None:
            return {
                "error": f"No honeytoken with id={token_id}.",
                "hint": "honeytoken_list shows every token's id and label.",
            }
        if old.status is HoneytokenStatus.REVOKED:
            return {
                "error": f"Honeytoken {token_id} is already revoked.",
                "hint": "Create a new one with honeytoken_create, or rotate the token that "
                "replaced it (honeytoken_list with its token_id shows `rotated_to`).",
            }
        old_type = old.type
        old_label = old.label
        old_meta = dict(old.token_meta or {})
    if old_meta.get("adopted"):
        return {
            "error": (
                f"Honeytoken {token_id} is a real identity from your cloud account, so it "
                "cannot be rotated here: a generated replacement would not exist in the cloud "
                "and would silently stop detecting."
            ),
            "hint": "Issue a new key in the cloud, create a token from it with honeytoken_create "
            "(metadata = the new keys), then honeytoken_revoke this one.",
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

    try:
        created = await _create_token(
            type=old_type.value,
            label=old_label,
            metadata=carried,
            planted_at=planted_at or old_meta.get("planted_at"),
        )
    except ValueError as e:
        return {"error": str(e), "hint": "Create a replacement with honeytoken_create instead."}

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
    """Stop a honeytoken from alerting. It cannot be undone, but the token and its history stay.

    Use it for "retire the bait credential" or "that token leaked, turn it off". To keep watching
    with a fresh secret, use `honeytoken_rotate` instead.

    Args:
        token_id: The honeytoken to revoke (honeytoken_list shows ids and labels).
    """
    async with get_session() as session:
        token = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one_or_none()
        if token is None:
            return {
                "error": f"No honeytoken with id={token_id}.",
                "hint": "honeytoken_list shows every token's id and label.",
            }
        if token.status is HoneytokenStatus.REVOKED:
            return {
                "token_id": token_id,
                "status": "revoked",
                "note": "It was already revoked; nothing changed.",
            }
        token.status = HoneytokenStatus.REVOKED

    _invalidate_matcher_caches()

    await record_action(
        "honeytoken_revoke",
        summary=f"revoked honeytoken id={token_id} — it will no longer match",
        arguments={"token_id": token_id},
        target=str(token_id),
    )
    return {
        "token_id": token_id,
        "status": "revoked",
        "note": "It will no longer match or alert. honeytoken_rotate issues a fresh replacement.",
    }


@mcp.tool(auth=require_role("operator"), **hints("honeytoken_export"))
async def honeytoken_export(
    token_id: int, context: Literal["env_file", "aws_credentials", "bash", "json"] = "json"
) -> dict[str, Any]:
    """Format an existing honeytoken for planting: the text to paste into a file, plus where to put it.

    Use it for "give me that key as a .env file" or "as ~/.aws/credentials". The result contains
    the secret, so treat it as sensitive.

    Args:
        token_id: The honeytoken to export (honeytoken_list shows ids).
        context: env_file (.env lines), aws_credentials (~/.aws/credentials), bash (export
            statements) or json (default). The first three apply to AWS keys only.
    """
    async with get_session() as session:
        token = (
            await session.execute(select(Honeytoken).where(Honeytoken.id == token_id))
        ).scalar_one_or_none()
    if token is None:
        return {
            "error": f"No honeytoken with id={token_id}.",
            "hint": "honeytoken_list shows every token's id and label.",
        }
    if token.status is HoneytokenStatus.REVOKED:
        return {
            "error": f"Honeytoken {token_id} is revoked: planting it would catch nothing.",
            "hint": "honeytoken_create makes a new one, or find its replacement with "
            "honeytoken_list with its token_id (`rotated_to`).",
        }

    meta = token.token_meta or {}
    val = token.token_value
    note = "Contains the secret; keep it out of logs and chat history."
    content: str | None = None
    if token.type == HoneytokenType.API_KEY and meta.get("service") == "aws":
        key_id = meta.get("access_key_id", val[:20])
        secret = meta.get("secret_access_key", val[20:])
        region = meta.get("region", "us-east-1")
        if context == "aws_credentials":
            content = (
                f"[default]\naws_access_key_id = {key_id}\n"
                f"aws_secret_access_key = {secret}\nregion = {region}\n"
            )
        elif context == "env_file":
            content = (
                f"AWS_ACCESS_KEY_ID={key_id}\nAWS_SECRET_ACCESS_KEY={secret}\n"
                f"AWS_DEFAULT_REGION={region}\n"
            )
        elif context == "bash":
            content = (
                f'export AWS_ACCESS_KEY_ID="{key_id}"\nexport AWS_SECRET_ACCESS_KEY="{secret}"\n'
                f'export AWS_DEFAULT_REGION="{region}"\n'
            )
    elif context != "json":
        note += f" `{context}` only applies to AWS keys, so the JSON form is returned."
    if content is None:
        context = "json"
        content = json.dumps(
            {"label": token.label, "type": token.type.value, "value": val, "metadata": meta},
            indent=2,
        )
    provider = get_provider(token.type)
    return {
        "token_id": token.id,
        "label": token.label,
        "type": token.type.value,
        "context": context,
        "content": content,
        "plant_instructions": provider.plant_instructions(val, meta),
        "note": note,
    }
