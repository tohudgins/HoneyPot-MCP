"""Credential honeytoken cross-reference.

When an engine submits a login attempt whose `username` + `password` matches
an active CREDENTIAL honeytoken, this module returns the token's id so the
event buffer can escalate severity to CRITICAL and link the alert back to
the originating token.

Cache pattern mirrors `suppression.py`: an in-memory dict keyed by
`(service, username_lower, password)` refreshed every `CRED_REFRESH_SECONDS`,
plus explicit `invalidate_cache()` from the honeytoken MCP tools when tokens
are created or revoked.

Service inference is event-type driven (see `_infer_service`). Token `service`
of `"any"` matches any service — useful when planting a single fake credential
pair across multiple decoy surfaces.
"""

from __future__ import annotations

import base64
import logging
import time
from typing import TYPE_CHECKING

from sqlalchemy import select

from honeypot_mcp.credential_verify import verify_mysql, verify_vnc
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

if TYPE_CHECKING:
    from honeypot_mcp.storage.event_buffer import PendingEvent

log = logging.getLogger(__name__)

CRED_REFRESH_SECONDS = 30

# Services whose login events never carry the plaintext password. They can't
# be matched by exact (service, user, pass) lookup — the engine captures a
# salted digest instead, verified against candidate passwords in
# `credential_verify`. See `_match_hashed`.
_HASHED_SERVICES = {"mysql", "vnc"}

# (service, username_lower, password) → token_id
# Usernames are lowercased on insert AND lookup; passwords stay case-sensitive.
_index: dict[tuple[str, str, str], int] = {}
# service → [(username_lower, password, token_id)] — the candidate list the
# hashed-service verifier iterates. Built alongside `_index`; requires only a
# non-empty password (VNC has no username), so it's a looser superset.
_candidates: dict[str, list[tuple[str, str, int]]] = {}
_loaded_at: float = 0.0


def invalidate_cache() -> None:
    """Force the next match() call to reload tokens from the DB."""
    global _loaded_at
    _loaded_at = 0.0


async def _load_index() -> None:
    global _index, _candidates, _loaded_at
    now = time.monotonic()
    if now - _loaded_at < CRED_REFRESH_SECONDS:
        return

    async with get_session() as session:
        result = await session.execute(
            select(Honeytoken).where(
                Honeytoken.status == HoneytokenStatus.ACTIVE,
                Honeytoken.type == HoneytokenType.CREDENTIAL,
            )
        )
        tokens = list(result.scalars().all())

    new_index: dict[tuple[str, str, str], int] = {}
    new_candidates: dict[str, list[tuple[str, str, int]]] = {}
    for t in tokens:
        meta = t.token_meta or {}
        service = (meta.get("service") or "any").lower()
        for pair in meta.get("credentials") or []:
            u = (pair.get("username") or "").strip().lower()
            p = pair.get("password") or ""
            if not p:
                continue
            if u:
                new_index[(service, u, p)] = t.id
            new_candidates.setdefault(service, []).append((u, p, t.id))

    _index = new_index
    _candidates = new_candidates
    _loaded_at = now


# Event-type prefix → service label the operator picked when planting the
# credential. `mysql_` / `vnc_` route through the hashed-verification path
# (see `_HASHED_SERVICES`) rather than the plaintext index.
_SERVICE_PREFIXES = {
    "ssh_": "ssh",
    "telnet_": "telnet",
    "http_": "http",
    "ftp_": "ftp",
    "smtp_": "smtp",
    "postgresql_": "postgresql",
    "mssql_": "mssql",
    "redis_": "redis",
    "mysql_": "mysql",
    "vnc_": "vnc",
}


def _infer_service(event_type: str) -> str:
    """Map an event_type back to the service label the operator picked when
    planting the credential (matches `_USERNAMES`-era choices in CredentialProvider)."""
    et = event_type.lower()
    for prefix, service in _SERVICE_PREFIXES.items():
        if et.startswith(prefix):
            return service
    return "any"


def _extract_pairs(payload: dict, event_type: str) -> list[tuple[str, str]]:
    """Return candidate (username, password) pairs to test against the index.

    Most engines stash creds in canonical keys: `username` + `password`.
    HTTP form posts arrive as `post_data: {...}` with arbitrary field names,
    so we scan all string values for any pair where one looks like a username
    and another looks like a password. SMTP AUTH PLAIN is a base64 blob in
    `command` — we decode-and-split it.
    """
    pairs: list[tuple[str, str]] = []

    direct_u = payload.get("username")
    direct_p = payload.get("password")
    if isinstance(direct_u, str) and isinstance(direct_p, str):
        pairs.append((direct_u, direct_p))

    post = payload.get("post_data")
    if isinstance(post, dict):
        u = post.get("username") or post.get("user") or post.get("email") or post.get("login")
        p = post.get("password") or post.get("pass") or post.get("passwd") or post.get("pwd")
        if isinstance(u, str) and isinstance(p, str):
            pairs.append((u, p))

    if event_type.lower().startswith("smtp_auth"):
        cmd = payload.get("command") or ""
        if isinstance(cmd, str) and cmd.upper().startswith("AUTH PLAIN"):
            parts = cmd.split(" ", 2)
            if len(parts) == 3:
                try:
                    decoded = base64.b64decode(parts[2] + "==", validate=False).decode(
                        "utf-8", errors="replace"
                    )
                    # AUTH PLAIN format: <authzid>\0<username>\0<password>
                    bits = decoded.split("\x00")
                    if len(bits) >= 3:
                        pairs.append((bits[1], bits[2]))
                except (ValueError, UnicodeDecodeError):
                    pass

    return pairs


def _decode_hex(value: object) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _match_hashed(service: str, payload: dict) -> int | None:
    """Verify a captured MySQL/VNC auth digest against planted-password
    candidates. Candidates for the exact service plus `any`-service tokens are
    tried; the first plaintext that reproduces the digest wins."""
    candidates = _candidates.get(service, []) + _candidates.get("any", [])
    if not candidates:
        return None

    if service == "mysql":
        salt = _decode_hex(payload.get("salt_hex"))
        resp = _decode_hex(payload.get("auth_response_hex"))
        if salt is None or resp is None:
            return None
        username = (payload.get("username") or "").strip().lower()
        for u, pw, token_id in candidates:
            if u == username and verify_mysql(salt, resp, pw):
                return token_id
        return None

    if service == "vnc":
        challenge = _decode_hex(payload.get("challenge_hex"))
        resp = _decode_hex(payload.get("response_hex"))
        if challenge is None or resp is None:
            return None
        # VNC auth is password-only — no username on the wire, so match on
        # password regardless of the token's username field.
        for _u, pw, token_id in candidates:
            if verify_vnc(challenge, resp, pw):
                return token_id
        return None

    return None


async def match(event: PendingEvent) -> int | None:
    """Return the matching active CREDENTIAL honeytoken id, or None.

    Matches in priority: exact service first, then `any`-service tokens as a
    fallback. Usernames compared case-insensitively, passwords case-sensitive.
    MySQL/VNC events route through `_match_hashed` because their passwords
    arrive as a salted digest rather than plaintext.
    """
    await _load_index()
    if not _candidates:
        return None

    service = _infer_service(event.event_type)
    if service in _HASHED_SERVICES:
        return _match_hashed(service, event.payload)

    for username, password in _extract_pairs(event.payload, event.event_type):
        u = username.strip().lower()
        if (service, u, password) in _index:
            return _index[(service, u, password)]
        if ("any", u, password) in _index:
            return _index[("any", u, password)]
    return None
