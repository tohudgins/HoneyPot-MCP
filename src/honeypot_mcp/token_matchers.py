"""Cross-reference for SSH-key, JWT, and DB-row honeytokens.

These three token types share the same shape as `credential_match.py` — a
TTL-cached in-memory index plus a `match(event)` function — but they look
at different payload fields. We bundle them in one module because the cache
loading is identical (a single DB query per refresh, partitioned by token
type into three indices).

Indices:
  - `_ssh_key_index`: `fingerprint → token_id` for ACTIVE SSH_KEY tokens.
    Matched against `payload.fingerprint` (Cowrie's `cowrie.client.publickey`
    event) or any value in the payload that looks like a SHA256 SSH
    fingerprint.
  - `_jwt_index`: `jti → token_id` for ACTIVE JWT tokens. Matched against
    JWT-shaped Authorization Bearer tokens decoded from HTTP request headers.
  - `_dbrow_index`: `canary_email → token_id` for ACTIVE DB_ROW tokens.
    Matched against SMTP `RCPT TO` arguments and any email-looking value
    in payload (covers MAIL FROM tracebacks too).

`match(event)` returns the first matching token_id across all three indices,
or None. Caller (event_buffer.submit_event) escalates severity to CRITICAL
and tags the event with `honeytoken_id` + a type-specific event_type prefix
so the flusher knows to mark the token as TRIGGERED.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import time
from typing import TYPE_CHECKING

from sqlalchemy import select

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

if TYPE_CHECKING:
    from honeypot_mcp.storage.event_buffer import PendingEvent

log = logging.getLogger(__name__)

CACHE_REFRESH_SECONDS = 30

_ssh_key_index: dict[str, int] = {}  # fingerprint → token_id
_jwt_index: dict[str, int] = {}  # jti → token_id
_dbrow_index: dict[str, int] = {}  # canary_email → token_id
_file_uid_index: dict[str, int] = {}  # token_uid → token_id (FILE tokens)
# Cloud-credential index — keyed on whatever identifying field a cloud
# audit log emits for the credential. AWS uses `accessKeyId`, Azure uses
# `appid` / `client_id`, GCP uses `principalEmail` (the service account
# email). Each ID is stored verbatim; ambiguous prefixes are not
# coalesced (e.g. "AKIA" prefix is left intact so it doesn't collide
# with Azure GUIDs).
_cloud_cred_index: dict[str, int] = {}
_loaded_at: float = 0.0
_refresh_lock: LoopBound[asyncio.Lock] = LoopBound(asyncio.Lock)
_refresh_failing = False
# After a failed refresh, retry this many seconds later instead of on the next event.
_REFRESH_RETRY_SECONDS = 5
# TRIGGERED tokens stay matchable: a first (possibly benign) hit must not
# disarm the token against the attacker who uses it later.
_MATCHABLE_STATUSES = (HoneytokenStatus.ACTIVE, HoneytokenStatus.TRIGGERED)

# Every scanned string is clipped to this many characters first. Payload
# values are attacker-authored and the scan runs on the ingest hot path.
_MAX_SCAN_CHARS = 8192

# OpenSSH fingerprint pattern: SHA256:<43 base64url chars>
_SSH_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/=]{40,50}")

# JWT detection is done without a backtracking regex: the old pattern
# `\b[..]{6,}\.[..]{8,}\.[..]{6,}\b` was quadratic on long runs like
# `a-a-a-…`. Instead, maximal runs of base64url-or-dot characters are found
# (one linear pass) and each run is split on dots; three consecutive segments
# of at least 6 / 8 / 6 characters form a candidate (header.payload.signature).
_JWT_RUN_RE = re.compile(r"[A-Za-z0-9_.\-]+")
_JWT_SEGMENT_MIN = (6, 8, 6)

# Canary email pattern — we own the local-part prefix `canary-<hex16>`, so
# this match is very specific.
_CANARY_EMAIL_RE = re.compile(r"canary-[0-9a-f]{16}@[A-Za-z0-9.\-_]+")


def invalidate_cache() -> None:
    """Force the next match() call to reload tokens from the DB."""
    global _loaded_at
    _loaded_at = 0.0


def _cache_fresh() -> bool:
    return time.monotonic() - _loaded_at < CACHE_REFRESH_SECONDS


async def _load_indices() -> None:
    """Refresh the indices if they have expired.

    Double-checked under a lock so a burst of events at expiry costs one
    SELECT. A failed refresh keeps the previous indices (stale beats empty) and
    lets the event continue to the queue rather than raising out of
    `submit_event` and losing it.
    """
    global _ssh_key_index, _jwt_index, _dbrow_index, _cloud_cred_index, _file_uid_index
    global _loaded_at, _refresh_failing
    if _cache_fresh():
        return
    async with _refresh_lock.get():
        if _cache_fresh():
            return
        now = time.monotonic()
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(Honeytoken).where(
                        Honeytoken.status.in_(_MATCHABLE_STATUSES),
                        Honeytoken.type.in_(
                            [
                                HoneytokenType.SSH_KEY,
                                HoneytokenType.JWT,
                                HoneytokenType.DB_ROW,
                                HoneytokenType.API_KEY,
                                HoneytokenType.AZURE_CREDENTIAL,
                                HoneytokenType.GCP_SERVICE_ACCOUNT,
                                HoneytokenType.FILE,
                            ]
                        ),
                    )
                )
                tokens = list(result.scalars().all())
        except Exception as e:
            if not _refresh_failing:
                log.warning("Honeytoken index refresh failed (%s) — keeping the previous index.", e)
            _refresh_failing = True
            _loaded_at = now - CACHE_REFRESH_SECONDS + _REFRESH_RETRY_SECONDS
            return
        _refresh_failing = False

        ssh: dict[str, int] = {}
        jwt: dict[str, int] = {}
        dbr: dict[str, int] = {}
        cloud: dict[str, int] = {}
        file_uid: dict[str, int] = {}
        for t in tokens:
            meta = t.token_meta or {}
            if t.type == HoneytokenType.SSH_KEY:
                fp = meta.get("fingerprint")
                if isinstance(fp, str) and fp:
                    ssh[fp] = t.id
            elif t.type == HoneytokenType.JWT:
                jti = meta.get("jti")
                if isinstance(jti, str) and jti:
                    jwt[jti] = t.id
            elif t.type == HoneytokenType.DB_ROW:
                email = meta.get("canary_email")
                if isinstance(email, str) and email:
                    dbr[email.lower()] = t.id
            elif t.type == HoneytokenType.API_KEY:
                # AWS access_key_id is the identifying field in CloudTrail.
                akid = meta.get("access_key_id")
                if isinstance(akid, str) and akid:
                    cloud[akid] = t.id
            elif t.type == HoneytokenType.AZURE_CREDENTIAL:
                cid = meta.get("client_id")
                if isinstance(cid, str) and cid:
                    cloud[cid] = t.id
            elif t.type == HoneytokenType.GCP_SERVICE_ACCOUNT:
                # GCP audit logs surface the principalEmail (the service-account
                # email). The private_key_id is also distinctive but rarely
                # appears in audit logs.
                email = meta.get("client_email")
                if isinstance(email, str) and email:
                    cloud[email.lower()] = t.id
                pkid = meta.get("private_key_id")
                if isinstance(pkid, str) and pkid:
                    cloud[pkid] = t.id
            elif t.type == HoneytokenType.FILE:
                uid = meta.get("token_uid")
                if isinstance(uid, str) and uid:
                    file_uid[uid] = t.id

        _ssh_key_index = ssh
        _jwt_index = jwt
        _dbrow_index = dbr
        _cloud_cred_index = cloud
        _file_uid_index = file_uid
        _loaded_at = now


async def match_file_uid(labels: list[str]) -> int | None:
    """Return the token id of the first active FILE honeytoken whose
    `token_uid` appears in `labels`, or None.

    Pulled out for DNS's canary-subdomain matching (`<uid>.<zone>` queries),
    which previously ran an uncached DB query plus a full Python-side scan of
    every active FILE honeytoken on *every* matching DNS packet — no TTL
    cache, unlike every other honeytoken cross-reference in this codebase.
    Under a DNS-tunneling-shaped burst (the exact traffic this engine exists
    to catch), that's a per-packet DB round trip on the ingest hot path.
    """
    await _load_indices()
    if not _file_uid_index:
        return None
    for label in labels:
        token_id = _file_uid_index.get(label)
        if token_id is not None:
            return token_id
    return None


def _as_dict(value: object) -> dict:
    """`value` if it is a dict, else an empty one. A forwarded event is whatever the sender
    signed; a field that should be an object arriving as a string must not crash the match."""
    return value if isinstance(value, dict) else {}


async def match_cloud_event(event: dict) -> tuple[int | None, str | None]:
    """Match an inbound cloud-audit-log event against active cloud-credential
    tokens. Returns `(token_id, source)` where `source` is one of `"aws"`,
    `"azure"`, `"gcp"`, or `None`.

    Supports three shapes:
    * AWS CloudTrail: `userIdentity.accessKeyId` (or top-level `accessKeyId`).
    * Azure Activity Log: `claims.appid` or `identity.claims.appid` or
      top-level `client_id`.
    * GCP Audit Log: `protoPayload.authenticationInfo.principalEmail` or
      top-level `principalEmail`. Case-insensitive on the email.

    We probe all three shapes regardless of source so a forwarder that
    flattens nested fields still matches. Returns the first hit by shape
    priority (AWS, then Azure, then GCP).
    """
    await _load_indices()
    if not _cloud_cred_index:
        return None, None

    # AWS shapes
    aws_key = _as_dict(event.get("userIdentity")).get("accessKeyId") or event.get("accessKeyId")
    if isinstance(aws_key, str) and aws_key in _cloud_cred_index:
        return _cloud_cred_index[aws_key], "aws"

    # Azure shapes
    claims = _as_dict(event.get("claims"))
    azure_appid = (
        claims.get("appid")
        or _as_dict(_as_dict(event.get("identity")).get("claims")).get("appid")
        or event.get("appId")
        or event.get("client_id")
    )
    if isinstance(azure_appid, str) and azure_appid in _cloud_cred_index:
        return _cloud_cred_index[azure_appid], "azure"

    # GCP shapes
    proto = _as_dict(event.get("protoPayload"))
    auth = _as_dict(proto.get("authenticationInfo"))
    gcp_email = (
        auth.get("principalEmail")
        or event.get("principalEmail")
        or _as_dict(event.get("authenticationInfo")).get("principalEmail")
    )
    if isinstance(gcp_email, str):
        # Case-insensitive lookup since email local-parts are case-insensitive
        # in practice and audit logs occasionally re-case.
        lower = gcp_email.lower()
        if lower in _cloud_cred_index:
            return _cloud_cred_index[lower], "gcp"

    return None, None


def _decode_jwt_jti(jwt: str) -> str | None:
    """Pull the `jti` claim out of a compact JWT without verifying the
    signature. Returns None if the structure isn't a valid JWT."""
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    try:
        payload_b64 = parts[1]
        # Re-pad for base64
        padding = "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + padding)
        claims = json.loads(decoded)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    jti = claims.get("jti")
    return jti if isinstance(jti, str) else None


def _find_jwt(text: str) -> str | None:
    """Return the first `header.payload.signature`-shaped token in `text`.

    Linear in the (clipped) input: one pass to find runs of base64url/dot
    characters, then a split per run — no backtracking regex."""
    for m in _JWT_RUN_RE.finditer(text[:_MAX_SCAN_CHARS]):
        segments = m.group(0).split(".")
        for i in range(len(segments) - 2):
            a, b, c = segments[i], segments[i + 1], segments[i + 2]
            min_a, min_b, min_c = _JWT_SEGMENT_MIN
            if len(a) >= min_a and len(b) >= min_b and len(c) >= min_c:
                return f"{a}.{b}.{c}"
    return None


def _scan_for_fingerprint(payload: dict) -> str | None:
    """Look for an OpenSSH SHA256 fingerprint anywhere in the payload."""
    fp = payload.get("fingerprint")
    if isinstance(fp, str) and fp.startswith("SHA256:"):
        return fp
    # Cowrie embeds the fingerprint in the `key` or `kex` event payload.
    for value in payload.values():
        if isinstance(value, str):
            m = _SSH_FINGERPRINT_RE.search(value[:_MAX_SCAN_CHARS])
            if m:
                return m.group(0)
    return None


def _scan_for_jwt(payload: dict) -> str | None:
    """Look for a JWT in the payload's headers or body."""
    # HTTP headers are stored under payload.headers["Authorization"] or similar.
    headers = payload.get("headers") or {}
    if isinstance(headers, dict):
        for header_name, header_value in headers.items():
            if not isinstance(header_value, str):
                continue
            # Authorization: Bearer <jwt>
            if header_name.lower() == "authorization":
                parts = header_value[:_MAX_SCAN_CHARS].split(None, 1)
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    return parts[1].strip()
            # Or scan any header value for JWT-shaped strings
            found = _find_jwt(header_value)
            if found:
                return found
    # Scan post_data and any other top-level string values
    for value in payload.values():
        if isinstance(value, str):
            found = _find_jwt(value)
            if found:
                return found
        elif isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str):
                    found = _find_jwt(v)
                    if found:
                        return found
    return None


def _scan_for_canary_email(payload: dict, event_type: str) -> str | None:
    """Look for a canary-prefixed email in SMTP RCPT TO / MAIL FROM commands."""
    # SMTP commands ship in payload.command — "RCPT TO:<canary-...@dom>"
    cmd = payload.get("command")
    if isinstance(cmd, str):
        m = _CANARY_EMAIL_RE.search(cmd[:_MAX_SCAN_CHARS])
        if m:
            return m.group(0).lower()
    # Scan all string values — covers email-bearing payload shapes.
    for value in payload.values():
        if isinstance(value, str):
            m = _CANARY_EMAIL_RE.search(value[:_MAX_SCAN_CHARS])
            if m:
                return m.group(0).lower()
    return None


async def match(event: PendingEvent) -> tuple[int | None, str | None]:
    """Return `(token_id, match_type)` for the first match, or `(None, None)`.

    `match_type` is one of `"ssh_key"`, `"jwt"`, `"db_row"` — caller uses it
    to build the new event_type as
    `honeytoken_triggered_{match_type}_via_{original}`.
    """
    await _load_indices()
    if not (_ssh_key_index or _jwt_index or _dbrow_index):
        return None, None

    payload = event.payload
    if not isinstance(payload, dict):
        return None, None

    # SSH-key fingerprint match (most specific — exact format match)
    if _ssh_key_index:
        fp = _scan_for_fingerprint(payload)
        if fp and fp in _ssh_key_index:
            return _ssh_key_index[fp], "ssh_key"

    # JWT jti match
    if _jwt_index:
        jwt = _scan_for_jwt(payload)
        if jwt:
            jti = _decode_jwt_jti(jwt)
            if jti and jti in _jwt_index:
                return _jwt_index[jti], "jwt"

    # Canary email match
    if _dbrow_index:
        email = _scan_for_canary_email(payload, event.event_type)
        if email and email in _dbrow_index:
            return _dbrow_index[email], "db_row"

    return None, None
