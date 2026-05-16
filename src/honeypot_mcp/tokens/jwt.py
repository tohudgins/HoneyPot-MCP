"""JWT honeytoken provider — planted bearer tokens with `jti` tracking.

Generates a signed JWT (HS256 over a per-token random secret) with a unique
`jti` claim. The operator plants the JWT somewhere attractive — committed to
a public repo as `API_TOKEN=...`, embedded in a fake `.env` file, leaked in
Slack message backups.

Trigger path:

    Attacker → finds JWT → tries it as `Authorization: Bearer <jwt>` against
    a target → our HTTP honeypot captures the header → jwt_match.py decodes
    and recognises the `jti` → CRITICAL alert with honeytoken_id linked.

We sign on a random secret so the JWT looks real to scanners that try to
validate the signature locally (they'll fail validation, but the structure
is intact). The point is the `jti` matching, not the signature.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _build_jwt(payload: dict[str, Any], secret: bytes) -> str:
    """Build a JWT manually (HS256). Avoids a hard dep on PyJWT — the
    crypto here is just HMAC-SHA256 over base64url-encoded blobs."""
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    s_b64 = _b64url(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"


class JWTProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        jti = uuid.uuid4().hex
        issuer = options.get("issuer", "https://auth.corp.local")
        subject = options.get("subject", f"svc-account-{jti[:8]}")
        ttl_seconds = int(options.get("ttl_seconds", 3600 * 24 * 365))  # 1 year default

        now = int(time.time())
        payload = {
            "iss": issuer,
            "sub": subject,
            "aud": options.get("audience", "internal-api"),
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": jti,
            "scope": options.get("scope", "read:all write:all admin"),
        }

        # Random secret — the JWT is signed but we don't expect anyone to
        # validate against a real KMS. The signature being intact is enough.
        secret = secrets.token_bytes(32)
        jwt = _build_jwt(payload, secret)

        meta = {
            "jti": jti,
            "issuer": issuer,
            "subject": subject,
            "audience": payload["aud"],
            "scope": payload["scope"],
            "expires_at": payload["exp"],
        }
        return jwt, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        return (
            f"JWT honeytoken created.\n\n"
            f"  Token: {token_value}\n"
            f"  jti:   {metadata.get('jti')}\n"
            f"  sub:   {metadata.get('subject')}\n"
            f"  scope: {metadata.get('scope')}\n\n"
            f"Plant this where an attacker would find it as a credential:\n"
            f"  - `API_TOKEN=...` in a fake .env committed to a public repo\n"
            f"  - Hard-coded in a leaked JavaScript bundle\n"
            f"  - Inside a 'forgotten' Postman collection or Insomnia export\n"
            f"  - Slack message export, decompiled APK strings\n\n"
            f"The trigger fires the moment an attacker sends this JWT as\n"
            f"`Authorization: Bearer <token>` to your HTTP honeypot.\n"
            f"The HTTP engine captures the header, jwt_match.py decodes the JWT\n"
            f"and matches the `jti` against active JWT tokens, escalating the\n"
            f"alert to CRITICAL and linking the originating honeytoken_id."
        )
