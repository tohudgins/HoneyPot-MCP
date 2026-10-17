"""Masking of planted honeytoken secrets in text a tool hands back.

Attackers replay stolen bait: a planted password typed into a shell command, an AWS key pasted into a
request path, a canary URL fetched with `curl`. A captured command or path can therefore quote a
secret this server planted, and listing it would hand the bait value to whoever reads the answer.
`load_planted()` collects every token's discrete secret strings (revoked tokens included: their
secrets are still secrets, and `credential_match`'s live index no longer carries them) and
`Planted.redact` replaces each occurrence with `[masked: planted honeytoken #<id>]`.

What is masked, by token type:

* `credential`: every planted password.
* `api_key`: the AWS access key id and secret access key, or the `sk-...` value.
* `azure_credential`: the client secret and client id.
* `kubeconfig`: the bearer token and the callback token id.
* `slack_webhook`, `canary_url`: the callback URL and its token id.
* `jwt`: the whole token and its `jti`.
* `gcp_service_account`: the private key (whole, as one base64 run, and each line of its body) and
  its key id.
* `file`: the tracking token uid and URL.
* `db_row`: the canary e-mail address.

Not masked: `ssh_key` (its stored value is the public key fingerprint, which is public by
construction) and, inside free text, any secret shorter than four characters (masking a two-letter
string would corrupt unrelated text; `mask()` of a value that is exactly such a secret still works).

This is hygiene, not an access control. `sql_query` and `alerts_get` return captured values as stored,
and a secret an attacker transformed (base64, hex, split across commands) is not recognised.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Any

from sqlalchemy import select

from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Honeytoken, HoneytokenType

_MIN_SECRET_CHARS = 4
_MIN_KEY_LINE_CHARS = 16  # a line of a PEM body worth masking on its own

# Keys of `token_meta` that hold a discrete secret or an identifier that is itself the bait.
_META_SECRET_KEYS: dict[HoneytokenType, tuple[str, ...]] = {
    HoneytokenType.API_KEY: ("access_key_id", "secret_access_key"),
    HoneytokenType.AZURE_CREDENTIAL: ("client_secret", "client_id"),
    HoneytokenType.KUBECONFIG: ("bearer_token", "token_id"),
    HoneytokenType.SLACK_WEBHOOK: ("full_url", "token_id"),
    HoneytokenType.CANARY_URL: ("full_url", "token_id"),
    HoneytokenType.JWT: ("jti",),
    HoneytokenType.FILE: ("token_uid", "tracking_url"),
    HoneytokenType.DB_ROW: ("canary_email",),
    HoneytokenType.GCP_SERVICE_ACCOUNT: ("private_key_id",),
}
# Types whose stored `token_value` is itself the secret (for the others it is a document that
# embeds one, a fingerprint or a bookkeeping id).
_VALUE_IS_SECRET = frozenset(
    {
        HoneytokenType.JWT,
        HoneytokenType.SLACK_WEBHOOK,
        HoneytokenType.CANARY_URL,
        HoneytokenType.DB_ROW,
        HoneytokenType.FILE,
    }
)


@dataclass(frozen=True)
class Planted:
    """Every planted secret string, with the id of the honeytoken it belongs to."""

    by_secret: dict[str, tuple[int, str]]

    @cached_property
    def pattern(self) -> re.Pattern[str] | None:
        secrets = sorted(
            (s for s in self.by_secret if len(s) >= _MIN_SECRET_CHARS), key=len, reverse=True
        )
        return re.compile("|".join(re.escape(s) for s in secrets)) if secrets else None

    def mask(self, secret: str | None) -> str | None:
        """`secret` itself, or the placeholder when it is exactly a planted value."""
        if secret is not None and secret in self.by_secret:
            return f"[masked: planted honeytoken #{self.by_secret[secret][0]}]"
        return secret

    def redact(self, text_value: str) -> str:
        """`text_value` with every occurrence of a planted secret replaced."""
        pattern = self.pattern
        if pattern is None:
            return text_value
        return pattern.sub(
            lambda m: f"[masked: planted honeytoken #{self.by_secret[m.group(0)][0]}]", text_value
        )


def _secrets_of(
    token_type: HoneytokenType, token_value: str | None, meta: dict[str, Any]
) -> list[str]:
    found: list[Any] = []
    if token_type == HoneytokenType.CREDENTIAL:
        for pair in meta.get("credentials") or []:
            if isinstance(pair, dict):
                found.append(pair.get("password"))
        return [s for s in found if isinstance(s, str)]
    for key in _META_SECRET_KEYS.get(token_type, ()):
        found.append(meta.get(key))
    if token_type in _VALUE_IS_SECRET:
        found.append(token_value)
    elif token_type == HoneytokenType.API_KEY and meta.get("service") != "aws":
        found.append(token_value)  # `sk-...`: the value is the key (AWS: the meta parts above)
    elif token_type == HoneytokenType.GCP_SERVICE_ACCOUNT and token_value:
        try:
            document = json.loads(token_value)
        except ValueError:
            document = None
        if isinstance(document, dict):
            pem = document.get("private_key")
            found.append(pem)
            if isinstance(pem, str):
                # An exfiltrated key is usually pasted a line or a base64 run at a time.
                body = [
                    line.strip()
                    for line in pem.splitlines()
                    if line.strip() and not line.startswith("-----")
                ]
                found.extend(line for line in body if len(line) >= _MIN_KEY_LINE_CHARS)
                found.append("".join(body))
    return [s for s in found if isinstance(s, str)]


async def load_planted() -> Planted:
    async with get_session() as session:
        rows = (
            await session.execute(
                select(
                    Honeytoken.id,
                    Honeytoken.label,
                    Honeytoken.type,
                    Honeytoken.token_value,
                    Honeytoken.token_meta,
                )
            )
        ).all()
    by_secret: dict[str, tuple[int, str]] = {}
    for token_id, label, token_type, token_value, meta in rows:
        for secret in _secrets_of(token_type, token_value, meta or {}):
            if secret:
                by_secret.setdefault(secret, (token_id, label))
    return Planted(by_secret)
