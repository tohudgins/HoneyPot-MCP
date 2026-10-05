"""Fake API key / cloud credential honeytoken provider."""

from __future__ import annotations

import re
import secrets
import string
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_AWS_CHARS = string.ascii_uppercase + string.digits
_SECRET_CHARS = string.ascii_letters + string.digits + "/+"


def _generate_aws_key_id(prefix: str = "AKIA") -> str:
    """Generate an AWS-format access key ID (20 chars, starts with prefix)."""
    body = "".join(secrets.choice(_AWS_CHARS) for _ in range(16))
    return f"{prefix}{body}"


def _generate_aws_secret() -> str:
    """Generate a 40-char AWS secret key lookalike."""
    return "".join(secrets.choice(_SECRET_CHARS) for _ in range(40))


_AWS_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_AWS_SECRET = re.compile(r"^[A-Za-z0-9/+]{40}$")


def adopted_aws_credentials(options: dict[str, Any]) -> tuple[str, str] | None:
    """A real decoy key the operator created in their AWS account (see
    examples/cloud-forwarders/aws/terraform/decoy_user.tf), or None to generate a lookalike.

    A generated key does not exist in AWS, so using it produces no CloudTrail event worth
    forwarding; only a key that IAM knows about is observable. Both halves are required
    and are format-checked, because a typo would produce a token that can never fire."""
    key_id = options.get("access_key_id")
    secret = options.get("secret_access_key")
    if key_id is None and secret is None:
        return None
    if not (isinstance(key_id, str) and isinstance(secret, str)):
        raise ValueError("Provide both access_key_id and secret_access_key to adopt an AWS key.")
    if not _AWS_KEY_ID.fullmatch(key_id):
        raise ValueError("access_key_id must be 20 characters starting AKIA or ASIA.")
    if not _AWS_SECRET.fullmatch(secret):
        raise ValueError("secret_access_key must be 40 characters of A-Z a-z 0-9 / +.")
    return key_id, secret


class APIKeyProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        service = options.get("service", "aws")
        prefix = options.get("prefix", "AKIA")

        if service == "aws":
            adopted = adopted_aws_credentials(options)
            key_id, secret = adopted or (_generate_aws_key_id(prefix), _generate_aws_secret())
            region = options.get("region", "us-east-1")

            meta = {
                "service": "aws",
                "access_key_id": key_id,
                "secret_access_key": secret,
                "region": region,
                "adopted": adopted is not None,
            }
            # token_value encodes both parts for uniqueness
            token_value = f"{key_id}:{secret}"
            return token_value, meta

        # Generic API key
        token_value = f"sk-{secrets.token_urlsafe(32)}"
        return token_value, {"service": service}

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        service = metadata.get("service", "generic")
        if service == "aws":
            key_id = metadata.get("access_key_id", "")
            secret = metadata.get("secret_access_key", "")
            region = metadata.get("region", "us-east-1")
            if metadata.get("adopted"):
                caveat = (
                    "This is a REAL key you created in your AWS account, so using it makes "
                    "CloudTrail record the call (AccessDenied for a deny-all user). With the "
                    "forwarder in examples/cloud-forwarders/aws deployed, that raises a CRITICAL "
                    "alert carrying the attacker's source IP."
                )
            else:
                caveat = (
                    "NOTE: this is a believable-looking decoy that does not exist in AWS, so "
                    "using it leaves no CloudTrail trail. For real detection, create a decoy "
                    "IAM user (examples/cloud-forwarders/aws/terraform/decoy_user.tf) and "
                    "re-create this token with its access_key_id and secret_access_key."
                )
            return (
                f"Plant this AWS credential in a target location:\n\n"
                f"~/.aws/credentials:\n"
                f"  [default]\n"
                f"  aws_access_key_id = {key_id}\n"
                f"  aws_secret_access_key = {secret}\n"
                f"  region = {region}\n\n"
                f"Or in a .env file:\n"
                f"  AWS_ACCESS_KEY_ID={key_id}\n"
                f"  AWS_SECRET_ACCESS_KEY={secret}\n\n"
                f"{caveat}\n"
                f"Alternative with a hosted backend: Thinkst Canarytokens (canarytokens.org)."
            )
        return (
            f"Plant API key '{token_value}' in configuration files, source code, or documentation."
        )
