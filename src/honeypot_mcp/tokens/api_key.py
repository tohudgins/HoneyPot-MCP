"""Fake API key / cloud credential honeytoken provider."""

from __future__ import annotations

import random
import secrets
import string
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_AWS_CHARS = string.ascii_uppercase + string.digits
_SECRET_CHARS = string.ascii_letters + string.digits + "/+"


def _generate_aws_key_id(prefix: str = "AKIA") -> str:
    """Generate an AWS-format access key ID (20 chars, starts with prefix)."""
    body = "".join(random.choices(_AWS_CHARS, k=16))
    return f"{prefix}{body}"


def _generate_aws_secret() -> str:
    """Generate a 40-char AWS secret key lookalike."""
    return "".join(random.choices(_SECRET_CHARS, k=40))


class APIKeyProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        service = options.get("service", "aws")
        prefix = options.get("prefix", "AKIA")

        if service == "aws":
            key_id = _generate_aws_key_id(prefix)
            secret = _generate_aws_secret()
            region = options.get("region", "us-east-1")

            meta = {
                "service": "aws",
                "access_key_id": key_id,
                "secret_access_key": secret,
                "region": region,
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
                f"Alert triggers when anyone attempts to use these credentials.\n"
                f"Configure AWS CloudTrail or use the MCP alert webhook."
            )
        return (
            f"Plant API key '{token_value}' in configuration files, source code, or documentation."
        )
