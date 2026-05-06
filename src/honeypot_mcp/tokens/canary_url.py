"""Canary URL honeytoken provider — unique URLs that trigger on HTTP GET."""

from __future__ import annotations

import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


class CanaryURLProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        token_id = str(uuid.uuid4())
        path = f"/t/{token_id}"
        full_url = f"{settings.canary_public_url.rstrip('/')}{path}"

        meta = {
            "token_id": token_id,
            "path": path,
            "full_url": full_url,
            "callback_host": settings.canary_callback_host,
            "callback_port": settings.canary_callback_port,
        }
        return full_url, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        return (
            f"Plant this canary URL where an attacker might discover it:\n\n"
            f"  URL: {token_value}\n\n"
            f"Planting ideas:\n"
            f"  - Embed in HTML comments: <!-- backup: {token_value} -->\n"
            f"  - Add to a fake password file or config\n"
            f"  - Include in a document as a 'reference link'\n"
            f"  - Set as a webhook URL in a fake integration\n\n"
            f"An alert fires the moment this URL is visited."
        )
