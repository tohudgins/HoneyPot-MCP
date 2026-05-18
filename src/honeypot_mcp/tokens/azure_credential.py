"""Azure service-principal credential honeytoken.

Generates a believable Azure app-registration credential bundle:
client_id (UUID), client_secret (~43-char base64-ish), tenant_id (UUID),
and subscription_id (UUID). The token_value is a multi-line config
string suitable for direct paste into a `.env` or for use with
`az login --service-principal`.

Detection: same caveat as AWS. The credentials themselves don't phone
home. Detection requires the operator to forward Azure Activity Log
entries (specifically failed sign-in / role-assignment events for the
fake client_id) to the `/cloud-event` ingest endpoint on canary.py.
With that wiring in place, an attacker who tries to `az login` with
these credentials produces a CRITICAL alert.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


class AzureCredentialProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        client_id = str(uuid.uuid4())
        client_secret = secrets.token_urlsafe(32)
        tenant_id = str(uuid.uuid4())
        subscription_id = str(uuid.uuid4())

        token_value = (
            f"AZURE_CLIENT_ID={client_id}\n"
            f"AZURE_CLIENT_SECRET={client_secret}\n"
            f"AZURE_TENANT_ID={tenant_id}\n"
            f"AZURE_SUBSCRIPTION_ID={subscription_id}\n"
        )

        meta = {
            "service": "azure",
            "client_id": client_id,
            "client_secret": client_secret,
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
        }
        return token_value, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        client_id = metadata.get("client_id", "")
        tenant_id = metadata.get("tenant_id", "")
        return (
            "Plant this Azure service-principal credential in a believable location:\n\n"
            "  - .env: paste the AZURE_* lines\n"
            "  - terraform.tfvars: client_id, client_secret, tenant_id\n"
            "  - A 'deploy.ps1' or 'login.sh' file\n\n"
            f"client_id: {client_id}\n"
            f"tenant_id: {tenant_id}\n\n"
            "Detection wire: this token is decoy-only by default. To enable\n"
            "real detection, configure Azure Monitor / Activity Log forwarding\n"
            "to POST sign-in attempt JSON (with `claims.appid` or\n"
            "`identity.claims.appid` matching the client_id) to the MCP\n"
            f"`/cloud-event` HMAC-signed ingest endpoint. With that wired up,\n"
            "an `az login --service-principal` attempt with these creds\n"
            "produces a CRITICAL alert."
        )
