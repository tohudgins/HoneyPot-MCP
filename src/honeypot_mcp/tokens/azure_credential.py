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

import re
import secrets
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _guid(options: dict[str, Any], key: str) -> str:
    value = options[key]
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise ValueError(f"{key} must be a GUID like 00000000-0000-0000-0000-000000000000.")
    return value.lower()


class AzureCredentialProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        # Adopting a REAL decoy service principal (examples/cloud-forwarders/azure/
        # decoy_sp.sh): a generated client_id does not exist in Entra ID, so signing in
        # with it produces a sign-in log entry for no known application and nothing
        # that ties it to this token.
        adopted = "client_id" in options or "client_secret" in options
        if adopted:
            missing = [k for k in ("client_id", "client_secret", "tenant_id") if not options.get(k)]
            if missing:
                raise ValueError(
                    "To adopt an Azure service principal provide client_id, client_secret "
                    f"and tenant_id (missing: {', '.join(missing)})."
                )
            client_id = _guid(options, "client_id")
            tenant_id = _guid(options, "tenant_id")
            client_secret = options["client_secret"]
            # The secret is written into a multi-line AZURE_* env block: a newline in it
            # would forge further lines (a different tenant, say) in the token value.
            if (
                not isinstance(client_secret, str)
                or not 1 <= len(client_secret) <= 256
                or not client_secret.isprintable()
                or any(c.isspace() for c in client_secret)
            ):
                raise ValueError("client_secret must be 1-256 printable characters, no spaces.")
            subscription_id = (
                _guid(options, "subscription_id")
                if options.get("subscription_id")
                else str(uuid.uuid4())
            )
        else:
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
            "adopted": adopted,
        }
        return token_value, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        client_id = metadata.get("client_id", "")
        tenant_id = metadata.get("tenant_id", "")
        if metadata.get("adopted"):
            detection = (
                "This is a REAL service principal you created (no permissions), so a "
                "sign-in attempt with it appears in Entra ID's sign-in logs against this "
                "client_id; with the forwarder in examples/cloud-forwarders/azure deployed "
                "that raises a CRITICAL alert."
            )
        else:
            detection = (
                "Detection wire: this token is decoy-only: the client_id does not exist in "
                "Entra ID. Create a decoy service principal "
                "(examples/cloud-forwarders/azure/decoy_sp.sh) and re-create this token "
                "with its client_id, client_secret and tenant_id."
            )
        return (
            "Plant this Azure service-principal credential in a believable location:\n\n"
            "  - .env: paste the AZURE_* lines\n"
            "  - terraform.tfvars: client_id, client_secret, tenant_id\n"
            "  - A 'deploy.ps1' or 'login.sh' file\n\n"
            f"client_id: {client_id}\n"
            f"tenant_id: {tenant_id}\n\n"
            f"{detection}"
        )
