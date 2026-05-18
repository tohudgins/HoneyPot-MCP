"""GCP service-account JSON honeytoken.

Generates a full `service_account.json` shape including a real-looking but
throwaway 2048-bit RSA private key. The token_value is the formatted JSON
string suitable for direct drop into `GOOGLE_APPLICATION_CREDENTIALS`.

Detection: same as Azure. The credentials don't phone home. To enable
real detection, wire your GCP Audit Log sink to POST events into the
`/cloud-event` ingest endpoint on canary.py — events whose
`protoPayload.authenticationInfo.principalEmail` matches the synthetic
`client_email` produced here will trigger a CRITICAL alert.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


def _generate_throwaway_rsa_pem() -> str:
    """Generate a real-format RSA private key. The key is genuinely
    cryptographically generated so its structure passes any parser
    validation, but it has no production use — it never leaves this token
    and isn't backed by any cloud account.

    `cryptography` is already a project dep (used by `engines/tls.py`).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem.decode("ascii")


class GCPServiceAccountProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        project_id = options.get("project_id", f"prod-{secrets.token_hex(4)}")
        private_key_id = secrets.token_hex(20)  # 40-hex GCP convention
        client_id = "".join(secrets.choice("0123456789") for _ in range(21))
        client_email = f"hp-canary-{secrets.token_hex(4)}@{project_id}.iam.gserviceaccount.com"
        private_key_pem = _generate_throwaway_rsa_pem()

        sa_json = {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key_pem,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": (
                f"https://www.googleapis.com/robot/v1/metadata/x509/"
                f"{client_email.replace('@', '%40')}"
            ),
            "universe_domain": "googleapis.com",
        }
        token_value = json.dumps(sa_json, indent=2)

        meta = {
            "service": "gcp",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "client_id": client_id,
            "client_email": client_email,
        }
        return token_value, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        client_email = metadata.get("client_email", "")
        project_id = metadata.get("project_id", "")
        return (
            "Plant this GCP service-account JSON in a believable location:\n\n"
            "  - Save as service-account.json and set\n"
            "    GOOGLE_APPLICATION_CREDENTIALS=/path/to/it\n"
            "  - Include in a deploy-helper script alongside `gcloud auth\n"
            "    activate-service-account`\n"
            "  - Embed in a Kubernetes Secret manifest as `key.json`\n\n"
            f"project_id: {project_id}\n"
            f"client_email: {client_email}\n\n"
            "Detection wire: this token is decoy-only by default. To enable\n"
            "real detection, forward your GCP Audit Log entries to the MCP\n"
            "`/cloud-event` HMAC-signed ingest endpoint. Events whose\n"
            "`protoPayload.authenticationInfo.principalEmail` matches the\n"
            "synthesized client_email will trigger a CRITICAL alert."
        )
