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

import asyncio
import json
import re
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


_MAX_KEY_FILE = 20_000
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+")


def adopted_service_account(options: dict[str, Any]) -> dict[str, Any] | None:
    """A REAL decoy service-account key (examples/cloud-forwarders/gcp/decoy_sa.sh), given
    as `service_account_json` (the file's text or the parsed object), or None to generate
    a lookalike. A generated key's service account does not exist, so using it produces no
    audit-log entry that names it."""
    raw = options.get("service_account_json")
    if raw is None:
        return None
    if isinstance(raw, str) and len(raw) > _MAX_KEY_FILE:
        raise ValueError("service_account_json is too large to be a service-account key.")
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, RecursionError) as e:
        raise ValueError("service_account_json is not valid JSON.") from e
    if not isinstance(data, dict) or data.get("type") != "service_account":
        raise ValueError('service_account_json must be a key file with "type": "service_account".')
    missing = [
        k for k in ("project_id", "private_key_id", "private_key", "client_email", "client_id")
        if not data.get(k)
    ]  # fmt: skip
    if missing:
        raise ValueError(f"service_account_json is missing: {', '.join(missing)}.")
    # A key that is the right shape but the wrong kind of value would become an ACTIVE token
    # that can never fire.
    if not all(
        isinstance(data[k], str) and data[k]
        for k in ("project_id", "private_key_id", "private_key", "client_email")
    ) or not isinstance(data["client_id"], str | int):
        raise ValueError("service_account_json fields must be strings.")
    if not _EMAIL.fullmatch(data["client_email"]):
        raise ValueError("client_email is not an email address.")
    if "PRIVATE KEY" not in data["private_key"]:
        raise ValueError("private_key does not look like a PEM private key.")
    return data


class GCPServiceAccountProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        if (real := adopted_service_account(options)) is not None:
            return json.dumps(real, indent=2), {
                "service": "gcp",
                "project_id": real["project_id"],
                "private_key_id": real["private_key_id"],
                "client_id": str(real["client_id"]),
                "client_email": real["client_email"],
                "adopted": True,
            }
        project_id = options.get("project_id", f"prod-{secrets.token_hex(4)}")
        private_key_id = secrets.token_hex(20)  # 40-hex GCP convention
        client_id = "".join(secrets.choice("0123456789") for _ in range(21))
        client_email = f"hp-canary-{secrets.token_hex(4)}@{project_id}.iam.gserviceaccount.com"
        # RSA keygen is CPU-bound; keep it off the event loop.
        private_key_pem = await asyncio.to_thread(_generate_throwaway_rsa_pem)

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
            "adopted": False,
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
            + (
                "This is a REAL service account key you created (no roles), so any use of "
                "it is written to Cloud Audit Logs under its client_email; with the "
                "forwarder in examples/cloud-forwarders/gcp deployed that raises a "
                "CRITICAL alert."
                if metadata.get("adopted")
                else "This token is decoy-only: the service account does not exist, so "
                "its use leaves no audit-log entry. Create a decoy service account "
                "(examples/cloud-forwarders/gcp/decoy_sa.sh) and re-create this token "
                "with service_account_json set to its key file."
            )
        )
