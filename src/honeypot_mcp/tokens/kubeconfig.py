"""Kubernetes kubeconfig honeytoken — fires on `kubectl --kubeconfig …` use.

Generates a complete YAML kubeconfig file whose `clusters[0].cluster.server`
points at the canary callback. The moment an attacker uses the file
(`kubectl --kubeconfig <file> get pods`), kubectl makes an HTTPS-style
request to the server URL — that request lands at the canary callback
and triggers a CRITICAL alert via the same path canary URL tokens use.

Detection wire: identical to `tokens/canary_url.py` — the canary callback
matches on `token_meta.token_id`. No new infrastructure required.
"""

from __future__ import annotations

import re
import secrets
import uuid
from typing import Any

import yaml

from honeypot_mcp.tokens.base import HoneytokenProvider

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_MAX_CLUSTER_NAME_LEN = 253


def _validate_cluster_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("kubeconfig cluster_name must be a non-empty string")
    if len(name) > _MAX_CLUSTER_NAME_LEN:
        raise ValueError(f"kubeconfig cluster_name must be at most {_MAX_CLUSTER_NAME_LEN} chars")
    if _CONTROL_CHARS.search(name):
        raise ValueError("kubeconfig cluster_name must not contain control characters")
    return name


def _kubeconfig_yaml(cluster_name: str, server_url: str, bearer_token: str) -> str:
    """Render the kubeconfig through a YAML serialiser, never by interpolation.

    `cluster_name` is operator/model supplied; spliced into a template, a value
    containing a newline or `: ` rewrites the document structure.

    TLS: the canary callback server speaks plain HTTP and, in production, sits
    behind whatever `CANARY_PUBLIC_URL` points at — often a reverse proxy with a
    publicly trusted certificate. `certificate-authority-data` would *replace*
    the system trust store and make kubectl abort the handshake against such a
    proxy before a single request (and so a single alert) was sent, while a
    bogus/truncated blob fails even earlier at parse time. `insecure-skip-tls-verify`
    works for every scheme and certificate the operator might front the canary
    with, so the first `kubectl` call always reaches us.
    """
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": cluster_name,
                "cluster": {"server": server_url, "insecure-skip-tls-verify": True},
            }
        ],
        "contexts": [{"name": cluster_name, "context": {"cluster": cluster_name, "user": "admin"}}],
        "current-context": cluster_name,
        "users": [{"name": "admin", "user": {"token": bearer_token}}],
    }
    return yaml.safe_dump(
        config, default_flow_style=False, sort_keys=False, allow_unicode=True, width=4096
    )


class KubeconfigProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        token_id = str(uuid.uuid4())
        # kubectl appends its request paths to this base (`/version`, `/api`,
        # `/apis`, `/api/v1/...`); the canary server's `/t/{token_id}/{tail}`
        # catch-all answers those with minimal Kubernetes discovery documents
        # and fires the token on each.
        canary_base = settings.canary_public_url.rstrip("/")
        server_url = f"{canary_base}/t/{token_id}"
        cluster_name = _validate_cluster_name(options.get("cluster_name", "production-cluster"))
        bearer_token = secrets.token_urlsafe(48)

        yaml_body = _kubeconfig_yaml(
            cluster_name=cluster_name,
            server_url=server_url,
            bearer_token=bearer_token,
        )

        meta = {
            "token_id": token_id,
            "cluster_name": cluster_name,
            "server_url": server_url,
            "bearer_token": bearer_token,
        }
        return yaml_body, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        cluster_name = metadata.get("cluster_name", "production-cluster")
        server_url = metadata.get("server_url", "")
        return (
            "Plant this kubeconfig where an attacker would search for one:\n\n"
            "  - ~/.kube/config on a developer machine\n"
            "  - CI/CD environment variable (KUBECONFIG)\n"
            "  - A backup directory on a Linux honeypot host\n"
            "  - Embedded in a 'devops-runbook.txt' file\n\n"
            "The moment an attacker runs:\n\n"
            "    kubectl --kubeconfig <file> get pods\n\n"
            f"…kubectl reaches out to {server_url}, which triggers a CRITICAL\n"
            f"alert in HoneyPot MCP via the canary callback path.\n\n"
            f"Cluster name in file: {cluster_name}"
        )
