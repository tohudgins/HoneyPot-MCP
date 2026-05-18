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

import secrets
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

# A throwaway base64-ish blob that LOOKS like a CA bundle without containing
# any real key material. Real kubeconfigs embed a base64-encoded PEM cert.
_FAKE_CA_BUNDLE = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURIRENDQWdTZ0F3SUJBZ0lVU"
    "FlBVUNQVTBaaFRSQUVURFlxV1RKWlpkcWh3Z2dPQ0EwR0NTcUdTSWIzRFFFQkN3VU"
    "FNQjB4R3pBWkJnTlZCQU1NRWtSbApabUYxYkhRZ1FYVjBhRzl5YVhSNU1CNFhEVE0"
    "wTURFd01UQXdNREF3TUZvWERUTTBNREV3TVRBd01EQXdNRm93RXpFUk1BOEdBMVVF"
)


def _kubeconfig_yaml(cluster_name: str, server_url: str, ca_bundle: str, bearer_token: str) -> str:
    return (
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n"
        f"- name: {cluster_name}\n"
        "  cluster:\n"
        f"    server: {server_url}\n"
        f"    certificate-authority-data: {ca_bundle}\n"
        "contexts:\n"
        f"- name: {cluster_name}\n"
        "  context:\n"
        f"    cluster: {cluster_name}\n"
        "    user: admin\n"
        f"current-context: {cluster_name}\n"
        "users:\n"
        "- name: admin\n"
        "  user:\n"
        f"    token: {bearer_token}\n"
    )


class KubeconfigProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        token_id = str(uuid.uuid4())
        # `/kubeconfig/<token_id>` path is captured by the existing
        # `/t/{token_id}` route — we point kubectl at it directly via
        # the trailing token_id in the path. kubectl makes a GET on
        # `/version` or `/api` after the URL — both 200 OK from the
        # canary server suffice for it to consider the cluster reachable
        # long enough to record the access.
        canary_base = settings.canary_public_url.rstrip("/")
        server_url = f"{canary_base}/t/{token_id}"
        cluster_name = options.get("cluster_name", "production-cluster")
        bearer_token = secrets.token_urlsafe(48)

        yaml_body = _kubeconfig_yaml(
            cluster_name=cluster_name,
            server_url=server_url,
            ca_bundle=_FAKE_CA_BUNDLE,
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
