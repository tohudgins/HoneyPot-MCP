"""Azure Activity Log → HoneyPot MCP forwarder.

Deploy as an Azure Function App using the Python v2 model with an
Event Hub trigger. Set up a diagnostic setting on your subscription
that routes the `Administrative` and `Security` categories to an
Event Hub; this function consumes from it.

Required env vars (Function App configuration):

- `HONEYPOT_ENDPOINT`  — base URL of your HoneyPot MCP
- `HONEYPOT_HMAC_SECRET` — matches `cloud_event_hmac_secret` in MCP

Use `urllib.request` so the deployment package needs no extra deps.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request

import azure.functions as func

# Operation-name prefixes worth forwarding. Activity Log operation names are
# `<namespace>/<resource>/<action>` — the prefix usually contains the
# namespace + resource type.
_INTERESTING_OPERATION_PREFIXES = (
    "Microsoft.Authorization/",
    "Microsoft.KeyVault/vaults/secrets/",
    "Microsoft.Storage/storageAccounts/listKeys",
    "Microsoft.Resources/deployments/",
)


def _is_interesting(record: dict) -> bool:
    """Filter to security-relevant Activity Log records."""
    op = (record.get("operationName") or "").lower()
    if any(op.startswith(p.lower()) for p in _INTERESTING_OPERATION_PREFIXES):
        return True
    # Sign-in / Audit logs come through with different shapes (categories
    # `SignInLogs`, `AuditLogs`). Forward those wholesale.
    cat = (record.get("category") or "").lower()
    if cat in {"signinlogs", "auditlogs"}:
        return True
    # Any explicit failure status — typical probe pattern.
    status = (record.get("status", {}).get("value") or "").lower()
    if status == "failed":
        return True
    return False


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post(endpoint: str, secret: str, record: dict) -> int:
    body = json.dumps(record, default=str).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310
        url=f"{endpoint.rstrip('/')}/cloud-event",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HoneyPot-Signature": _sign(secret, body),
            "User-Agent": "HoneyPot-MCP-Azure-Forwarder/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return resp.status


app = func.FunctionApp()


@app.event_hub_message_trigger(
    arg_name="azeventhub",
    event_hub_name="honeypot-mcp-activity-log",
    connection="EventHubConnection",
)
def forwarder(azeventhub: func.EventHubEvent) -> None:
    """Event Hub batched delivery — process each record in the batch."""
    endpoint = os.environ["HONEYPOT_ENDPOINT"]
    secret = os.environ["HONEYPOT_HMAC_SECRET"]

    body_text = azeventhub.get_body().decode("utf-8")
    try:
        envelope = json.loads(body_text)
    except json.JSONDecodeError:
        logging.warning("Non-JSON Event Hub message — skipping")
        return

    # Activity Log diagnostic settings deliver `{"records": [...]}` envelopes.
    records = envelope.get("records") if isinstance(envelope, dict) else None
    if not records:
        records = [envelope] if isinstance(envelope, dict) else []

    for rec in records:
        if not _is_interesting(rec):
            continue
        try:
            status = _post(endpoint, secret, rec)
            logging.info("Forwarded operation=%s status=%s", rec.get("operationName"), status)
        except Exception as e:
            logging.warning("Forward failed: %s", e)
