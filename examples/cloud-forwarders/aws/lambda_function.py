"""AWS CloudTrail → HoneyPot MCP forwarder.

Deploy as a Lambda triggered by EventBridge on the
`aws.cloudtrail` source. Lambda runtime: `python3.12`. Required env vars:

- `HONEYPOT_ENDPOINT`  — e.g. https://honeypot.example.com
- `HONEYPOT_HMAC_SECRET` — must match `cloud_event_hmac_secret` in MCP

Both should resolve from AWS Secrets Manager or SSM Parameter Store; the
provided Terraform module wires SSM by default. Plain env-var values work
for quick testing but expose the secret in the Lambda configuration.

We use stdlib `urllib.request` rather than `requests` so the Lambda needs
no layer.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.request

log = logging.getLogger()
log.setLevel(logging.INFO)

# Security-relevant CloudTrail event names. Anything not in this set is
# dropped unless `errorCode` is present (failed calls often reveal probing).
_INTERESTING_EVENT_NAMES = {
    "ConsoleLogin",
    "AssumeRole",
    "GetSessionToken",
    "GetFederationToken",
    "CreateAccessKey",
    "UpdateAccessKey",
    "DeleteAccessKey",
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    # S3 + KMS — credential-bearing services worth watching even on success.
    "GetObject",
    "Decrypt",
    "Sign",
}


def _is_interesting(record: dict) -> bool:
    """Filter to security-relevant CloudTrail records."""
    if record.get("errorCode"):
        return True
    return record.get("eventName") in _INTERESTING_EVENT_NAMES


def _sign(secret: str, body: bytes) -> str:
    """`sha256=<hex>` — must exactly mirror canary.py:_handle_cloud_event."""
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _post(endpoint: str, secret: str, record: dict) -> int:
    """POST a single CloudTrail record. Returns HTTP status code."""
    body = json.dumps(record, default=str).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 — endpoint is operator-controlled
        url=f"{endpoint.rstrip('/')}/cloud-event",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-HoneyPot-Signature": _sign(secret, body),
            "User-Agent": "HoneyPot-MCP-AWS-Forwarder/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return resp.status


def lambda_handler(event: dict, context) -> dict:  # noqa: ARG001
    """EventBridge → Lambda entry point.

    EventBridge delivers events one at a time when the rule targets a Lambda
    function. The CloudTrail record is in `event["detail"]`.
    """
    endpoint = os.environ["HONEYPOT_ENDPOINT"]
    secret = os.environ["HONEYPOT_HMAC_SECRET"]

    detail = event.get("detail", {})
    if not detail:
        log.info("No detail in event — dropping")
        return {"forwarded": 0}

    if not _is_interesting(detail):
        log.debug("Dropping uninteresting event: %s", detail.get("eventName"))
        return {"forwarded": 0}

    try:
        status = _post(endpoint, secret, detail)
        log.info("Forwarded eventName=%s status=%s", detail.get("eventName"), status)
        return {"forwarded": 1, "status": status}
    except Exception as e:
        # Don't raise — Lambda retries on raise. We'd rather log and skip
        # than spam the receiver with retries when it's down.
        log.warning("Forward failed: %s", e)
        return {"forwarded": 0, "error": str(e)[:200]}
