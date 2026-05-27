"""GCP Cloud Audit Log → HoneyPot MCP forwarder.

Deploy as a Cloud Function (Gen2) triggered by a Pub/Sub topic. The
recommended pipeline is:

    Cloud Logging sink (filter: protoPayload.serviceName matches the
    interesting services) → Pub/Sub topic → this function

Required env vars (set on the Cloud Function):

- `HONEYPOT_ENDPOINT`  — base URL of your MCP
- `HONEYPOT_HMAC_SECRET` — matches `cloud_event_hmac_secret` in MCP

`functions-framework` is provided by the Gen2 runtime; no other deps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import urllib.request

import functions_framework

# Services worth forwarding. Anything else is dropped at the function level
# even if the log sink delivered it.
_INTERESTING_SERVICES = {
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudkms.googleapis.com",
    "secretmanager.googleapis.com",
    # Watching object reads in storage gets noisy; the log sink filter
    # should narrow to the bucket(s) that hold cloud honeytokens.
    "storage.googleapis.com",
}


def _is_interesting(record: dict) -> bool:
    """Filter to security-relevant audit log records."""
    proto = record.get("protoPayload") or {}
    service = proto.get("serviceName")
    if service not in _INTERESTING_SERVICES:
        return False
    # Honeytokens fire only on actual principals — drop anonymous/system calls.
    auth = proto.get("authenticationInfo") or {}
    if not auth.get("principalEmail"):
        return False
    return True


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
            "User-Agent": "HoneyPot-MCP-GCP-Forwarder/1.0",
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
        return resp.status


@functions_framework.cloud_event
def forwarder(cloud_event) -> None:
    """Cloud Functions Gen2 entry point.

    Pub/Sub messages arrive as CloudEvents with the actual message in
    `cloud_event.data["message"]["data"]` (base64-encoded).
    """
    endpoint = os.environ["HONEYPOT_ENDPOINT"]
    secret = os.environ["HONEYPOT_HMAC_SECRET"]

    msg = (cloud_event.data or {}).get("message") or {}
    b64 = msg.get("data")
    if not b64:
        logging.info("Empty Pub/Sub message — dropping")
        return

    try:
        raw = base64.b64decode(b64)
        record = json.loads(raw.decode("utf-8"))
    except Exception as e:
        logging.warning("Decode failed: %s", e)
        return

    if not _is_interesting(record):
        return

    try:
        status = _post(endpoint, secret, record)
        op = (record.get("protoPayload") or {}).get("methodName")
        logging.info("Forwarded method=%s status=%s", op, status)
    except Exception as e:
        logging.warning("Forward failed: %s", e)
