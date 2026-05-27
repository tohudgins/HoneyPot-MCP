# Cloud audit-log forwarders

HoneyPot MCP ships a built-in receiver at `POST /cloud-event` that ingests
HMAC-signed audit-log events from AWS / Azure / GCP. When the body matches an
active cloud honeytoken (AWS access key, Azure service principal, GCP service
account), it fires the same CRITICAL alert pipeline as a canary URL hit.

The receiver lives in `src/honeypot_mcp/canary.py:_handle_cloud_event`. This
directory contains operator-deployable forwarders that wire each cloud's
native audit pipeline up to that endpoint.

## Why you need a forwarder

A planted AWS access key sitting in a `.env` file is decorative unless your
CloudTrail emits an event the moment someone tries to use it. The forwarder
is the glue: it watches CloudTrail / Activity Log / Audit Log, filters to
the events that matter, and POSTs them to the MCP receiver.

## Protocol

```
POST <HONEYPOT_ENDPOINT>/cloud-event
Content-Type: application/json
X-HoneyPot-Signature: sha256=<hex of hmac_sha256(secret, body)>
<raw cloud audit-log event as JSON>
```

The receiver:
1. Returns 503 if `cloud_event_hmac_secret` is unset (operator opted out).
2. Returns 401 on signature mismatch (compare-secure).
3. Returns 202 unconditionally on success — does **not** leak whether the
   event matched a token. Attackers who control a forwarder can't probe
   for which tokens are planted.

## Two env vars every forwarder needs

| Variable | Description |
|---|---|
| `HONEYPOT_ENDPOINT` | Base URL of your HoneyPot MCP, e.g. `https://honeypot.example.com` |
| `HONEYPOT_HMAC_SECRET` | Same value as `cloud_event_hmac_secret` in your MCP `.env` |

Store the secret in a secret manager (AWS Secrets Manager / Azure Key Vault /
GCP Secret Manager) — **not** as a plaintext env var in version control.

## Filtering philosophy

Each forwarder pre-filters to a small set of security-relevant events before
signing and POSTing:

- **AWS:** IAM activity, console logins, key creation/use, and any call
  with `errorCode` set (failures often reveal probing).
- **Azure:** RBAC role assignments, Key Vault secret access, sign-in logs.
- **GCP:** IAM/IAMCredentials/KMS calls and any event with `principalEmail`
  set (this is where service-account misuse shows up).

Forwarding every event would work but burns the MCP's rate limit (30/IP/min)
and racks up egress costs. The pre-filters are aggressive on purpose.

## Subdirectories

- [`aws/`](./aws/) — Lambda + Terraform + IAM
- [`azure/`](./azure/) — Function App + Bicep
- [`gcp/`](./gcp/) — Cloud Function (Gen2) + Pub/Sub sink

Each has its own README with deploy instructions.

## Verifying it works

After deploying, do the following:

1. Plant a cloud honeytoken via the MCP: `honeytoken_create_aws_key` (or
   `_azure_credential` / `_gcp_service_account`).
2. Trigger the credential from outside your environment — e.g. try
   `aws sts get-caller-identity` with the planted AWS keys.
3. Within ~1–5 minutes (cloud audit-log latency), the MCP should fire a
   CRITICAL alert. Check with `alerts_recent` or your subscribed SIEM.

If nothing fires, work the chain backwards: forwarder logs → MCP
`/cloud-event` receiver logs → token table. The receiver always returns
202 on success even when no match — that's by design but makes silent
failures harder to debug. Enable DEBUG logging on the MCP if you need to
see match attempts.
