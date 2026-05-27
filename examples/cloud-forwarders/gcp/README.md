# GCP Cloud Audit Log forwarder

Deploys a Cloud Function (Gen2, Python 3.11) that consumes Cloud Audit
Logs via Pub/Sub and forwards security-relevant entries to your
HoneyPot MCP.

## Architecture

```
   Cloud Audit Logs
        │
        ▼
   Logging sink (filter: IAM / IAMCredentials / KMS / Secret Manager)
        │
        ▼
   Pub/Sub topic   ──►   Cloud Function (Gen2)   ──►   MCP /cloud-event
```

## Prerequisites

- GCP project with audit logs enabled (Data Access logs need
  explicit opt-in per service — see [GCP docs](https://cloud.google.com/logging/docs/audit/configure-data-access)).
- An MCP deployment with `cloud_event_hmac_secret` set.
- `gcloud` CLI authenticated against the target project.

## Deploy

```bash
cd examples/cloud-forwarders/gcp
chmod +x deploy.sh
HONEYPOT_ENDPOINT=https://honeypot.example.com \
HONEYPOT_HMAC_SECRET='<secret-from-mcp-env>' \
GCP_PROJECT=my-project \
./deploy.sh
```

The script:
1. Creates a Pub/Sub topic `honeypot-mcp-audit-log`.
2. Creates a Logging sink that filters to interesting services and
   publishes matching entries to the topic.
3. Grants the sink's writer-identity service account publish rights on the
   topic.
4. Deploys the Cloud Function with the env vars set.

## What gets forwarded

The sink filter is broader than the in-function `_INTERESTING_SERVICES`
allow-list — the sink uses a Logging filter expression (efficient at scale)
and the function applies a final narrower check. Edit `LOG_FILTER` in
`deploy.sh` to extend or restrict.

The function also drops events without `authenticationInfo.principalEmail`
because honeytokens only match on principal — system/anonymous calls
can't trigger them anyway.

## Cost notes

- Logging sink → Pub/Sub: free.
- Pub/Sub: $40 / TiB of throughput. Audit log traffic for a typical
  project is well under 1 GiB/month.
- Cloud Function: free tier covers 2 million invocations/month. Audit log
  volume is normally a few hundred per day.

## Testing

```bash
# Generate a benign IAM event
gcloud iam service-accounts list --project="${GCP_PROJECT}" >/dev/null
```

Should generate a `iam.googleapis.com/google.iam.admin.v1.IAM.ListServiceAccounts`
audit entry within ~1 minute. Check Cloud Functions logs:

```bash
gcloud functions logs read honeypot-mcp-forwarder --region=us-central1 --limit=20
```

Look for the `INFO Forwarded method=... status=202` line.
