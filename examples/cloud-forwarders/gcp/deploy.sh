#!/usr/bin/env bash
# Deploy the GCP audit log forwarder. Uses gcloud CLI; equivalent
# Terraform left as an exercise (template at bottom of this file).
#
# Usage:
#   HONEYPOT_ENDPOINT=https://honeypot.example.com \
#   HONEYPOT_HMAC_SECRET='<secret>' \
#   GCP_PROJECT=my-project \
#   ./deploy.sh

set -euo pipefail

: "${HONEYPOT_ENDPOINT:?must be set}"
: "${HONEYPOT_HMAC_SECRET:?must be set}"
: "${GCP_PROJECT:?must be set}"

TOPIC="honeypot-mcp-audit-log"
SINK="honeypot-mcp-audit-sink"
FUNCTION="honeypot-mcp-forwarder"
REGION="${REGION:-us-central1}"

# Service filter — adjust to taste. The function does another in-process
# filter against _INTERESTING_SERVICES, so a wider sink here is fine.
LOG_FILTER='protoPayload.serviceName=("iam.googleapis.com" OR "iamcredentials.googleapis.com" OR "cloudkms.googleapis.com" OR "secretmanager.googleapis.com") AND protoPayload.authenticationInfo.principalEmail != ""'

# 1. Pub/Sub topic
gcloud pubsub topics create "${TOPIC}" --project="${GCP_PROJECT}" 2>/dev/null || true

# 2. Log sink — note the use of --include-children for org/folder sinks
gcloud logging sinks create "${SINK}" \
  "pubsub.googleapis.com/projects/${GCP_PROJECT}/topics/${TOPIC}" \
  --log-filter="${LOG_FILTER}" \
  --project="${GCP_PROJECT}" \
  --quiet 2>/dev/null || true

# Grant the sink's service account publish rights
SINK_SA=$(gcloud logging sinks describe "${SINK}" --project="${GCP_PROJECT}" --format='value(writerIdentity)')
gcloud pubsub topics add-iam-policy-binding "${TOPIC}" \
  --member="${SINK_SA}" \
  --role="roles/pubsub.publisher" \
  --project="${GCP_PROJECT}" \
  --quiet

# 3. Cloud Function (Gen2) — Python 3.11
gcloud functions deploy "${FUNCTION}" \
  --gen2 \
  --runtime=python311 \
  --region="${REGION}" \
  --source=. \
  --entry-point=forwarder \
  --trigger-topic="${TOPIC}" \
  --set-env-vars="HONEYPOT_ENDPOINT=${HONEYPOT_ENDPOINT},HONEYPOT_HMAC_SECRET=${HONEYPOT_HMAC_SECRET}" \
  --project="${GCP_PROJECT}"

echo "Done. Function ${FUNCTION} now consumes ${TOPIC} and forwards to ${HONEYPOT_ENDPOINT}/cloud-event"
