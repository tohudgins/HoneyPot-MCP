#!/usr/bin/env bash
# Create a decoy GCP service account with NO roles and download its key, to adopt as a honeytoken.
#
# A generated service-account JSON names an account that does not exist, so its use is not
# written to Cloud Audit Logs under any principal. A real account with no roles still
# authenticates, and every call it makes (all denied) is logged with its client_email and the
# caller's IP, which the forwarder in this directory relays.
#
#   ./decoy_sa.sh my-project svc-backup-prod key.json
#
# then, in your agent:
#   honeytoken_create(type="gcp_service_account", label=..., metadata={
#       "service_account_json": "<contents of key.json>"})
# and delete key.json from this machine.
#
# Requires: gcloud, authenticated, with iam.serviceAccounts.create on the project.
set -euo pipefail

project="${1:?usage: decoy_sa.sh <project> <account-id> <key-file>}"
account="${2:?usage: decoy_sa.sh <project> <account-id> <key-file>}"
keyfile="${3:?usage: decoy_sa.sh <project> <account-id> <key-file>}"

gcloud iam service-accounts create "$account" --project "$project" \
  --display-name "$account" --description "honeytoken - no roles by design"
umask 077
gcloud iam service-accounts keys create "$keyfile" \
  --iam-account "$account@$project.iam.gserviceaccount.com" --project "$project"
echo "Key written to $keyfile (mode 600). No roles were granted." >&2
