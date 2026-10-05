#!/usr/bin/env bash
# Create a decoy Entra ID service principal with NO role assignments, to adopt as a honeytoken.
#
# A generated client_id is not an application Entra ID knows, so a sign-in with it cannot be
# tied to anything. A real app registration that has no permissions still authenticates (and
# is logged in the sign-in logs by appId, with the caller's IP) when someone tries it.
#
#   ./decoy_sp.sh svc-backup-prod
#
# then, in your agent:
#   honeytoken_create(type="azure_credential", label=..., metadata={
#       "client_id": "<appId>", "client_secret": "<password>", "tenant_id": "<tenant>"})
#
# Requires: az CLI, logged in with permission to create app registrations.
set -euo pipefail

name="${1:?usage: decoy_sp.sh <display-name>}"

# --skip-assignment: no role on any scope. The secret is shown once; copy it now.
az ad sp create-for-rbac --name "$name" --skip-assignment --years 2 \
  --query '{client_id: appId, client_secret: password, tenant_id: tenant}' -o json
