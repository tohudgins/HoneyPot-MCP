# Azure Activity Log forwarder

Deploys an Azure Function (Python v2 model) that consumes Activity Log via
an Event Hub and forwards security-relevant entries to your HoneyPot MCP.

## Prerequisites

- Azure subscription where you can create resource groups + diagnostic
  settings.
- An MCP deployment with `cloud_event_hmac_secret` set in `.env`.
- The Azure Functions Core Tools (`func`) if deploying the code separately
  from the infrastructure.

## Deploy

```bash
# 1. Provision infrastructure (resource group, Event Hub, Function App,
#    diagnostic setting) — uses subscription-scope Bicep
az deployment sub create \
  --location eastus \
  --template-file deploy.bicep \
  --parameters honeypotEndpoint=https://honeypot.example.com \
               honeypotHmacSecret='<secret-from-mcp-env>'

# 2. Deploy the function code
cd examples/cloud-forwarders/azure
func azure functionapp publish honeypot-mcp-forwarder --python
```

> `deploy.bicep` references a sibling `function.bicep` that you'll need to
> author to taste — the recommended split keeps subscription-scope
> resources (the diagnostic setting) and resource-group-scope resources
> (the function, storage, Event Hub) cleanly separated. A minimal
> `function.bicep` provisions: a v3 storage account, an Event Hub
> namespace + hub named `honeypot-mcp-activity-log`, a Linux Consumption
> plan, and a Function App with the two env vars set. Export
> `ehAuthRuleId` and `eventHubName` so `deploy.bicep` can wire the
> diagnostic setting.

## What gets forwarded

See `_INTERESTING_OPERATION_PREFIXES` in `function_app.py`. By default:

- `Microsoft.Authorization/*` — RBAC role assignments, eligibility, etc.
- `Microsoft.KeyVault/vaults/secrets/*` — secret reads.
- `Microsoft.Storage/storageAccounts/listKeys` — key recovery (classic
  exfil technique).
- `Microsoft.Resources/deployments/*` — ARM deployment activity.
- Any record in the `SignInLogs` or `AuditLogs` category.
- Any record with `status.value == "failed"`.

## Cost notes

Event Hub Basic tier (cheapest) is sufficient for activity log volume.
Function App Consumption plan is effectively free at this scale (~few
thousand executions/day). The main cost is the diagnostic setting itself —
free for subscription-level activity logs.

## Testing

```bash
# Trigger a benign administrative event
az role assignment list --all -o table >/dev/null
```

Should generate a `Microsoft.Authorization/roleAssignments/read` event
within 1–3 minutes; check the Function App's Application Insights traces
for the `INFO Forwarded operation=... status=202` line.
