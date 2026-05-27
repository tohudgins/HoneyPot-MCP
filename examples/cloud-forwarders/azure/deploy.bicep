// Azure Activity Log → HoneyPot MCP forwarder
//
// Provisions: storage account, Event Hub namespace + hub, Function App
// (Linux consumption plan, Python 3.11), and the diagnostic setting that
// routes Activity Log into the Event Hub.
//
// Deploy:
//   az deployment sub create \
//     --location eastus \
//     --template-file deploy.bicep \
//     --parameters honeypotEndpoint=https://honeypot.example.com \
//                  honeypotHmacSecret='<secret>'

targetScope = 'subscription'

param location string = 'eastus'
param resourceGroupName string = 'honeypot-mcp-forwarder'
param honeypotEndpoint string

@secure()
param honeypotHmacSecret string

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module fwd './function.bicep' = {
  scope: rg
  name: 'forwarder'
  params: {
    location: location
    honeypotEndpoint: honeypotEndpoint
    honeypotHmacSecret: honeypotHmacSecret
  }
}

resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'honeypot-mcp-activity-log'
  scope: subscription()
  properties: {
    eventHubAuthorizationRuleId: fwd.outputs.ehAuthRuleId
    eventHubName: fwd.outputs.eventHubName
    logs: [
      { category: 'Administrative', enabled: true }
      { category: 'Security', enabled: true }
    ]
  }
}
