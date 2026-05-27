# AWS CloudTrail forwarder

Deploys a Lambda that watches CloudTrail via EventBridge, filters to
security-relevant events, and POSTs them to your HoneyPot MCP's
`/cloud-event` endpoint.

## Prerequisites

- AWS account with CloudTrail enabled (the default trail is fine — it
  emits to EventBridge).
- An MCP deployment with `cloud_event_hmac_secret` set in `.env`.
- The HMAC secret stored in SSM Parameter Store as a SecureString.

## Quickstart with Terraform

```bash
# 1. Put the secret in SSM (one-time)
aws ssm put-parameter \
  --name /honeypot-mcp/cloud-event-hmac-secret \
  --type SecureString \
  --value "<the secret from your MCP .env>" \
  --tier Standard

# 2. Deploy
cd examples/cloud-forwarders/aws/terraform
terraform init
terraform apply -var "honeypot_endpoint=https://honeypot.example.com"
```

That's it. Within a few minutes CloudTrail events start hitting your MCP.

## Manual CLI fallback (no Terraform)

If you don't run Terraform, the same setup in three commands:

```bash
# Package the Lambda
cd examples/cloud-forwarders/aws
zip lambda.zip lambda_function.py

# Create the function
aws lambda create-function \
  --function-name honeypot-mcp-cloudtrail-forwarder \
  --runtime python3.12 \
  --role arn:aws:iam::ACCOUNT_ID:role/lambda-basic-execution \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda.zip \
  --environment Variables="{HONEYPOT_ENDPOINT=https://honeypot.example.com,HONEYPOT_HMAC_SECRET=...}"

# Create the EventBridge rule + target
aws events put-rule \
  --name honeypot-mcp-cloudtrail \
  --event-pattern '{"source":["aws.cloudtrail"]}'

aws events put-targets \
  --rule honeypot-mcp-cloudtrail \
  --targets "Id=1,Arn=arn:aws:lambda:REGION:ACCOUNT_ID:function:honeypot-mcp-cloudtrail-forwarder"

aws lambda add-permission \
  --function-name honeypot-mcp-cloudtrail-forwarder \
  --statement-id AllowEventBridge \
  --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:REGION:ACCOUNT_ID:rule/honeypot-mcp-cloudtrail
```

## What gets forwarded

The Lambda filters by `eventName` — see `_INTERESTING_EVENT_NAMES` in
`lambda_function.py`. Adjust to taste. Events with `errorCode` set are
always forwarded regardless of name — failed calls often reveal probing.

## Cost notes

- EventBridge: free for AWS service events.
- Lambda: $0.20 per million requests + tiny compute time. A typical AWS
  account generates a few thousand interesting CloudTrail events per day;
  cost should be cents/month.
- Egress to your MCP: depends on your network setup — internal VPC routing
  is free, public HTTPS is standard egress pricing.

## Testing

After deploy, smoke-test by triggering an event the filter catches:

```bash
aws sts get-session-token --output text >/dev/null
```

Within 1–5 minutes the Lambda should run. Check CloudWatch Logs for
`/aws/lambda/honeypot-mcp-cloudtrail-forwarder` — you should see an
`INFO Forwarded eventName=GetSessionToken status=202` line. If MCP receives
nothing, see the project root `examples/cloud-forwarders/README.md`
troubleshooting section.
