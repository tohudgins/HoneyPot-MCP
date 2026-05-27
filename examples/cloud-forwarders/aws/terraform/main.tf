terraform {
  required_version = ">= 1.6"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.50" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
}

variable "honeypot_endpoint" {
  description = "Base URL of your HoneyPot MCP, e.g. https://honeypot.example.com"
  type        = string
}

variable "honeypot_hmac_secret_ssm_name" {
  description = "SSM Parameter Store name holding the HMAC secret (SecureString)"
  type        = string
  default     = "/honeypot-mcp/cloud-event-hmac-secret"
}

# ── Lambda package ──────────────────────────────────────────────────────────
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda_function.py"
  output_path = "${path.module}/lambda.zip"
}

# ── IAM role ────────────────────────────────────────────────────────────────
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "forwarder" {
  name               = "honeypot-mcp-cloudtrail-forwarder"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "basic_logs" {
  role       = aws_iam_role.forwarder.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Allow reading the SSM SecureString that holds the HMAC secret.
data "aws_iam_policy_document" "ssm" {
  statement {
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:aws:ssm:*:*:parameter${var.honeypot_hmac_secret_ssm_name}"]
  }
}

resource "aws_iam_role_policy" "ssm_read" {
  role   = aws_iam_role.forwarder.id
  policy = data.aws_iam_policy_document.ssm.json
}

# ── Lambda ──────────────────────────────────────────────────────────────────
# The HMAC secret is materialised as an env var at function-create time from
# the SSM parameter. For zero-trust rotation, swap this for a runtime
# `boto3.client('ssm').get_parameter(...)` call inside the handler.
data "aws_ssm_parameter" "hmac" {
  name            = var.honeypot_hmac_secret_ssm_name
  with_decryption = true
}

resource "aws_lambda_function" "forwarder" {
  function_name    = "honeypot-mcp-cloudtrail-forwarder"
  role             = aws_iam_role.forwarder.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 10

  environment {
    variables = {
      HONEYPOT_ENDPOINT    = var.honeypot_endpoint
      HONEYPOT_HMAC_SECRET = data.aws_ssm_parameter.hmac.value
    }
  }
}

# ── EventBridge rule on CloudTrail management events ────────────────────────
resource "aws_cloudwatch_event_rule" "cloudtrail" {
  name        = "honeypot-mcp-cloudtrail-rule"
  description = "Forward security-relevant CloudTrail events to HoneyPot MCP"

  event_pattern = jsonencode({
    source        = ["aws.cloudtrail"]
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.cloudtrail.name
  arn  = aws_lambda_function.forwarder.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.forwarder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail.arn
}

output "forwarder_arn" {
  value = aws_lambda_function.forwarder.arn
}
