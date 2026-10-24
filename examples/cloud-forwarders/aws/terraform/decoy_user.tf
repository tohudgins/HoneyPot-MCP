# A decoy IAM user whose access key becomes a honeytoken.
#
# Why this exists: a randomly generated AKIA... string is not a key AWS knows about, so
# using it leaves no CloudTrail trail and nothing for the forwarder to relay. A key that
# IAM issued is observable: every call made with it (including the AccessDenied it will
# get, because this user is denied everything) is written to CloudTrail with the caller's
# source IP, and the forwarder in main.tf relays it to HoneyPot MCP.
#
#   terraform apply -var honeypot_endpoint=https://honeypot.example.com
#   terraform output -raw decoy_access_key_id
#   terraform output -raw decoy_secret_access_key
#
# then, in your agent:  honeytoken_create(type="api_key", label=..., metadata={"access_key_id": ..., "secret_access_key": ...})
#
# The secret lands in Terraform state: keep the state private, and do not commit it.

variable "decoy_user_name" {
  description = "Name of the decoy IAM user. Pick something an attacker would value (e.g. svc-backup-prod)."
  type        = string
  default     = "svc-backup-prod"
}

resource "aws_iam_user" "decoy" {
  name = var.decoy_user_name
  path = "/service/"
  tags = { purpose = "honeytoken" }
}

# Explicit deny-all: the key can authenticate but can do nothing, ever.
resource "aws_iam_user_policy" "deny_all" {
  name = "deny-everything"
  user = aws_iam_user.decoy.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_access_key" "decoy" {
  user = aws_iam_user.decoy.name
}

output "decoy_access_key_id" {
  value = aws_iam_access_key.decoy.id
}

output "decoy_secret_access_key" {
  value     = aws_iam_access_key.decoy.secret
  sensitive = true
}
