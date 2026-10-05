#!/usr/bin/env bash
# Pre-flight checks before exposing a HoneyPot MCP deployment to the internet.
#
#   scripts/preflight.sh --ports 22,80,3389 \
#       --metrics-url http://127.0.0.1:9090 \
#       --mcp-url http://127.0.0.1:8000/mcp --token "$OPERATOR_TOKEN" \
#       --backup-dir /var/backups/honeypot
#
# Static checks (config, bind addresses, token strength, disk, ports, Docker) always run;
# --metrics-url and --mcp-url add the live checks against the running server. Exit status 1
# on any failure, so it can gate a deploy. See `--help` and docs/DEPLOY.md ("Go-live checklist").
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run python -m honeypot_mcp.preflight "$@"
