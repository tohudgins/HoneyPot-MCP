"""Slack-webhook-shaped honeytoken.

Generates a URL with the Slack webhook path shape:
`https://<canary-host>/services/T<...>/B<...>/<token_id>`.

Real Slack webhooks live under `hooks.slack.com/services/`, so the path
prefix is what makes this believable — attackers who scrape git
repositories, environment files, or CI configs see the pattern and try
to POST a test message before sending the real notification. That POST
hits the canary server and triggers a CRITICAL alert.

Detection wire: identical to `tokens/canary_url.py` — the canary callback's
`/t/{token_id}` handler matches by `token_meta.token_id`. We register an
additional Slack-shaped route alongside `/t/...` in `canary.py:build_app`
so the actual `/services/T.../B.../<token_id>` path also routes to the
trigger handler.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


class SlackWebhookProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        token_id = str(uuid.uuid4())
        team_id = "T" + secrets.token_hex(4).upper()
        bot_id = "B" + secrets.token_hex(4).upper()

        canary_base = settings.canary_public_url.rstrip("/")
        # Slack-shaped path. The canary server serves this path (plus the
        # standard /t/<id> path) through the same trigger handler.
        webhook_path = f"/services/{team_id}/{bot_id}/{token_id}"
        webhook_url = f"{canary_base}{webhook_path}"

        meta = {
            "token_id": token_id,
            "team_id": team_id,
            "bot_id": bot_id,
            "webhook_path": webhook_path,
            "full_url": webhook_url,
        }
        return webhook_url, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        return (
            "Plant this Slack-shaped webhook URL where an attacker would find it:\n\n"
            f"  URL: {token_value}\n\n"
            "Real-world locations:\n"
            "  - .env / docker-compose.yml: SLACK_WEBHOOK_URL=...\n"
            "  - GitHub Actions secrets template\n"
            "  - A 'deploy-notifications.sh' script\n"
            "  - A README's 'monitoring' section\n\n"
            "An alert fires when the URL is requested — typically attackers test\n"
            "scraped webhooks with `curl -X POST <url>` before exfiltrating data\n"
            "through them, so a CRITICAL alert lands on the first probe.\n\n"
            "Note: in a real Slack deploy this URL would live under\n"
            "hooks.slack.com. The path SHAPE is identical to a real webhook,\n"
            "but the host is your canary domain. Sophisticated attackers may\n"
            "notice the host mismatch — combine with a CNAME on your canary\n"
            "domain to a Slack-lookalike subdomain for higher fidelity."
        )
