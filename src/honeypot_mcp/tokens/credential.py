"""Fake credential honeytoken provider."""

from __future__ import annotations

import random
import secrets
import string
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_USERNAMES = [
    "admin", "administrator", "root", "sysadmin", "devops", "deploy",
    "ftpuser", "backup", "webmaster", "dbadmin", "mysql", "postgres",
    "ubuntu", "ec2-user", "ansible", "jenkins", "gitlab", "docker",
]

_PASSWORD_PATTERNS = [
    lambda: f"{''.join(random.choices(string.ascii_letters + string.digits, k=12))}!",
    lambda: f"{''.join(random.choices(string.ascii_lowercase, k=8))}{''.join(random.choices(string.digits, k=4))}",
    lambda: f"P@ssw0rd{random.randint(100, 999)}",
    lambda: f"{''.join(random.choices(string.ascii_letters, k=6))}_{random.randint(10, 99)}!",
    lambda: f"{''.join(random.choices(string.ascii_lowercase + string.digits + '!@#$', k=16))}",
]


def _generate_pair(service: str) -> dict[str, str]:
    username = random.choice(_USERNAMES)
    password = random.choice(_PASSWORD_PATTERNS)()
    return {"username": username, "password": password, "service": service}


class CredentialProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        service = options.get("service", "ssh")
        count = min(int(options.get("count", 1)), 20)

        pairs = [_generate_pair(service) for _ in range(count)]
        token_value = f"cred:{secrets.token_hex(16)}"

        meta = {
            "service": service,
            "credentials": pairs,
            "count": count,
        }
        return token_value, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        service = metadata.get("service", "ssh")
        creds = metadata.get("credentials", [])

        lines = [f"Plant these fake {service} credentials in a target location:\n"]
        for c in creds[:5]:
            lines.append(f"  {c['username']} : {c['password']}")

        lines.append(
            f"\nIdeas:\n"
            f"  - Add to /etc/shadow or a fake passwd file on a honeypot\n"
            f"  - Place in a 'passwords.txt' file in a shared drive\n"
            f"  - Embed in a config file on a web honeypot\n"
            f"  - Plant in a Git repository's commit history\n\n"
            f"Alerts fire when these credentials are used on any honeypot."
        )
        return "\n".join(lines)
