"""Fake credential honeytoken provider."""

from __future__ import annotations

import secrets
import string
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_USERNAMES = [
    "admin",
    "administrator",
    "root",
    "sysadmin",
    "devops",
    "deploy",
    "ftpuser",
    "backup",
    "webmaster",
    "dbadmin",
    "mysql",
    "postgres",
    "ubuntu",
    "ec2-user",
    "ansible",
    "jenkins",
    "gitlab",
    "docker",
]

def _rand_str(pool: str, k: int) -> str:
    return "".join(secrets.choice(pool) for _ in range(k))


_PASSWORD_PATTERNS = [
    lambda: f"{_rand_str(string.ascii_letters + string.digits, 12)}!",
    lambda: f"{_rand_str(string.ascii_lowercase, 8)}{_rand_str(string.digits, 4)}",
    lambda: f"P@ssw0rd{secrets.randbelow(900) + 100}",
    lambda: f"{_rand_str(string.ascii_letters, 6)}_{secrets.randbelow(90) + 10}!",
    lambda: f"{_rand_str(string.ascii_lowercase + string.digits + '!@#$', 16)}",
]


def _generate_pair(service: str) -> dict[str, str]:
    username = secrets.choice(_USERNAMES)
    password = secrets.choice(_PASSWORD_PATTERNS)()
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
            "\nIdeas:\n"
            "  - Add to /etc/shadow or a fake passwd file on a honeypot\n"
            "  - Place in a 'passwords.txt' file in a shared drive\n"
            "  - Embed in a config file on a web honeypot\n"
            "  - Plant in a Git repository's commit history\n\n"
            "Alerts fire when these credentials are used on any honeypot."
        )
        return "\n".join(lines)
