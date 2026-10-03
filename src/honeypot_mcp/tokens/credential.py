"""Fake credential honeytoken provider."""

from __future__ import annotations

import random
import re
import secrets
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


# Usernames stay plausible (an attacker working a service-account list should
# find them believable), but each is suffixed with a random tag. Bare stock names
# — `admin`, `root`, `postgres` — are what every scanner tries first, and two
# tokens sharing `(service, username)` would be indistinguishable on replay.
_USERNAME_TAG_BYTES = 2  # 4 hex chars → 65,536 variants per stock name

# Unambiguous alphabets: no 0/O, 1/l/I — a planted password is retyped by people.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGITS = "23456789"
# Symbols that survive URL-encoded forms, shells and SQL without quoting rules.
_SYMBOLS = "!@#$*-_"
_PASSWORD_MIN_LEN = 16
_PASSWORD_MAX_LEN = 20

_MAX_USERNAME_LEN = 64
_CONTROL_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f]")
_SYSTEM_RANDOM = random.SystemRandom()


def _generate_password() -> str:
    """A password a scanner cannot reach by guessing.

    These are one-shot tripwires: a dictionary-guessable password (the former
    `P@ssw0rd123` pattern) lets an ordinary brute-force run trip the token with
    a false CRITICAL. 16-20 characters drawn with `secrets` from a mixed
    alphabet with every class present is far outside any wordlist.
    """
    length = _PASSWORD_MIN_LEN + secrets.randbelow(_PASSWORD_MAX_LEN - _PASSWORD_MIN_LEN + 1)
    chars = [
        secrets.choice(_UPPER),
        secrets.choice(_LOWER),
        secrets.choice(_DIGITS),
        secrets.choice(_SYMBOLS),
    ]
    pool = _UPPER + _LOWER + _DIGITS + _SYMBOLS
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    _SYSTEM_RANDOM.shuffle(chars)
    return "".join(chars)


def _generate_username() -> str:
    return f"{secrets.choice(_USERNAMES)}_{secrets.token_hex(_USERNAME_TAG_BYTES)}"


def _validate_username(username: Any) -> str:
    if not isinstance(username, str) or not username:
        raise ValueError("credential username must be a non-empty string")
    if len(username) > _MAX_USERNAME_LEN:
        raise ValueError(f"credential username must be at most {_MAX_USERNAME_LEN} characters")
    if _CONTROL_CHARS.search(username):
        raise ValueError("credential username must not contain whitespace or control characters")
    return username


def _generate_pair(service: str, username: str | None = None) -> dict[str, str]:
    return {
        "username": username if username is not None else _generate_username(),
        "password": _generate_password(),
        "service": service,
    }


class CredentialProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        service = options.get("service", "ssh")
        count = int(options.get("count", 1))
        if count < 1:
            raise ValueError("credential count must be at least 1")
        count = min(count, 20)
        # A caller-chosen username (the deception planner pins one so the plan
        # and the created token agree) is used as given; otherwise each pair gets
        # a generated one.
        chosen = options.get("username")
        username = _validate_username(chosen) if chosen is not None else None

        pairs = [_generate_pair(service, username) for _ in range(count)]
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
