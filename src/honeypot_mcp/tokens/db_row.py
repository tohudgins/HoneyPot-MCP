"""Database-row honeytoken provider — canary rows in a real DB.

Generates a believable user record (name, email, etc.) with a unique-pattern
email address (`canary-${uid}@${your-domain}`). The operator inserts this
row into their real production database — a users table, a customer
contacts list, anywhere an attacker who exfiltrates the DB would find it.

Trigger path:

    Attacker → SELECTs the table → harvests the canary email → tries to
    phish / spam / abuse it → email lands at your domain's MX → SMTP
    honeypot captures the RCPT TO → email_match.py recognises the canary
    pattern → CRITICAL alert with honeytoken_id linked.

For this to work end-to-end the operator needs:
  1. A domain whose MX points at this project's SMTP honeypot (or a forwarder).
  2. The canary row planted in their DB.

We don't try to insert the row for them — that requires DB credentials we
shouldn't have. Instead `plant_instructions` returns the SQL they need to
run manually against their own DB.
"""

from __future__ import annotations

import random
import re
import uuid
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider

_FIRST_NAMES = (
    "James",
    "Sarah",
    "Michael",
    "Emily",
    "David",
    "Jennifer",
    "Robert",
    "Lisa",
    "John",
    "Amy",
    "Daniel",
    "Karen",
)
_LAST_NAMES = (
    "Anderson",
    "Martinez",
    "Walker",
    "Cooper",
    "Bailey",
    "Reed",
    "Foster",
    "Brooks",
    "Bennett",
    "Hayes",
    "Russell",
    "Coleman",
)


# The table name is spliced into the INSERT statement shown to the operator, and
# the domain into the canary address — both must be inert identifiers.
_TABLE_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*$")


def _valid_domain(domain: Any) -> bool:
    return (
        isinstance(domain, str) and len(domain) <= 253 and _DOMAIN_RE.fullmatch(domain) is not None
    )


def _fake_identity(seed: str) -> tuple[str, str]:
    rnd = random.Random(seed)
    return rnd.choice(_FIRST_NAMES), rnd.choice(_LAST_NAMES)


class DBRowProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        token_uid = uuid.uuid4().hex[:16]  # 16 chars is plenty for uniqueness
        domain = options.get("domain")
        if domain and not _valid_domain(domain):
            raise ValueError("db_row domain must be a hostname such as 'corp.example'")
        if not domain:
            from honeypot_mcp.config import get_settings

            # Derive domain from canary_public_url if not specified.
            settings = get_settings()
            base = (
                settings.canary_public_url.replace("http://", "")
                .replace("https://", "")
                .split(":")[0]
                .split("/")[0]
            )
            domain = base if _valid_domain(base) else "example.com"

        first, last = _fake_identity(token_uid)
        canary_email = f"canary-{token_uid}@{domain}"

        # Build a plausible canary record. The operator picks which columns
        # apply to their schema — we generate a kitchen-sink dict they can
        # cherry-pick from when they write the INSERT.
        canary_row = {
            "email": canary_email,
            "first_name": first,
            "last_name": last,
            "full_name": f"{first} {last}",
            "username": f"{first.lower()}.{last.lower()}",
            "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
            "company": options.get("company", "Internal Corp"),
            "notes": "VIP — exec contact, please escalate any inquiries",
        }

        table_hint = options.get("table", "users")
        if not isinstance(table_hint, str) or not _TABLE_RE.fullmatch(table_hint):
            raise ValueError("db_row table must be 1-64 characters of letters, digits or '_'")

        meta = {
            "token_uid": token_uid,
            "canary_email": canary_email,
            "row_data": canary_row,
            "target_table": table_hint,
            "domain": domain,
        }
        return canary_email, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        row = metadata.get("row_data", {})
        table = metadata.get("target_table", "users")
        email = metadata.get("canary_email", token_value)
        domain = metadata.get("domain", "your-domain.example")

        sql_cols = ", ".join(row.keys())
        sql_vals = ", ".join(f"'{str(v).replace(chr(39), chr(39) * 2)}'" for v in row.values())
        sql = f"INSERT INTO {table} ({sql_cols})\nVALUES ({sql_vals});"

        return (
            f"Database-row honeytoken created.\n\n"
            f"  Canary email: {email}\n"
            f"  Target table: {table} (rename to match your schema)\n\n"
            f"Step 1 — run this SQL against your production DB (drop columns\n"
            f"your schema doesn't have):\n\n"
            f"{sql}\n\n"
            f"Step 2 — ensure mail to {domain} routes to the SMTP honeypot:\n"
            f"  • Point your domain's MX record at the SMTP honeypot host, OR\n"
            f"  • Configure your real mailserver to forward {email} traffic\n"
            f"    to the SMTP honeypot, OR\n"
            f"  • Run a Postfix transport_map entry that pipes\n"
            f"    canary-* users to the honeypot.\n\n"
            f"The trigger fires when an attacker who exfiltrated the DB tries\n"
            f"to spam, phish, or otherwise use {email}. The SMTP honeypot\n"
            f"captures the RCPT TO, email_match.py recognises the canary-*\n"
            f"pattern, the alert is escalated to CRITICAL and linked to this\n"
            f"honeytoken.\n\n"
            f"Don't add 'canary' or 'honeypot' anywhere visible in your DB schema —\n"
            f"the unique token UID in the email is what we match on; the local\n"
            f"part is intentionally generic-looking."
        )
