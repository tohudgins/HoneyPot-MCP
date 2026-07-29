"""add telnet, memcached, snmp, ldap and docker_api honeypot types

Adds five values to the `HoneypotType` enum. SQLite no-op (create_all rebuilds
the CHECK constraint from models.py); Postgres uses ALTER TYPE ADD VALUE, same
pattern as 0004 / 0008 / 0009.

Note the separate `op.execute` per value: Postgres will not accept several
ADD VALUEs in one statement, and before PG12 could not run them inside a
transaction at all.

Revision ID: 0012_add_five_types
Revises: 0011_add_triage_and_audit_log
Create Date: 2026-07-29
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0012_add_five_types"
down_revision = "0011_add_triage_and_audit_log"
branch_labels = None
depends_on = None

_NEW_TYPES = ("telnet", "memcached", "snmp", "ldap", "docker_api")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        for value in _NEW_TYPES:
            op.execute(f"ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS '{value}'")
    # SQLite: no-op.


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        raise NotImplementedError(
            "Downgrading past 0012_add_five_types requires manual intervention "
            "on Postgres — drop affected honeypot rows first."
        )
    # SQLite: no-op.
