"""add imap, sip, rsync and nfs honeypot types

SQLite no-op (create_all rebuilds the CHECK constraint from models.py);
Postgres uses ALTER TYPE ADD VALUE, one statement per value — it will not
accept several in one, and before PG12 could not run them in a transaction.

Revision ID: 0013_add_four_types
Revises: 0012_add_five_types
Create Date: 2026-07-29
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0013_add_four_types"
down_revision = "0012_add_five_types"
branch_labels = None
depends_on = None

_NEW_TYPES = ("imap", "sip", "rsync", "nfs")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        for value in _NEW_TYPES:
            op.execute(f"ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS '{value}'")


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        raise NotImplementedError(
            "Downgrading past 0013_add_four_types requires manual intervention "
            "on Postgres — drop affected honeypot rows first."
        )
