"""add pop3 and kubernetes honeypot types

SQLite no-op; Postgres uses ALTER TYPE ADD VALUE, one statement per value.

Revision ID: 0014_add_two_types
Revises: 0013_add_four_types
Create Date: 2026-07-29
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0014_add_two_types"
down_revision = "0013_add_four_types"
branch_labels = None
depends_on = None

_NEW_TYPES = ("pop3", "kubernetes")


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
            "Downgrading past 0014_add_two_types requires manual intervention "
            "on Postgres — drop affected honeypot rows first."
        )
