"""add MSSQL honeypot type

Adds `mssql` to the `HoneypotType` enum. SQLite no-op (create_all rebuilds the
CHECK constraint from models.py); Postgres uses ALTER TYPE ADD VALUE, same
pattern as 0004 / 0008.

Revision ID: 0009_add_mssql_type
Revises: 0008_add_smb_pg_mongo_types
Create Date: 2026-07-03
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0009_add_mssql_type"
down_revision = "0008_add_smb_pg_mongo_types"
branch_labels = None
depends_on = None


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        op.execute("ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS 'mssql'")
    # SQLite: no-op.


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        raise NotImplementedError(
            "Downgrading past 0009_add_mssql_type requires manual intervention "
            "on Postgres — drop affected honeypot rows first."
        )
    # SQLite: no-op.
