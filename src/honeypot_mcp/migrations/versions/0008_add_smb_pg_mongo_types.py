"""add SMB / PostgreSQL / MongoDB honeypot types

Adds three new values to the `HoneypotType` enum so the engine registry can
hand them to deploy/list/stop/clone tools without enum-conversion errors on
Postgres.

On SQLite this is a no-op (the enum is a CHECK constraint that
`create_all` rebuilds from the current model). On Postgres we use
`ALTER TYPE … ADD VALUE IF NOT EXISTS`, same pattern as 0004.

Revision ID: 0008_add_smb_pg_mongo_types
Revises: 0007_drop_profile_shodan
Create Date: 2026-07-03
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0008_add_smb_pg_mongo_types"
down_revision = "0007_drop_profile_shodan"
branch_labels = None
depends_on = None


_NEW_VALUES = ("smb", "postgresql", "mongodb")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        for value in _NEW_VALUES:
            op.execute(f"ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS '{value}'")
    # SQLite: no-op — create_all rebuilds the CHECK constraint from models.py.


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        raise NotImplementedError(
            "Downgrading past 0008_add_smb_pg_mongo_types requires manual "
            "intervention on Postgres — drop affected honeypot rows first."
        )
    # SQLite: no-op.
