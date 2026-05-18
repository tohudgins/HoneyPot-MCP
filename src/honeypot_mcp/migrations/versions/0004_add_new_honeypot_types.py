"""add VNC / Redis / MySQL / Elasticsearch honeypot types

Adds four new values to the `HoneypotType` enum so the engine registry can
hand them to deploy/list/stop/clone tools without the enum-conversion errors
that would otherwise hit Postgres at runtime.

On SQLite this is a no-op (no CHECK constraint enforcement on enum strings).
On Postgres we use `ALTER TYPE … ADD VALUE IF NOT EXISTS` which is the
idiomatic in-place extension path, the same pattern as 0002 / 0003.

Revision ID: 0004_add_new_honeypot_types
Revises: 0003_add_honeytoken_types
Create Date: 2026-05-18
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0004_add_new_honeypot_types"
down_revision = "0003_add_honeytoken_types"
branch_labels = None
depends_on = None


_NEW_VALUES = ("vnc", "redis", "mysql", "elasticsearch")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        for value in _NEW_VALUES:
            op.execute(f"ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS '{value}'")
    # SQLite: no-op — the enum is enforced via a CHECK constraint that
    # `Base.metadata.create_all` rebuilds from the current model, which
    # already lists the new values once models.py is updated.


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        # Postgres doesn't support removing enum values cleanly. Downgrading
        # would orphan any honeypot rows of these types — manual surgery is
        # required if you really need it.
        raise NotImplementedError(
            "Downgrading past 0004_add_new_honeypot_types requires manual "
            "intervention on Postgres — drop affected honeypot rows first."
        )
    # SQLite: no-op.
