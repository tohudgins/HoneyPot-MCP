"""add RDP honeypot type

Adds `rdp` to the `HoneypotType` enum. On SQLite this is a no-op because
the engine doesn't enforce enum CHECK constraints by default. On Postgres
this drops and re-creates the constraint to include the new value.

Revision ID: 0002_add_rdp_honeypot_type
Revises: 0001_baseline
Create Date: 2026-05-15
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0002_add_rdp_honeypot_type"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


# Allowed values for HoneypotType after this migration.
_POST_VALUES = ("ssh", "http", "smtp", "ftp", "dns", "rdp")
_PRE_VALUES = ("ssh", "http", "smtp", "ftp", "dns")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    dialect = _dialect(bind)
    if dialect == "postgresql":
        # Postgres uses a real enum type — extend it in place.
        # Use ALTER TYPE … ADD VALUE which is the idiomatic upgrade path.
        # `IF NOT EXISTS` keeps the migration idempotent against pre-Alembic
        # databases that already added rdp manually.
        op.execute("ALTER TYPE honeypottype ADD VALUE IF NOT EXISTS 'rdp'")
    # SQLite (and most other backends): no schema change required because
    # the enum is enforced via a CHECK constraint that the baseline migration
    # built from Base.metadata, which already includes rdp once the model
    # is updated. We rely on the running app's model to be the source of
    # truth for new deployments.


def downgrade() -> None:
    bind = op.get_bind()
    dialect = _dialect(bind)
    if dialect == "postgresql":
        # Postgres doesn't support removing enum values cleanly. The downgrade
        # path is to recreate the type without `rdp` and migrate columns —
        # we don't ship that because it would orphan any RDP honeypot rows.
        # If you really need to downgrade, drop RDP rows first manually then
        # run a custom migration.
        raise NotImplementedError(
            "Downgrading past 0002_add_rdp_honeypot_type requires manual "
            "intervention on Postgres — drop RDP rows first."
        )
    # SQLite: no-op (no CHECK constraint enforcement on enum strings).
