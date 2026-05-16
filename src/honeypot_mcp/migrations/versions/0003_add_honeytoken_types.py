"""add ssh_key, jwt, db_row honeytoken types

Adds `ssh_key`, `jwt`, `db_row` to the `HoneytokenType` enum. SQLite is a
no-op (the engine doesn't enforce enum CHECK constraints by default);
Postgres extends the enum in place.

Revision ID: 0003_add_honeytoken_types
Revises: 0002_add_rdp_honeypot_type
Create Date: 2026-05-15
"""

from alembic import op

revision = "0003_add_honeytoken_types"
down_revision = "0002_add_rdp_honeypot_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for value in ("ssh_key", "jwt", "db_row"):
            op.execute(f"ALTER TYPE honeytokentype ADD VALUE IF NOT EXISTS '{value}'")
    # SQLite: no-op — see 0002 migration for rationale.


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        raise NotImplementedError(
            "Postgres enum value removal requires manual intervention — "
            "drop dependent rows first then recreate the type."
        )
