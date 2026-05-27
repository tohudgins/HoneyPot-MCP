"""drop attacker_profiles.shodan_data

Removes the unused `shodan_data` JSON column from `attacker_profiles`. Shodan
integration was removed earlier; the column had been left in place pending the
next model touch. Downgrade re-adds it with the original default so a rollback
restores the prior schema shape.

Revision ID: 0007_drop_attacker_profile_shodan_data
Revises: 0006_add_subscription_format
Create Date: 2026-05-27
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

revision = "0007_drop_attacker_profile_shodan_data"
down_revision = "0006_add_subscription_format"
branch_labels = None
depends_on = None


def _has_column(table: str, name: str) -> bool:
    """True if `table.name` already exists. See 0006 for why this guard is
    necessary — the baseline migration uses `create_all` which reflects the
    current model state, so on a fresh DB `shodan_data` is already gone."""
    return name in {c["name"] for c in inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if not _has_column("attacker_profiles", "shodan_data"):
        return
    with op.batch_alter_table("attacker_profiles") as batch_op:
        batch_op.drop_column("shodan_data")


def downgrade() -> None:
    if _has_column("attacker_profiles", "shodan_data"):
        return
    with op.batch_alter_table("attacker_profiles") as batch_op:
        batch_op.add_column(
            sa.Column(
                "shodan_data",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            )
        )
