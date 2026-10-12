"""subscriptions.suppressed_count

A notification the throttle declined to send was recorded as a successful delivery. On the live
droplet the Slack subscription reported 13,025 "deliveries" in nine hours while it had received a
handful of messages, and each such "success" also reset `failure_count` and cleared `last_error`, so
a broken webhook would have looked healthy. Suppressed events are now counted here instead.

Idempotent per the project convention: skipped when the column already exists (a fresh database
built by 0001_baseline's create_all already has it from models.py).

Revision ID: 0018_sub_suppressed
Revises: 0017_alert_rollups
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_sub_suppressed"
down_revision = "0017_alert_rollups"
branch_labels = None
depends_on = None


def _columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if "subscriptions" not in inspector.get_table_names():
        return set()
    return {c["name"] for c in inspector.get_columns("subscriptions")}


def upgrade() -> None:
    if (
        "subscriptions" in sa.inspect(op.get_bind()).get_table_names()
        and "suppressed_count" not in _columns()
    ):
        op.add_column(
            "subscriptions",
            sa.Column("suppressed_count", sa.Integer(), nullable=False, server_default="0"),
        )


def downgrade() -> None:
    if "suppressed_count" in _columns():
        with op.batch_alter_table("subscriptions") as batch:
            batch.drop_column("suppressed_count")
