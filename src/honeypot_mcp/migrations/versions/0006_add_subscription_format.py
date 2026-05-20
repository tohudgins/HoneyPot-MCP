"""add subscription.format column

Adds a `format` VARCHAR(32) column to the `subscriptions` table with a
server-side default of `'json'` so existing rows keep the previous
behaviour without touching them.

New rows can use one of: json, splunk_hec, elastic_ecs, cef, syslog —
see `webhooks.py` for the format-specific renderers.

Revision ID: 0006_add_subscription_format
Revises: 0005_add_cloud_honeytoken_types
Create Date: 2026-05-20
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_add_subscription_format"
down_revision = "0005_add_cloud_honeytoken_types"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "subscriptions",
        sa.Column(
            "format",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text("'json'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("subscriptions", "format")
