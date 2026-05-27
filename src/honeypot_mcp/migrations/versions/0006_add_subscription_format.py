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
from sqlalchemy import inspect

revision = "0006_add_subscription_format"
down_revision = "0005_add_cloud_honeytoken_types"
branch_labels = None
depends_on = None


def _has_column(table: str, name: str) -> bool:
    """True if `table.name` already exists in the live schema.

    Needed because `0001_baseline` builds the schema from the *current*
    `Base.metadata` rather than the schema as it was at the time 0001 was
    written. Fresh DBs therefore already have every column the model
    defines today; this migration's ALTER TABLE would fail on them
    without this guard.
    """
    return name in {c["name"] for c in inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    if _has_column("subscriptions", "format"):
        return
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
    if not _has_column("subscriptions", "format"):
        return
    op.drop_column("subscriptions", "format")
