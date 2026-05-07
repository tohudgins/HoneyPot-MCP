"""baseline schema

Captures the schema as it stands at the introduction of Alembic. Uses
`Base.metadata.create_all` so the migration is idempotent — if tables
already exist (an upgrade from a pre-Alembic DB), this is a no-op and
just stamps the alembic_version row. Fresh DBs get the full schema.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-05-06
"""

from alembic import op

from honeypot_mcp.storage.models import Base

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
