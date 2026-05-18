"""add cloud-era honeytoken types

Adds KUBECONFIG, SLACK_WEBHOOK, AZURE_CREDENTIAL, GCP_SERVICE_ACCOUNT
to the `HoneytokenType` enum. Same shape as 0003_add_honeytoken_types.py.

Revision ID: 0005_add_cloud_honeytoken_types
Revises: 0004_add_new_honeypot_types
Create Date: 2026-05-18
"""

from alembic import op
from sqlalchemy.engine import Connection

revision = "0005_add_cloud_honeytoken_types"
down_revision = "0004_add_new_honeypot_types"
branch_labels = None
depends_on = None


_NEW_VALUES = ("kubeconfig", "slack_webhook", "azure_credential", "gcp_service_account")


def _dialect(bind: Connection) -> str:
    return bind.dialect.name


def upgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        for value in _NEW_VALUES:
            op.execute(f"ALTER TYPE honeytokentype ADD VALUE IF NOT EXISTS '{value}'")
    # SQLite no-op — see comments on 0002 / 0004 for the rationale.


def downgrade() -> None:
    bind = op.get_bind()
    if _dialect(bind) == "postgresql":
        raise NotImplementedError(
            "Downgrading past 0005_add_cloud_honeytoken_types requires manual "
            "intervention on Postgres — drop affected honeytoken rows first."
        )
