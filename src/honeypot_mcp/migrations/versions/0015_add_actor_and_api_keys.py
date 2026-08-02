"""add audit_log.actor and the api_keys table

Two additions closing the same gap: the audit log could say *what* happened
but never *who* did it, and the only way to add or revoke a credential was a
static MCP_AUTH_TOKEN(S) env var requiring a process restart.

* `audit_log.actor` — nullable, since rows written before this column
  existed have no honest answer (NULL means "recorded before actor tracking
  existed", not "caller unknown").
* `api_keys` — live-provisioned, per-person credentials (tools/api_keys.py).
  Only a SHA-256 digest of the token is stored, never the plaintext.

Idempotent per the project convention: both halves inspect the live schema
first, so this is a no-op on a fresh DB where 0001_baseline's `create_all`
already built everything from models.py.

Revision ID: 0015_add_actor_and_api_keys
Revises: 0014_add_two_types
Create Date: 2026-08-01
"""

import sqlalchemy as sa
from alembic import op

revision = "0015_add_actor_and_api_keys"
down_revision = "0014_add_two_types"
branch_labels = None
depends_on = None


def _inspector() -> sa.Inspector:
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    inspector = _inspector()
    tables = set(inspector.get_table_names())

    if "audit_log" in tables:
        existing = {c["name"] for c in inspector.get_columns("audit_log")}
        if "actor" not in existing:
            op.add_column("audit_log", sa.Column("actor", sa.String(length=160), nullable=True))

    if "api_keys" not in tables:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("label", sa.String(length=128), nullable=False),
            sa.Column("role", sa.String(length=16), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
            sa.Column("created_by", sa.String(length=160), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_api_keys_token_hash", "api_keys", ["token_hash"], unique=True)
        op.create_index("ix_api_keys_revoked_at", "api_keys", ["revoked_at"])


def downgrade() -> None:
    inspector = _inspector()
    tables = set(inspector.get_table_names())

    if "api_keys" in tables:
        op.drop_table("api_keys")

    if "audit_log" in tables:
        existing = {c["name"] for c in inspector.get_columns("audit_log")}
        if "actor" in existing:
            op.drop_column("audit_log", "actor")
