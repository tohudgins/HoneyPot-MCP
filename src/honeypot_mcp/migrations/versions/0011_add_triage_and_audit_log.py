"""add alert triage fields and the control-plane audit log

Two additions for SOC use:

* `alerts.disposition/triage_note/triaged_by/triaged_at` — a bare `acknowledged`
  boolean records that somebody looked at an alert but not what they concluded,
  so shifts can't hand over and nobody can measure what's being dismissed.
* `audit_log` — every state-changing control-plane call. The control plane is
  driven by a language model, so "what did the agent actually do?" needs an
  answer; `alerts_prune` in particular can delete months of evidence and
  previously left no trace.

Idempotent per the project convention: both halves inspect the live schema
first, so this is a no-op on a fresh DB where 0001_baseline's `create_all`
already built everything from models.py.

Revision ID: 0011_add_triage_and_audit_log
Revises: 0010_add_alert_query_indexes
Create Date: 2026-07-29
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_add_triage_and_audit_log"
down_revision = "0010_add_alert_query_indexes"
branch_labels = None
depends_on = None

_TRIAGE_COLUMNS = (
    ("disposition", sa.String(length=32)),
    ("triage_note", sa.Text()),
    ("triaged_by", sa.String(length=128)),
    ("triaged_at", sa.DateTime(timezone=True)),
)


def _inspector() -> sa.Inspector:
    return sa.inspect(op.get_bind())


def upgrade() -> None:
    inspector = _inspector()
    tables = set(inspector.get_table_names())

    if "alerts" in tables:
        existing = {c["name"] for c in inspector.get_columns("alerts")}
        for name, coltype in _TRIAGE_COLUMNS:
            if name not in existing:
                op.add_column("alerts", sa.Column(name, coltype, nullable=True))

    if "audit_log" not in tables:
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("tool", sa.String(length=64), nullable=False),
            sa.Column("summary", sa.Text(), nullable=False),
            sa.Column("arguments", sa.JSON(), nullable=True),
            sa.Column("outcome", sa.String(length=16), nullable=False, server_default="ok"),
            sa.Column("target", sa.String(length=128), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column(
                "timestamp",
                sa.DateTime(timezone=True),
                server_default=sa.func.now(),
                nullable=False,
            ),
        )
        op.create_index("ix_audit_log_tool", "audit_log", ["tool"])
        op.create_index("ix_audit_log_target", "audit_log", ["target"])
        op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
        op.create_index("ix_audit_log_timestamp_tool", "audit_log", ["timestamp", "tool"])


def downgrade() -> None:
    inspector = _inspector()
    tables = set(inspector.get_table_names())

    if "audit_log" in tables:
        op.drop_table("audit_log")

    if "alerts" in tables:
        existing = {c["name"] for c in inspector.get_columns("alerts")}
        for name, _coltype in _TRIAGE_COLUMNS:
            if name in existing:
                op.drop_column("alerts", name)
