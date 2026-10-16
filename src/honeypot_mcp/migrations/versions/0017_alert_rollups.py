"""alert_rollups: hourly alert counts, plus two small partial indexes for the triage queue

On the live VPS the alert table reached 4.9M rows in nine hours (one SIP flood) and the basic
analyst tools stopped working: `alerts_stats` took 27 s (and over 100 s over a one-hour window),
`soc_brief` timed out, because each aggregate read every row. The remedy is to make the cost of a
statistic depend on the size of the answer, not of the table:

* `alert_rollups` holds alerts counted per hour per (severity, event type, source, sensor). It is
  written in the same transaction as the alerts from now on; this migration backfills it from the
  existing rows with one GROUP BY. It grows with the number of distinct combinations, which a
  flood does not change.
* `ix_alerts_acked` (acknowledged rows only) and `ix_alerts_urgent` (CRITICAL/HIGH only) are
  partial indexes, so the "untriaged" counts and the "needs attention" list never touch the flood
  of LOW/MEDIUM rows and cost nothing to maintain for them.

Idempotent per the project convention: every step checks what exists first, so this is a no-op on
a fresh database where 0001_baseline's create_all already built it all from models.py. Backfill
runs only when this migration creates the table. On the 4.9M-row table expect the backfill
to take a minute or two, during which writers wait.

Revision ID: 0017_alert_rollups
Revises: 0016_alert_honeypot_idx
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0017_alert_rollups"
down_revision = "0016_alert_honeypot_idx"
branch_labels = None
depends_on = None

_SEVERITIES = ("low", "medium", "high", "critical")


def _inspector() -> sa.Inspector:
    return sa.inspect(op.get_bind())


def _alert_indexes() -> set[str]:
    inspector = _inspector()
    if "alerts" not in inspector.get_table_names():
        return set()
    return {name for ix in inspector.get_indexes("alerts") if (name := ix.get("name"))}


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    tables = set(_inspector().get_table_names())

    if "alert_rollups" not in tables:
        severity = (
            postgresql.ENUM(*_SEVERITIES, name="alertseverity", create_type=False)
            if dialect == "postgresql"
            else sa.String(length=8)
        )
        op.create_table(
            "alert_rollups",
            sa.Column("bucket", sa.DateTime(timezone=True), primary_key=True),
            sa.Column("severity", severity, primary_key=True),
            sa.Column("event_type", sa.String(length=64), primary_key=True),
            sa.Column("source_ip", sa.String(length=45), primary_key=True),
            sa.Column("honeypot_id", sa.Integer(), primary_key=True, autoincrement=False),
            sa.Column("count", sa.Integer(), nullable=False),
        )
        op.create_index(
            "ix_alert_rollups_source_ip_bucket", "alert_rollups", ["source_ip", "bucket"]
        )
        if "alerts" in tables:
            hour = (
                "date_trunc('hour', timestamp)"
                if dialect == "postgresql"
                else "strftime('%Y-%m-%d %H:00:00.000000', timestamp)"
            )
            op.execute(
                sa.text(
                    "INSERT INTO alert_rollups "
                    "(bucket, severity, event_type, source_ip, honeypot_id, count) "
                    f"SELECT {hour}, severity, event_type, source_ip, "
                    "COALESCE(honeypot_id, 0), count(*) FROM alerts "
                    "GROUP BY 1, 2, 3, 4, 5"
                )
            )

    if "alerts" in tables:
        existing = _alert_indexes()
        severity_in = "severity IN ('critical', 'high')"
        if "ix_alerts_acked" not in existing:
            true = "true" if dialect == "postgresql" else "1"
            op.execute(
                sa.text(
                    f"CREATE INDEX ix_alerts_acked ON alerts (timestamp) "
                    f"WHERE acknowledged IS {true}"
                )
            )
        if "ix_alerts_urgent" not in existing:
            op.execute(
                sa.text(
                    "CREATE INDEX ix_alerts_urgent ON alerts (severity, acknowledged, timestamp) "
                    f"WHERE {severity_in}"
                )
            )


def downgrade() -> None:
    tables = set(_inspector().get_table_names())
    existing = _alert_indexes()
    for name in ("ix_alerts_urgent", "ix_alerts_acked"):
        if name in existing:
            op.drop_index(name, table_name="alerts")
    if "alert_rollups" in tables:
        op.drop_table("alert_rollups")
