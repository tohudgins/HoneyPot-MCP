"""add composite indexes for alert triage queries

Every triage path filters alerts by a time window plus either a severity or a
source IP (`alerts_recent`, `alerts_stats`, `threat_timeline`, the retention
sweep, and all three Grafana dashboards). The pre-existing single-column
indexes on `timestamp`, `source_ip` and `event_type` can't serve those pairs,
and `severity` had no index at all despite being a filterable column — so a
deployment with real traffic volume degrades to scanning.

Idempotent per the project convention: checks the reflected index list first,
so this is a no-op on a fresh DB where 0001_baseline's create_all already
built them from models.py.

Revision ID: 0010_add_alert_query_indexes
Revises: 0009_add_mssql_type
Create Date: 2026-07-28
"""

from alembic import op
from sqlalchemy import inspect

revision = "0010_add_alert_query_indexes"
down_revision = "0009_add_mssql_type"
branch_labels = None
depends_on = None

_INDEXES = (
    ("ix_alerts_timestamp_severity", ["timestamp", "severity"]),
    ("ix_alerts_source_ip_timestamp", ["source_ip", "timestamp"]),
)


def _existing() -> set[str]:
    inspector = inspect(op.get_bind())
    if "alerts" not in inspector.get_table_names():
        return set()
    return {name for ix in inspector.get_indexes("alerts") if (name := ix.get("name"))}


def upgrade() -> None:
    existing = _existing()
    for name, columns in _INDEXES:
        if name not in existing:
            op.create_index(name, "alerts", columns)


def downgrade() -> None:
    existing = _existing()
    for name, _columns in _INDEXES:
        if name in existing:
            op.drop_index(name, table_name="alerts")
