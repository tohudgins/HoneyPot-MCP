"""index alerts.honeypot_id

`honeypot_list`, `honeypot_status` and the per-sensor counts group alerts by `honeypot_id`, and
nothing indexed that column, so every call scanned the whole table. On the live droplet with 4.9M
alerts `honeypot_list` took 51 seconds; with this covering index the same count is 0.02 seconds on a
1.1M-row copy (a table scan became an index search).

Idempotent per the project convention: checks the reflected index list first, so it is a no-op on a
fresh database where 0001_baseline's create_all already built it from models.py. On a large existing
table the index build takes a few seconds and blocks writers while it runs.

Revision ID: 0016_alert_honeypot_idx
Revises: 0015_add_actor_and_api_keys
Create Date: 2026-10-12
"""

from alembic import op
from sqlalchemy import inspect

revision = "0016_alert_honeypot_idx"
down_revision = "0015_add_actor_and_api_keys"
branch_labels = None
depends_on = None

_INDEX = "ix_alerts_honeypot_id"


def _existing() -> set[str]:
    inspector = inspect(op.get_bind())
    if "alerts" not in inspector.get_table_names():
        return set()
    return {name for ix in inspector.get_indexes("alerts") if (name := ix.get("name"))}


def upgrade() -> None:
    if _INDEX not in _existing():
        op.create_index(_INDEX, "alerts", ["honeypot_id"])


def downgrade() -> None:
    if _INDEX in _existing():
        op.drop_index(_INDEX, table_name="alerts")
