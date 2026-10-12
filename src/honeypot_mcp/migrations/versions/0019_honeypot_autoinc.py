"""honeypots.id never reused (SQLite AUTOINCREMENT)

SQLite hands a deleted row's rowid to the next insert unless the table is AUTOINCREMENT. Removing a
sensor and deploying another therefore gave the new one the old id, and every alert and rollup row
the old sensor produced (they carry the id) was attributed to the new one. PostgreSQL's sequences
never reuse ids, so this is SQLite only and a no-op elsewhere.

The table is rebuilt (SQLite cannot add AUTOINCREMENT in place) and the AUTOINCREMENT counter is
seeded past EVERY id ever referenced, not just the surviving rows: alerts and rollups of a removed
sensor still carry its id, and a counter that restarted at max(surviving id) would reuse exactly
the ids this exists to retire.

Idempotent per the project convention: skipped when the table already is AUTOINCREMENT (a fresh
database built by 0001_baseline's create_all from models.py already is).

Revision ID: 0019_honeypot_autoinc
Revises: 0018_sub_suppressed
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_honeypot_autoinc"
down_revision = "0018_sub_suppressed"
branch_labels = None
depends_on = None


def _is_autoincrement(bind: sa.Connection) -> bool:
    sql = bind.execute(
        sa.text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'honeypots'")
    ).scalar()
    return isinstance(sql, str) and "AUTOINCREMENT" in sql.upper()


def _highest_id_ever_used(bind: sa.Connection) -> int:
    tables = set(sa.inspect(bind).get_table_names())
    highest = bind.execute(sa.text("SELECT COALESCE(MAX(id), 0) FROM honeypots")).scalar() or 0
    for table in ("alerts", "alert_rollups"):
        if table in tables:
            used = bind.execute(
                sa.text(f"SELECT COALESCE(MAX(honeypot_id), 0) FROM {table}")  # noqa: S608
            ).scalar()
            highest = max(highest, used or 0)
    return int(highest)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        return
    if "honeypots" not in sa.inspect(bind).get_table_names() or _is_autoincrement(bind):
        return
    with op.batch_alter_table(
        "honeypots", recreate="always", table_kwargs={"sqlite_autoincrement": True}
    ):
        pass
    highest = _highest_id_ever_used(bind)
    updated = bind.execute(
        sa.text("UPDATE sqlite_sequence SET seq = :seq WHERE name = 'honeypots'"), {"seq": highest}
    ).rowcount
    if not updated:
        bind.execute(
            sa.text("INSERT INTO sqlite_sequence (name, seq) VALUES ('honeypots', :seq)"),
            {"seq": highest},
        )


def downgrade() -> None:
    # Leaving AUTOINCREMENT in place is harmless and avoids a second table rebuild.
    pass
