"""`run_analysis` and `database_backup`: the post-run workflows, as tools."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(age: timedelta = timedelta(0)) -> None:
    """Three sources: a brute-forcer, a command runner and a scanner, plus a trip."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )

    now = datetime.now(UTC) - age
    plan = [
        ("198.51.100.1", "ssh_login_failed", AlertSeverity.MEDIUM, 40),
        ("198.51.100.2", "ssh_login_failed", AlertSeverity.MEDIUM, 25),
        ("198.51.100.3", "ssh_login_failed", AlertSeverity.MEDIUM, 10),
        ("203.0.113.9", "redis_config_set", AlertSeverity.HIGH, 6),
        ("203.0.113.9", "ssh_connection", AlertSeverity.LOW, 9),
    ]
    async with get_session() as session:
        for ip, event_type, severity, n in plan:
            for i in range(n):
                session.add(
                    Alert(
                        source_ip=ip,
                        event_type=event_type,
                        severity=severity,
                        timestamp=now - timedelta(seconds=i),
                        payload={},
                    )
                )
        session.add(
            Honeytoken(
                type=HoneytokenType("credential"),
                label="planted-admin",
                token_value="not-a-real-secret",
                status=HoneytokenStatus.TRIGGERED,
                triggered_at=now,
            )
        )


# ── run_analysis ──────────────────────────────────────────────────────────────


async def test_run_analysis_writes_a_summary_with_every_section(tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.workflows import run_analysis

    await _seed()
    out = await run_analysis(top=2, hours=24)

    assert out["complete"] is True and out["failed"] == []
    assert out["headline"]["total_alerts"] == 90
    assert out["headline"]["unique_source_ips"] == 4
    assert out["soc"]["triggered_tokens"][0]["label"] == "planted-admin"
    assert out["soc"]["untriaged_by_severity"]["high"] == 6
    tactics = {t["tactic"]: t for t in out["attack"]["tactics"]}
    assert tactics["Credential Access"]["alerts"] == 75
    # ssh_connection is bookkeeping: unmapped, and the mapped share says so
    assert [u["type"] for u in out["attack"]["unmapped"]] == ["ssh_connection"]
    assert out["attack"]["mapped_share"] == pytest.approx(81 / 90, abs=1e-3)
    assert [s["ip"] for s in out["top_sources"]] == ["198.51.100.1", "198.51.100.2"]
    assert out["campaigns"]["total"] == 1  # three sources, one event type, one hour

    summary = Path(out["summary_file"]["path"])
    assert summary.parent == get_settings().reports_dir.resolve()
    text = summary.read_text()
    for section in (
        "# Analysis summary",
        "## ATT&CK: what the run did, by tactic",
        "| Credential Access | T1110",
        "Left unmapped: ssh_connection (9)",
        "## Top 2 sources",
        "## Campaigns and shared tooling",
        "## Files",
        "planted-admin",
        "honeytokens triggered: 1",
    ):
        assert section in text, section
    assert "## Parts that failed" not in text
    # the per-source reports and the exports exist and are named in the summary
    for name in out["files"].values():
        if name.endswith((".md", ".html", ".json", ".txt")):
            assert (summary.parent / name).is_file(), name
    assert "STIX bundle" in out["files"] and "full report" in out["files"]


async def test_one_failing_sub_tool_is_reported_and_the_rest_still_lands(monkeypatch):
    from honeypot_mcp.tools import analysis
    from honeypot_mcp.tools.workflows import run_analysis

    async def boom(*_a, **_k):
        raise RuntimeError("fingerprint store unavailable")

    monkeypatch.setattr(analysis, "fingerprint_clusters", boom)
    await _seed()
    out = await run_analysis(top=1, hours=24)

    assert out["complete"] is False
    assert [f["part"] for f in out["failed"]] == ["fingerprint_clusters"]
    assert "fingerprint store unavailable" in out["failed"][0]["error"]
    assert "fingerprint_clusters" not in out  # no half-made section
    assert out["headline"]["total_alerts"] == 90 and out["attack"]["tactics"]
    text = Path(out["summary_file"]["path"]).read_text()
    assert "## Parts that failed" in text and "fingerprint store unavailable" in text
    assert "SSH fingerprint clusters: unavailable" in text


async def test_a_tool_that_returns_an_error_dict_counts_as_a_failed_part(monkeypatch):
    from honeypot_mcp.tools import analysis
    from honeypot_mcp.tools.workflows import run_analysis

    async def refuse(*_a, **_k):
        return {"error": "more than 500,000 rows"}

    monkeypatch.setattr(analysis, "analyze_campaign", refuse)
    await _seed()
    out = await run_analysis(top=1, hours=24)
    assert [f["part"] for f in out["failed"]] == ["analyze_campaign"]
    assert "campaigns" not in out and out["files"]


async def test_the_window_ends_at_the_newest_alert_not_at_the_wall_clock():
    """A backup taken a week ago must not be analysed through an empty present."""
    from honeypot_mcp.tools.workflows import run_analysis

    await _seed(age=timedelta(days=10))
    out = await run_analysis(top=1, hours=24, write_exports=False)

    assert out["window"]["effective_hours"] >= 24 + 239
    assert "newest alert is" in out["window"]["note"]
    assert out["soc"]["volume"]["total_events"] == 90  # not "nothing needs a decision"
    assert out["top_sources"][0]["ip"] == "198.51.100.1"


async def test_without_exports_nothing_is_written_and_the_summary_comes_back_inline(tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.workflows import run_analysis

    await _seed()
    out = await run_analysis(top=1, hours=24, write_exports=False)

    assert "summary_file" not in out and out["files"] == {}
    assert out["summary_markdown"].startswith("# Analysis summary")
    assert not get_settings().reports_dir.exists()


async def test_an_empty_database_is_analysed_without_error():
    from honeypot_mcp.tools.workflows import run_analysis

    out = await run_analysis(top=3, hours=24, write_exports=False)
    assert out["complete"] is True
    assert out["headline"]["total_alerts"] == 0 and out["top_sources"] == []
    assert "no alerts" in out["window"]["note"]


async def test_bad_arguments_are_refused_and_top_is_clamped():
    from honeypot_mcp.tools.workflows import run_analysis

    assert "error" in await run_analysis(hours=0)
    await _seed()
    out = await run_analysis(top=9999, hours=24, write_exports=False)
    assert out["top_sources_count"] <= 25


async def test_the_summary_is_regenerated_on_every_run_but_exports_are_not_overwritten():
    from honeypot_mcp.tools.workflows import run_analysis

    await _seed()
    first = await run_analysis(top=1, hours=24)
    second = await run_analysis(top=1, hours=24)
    assert first["summary_file"]["path"] == second["summary_file"]["path"]
    assert second["complete"] is True


# ── database_backup ───────────────────────────────────────────────────────────


@pytest.fixture
def source_db(tmp_path, monkeypatch):
    """A file-backed SQLite database in WAL mode whose newest rows live only in the -wal file."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Base,
        Honeypot,
        HoneypotStatus,
        HoneypotType,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )

    path = tmp_path / "src" / "honeypot_mcp.db"
    path.parent.mkdir()
    engine = create_engine(f"sqlite:///{path}")
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA wal_autocheckpoint=0")
    Base.metadata.create_all(engine)
    base = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
    with Session(engine) as session:
        session.add(
            Honeypot(
                name="web-1",
                type=HoneypotType("http"),
                port=8080,
                status=HoneypotStatus.RUNNING,
            )
        )
        for i in range(30):
            session.add(
                Alert(
                    source_ip=f"192.0.2.{i % 3 + 1}",
                    event_type="http_request",
                    severity=AlertSeverity.LOW,
                    timestamp=base + timedelta(hours=i),
                    payload={"path": "/"},
                )
            )
        session.add(
            Honeytoken(
                type=HoneytokenType("credential"),
                label="t",
                token_value="v",
                status=HoneytokenStatus.TRIGGERED,
            )
        )
        session.commit()
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{path}")
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path / "backups")
    wal = path.with_name(path.name + "-wal")
    assert wal.exists() and wal.stat().st_size > 0, "the fixture must leave rows only in the WAL"
    yield path
    engine.dispose()


async def test_backup_is_a_verified_snapshot_that_includes_uncheckpointed_rows(source_db, tmp_path):
    from honeypot_mcp.tools.workflows import database_backup

    out = await database_backup()

    assert "error" not in out, out
    final = Path(out["path"])
    assert final.parent == (tmp_path / "backups").resolve()
    assert final.name.startswith("honeypot-")
    assert out["alerts"] == 30 and out["distinct_sources"] == 3
    assert out["window_hours"] == 29.0
    assert out["honeypots"] == 1 and out["honeytokens"] == 1 and out["honeytokens_triggered"] == 1
    assert out["integrity_check"] == "ok" and out["verified"] is True
    db = final / "honeypot_mcp.db"
    assert out["size_bytes"] == db.stat().st_size and len(out["sha256"]) == 64
    manifest = json.loads((final / "MANIFEST.json").read_text())
    assert manifest["alerts"] == 30 and manifest["sha256"] == out["sha256"]
    assert "/" not in manifest["source_file"]
    # private from the first byte, rollback-mode (no side files), nothing left half-made
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE((final / "MANIFEST.json").stat().st_mode) == 0o600
    assert sorted(p.name for p in final.iterdir()) == ["MANIFEST.json", "honeypot_mcp.db"]
    assert [p.name for p in final.parent.iterdir()] == [final.name]
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


async def test_backup_is_audited_without_secrets(source_db):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog
    from honeypot_mcp.tools.workflows import database_backup

    await database_backup(destination="nightly")
    async with get_session() as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.tool == "database_backup")))
            .scalars()
            .all()
        )
    assert len(rows) == 1 and rows[0].outcome == "ok" and rows[0].target == "nightly"


async def test_backup_refuses_to_overwrite(source_db, tmp_path):
    from honeypot_mcp.tools.workflows import database_backup

    first = await database_backup(destination="nightly")
    marker = Path(first["path"]) / "honeypot_mcp.db"
    before = marker.read_bytes()
    second = await database_backup(destination="nightly")

    assert "already exists" in second["error"]
    assert marker.read_bytes() == before
    assert [p.name for p in (tmp_path / "backups").iterdir()] == ["nightly"]


@pytest.mark.parametrize(
    "destination",
    [
        "../escape",
        "../../etc/cron.d/x",
        "/tmp/elsewhere",
        "a/../../out",
        ".",
        "",
        "..",
        ".hidden",
        "x.partial",
    ],
)
async def test_backup_destination_is_confined(source_db, tmp_path, destination):
    from honeypot_mcp.tools.workflows import database_backup

    out = await database_backup(destination=destination)
    if destination == "":  # falsy means "use the default timestamped name"
        assert "error" not in out
        return
    assert "error" in out and "path" not in out
    assert not (tmp_path / "escape").exists() and not Path("/tmp/elsewhere").exists()
    assert not (tmp_path / "backups").exists() or list((tmp_path / "backups").iterdir()) == []


async def test_backup_accepts_an_absolute_path_inside_the_backups_directory(source_db, tmp_path):
    from honeypot_mcp.tools.workflows import database_backup

    inside = tmp_path / "backups" / "weekly" / "w42"
    out = await database_backup(destination=str(inside))
    assert "error" not in out, out
    assert Path(out["path"]) == inside.resolve()


async def test_backup_refuses_when_the_disk_cannot_hold_it(source_db, tmp_path, monkeypatch):
    from honeypot_mcp.tools import workflows

    monkeypatch.setattr(workflows, "_free_bytes", lambda _p: 1024)
    out = await workflows.database_backup()

    assert "Not enough free disk space" in out["error"]
    assert "1.0 KiB" in out["error"] and "needs up to" in out["error"]
    assert not (tmp_path / "backups").exists()


async def test_backup_refuses_non_sqlite(monkeypatch, tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.workflows import database_backup

    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path / "backups")
    monkeypatch.setattr(
        get_settings(), "database_url", "postgresql+asyncpg://u:hunter2@db.example/hp"
    )
    out = await database_backup()
    assert "pg_dump" in out["error"] and "postgresql" in out["error"]
    assert "hunter2" not in json.dumps(out)
    assert not (tmp_path / "backups").exists()


async def test_backup_refuses_an_in_memory_database(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.workflows import database_backup

    monkeypatch.setattr(get_settings(), "database_url", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path / "backups")
    out = await database_backup()
    assert "in memory" in out["error"]


async def test_a_failed_backup_leaves_no_partial_file(source_db, tmp_path, monkeypatch):
    from honeypot_mcp.tools import workflows

    def explode(*_a, **_k):
        raise sqlite3.DatabaseError("disk I/O error")

    monkeypatch.setattr(workflows, "_database_facts", explode)
    out = await workflows.database_backup(destination="nightly")

    assert "Backup failed" in out["error"]
    assert list((tmp_path / "backups").iterdir()) == []  # not even a hidden .partial directory


async def test_a_copy_that_fails_the_integrity_check_is_not_kept(source_db, tmp_path, monkeypatch):
    from honeypot_mcp.tools import workflows

    real_open = workflows._open_readonly

    class _Lying:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, sql, *a):
            if sql == "PRAGMA integrity_check":
                return sqlite3.connect(":memory:").execute(
                    "SELECT 'row 1 missing from index ix_alerts_source_ip'"
                )
            return self._conn.execute(sql, *a)

        def close(self):
            self._conn.close()

    calls = {"n": 0}

    def open_ro(path):
        conn = real_open(path)
        calls["n"] += 1
        return _Lying(conn) if path.parent.name.endswith(".partial") else conn

    monkeypatch.setattr(workflows, "_open_readonly", open_ro)
    out = await workflows.database_backup()

    assert "integrity_check" in out["error"] and "was not kept" in out["error"]
    assert list((tmp_path / "backups").iterdir()) == []


async def test_a_file_that_is_not_a_honeypot_database_is_not_kept(tmp_path, monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.workflows import database_backup

    other = tmp_path / "other.db"
    with sqlite3.connect(other) as conn:
        conn.execute("CREATE TABLE notes (x)")
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{other}")
    monkeypatch.setattr(get_settings(), "backup_dir", tmp_path / "backups")
    out = await database_backup()

    assert "does not look like a HoneyPot-MCP database" in out["error"]
    assert list((tmp_path / "backups").iterdir()) == []


async def test_verify_false_skips_the_integrity_check_and_the_hash(source_db):
    from honeypot_mcp.tools.workflows import database_backup

    out = await database_backup(verify=False)
    assert out["verified"] is False and out["sha256"] is None
    assert out["integrity_check"] == "not run" and out["alerts"] == 30


async def test_the_backup_opens_with_the_projects_own_init_db(source_db, tmp_path, monkeypatch):
    """What `scripts/analyze_backup.py` does with a backup: open it with the server's own code."""
    from sqlalchemy import func, select

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.tools.workflows import database_backup

    out = await database_backup()
    copy = tmp_path / "analysis" / "honeypot_mcp.db"
    copy.parent.mkdir()
    copy.write_bytes((Path(out["path"]) / "honeypot_mcp.db").read_bytes())

    await close_db()
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{copy}")
    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    await init_db()
    async with get_session() as session:
        assert (await session.execute(select(func.count(Alert.id)))).scalar_one() == 30
