"""Bulk operations, archive-before-delete, and token rotation.

Three gaps found by auditing the product against the job rather than the code.
Each is the kind of thing that only bites after the tool has been running for a
while, which is exactly why they were missing.

* Stopping one honeypot per call is not a workflow when a deployment is twenty
  sensors.
* `alerts_prune` destroyed evidence with no way back — a campaign that started
  eleven months ago simply gone, and the unattended retention sweep did it
  without anyone watching.
* A fired token could only be revoked and recreated, which severs the thread:
  "this credential has fired three times in eight months" becomes three
  unrelated incidents.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    from honeypot_mcp import config
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    config._settings = None
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()
    config._settings = None


async def _seed_alerts(count: int, age_days: int) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    stamp = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=age_days)
    async with get_session() as session:
        for i in range(count):
            session.add(
                Alert(
                    source_ip=f"192.0.2.{i % 250}",
                    event_type="ssh_login_failed",
                    payload={"username": "root", "password": f"p{i}", "seq": i},
                    severity=AlertSeverity.MEDIUM,
                    timestamp=stamp,
                )
            )


async def _alert_count() -> int:
    from sqlalchemy import func, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        return (await session.execute(select(func.count(Alert.id)))).scalar() or 0


# ── Bulk honeypot operations ────────────────────────────────────────────────


# Engines are process-lifetime singletons holding real listening sockets, so a
# port bound by one test is still bound in the next. A fresh range per deploy
# keeps the tests independent of execution order.
_next_port = [45500]


async def _deploy(*types: str) -> None:
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    for t in types:
        _next_port[0] += 1
        result = await honeypot_deploy(type=t, name=f"bulk-{t}", port=_next_port[0])
        assert "error" not in result, result


async def _running() -> list[str]:
    from honeypot_mcp.tools.honeypot import honeypot_list

    return [h["name"] for h in await honeypot_list() if h["status"] == "running"]


async def test_stop_with_no_arguments_is_refused():
    """The natural default would be "everything", and that is unrecoverable.

    Collection simply ends, and nothing tells you it did.
    """
    from honeypot_mcp.tools.honeypot import honeypot_stop

    result = await honeypot_stop()
    assert "error" in result
    assert "Refusing to guess" in result["error"]


async def test_stop_several_by_name():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    await _deploy("ftp", "smtp", "vnc")
    result = await honeypot_stop(names=["bulk-ftp", "bulk-smtp"])

    assert sorted(result["stopped"]) == ["bulk-ftp", "bulk-smtp"]
    assert await _running() == ["bulk-vnc"]


async def test_stop_everything_with_type_all():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    await _deploy("ftp", "smtp", "vnc", "memcached")
    result = await honeypot_stop(type="all")

    assert result["count"] == 4
    assert await _running() == []


async def test_stop_by_type_leaves_other_types_running():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    await _deploy("ftp", "smtp", "vnc")
    await honeypot_stop(type="ftp")

    assert sorted(await _running()) == ["bulk-smtp", "bulk-vnc"]


async def test_stop_reports_an_unknown_name_rather_than_silently_skipping():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    await _deploy("ftp")
    result = await honeypot_stop(names=["bulk-ftp", "does-not-exist"])

    assert "error" in result
    assert "does-not-exist" in result["error"]
    # And nothing was stopped, so the caller can retry the whole set.
    assert await _running() == ["bulk-ftp"]


async def test_a_filter_matching_nothing_changes_nothing():
    from honeypot_mcp.tools.honeypot import honeypot_stop

    await _deploy("ftp")
    result = await honeypot_stop(type="mongodb")

    assert result["stopped"] == []
    assert await _running() == ["bulk-ftp"]


# ── Archive before delete ───────────────────────────────────────────────────


async def test_prune_archives_before_deleting_by_default():
    """Deleting evidence with no copy is the failure this exists to prevent."""
    from honeypot_mcp.tools.alerts import alerts_prune

    await _seed_alerts(40, age_days=200)
    result = await alerts_prune(older_than_days=90)

    assert result["alerts_deleted"] == 40
    assert await _alert_count() == 0

    archive = result["archive"]
    assert isinstance(archive, dict), "an archive should have been written"
    lines = [ln for ln in Path(archive["path"]).read_text().splitlines() if ln]
    assert len(lines) == 40

    # Full payloads, not digests — an archive is the record of last resort.
    record = json.loads(lines[0])
    assert record["payload"]["password"].startswith("p")
    assert {"id", "source_ip", "event_type", "severity", "timestamp"} <= set(record)


async def test_prune_leaves_data_alone_when_the_archive_fails():
    """Failing to archive must cancel the delete, not proceed without it."""
    from honeypot_mcp.storage import queries
    from honeypot_mcp.tools import alerts as alerts_module

    await _seed_alerts(10, age_days=200)

    async def _boom(*_args, **_kwargs):
        raise OSError("disk full")

    original = queries.serialise_alerts_before
    queries.serialise_alerts_before = _boom  # type: ignore[assignment]
    try:
        result = await alerts_module.alerts_prune(older_than_days=90)
    finally:
        queries.serialise_alerts_before = original  # type: ignore[assignment]

    assert "error" in result
    assert "nothing was deleted" in result["error"]
    assert await _alert_count() == 10, "alerts were deleted despite the archive failing"


async def test_archive_can_be_skipped_deliberately():
    from honeypot_mcp.tools.alerts import alerts_prune

    await _seed_alerts(5, age_days=200)
    result = await alerts_prune(older_than_days=90, archive=False)

    assert result["alerts_deleted"] == 5
    assert result["archive"] == "skipped (archive=False)"


async def test_prune_does_not_touch_recent_alerts():
    from honeypot_mcp.tools.alerts import alerts_prune

    await _seed_alerts(6, age_days=200)
    await _seed_alerts(4, age_days=2)
    await alerts_prune(older_than_days=90)

    assert await _alert_count() == 4


async def test_retention_sweep_archives_too():
    """The unattended path is the one most likely to destroy data unnoticed."""
    from honeypot_mcp import config
    from honeypot_mcp.watchdog import HoneypotWatchdog

    await _seed_alerts(12, age_days=400)
    settings = config.get_settings()
    object.__setattr__(settings, "retention_days", 30)
    object.__setattr__(settings, "retention_archive", True)

    watchdog = HoneypotWatchdog()
    await watchdog._maybe_prune()

    assert await _alert_count() == 0
    archives = list(settings.reports_dir.glob("retention-archive-*.jsonl"))
    assert archives, "the unattended sweep deleted without leaving an archive"
    assert len([ln for ln in archives[0].read_text().splitlines() if ln]) == 12


async def test_retention_sweep_skips_the_prune_when_archiving_fails():
    from honeypot_mcp import config
    from honeypot_mcp.storage import queries
    from honeypot_mcp.watchdog import HoneypotWatchdog

    await _seed_alerts(7, age_days=400)
    settings = config.get_settings()
    object.__setattr__(settings, "retention_days", 30)
    object.__setattr__(settings, "retention_archive", True)

    async def _boom(*_args, **_kwargs):
        raise OSError("read-only filesystem")

    original = queries.serialise_alerts_before
    queries.serialise_alerts_before = _boom  # type: ignore[assignment]
    try:
        await HoneypotWatchdog()._maybe_prune()
    finally:
        queries.serialise_alerts_before = original  # type: ignore[assignment]

    assert await _alert_count() == 7


# ── Token rotation ──────────────────────────────────────────────────────────


async def test_rotation_issues_a_new_secret_and_keeps_the_old_one():
    """Revoke-then-create severs the thread; rotation keeps both ends of it."""
    from honeypot_mcp.tools.honeytoken import (
        honeytoken_create,
        honeytoken_list,
        honeytoken_rotate,
    )

    original = await honeytoken_create(
        type="credential",
        label="pg-svc-backup",
        metadata={"service": "postgresql", "username": "svc_backup"},
        planted_at="wiki page IT-114",
    )
    result = await honeytoken_rotate(original["id"])
    new = result["new_token"]

    assert new["token_value"] != original["token_value"], "the secret must actually change"
    assert new["label"] == original["label"]
    assert new["metadata"]["service"] == "postgresql"
    assert new["metadata"]["planted_at"] == "wiki page IT-114"
    assert new["metadata"]["rotated_from"] == original["id"]

    statuses = {t["id"]: t["status"] for t in await honeytoken_list()}
    assert statuses[original["id"]] == "revoked", "the old token must stop matching"
    assert statuses[new["id"]] == "active"


async def test_rotation_links_both_directions_so_history_resolves():
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_rotate

    original = await honeytoken_create(type="canary_url", label="wiki-link")
    new_id = (await honeytoken_rotate(original["id"]))["new_token"]["id"]

    async with get_session() as session:
        rows = {
            t.id: t.token_meta for t in (await session.execute(select(Honeytoken))).scalars().all()
        }
    assert rows[original["id"]]["rotated_to"] == new_id
    assert rows[new_id]["rotated_from"] == original["id"]


async def test_rotation_can_move_a_token_to_a_new_location():
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_rotate

    original = await honeytoken_create(type="canary_url", label="link", planted_at="old wiki page")
    new = (await honeytoken_rotate(original["id"], planted_at="new runbook"))["new_token"]
    assert new["metadata"]["planted_at"] == "new runbook"


async def test_rotating_an_already_revoked_token_is_refused():
    from honeypot_mcp.tools.honeytoken import (
        honeytoken_create,
        honeytoken_revoke,
        honeytoken_rotate,
    )

    original = await honeytoken_create(type="canary_url", label="dead")
    await honeytoken_revoke(original["id"])
    result = await honeytoken_rotate(original["id"])

    assert "error" in result
    assert "already revoked" in result["error"]


async def test_rotating_a_missing_token_is_an_error():
    from honeypot_mcp.tools.honeytoken import honeytoken_rotate

    assert "error" in await honeytoken_rotate(99999)


async def test_rotated_credential_matches_on_the_new_value_not_the_old():
    """The point of rotating: the old secret must stop being a live detection."""
    from honeypot_mcp import credential_match
    from honeypot_mcp.credential_match import _load_index
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_rotate

    original = await honeytoken_create(
        type="credential", label="rotate-me", metadata={"service": "ssh"}
    )
    old_password = original["metadata"]["credentials"][0]["password"]
    new = (await honeytoken_rotate(original["id"]))["new_token"]
    new_password = new["metadata"]["credentials"][0]["password"]
    assert new_password != old_password

    await _load_index()
    live_passwords = {key[2] for key in credential_match._index}
    assert new_password in live_passwords
    assert old_password not in live_passwords, "a revoked secret must stop matching"
