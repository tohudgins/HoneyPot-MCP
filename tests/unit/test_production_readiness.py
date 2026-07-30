"""Operational checks a production deployment depends on.

These cover the difference between "the process is up" and "the sensor is
actually collecting", which is not the same question and has a different
answer often enough to matter.

Chaos testing found the case that motivates all of this: with the database
removed underneath a running server, every engine keeps accepting connections
and answering attackers perfectly — the listeners are in-process and never
touch the DB — while nothing persists. A deploy even returned success. A
liveness probe sees a healthy process the entire time.
"""

from __future__ import annotations

import os
import stat

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()


async def _client():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.metrics import build_app

    client = TestClient(TestServer(build_app()))
    await client.start_server()
    return client


# ── Liveness vs readiness ───────────────────────────────────────────────────


async def test_healthz_is_liveness_only():
    """Liveness must not depend on the database, or a DB blip restarts a
    process whose honeypots are still happily capturing."""
    client = await _client()
    try:
        response = await client.get("/healthz")
        assert response.status == 200
        assert (await response.json())["status"] == "ok"
    finally:
        await client.close()


async def test_readyz_passes_when_the_database_answers():
    client = await _client()
    try:
        response = await client.get("/readyz")
        assert response.status == 200
        body = await response.json()
        assert body["status"] == "ready"
        assert body["checks"]["database"] == "ok"
    finally:
        await client.close()


async def test_readyz_fails_when_the_schema_is_gone_but_healthz_still_passes():
    """The exact chaos-test scenario: process fine, collection dead."""
    from sqlalchemy import text

    from honeypot_mcp.storage.database import get_session

    client = await _client()
    try:
        async with get_session() as session:
            await session.execute(text("DROP TABLE honeypots"))

        live = await client.get("/healthz")
        assert live.status == 200, "the process really is alive; liveness should not flap"

        ready = await client.get("/readyz")
        assert ready.status == 503
        body = await ready.json()
        assert body["status"] == "not ready"
        assert "unavailable" in body["checks"]["database"]
    finally:
        await client.close()


async def test_readyz_fails_on_a_runaway_ingest_backlog():
    """The queue is unbounded, so a backlog is a memory problem before it is a
    data-loss one. Readiness is where an orchestrator can see it."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    buffer = event_buffer.get_buffer()  # never started, so nothing drains
    for _ in range(50_001):
        buffer._queue.put_nowait(
            PendingEvent(
                honeypot_id=None,
                source_ip="192.0.2.1",
                event_type="x",
                payload={},
                severity=AlertSeverity.LOW,
            )
        )

    client = await _client()
    try:
        response = await client.get("/readyz")
        assert response.status == 503
        assert "backlog" in (await response.json())["checks"]["event_queue"]
    finally:
        await client.close()
        event_buffer.reset_for_tests()


# ── Secret hygiene ──────────────────────────────────────────────────────────


async def test_world_readable_env_is_reported(tmp_path):
    """`cp .env.example .env` under a 0644 umask hands the control-plane token
    to every local account, and nobody thinks to check the mode."""
    from honeypot_mcp.config import warn_on_world_readable_env

    env = tmp_path / ".env"
    env.write_text("MCP_AUTH_TOKEN=secret\n")
    env.chmod(0o644)

    warning = warn_on_world_readable_env(env)
    assert warning is not None
    assert "chmod 600" in warning, "the warning must say how to fix it"


async def test_owner_only_env_is_silent(tmp_path):
    from honeypot_mcp.config import warn_on_world_readable_env

    env = tmp_path / ".env"
    env.write_text("MCP_AUTH_TOKEN=secret\n")
    env.chmod(0o600)

    assert warn_on_world_readable_env(env) is None


async def test_group_readable_env_is_also_reported(tmp_path):
    """Group-readable is the multi-tenant case, and just as exposed."""
    from honeypot_mcp.config import warn_on_world_readable_env

    env = tmp_path / ".env"
    env.write_text("x=1\n")
    env.chmod(0o640)

    assert warn_on_world_readable_env(env) is not None


async def test_missing_env_is_not_an_error(tmp_path):
    """Running purely from environment variables is a valid deployment."""
    from honeypot_mcp.config import warn_on_world_readable_env

    assert warn_on_world_readable_env(tmp_path / "nope.env") is None


async def test_the_shipped_env_example_carries_no_real_secrets(tmp_path):
    """It is committed, so a real value in it is a leak in the repo history.

    Placeholders are fine and useful; the check is for something that looks
    like an actual key — long, high-entropy, and not obviously a stand-in.
    """
    import re
    from pathlib import Path

    example = Path(__file__).resolve().parents[2] / ".env.example"
    placeholder = re.compile(r"^$|your_|_here|change_?me|example|placeholder|xxx|<.*>|\.\.\.", re.I)
    offenders = []
    for line in example.read_text().splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if not any(t in key.upper() for t in ("TOKEN", "KEY", "SECRET", "PASSWORD")):
            continue
        value = value.strip().strip("'\"")
        if placeholder.search(value):
            continue
        # A real credential is long and mixed; a short word is a setting.
        if len(value) >= 20 and re.search(r"[0-9]", value) and re.search(r"[a-zA-Z]", value):
            offenders.append(key)
    assert not offenders, f"these look like real secrets committed in .env.example: {offenders}"


# ── Backup ──────────────────────────────────────────────────────────────────


async def test_backup_script_uses_sqlite_backup_not_copy():
    """A `cp` of a WAL database silently loses uncheckpointed transactions —
    the copy opens cleanly and is simply missing the most recent captures,
    which is the worst possible way for a backup to fail."""
    from pathlib import Path

    script = (Path(__file__).resolve().parents[2] / "scripts" / "backup.sh").read_text()
    assert ".backup" in script
    assert "pg_dump" in script, "PostgreSQL deployments need a path too"
    assert "chmod 600" in script, "the backup inherits the .env's secrecy"


async def test_backup_and_restore_scripts_are_executable():
    from pathlib import Path

    scripts = Path(__file__).resolve().parents[2] / "scripts"
    for name in ("backup.sh", "restore.sh"):
        mode = (scripts / name).stat().st_mode
        assert mode & stat.S_IXUSR, f"{name} is not executable"
