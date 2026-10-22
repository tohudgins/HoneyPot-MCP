"""`honeypot_pause` must do what its status says: a paused in-process sensor stops answering.

Found on the live VPS: pausing `hp-vnc` returned `paused` while its port kept answering and
recording, because the engine's `pause()` is a no-op for everything that is not a Docker container.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from tests._ports import free_port

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db(tmp_path, monkeypatch):
    """A file-backed SQLite, not the shared in-memory one.

    The in-memory database is a single connection shared by every session, so a connection made to
    the honeypot (which makes the server run a query in another task) can roll back the pause
    transaction in flight. That is a property of the test database, not of the tools: production
    gives each session its own connection, and this module exercises exactly that.
    """
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    monkeypatch.setattr(
        get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path}/pause.db", raising=False
    )
    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _answers(port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 2)
    except OSError:
        return False
    writer.close()
    return True


@pytest.mark.asyncio
async def test_pausing_an_in_process_sensor_closes_its_port_and_resuming_reopens_it():
    from honeypot_mcp.tools import honeypot as tools

    port = free_port()
    deployed = await tools.honeypot_deploy(type="redis", port=port, name="pause-me")
    assert "error" not in deployed, deployed
    try:
        assert await _answers(port)

        assert (await tools.honeypot_pause("pause-me"))["status"] == "paused"
        assert not await _answers(port), "a paused sensor must not accept connections"

        assert (await tools.honeypot_resume("pause-me"))["status"] == "running"
        assert await _answers(port), "resuming must start listening again on the same port"
        listed = {h["name"]: h for h in (await tools.honeypot_list())["honeypots"]}
        assert listed["pause-me"]["status"] == "running" and listed["pause-me"]["port"] == port
    finally:
        await tools.honeypot_stop(name="pause-me", remove=True)


@pytest.mark.asyncio
async def test_a_resume_that_cannot_bind_says_so_and_leaves_the_sensor_paused(monkeypatch):
    from honeypot_mcp.storage.models import HoneypotType
    from honeypot_mcp.tools import honeypot as tools

    port = free_port()
    await tools.honeypot_deploy(type="redis", port=port, name="pause-clash")
    try:
        await tools.honeypot_pause("pause-clash")
        engine = tools.get_engine(HoneypotType.REDIS)
        real_start = engine.start

        async def _port_taken(*_args: object, **_kwargs: object) -> str:
            raise OSError("[Errno 98] Address already in use")

        monkeypatch.setattr(engine, "start", _port_taken)  # something took the port meanwhile
        result = await tools.honeypot_resume("pause-clash")
        assert "stays paused" in result["error"] and "Address already in use" in result["error"]
        listed = {h["name"]: h for h in (await tools.honeypot_list())["honeypots"]}
        assert listed["pause-clash"]["status"] == "paused"

        monkeypatch.setattr(engine, "start", real_start)  # the port is free again
        assert (await tools.honeypot_resume("pause-clash"))["status"] == "running"
    finally:
        await tools.honeypot_stop(name="pause-clash", remove=True)
