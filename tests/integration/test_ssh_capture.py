"""Does a deployed SSH honeypot actually capture anything?

Every other SSH test feeds synthetic JSON straight into the parser, which is
why the engine could ship for months capturing nothing at all: Cowrie's stdout
was Twisted's text log, `json.loads` rejected every line, and the container
still started, still answered SSH, and still reported healthy. Nothing short of
running the real image proves this works.

So this test starts a real Cowrie container through the real engine, opens a
real TCP connection to it, and asserts an alert lands in the database. It skips
itself when Docker is unavailable, and is opt-in via `RUN_DOCKER_TESTS=1`
because it pulls a ~430 MB image and takes about a minute.

A file-backed database is deliberate. In-memory SQLite runs every session over
one shared connection (StaticPool), so the ingestion task's concurrent session
interleaves with the deploy's writes and the status update is lost — the
honeypot then reads back as STOPPED and `honeypot_stop` refuses to act on it.
That is a property of the test database, not of the product, but it makes an
in-memory version of this test fail for reasons that have nothing to do with
capture.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import tempfile
import uuid
from pathlib import Path

import pytest

# Deliberately NOT set at module scope. `config.get_settings()` caches the
# first Settings it builds, so a module-level DATABASE_URL here would decide
# the database for every integration module imported after this one — which is
# exactly how this file first broke `test_pipeline.py`. The swap happens inside
# the test instead, and is undone in its `finally`.

pytestmark = pytest.mark.asyncio


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytest.importorskip("docker", reason="docker SDK not installed")

skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs Docker and RUN_DOCKER_TESTS=1 (pulls the Cowrie image)",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@skip_docker
async def test_deployed_ssh_honeypot_records_a_real_connection():
    from sqlalchemy import select

    from honeypot_mcp import config
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop

    previous_url = os.environ.get("DATABASE_URL")
    db_dir = tempfile.mkdtemp(prefix="honeypot-ssh-it-")
    await close_db()
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(db_dir) / 'it.db'}"
    config._settings = None

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()

    name = f"it-ssh-{uuid.uuid4().hex[:8]}"
    port = _free_port()
    deployed = False
    try:
        result = await honeypot_deploy(type="ssh", name=name, port=port)
        assert "error" not in result, result
        deployed = True

        # Cowrie needs a moment to bind after the container starts.
        for _ in range(40):
            await asyncio.sleep(1)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
                    banner = s.recv(64)
                break
            except OSError:
                continue
        else:
            pytest.fail("Cowrie never accepted a connection")

        assert banner.startswith(b"SSH-2.0-"), banner

        # Identify as an SSH client so Cowrie logs a version exchange too.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.recv(64)
            s.sendall(b"SSH-2.0-IntegrationTest\r\n")
            await asyncio.sleep(1)

        # Ingestion polls docker logs every 2s, then the buffer flushes.
        events: list[str] = []
        for _ in range(20):
            await asyncio.sleep(1)
            async with get_session() as session:
                rows = (await session.execute(select(Alert))).scalars().all()
            events = [r.event_type for r in rows]
            if events:
                break

        assert events, (
            "a real SSH connection produced no alert — Cowrie's JSON is not "
            "reaching the ingester (check COWRIE_OUTPUT_JSONLOG_* env vars)"
        )
        assert "ssh_session_connect" in events, events
    finally:
        if deployed:
            with contextlib.suppress(Exception):
                await honeypot_stop(name=name, remove=True)
        await buffer.stop()
        event_buffer.reset_for_tests()
        await close_db()
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url
        config._settings = None
