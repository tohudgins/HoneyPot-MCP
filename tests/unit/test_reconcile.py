"""Tests for startup reconciliation, deploy-failure cleanup, and subscribe
URL validation — the restart-resilience fixes.
"""

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buf = event_buffer.get_buffer()
    await buf.start()
    yield
    await buf.stop()
    event_buffer.reset_for_tests()
    await close_db()


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_reconcile_restarts_in_process_honeypot():
    """A RUNNING in-process honeypot from a 'previous process' should be
    restarted and reachable, with its container_id refreshed."""
    import asyncio

    from honeypot_mcp.reconcile import reconcile_running_honeypots
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    port = _free_port()
    async with get_session() as session:
        session.add(
            Honeypot(
                name="reboot-redis",
                type=HoneypotType.REDIS,
                port=port,
                status=HoneypotStatus.RUNNING,
                container_id="stale-cid-from-dead-process",
            )
        )

    result = await reconcile_running_honeypots()
    assert "reboot-redis" in result["reattached"]

    # The port should now actually accept connections.
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.close()
    with __import__("contextlib").suppress(Exception):
        await writer.wait_closed()

    async with get_session() as session:
        from honeypot_mcp.storage import queries

        hp = await queries.get_honeypot_by_name(session, "reboot-redis")
        assert hp is not None
        assert hp.container_id != "stale-cid-from-dead-process"

    # Clean up the listener we started.
    from honeypot_mcp.engines import get_engine

    engine = get_engine(HoneypotType.REDIS)
    await engine.stop(hp.container_id)


@pytest.mark.asyncio
async def test_reconcile_marks_unrestartable_as_error():
    """If reattach raises (e.g. SSH with no Docker / missing container), the
    honeypot is flipped to ERROR rather than aborting startup."""
    from unittest.mock import AsyncMock, patch

    from honeypot_mcp.reconcile import reconcile_running_honeypots
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        session.add(
            Honeypot(
                name="dead-ssh",
                type=HoneypotType.SSH,
                port=2222,
                status=HoneypotStatus.RUNNING,
                container_id="gone",
            )
        )

    boom = AsyncMock(side_effect=RuntimeError("container gone"))
    with patch("honeypot_mcp.engines.ssh.SSHEngine.reattach", boom):
        result = await reconcile_running_honeypots()

    assert "dead-ssh" in result["failed"]
    async with get_session() as session:
        hp = await queries.get_honeypot_by_name(session, "dead-ssh")
        assert hp.status == HoneypotStatus.ERROR


@pytest.mark.asyncio
async def test_reconcile_empty_is_noop():
    from honeypot_mcp.reconcile import reconcile_running_honeypots

    result = await reconcile_running_honeypots()
    assert result == {"reattached": [], "failed": []}


@pytest.mark.asyncio
async def test_deploy_failure_releases_name():
    """A failed engine.start() must not leave a stuck DB row that permanently
    reserves the name."""
    from unittest.mock import AsyncMock, patch

    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    boom = AsyncMock(side_effect=OSError("address already in use"))
    with patch("honeypot_mcp.engines.rdp.RDPEngine.start", boom):
        result = await honeypot_deploy(type="rdp", port=_free_port(), name="doomed")

    assert "error" in result
    async with get_session() as session:
        assert await queries.get_honeypot_by_name(session, "doomed") is None


@pytest.mark.asyncio
async def test_subscribe_rejects_bad_scheme():
    from honeypot_mcp.tools.integrations import alert_subscribe

    # HTTP format with a syslog scheme.
    result = await alert_subscribe(url="udp://host:514", label="x", format="json")
    assert "error" in result

    # syslog format with an http scheme.
    result = await alert_subscribe(url="https://host/x", label="y", format="syslog")
    assert "error" in result

    # No host at all.
    result = await alert_subscribe(url="not-a-url", label="z", format="json")
    assert "error" in result


@pytest.mark.asyncio
async def test_subscribe_accepts_valid_url():
    from honeypot_mcp.tools.integrations import alert_subscribe

    result = await alert_subscribe(url="https://hooks.example.com/x", label="ok", format="json")
    assert result.get("active") is True
    assert "error" not in result
