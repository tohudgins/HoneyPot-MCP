"""Unit tests for database layer."""

import asyncio
import os

import pytest

# Use in-memory SQLite for tests
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


@pytest.mark.asyncio
async def test_create_and_retrieve_honeypot():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    async with get_session() as session:
        hp = Honeypot(name="test-ssh", type=HoneypotType.SSH, port=2222)
        session.add(hp)
        await session.flush()

    async with get_session() as session:
        result = await queries.get_honeypot_by_name(session, "test-ssh")
        assert result is not None
        assert result.port == 2222
        assert result.type == HoneypotType.SSH


@pytest.mark.asyncio
async def test_create_alert_and_retrieve():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity

    async with get_session() as session:
        alert = await queries.create_alert(
            session,
            honeypot_id=None,
            source_ip="10.0.0.1",
            source_port=12345,
            event_type="ssh_login_failed",
            payload={"username": "root", "password": "secret"},
            severity=AlertSeverity.HIGH,
        )
        assert alert.id is not None

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, limit=10, source_ip="10.0.0.1")
        assert len(alerts) == 1
        assert alerts[0].event_type == "ssh_login_failed"
        assert alerts[0].severity == AlertSeverity.HIGH


@pytest.mark.asyncio
async def test_alert_stats():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity

    async with get_session() as session:
        for i in range(5):
            await queries.create_alert(
                session,
                honeypot_id=None,
                source_ip=f"10.0.0.{i}",
                source_port=None,
                event_type="port_scan",
                payload={},
                severity=AlertSeverity.LOW,
            )

    async with get_session() as session:
        stats = await queries.get_alert_stats(session)
        assert stats["total_alerts"] == 5
        assert len(stats["top_source_ips"]) <= 10


@pytest.mark.asyncio
async def test_acknowledge_alert():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity

    async with get_session() as session:
        alert = await queries.create_alert(
            session,
            honeypot_id=None,
            source_ip="192.168.1.1",
            source_port=None,
            event_type="http_probe",
            payload={},
            severity=AlertSeverity.LOW,
        )
        alert_id = alert.id

    async with get_session() as session:
        updated = await queries.acknowledge_alert(session, alert_id)
        assert updated is True

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(session, source_ip="192.168.1.1")
        assert alerts[0].acknowledged is True


@pytest.mark.asyncio
async def test_one_session_finishing_does_not_undo_another_sessions_uncommitted_write():
    """The in-memory test database is ONE connection shared by every session. The pool's
    reset-on-return rolled that connection back whenever any session's connection was returned,
    which silently undid a different session's uncommitted INSERT: the flusher's Alert row vanished
    while the rows written after it survived, so honeytoken tests failed depending on interleaving.
    Production gives each session its own connection; this pins the test database to behave the
    same way.

    The window is the one between another session's COMMIT and its connection being returned, so it
    is reproduced with a raw engine connection."""
    from sqlalchemy import func, select, text

    from honeypot_mcp.storage import database
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    other_committed, writer_inserted = asyncio.Event(), asyncio.Event()

    async def other() -> None:
        async with database._get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
            await conn.commit()
            other_committed.set()
            await writer_inserted.wait()
        # leaving the block returns the connection to the pool

    async def writer() -> None:
        await other_committed.wait()
        async with get_session() as session:
            session.add(
                Alert(
                    source_ip="203.0.113.1",
                    event_type="x",
                    payload={},
                    severity=AlertSeverity.LOW,
                )
            )
            await session.flush()  # written, not yet committed
            writer_inserted.set()
            await asyncio.sleep(0.2)  # the other connection is returned while this is pending

    await asyncio.gather(other(), writer())
    async with get_session() as session:
        assert (await session.execute(select(func.count()).select_from(Alert))).scalar_one() == 1
