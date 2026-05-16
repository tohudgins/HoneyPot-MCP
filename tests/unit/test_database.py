"""Unit tests for database layer."""

import os

import pytest

# Use in-memory SQLite for tests
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


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
