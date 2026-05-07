"""Tests for the bulk hit-count query that fixed the N+1 problem in honeypot_list."""

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db
    await init_db()
    yield
    await close_db()


@pytest.mark.asyncio
async def test_get_hit_counts_groups_by_honeypot():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.models import (
        AlertSeverity,
        Honeypot,
        HoneypotType,
    )

    async with get_session() as session:
        a = Honeypot(name="hp-a", type=HoneypotType.SSH, port=2222)
        b = Honeypot(name="hp-b", type=HoneypotType.HTTP, port=8080)
        c = Honeypot(name="hp-c", type=HoneypotType.SMTP, port=2525)
        session.add_all([a, b, c])
        await session.flush()
        a_id, b_id, c_id = a.id, b.id, c.id

        # 3 hits on a, 1 hit on b, 0 on c
        for _ in range(3):
            await queries.create_alert(
                session, honeypot_id=a_id, source_ip="1.1.1.1",
                source_port=None, event_type="ssh", payload={}, severity=AlertSeverity.LOW,
            )
        await queries.create_alert(
            session, honeypot_id=b_id, source_ip="2.2.2.2",
            source_port=None, event_type="http", payload={}, severity=AlertSeverity.LOW,
        )

    async with get_session() as session:
        counts = await queries.get_hit_counts(session, [a_id, b_id, c_id])

    assert counts.get(a_id) == 3
    assert counts.get(b_id) == 1
    # Honeypots with zero hits are absent from the dict.
    assert c_id not in counts


@pytest.mark.asyncio
async def test_get_hit_counts_filters_by_id_list():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.models import (
        AlertSeverity,
        Honeypot,
        HoneypotType,
    )

    async with get_session() as session:
        a = Honeypot(name="x", type=HoneypotType.SSH, port=22)
        b = Honeypot(name="y", type=HoneypotType.HTTP, port=80)
        session.add_all([a, b])
        await session.flush()
        a_id, b_id = a.id, b.id
        for hp_id in (a_id, b_id):
            await queries.create_alert(
                session, honeypot_id=hp_id, source_ip="3.3.3.3",
                source_port=None, event_type="x", payload={}, severity=AlertSeverity.LOW,
            )

    async with get_session() as session:
        # Only ask about `a` — `b`'s count must not appear.
        counts = await queries.get_hit_counts(session, [a_id])
    assert counts == {a_id: 1}
