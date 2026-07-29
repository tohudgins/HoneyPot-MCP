"""Shutdown must not cut off writes that are already in flight.

A lot of this codebase writes fire-and-forget: every engine's `_record`, the
CRITICAL-alert enrichment merge, `record_action` in the audit log. None of
those are awaited by anyone, so at the moment `close_db()` runs they may be
scheduled but not yet started, or started but mid-statement.

Disposing the engine underneath one of them destroys the write and surfaces
only as a stray `Cannot operate on a closed database` traceback from a task
nobody owns — an audit entry or an enrichment result silently gone. It also
made CI intermittently red with a `KeyError: 'connection'` raised out of
`dispose()` itself, on a different test each time depending on ordering.

Two properties are pinned here, and the first one is the subtle half: a
fire-and-forget task has *not run yet* when close is called, so waiting on a
session counter alone reads zero and disposes straight through it.
"""

from __future__ import annotations

import asyncio
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

pytestmark = pytest.mark.asyncio


def _honeypot(name: str):
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    return Honeypot(
        name=name, type=HoneypotType.SMTP, port=1, status=HoneypotStatus.STOPPED, config={}
    )


async def test_a_scheduled_write_still_completes_across_close():
    """The task exists but has not started — the case a counter alone misses."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()

    finished = asyncio.Event()
    failed: list[BaseException] = []

    async def writer() -> None:
        try:
            async with get_session() as session:
                session.add(_honeypot("late-writer"))
        except BaseException as e:  # noqa: BLE001 - recording it is the assertion
            failed.append(e)
        finally:
            finished.set()

    asyncio.create_task(writer())
    # Deliberately no yield here: this is exactly how the engines call it.
    await close_db()

    assert finished.is_set(), "close_db disposed before the write could run"
    assert not failed, f"the in-flight write was killed: {failed!r}"
    event_buffer.reset_for_tests()


async def test_close_waits_for_a_session_that_is_already_open():
    from honeypot_mcp.storage import database, event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()

    opened = asyncio.Event()
    release = asyncio.Event()
    finished = asyncio.Event()

    async def slow_writer() -> None:
        async with get_session() as session:
            session.add(_honeypot("slow-writer"))
            opened.set()
            await release.wait()
        finished.set()

    asyncio.create_task(slow_writer())
    await opened.wait()
    assert database._active_sessions == 1

    closer = asyncio.create_task(close_db())
    await asyncio.sleep(0.05)
    assert not closer.done(), "close_db should be waiting on the open session"

    release.set()
    await asyncio.wait_for(closer, timeout=3)
    assert finished.is_set()
    event_buffer.reset_for_tests()


async def test_close_gives_up_rather_than_hanging_on_a_leaked_session(monkeypatch, caplog):
    """A session that never exits must not wedge shutdown forever."""
    import logging

    from honeypot_mcp.storage import database, event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    monkeypatch.setattr(database, "_CLOSE_GRACE_SECONDS", 0.2)
    monkeypatch.setattr(database, "_active_sessions", 1)  # simulate the leak

    with caplog.at_level(logging.WARNING, logger="honeypot_mcp.storage.database"):
        await asyncio.wait_for(close_db(), timeout=3)

    assert any("still open" in r.getMessage() for r in caplog.records), (
        "giving up on a leaked session must be reported, not silent"
    )
    monkeypatch.setattr(database, "_active_sessions", 0)
    event_buffer.reset_for_tests()


async def test_session_counter_returns_to_zero_even_on_error():
    """A rolled-back session must not leak a count and stall every later close."""
    from honeypot_mcp.storage import database, event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()

    with pytest.raises(RuntimeError):
        async with get_session():
            raise RuntimeError("boom")

    assert database._active_sessions == 0
    await close_db()
    event_buffer.reset_for_tests()


async def test_a_fired_token_says_where_it_was_planted():
    """ "Token X fired" is half an alert; the other half is which system it was on.

    A deployment scatters tokens across file shares, wiki pages, config files
    and cloud accounts. Months later one fires, and the first triage question
    is where it lived — that is what identifies the system the attacker
    actually reached. Recording it at creation is the only moment the operator
    knows.
    """
    from urllib.parse import urlparse

    from aiohttp.test_utils import TestClient, TestServer
    from sqlalchemy import select

    from honeypot_mcp.canary import build_app
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()

    server = TestServer(build_app())
    client = TestClient(server)
    await client.start_server()
    try:
        token = await honeytoken_create(
            type="canary_url",
            label="finance-wiki-link",
            planted_at="IT wiki page 114, 'Quarterly Close Runbook'",
        )
        await client.get(urlparse(token["token_value"]).path)
        await asyncio.sleep(1.0)

        async with get_session() as session:
            alert = (await session.execute(select(Alert))).scalars().first()
        assert alert is not None
        assert alert.severity.value == "critical"
        assert alert.payload["token_label"] == "finance-wiki-link"
        assert alert.payload["planted_at"] == "IT wiki page 114, 'Quarterly Close Runbook'"
    finally:
        await client.close()
        await buffer.stop()
        await close_db()
        event_buffer.reset_for_tests()


async def test_planted_at_is_optional_and_absent_reads_as_empty():
    """Not recording a location must not break the alert path."""
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    event_buffer.reset_for_tests()
    await init_db()
    try:
        token = await honeytoken_create(type="canary_url", label="no-location")
        assert "planted_at" not in (token.get("metadata") or {})
    finally:
        await close_db()
        event_buffer.reset_for_tests()
