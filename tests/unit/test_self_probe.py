"""Health probes must not appear in the attack data.

The watchdog checks every running honeypot every 30s by opening a TCP
connection to it. Ten in-process engines log a bare `<proto>_connection`
event the moment a peer connects, so each check manufactured one fake attack
per honeypot per cycle — about 2,880 a day each. On the demo stack, with four
honeypots running, that was 33% of every row in the alerts table, and
`127.0.0.1` was the top attacker by two orders of magnitude.

The end-to-end test below is the one that matters: it runs a real engine, a
real `tcp_probe`, and the real buffer, and asserts the difference between a
probe and an attacker.
"""

from __future__ import annotations

import asyncio
import os
import socket

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup():
    from honeypot_mcp import self_probe
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    self_probe.reset_for_tests()
    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()
    self_probe.reset_for_tests()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def test_watchdog_probe_does_not_become_an_alert():
    """A real probe against a real engine produces no alert; an attacker does.

    Both halves are necessary. Suppressing the probe is only correct if
    genuine traffic to the same port still lands — a fix that silenced the
    engine would pass the first assertion alone.
    """
    from sqlalchemy import select

    from honeypot_mcp.engines.base import tcp_probe
    from honeypot_mcp.engines.ftp import FTPEngine
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = _free_port()
    engine = FTPEngine()
    container_id = await engine.start("probe-test", port, {})
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        result = await tcp_probe(port)
        assert result["alive"] is True
        await asyncio.sleep(0.5)

        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        assert rows == [], f"health probe was recorded as an attack: {[r.event_type for r in rows]}"

        # A real client connecting to the same port must still be recorded.
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.read(128)
        writer.close()
        await asyncio.sleep(0.5)

        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        assert [r.event_type for r in rows] == ["ftp_connection"]
    finally:
        await buf.stop()
        await engine.stop(container_id)


async def test_claim_is_one_shot():
    """A probe drops exactly one event, never a second from the same peer.

    Without this, an attacker who happened to reuse the ephemeral port would
    get a free pass for as long as the entry lived.
    """
    from honeypot_mcp import self_probe

    self_probe.register(("127.0.0.1", 54321))
    assert self_probe.claim("127.0.0.1", 54321) is True
    assert self_probe.claim("127.0.0.1", 54321) is False


async def test_claim_requires_both_ip_and_port_to_match():
    from honeypot_mcp import self_probe

    self_probe.register(("127.0.0.1", 54321))
    assert self_probe.claim("127.0.0.1", 54322) is False
    assert self_probe.claim("10.0.0.5", 54321) is False
    assert self_probe.claim(None, 54321) is False
    assert self_probe.claim("127.0.0.1", None) is False
    # The original is untouched by the misses above.
    assert self_probe.claim("127.0.0.1", 54321) is True


async def test_entries_expire(monkeypatch):
    """A probe that never produces an event cannot suppress a later one."""
    from honeypot_mcp import self_probe

    clock = {"t": 1000.0}
    monkeypatch.setattr(self_probe.time, "monotonic", lambda: clock["t"])

    self_probe.register(("127.0.0.1", 54321))
    clock["t"] += self_probe._TTL_SECONDS + 1
    assert self_probe.claim("127.0.0.1", 54321) is False
    assert self_probe.pending_count() == 0


async def test_register_tolerates_a_socket_that_never_connected():
    """`get_extra_info("sockname")` is None on a failed connection."""
    from honeypot_mcp import self_probe

    self_probe.register(None)
    self_probe.register(())
    self_probe.register(("127.0.0.1",))
    assert self_probe.pending_count() == 0

    # IPv6 socknames are 4-tuples; the leading pair is still the address.
    self_probe.register(("::1", 4444, 0, 0))
    assert self_probe.claim("::1", 4444) is True
