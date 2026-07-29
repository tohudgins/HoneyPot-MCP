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
        # FTP records in `connection_made`, which fires the moment the kernel
        # completes the handshake — before `connect()` returns. A claim made
        # after connecting loses that race, and did so consistently in a
        # container while passing on the developer's machine. Twenty probes
        # make the ordering bug reproducible rather than a coin flip.
        for _ in range(20):
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


async def test_probe_is_claimed_before_the_server_sees_it(monkeypatch):
    """The claim must be registered before the connection is made.

    This is the invariant, and it cannot be tested by timing: whether the
    server's `connection_made` runs before or after `connect()` returns is up
    to the event loop, so the original post-connect registration passed on
    macOS and failed in a container. Observing the *order of calls* instead is
    deterministic — with the claim ahead of `sock_connect` the server cannot
    possibly be first, because the syscall has not been issued yet.
    """
    import honeypot_mcp.self_probe as self_probe_mod
    from honeypot_mcp.engines.base import tcp_probe

    order: list[str] = []
    real_register = self_probe_mod.register

    def spy(sockname):
        order.append("claimed")
        real_register(sockname)

    monkeypatch.setattr(self_probe_mod, "register", spy)

    class _Server(asyncio.Protocol):
        def connection_made(self, transport):
            order.append("server_saw_connection")
            transport.close()

    loop = asyncio.get_running_loop()
    server = await loop.create_server(_Server, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert (await tcp_probe(port))["alive"] is True
        for _ in range(10):
            await asyncio.sleep(0.02)
            if "server_saw_connection" in order:
                break
        assert order[0] == "claimed", f"probe was visible before it was claimed: {order}"
    finally:
        server.close()
        await server.wait_closed()


async def test_probe_to_a_non_loopback_local_address_is_also_claimed():
    """Claims must not be limited to 127.0.0.1.

    The SSH health check falls back to probing a sibling container's IP when
    the host-published port isn't reachable from inside a container. Binding
    the probe to the *target* address only works for loopback, so that
    fallback went unclaimed and the watchdog's own SSH connections were
    recorded as attacks every 30 seconds.
    """
    from honeypot_mcp import self_probe
    from honeypot_mcp.engines.base import tcp_probe

    seen: list[tuple[str, int]] = []

    class _Server(asyncio.Protocol):
        def connection_made(self, transport):
            seen.append(transport.get_extra_info("peername"))
            transport.close()

    loop = asyncio.get_running_loop()
    # A routable local address that is not 127.0.0.1, so `bind((host, 0))`
    # would have been the only thing that worked before.
    host = socket.gethostbyname(socket.gethostname())
    try:
        server = await loop.create_server(_Server, host, 0)
    except OSError:
        pytest.skip("no non-loopback address available in this environment")
    port = server.sockets[0].getsockname()[1]
    try:
        assert (await tcp_probe(port, host=host))["alive"] is True
        for _ in range(20):
            await asyncio.sleep(0.02)
            if seen:
                break
        assert seen, "server never saw the probe"
        assert self_probe.claim(*seen[0]) is True, (
            f"probe from {seen[0]} was not claimed and would be logged as an attack"
        )
    finally:
        server.close()
        await server.wait_closed()


async def test_claim_covers_every_event_from_one_probe_connection():
    """A claim is per-connection, not per-event.

    One probe connection produces several events — Cowrie emits
    session-connect, client-version and session-closed for a single TCP
    open/close. A claim consumed on first use dropped the connect and let
    `ssh_session_closed` straight through, so the noise came back in a
    different shape.
    """
    from honeypot_mcp import self_probe

    self_probe.register(("127.0.0.1", 54321))
    assert self_probe.claim("127.0.0.1", 54321) is True
    assert self_probe.claim("127.0.0.1", 54321) is True
    assert self_probe.claim("127.0.0.1", 54321) is True


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
