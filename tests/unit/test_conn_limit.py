"""Tests for the per-source-IP connection limiter.

Covers the counting logic (ConnectionLimiter) and the delegating protocol
wrapper (_LimitedProtocol) that admits or rejects a connection before the real
protocol sees it.
"""

import os

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

from honeypot_mcp.engines.conn_limit import (  # noqa: E402
    ConnectionLimiter,
    limited_factory,
)


def test_limiter_admits_up_to_cap_then_rejects():
    lim = ConnectionLimiter(max_per_ip=2)
    assert lim.try_acquire("1.2.3.4") is True
    assert lim.try_acquire("1.2.3.4") is True
    assert lim.try_acquire("1.2.3.4") is False  # at cap
    assert lim.live_count("1.2.3.4") == 2


def test_limiter_release_frees_a_slot():
    lim = ConnectionLimiter(max_per_ip=1)
    assert lim.try_acquire("1.2.3.4") is True
    assert lim.try_acquire("1.2.3.4") is False
    lim.release("1.2.3.4")
    assert lim.live_count("1.2.3.4") == 0
    assert lim.try_acquire("1.2.3.4") is True


def test_limiter_is_per_ip():
    lim = ConnectionLimiter(max_per_ip=1)
    assert lim.try_acquire("1.1.1.1") is True
    assert lim.try_acquire("2.2.2.2") is True  # different IP, own budget
    assert lim.try_acquire("1.1.1.1") is False


def test_limiter_zero_means_unlimited():
    lim = ConnectionLimiter(max_per_ip=0)
    for _ in range(1000):
        assert lim.try_acquire("1.2.3.4") is True
    # release is a no-op in unlimited mode and must not raise
    lim.release("1.2.3.4")
    assert lim.live_count("1.2.3.4") == 0


def test_limiter_release_without_acquire_is_safe():
    lim = ConnectionLimiter(max_per_ip=5)
    lim.release("9.9.9.9")  # never acquired
    assert lim.live_count("9.9.9.9") == 0


class _FakeTransport:
    def __init__(self, peer):
        self._peer = peer
        self.closed = False

    def get_extra_info(self, key, default=None):
        return self._peer if key == "peername" else default

    def close(self):
        self.closed = True


class _RecordingProtocol:
    """Stand-in inner protocol that records which callbacks it received."""

    def __init__(self):
        self.made = False
        self.data = []
        self.lost = False

    def connection_made(self, transport):
        self.made = True

    def data_received(self, data):
        self.data.append(data)

    def eof_received(self):
        return None

    def connection_lost(self, exc):
        self.lost = True

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass


def test_wrapper_admits_first_rejects_second_from_same_ip():
    lim = ConnectionLimiter(max_per_ip=1)
    inners = []

    def factory():
        p = _RecordingProtocol()
        inners.append(p)
        return p

    wrapped = limited_factory(factory, lim)

    # First connection: admitted, inner driven.
    p1 = wrapped()
    t1 = _FakeTransport(("1.2.3.4", 5000))
    p1.connection_made(t1)
    p1.data_received(b"hello")
    assert inners[0].made is True
    assert inners[0].data == [b"hello"]
    assert t1.closed is False

    # Second connection from same IP: rejected, transport closed, inner never driven.
    p2 = wrapped()
    t2 = _FakeTransport(("1.2.3.4", 5001))
    p2.connection_made(t2)
    p2.data_received(b"should-be-dropped")
    assert t2.closed is True
    assert inners[1].made is False
    assert inners[1].data == []


def test_wrapper_release_on_connection_lost_reopens_budget():
    lim = ConnectionLimiter(max_per_ip=1)
    wrapped = limited_factory(_RecordingProtocol, lim)

    p1 = wrapped()
    t1 = _FakeTransport(("1.2.3.4", 5000))
    p1.connection_made(t1)
    assert lim.live_count("1.2.3.4") == 1

    p1.connection_lost(None)
    assert lim.live_count("1.2.3.4") == 0

    # Budget freed — a new connection from the same IP is admitted.
    p2 = wrapped()
    t2 = _FakeTransport(("1.2.3.4", 5002))
    p2.connection_made(t2)
    assert t2.closed is False


def test_rejected_connection_lost_does_not_double_release():
    """A rejected connection still gets a connection_lost from asyncio; it must
    not release a slot it never acquired."""
    lim = ConnectionLimiter(max_per_ip=1)
    wrapped = limited_factory(_RecordingProtocol, lim)

    p1 = wrapped()
    p1.connection_made(_FakeTransport(("1.2.3.4", 5000)))

    p2 = wrapped()
    p2.connection_made(_FakeTransport(("1.2.3.4", 5001)))  # rejected
    p2.connection_lost(None)  # must be a no-op for the counter

    assert lim.live_count("1.2.3.4") == 1  # still just the admitted one
