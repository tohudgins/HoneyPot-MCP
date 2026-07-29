"""Shared test configuration.

Kept deliberately small: the only thing here is the timing knob that makes
buffer-dependent assertions deterministic.
"""

import os

import pytest

# Every test that drives an engine ends up asserting on rows the event buffer
# wrote. The buffer flushes a partial batch once per `flush_interval`, which
# defaults to 1 second — and the suite is full of `await asyncio.sleep(1.0)`
# followed immediately by a query. That is a coin flip: on an unloaded laptop
# the flush wins, on a loaded CI runner it doesn't, and the failure lands on
# whichever engine test happened to lose that run.
#
# Shortening the interval for tests turns those exact-boundary waits into a
# 20x margin without rewriting 40-odd assertions.
os.environ.setdefault("EVENT_FLUSH_INTERVAL_SECONDS", "0.05")


@pytest.fixture(autouse=True)
def _fast_flush():
    """Guard the setting against a cached Settings singleton built earlier."""
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    if settings.event_flush_interval_seconds > 0.2:
        settings.event_flush_interval_seconds = 0.05
    yield
