"""Retained fire-and-forget tasks.

`asyncio.create_task()` only holds a *weak* reference to the task it returns, so
a task nobody else references can be garbage-collected mid-run — silently
dropping the event it was about to submit — and an exception it raises is
reported only as an unhelpful "Task exception was never retrieved" at GC time.

`spawn()` keeps a strong reference until the task finishes and logs any
exception with its traceback. Engines use it for every per-event / per-datagram
background coroutine instead of a bare `asyncio.create_task`.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any

log = logging.getLogger(__name__)

_live: set[asyncio.Task[Any]] = set()


def _done(task: asyncio.Task[Any]) -> None:
    _live.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        log.error("Background task %r failed", task.get_name(), exc_info=exc)


def spawn(coro: Coroutine[Any, Any, Any], *, name: str | None = None) -> asyncio.Task[Any]:
    """Schedule `coro`, retain it until done, and log any exception."""
    task = asyncio.get_running_loop().create_task(coro, name=name)
    _live.add(task)
    task.add_done_callback(_done)
    return task


def live_count() -> int:
    """Number of retained tasks still running (for tests and metrics)."""
    return len(_live)
