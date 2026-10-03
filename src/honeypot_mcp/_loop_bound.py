"""Per-event-loop holder for asyncio synchronisation primitives.

`asyncio.Lock` / `asyncio.Semaphore` bind to the running loop the first time
they have to *wait*. A module-level instance therefore works for the life of a
production process (one loop) but raises "is bound to a different event loop"
the first time a second loop — every pytest-asyncio test gets its own — contends
on it. `LoopBound` hands out a primitive that belongs to the current loop,
building a fresh one when the loop changes.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")


class LoopBound(Generic[T]):
    def __init__(self, factory: Callable[[], T]) -> None:
        self._factory = factory
        self._loop: asyncio.AbstractEventLoop | None = None
        self._obj: T | None = None

    def get(self) -> T:
        loop = asyncio.get_running_loop()
        if self._obj is None or self._loop is not loop:
            self._obj = self._factory()
            self._loop = loop
        return self._obj
