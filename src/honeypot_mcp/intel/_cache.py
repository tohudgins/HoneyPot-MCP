"""Lightweight TTL cache for IP-enrichment lookups.

Why not LRU? Intel data is keyed by IP and changes on a slow timeline (hours-
to-days). A pure LRU would evict hot entries during a burst; a TTL gives us
predictable freshness regardless of workload shape.

We only cache successful responses (`available: True`). Errors and rate-limit
hits are NOT cached — caller wants the next call to retry, not be poisoned.
"""

from __future__ import annotations

import time
from typing import Any

_DEFAULT_TTL = 900  # 15 minutes — VT / AbuseIPDB sweet spot

_store: dict[str, tuple[float, dict[str, Any]]] = {}


def _now() -> float:
    return time.monotonic()


def get(key: str) -> dict[str, Any] | None:
    entry = _store.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if _now() > expires_at:
        _store.pop(key, None)
        return None
    return value


def set(key: str, value: dict[str, Any], ttl: int = _DEFAULT_TTL) -> None:
    _store[key] = (_now() + ttl, value)


def clear() -> None:
    """Used by tests."""
    _store.clear()
