"""Lightweight TTL cache for IP-enrichment lookups.

Why not LRU? Intel data is keyed by IP and changes on a slow timeline (hours-
to-days). A pure LRU would evict hot entries during a burst; a TTL gives us
predictable freshness regardless of workload shape.

We only cache successful responses (`available: True`) under the normal key.
Errors and rate-limit hits are NOT cached there — the caller wants a retry, not
to be poisoned. They can be remembered briefly under a separate *negative* key
(`set_negative` / `get_negative`, ~60 s) so a flood of CRITICALs from one IP
during an outage or a 429 does not turn into a flood of failing API calls.

The store is keyed by attacker IP, so it is size-capped: past `_MAX_ENTRIES`
the oldest-inserted entries are evicted (expired ones go first when a sweep is
due).
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any

_DEFAULT_TTL = 900  # 15 minutes — VT / AbuseIPDB sweet spot
_NEGATIVE_TTL = 60
_MAX_ENTRIES = 10_000
_SWEEP_INTERVAL = 60.0
_NEGATIVE_PREFIX = "neg:"

_store: OrderedDict[str, tuple[float, dict[str, Any]]] = OrderedDict()
_last_sweep: float = float("-inf")


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


def _evict() -> None:
    global _last_sweep
    if len(_store) <= _MAX_ENTRIES:
        return
    now = _now()
    if now - _last_sweep >= _SWEEP_INTERVAL:
        _last_sweep = now
        for k in [k for k, (exp, _v) in _store.items() if now > exp]:
            del _store[k]
    while len(_store) > _MAX_ENTRIES:
        _store.popitem(last=False)


def set(key: str, value: dict[str, Any], ttl: int = _DEFAULT_TTL) -> None:
    _store.pop(key, None)
    _store[key] = (_now() + ttl, value)
    _evict()


def get_negative(key: str) -> dict[str, Any] | None:
    """A recently cached failure for `key`, if any."""
    return get(_NEGATIVE_PREFIX + key)


def set_negative(key: str, value: dict[str, Any], ttl: int = _NEGATIVE_TTL) -> None:
    """Remember a failure for `key` briefly. Never visible through `get(key)`."""
    set(_NEGATIVE_PREFIX + key, value, ttl)


def size() -> int:
    return len(_store)


def clear() -> None:
    """Used by tests."""
    _store.clear()
