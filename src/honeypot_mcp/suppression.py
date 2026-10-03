"""Event suppression engine.

Two responsibilities:
1. Drop events whose source IP / event type matches an active rule (action=drop).
2. Rate-limit events: keep the first N within a sliding window, drop the rest
   (action=rate_limit). When the window expires, the next event passes again.

Rules are cached in memory and refreshed every `RULE_REFRESH_SECONDS` to avoid
a DB round-trip on every event. The cache is also invalidated explicitly when
rules are added/removed via MCP tools — `invalidate_rule_cache()`.

Pattern semantics:
- `ip_pattern`: empty matches anything; otherwise tried as CIDR first
  (e.g. `10.0.0.0/8`), falling back to exact string match.
- `event_type_pattern`: empty matches anything; otherwise glob via `fnmatch`
  so `ssh_*` matches `ssh_login_failed` etc.

Hit counters (`suppressed_count`) are tallied in memory and written back in
batches by `flush_suppression_counts()` — one UPDATE per rule per flush rather
than a session, UPDATE and commit per dropped event, which during a flood
turned the thing that sheds load into a second load.
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache

from sqlalchemy import select, update

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent
from honeypot_mcp.storage.models import SuppressionRule

log = logging.getLogger(__name__)

RULE_REFRESH_SECONDS = 30
# After a failed refresh, retry this many seconds later rather than on the next
# event — otherwise a database outage turns every submit into a failing SELECT.
_REFRESH_RETRY_SECONDS = 5


@dataclass
class _Rule:
    id: int
    label: str
    ip_pattern: str | None
    event_type_pattern: str | None
    action: str
    rate_limit_count: int | None
    rate_limit_window_seconds: int | None
    expires_at: float | None  # monotonic-clock seconds


_rules: list[_Rule] = []
_rules_loaded_at: float = 0.0
_refresh_lock: LoopBound[asyncio.Lock] = LoopBound(asyncio.Lock)
_refresh_failing = False
# (rule_id, ip, event_type) → list of monotonic timestamps of events seen in window.
# An OrderedDict so the least recently used key can be shed when the table hits
# its hard cap; every access moves the key to the end.
_rate_state: OrderedDict[tuple[int, str, str], list[float]] = OrderedDict()
# Above this many tracked keys we sweep out decayed entries on the next check.
# Mirrors canary.py's _rate_state / _RATE_STATE_MAX_IPS — the identical
# unbounded-growth risk (one entry per distinct key ever seen on a long-lived
# public deployment), just keyed on rule+IP+event_type instead of IP alone.
_RATE_STATE_MAX_KEYS = 10_000
# The sweep is O(n), so it runs at most this often; between sweeps the hard cap
# below is what bounds the table, shedding least-recently-used keys one at a time.
_RATE_SWEEP_MIN_INTERVAL = 5.0
_RATE_STATE_HARD_CAP = 4 * _RATE_STATE_MAX_KEYS
_last_rate_sweep_at: float = float("-inf")

# rule_id → events dropped since the last flush.
_pending_counts: dict[int, int] = {}


def invalidate_rule_cache() -> None:
    """Force the next suppression check to reload rules from the DB."""
    global _rules_loaded_at, _last_rate_sweep_at
    _rules_loaded_at = 0.0
    # Rules changed, so decayed rate-limit state may be sweepable right away.
    _last_rate_sweep_at = float("-inf")


def _rules_fresh() -> bool:
    return time.monotonic() - _rules_loaded_at < RULE_REFRESH_SECONDS


async def _load_rules() -> None:
    """Refresh the rule cache if it has expired.

    Double-checked under a lock so a burst of events arriving at expiry causes
    one SELECT, not one each. If the refresh fails the previous rules stay in
    force and the caller carries on — losing an event because the *suppression
    table* could not be read would be the wrong failure.
    """
    global _rules, _rules_loaded_at, _refresh_failing
    if _rules_fresh():
        return
    async with _refresh_lock.get():
        if _rules_fresh():
            return
        now = time.monotonic()
        try:
            async with get_session() as session:
                result = await session.execute(
                    select(SuppressionRule).where(SuppressionRule.active.is_(True))
                )
                live = list(result.scalars().all())
        except Exception as e:
            if not _refresh_failing:
                log.warning(
                    "Suppression rule refresh failed (%s) — keeping the previous %d rule(s).",
                    e,
                    len(_rules),
                )
            _refresh_failing = True
            _rules_loaded_at = now - RULE_REFRESH_SECONDS + _REFRESH_RETRY_SECONDS
            return

        _refresh_failing = False
        new_rules: list[_Rule] = []
        wall_now = time.time()
        for r in live:
            if r.expires_at is not None and r.expires_at.timestamp() < wall_now:
                continue
            new_rules.append(
                _Rule(
                    id=r.id,
                    label=r.label,
                    ip_pattern=r.ip_pattern or None,
                    event_type_pattern=r.event_type_pattern or None,
                    action=r.action,
                    rate_limit_count=r.rate_limit_count,
                    rate_limit_window_seconds=r.rate_limit_window_seconds,
                    expires_at=r.expires_at.timestamp() if r.expires_at else None,
                )
            )
        _rules = new_rules
        _rules_loaded_at = now


@lru_cache(maxsize=1024)
def _parse_network(
    pattern: str,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except (ValueError, TypeError):
        return None


def _ip_matches(pattern: str, ip: str) -> bool:
    net = _parse_network(pattern)
    if net is None:
        return pattern == ip
    try:
        return ipaddress.ip_address(ip) in net
    except (ValueError, TypeError):
        return pattern == ip


def _event_type_matches(pattern: str, event_type: str) -> bool:
    return fnmatch.fnmatchcase(event_type, pattern)


def _rule_matches(rule: _Rule, event: PendingEvent) -> bool:
    if rule.ip_pattern and not _ip_matches(rule.ip_pattern, event.source_ip):
        return False
    return not (
        rule.event_type_pattern
        and not _event_type_matches(rule.event_type_pattern, event.event_type)
    )


def _evict_stale_rate_state() -> None:
    """Drop (rule_id, ip, event_type) entries whose window has fully decayed
    for their own rule, or whose rule no longer exists. Called only when the
    table grows large, mirroring canary.py's _evict_stale_rate_windows."""
    now = time.monotonic()
    windows = {r.id: r.rate_limit_window_seconds for r in _rules if r.rate_limit_window_seconds}
    stale = [
        key
        for key, history in _rate_state.items()
        if not history or key[0] not in windows or history[-1] < now - windows[key[0]]
    ]
    for key in stale:
        del _rate_state[key]


def _bound_rate_state() -> None:
    """Keep `_rate_state` bounded without scanning it on every call.

    The O(n) sweep of decayed entries is rate-limited; the hard cap (shed the
    least recently used key) is O(1) per insertion and is what guarantees the
    table cannot grow without bound between sweeps."""
    global _last_rate_sweep_at
    if len(_rate_state) > _RATE_STATE_MAX_KEYS:
        now = time.monotonic()
        if now - _last_rate_sweep_at >= _RATE_SWEEP_MIN_INTERVAL:
            _last_rate_sweep_at = now
            _evict_stale_rate_state()
    while len(_rate_state) > _RATE_STATE_HARD_CAP:
        _rate_state.popitem(last=False)


def _rate_limited(rule: _Rule, event: PendingEvent) -> bool:
    """Return True if this rate-limit rule says drop this event."""
    if rule.rate_limit_count is None or rule.rate_limit_window_seconds is None:
        return True  # malformed rule — treat as drop to be safe

    _bound_rate_state()

    key = (rule.id, event.source_ip, event.event_type)
    now = time.monotonic()
    window_start = now - rule.rate_limit_window_seconds
    history = _rate_state.get(key, [])
    history = [t for t in history if t >= window_start]
    limited = len(history) >= rule.rate_limit_count
    if not limited:
        history.append(now)
    _rate_state[key] = history
    _rate_state.move_to_end(key)
    return limited


async def should_suppress(event: PendingEvent) -> tuple[bool, int | None]:
    """Return `(suppress, matched_rule_id)`. The rule_id lets the caller
    count the drop against that rule via `record_suppressed`."""
    await _load_rules()
    for rule in _rules:
        if not _rule_matches(rule, event):
            continue
        if rule.action == "drop":
            return True, rule.id
        if rule.action == "rate_limit" and _rate_limited(rule, event):
            return True, rule.id
    return False, None


def record_suppressed(rule_id: int) -> None:
    """Count one dropped event against `rule_id` (in memory; see
    `flush_suppression_counts`)."""
    _pending_counts[rule_id] = _pending_counts.get(rule_id, 0) + 1


def pending_suppression_counts() -> dict[int, int]:
    """Drops counted but not yet written to `suppression_rules.suppressed_count`.
    Readers that report that column add these to stay exact."""
    return dict(_pending_counts)


async def flush_suppression_counts() -> None:
    """Write the in-memory drop tallies to the database: one UPDATE per rule,
    one transaction. Best-effort — on failure the tallies are kept for the next
    attempt, and a missed counter is never worth back-pressuring ingest."""
    if not _pending_counts:
        return
    batch = dict(_pending_counts)
    _pending_counts.clear()
    try:
        async with get_session() as session:
            for rule_id, n in batch.items():
                await session.execute(
                    update(SuppressionRule)
                    .where(SuppressionRule.id == rule_id)
                    .values(suppressed_count=SuppressionRule.suppressed_count + n)
                )
    except Exception as e:
        for rule_id, n in batch.items():
            _pending_counts[rule_id] = _pending_counts.get(rule_id, 0) + n
        log.debug("Could not flush suppression counts: %s", e)
