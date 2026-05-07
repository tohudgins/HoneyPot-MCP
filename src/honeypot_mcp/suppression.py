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
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import time
from dataclasses import dataclass

from sqlalchemy import select

from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent
from honeypot_mcp.storage.models import SuppressionRule

log = logging.getLogger(__name__)

RULE_REFRESH_SECONDS = 30


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
# (rule_id, ip, event_type) → list of monotonic timestamps of events seen in window
_rate_state: dict[tuple[int, str, str], list[float]] = {}


def invalidate_rule_cache() -> None:
    """Force the next suppression check to reload rules from the DB."""
    global _rules_loaded_at
    _rules_loaded_at = 0.0


async def _load_rules() -> None:
    global _rules, _rules_loaded_at
    now = time.monotonic()
    if now - _rules_loaded_at < RULE_REFRESH_SECONDS:
        return

    async with get_session() as session:
        result = await session.execute(
            select(SuppressionRule).where(SuppressionRule.active.is_(True))
        )
        live = list(result.scalars().all())

    new_rules: list[_Rule] = []
    wall_now = time.time()
    for r in live:
        if r.expires_at is not None and r.expires_at.timestamp() < wall_now:
            continue
        new_rules.append(_Rule(
            id=r.id,
            label=r.label,
            ip_pattern=r.ip_pattern or None,
            event_type_pattern=r.event_type_pattern or None,
            action=r.action,
            rate_limit_count=r.rate_limit_count,
            rate_limit_window_seconds=r.rate_limit_window_seconds,
            expires_at=r.expires_at.timestamp() if r.expires_at else None,
        ))
    _rules = new_rules
    _rules_loaded_at = now


def _ip_matches(pattern: str, ip: str) -> bool:
    try:
        net = ipaddress.ip_network(pattern, strict=False)
        return ipaddress.ip_address(ip) in net
    except (ValueError, TypeError):
        return pattern == ip


def _event_type_matches(pattern: str, event_type: str) -> bool:
    return fnmatch.fnmatchcase(event_type, pattern)


def _rule_matches(rule: _Rule, event: PendingEvent) -> bool:
    if rule.ip_pattern and not _ip_matches(rule.ip_pattern, event.source_ip):
        return False
    if rule.event_type_pattern and not _event_type_matches(rule.event_type_pattern, event.event_type):
        return False
    return True


def _rate_limited(rule: _Rule, event: PendingEvent) -> bool:
    """Return True if this rate-limit rule says drop this event."""
    if rule.rate_limit_count is None or rule.rate_limit_window_seconds is None:
        return True  # malformed rule — treat as drop to be safe

    key = (rule.id, event.source_ip, event.event_type)
    now = time.monotonic()
    window_start = now - rule.rate_limit_window_seconds
    history = _rate_state.get(key, [])
    history = [t for t in history if t >= window_start]
    if len(history) >= rule.rate_limit_count:
        _rate_state[key] = history
        return True
    history.append(now)
    _rate_state[key] = history
    return False


async def should_suppress(event: PendingEvent) -> tuple[bool, int | None]:
    """Return `(suppress, matched_rule_id)`. The rule_id lets the caller
    increment that rule's `suppressed_count` for visibility."""
    await _load_rules()
    for rule in _rules:
        if not _rule_matches(rule, event):
            continue
        if rule.action == "drop":
            return True, rule.id
        if rule.action == "rate_limit" and _rate_limited(rule, event):
            return True, rule.id
    return False, None
