"""Bound what one noisy source can write: store the first N events a minute, count the rest.

Found on the live droplet: one address sent SIP probes at about 190 events a second and the database
went from 1.1M to 4.9M rows in nine hours (3.8 GB, past the host's RAM). From then on the basic
analyst tools took tens of seconds or timed out, because every aggregate reads millions of rows that
carry no information the first few thousand did not. A probe flood is volume, not intelligence.

The guard is deliberately small and honest about what it drops:

* The key is (source address, event type). Different sources, and different kinds of event from the
  same source, are independent: a scanner that also tries a login still has the login recorded.
* The limit is generous (600 a minute, ten a second). A real brute-forcer or botnet session is far
  below it, so credentials and commands are kept; only a flood is cut.
* **Nothing is hidden.** When a window ends with events dropped, one `flood_summary` event is
  recorded for it, carrying how many were stored and how many were not, so volume stays visible even
  though it is no longer the storage mechanism. A source that stops mid-window still gets its
  summary: `due_summaries` sweeps ended windows on the next event from any source.
* CRITICAL events and honeytoken hits are never dropped; the caller exempts them.

Everything is in memory and bounded: at most `max_sources` windows, evicting the oldest quarter when
full (their pending counts are summarised first, never discarded).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from honeypot_mcp.storage.models import AlertSeverity

if TYPE_CHECKING:
    from honeypot_mcp.storage.event_buffer import PendingEvent

SUMMARY_EVENT_TYPE = "flood_summary"
_WINDOW_SECONDS = 60.0
# Sweeping every window on every event would be O(windows); every few seconds is plenty.
_SWEEP_INTERVAL_SECONDS = 5.0


class _Window:
    __slots__ = ("honeypot_id", "start", "stored", "suppressed")

    def __init__(self, start: float, honeypot_id: int | None) -> None:
        self.start = start
        self.stored = 0  # events kept in this window
        self.suppressed = 0  # events counted but not kept
        self.honeypot_id = honeypot_id


class FloodGuard:
    def __init__(self, per_minute: int = 600, max_sources: int = 50_000) -> None:
        self.per_minute = per_minute
        self.max_sources = max_sources
        self._windows: dict[tuple[str, str], _Window] = {}
        self._ready: list[PendingEvent] = []  # summaries of windows that already ended
        self._last_sweep = 0.0

    def admit(self, event: PendingEvent, now: float | None = None) -> bool:
        """True if this event should be stored. Either way it is counted."""
        if self.per_minute <= 0 or event.event_type == SUMMARY_EVENT_TYPE:
            return True
        now = time.monotonic() if now is None else now
        key = (event.source_ip or "", event.event_type)
        window = self._windows.get(key)
        if window is not None and now - window.start >= _WINDOW_SECONDS:
            self._close(key, window)
            window = None
        if window is None:
            if len(self._windows) >= self.max_sources:
                self._evict_oldest_quarter()
            window = self._windows[key] = _Window(now, event.honeypot_id)
        if window.stored < self.per_minute:
            window.stored += 1
            return True
        window.suppressed += 1
        return False

    def due_summaries(self, now: float | None = None, force: bool = False) -> list[PendingEvent]:
        """The `flood_summary` events owed for ended windows. Cheap enough to call on every event:
        it sweeps at most every few seconds unless `force` (shutdown, tests)."""
        now = time.monotonic() if now is None else now
        if force or now - self._last_sweep >= _SWEEP_INTERVAL_SECONDS:
            self._last_sweep = now
            for key, window in list(self._windows.items()):
                if force or now - window.start >= _WINDOW_SECONDS:
                    self._close(key, window)
        ready, self._ready = self._ready, []
        return ready

    def _close(self, key: tuple[str, str], window: _Window) -> None:
        self._windows.pop(key, None)
        if window.suppressed:
            self._ready.append(_summary(key, window))

    def _evict_oldest_quarter(self) -> None:
        oldest = sorted(self._windows, key=lambda k: self._windows[k].start)
        for key in oldest[: max(self.max_sources // 4, 1)]:
            self._close(key, self._windows[key])


def _summary(key: tuple[str, str], window: _Window) -> PendingEvent:
    from honeypot_mcp.storage.event_buffer import PendingEvent

    source_ip, event_type = key
    return PendingEvent(
        honeypot_id=window.honeypot_id,
        source_ip=source_ip,
        source_port=None,
        event_type=SUMMARY_EVENT_TYPE,
        payload={
            "event_type": event_type,
            "stored": window.stored,
            "suppressed": window.suppressed,
            "total": window.stored + window.suppressed,
            "window_seconds": int(_WINDOW_SECONDS),
            "note": (
                f"{window.suppressed} further {event_type} events from this source were counted "
                f"but not stored (limit {window.stored} a minute)"
            ),
        },
        severity=AlertSeverity.MEDIUM,
        timestamp=datetime.now(UTC),
    )


_guard: FloodGuard | None = None


def get_guard() -> FloodGuard:
    global _guard
    if _guard is None:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        _guard = FloodGuard(settings.flood_guard_per_minute, settings.flood_guard_max_sources)
    return _guard


def reset_for_tests() -> None:
    global _guard
    _guard = None
