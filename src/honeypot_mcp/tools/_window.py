"""The end of a `since_hours` window.

A live server's "last 12 hours" ends now. A backup opened in `ANALYSIS_MODE` is a frozen run, so a
window measured from the wall clock lands after the data and every windowed answer comes back empty
(or, worse, silently covers a slice of nothing). In that mode the window ends at the newest alert
instead, and the result says so (`window_anchor`).

The newest alert cannot change while nothing is capturing, so it is looked up once and cached.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert

_cached: tuple[str, datetime | None] | None = None


def reset_for_tests() -> None:
    global _cached
    _cached = None


async def _newest_alert() -> datetime | None:
    # Highest id is the newest row and is an index seek; max(timestamp) would scan.
    async with get_session() as session:
        value = (
            await session.execute(select(Alert.timestamp).order_by(Alert.id.desc()).limit(1))
        ).scalar_one_or_none()
    if value is not None and value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value


async def window_end() -> datetime:
    """Where a `since_hours` window ends: now live, the newest alert in analysis mode."""
    global _cached
    settings = get_settings()
    if not settings.analysis_mode:
        return datetime.now(UTC)
    if _cached is None or _cached[0] != settings.database_url:
        _cached = (settings.database_url, await _newest_alert())
    newest = _cached[1]
    return newest if newest is not None else datetime.now(UTC)


async def window_anchor() -> dict[str, Any] | None:
    """What to merge into a result's `window` when the end is not "now", else None."""
    if not get_settings().analysis_mode:
        return None
    end = await window_end()
    return {
        "window_anchor": "newest alert",
        "window_end": end.isoformat(),
        "window_anchor_note": (
            "Analysis mode: windows end at the newest alert in this database, not at the current time."
        ),
    }


async def window_bounds(hours: float) -> tuple[datetime, datetime]:
    """`(since, end)` for a `since_hours` window: `end` is `window_end()`, `since` is `hours` before it."""
    end = await window_end()
    return end - timedelta(hours=hours), end


async def annotate_window(result: dict[str, Any]) -> dict[str, Any]:
    """Say, in analysis mode, that the result's window ends at the newest alert.

    A `window` that is a dict gets the anchor keys merged in; any other result (no window, or a
    textual one) gets them as top-level keys. Live servers are left untouched.
    """
    anchor = await window_anchor()
    if anchor is None:
        return result
    window = result.get("window")
    if isinstance(window, dict):
        window.update(anchor)
    else:
        result.update(anchor)
    return result
