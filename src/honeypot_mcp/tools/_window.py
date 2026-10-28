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

from sqlalchemy import func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert, AlertRollup

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


async def data_span(max_days: int = 30) -> tuple[datetime, datetime]:
    """The time range the data covers, for a link that must open on it: oldest hour to `window_end`.

    A saved run's dashboards opened on "the last 6 hours" are empty, so a link carries this range.
    The oldest hour comes from the hourly rollups (thousands of rows, exact to the hour, and not
    hidden by pruning old alerts), never from ordering millions of alert rows. Capped at `max_days`
    back from the end so a long-lived server does not open on years.
    """
    end = await window_end()
    async with get_session() as session:
        oldest = (await session.execute(select(func.min(AlertRollup.bucket)))).scalar_one_or_none()
    if oldest is not None and oldest.tzinfo is None:
        oldest = oldest.replace(tzinfo=UTC)
    start = min(oldest, end) if oldest is not None else end - timedelta(hours=24)
    return max(start, end - timedelta(days=max_days)), end


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
