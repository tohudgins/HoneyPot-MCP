"""Helpers shared by `attack_patterns`, `extract_iocs` and `sample_scan`, importing no tool module.

Id-slice planning for the whole-capture scans of `attack_patterns` and `extract_iocs`, and the small
capture helpers (`_clip`, `_iso`, `file_origin`) that `sample_scan` also uses.

Both tools read one or a few event types over millions of rows. They cut the `event_type` index
range (`WHERE event_type = ? AND id > ? AND id <= ?`) into slices of `_CHUNK_ROWS`, read a few
slices at a time and stop when a time budget is spent. These helpers lived in `patterns`, which
imports the MCP server, which imports every tool module, which imported `patterns` again: importing
`honeypot_mcp.tools.patterns` first in a fresh interpreter died on a half-initialised module. Nothing
here imports the server or another tool, so any tool module can be imported first.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert

# Events per slice of a scan: ~1-2 s of database work for a wide payload, small enough that the time
# budget is checked often. A slice's rows are streamed and folded in batches, so this bounds time per
# slice, not memory.
_CHUNK_ROWS = 60_000
_SCAN_WORKERS = 6
# Rows fetched from the database per round trip while a slice is folded into the running totals.
_BATCH_ROWS = 1_000


def _expired(deadline: float) -> bool:
    return time.monotonic() >= deadline


def _scan_workers() -> int:
    # An in-memory SQLite database is one shared connection; slices cannot overlap on it.
    return 1 if ":memory:" in get_settings().database_url else _SCAN_WORKERS


def _jv(*path: str) -> Any:
    """A payload value as text, portable across SQLite (`json_extract`) and PostgreSQL (`->>`)."""
    key: Any = path[0] if len(path) == 1 else tuple(path)
    return Alert.payload[key].as_string()


async def _first_id_since(since: datetime) -> int | None:
    """The lowest alert id at or after `since`, from the timestamp index (None: no such alert).

    Ids rise with insertion and the flusher writes in batches, so the minimum over the first thousand
    rows by timestamp absorbs the small reordering a batch can introduce. The exact `timestamp >= since`
    filter is still applied to every row.
    """
    async with get_session() as session:
        first = (
            select(Alert.id).where(Alert.timestamp >= since).order_by(Alert.timestamp).limit(1000)
        )
        return (await session.execute(select(func.min(first.subquery().c.id)))).scalar()


async def _slice_plan(
    event_type: str, low_id: int, source_ip: str | None
) -> tuple[int, list[tuple[int | None, int | None]]]:
    """`(events of this type at or above low_id, [(after_id, up_to_id), ...])` in ascending order."""
    conds = [Alert.event_type == event_type, Alert.id >= low_id]
    if source_ip is not None:
        conds.append(Alert.source_ip == source_ip)
    async with get_session() as session:
        total = (await session.execute(select(func.count()).where(*conds))).scalar() or 0
        if total <= _CHUNK_ROWS:
            return total, [(None, None)]
        numbered = select(
            Alert.id.label("id"), func.row_number().over(order_by=Alert.id).label("rn")
        ).where(*conds)
        sub = numbered.subquery()
        bounds = [
            row[0]
            for row in await session.execute(
                select(sub.c.id).where(sub.c.rn % _CHUNK_ROWS == 0).order_by(sub.c.id)
            )
        ]
    if total % _CHUNK_ROWS == 0:
        bounds = bounds[:-1]  # the last boundary is the last row: the open-ended slice replaces it
    edges: list[int | None] = [None, *bounds, None]
    return total, list(zip(edges[:-1], edges[1:], strict=True))


_CLIP = 200


def _clip(value: Any, limit: int = _CLIP) -> str:
    text_value = value if isinstance(value, str) else str(value)
    return (
        text_value
        if len(text_value) <= limit
        else text_value[:limit] + f"… [{len(text_value)} chars]"
    )


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


# ── captured files ────────────────────────────────────────────────────────────

_FILE_TYPES = {
    "ssh": ("ssh_file_download", "ssh_file_upload"),
    "telnet": ("telnet_file_download", "telnet_file_upload"),
    "ftp": ("ftp_file_upload", "ftp_file_download"),
}
_URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def file_origin(event_type: str, url: str | None, message: str | None, destfile: str | None) -> str:
    """Where a captured file came from.

    Cowrie logs `cowrie.session.file_download` both when `wget`/`curl` fetched something over the
    network and when the shell saved the attacker's own text: a *redirection* (`printf ... > file`,
    "Saved redir contents ...") or piped standard input ("Saved stdin contents ..."). Those are not
    downloads. A real fetch carries the URL it came from; the saved text has none.
    """
    if event_type.endswith("_file_upload"):
        return "uploaded_by_client"
    if event_type == "ftp_file_download":
        return "decoy_retrieved"
    if url and _URL_SCHEME_RE.match(url):
        return "fetched_from_network"
    if (message or "").lower().startswith("saved ") or (destfile and not url):
        return "written_by_session"
    return "unknown"
