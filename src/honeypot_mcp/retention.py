"""Archive-then-delete for old alerts, shared by `alerts_prune` and the retention sweep.

Both paths must be safe on a table of millions of rows and must never destroy evidence they did not
first write down. The manual tool used to build the whole archive as ONE string in memory and
delete with one statement: on the live droplet's 4.9M-row, 3.8 GB table that is gigabytes of RAM on
a 4 GB host and a write lock held for the length of the delete. So there is one implementation:

* `archive_alerts` streams keyset-paginated chunks to a `.partial` file and renames it into place
  only when complete, so neither memory nor event-loop latency scales with the archive, and a
  failure leaves no file that looks like a finished archive. It returns the highest alert id it
  wrote, which confines the delete: no row is deleted unless it is on disk.
* `delete_before` deletes in bounded chunks, one transaction each, so the SQLite writer lock is
  never held for the whole job (a single DELETE of millions of rows outlasts busy_timeout and
  stalls ingest).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime
from typing import Any

from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.tools._format import resolve_artifact_path

log = logging.getLogger(__name__)


async def archive_alerts(
    cutoff: datetime, *, prefix: str, output_path: str | None = None
) -> tuple[int | None, dict[str, Any] | None]:
    """Stream alerts older than `cutoff` to a JSONL file in the reports directory.

    Returns `(highest alert id archived, {"path", "bytes", "lines"})`, or `(None, None)` when
    nothing was old enough. Raises if the destination is unusable or the write fails; a
    caller-named file is created exclusively and never replaces an existing one (the name can come
    from a model that has been reading attacker-authored payloads).
    """
    dest = resolve_artifact_path(output_path, prefix=prefix, extension="jsonl")
    if isinstance(dest, str):
        raise OSError(dest)
    if output_path is not None and dest.exists():
        raise FileExistsError(
            f"{dest.name!r} already exists in the reports directory; "
            "refusing to overwrite it. Pick another output_path."
        )
    partial = dest.with_name(dest.name + ".partial")
    await asyncio.to_thread(dest.parent.mkdir, parents=True, exist_ok=True)
    fh = await asyncio.to_thread(partial.open, "w", encoding="utf-8")
    last_id: int | None = None
    written = lines = 0
    try:
        try:
            first = True
            async with get_session() as session:
                async for chunk, chunk_last in queries.iter_alert_archive_chunks(session, cutoff):
                    text = ("" if first else "\n") + "\n".join(chunk)
                    await asyncio.to_thread(fh.write, text)
                    written += len(text.encode("utf-8"))
                    lines += len(chunk)
                    first = False
                    last_id = chunk_last
            await asyncio.to_thread(fh.flush)
        finally:
            await asyncio.to_thread(fh.close)
        if last_id is None:
            await asyncio.to_thread(partial.unlink, True)
            return None, None
        await asyncio.to_thread(partial.replace, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            partial.unlink(missing_ok=True)
        raise
    log.info("Alert archive written to %s (%d alerts)", dest, lines)
    return last_id, {"path": str(dest), "bytes": written, "lines": lines}


async def delete_before(cutoff: datetime, max_id: int | None = None) -> tuple[int, int]:
    """Delete alerts (at most up to `max_id`, when given) and attacker events older than `cutoff`,
    in bounded chunks. Returns `(alerts deleted, attacker events deleted)`."""
    alerts_deleted = events_deleted = 0
    if max_id != 0:  # 0 means "archived nothing": no alert is deletable
        while True:
            async with get_session() as session:
                n = await queries.delete_alerts_chunk(session, cutoff, max_id=max_id)
            alerts_deleted += n
            if n == 0:
                break
            await asyncio.sleep(0)
    while True:
        async with get_session() as session:
            n = await queries.delete_attacker_events_chunk(session, cutoff)
        events_deleted += n
        if n == 0:
            break
        await asyncio.sleep(0)
    return alerts_deleted, events_deleted
