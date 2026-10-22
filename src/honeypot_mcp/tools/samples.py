"""`sample_scan` and `sample_collect`: what to do with the files the honeypots captured.

The engine (confined quarantine, YARA, collection from Cowrie containers) is `samples.py`; this
module is the MCP surface, the database join and the audit trail. Captured files are live malware
that is never executed or returned: results are hashes, sizes, types, rule hits and clipped
excerpts, and the full per-file table goes to an artifact file.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from honeypot_mcp import samples
from honeypot_mcp.config import get_settings
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._format import mark_untrusted, write_artifact
from honeypot_mcp.tools._planted import load_planted
from honeypot_mcp.tools._scan import _FILE_TYPES, _clip, _iso, _jv, file_origin

_TOP_FILES = 10
# Hashes per database pass. Every pass reads the file-event rows once (the `event_type` index, then
# the payload of each row), so the number of passes is what costs: 900 stays under SQLite's old
# 999-variable ceiling with the six event types, and is 4.5x fewer passes than the 200 it was.
_HASH_CHUNK = 900
# Distinct (hash, event type, source, url, message, name) groups kept in memory: a bound on the
# result, never reached by a capture of any realistic size.
_GROUP_ROW_CAP = 200_000


@dataclass
class DatabaseContext:
    """What `database_context` found and how much of the question it got to ask."""

    by_hash: dict[str, dict[str, Any]]
    looked_up: set[str]
    total: int
    budget_seconds: float
    capped: bool = False

    @property
    def complete(self) -> bool:
        return len(self.looked_up) == self.total

    @property
    def not_looked_up(self) -> int:
        return self.total - len(self.looked_up)


async def database_context(hashes: list[str]) -> DatabaseContext:
    """What the database knows about each hash: the file-capture events (`*_file_download`,
    `*_file_upload`) that carry it. The origin logic is `attack_patterns kind=files`'s own
    (`file_origin`): Cowrie logs a `wget` and an attacker's `echo ... > file` as the same event
    type, and only the first is a download. Planted honeytoken passwords are masked, as there.

    Each pass over the file events answers up to `_HASH_CHUNK` hashes and is aggregated in the
    database, one row per distinct (hash, event type, source, url, message, name) with its count
    and first/last time, so a million repeats of one dropper cost one row. The wall-clock budget
    (`sample_context_seconds`) is checked between passes; when it runs out the hashes not yet
    asked about are left out and `DatabaseContext.complete` is False. The first pass always runs.
    """
    budget = float(get_settings().sample_context_seconds)
    result = DatabaseContext(by_hash={}, looked_up=set(), total=len(hashes), budget_seconds=budget)
    if not hashes:
        return result
    planted = await load_planted()
    types = sorted({t for pair in _FILE_TYPES.values() for t in pair})
    # Label names, not expressions, in GROUP BY: on PostgreSQL the key of `payload ->> $n` is a
    # bound parameter, so the same expression written twice would be two different expressions.
    sha_expr = func.coalesce(_jv("shasum"), _jv("sha256")).label("sha")
    cols = [
        sha_expr,
        Alert.event_type.label("etype"),
        Alert.source_ip.label("src"),
        _jv("url").label("url"),
        _jv("message").label("msg"),
        _jv("destfile").label("destfile"),
        _jv("filename").label("fname"),
    ]
    rows: list[Any] = []
    deadline = time.monotonic() + budget
    async with get_session() as session:
        for start in range(0, len(hashes), _HASH_CHUNK):
            if start and time.monotonic() >= deadline:
                break
            chunk = hashes[start : start + _HASH_CHUNK]
            stmt = (
                select(*cols, func.count(), func.min(Alert.timestamp), func.max(Alert.timestamp))
                .where(Alert.event_type.in_(types), sha_expr.in_(chunk))
                .group_by(*cols)
                .limit(_GROUP_ROW_CAP - len(rows))
            )
            rows.extend((await session.execute(stmt)).all())
            result.looked_up.update(chunk)
            if len(rows) >= _GROUP_ROW_CAP:
                result.capped = True
                break

    grouped: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        grouped[row[0]].append(row)
    for sha, events in grouped.items():
        origins: Counter[str] = Counter()
        types_seen: Counter[str] = Counter()
        names: Counter[str] = Counter()
        urls: Counter[str] = Counter()
        sources: set[str] = set()
        total = 0
        first = last = None
        for _sha, event_type, ip, url, message, destfile, filename, count, lo, hi in events:
            total += count
            origins[file_origin(event_type, url, message, destfile)] += count
            types_seen[event_type] += count
            sources.add(ip)
            first = lo if first is None or lo < first else first
            last = hi if last is None or hi > last else last
            if destfile or filename:
                names[destfile or filename] += count
            if url and "://" in url:
                urls[url] += count
        result.by_hash[sha] = {
            "events": total,
            "distinct_sources": len(sources),
            "first_seen": _iso(first),
            "last_seen": _iso(last),
            "origin": origins.most_common(1)[0][0],
            "origins": dict(origins),
            "written_by_session": origins.get("written_by_session", 0),
            "fetched_from_network": origins.get("fetched_from_network", 0),
            "event_types": dict(types_seen),
            "destination_names": [_clip(planted.redact(n), 120) for n, _ in names.most_common(3)],
            "source_urls": [_clip(planted.redact(u)) for u, _ in urls.most_common(3)],
        }
    return result


def _quarantine_entries() -> list[str]:
    """Top-level names in the quarantine (what `path` can name), without creating anything."""
    try:
        root = get_settings().samples_dir
        return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return []


@mcp.tool(auth=require_role("operator"), **hints("sample_scan"))
async def sample_scan(path: str | None = None) -> dict[str, Any]:
    """Hash, type and YARA-scan the malware samples the honeypots captured.

    Use it for "what did the attackers drop?", "scan the samples", "is any of it Mirai or a
    miner?". Scans the whole quarantine by default (files `sample_collect` copied from the
    sensors, or a fetched backup's samples); nothing is executed or changed. Gives each file's
    SHA-256, size, type, YARA hits (family, severity), duplicates, and how many sources sent it
    and whether the shell wrote it or it was downloaded. The digest lists the ten most significant
    files; the full table is a file in the reports directory. Hand a hash to `lookup_hash`.

    Args:
        path: Only one sensor's samples, by name (for example `hp-ssh`). Optional.
    """
    status = samples.availability()
    if not status["available"]:
        return status
    path = path.strip() if isinstance(path, str) and path.strip() else None
    try:
        try:
            report = await asyncio.to_thread(samples.scan_records, path, None)
        except samples.SampleAccessError as exc:
            # "hp-ssh" is how a sensor is named; its directory is "honeypot-hp-ssh".
            if not (path and "not found" in exc.message and not path.startswith("honeypot-")):
                raise
            try:
                report = await asyncio.to_thread(samples.scan_records, f"honeypot-{path}", None)
                path = f"honeypot-{path}"
            except samples.SampleError:
                raise exc from None
    except samples.SampleError as exc:
        await _audit.record_action(
            "sample_scan",
            "Sample scan refused",
            arguments={"path": path},
            target=(path or ".")[:128],
            outcome="error",
            error=exc.message[:500],
        )
        failure = exc.as_result()
        entries = _quarantine_entries()
        if path and "not found" in exc.message:
            failure["hint"] = (
                f"Sample folders: {', '.join(entries[:10])}. Name one of them."
                if entries
                else "The quarantine holds no samples yet: run sample_collect on the sensor host."
            )
        return failure

    context = await database_context(sorted({r["sha256"] for r in report.records}))
    for record in report.records:
        record["database"] = context.by_hash.get(record["sha256"])
        if record["sha256"] not in context.looked_up:
            record["database_looked_up"] = False
    summary = samples.digest(
        report.records,
        report.skipped,
        top=_TOP_FILES,
        not_scanned=report.not_scanned,
        max_files=report.max_files,
    )
    rules_info = report.ruleset.describe()
    table = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": path or ".",
        "rules": rules_info,
        "summary": {k: v for k, v in summary.items() if k != "top_files"},
        "database_context_complete": context.complete,
        "files": report.records,
        "skipped": report.skipped,
    }
    artifact = write_artifact(
        json.dumps(table, indent=1, default=str), prefix="sample-scan", extension="json"
    )
    database: dict[str, Any] = {
        "files_with_context": sum(1 for r in report.records if r["database"]),
        "note": (
            "Context comes from ssh/telnet/ftp file-capture events whose hash equals the "
            "file's SHA-256. A file the database has no event for was collected from a "
            "container or a backup but never reported by a session (or the events were pruned)."
        ),
    }
    if not context.complete:
        database["context_note"] = (
            f"The capture-context lookup stopped at its {context.budget_seconds:g} s budget "
            f"(sample_context_seconds): {context.not_looked_up} of {context.total} distinct "
            "hashes were not looked up"
            + (" (the result-size cap was reached)" if context.capped else "")
            + ", so a file with `database: null` and `database_looked_up: false` may well have "
            "events. Scan one sensor's folder at a time to look them all up."
        )
    result: dict[str, Any] = {
        "available": True,
        "engine": status["engine"],
        "scope": path or ".",
        **summary,
        "database_context_complete": context.complete,
        "database": database,
        "rules": rules_info,
        "seconds": report.seconds,
        "next_step": (
            "Pass a sha256 to lookup_hash to ask MalwareBazaar about it. The full per-file table "
            "is in the artifact file."
        ),
    }
    if "error" in artifact:
        result["artifact_error"] = artifact["error"]
    else:
        result["artifact"] = artifact
    if not report.records and not report.skipped:
        entries = _quarantine_entries()
        result["note"] = (
            "No sample files found"
            + (f" under {path!r}" if path else " in the quarantine")
            + ". On the sensor host run sample_collect to copy what the SSH/Telnet honeypots "
            "captured; for a restored backup, copy its samples folder into the samples directory."
            + (f" Folders present: {', '.join(entries[:10])}." if entries else "")
        )
    hit_files = summary["files_with_hits"]
    await _audit.record_action(
        "sample_scan",
        f"Scanned {len(report.records)} sample file(s): {hit_files} with rule hits, "
        f"{len(report.skipped)} skipped",
        arguments={"path": path},
        target=(path or ".")[:128],
    )
    return mark_untrusted(result)


@mcp.tool(auth=require_role("admin"), **hints("sample_collect"))
async def sample_collect(honeypot: str | None = None) -> dict[str, Any]:
    """Copy the files the SSH and Telnet honeypots captured into the local quarantine.

    Use it for "pull the samples", "collect what the honeypots downloaded", before redeploying a
    sensor (Cowrie keeps downloads and session recordings inside its container, lost when the
    container is replaced). Safe to repeat: files already collected are skipped. Then run
    `sample_scan`. Only SSH and Telnet sensors run in a container; it needs Docker on the sensor
    host and says so clearly when there is none, or in analysis mode. Admin only.

    Args:
        honeypot: One sensor by name (for example `hp-ssh`). Optional: default is every running
                  SSH/Telnet sensor.
    """
    try:
        result = await asyncio.to_thread(samples.collect, honeypot)
    except samples.SampleError as exc:
        await _audit.record_action(
            "sample_collect",
            "Sample collection failed",
            arguments={"honeypot": honeypot},
            target=honeypot,
            outcome="error",
            error=exc.message[:500],
        )
        return exc.as_result()
    errors = [h["error"] for h in result["honeypots"] if h.get("error")]
    await _audit.record_action(
        "sample_collect",
        f"Collected {result['new_files']} new sample file(s) from "
        f"{result['containers_checked']} container(s)"
        + (f"; {len(errors)} container(s) failed" if errors else ""),
        arguments={"honeypot": honeypot},
        target=honeypot,
        outcome="error" if errors and not result["collected"] else "ok",
        error=errors[0][:500] if errors and not result["collected"] else None,
    )
    return result
