"""`sample_scan` and `sample_collect`: what to do with the files the honeypots captured.

The engine (confined quarantine, YARA, collection from Cowrie containers) is `samples.py`; this
module is the MCP surface, the database join and the audit trail. Captured files are live malware
that is never executed or returned: results are hashes, sizes, types, rule hits and clipped
excerpts, and the full per-file table goes to an artifact file.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from honeypot_mcp import samples
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._format import write_artifact
from honeypot_mcp.tools.patterns import (
    _FILE_TYPES,
    _clip,
    _iso,
    _jv,
    _load_planted,
    file_origin,
)

_HASH_CHUNK = 200
_EVENT_ROW_CAP = 200_000


async def database_context(hashes: list[str]) -> dict[str, dict[str, Any]]:
    """What the database knows about each hash: the file-capture events (`*_file_download`,
    `*_file_upload`) that carry it. The origin logic is `attack_patterns kind=files`'s own
    (`file_origin`): Cowrie logs a `wget` and an attacker's `echo ... > file` as the same event
    type, and only the first is a download. Planted honeytoken passwords are masked, as there."""
    if not hashes:
        return {}
    planted = await _load_planted()
    types = sorted({t for pair in _FILE_TYPES.values() for t in pair})
    sha_expr = func.coalesce(_jv("shasum"), _jv("sha256"))
    rows: list[Any] = []
    async with get_session() as session:
        for start in range(0, len(hashes), _HASH_CHUNK):
            chunk = hashes[start : start + _HASH_CHUNK]
            stmt = (
                select(
                    sha_expr,
                    Alert.event_type,
                    Alert.source_ip,
                    Alert.timestamp,
                    _jv("url"),
                    _jv("message"),
                    _jv("destfile"),
                    _jv("filename"),
                )
                .where(Alert.event_type.in_(types), sha_expr.in_(chunk))
                .limit(_EVENT_ROW_CAP - len(rows))
            )
            rows.extend((await session.execute(stmt)).all())
            if len(rows) >= _EVENT_ROW_CAP:
                break

    grouped: dict[str, list[Any]] = defaultdict(list)
    for row in rows:
        grouped[row[0]].append(row)
    out: dict[str, dict[str, Any]] = {}
    for sha, events in grouped.items():
        origins: Counter[str] = Counter()
        types_seen: Counter[str] = Counter()
        names: Counter[str] = Counter()
        urls: Counter[str] = Counter()
        sources: set[str] = set()
        first = last = None
        for _sha, event_type, ip, ts, url, message, destfile, filename in events:
            origins[file_origin(event_type, url, message, destfile)] += 1
            types_seen[event_type] += 1
            sources.add(ip)
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
            if destfile or filename:
                names[destfile or filename] += 1
            if url and "://" in url:
                urls[url] += 1
        out[sha] = {
            "events": len(events),
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
    return out


@mcp.tool(auth=require_role("operator"), **hints("sample_scan"))
async def sample_scan(
    path: str | None = None, rules: str | None = None, top: int = 20
) -> dict[str, Any]:
    """Hash, type and YARA-scan the malware samples the honeypots captured.

    Use when someone asks what the captured files are, whether any is a known botnet binary,
    miner, dropper or webshell, or "scan the samples". Reads files from the quarantine directory
    (the `samples_dir` setting, where `sample_collect` puts them and where
    `scripts/fetch_backup.sh --samples` keeps them with no permissions), including files whose
    mode is 000. Nothing is executed and the originals are not changed. For every file it gives
    the SHA-256, size, type by magic bytes (ELF architecture and linking, script interpreter,
    text, archive, Cowrie TTY recording), an entropy bucket (packed or encrypted content stands
    out), the YARA rules that matched with their `family` and `severity` (info, low, medium,
    high) and which rule strings matched where, and, when the hash appears in the database, the
    capture context: how many distinct sources sent it, first and last seen, the names it was
    saved under, and whether the shell wrote it (`written_by_session`, the attacker's own typed
    text) or it was fetched from the network. Bundled rules cover Mirai and Gafgyt binaries, IoT
    droppers (busybox probes, echo -ne hex droppers, per-architecture download scripts), UPX and
    small static ELF loaders, cryptominers, reverse shells, SSH-key persistence, webshells,
    fetch-chmod-run-delete scripts, credential-theft strings and the harmless "can I run a file
    here" probe (severity info). Rules you add as `*.yar` files in the `yara_rules_dir` directory
    load too; a user rule file that does not compile is reported with its file and line and does
    not disable the others.

    Operator tier. The result is a digest: counts of files scanned and skipped (with reasons),
    hits by rule, family and severity, duplicates by hash, unknown-type files, and the most
    significant files. The full per-file table is written to a file in the reports directory.
    Hand any hash from the result to `lookup_hash` to ask MalwareBazaar about it.

    Args:
        path: A file or directory name inside the samples directory (for example
            `honeypot-hp-ssh` or `honeypot-hp-ssh/downloads`). Omit it to scan everything. `..`,
            absolute paths outside the directory and symbolic links are refused.
        rules: Limit the scan to named rule files, comma separated: a bundled name (`miners`,
            `iot_botnets`, `shells`, `webshells`) or a file in the rules directory. Omit it to use
            every bundled rule plus the user's.
        top: How many of the most significant files to detail in the result (1-100, default 20).

    Returns:
        `files_scanned`, `distinct_hashes`, `files_skipped`, `by_type`, `hits_by_rule`,
        `hits_by_family`, `hits_by_severity`, `top_files`, `duplicates`, `database`, `rules`
        (what loaded, with any compile errors) and `artifact` (the full table's path). When no
        YARA engine is installed: `{"available": False, "note": ...}`. On a bad path or an
        unusable directory: `error` and `hint`.
    """
    status = samples.availability()
    if not status["available"]:
        return status
    top = max(1, min(int(top), 100))
    try:
        report = await asyncio.to_thread(samples.scan_records, path, rules)
    except samples.SampleError as exc:
        await _audit.record_action(
            "sample_scan",
            "Sample scan refused",
            arguments={"path": path, "rules": rules},
            target=(path or ".")[:128],
            outcome="error",
            error=exc.message[:500],
        )
        return exc.as_result()

    context = await database_context(sorted({r["sha256"] for r in report.records}))
    for record in report.records:
        record["database"] = context.get(record["sha256"])
    summary = samples.digest(
        report.records,
        report.skipped,
        top=top,
        not_scanned=report.not_scanned,
        max_files=report.max_files,
    )
    rules_info = report.ruleset.describe()
    table = {
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": path or ".",
        "rules": rules_info,
        "summary": {k: v for k, v in summary.items() if k != "top_files"},
        "files": report.records,
        "skipped": report.skipped,
    }
    artifact = write_artifact(
        json.dumps(table, indent=1, default=str), prefix="sample-scan", extension="json"
    )
    result: dict[str, Any] = {
        "available": True,
        "engine": status["engine"],
        "scope": path or ".",
        **summary,
        "database": {
            "files_with_context": sum(1 for r in report.records if r["database"]),
            "note": (
                "Context comes from ssh/telnet/ftp file-capture events whose hash equals the "
                "file's SHA-256. A file the database has no event for was collected from a "
                "container or a backup but never reported by a session (or the events were pruned)."
            ),
        },
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
    hit_files = summary["files_with_hits"]
    await _audit.record_action(
        "sample_scan",
        f"Scanned {len(report.records)} sample file(s): {hit_files} with rule hits, "
        f"{len(report.skipped)} skipped",
        arguments={"path": path, "rules": rules, "top": top},
        target=(path or ".")[:128],
    )
    return result


@mcp.tool(auth=require_role("admin"), **hints("sample_collect"))
async def sample_collect(honeypot: str | None = None) -> dict[str, Any]:
    """Copy the files the SSH and Telnet honeypots captured into the local quarantine.

    Use when someone asks to "pull the samples", "collect what the honeypots downloaded" or
    wants to look at captured malware or TTY recordings from a live sensor. Cowrie keeps what
    attackers download or upload, and each session's TTY recording, inside its container, so
    they are lost when the container is replaced: collect before a redeploy. This copies them
    out of the running Cowrie containers with Docker's copy-out API (the same files
    `scripts/fetch_backup.sh --samples` bundles), writes each into the samples directory as
    `<container>/downloads/<sha256>` (named by content hash) or `<container>/tty/<name>`, mode
    000, never over an existing file, and records their hashes in `SHA256SUMS`. Files already
    collected are skipped, so it is safe to run repeatedly. Then use `sample_scan` on them.

    Admin tier: the files are live malware and the container is treated as hostile. The archive
    is read as a stream under size and file-count limits; only regular files directly inside
    `downloads` and `tty` are kept (links, devices, nested or oddly named paths are counted and
    refused); nothing is executed. Only Cowrie (the `ssh` and `telnet` honeypot types) runs in a
    container; every other honeypot runs inside this server and has no files to collect. It
    works on the host that runs the sensors, and says so when Docker or a container is missing,
    or when the server is in ANALYSIS_MODE (no containers exist there).

    Args:
        honeypot: Collect from one honeypot, by its name or container name (for example
            `hp-ssh` or `honeypot-hp-ssh`). Omit it to collect from every running Cowrie
            container.

    Returns:
        `new_files`, `new_bytes`, `duplicates_skipped`, and per container: `new` (path, sha256,
        size), what was `skipped` and why, and `truncated` when a limit was hit. On failure
        (Docker unavailable, no running container, analysis mode): `error` and `hint`.
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
