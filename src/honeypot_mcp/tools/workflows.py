"""Whole-workflow tools: analyse a run, and take a verified database backup.

Everything an analyst does after a run used to live in two places an MCP user could not reach:
`scripts/analyze_backup.py` (drove the server from outside, one tool at a time) and
`scripts/backup.sh` (shell). These two tools put the same workflows behind the control plane, so
"analyse this run" and "back up the database and verify it" are things one can simply ask for.

* `run_analysis` composes the existing tools in-process. It is a *digest*, never a dump: headline
  numbers come from the rollups, the busiest sources get a one-line journey each, and everything
  bulky (reports, STIX, blocklist, the markdown write-up) goes to `reports_dir`. Each part runs
  on its own: one failing sub-tool is reported under `failed` and the rest still lands.
* `database_backup` uses SQLite's online backup API from a read-only connection, in one step, so
  the copy is a single consistent snapshot of a WAL database taken without blocking the server
  (a file copy would silently miss recent transactions, and a stepwise backup restarts whenever
  the server writes between steps). The copy is written under a temporary name inside a confined
  directory and renamed into place only after it verified, so a failed run never leaves something
  that looks like a backup.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import shutil
import sqlite3
import threading
import time
from collections.abc import Awaitable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.rbac import require_role
from honeypot_mcp.secure_io import ensure_private_dir, write_private_file
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools import alerts as _alerts_tools
from honeypot_mcp.tools import analysis as _analysis_tools
from honeypot_mcp.tools import deception as _deception_tools
from honeypot_mcp.tools._format import write_artifact

log = logging.getLogger(__name__)

_MAX_TOP = 25
_TECHNIQUES_PER_TACTIC_IN_DIGEST = 5
_MIN_HITS_FOR_EXPORTS = 50
_SUMMARY_NAME = "analysis-summary.md"

# ── run_analysis ──────────────────────────────────────────────────────────────


def _one_line(value: Any, limit: int = 200) -> str:
    """Attacker-influenced text, made safe for a markdown line: no newlines, no table breaks."""
    text = " ".join(str(value).split()).replace("|", "/").replace("`", "'")
    return text if len(text) <= limit else text[: limit - 1] + "…"


class _Run:
    """Collects section failures and timings so one bad sub-tool never costs the rest."""

    def __init__(self) -> None:
        self.failed: list[dict[str, str]] = []
        self.timings: dict[str, float] = {}

    async def step(self, name: str, work: Awaitable[Any]) -> Any:
        """Await `work`; return its result, or None after recording why it failed.

        Tools report ordinary failures as `{"error": ...}` rather than raising, so both are
        treated as a failed part.
        """
        started = time.monotonic()
        try:
            result = await work
        except Exception as e:
            self.failed.append({"part": name, "error": f"{type(e).__name__}: {e}"[:300]})
            log.exception("run_analysis: %s failed", name)
            return None
        finally:
            self.timings[name] = round(time.monotonic() - started, 2)
        if isinstance(result, dict) and result.get("error"):
            self.failed.append({"part": name, "error": str(result["error"])[:300]})
            return None
        return result


async def _alert_time_range() -> tuple[datetime | None, datetime | None]:
    async with get_session() as session:
        row = (
            await session.execute(select(func.min(Alert.timestamp), func.max(Alert.timestamp)))
        ).one()
    return row[0], row[1]


def _tactic_digest(attack: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "tactic": tactic["tactic"],
            "alerts": tactic["alerts"],
            "techniques_total": len(tactic["techniques"]),
            "techniques": [
                {
                    "technique": f"{t['technique_id']} {t['technique_name']}",
                    "alerts": t["alerts"],
                    "main_event_types": [e["type"] for e in t["top_event_types"][:3]],
                }
                for t in tactic["techniques"][:_TECHNIQUES_PER_TACTIC_IN_DIGEST]
            ],
        }
        for tactic in attack["tactics"]
    ]


def _render_summary(d: dict[str, Any], attack: dict[str, Any] | None) -> str:
    """The `analysis-summary.md` write-up, rendered from the digest (plus the full ATT&CK table)."""
    lines: list[str] = ["# Analysis summary", ""]
    window = d["window"]
    head = d.get("headline")
    if head:
        lines.append(
            f"- **{head['total_alerts']:,}** alerts from **{head['unique_source_ips']:,}** source IPs"
        )
        lines.append(
            "- by severity: "
            + (", ".join(f"{k} {v:,}" for k, v in head["by_severity"].items()) or "none")
        )
    soc = d.get("soc")
    if soc:
        lines.extend(f"- {_one_line(h)}" for h in soc["headline"])
        vol = soc["volume"]
        lines.append(
            f"- last {window['effective_hours']} h of data: {vol['total_events']:,} alerts, "
            f"{vol['untriaged']:,} untriaged "
            f"({soc['untriaged_by_severity']['critical']:,} critical, "
            f"{soc['untriaged_by_severity']['high']:,} high)"
        )
        tokens = soc["triggered_tokens"]
        lines.append(
            f"- honeytokens triggered: {len(tokens)}"
            + (
                " (" + ", ".join(f"{_one_line(t['label'], 60)} [{t['type']}]" for t in tokens) + ")"
                if tokens
                else ""
            )
        )
        sensors = soc["sensors"]
        lines.append(
            f"- sensors recorded: {sensors['total']} ({sensors['running']} marked running, "
            f"{len(sensors['unhealthy'])} in error)"
        )
    if window.get("note"):
        lines += ["", f"> {_one_line(window['note'], 400)}"]

    lines += ["", "## ATT&CK: what the run did, by tactic", ""]
    if attack is None:
        lines.append("_The ATT&CK summary failed; see the failed parts below._")
    else:
        lines += [
            f"{attack['event_types_seen']} event types; {attack['mapped_share']:.1%} of alerts map to "
            "a technique (the rest is connection and session bookkeeping).",
            "",
            "| Tactic | Technique | Alerts | Main event types |",
            "|---|---|---:|---|",
        ]
        for tactic in attack["tactics"]:
            for t in tactic["techniques"]:
                types = ", ".join(e["type"] for e in t["top_event_types"][:3])
                lines.append(
                    f"| {_one_line(tactic['tactic'])} | {_one_line(t['technique_id'])} "
                    f"{_one_line(t['technique_name'])} | {t['alerts']:,} | {_one_line(types)} |"
                )
        if attack["unmapped"]:
            lines += [
                "",
                "Left unmapped: "
                + ", ".join(
                    f"{_one_line(u['type'])} ({u['alerts']:,})" for u in attack["unmapped"][:8]
                ),
            ]

    lines += ["", f"## Top {len(d['top_sources'])} sources", ""]
    for s in d["top_sources"]:
        bits = [f"**{s['ip']}**: {s['alerts']:,} alerts"]
        if s.get("risk_level") is not None:
            bits.append(f"risk {s['risk_level']} ({s['risk_score']})")
        line = ", ".join(bits) + "."
        if s.get("journey"):
            line += f" {_one_line(s['journey'], 400)}"
        if s.get("report"):
            line += f" Report: `{s['report']}`"
        lines.append(f"- {line}")

    lines += ["", "## Campaigns and shared tooling", ""]
    camp = d.get("campaigns")
    lines.append(
        f"- {camp['total']} campaign(s): several sources, one event type, one window"
        if camp
        else "- campaigns: unavailable"
    )
    fp = d.get("fingerprint_clusters")
    lines.append(
        f"- {fp['matching']} SSH client fingerprint cluster(s) shared by 2+ sources"
        if fp
        else "- SSH fingerprint clusters: unavailable"
    )
    cov = d.get("coverage")
    lines.append(
        f"- sensors map to {cov['techniques_covered']} ATT&CK techniques"
        if cov
        else "- coverage: unavailable"
    )

    lines += ["", "## Files", ""]
    files = d.get("files") or {}
    if not files:
        lines.append("_Exports were not requested._")
    for label, info in files.items():
        lines.append(f"- {label}: `{info}`")
    if d["failed"]:
        lines += ["", "## Parts that failed", ""]
        lines.extend(f"- {_one_line(f['part'])}: {_one_line(f['error'], 300)}" for f in d["failed"])
    return "\n".join(lines) + "\n"


@mcp.tool(auth=require_role("operator"), **hints("run_analysis"))
async def run_analysis(
    top: int = 5, hours: int = 168, write_exports: bool = True
) -> dict[str, Any]:
    """Analyse the whole run in one call: the post-run workflow, as a digest plus files.

    Use it for "analyse this run", "what happened while I was away", or on a restored backup
    (ANALYSIS_MODE). It assembles the headline numbers and severity split, what needs triage,
    triggered honeytokens, the ATT&CK techniques the captured event types map to (by tactic,
    with the unmapped remainder), a profile and journey for each of the busiest sources,
    campaigns, SSH-client fingerprint clusters and sensor coverage. With `write_exports` it also
    writes a full report, a STIX bundle, a blocklist, a Markdown report per busy source and
    `analysis-summary.md` into the reports directory. Each part runs on its own: if one fails,
    it is listed under `failed` and everything else is still produced.

    Totals and the ATT&CK table are exact (rollups, whole run). The window-bound parts (triage
    counts, journeys, fingerprint clusters, exports) cover the last `hours` of *data*: the window
    ends at the newest alert, not at the wall clock, so analysing a backup taken last week still
    looks at its final `hours` rather than an empty present. `window` says what was used.

    Args:
        top: How many of the busiest sources to profile (0-25).
        hours: Window for triage counts, journeys, fingerprint clusters and exports (>= 1).
        write_exports: Write the report/STIX/blocklist/summary files. False returns the same
              digest, plus the summary as `summary_markdown`, and writes nothing.
    """
    if hours < 1:
        return {"error": "hours must be at least 1."}
    top = max(0, min(top, _MAX_TOP))
    run = _Run()
    started = time.monotonic()

    # ── window: anchored to the newest alert so an old backup is not analysed as empty ───────
    oldest = newest = None
    try:
        oldest, newest = await _alert_time_range()
    except Exception as e:
        run.failed.append({"part": "alert_time_range", "error": f"{type(e).__name__}: {e}"[:300]})
    age_hours = 0.0
    if newest is not None:
        age_hours = max(0.0, (datetime.now(UTC) - newest).total_seconds() / 3600)
    effective = hours + int(age_hours)
    window: dict[str, Any] = {
        "requested_hours": hours,
        "effective_hours": effective,
        "oldest_alert": oldest.isoformat() if oldest else None,
        "newest_alert": newest.isoformat() if newest else None,
    }
    if newest is None:
        window["note"] = "The database holds no alerts, so there is nothing to analyse."
    elif int(age_hours) >= 1:
        window["note"] = (
            f"The newest alert is {age_hours:.0f} h old, so the {hours} h window is measured back "
            f"from it ({effective} h from now). Totals and the ATT&CK table cover the whole run."
        )

    # ── headline + triage ─────────────────────────────────────────────────────────────────────
    stats = await run.step("alerts_stats", _alerts_tools.alerts_stats())
    brief = await run.step(
        "soc_brief", _deception_tools.soc_brief(since_hours=float(effective), max_highlights=1)
    )
    attack = await run.step("attack_summary", _analysis_tools.attack_summary())

    digest: dict[str, Any] = {"window": window}
    if stats:
        digest["headline"] = {
            "total_alerts": stats["total_alerts"],
            "unique_source_ips": stats["unique_source_ips"],
            "by_severity": stats["by_severity"],
            "top_event_types": stats["top_event_types"][:5],
        }
    if brief:
        digest["soc"] = {
            "headline": brief["headline"],
            "volume": brief["volume"],
            "untriaged_by_severity": brief["untriaged_by_severity"],
            "needs_attention_total": brief["needs_attention_total"],
            "triggered_tokens": brief["triggered_tokens"],
            "sensors": brief["sensors"],
        }
    if attack:
        digest["attack"] = {
            "event_types_seen": attack["event_types_seen"],
            "mapped_share": attack["mapped_share"],
            "tactics": _tactic_digest(attack),
            "unmapped": attack["unmapped"][:8],
            "note": (
                f"Top {_TECHNIQUES_PER_TACTIC_IN_DIGEST} techniques per tactic shown; the full "
                f"table is in {_SUMMARY_NAME}."
            ),
        }

    # ── the busiest sources ───────────────────────────────────────────────────────────────────
    # Per-source names are explicit (a model-chosen name is never overwritten), so make them unique per run.
    stamp = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(2)}"
    sources: list[dict[str, Any]] = []
    busiest = (stats or {}).get("top_source_ips", [])
    if not busiest and brief:
        busiest = [{"ip": b["source_ip"], "count": b["events"]} for b in brief["busiest_sources"]]
    for source in busiest[:top]:
        ip = source["ip"]
        row: dict[str, Any] = {"ip": ip, "alerts": source["count"]}
        profile = await run.step(f"analyze_attacker({ip})", _analysis_tools.analyze_attacker(ip))
        if profile:
            row["risk_level"] = profile.get("risk_level")
            row["risk_score"] = profile.get("risk_score")
        journey = await run.step(
            f"analyze_attacker_journey({ip})",
            _analysis_tools.analyze_attacker_journey(ip, hours=effective),
        )
        if journey:
            row["journey"] = _one_line(journey.get("summary", ""), 400)
        if write_exports:
            report = await run.step(
                f"generate_report({ip})",
                _analysis_tools.generate_report(
                    title=f"Source {ip}",
                    ip=ip,
                    format="markdown",
                    since_hours=float(effective),
                    output_path=f"analysis-{stamp}-source-{ip.replace(':', '-')}.md",
                ),
            )
            if report:
                row["report"] = Path(report["path"]).name
        sources.append(row)
    digest["top_sources"] = sources
    digest["top_sources_count"] = len(sources)

    # ── campaigns, shared tooling, coverage ───────────────────────────────────────────────────
    campaigns = await run.step(
        "analyze_campaign", _analysis_tools.analyze_campaign(window_minutes=60, min_sources=3)
    )
    if campaigns:
        shown = campaigns["campaigns"][:5]
        digest["campaigns"] = {
            "total": campaigns["campaigns_total"],
            "count": len(shown),
            "campaigns": [
                {
                    "event_type": c["event_type"],
                    "start_time": c["start_time"],
                    "duration_minutes": c["duration_minutes"],
                    "unique_source_ips": c["unique_source_ips"],
                    "total_events": c["total_events"],
                }
                for c in shown
            ],
            "note": (
                f"Largest {len(shown)} of {campaigns['campaigns_total']} shown."
                if campaigns["campaigns_total"] > len(shown)
                else None
            ),
        }
    clusters = await run.step(
        "fingerprint_clusters",
        _analysis_tools.fingerprint_clusters(hours=effective, min_sources=2, limit=10),
    )
    if clusters:
        shown_c = clusters["clusters"][:5]
        digest["fingerprint_clusters"] = {
            "matching": clusters["clusters_matching"],
            "count": len(shown_c),
            "window_hours": clusters["window_hours"],
            "clusters": [
                {
                    "hassh": c["hassh"],
                    "distinct_ips": c["distinct_ips"],
                    "sessions": c["sessions"],
                    "client_banners": [b["banner"] for b in c["client_banners"][:2]],
                }
                for c in shown_c
            ],
            "note": (
                "Scan hit its row cap, so older activity is missing."
                if clusters.get("truncated")
                else (
                    f"Largest {len(shown_c)} of {clusters['clusters_matching']} shown."
                    if clusters["clusters_matching"] > len(shown_c)
                    else None
                )
            ),
        }
    coverage = await run.step("deception_coverage", _deception_tools.deception_coverage())
    if coverage:
        digest["coverage"] = {
            "techniques_covered": coverage.get("techniques_covered"),
            "coverage": coverage.get("coverage"),
        }

    # ── exports ───────────────────────────────────────────────────────────────────────────────
    files: dict[str, str] = {}
    if write_exports:
        exports = (
            (
                "full report",
                "generate_report(full)",
                _analysis_tools.generate_report(
                    title="Run summary", format="html", since_hours=float(effective)
                ),
            ),
            (
                "STIX bundle",
                "export_stix",
                _analysis_tools.export_stix(hours=effective, min_hits=_MIN_HITS_FOR_EXPORTS),
            ),
            (
                "blocklist",
                "export_blocklist",
                _analysis_tools.export_blocklist(
                    format="plain", hours=effective, min_hits=_MIN_HITS_FOR_EXPORTS
                ),
            ),
        )
        for label, part, work in exports:
            out = await run.step(part, work)
            if not out:
                continue
            if "path" in out:
                files[label] = Path(out["path"]).name
            else:
                files[label] = _one_line(out.get("note", "nothing written"), 200)
        for row in sources:
            if row.get("report"):
                files[f"source report {row['ip']}"] = row["report"]
    digest["files"] = files

    digest["failed"] = run.failed
    digest["complete"] = not run.failed
    digest["timings_seconds"] = run.timings
    markdown = _render_summary(digest, attack)
    if write_exports:
        written = write_artifact(
            markdown,
            prefix="analysis-summary",
            extension="md",
            output_path=_SUMMARY_NAME,
            overwrite=True,  # a name this tool fixes itself, regenerated on every run
        )
        if "error" in written:
            run.failed.append({"part": "summary_file", "error": str(written["error"])[:300]})
            digest["complete"] = False
        else:
            digest["summary_file"] = written
        await _audit.record_action(
            "run_analysis",
            summary=f"analysed the run (top {top}, {hours} h), {len(files)} file(s) written",
            arguments={"top": top, "hours": hours, "write_exports": write_exports},
            target=_SUMMARY_NAME,
            outcome="ok" if digest["complete"] else "error",
            error=None if digest["complete"] else f"{len(run.failed)} part(s) failed",
        )
    else:
        digest["summary_markdown"] = markdown
    digest["seconds"] = round(time.monotonic() - started, 1)
    return digest


# ── database_backup ───────────────────────────────────────────────────────────────────────────

_SQLITE_PREFIXES = ("sqlite:///", "sqlite+aiosqlite:///")
_DB_NAME = "honeypot_mcp.db"
_MANIFEST_NAME = "MANIFEST.json"
_PROGRESS_SECONDS = 10.0


class _BackupError(Exception):
    """A refusal or failure with a message meant for the caller."""


def _sqlite_source(url: str) -> Path:
    """The database file behind `database_url`, or a `_BackupError` saying why there is none."""
    if not url.startswith(_SQLITE_PREFIXES):
        scheme = url.split(":", 1)[0].split("+", 1)[0]
        raise _BackupError(
            f"database_backup only supports SQLite; this server uses {scheme!r}. Back a PostgreSQL "
            "database up with pg_dump (see scripts/backup.sh, which runs it with the password kept "
            "out of the process list)."
        )
    path = url.split(":///", 1)[1].split("?", 1)[0]
    if not path or ":memory:" in path:
        raise _BackupError("The database is in memory, so there is no file to back up.")
    source = Path(path)
    if not source.is_file():
        raise _BackupError("The database file does not exist yet (nothing has been written).")
    return source


def _resolve_backup_destination(destination: str | None, root: Path) -> Path:
    """The new backup directory, confined to `root` (a `_BackupError` if it escapes or exists).

    Same boundary as report artifacts: the argument can come from a model that has read
    attacker-authored data, so it may only name a not-yet-existing directory below `backup_dir`.
    """
    if not destination:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        final = root / f"honeypot-{stamp}"
    else:
        try:
            candidate = Path(destination).expanduser()
            final = (candidate if candidate.is_absolute() else root / candidate).resolve()
        except Exception as e:  # embedded NUL, unknown ~user: a refusal, not a crash
            raise _BackupError(f"{destination!r} is not a usable path: {e}") from e
        if root not in final.parents:
            raise _BackupError(
                f"Refusing to write outside the backups directory ({root}). Pass a new "
                f"directory name (or a path inside it) instead of {destination!r}."
            )
    if final.name.endswith(".partial") or any(
        p.startswith(".") for p in final.relative_to(root).parts
    ):
        raise _BackupError("Backup directory names may not start with '.' or end in '.partial'.")
    if final.exists():
        raise _BackupError(
            f"{final.name!r} already exists in the backups directory; refusing to overwrite it."
        )
    return final


def _free_bytes(path: Path) -> int:
    """Free space on the filesystem that holds `path` (or its nearest existing ancestor)."""
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return shutil.disk_usage(probe).free


def _fmt_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def _open_readonly(source: Path) -> sqlite3.Connection:
    """A read-only connection to the (possibly live, WAL) database.

    A plain read-only open of a WAL database needs the `-shm`/`-wal` side files; a cleanly closed
    database has none. Only then is `immutable=1` safe (no unflushed transactions to miss), so
    that is the only case it is used as a fallback.
    """
    uri = f"file:{source.as_posix().replace('%', '%25').replace('?', '%3f').replace('#', '%23')}"
    try:
        return sqlite3.connect(f"{uri}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        if source.with_name(source.name + "-wal").exists():
            raise
        return sqlite3.connect(f"{uri}?mode=ro&immutable=1", uri=True)


def _database_facts(conn: sqlite3.Connection) -> dict[str, Any]:
    """Headline facts about a database, the ones `fetch_backup.sh report` prints."""
    try:
        total, sources, first, last, hours = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_ip), MIN(timestamp), MAX(timestamp), "
            "ROUND((julianday(MAX(timestamp)) - julianday(MIN(timestamp))) * 24, 1) FROM alerts"
        ).fetchone()
    except sqlite3.Error as e:
        raise _BackupError(
            f"The copy has no readable alerts table ({e}); this does not look like a "
            "HoneyPot-MCP database, so it was not kept."
        ) from e
    facts: dict[str, Any] = {
        "alerts": total,
        "distinct_sources": sources,
        "first_alert": first,
        "last_alert": last,
        "window_hours": hours or 0.0,
    }
    for key, sql in (
        ("honeypots", "SELECT COUNT(*) FROM honeypots"),
        ("honeytokens", "SELECT COUNT(*) FROM honeytokens"),
        (
            "honeytokens_triggered",
            "SELECT COUNT(*) FROM honeytokens WHERE LOWER(status) = 'triggered'",
        ),
        ("schema_revision", "SELECT version_num FROM alembic_version"),
    ):
        try:
            row = conn.execute(sql).fetchone()
            facts[key] = row[0] if row else None
        except sqlite3.Error:
            facts[key] = None
    return facts


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def _progress_logger(target: Path, expected: int, stop: threading.Event) -> None:
    while not stop.wait(_PROGRESS_SECONDS):
        with contextlib.suppress(OSError):
            log.info(
                "database_backup: %s written of about %s",
                _fmt_bytes(target.stat().st_size),
                _fmt_bytes(expected),
            )


def _backup_into(source: Path, work_dir: Path, verify: bool, expected: int) -> dict[str, Any]:
    """Blocking: copy, check and describe. Runs in a worker thread. Raises on any failure."""
    target = work_dir / _DB_NAME
    # Created 0600 by us, so the file is never readable by others, even briefly.
    os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    stop = threading.Event()
    watcher = threading.Thread(target=_progress_logger, args=(target, expected, stop), daemon=True)
    started = time.monotonic()
    log.info("database_backup: copying %s", _fmt_bytes(expected))
    watcher.start()
    try:
        src = _open_readonly(source)
        dst = sqlite3.connect(target)
        try:
            # pages=-1: the whole database in ONE step, i.e. one read transaction. Stepwise copies
            # restart from the top whenever another connection writes between steps.
            src.backup(dst, pages=-1)
            # Rollback-mode result: no -wal/-shm beside it, so it opens read-only anywhere.
            dst.execute("PRAGMA journal_mode=DELETE").fetchall()
            dst.commit()
        finally:
            dst.close()
            src.close()
    finally:
        stop.set()
        watcher.join(timeout=2)
    log.info("database_backup: copy finished in %.1f s", time.monotonic() - started)

    check = _open_readonly(target)
    try:
        integrity = "not run"
        if verify:
            log.info("database_backup: running PRAGMA integrity_check")
            rows = [r[0] for r in check.execute("PRAGMA integrity_check").fetchall()]
            integrity = rows[0] if rows == ["ok"] else "; ".join(map(str, rows[:5]))
            if rows != ["ok"]:
                raise _BackupError(
                    f"The copy failed PRAGMA integrity_check ({integrity}), so it was not kept. "
                    "The source database may be damaged."
                )
        log.info("database_backup: reading headline counts")
        facts = _database_facts(check)
    finally:
        check.close()

    manifest: dict[str, Any] = {
        "created_at": datetime.now(UTC).isoformat(),
        "created_by": "database_backup",
        "source_file": source.name,
        "database": _DB_NAME,
        "size_bytes": target.stat().st_size,
        "verified": verify,
        "integrity_check": integrity,
        "sha256": _sha256_file(target) if verify else None,
        **facts,
    }
    write_private_file(work_dir / _MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
    return manifest


async def _audited(
    result: dict[str, Any], arguments: dict[str, Any], summary: str, target: str | None
) -> dict[str, Any]:
    failed = "error" in result
    await _audit.record_action(
        "database_backup",
        summary=summary,
        arguments=arguments,
        target=target,
        outcome="error" if failed else "ok",
        error=str(result["error"]) if failed else None,
    )
    return result


@mcp.tool(auth=require_role("admin"), **hints("database_backup"))
async def database_backup(destination: str | None = None, verify: bool = True) -> dict[str, Any]:
    """Take a consistent, verified snapshot of the SQLite database, safe on a running server.

    Use it for "back up the database and verify it", before an upgrade, or before pruning. It
    writes `honeypot_mcp.db` and a `MANIFEST.json` (counts, window, size, SHA-256) into a new
    directory below the backups directory (`BACKUP_DIR`, default `./backups`), mode 0600, built
    under a temporary name and renamed only once it checked out: a failed run leaves nothing
    behind. It refuses to overwrite an existing backup, and refuses when the disk cannot hold the
    copy (the message gives the numbers). The copy runs in a worker thread, so sensors keep
    serving. **The file contains secrets** (honeytoken values, API-key digests, captured
    credentials): store it like the `.env`.

    This covers the database only. TLS certificates, generated reports, `.env`, remote fetch and
    malware samples remain the job of `scripts/backup.sh` / `scripts/fetch_backup.sh`. PostgreSQL
    deployments are not supported here; use `pg_dump`.

    Args:
        destination: A new directory name (or path) inside the backups directory. Omit for
              `honeypot-<UTC timestamp>`. Anything resolving outside it is refused.
        verify: Run `PRAGMA integrity_check` on the copy and record its SHA-256. False skips both
              (the headline counts are always read, which also proves the copy opens).
    """
    arguments = {"destination": destination, "verify": verify}
    settings = get_settings()
    root = settings.backup_dir.resolve()
    try:
        source = _sqlite_source(settings.database_url)
        final = _resolve_backup_destination(destination, root)
        wal = source.with_name(source.name + "-wal")
        needed = source.stat().st_size + (wal.stat().st_size if wal.exists() else 0)
        reserve = settings.min_free_disk_mb * 1024 * 1024
        free = _free_bytes(final.parent)
        if free < needed + reserve:
            raise _BackupError(
                f"Not enough free disk space: the backup needs up to {_fmt_bytes(needed)} "
                f"({needed:,} bytes) plus a {_fmt_bytes(reserve)} reserve, and only "
                f"{_fmt_bytes(free)} ({free:,} bytes) is free where backups are written. Free "
                "space or point BACKUP_DIR at a larger volume."
            )
    except _BackupError as e:
        return await _audited({"error": str(e)}, arguments, "database backup refused", None)
    except OSError as e:
        return await _audited(
            {"error": f"Could not prepare the backup: {e}"},
            arguments,
            "database backup failed",
            None,
        )

    work_dir = final.parent / f".{final.name}.{secrets.token_hex(4)}.partial"
    try:
        ensure_private_dir(final.parent)
        work_dir.mkdir(mode=0o700)
        manifest = await asyncio.to_thread(_backup_into, source, work_dir, verify, needed)
        if final.exists():  # lost a race with another backup of the same name
            raise _BackupError(
                f"{final.name!r} appeared while the backup ran; refusing to replace it."
            )
        os.rename(work_dir, final)
    except (_BackupError, OSError, sqlite3.Error) as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        return await _audited(
            {"error": str(e) if isinstance(e, _BackupError) else f"Backup failed: {e}"},
            arguments,
            "database backup failed",
            final.name,
        )
    except BaseException:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise

    log.info("database_backup: wrote %s", final.name)
    result = {
        "path": str(final),
        "database": str(final / _DB_NAME),
        "manifest": str(final / _MANIFEST_NAME),
        **{k: v for k, v in manifest.items() if k not in {"created_by", "database"}},
        "note": (
            "Contains secrets (honeytoken values, captured credentials): store it like the .env. "
            "Not included: TLS certificates, generated reports, .env, malware samples "
            "(scripts/backup.sh and scripts/fetch_backup.sh cover those)."
        ),
    }
    return await _audited(
        result,
        arguments,
        f"backed up the database: {manifest['alerts']:,} alerts, {_fmt_bytes(manifest['size_bytes'])}",
        final.name,
    )
