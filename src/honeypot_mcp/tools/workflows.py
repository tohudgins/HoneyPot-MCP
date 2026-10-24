"""Whole-workflow tools: analyse a run, and take a verified database backup.

Everything an analyst does after a run used to live in two places an MCP user could not reach:
`scripts/analyze_backup.py` (drove the server from outside, one tool at a time) and
`scripts/backup.sh` (shell). These two tools put the same workflows behind the control plane, so
"analyse this run" and "back up the database and verify it" are things one can simply ask for.

* `run_analysis` composes the existing tools in-process. It is a *digest*, never a dump: headline
  numbers come from the rollups, the busiest sources get a one-line journey each, and everything
  bulky (reports, STIX, blocklist, the markdown write-up) goes to `reports_dir`. Each part runs
  on its own: one failing sub-tool is reported under `failed` and the rest still lands.
* `database_backup` (no arguments: automatic timestamped folder, always integrity-checked) uses SQLite's online backup API from a read-only connection, in one step, so
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

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import get_settings
from honeypot_mcp.rbac import require_role
from honeypot_mcp.secure_io import write_private_file
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


async def _gather(*work: Awaitable[Any]) -> list[Any]:
    """Run the parts of the analysis together, except on an in-memory database.

    A file database gives every session its own connection, so independent reads overlap and a
    run on a large database takes the time of its slowest part. The in-memory database used by
    tests is one shared connection: a commit from one part while another still has a cursor open
    fails with "cannot commit transaction - SQL statements in progress", so there the parts run
    one after another.
    """
    if ":memory:" in get_settings().database_url:
        return [await item for item in work]
    return list(await asyncio.gather(*work))


_TOP_SOURCES = 5
_CAMPAIGNS_IN_DIGEST = 3
_CLUSTERS_IN_DIGEST = 3
_JOURNEY_CHARS = 300
_TECHNIQUES_PER_TACTIC_IN_DIGEST = 3
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
        lines.append("_No files were written (see the failed parts below)._")
    for label, info in files.items():
        lines.append(f"- {label}: `{info}`")
    if d["failed"]:
        lines += ["", "## Parts that failed", ""]
        lines.extend(f"- {_one_line(f['part'])}: {_one_line(f['error'], 300)}" for f in d["failed"])
    return "\n".join(lines) + "\n"


async def _profile_source(
    run: _Run, ip: str, alerts: int, effective: int, stamp: str
) -> dict[str, Any]:
    """One busy source: risk, a one-line journey and a Markdown report file. Parts fail separately."""
    row: dict[str, Any] = {"ip": ip, "alerts": alerts}
    profile, journey, report = await _gather(
        run.step(f"analyze_attacker({ip})", _analysis_tools.analyze_attacker(ip)),
        run.step(
            f"analyze_attacker_journey({ip})",
            _analysis_tools.analyze_attacker_journey(ip, hours=effective),
        ),
        run.step(
            f"generate_report({ip})",
            _analysis_tools.write_report(
                f"Source {ip}",
                ip,
                "markdown",
                float(effective),
                output_path=f"analysis-{stamp}-source-{ip.replace(':', '-')}.md",
            ),
        ),
    )
    if profile:
        row["risk_level"] = profile.get("risk_level")
        row["risk_score"] = profile.get("risk_score")
    if journey:
        row["journey"] = _one_line(journey.get("summary", ""), _JOURNEY_CHARS)
    if report:
        row["report"] = Path(report["path"]).name
    return row


@mcp.tool(auth=require_role("operator"), **hints("run_analysis"))
async def run_analysis(hours: int = 168) -> dict[str, Any]:
    """Analyse the whole run in one call: what happened, who did it, what to do first.

    Use it for "analyse this run", "what happened while I was away", "give me the full picture",
    or on a restored backup in analysis mode. Assembles headline numbers, triage, triggered
    honeytokens, ATT&CK tactics seen, the five busiest sources (risk and a one-line story each),
    campaigns, shared SSH-client fingerprints and sensor coverage, and writes the details to the
    reports directory: `analysis-summary.md` (path in `summary_file`), an HTML report, a STIX bundle,
    a blocklist and one report per busy source. A failing part is listed under `failed`; the rest
    still lands. Totals and ATT&CK cover the whole run; the rest covers the last `hours`, counted
    back from the newest alert (an old backup is not analysed as empty).

    Args:
        hours: How far back the recent-activity parts look: "today" is 24, "this week" 168 (the
               default).
    """
    if isinstance(hours, bool) or not isinstance(hours, int) or hours < 1:
        return {
            "error": f"hours must be a whole number of at least 1 (got {hours!r}).",
            "hint": "Say how far back to look: 24 for today, 168 for this week (the default).",
        }
    top = _TOP_SOURCES
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

    # ── everything that does not depend on another part runs at once ─────────────────────────
    # Per-source names are explicit (a model-chosen name is never overwritten), so make them unique per run.
    stamp = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(2)}"
    (
        stats,
        brief,
        attack,
        campaigns,
        clusters,
        coverage,
        full_report,
        stix,
        blocklist,
    ) = await _gather(
        run.step("alerts_stats", _alerts_tools.alerts_stats()),
        run.step(
            "soc_brief",
            _deception_tools.soc_brief(since_hours=float(effective), max_highlights=1),
        ),
        run.step("attack_summary", _analysis_tools.attack_summary()),
        run.step(
            "analyze_campaign",
            _analysis_tools.analyze_campaign(min_sources=3),
        ),
        run.step(
            "fingerprint_clusters",
            _analysis_tools.fingerprint_clusters(hours=effective, min_sources=2),
        ),
        run.step("deception_coverage", _deception_tools.deception_coverage()),
        run.step(
            "generate_report(full)",
            _analysis_tools.write_report("Run summary", None, "html", float(effective)),
        ),
        run.step(
            "export_indicators(stix)",
            _analysis_tools.export_indicators(
                format="stix", hours=effective, min_hits=_MIN_HITS_FOR_EXPORTS
            ),
        ),
        run.step(
            "export_indicators(plain)",
            _analysis_tools.export_indicators(
                format="plain", hours=effective, min_hits=_MIN_HITS_FOR_EXPORTS
            ),
        ),
    )

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
            "headline": [_one_line(h, 300) for h in brief["headline"]],
            "needs_attention_total": brief["needs_attention_total"],
            "untriaged_by_severity": brief["untriaged_by_severity"],
            "triggered_tokens": [
                {"label": t.get("label"), "type": t.get("type")}
                for t in brief["triggered_tokens"][:5]
            ],
            "sensors": {k: v for k, v in brief["sensors"].items() if k in ("total", "running")}
            | {"unhealthy": len(brief["sensors"].get("unhealthy", []))},
        }
    if attack:
        digest["attack"] = {
            "event_types_seen": attack["event_types_seen"],
            "mapped_share": attack["mapped_share"],
            "tactics": _tactic_digest(attack),
            "unmapped": attack["unmapped"][:5],
            "note": (
                f"Top {_TECHNIQUES_PER_TACTIC_IN_DIGEST} techniques per tactic shown; the full "
                f"table is in {_SUMMARY_NAME}."
            ),
        }

    # ── the busiest sources ───────────────────────────────────────────────────────────────────
    busiest = (stats or {}).get("top_source_ips", [])
    if not busiest and brief:
        busiest = [{"ip": b["source_ip"], "count": b["events"]} for b in brief["busiest_sources"]]
    sources = list(
        await _gather(
            *(
                _profile_source(run, source["ip"], source["count"], effective, stamp)
                for source in busiest[:top]
            )
        )
    )
    digest["top_sources"] = sources
    digest["top_sources_count"] = len(sources)

    # ── campaigns, shared tooling, coverage ───────────────────────────────────────────────────
    if campaigns:
        shown = campaigns["campaigns"][:_CAMPAIGNS_IN_DIGEST]
        digest["campaigns"] = {
            "total": campaigns["campaigns_total"],
            "count": len(shown),
            "campaigns": [
                {
                    "event_type": c["event_type"],
                    "kind": c["kind"],
                    "score": c["score"],
                    "start_time": c["start_time"],
                    "duration_minutes": c["duration_minutes"],
                    "unique_source_ips": c["unique_source_ips"],
                    "total_events": c["total_events"],
                }
                for c in shown
            ],
            "note": (
                f"Top {len(shown)} of {campaigns['campaigns_total']} by score shown."
                if campaigns["campaigns_total"] > len(shown)
                else None
            ),
        }
    if clusters:
        shown_c = clusters["clusters"][:_CLUSTERS_IN_DIGEST]
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
    if coverage:
        digest["coverage"] = {
            "techniques_covered": coverage.get("techniques_covered"),
            "coverage": coverage.get("coverage"),
        }

    # ── files ─────────────────────────────────────────────────────────────────────────────────
    files: dict[str, str] = {}
    for label, out in (
        ("full report", full_report),
        ("STIX bundle", stix),
        ("blocklist", blocklist),
    ):
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
    markdown = _render_summary({**digest, "soc": brief} if brief else digest, attack)
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
    digest["summary"] = (
        (
            f"Analysis of {digest['headline']['total_alerts']:,} alerts from "
            f"{digest['headline']['unique_source_ips']:,} sources. "
            if "headline" in digest
            else "Analysis finished. "
        )
        + (
            f"The write-up is in {written['path']}; "
            if "path" in written
            else "The write-up could not be saved; "
        )
        + f"{len(files)} more file(s) are in the reports directory"
        + (f"; {len(run.failed)} part(s) failed (see `failed`)." if run.failed else ".")
    )
    await _audit.record_action(
        "run_analysis",
        summary=f"analysed the run ({hours} h), {len(files)} file(s) written",
        arguments={"hours": hours},
        target=_SUMMARY_NAME,
        outcome="ok" if digest["complete"] else "error",
        error=None if digest["complete"] else f"{len(run.failed)} part(s) failed",
    )
    digest["seconds"] = round(time.monotonic() - started, 1)
    return digest


# ── database_backup ───────────────────────────────────────────────────────────────────────────

_SQLITE_PREFIXES = ("sqlite:///", "sqlite+aiosqlite:///")
_DB_NAME = "honeypot_mcp.db"
_MANIFEST_NAME = "MANIFEST.json"
_PROGRESS_SECONDS = 10.0


class _BackupError(Exception):
    """A refusal or failure with a message (and what to do about it) meant for the caller."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.hint = hint


def _sqlite_source(url: str) -> Path:
    """The database file behind `database_url`, or a `_BackupError` saying why there is none."""
    if not url.startswith(_SQLITE_PREFIXES):
        scheme = url.split(":", 1)[0].split("+", 1)[0]
        raise _BackupError(
            f"database_backup only supports SQLite; this server uses {scheme!r}.",
            "Back a PostgreSQL database up with pg_dump (scripts/backup.sh runs it with the "
            "password kept out of the process list).",
        )
    path = url.split(":///", 1)[1].split("?", 1)[0]
    if not path or ":memory:" in path:
        raise _BackupError(
            "The database is in memory, so there is no file to back up.",
            "Point DATABASE_URL at a SQLite file to keep data between runs.",
        )
    source = Path(path)
    if not source.is_file():
        raise _BackupError(
            "The database file does not exist yet (nothing has been written).",
            "Back up after the server has captured something.",
        )
    return source


def _new_backup_dir(root: Path) -> Path:
    """The not-yet-existing `honeypot-<UTC timestamp>` directory inside `root` (a numeric suffix
    when two backups start in the same second)."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    final = root / f"honeypot-{stamp}"
    suffix = 1
    while final.exists():
        suffix += 1
        final = root / f"honeypot-{stamp}-{suffix}"
    return final


def _make_private_tree(path: Path) -> None:
    """Create `path` and every missing ancestor owner-only (0700); existing directories are left as
    they are. `mkdir(mode=, parents=True)` applies the mode to the leaf only, so a nested
    destination left its intermediate directories at the umask's 0755 above a 0600 backup."""
    missing: list[Path] = []
    probe = path
    while not probe.exists() and probe != probe.parent:
        missing.append(probe)
        probe = probe.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)


# One backup at a time. Each call checks the free space and then writes up to that much, so two
# concurrent calls both passed a check that only one of them could satisfy and doubled the disk use.
_backup_lock: LoopBound[asyncio.Lock] = LoopBound(asyncio.Lock)


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


def _backup_into(source: Path, work_dir: Path, expected: int) -> dict[str, Any]:
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
        "verified": True,
        "integrity_check": integrity,
        "sha256": _sha256_file(target),
        **facts,
    }
    write_private_file(work_dir / _MANIFEST_NAME, json.dumps(manifest, indent=2) + "\n")
    return manifest


async def _audited(result: dict[str, Any], summary: str, target: str | None) -> dict[str, Any]:
    failed = "error" in result
    await _audit.record_action(
        "database_backup",
        summary=summary,
        arguments={},
        target=target,
        outcome="error" if failed else "ok",
        error=str(result["error"]) if failed else None,
    )
    return result


@mcp.tool(auth=require_role("admin"), **hints("database_backup"))
async def database_backup() -> dict[str, Any]:
    """Back up the database now and check the copy; safe while the server is running.

    Use it for "back up the database", before an upgrade or before pruning. Takes no arguments: it
    writes `honeypot_mcp.db` plus a `MANIFEST.json` (counts, span, size, SHA-256) into a new
    timestamped, owner-only folder in the backups directory and always integrity-checks the copy.
    A failed run leaves nothing behind and an existing backup is never replaced. A big database
    takes a minute or more; sensors keep serving. The file holds secrets (honeytoken values,
    captured credentials): store it like the `.env`. SQLite only (`pg_dump` for PostgreSQL);
    certificates, reports, `.env` and samples are covered by `scripts/backup.sh`.
    """
    async with _backup_lock.get():
        return await _database_backup()


async def _database_backup() -> dict[str, Any]:
    settings = get_settings()
    root = settings.backup_dir.resolve()
    try:
        source = _sqlite_source(settings.database_url)
        final = _new_backup_dir(root)
        wal = source.with_name(source.name + "-wal")
        needed = source.stat().st_size + (wal.stat().st_size if wal.exists() else 0)
        reserve = settings.min_free_disk_mb * 1024 * 1024
        free = _free_bytes(final.parent)
        if free < needed + reserve:
            raise _BackupError(
                f"Not enough free disk space: the backup needs up to {_fmt_bytes(needed)} "
                f"({needed:,} bytes) plus a {_fmt_bytes(reserve)} reserve, and only "
                f"{_fmt_bytes(free)} ({free:,} bytes) is free where backups are written.",
                "Free some space, or point BACKUP_DIR at a larger volume.",
            )
    except _BackupError as e:
        failure = {"error": str(e), **({"hint": e.hint} if e.hint else {})}
        return await _audited(failure, "database backup refused", None)
    except OSError as e:
        return await _audited(
            {
                "error": f"Could not prepare the backup: {e}",
                "hint": "Check that the backups directory exists and is writable.",
            },
            "database backup failed",
            None,
        )

    work_dir = final.parent / f".{final.name}.{secrets.token_hex(4)}.partial"
    try:
        _make_private_tree(final.parent)
        work_dir.mkdir(mode=0o700)
        manifest = await asyncio.to_thread(_backup_into, source, work_dir, needed)
        if final.exists():  # lost a race with another backup of the same name
            raise _BackupError(
                f"{final.name!r} appeared while the backup ran; refusing to replace it.",
                "Run the backup again.",
            )
        os.rename(work_dir, final)
    except (_BackupError, OSError, sqlite3.Error) as e:
        shutil.rmtree(work_dir, ignore_errors=True)
        failure = {"error": str(e) if isinstance(e, _BackupError) else f"Backup failed: {e}"}
        if isinstance(e, _BackupError) and e.hint:
            failure["hint"] = e.hint
        elif not isinstance(e, _BackupError):
            failure["hint"] = (
                "Nothing was kept. Check free disk space and that the database file is readable, then retry."
            )
        return await _audited(failure, "database backup failed", final.name)
    except BaseException:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise

    log.info("database_backup: wrote %s", final.name)
    size = _fmt_bytes(manifest["size_bytes"])
    result = {
        "summary": (
            f"Backed up {manifest['alerts']:,} alerts ({size}) from {manifest['distinct_sources']:,} "
            f"sources to {final}. The copy passed an integrity check."
        ),
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
        f"backed up the database: {manifest['alerts']:,} alerts, {size}",
        final.name,
    )
