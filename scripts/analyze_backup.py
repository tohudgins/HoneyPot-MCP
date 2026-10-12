#!/usr/bin/env python3
"""Analyse a HoneyPot MCP backup without running any sensor.

    scripts/analyze_backup.py ~/hp-backups/honeypot-20261012T141156Z
    scripts/analyze_backup.py path/to/honeypot_mcp.db --top 5 --hours 168 --workdir ~/hp-analysis

It copies the database (opening one upgrades its schema, and the backup is the only evidence), starts
the server over real MCP stdio in ANALYSIS_MODE (no honeypots, capture, canary or notifications), and
runs the post-run workflow: headline numbers, the ATT&CK techniques the captured event types map to,
the busiest sources' journeys, campaigns, SSH-client fingerprint clusters, coverage, and the report,
STIX and blocklist exports. Everything lands in `<workdir>/reports/`, with `analysis-summary.md`
tying it together. Triage afterwards in an MCP client pointed at the same copy (docs/DEPLOY.md, step 13).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

ROOT = Path(__file__).resolve().parent.parent


def clone_database(source: Path, workdir: Path) -> Path:
    """A private working copy: a copy-on-write clone where the filesystem has one, else a copy."""
    db = source / "honeypot_mcp.db" if source.is_dir() else source
    if not db.is_file():
        raise SystemExit(f"no database at {db}")
    workdir.mkdir(parents=True, exist_ok=True)
    target = workdir / "honeypot_mcp.db"
    for stale in workdir.glob("honeypot_mcp.db*"):
        stale.unlink()
    clone = (
        ["cp", "-c", str(db), str(target)]
        if sys.platform == "darwin"
        else ["cp", "--reflink=auto", str(db), str(target)]
    )
    if subprocess.run(clone, capture_output=True).returncode != 0:
        shutil.copy2(db, target)
    target.chmod(0o600)
    return target


async def call(client: Client, tool: str, args: dict[str, Any] | None = None) -> tuple[Any, float]:
    started = time.monotonic()
    result = await client.call_tool(tool, args or {}, raise_on_error=False)
    text = result.content[0].text if result.content else ""
    try:
        data = json.loads(text)
    except ValueError:
        data = text
    return data, time.monotonic() - started


async def analyse(db: Path, workdir: Path, top: int, hours: int) -> str:
    reports = workdir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "ANALYSIS_MODE": "true",
        "MCP_TRANSPORT": "stdio",
        "DATABASE_URL": f"sqlite+aiosqlite:///{db}",
        "REPORTS_DIR": str(reports),
        "CONSOLE_PORT": "0",
        "METRICS_PORT": "0",
        "PCAP_ENABLED": "false",
        "LOG_LEVEL": "WARNING",
    }
    python = shutil.which("python", path=str(ROOT / ".venv" / "bin")) or sys.executable
    transport = StdioTransport(
        command=python, args=["-m", "honeypot_mcp.server"], env=env, cwd=str(ROOT)
    )
    lines: list[str] = ["# Analysis summary", ""]
    async with Client(transport, timeout=900) as client:
        stats, _ = await call(client, "alerts_stats")
        brief, _ = await call(client, "soc_brief")
        attack, _ = await call(client, "attack_summary")
        lines += [
            f"- **{stats['total_alerts']:,}** alerts from **{stats['unique_source_ips']:,}** source IPs",
            "- by severity: " + ", ".join(f"{k} {v:,}" for k, v in stats["by_severity"].items()),
            *(f"- {h}" for h in brief.get("headline", [])),
            "",
            "## ATT&CK: what the run did, by tactic",
            "",
            f"{attack['event_types_seen']} event types; {attack['mapped_share']:.1%} of alerts map to a technique "
            "(the rest is connection and session bookkeeping).",
            "",
            "| Tactic | Technique | Alerts | Main event types |",
            "|---|---|---:|---|",
        ]
        for tactic in attack["tactics"]:
            for t in tactic["techniques"]:
                types = ", ".join(e["type"] for e in t["top_event_types"][:3])
                lines.append(
                    f"| {tactic['tactic']} | {t['technique_id']} {t['technique_name']} | {t['alerts']:,} | {types} |"
                )
        if attack["unmapped"]:
            lines += [
                "",
                "Left unmapped: "
                + ", ".join(f"{u['type']} ({u['alerts']:,})" for u in attack["unmapped"][:8]),
            ]

        lines += ["", f"## Top {top} sources", ""]
        for source in stats["top_source_ips"][:top]:
            ip = source["ip"]
            profile, _ = await call(client, "analyze_attacker", {"ip": ip})
            journey, _ = await call(client, "analyze_attacker_journey", {"ip": ip, "hours": hours})
            report, _ = await call(
                client,
                "generate_report",
                {"title": f"Source {ip}", "ip": ip, "format": "markdown", "since_hours": hours},
            )
            lines.append(
                f"- **{ip}**: risk {profile.get('risk_level')} ({profile.get('risk_score')}), "
                f"{source['count']:,} alerts. {journey.get('summary', '')} Report: `{Path(report.get('path', '?')).name}`"
            )

        campaigns, _ = await call(
            client, "analyze_campaign", {"window_minutes": 60, "min_sources": 3}
        )
        clusters, _ = await call(
            client, "fingerprint_clusters", {"hours": hours, "min_sources": 2, "limit": 10}
        )
        lines += ["", "## Campaigns and shared tooling", ""]
        lines.append(
            f"- {len(campaigns) if isinstance(campaigns, list) else 0} campaign(s): several sources, one event type, one window"
        )
        lines.append(
            f"- {clusters.get('clusters_matching', 0)} SSH client fingerprint cluster(s) shared by 2+ sources"
        )

        coverage, _ = await call(client, "deception_coverage")
        lines.append(f"- sensors map to {coverage.get('techniques_covered')} ATT&CK techniques")

        lines += ["", "## Files", ""]
        for label, tool, args in (
            (
                "full report",
                "generate_report",
                {"title": "Run summary", "format": "html", "since_hours": hours},
            ),
            ("STIX bundle", "export_stix", {"hours": hours, "min_hits": 50}),
            ("blocklist", "export_blocklist", {"format": "plain", "hours": hours, "min_hits": 50}),
        ):
            out, _ = await call(client, tool, args)
            lines.append(f"- {label}: `{out.get('path', out)}`")
    summary = "\n".join(lines) + "\n"
    (reports / "analysis-summary.md").write_text(summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("source", type=Path, help="a backup directory or a honeypot_mcp.db")
    parser.add_argument("--workdir", type=Path, default=Path.home() / "hp-analysis")
    parser.add_argument(
        "--top", type=int, default=3, help="how many of the busiest sources to profile"
    )
    parser.add_argument(
        "--hours", type=int, default=168, help="window for journeys, clusters and exports"
    )
    args = parser.parse_args()
    db = clone_database(args.source.expanduser(), args.workdir.expanduser())
    print(asyncio.run(analyse(db, args.workdir.expanduser(), args.top, args.hours)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
