#!/usr/bin/env python3
"""Analyse a HoneyPot MCP backup without running any sensor.

    scripts/analyze_backup.py ./backups/honeypot-20261012T141156Z
    scripts/analyze_backup.py path/to/honeypot_mcp.db --top 5 --hours 168 --workdir ./analysis

It copies the database (opening one upgrades its schema, and the backup is the only evidence), starts
the server over real MCP stdio in ANALYSIS_MODE (no honeypots, capture, canary or notifications), and
calls its `run_analysis` tool: headline numbers, the ATT&CK techniques the captured event types map
to, the busiest sources' journeys, campaigns, SSH-client fingerprint clusters, coverage, and the
report, STIX and blocklist exports. The same tool is available to any MCP client. Everything lands
in `<workdir>/reports/`, with `analysis-summary.md` tying it together. Triage afterwards in an MCP
client pointed at the same copy (docs/DEPLOY.md, step 13).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
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


async def analyse(db: Path, workdir: Path, top: int, hours: int) -> tuple[dict[str, Any], str]:
    """Start the server over MCP stdio in ANALYSIS_MODE on `db` and call its `run_analysis` tool.

    The workflow itself (what is assembled, how the headline and the ATT&CK table are computed)
    lives in the tool, `honeypot_mcp/tools/workflows.py`, so an MCP client can ask for exactly the
    same thing. This script only supplies the safe copy and the server.
    """
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
    async with Client(transport, timeout=3600) as client:
        result = await client.call_tool(
            "run_analysis", {"top": top, "hours": hours}, raise_on_error=False
        )
    text = result.content[0].text if result.content else ""
    try:
        digest = json.loads(text)
    except ValueError:
        return {"error": text or "run_analysis returned nothing"}, ""
    summary = reports / "analysis-summary.md"
    return digest, summary.read_text() if summary.is_file() else ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("source", type=Path, help="a backup directory or a honeypot_mcp.db")
    parser.add_argument("--workdir", type=Path, default=Path("analysis"))
    parser.add_argument(
        "--top", type=int, default=3, help="how many of the busiest sources to profile"
    )
    parser.add_argument(
        "--hours", type=int, default=168, help="window for journeys, clusters and exports"
    )
    args = parser.parse_args()
    db = clone_database(args.source.expanduser(), args.workdir.expanduser())
    digest, summary = asyncio.run(analyse(db, args.workdir.expanduser(), args.top, args.hours))
    if "error" in digest:
        print(f"run_analysis failed: {digest['error']}", file=sys.stderr)
        return 1
    print(summary or "(no summary file was written)")
    for failed in digest.get("failed", []):
        print(f"! {failed['part']} failed: {failed['error']}", file=sys.stderr)
    return 0 if digest.get("complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
