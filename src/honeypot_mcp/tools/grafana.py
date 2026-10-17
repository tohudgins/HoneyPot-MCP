"""Grafana dashboards on the server's own data: start, stop, status.

"Put the dashboards on my data" is one call. `grafana_start` runs a Grafana container loaded with
the packaged dashboards, pointed read-only at the SQLite database this server uses, so it works
on a live server and in ANALYSIS_MODE against a restored backup. These tools never touch the
honeypot sensors, so the read-only gate that blocks deploy/stop in analysis mode does not apply.

The lifecycle (container, private directory, database view, readiness check) is `grafana.py`;
this module is the MCP surface and the audit trail. The generated admin password is written to a
0600 file and only the file's *path* is ever returned or audited.
"""

from __future__ import annotations

from typing import Any

from honeypot_mcp import grafana
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit


@mcp.tool(auth=require_role("admin"), **hints("grafana_start"))
async def grafana_start(port: int = 3000) -> dict[str, Any]:
    """Put the Grafana dashboards on this server's database.

    Use when someone asks to "put the dashboards on my data", see the overview, threat map,
    ATT&CK coverage, query or alerts dashboards, or look at a backup visually. Starts a
    pinned Grafana container with the five packaged dashboards, reading the configured SQLite
    database read-only, and waits until it is healthy and a test query through its SQLite
    datasource succeeds. Works in ANALYSIS_MODE against a restored backup. Starting it again
    REPLACES the previous instance: its containers, networks and private directory are removed
    first (Grafana keeps nothing between runs, so edits made in its UI are lost).

    Admin tier, because the dashboards can query the whole database, including the tables that
    hold honeytoken values and API-key digests. Grafana is published on 127.0.0.1 only (there is
    no bind-address option), has no anonymous access, runs as a non-root user, and gets a
    generated admin password that is written to a 0600 file: the result carries that file's path,
    never the password. The Grafana container that holds the data has no route out (internal
    Docker network); a small forwarder container publishes the loopback port and does keep
    outbound access, but holds no data. The SQLite plugin is a pinned version, checksum-verified.

    The database is exposed through a private directory that holds only the database files:
    `db_mount` says how (`hardlink` is a live view; `reflink` or `copy` is a snapshot as of the
    start, with the reason in `notes`). `GRAFANA_DIR` must be an empty or dedicated directory. The
    first start pulls the Grafana image and every start downloads the plugin, so it needs
    internet access; Docker must be running.

    Args:
        port: Local port to publish Grafana on (default 3000). Loopback only.

    Returns:
        `url`, `username`, `password_file`, `db_mount`, `dashboards` (names) and
        `dashboard_urls`, `datasource_ok`, `needs_prometheus` (dashboards that would show no data
        here), and `notes`. On failure (no Docker, offline, port busy, database not SQLite or
        missing) `error` and `hint`.
    """
    result = await grafana.start(port)
    ok = "error" not in result
    await _audit.record_action(
        "grafana_start",
        (
            f"Grafana started on 127.0.0.1:{result.get('port')} ({result.get('db_mount')} view)"
            if ok
            else "Grafana start failed"
        ),
        arguments={"port": port},
        target=grafana.CONTAINER_NAME,
        outcome="ok" if ok else "error",
        error=None if ok else str(result["error"])[:500],
    )
    return result


@mcp.tool(auth=require_role("admin"), **hints("grafana_stop"))
async def grafana_stop() -> dict[str, Any]:
    """Stop the Grafana started by `grafana_start` and remove its private files.

    Removes only the containers and networks this server created (identified by their label,
    never by name alone) and, from `GRAFANA_DIR`, only the exact names `grafana_start` made there
    (the database view, config, plugin, password file, marker) and only if the marker is present.
    Safe to call when nothing is running: it reports that and changes nothing. Does not touch the
    database or anyone else's Grafana. Admin tier, like `grafana_start`.

    Returns:
        `stopped`, `was_running`, `removed_containers`, `removed_networks`, `removed_link_dir`,
        `note`; or `error` when Docker cannot be reached.
    """
    result = await grafana.stop()
    ok = "error" not in result
    await _audit.record_action(
        "grafana_stop",
        "Grafana stopped" if ok and result.get("stopped") else "Grafana stop (nothing running)",
        target=grafana.CONTAINER_NAME,
        outcome="ok" if ok else "error",
        error=None if ok else str(result["error"])[:500],
    )
    return result


@mcp.tool(**hints("grafana_status"))
async def grafana_status() -> dict[str, Any]:
    """Is the Grafana from `grafana_start` running, and which database does it serve?

    Reports whether the container is up, its URL, the dashboards it carries, the database file
    it reads and how that file is mounted (`db_mount`), and how long it has been up. Reveals no
    credential: the password file's path comes back from `grafana_start`, not from here.

    Returns:
        `running`, `url`, `dashboards`, `database`, `db_mount`, `uptime_seconds`; `error` when
        Docker cannot be reached.
    """
    return await grafana.status()
