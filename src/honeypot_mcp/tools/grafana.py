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
async def grafana_start(port: int | None = None) -> dict[str, Any]:
    """Put the Grafana dashboards on this server's database and give back the URL.

    Use it for "show me the dashboards", "open the threat map", or to look at a restored backup
    visually. Starts Grafana in Docker with the five packaged dashboards reading the SQLite
    database read-only, then waits until it answers. Works in analysis mode; starting again
    replaces the previous instance. Reachable on 127.0.0.1 only, login `admin`, password in the
    returned `password_file` (never returned itself). Needs Docker and internet. Admin only:
    dashboards can query the whole database.

    Args:
        port: Local port. Optional: by default a free one is chosen and reported in `url`.
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
        arguments={"port": port} if port is not None else {},
        target=grafana.CONTAINER_NAME,
        outcome="ok" if ok else "error",
        error=None if ok else str(result["error"])[:500],
    )
    return result


@mcp.tool(auth=require_role("admin"), **hints("grafana_stop"))
async def grafana_stop() -> dict[str, Any]:
    """Stop the dashboards started by `grafana_start` and remove their temporary files.

    Use it for "stop Grafana", "shut the dashboards down". Safe when nothing is running (it says
    so). Removes only what this server created; the database and anyone else's Grafana are never
    touched. Takes no arguments. Admin only.
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
    """Are the dashboards running, and at what URL?

    Use it for "is Grafana up?", "what's the dashboard URL?". Reports whether it is up, its URL,
    which database it serves and for how long. No password is shown: `grafana_start` returns the
    password file's path. Takes no arguments.
    """
    return await grafana.status()
