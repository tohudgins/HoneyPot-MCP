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

from datetime import UTC, datetime, timedelta
from typing import Any

from honeypot_mcp import grafana, grafana_signin
from honeypot_mcp.config import get_settings
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._open import open_page
from honeypot_mcp.tools._window import data_span

_OVERVIEW_UID = "honeypot-overview"


async def _time_range() -> str:
    """The `from`/`to` a dashboard link must carry to open on data.

    A saved run is frozen in the past, so "the last 6 hours" is empty: link the span the data
    covers (capped at 30 days). A live server opens on the last 24 hours.
    """
    if get_settings().analysis_mode:
        start, end = await data_span()
    else:
        end = datetime.now(UTC)
        start = end - timedelta(hours=24)
    return f"orgId=1&from={int(start.timestamp() * 1000)}&to={int(end.timestamp() * 1000)}&timezone=utc"


async def _add_links(result: dict[str, Any], *, open_now: bool) -> None:
    """Put the person on the dashboards instead of telling them how to log in.

    Adds `signed_in_url`, a single-use link to the overview dashboard that signs in without the
    password ever being shown (`grafana_signin`), carries the data's time range on every
    dashboard link, and opens the page when this is the person's own machine.
    """
    port = result.get("port")
    if not result.get("running") or not port:
        return
    rng = await _time_range()
    base = f"http://127.0.0.1:{port}"
    urls = result.get("dashboard_urls")
    if isinstance(urls, dict):
        result["dashboard_urls"] = {title: f"{u}?{rng}" for title, u in urls.items()}
    try:
        password = (get_settings().grafana_dir / "admin_password").read_text().strip()
        link = await grafana_signin.mint(
            int(port), grafana.ADMIN_USER, password, f"{base}/d/{_OVERVIEW_UID}?{rng}"
        )
    except (OSError, ValueError):
        return  # no sign-in link: the plain URLs and the password file are still returned
    result["signed_in_url"] = link
    # Nothing in the result sends the person to a file: the link signs them in, and a fresh one
    # is a `grafana_status` away. (The password file stays on disk, 0600.)
    result.pop("read_password_with", None)
    result.pop("password_file", None)
    result["summary"] = (
        f"Grafana is running at {result.get('url')} (loopback only); sign-in is handled by `signed_in_url`."
    )
    result["opened_in_browser"] = await open_page(link) if open_now else False


def _headline(result: dict[str, Any]) -> str:
    if not result.get("running"):
        return "Grafana is not running."
    n = len(result.get("dashboards") or [])
    where = "a read-only view of the database"
    if result.get("opened_in_browser"):
        opened = "It is open in your browser, signed in, on the overview dashboard."
    elif result.get("signed_in_url"):
        opened = "Open `signed_in_url` to land on the overview dashboard already signed in (single use, 10 minutes)."
    else:
        opened = "Sign in as admin with the password in `password_file`."
    ok = result.get("datasource_ok")
    data = (
        ""
        if ok is None
        else (
            " It reads data fine."
            if ok
            else " The datasource did not answer: panels will be empty."
        )
    )
    return f"Grafana ({n} dashboards) is serving {where}. {opened}{data}"


@mcp.tool(auth=require_role("admin"), **hints("grafana_start"))
async def grafana_start(port: int | None = None) -> dict[str, Any]:
    """Put the Grafana dashboards on this server's database and give back the URL.

    Use it for "show me the dashboards", "open the threat map", or to look at a restored backup
    visually. Starts Grafana in Docker with the five packaged dashboards reading the SQLite
    database read-only, waits until it answers, then opens the overview in your browser already
    signed in (`signed_in_url` is a single-use link; the password is never shown). Dashboard
    links carry the time range of the data. Works in analysis mode; starting again replaces the
    previous instance. Loopback only. Needs Docker and internet. Admin only: dashboards can
    query the whole database.

    Args:
        port: Local port. Optional: by default a free one is chosen and reported in `url`.
    """
    result = await grafana.start(port)
    ok = "error" not in result
    if ok:
        await _add_links(result, open_now=True)
        result = {"headline": _headline(result), **result}
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

    Use it for "is Grafana up?", "what's the dashboard URL?". Reports whether it is up, which
    database it serves and for how long, with a fresh single-use `signed_in_url` (no password is
    shown). Takes no arguments.
    """
    result = await grafana.status()
    if result.get("running") and result.get("url"):
        result["port"] = int(str(result["url"]).rsplit(":", 1)[1].strip("/"))
        await _add_links(result, open_now=False)
        result = {"headline": _headline(result), **result}
    return result
