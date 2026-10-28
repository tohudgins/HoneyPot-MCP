"""Show something to the person instead of describing how to get to it.

A tool that makes a dashboard, a report or an ATT&CK Navigator layer should put it in front of the
person, not answer "open this file, then go to that site, then upload it". When the server runs on
the person's own machine (stdio: their MCP client started it) the page is opened in their default
browser; for a networked server, which cannot know whose screen that would be, nothing is opened and
the result carries the link instead.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

from honeypot_mcp.config import get_settings


def is_local_session() -> bool:
    """True when the server was started by the person's own client, so its screen is theirs."""
    settings = get_settings()
    return settings.open_in_browser and settings.mcp_transport == "stdio"


async def open_page(url: str) -> bool:
    """Open `url` in the default browser if this is the person's own machine.

    Returns whether a browser took it. Never raises: a headless host simply returns False and the
    caller's result still carries the link.
    """
    if not is_local_session():
        return False
    try:
        return bool(await asyncio.to_thread(webbrowser.open, url, 2))
    except Exception:
        return False


def file_url(path: str | Path) -> str:
    """A `file://` URL a browser or a terminal can open for a file this server wrote."""
    return Path(path).resolve().as_uri()


def _clipboard_command() -> list[str]:
    if sys.platform == "darwin":
        return ["pbcopy"]
    if sys.platform.startswith("win"):
        return ["clip"]
    if shutil.which("wl-copy"):
        return ["wl-copy"]
    if shutil.which("xclip"):
        return ["xclip", "-selection", "clipboard"]
    return []


async def copy_to_clipboard(text: str) -> bool:
    """Put `text` on the person's clipboard (their own machine only), so a login can be pasted.

    For a secret the model must never see: the caller reads it and this hands it straight to the
    clipboard utility. Returns False on a networked server or a host without one.
    """
    command = _clipboard_command() if is_local_session() else []
    if not command or not shutil.which(command[0]):
        return False
    try:
        done = await asyncio.to_thread(
            subprocess.run, command, input=text.encode(), timeout=5, check=False
        )
    except Exception:
        return False
    return done.returncode == 0
