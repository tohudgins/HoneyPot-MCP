"""Do the shell-level fixes hold in the real Cowrie image, through the real `ssh` client?

`tests/unit/test_cowrie_shell_patch.py` proves the pure helpers and the filesystem content.
Whether the import hook patches Cowrie's own `head`, `uptime` and `/proc/uptime` (and whether
the tracked bait credential reaches the container's filesystem) only shows up by logging in to
a deployed container. Opt-in via `RUN_DOCKER_TESTS=1` and needs `sshpass`.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest

from tests._ports import free_port

pytestmark = pytest.mark.asyncio


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytest.importorskip("docker", reason="docker SDK not installed")

skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1"
    or not _docker_available()
    or shutil.which("sshpass") is None,
    reason="needs Docker, sshpass and RUN_DOCKER_TESTS=1 (pulls the Cowrie image)",
)


def _ssh(port: int, command: str) -> str:
    """Run `command` on the honeypot with the real OpenSSH client; stdout."""
    result = subprocess.run(
        [
            "sshpass", "-p", "hunter22", "ssh",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR", "-o", "PubkeyAuthentication=no",
            "-p", str(port), "root@127.0.0.1", command,
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )  # fmt: skip
    return result.stdout + result.stderr


async def _wait_for_ssh(port: int) -> None:
    for _ in range(60):
        await asyncio.sleep(1)
        try:
            out = await asyncio.to_thread(_ssh, port, "echo ready")
        except subprocess.TimeoutExpired:
            continue
        if "ready" in out:
            return
    pytest.fail(f"no SSH session on {port}")


@skip_docker
async def test_real_cowrie_head_uptime_and_tracked_bait():
    from honeypot_mcp import config
    from honeypot_mcp.engines import cowrie_sitecustomize as patch
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    previous_url = os.environ.get("DATABASE_URL")
    db_dir = tempfile.mkdtemp(prefix="honeypot-shell-it-")
    await close_db()
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(db_dir) / 'it.db'}"
    config._settings = None
    event_buffer.reset_for_tests()
    await init_db()
    await event_buffer.get_buffer().start()

    name = f"it-shell-{uuid.uuid4().hex[:8]}"
    port = free_port()
    deployed = False
    try:
        made = await honeytoken_create("credential", "bait-it", {"count": 1, "service": "mysql"})
        assert "error" not in made, made
        pair = made["metadata"]["credentials"][0]
        user, password = pair["username"], pair["password"]

        result = await honeypot_deploy(
            type="ssh", name=name, port=port, config={"ssh_persona": "debian_12"}
        )
        assert "error" not in result, result
        deployed = True
        await _wait_for_ssh(port)

        passwd = await asyncio.to_thread(_ssh, port, "head -2 /etc/passwd")
        assert (
            passwd.splitlines()
            == (await asyncio.to_thread(_ssh, port, "head -n 2 /etc/passwd")).splitlines()
        )
        assert len(passwd.splitlines()) == 2 and "invalid option" not in passwd

        hostname = (await asyncio.to_thread(_ssh, port, "hostname")).strip()
        floor = patch.boot_offset_seconds(hostname)
        up = float((await asyncio.to_thread(_ssh, port, "cat /proc/uptime")).split()[0])
        assert floor <= up <= floor + 600, (up, floor)

        shown = await asyncio.to_thread(_ssh, port, "uptime")
        days = int(re.search(r"up (\d+) days", shown).group(1))  # type: ignore[union-attr]
        assert days == floor // 86400 or days == (floor + 600) // 86400, shown

        from honeypot_mcp.engines.cowrie_fs import username_for
        from honeypot_mcp.engines.ssh_personas import get_persona

        home = f"/home/{username_for(get_persona('debian_12'), name)}"
        history = await asyncio.to_thread(_ssh, port, f"cat {home}/.bash_history")
        assert user in history and password in history, history
        cnf = await asyncio.to_thread(_ssh, port, f"cat {home}/.my.cnf")
        assert f"user={user}" in cnf and f'password="{password}"' in cnf, cnf
    finally:
        if deployed:
            await honeypot_stop(name=name, remove=True)
        await event_buffer.get_buffer().stop()
        await close_db()
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url
        config._settings = None
        event_buffer.reset_for_tests()
