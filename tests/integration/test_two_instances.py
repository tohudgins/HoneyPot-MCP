"""Two real server processes against one database.

The bug this pins: opening a second chat starts a second server, which "re-established"
the first one's honeypots, failed to bind their ports, and wrote a CRITICAL
`honeypot_restart_failed` alert — a false alarm that pages the people subscribed.
"""

import asyncio
import contextlib
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import time
from pathlib import Path

from fastmcp import Client

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "admin-token-0123456789abcdef"


def _free() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _spawn(work: Path, tag: str, mcp_port: int):
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{work}/shared.db",
        "MCP_TRANSPORT": "streamable-http",
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": str(mcp_port),
        "MCP_AUTH_TOKENS": f"{TOKEN}:admin",
        "METRICS_PORT": str(_free()),
        "CONSOLE_PORT": "0",
        "CANARY_CALLBACK_PORT": str(_free()),
        "REPORTS_DIR": str(work / "reports"),
        "TLS_DIR": str(work / "tls"),
    }
    return subprocess.Popen(
        ["uv", "run", "--project", str(ROOT), "python", "-m", "honeypot_mcp.server"],
        cwd=work, env=env, stdout=open(work / f"{tag}.log", "w"), stderr=subprocess.STDOUT,
        start_new_session=True,  # `uv run` spawns the server; signal the whole group
    )  # fmt: skip


def _wait(port: int) -> bool:
    for _ in range(160):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            return True
        except OSError:
            time.sleep(0.25)
    return False


async def _call(port: int, tool: str, args: dict):
    async with Client(f"http://127.0.0.1:{port}/mcp", auth=TOKEN) as c:
        return await c.call_tool(tool, args, raise_on_error=False)


async def test_a_second_server_is_read_only_and_raises_no_false_alarm(tmp_path):
    work = tmp_path / "run"
    work.mkdir()
    a_port, b_port, c_port, sensor_port = _free(), _free(), _free(), _free()
    procs = []
    try:
        a = _spawn(work, "A", a_port)
        procs.append(a)
        assert _wait(a_port), "the first server did not start"
        deployed = await _call(
            a_port, "honeypot_deploy", {"type": "http", "port": sensor_port, "name": "shared"}
        )
        assert not deployed.is_error and deployed.data["status"] == "running"
        assert (await _call(a_port, "ping", {})).data["role"] == "owner"

        b = _spawn(work, "B", b_port)
        procs.append(b)
        assert _wait(b_port), "the second server did not start"
        await asyncio.sleep(2.0)  # give a faulty startup time to do its damage

        # The second process says what it is, refuses to touch sensors, and still reads.
        assert (await _call(b_port, "ping", {})).data["role"] == "read-only"
        refused = await _call(
            b_port, "honeypot_deploy", {"type": "http", "port": _free(), "name": "second"}
        )
        assert "read-only" in str(refused.data) and "pid" in str(refused.data)
        listed = await _call(b_port, "honeypot_list", {})
        assert [h["name"] for h in listed.data] == ["shared"]

        # No false alarm in the data, and the first server's sensor is untouched.
        con = sqlite3.connect(work / "shared.db")
        alarms = con.execute(
            "select count(*) from alerts where event_type like 'honeypot_%failed'"
        ).fetchone()[0]
        status = con.execute("select status from honeypots where name='shared'").fetchone()[0]
        con.close()
        assert alarms == 0, (
            "the second process raised a false CRITICAL alert about the first one's sensor"
        )
        assert status == "running"
        socket.create_connection(("127.0.0.1", sensor_port), timeout=2).close()

        # When the owner goes away the next process takes over, with no stale lock.
        os.killpg(a.pid, signal.SIGKILL)  # no chance to clean up
        a.wait(timeout=20)
        c = _spawn(work, "C", c_port)
        procs.append(c)
        assert _wait(c_port)
        assert (await _call(c_port, "ping", {})).data["role"] == "owner"
    finally:
        for p in procs:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGTERM)
        for p in procs:
            try:
                p.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
        shutil.rmtree(work, ignore_errors=True)
