"""`python -m honeypot_mcp.server` must serve the tools.

Running the file with `-m` makes it `__main__`, a different module object from
`honeypot_mcp.server`. The tool modules register on `honeypot_mcp.server.mcp`,
so the `__main__` copy used to serve a FastMCP instance with no tools at all —
every call answered "Unknown tool" — while startup logged nothing wrong.
"""

import os
import sys

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.mark.asyncio
async def test_module_launch_serves_the_registered_tools(tmp_path):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'launch.db'}",
        "MCP_TRANSPORT": "stdio",
        "METRICS_PORT": str(free_port()),
        "CANARY_CALLBACK_PORT": str(free_port()),
        "CONSOLE_PORT": "0",
    }
    transport = StdioTransport(
        command=sys.executable, args=["-m", "honeypot_mcp.server"], env=env, cwd=str(tmp_path)
    )
    async with Client(transport) as client:
        names = {t.name for t in await client.list_tools()}
    assert {"honeypot_deploy", "alerts_recent", "honeytoken_create", "soc_brief"} <= names
