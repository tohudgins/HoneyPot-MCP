"""Every tool tells its client what it does to the world.

MCP clients decide approval prompts from annotations. Without them an agent either
asks before every harmless read or has nothing to flag `alerts_prune` with. These
tests pin the properties that matter.
"""

import os

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


async def _tools():
    """The tools the server will serve. Read from the registry rather than through a
    `Client` session: opening one runs the server lifespan, whose process-wide
    singletons then bind to this test's event loop and break the next test's."""
    from honeypot_mcp.server import mcp

    return {t.name: t for t in await mcp.list_tools()}


async def test_every_registered_tool_is_annotated_and_titled():
    from honeypot_mcp import tool_hints

    tools = await _tools()
    assert set(tools) == tool_hints.tool_names(), "tool_hints and the registered tools disagree"
    for name, tool in tools.items():
        a = tool.annotations
        assert a is not None and a.readOnlyHint is not None, name
        assert a.idempotentHint is not None and a.openWorldHint is not None, name
        assert tool.title and tool.title != name, f"{name} has no human title"


async def test_read_only_tools_do_not_claim_to_be_destructive_and_are_idempotent():
    for name, tool in (await _tools()).items():
        a = tool.annotations
        if a.readOnlyHint:
            assert not a.destructiveHint, name
            assert a.idempotentHint is True, name


async def test_the_viewer_tier_is_read_only_apart_from_the_two_file_writers():
    """A viewer token is the credential you hand to a triage agent. Everything it can
    call must be safe to run unattended; `generate_report` and `attack_navigator_layer`
    are the deliberate exceptions (each writes a new file inside the reports directory and a
    caller-named one cannot overwrite an existing file), so they are pinned by name rather
    than allowed to creep."""
    from honeypot_mcp import rbac

    tools = await _tools()
    not_read_only = {n for n in rbac.VIEWER_TOOLS if not tools[n].annotations.readOnlyHint}
    assert not_read_only == {"generate_report", "attack_navigator_layer"}
    assert tools["generate_report"].annotations.destructiveHint is False
    assert tools["attack_navigator_layer"].annotations.destructiveHint is False


async def test_everything_that_deletes_or_cannot_be_undone_is_marked_destructive():
    tools = await _tools()
    must_be_destructive = {
        "alerts_prune", "honeypot_stop", "honeypot_configure", "honeytoken_revoke",
        "honeytoken_rotate", "suppression_remove", "alert_unsubscribe", "api_key_revoke",
        "report_ip_abuse", "alerts_acknowledge", "suppression_add",
    }  # fmt: skip
    for name in must_be_destructive:
        assert tools[name].annotations.destructiveHint is True, name
        assert tools[name].annotations.readOnlyHint is False, name


async def test_tools_that_reach_outside_this_server_say_so():
    tools = await _tools()
    external = {
        "enrich_ip", "analyze_attacker", "generate_report", "report_ip_abuse", "run_analysis",
        "alert_subscribe", "blocklist_push_aws_waf", "blocklist_push_cloudflare",
        "blocklist_push_pfsense", "lookup_hash", "grafana_start",
    }  # fmt: skip
    for name, tool in tools.items():
        assert tool.annotations.openWorldHint is (name in external), name


async def test_any_tool_that_calls_a_threat_intel_service_is_open_world():
    """Derived from the code, not a list: `analyze_attacker` and `generate_report` sent
    attacker IPs to VirusTotal/AbuseIPDB while claiming to be closed-world, so a client
    that auto-approves closed-world tools would have leaked them without asking."""
    import inspect
    import re

    tools = await _tools()
    outbound = re.compile(r"lookup_(virustotal|abuseipdb|geoip)|report_ip\b|httpx\.")
    for name, tool in tools.items():
        if tool.fn is None:
            continue
        if outbound.search(inspect.getsource(tool.fn)):
            assert tool.annotations.openWorldHint is True, name


async def test_a_tool_that_is_not_classified_cannot_be_registered():
    from honeypot_mcp.tool_hints import hints

    with pytest.raises(KeyError):
        hints("brand_new_tool_nobody_classified")


async def test_every_tool_has_a_real_description_and_documented_parameters():
    """An agent chooses between ~64 tools by their descriptions. A one-line stub
    ("Create a new honeytoken.") gives it nothing to choose with: no hint of when to
    use the tool, what it returns, or what to use instead."""
    for name, tool in (await _tools()).items():
        description = (tool.description or "").strip()
        assert len(description) >= 60, f"{name}: description is a stub ({len(description)} chars)"
        assert "Args:" not in description, f"{name}: docstring Args leaked into the description"
        props = (tool.parameters or {}).get("properties", {})
        undocumented = [p for p, spec in props.items() if not spec.get("description")]
        assert not undocumented, f"{name}: undocumented parameters {undocumented}"
