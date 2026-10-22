"""The agent-first contract every tool must keep.

The server is driven by a model from a sentence a person typed. A tool that returns a bare list gives
an empty response when nothing matched (an agent cannot tell "none" from "failed"), one whose
parameters are not explained is filled in by guessing, and one that wants many arguments makes the
person learn flags, which is what a natural-language interface is for avoiding. These checks read the
registry, so a new tool cannot ship without meeting them.
"""

from __future__ import annotations

import json
import os
import typing

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

# A person can say two or three things in a sentence (an address, a name, a role); more than that
# is a form to fill in.
MAX_REQUIRED = 3
# Optional parameters beyond this need a reason (listed here, with it).
MAX_PARAMETERS = 8
MORE_PARAMETERS_BECAUSE: dict[str, str] = {}
# What a tool costs every agent, all the time: its description plus its parameter schema are in the
# model's context for the whole conversation, for every tool.
MAX_TOOL_WEIGHT = 3_000
MAX_TOTAL_WEIGHT = 70_000


async def _tools():
    from honeypot_mcp.server import mcp

    return {t.name: t for t in await mcp.list_tools()}


def _weight(tool) -> int:
    return len(tool.description or "") + len(json.dumps(tool.parameters or {}))


async def test_every_tool_returns_a_dict():
    """A bare list or string is an empty MCP response when there is nothing to say."""
    offenders = []
    for name, tool in (await _tools()).items():
        returned = typing.get_type_hints(tool.fn).get("return")
        origin = typing.get_origin(returned) or returned
        if origin is not dict:
            offenders.append(f"{name} returns {returned}")
    assert not offenders, "return `dict[str, Any]` with a count and a note: " + "; ".join(offenders)


async def test_every_parameter_is_explained_to_the_model():
    """The docstring's Args section becomes each parameter's description: without one the model
    fills the parameter in by guessing."""
    offenders = []
    for name, tool in (await _tools()).items():
        for parameter, schema in (tool.parameters or {}).get("properties", {}).items():
            if not (schema.get("description") or "").strip():
                offenders.append(f"{name}.{parameter}")
    assert not offenders, "no description: " + ", ".join(offenders)


async def test_no_tool_asks_for_more_than_a_sentence_holds():
    offenders = []
    for name, tool in (await _tools()).items():
        schema = tool.parameters or {}
        required = schema.get("required", [])
        total = len(schema.get("properties", {}))
        if len(required) > MAX_REQUIRED:
            offenders.append(f"{name} requires {len(required)}: {required}")
        if total > MAX_PARAMETERS and name not in MORE_PARAMETERS_BECAUSE:
            offenders.append(f"{name} has {total} parameters")
    assert not offenders, "; ".join(offenders)


async def test_the_tool_list_stays_cheap_to_load():
    weights = {name: _weight(tool) for name, tool in (await _tools()).items()}
    heavy = {n: w for n, w in weights.items() if w > MAX_TOOL_WEIGHT}
    assert not heavy, f"over {MAX_TOOL_WEIGHT:,} characters (description + schema): {heavy}"
    assert sum(weights.values()) <= MAX_TOTAL_WEIGHT, (
        f"the tool list weighs {sum(weights.values()):,} characters "
        f"(budget {MAX_TOTAL_WEIGHT:,}): it is in every agent's context"
    )


async def test_every_description_opens_with_what_the_tool_answers():
    """One real sentence first: models choose between tools from the opening line."""
    for name, tool in (await _tools()).items():
        first = (tool.description or "").strip().split("\n", 1)[0]
        assert len(first) >= 20 and first[0].isupper(), f"{name}: weak opening line {first!r}"
