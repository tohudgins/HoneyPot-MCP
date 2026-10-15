"""`attack_navigator_layer`: an ATT&CK Navigator layer (format 4.5) from the exact rollup counts.

Validated against the published layer format
(github.com/mitre-attack/attack-navigator, layers/spec/v4.5/layerformat.md): required `name`,
`domain`, `versions.navigator` / `versions.layer == "4.5"`; each technique has a `techniqueID`
(`T####` or `T####.###`), a kebab-case `tactic`, numeric `score` and a `comment`; the gradient has
`maxValue > minValue`. Scores must equal what `attack_summary` reports for the same data.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}

# The 4.5 property table, transcribed: required members and types.
LAYER_SCHEMA = {
    "type": "object",
    "required": ["name", "domain", "versions", "techniques"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "description": {"type": "string"},
        "domain": {"enum": ["enterprise-attack", "mobile-attack", "ics-attack"]},
        "versions": {
            "type": "object",
            "required": ["navigator", "layer"],
            "properties": {
                "attack": {"type": "string"},
                "navigator": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
                "layer": {"const": "4.5"},
            },
        },
        "sorting": {"enum": [0, 1, 2, 3]},
        "layout": {
            "type": "object",
            "properties": {
                "layout": {"enum": ["side", "flat", "mini"]},
                "aggregateFunction": {"enum": ["average", "min", "max", "sum"]},
                "expandedSubtechniques": {"enum": ["none", "all", "annotated"]},
            },
        },
        "hideDisabled": {"type": "boolean"},
        "techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["techniqueID"],
                "properties": {
                    "techniqueID": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
                    "tactic": {"type": "string"},
                    "score": {"type": "number"},
                    "comment": {"type": "string"},
                    "enabled": {"type": "boolean"},
                    "showSubtechniques": {"type": "boolean"},
                },
            },
        },
        "gradient": {
            "type": "object",
            "required": ["colors", "minValue", "maxValue"],
            "properties": {
                "colors": {"type": "array", "minItems": 2, "items": {"type": "string"}},
                "minValue": {"type": "number"},
                "maxValue": {"type": "number"},
            },
        },
    },
}


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(rows: list[tuple[str, int, timedelta]]) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    now = datetime.now(UTC)
    async with get_session() as session:
        for event_type, count, age in rows:
            for i in range(count):
                session.add(
                    Alert(
                        source_ip=f"198.51.100.{i % 5 + 1}",
                        event_type=event_type,
                        severity=AlertSeverity.MEDIUM,
                        timestamp=now - age,
                        payload={},
                    )
                )


def _layer(result: dict) -> dict:
    return json.loads(Path(result["path"]).read_text(encoding="utf-8"))


async def _seed_run() -> None:
    await _seed(
        [
            ("sip_extension_probe", 40, timedelta(0)),  # Discovery, T1046
            ("redis_config_set", 7, timedelta(0)),  # Initial Access, T1190
            ("ssh_login_failed", 12, timedelta(0)),  # Credential Access, T1110.001
            ("telnet_session_connect", 15, timedelta(0)),  # bookkeeping: unmapped
        ]
    )


async def test_the_layer_validates_against_the_published_format():
    jsonschema = pytest.importorskip("jsonschema")
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    layer = _layer(await attack_navigator_layer())

    jsonschema.validate(layer, LAYER_SCHEMA)
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5" and layer["versions"]["attack"]
    assert layer["name"] and "all time" in layer["name"]
    assert layer["gradient"]["maxValue"] > layer["gradient"]["minValue"]
    for tech in layer["techniques"]:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", tech["techniqueID"])
        assert tech["tactic"] in TACTICS
        assert isinstance(tech["score"], int) and tech["score"] >= 0
        assert isinstance(tech["comment"], str) and tech["comment"]


async def test_scores_are_the_alert_counts_attack_summary_reports_for_the_same_data():
    from honeypot_mcp.tools.analysis import attack_summary
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    summary = await attack_summary()
    layer = _layer(await attack_navigator_layer())

    from_summary = {
        t["technique_id"]: t["alerts"]
        for tactic in summary["tactics"]
        for t in tactic["techniques"]
    }
    from_layer = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    for technique_id, alerts in from_summary.items():
        assert from_layer[technique_id] == alerts, technique_id
    assert from_layer["T1046"] == 40 and from_layer["T1190"] == 7 and from_layer["T1110.001"] == 12

    by_id = {t["techniqueID"]: t for t in layer["techniques"]}
    assert by_id["T1046"]["tactic"] == "discovery" and by_id["T1190"]["tactic"] == "initial-access"
    assert by_id["T1110.001"]["tactic"] == "credential-access"
    assert "sip_extension_probe (40)" in by_id["T1046"]["comment"]
    assert layer["gradient"]["maxValue"] == 40


async def test_a_sub_technique_carries_its_parent_so_it_shows_when_expanded():
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    by_id = {t["techniqueID"]: t for t in _layer(await attack_navigator_layer())["techniques"]}

    parent = by_id["T1110"]
    assert parent["tactic"] == by_id["T1110.001"]["tactic"] == "credential-access"
    assert parent["showSubtechniques"] is True
    assert parent["score"] == 0 and "sub-technique" in parent["comment"]


async def test_bookkeeping_is_reported_unmapped_and_never_scored():
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    result = await attack_navigator_layer()
    layer = _layer(result)

    assert result["total_alerts"] == 74 and result["mapped_alerts"] == 59
    assert result["unmapped"] == [{"type": "telnet_session_connect", "alerts": 15}]
    assert all("telnet_session_connect" not in t["comment"] for t in layer["techniques"])
    assert result["techniques"] == len(layer["techniques"])


async def test_the_window_filters_and_a_bad_window_is_refused():
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed([("redis_config_set", 4, timedelta(0)), ("redis_config_set", 6, timedelta(days=3))])

    recent = await attack_navigator_layer(since_hours=24, output_path="recent.json")
    everything = await attack_navigator_layer(output_path="everything.json")

    assert {t["techniqueID"]: t["score"] for t in _layer(recent)["techniques"]}["T1190"] == 4
    assert {t["techniqueID"]: t["score"] for t in _layer(everything)["techniques"]}["T1190"] == 10
    assert "last 24h" in _layer(recent)["name"]
    assert "error" in await attack_navigator_layer(since_hours=0)


async def test_an_empty_database_is_a_valid_empty_layer():
    jsonschema = pytest.importorskip("jsonschema")
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    result = await attack_navigator_layer()
    layer = _layer(result)

    jsonschema.validate(layer, LAYER_SCHEMA)
    assert layer["techniques"] == [] and result["techniques"] == 0
    assert layer["gradient"]["maxValue"] > layer["gradient"]["minValue"]


async def test_the_file_goes_to_the_reports_directory_and_a_named_file_is_never_replaced(tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    reports = get_settings().reports_dir.resolve()

    auto = await attack_navigator_layer()
    named = await attack_navigator_layer(output_path="mine.json")
    again = await attack_navigator_layer(output_path="mine.json")

    assert Path(auto["path"]).resolve().parent == reports
    assert Path(named["path"]) == reports / "mine.json"
    assert "already exists" in again["error"], "a caller-named file must never be overwritten"


@pytest.mark.parametrize("hostile", ["../escape.json", "/tmp/honeypot-navigator-escape.json"])
async def test_a_path_outside_the_reports_directory_is_refused_and_nothing_is_written(hostile):
    from honeypot_mcp.tools.ioc import attack_navigator_layer

    await _seed_run()
    result = await attack_navigator_layer(output_path=hostile)

    assert "Refusing to write outside the reports directory" in result["error"]
    assert not Path("/tmp/honeypot-navigator-escape.json").exists()


async def test_the_tool_is_registered_viewer_tier_and_honest_about_writing():
    from honeypot_mcp import rbac
    from honeypot_mcp.server import mcp

    tools = {t.name: t for t in await mcp.list_tools()}

    assert "attack_navigator_layer" in rbac.VIEWER_TOOLS
    annotations = tools["attack_navigator_layer"].annotations
    assert annotations.readOnlyHint is False, "it writes a file; it must not claim to be read-only"
    assert annotations.destructiveHint is False and annotations.openWorldHint is False
