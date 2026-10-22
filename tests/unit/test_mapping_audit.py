"""`mapping_audit`: a blind, reproducible, stratified sample and the scoring of labels against it.

The scoring arithmetic is checked on a hand-built key (no database) whose expected numbers are worked
out in the comments; the sampling is checked against a synthetic database of known events. Payloads
are deliberately neutral: the blind file is scanned for technique ids and tactic names, so no test
payload may contain either.
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

PLANTED_PASSWORD = "S3cretPlantedPw!"

# What the project maps these event types to (asserted below so a mapping change fails loudly here).
SEED_COUNTS = {
    "ssh_login_failed": 40,  # T1110.001
    "ssh_login_success": 3,  # T1110.001 + T1078 (two techniques)
    "mongodb_ransom_note": 2,  # T1486 (a rare type)
    "ssh_command_input": 60,  # T1059.004
    "telnet_session_connect": 30,  # unmapped, bookkeeping
    "ssh_client_version": 10,  # unmapped, not bookkeeping
    "sip_extension_probe": 100,  # T1046
}
TOTAL = sum(SEED_COUNTS.values())


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import _window

    event_buffer.reset_for_tests()
    _window.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    _window.reset_for_tests()
    await close_db()


def _payload(event_type: str, i: int) -> dict[str, Any]:
    return {"session": f"s{i}", "note": f"neutral text {event_type} {i}", "sensor": "lab"}


async def _seed(
    counts: dict[str, int] | None = None,
    *,
    when: datetime | None = None,
    payloads: dict[str, dict[str, Any]] | None = None,
) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    stamp = when or datetime.now(UTC)
    async with get_session() as session:
        for event_type, n in (counts or SEED_COUNTS).items():
            for i in range(n):
                session.add(
                    Alert(
                        source_ip="192.0.2.7",
                        event_type=event_type,
                        payload=(payloads or {}).get(event_type) or _payload(event_type, i),
                        severity=AlertSeverity.MEDIUM,
                        timestamp=stamp,
                    )
                )


def _reports() -> Path:
    from honeypot_mcp.config import get_settings

    return get_settings().reports_dir


async def _sample(**kwargs: Any) -> dict[str, Any]:
    """The sampler behind the tool. The tool itself takes no sizing knobs (it sizes its own
    sample and seeds from the data); the knobs stay on `_sample` so the design stays testable."""
    from honeypot_mcp.tools import mapping_audit as ma

    kwargs.setdefault("sample_size", 30)
    kwargs.setdefault("seed", 7)
    return await ma._sample(kwargs.pop("since_hours", None), **kwargs)


async def _score(**kwargs: Any) -> dict[str, Any]:
    """The scorer behind the tool, with explicit key file / top / draws."""
    from honeypot_mcp.tools import mapping_audit as ma

    return await ma._score(
        kwargs.get("labels_file"),
        kwargs.get("key_file"),
        kwargs.get("second_labels_file"),
        kwargs.get("top", 15),
        kwargs.get("interval_draws", 200),
    )


def _lines(name: str) -> list[dict[str, Any]]:
    return [json.loads(x) for x in (_reports() / name).read_text().splitlines() if x.strip()]


def _items(name: str) -> list[dict[str, Any]]:
    return [r for r in _lines(name) if r["record"] == "item"]


# ── pure arithmetic ───────────────────────────────────────────────────────────────────────────────


def test_allocate_floor_then_proportional_top_up_hand_computed():
    from honeypot_mcp.tools.mapping_audit import allocate

    # floor 1 each (3), 7 left; shares 3.465 / 3.465 / 0.069 -> 3, 3, 0; the last one by largest
    # remainder (a and b tie, a wins on name).
    assert allocate({"a": 100, "b": 100, "c": 2}, 10, 1) == {"a": 5, "b": 4, "c": 1}
    # a tiny stratum is never starved of its floor and never given more than it holds
    assert allocate({"a": 2, "b": 1000}, 50, 1) == {"a": 1, "b": 49}
    assert allocate({"a": 3, "b": 3}, 10, 1) == {
        "a": 3,
        "b": 3,
    }  # asks for more than exists: take all
    assert sum(allocate({"a": 5000, "b": 40, "c": 7}, 100, 2).values()) == 100


def test_allocate_refuses_a_budget_below_the_floor():
    from honeypot_mcp.tools.mapping_audit import allocate

    with pytest.raises(ValueError, match="cannot cover"):
        allocate({"a": 5, "b": 5, "c": 5}, 2, 1)


def test_wilson_and_kappa_known_values():
    from honeypot_mcp.tools.mapping_audit import cohen_kappa, jaccard, wilson

    lo, hi = wilson(5, 10)
    assert (round(lo, 4), round(hi, 4)) == (0.2366, 0.7634)
    lo, hi = wilson(0, 10)
    assert lo == 0.0 and round(hi, 4) == 0.2775
    assert wilson(0, 0) == (0.0, 1.0)
    # po=.75, pa=.5, pb=.25 -> pe=.5 -> kappa=.5
    assert cohen_kappa([True, True, False, False], [True, False, False, False]) == pytest.approx(
        0.5
    )
    assert cohen_kappa([True, True], [True, True]) is None  # no variation: undefined
    assert jaccard(set(), set()) == 1.0
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)


def test_protocol_comes_from_the_event_type_prefix():
    from honeypot_mcp.tools.mapping_audit import protocol_of

    assert protocol_of("ssh_login_failed") == "ssh"
    assert protocol_of("docker_api_container_escape") == "docker_api"
    assert protocol_of("honeytoken_triggered_credential_via_mysql_login_attempt") == "mysql"
    assert protocol_of("honeytoken_triggered_canary_url") == "honeytoken"
    assert protocol_of("flood_summary") == "platform"
    assert protocol_of("honeypot_health_failed") == "platform"


def test_tactic_names_are_normalised():
    from honeypot_mcp.tools.mapping_audit import _norm_tactic

    assert _norm_tactic("credential_access") == "Credential Access"
    assert _norm_tactic("TA0006") == "Credential Access"
    assert _norm_tactic("  command-and-control ") == "Command and Control"
    assert _norm_tactic("made up") is None


# ── scoring on a hand-built key ───────────────────────────────────────────────────────────────────


def _key() -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    strata = {
        # event type: (population, kind, mapped, item ids)
        "alpha_event": (100, "mapped", ["T1110.001"], ["a1", "a2", "a3", "a4"]),
        "beta_event": (50, "mapped", ["T1059.004"], ["b1", "b2"]),
        "gamma_event": (10, "unmapped_other", [], ["c1", "c2"]),
        "delta_event": (2, "mapped", ["T1486"], ["d1", "d2"]),  # every alert sampled
    }
    tactics = {"T1110.001": "Credential Access", "T1059.004": "Execution", "T1486": "Impact"}
    items: dict[str, dict[str, Any]] = {}
    for event_type, (population, kind, mapped, ids) in strata.items():
        for item_id in ids:
            items[item_id] = {
                "record": "item",
                "item_id": item_id,
                "event_type": event_type,
                "stratum": event_type,
                "kind": kind,
                "stratum_population": population,
                "stratum_sampled": len(ids),
                "weight": population / len(ids),
                "mapped_techniques": mapped,
                "mapped_names": {t: t + " name" for t in mapped},
                "mapped_tactics": sorted({tactics[t] for t in mapped}),
            }
    return {"seed": 5, "population_total": 162}, items


def _label(techniques: list[str], tactics: set[str] | None = None, confidence: str | None = None):
    return {
        "techniques": frozenset(techniques),
        "tactics": frozenset(tactics) if tactics is not None else None,
        "confidence": confidence,
    }


def _labels_a() -> dict[str, dict[str, Any]]:
    return {
        "a1": _label(["T1110.001"], {"Credential Access"}, "high"),
        "a2": _label(["T1110.003"]),
        "a3": _label(["T1110"]),
        "a4": _label([], set(), "low"),
        "b1": _label(["T1059.004", "T1105"], {"Execution", "Command and Control"}),
        "b2": _label(["T1059"]),
        "c1": _label(["T1046"]),
        "c2": _label([]),
        "d1": _label(["T1486"]),
        "d2": _label(["T1485"]),
    }


def _labels_b() -> dict[str, dict[str, Any]]:
    return {
        "a1": _label(["T1110.001"]),
        "a2": _label(["T1110.001"]),
        "a3": _label(["T1110"]),
        "a4": _label(["T1110.001"]),
        "b1": _label(["T1059.004"]),
        "b2": _label(["T1059"]),
        "c1": _label([]),
        "c2": _label([]),
        "d1": _label(["T1486"]),
        "d2": _label(["T1485"]),
    }


def _rate(result: dict[str, Any], level: str, metric: str, where: str) -> float | None:
    return result["headline"][level][metric][where]["rate"]


def test_scoring_hand_computed_strict_vs_parent_and_reweighting():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    out = score_labels(header, items, _labels_a(), draws=300)

    # Weights: alpha 25 each, beta 25, gamma 5, delta 1.  Alerts total 162 (mapped 152).
    # exact agreement strict: a1, c2, d1 -> 3/10 sample; (25 + 5 + 1)/162 population
    assert _rate(out, "strict", "exact_agreement", "sample") == 0.3
    assert _rate(out, "strict", "exact_agreement", "population") == pytest.approx(
        31 / 162, abs=1e-4
    )
    # parent level also agrees on a2, a3 (T1110.00x = T1110) and b2 (T1059 = T1059.004): 6/10
    assert _rate(out, "parent", "exact_agreement", "sample") == 0.6
    assert _rate(out, "parent", "exact_agreement", "population") == pytest.approx(
        106 / 162, abs=1e-4
    )

    # mapped alerts judged wrong: strict a2 a3 a4 b2 d2 of 8 mapped; parent only a4 and d2
    assert _rate(out, "strict", "mapped_judged_wrong", "sample") == 0.625
    assert _rate(out, "strict", "mapped_judged_wrong", "population") == pytest.approx(
        101 / 152, abs=1e-4
    )
    assert _rate(out, "parent", "mapped_judged_wrong", "sample") == 0.25
    assert _rate(out, "parent", "mapped_judged_wrong", "population") == pytest.approx(
        26 / 152, abs=1e-4
    )
    # b1's labels include the mapped technique, so a missing extra label does not make the mapping wrong
    assert _rate(out, "strict", "mapped_entirely_wrong", "sample") == 0.625
    assert _rate(out, "parent", "mapped_entirely_wrong", "sample") == 0.25

    # alerts the labeller gave a technique that the project left unmapped: only c1, of 8 labelled
    assert _rate(out, "strict", "labelled_left_unmapped", "sample") == 0.125
    assert _rate(out, "strict", "labelled_left_unmapped", "population") == pytest.approx(
        5 / 132, abs=1e-4
    )
    # ... and b1 has a labelled technique the project does not map (partly unmapped), c1 as well
    assert out["headline"]["strict"]["labelled_partly_unmapped"]["sample"]["numerator"] >= 2

    # micro precision/recall (strict): shared techniques a1, b1, d1 = 3; mapped total 8; labelled 9
    assert _rate(out, "strict", "precision", "sample") == 0.375
    assert _rate(out, "strict", "recall", "sample") == pytest.approx(3 / 9, abs=1e-4)
    assert out["items"]["labelled"] == 10 and out["items"]["population_covered_share"] == 1.0


def test_per_technique_per_tactic_and_empty_label_sets():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    out = score_labels(header, items, _labels_a(), draws=100)
    strict = {r["id"]: r for r in out["per_technique"]["strict"]}
    # T1110.001: mapped for a1..a4, labelled only for a1 -> tp 1, fp 3 (a4's empty set counts)
    assert (strict["T1110.001"]["tp"], strict["T1110.001"]["fp"], strict["T1110.001"]["fn"]) == (
        1,
        3,
        0,
    )
    assert strict["T1110.001"]["precision"] == 0.25 and strict["T1110.001"]["recall"] == 1.0
    # T1059.004: b1 tp, b2 fp (labelled the parent only, strict)
    assert strict["T1059.004"]["precision"] == 0.5
    assert strict["T1059.004"]["f1"] == pytest.approx(2 / 3, abs=1e-4)
    # a technique only a labeller gave is a pure false negative
    assert strict["T1105"]["support"] == 1 and strict["T1105"]["recall"] == 0.0
    assert strict["T1105"]["precision"] is None
    # parent level merges T1110.00x and T1110 and T1059(.004)
    parent = {r["id"]: r for r in out["per_technique"]["parent"]}
    assert (parent["T1110"]["tp"], parent["T1110"]["fp"], parent["T1110"]["fn"]) == (3, 1, 0)
    assert (parent["T1059"]["tp"], parent["T1059"]["fp"]) == (2, 0)

    # tactics: only items that carry a tactic (or an empty technique list, which implies none)
    tactics = {r["id"]: r for r in out["per_tactic"]}
    assert out["items"]["with_tactic_label"] == 3  # a1, a4 (explicit empty set) and b1
    assert tactics["Credential Access"]["precision"] == 0.5  # a1 right, a4 mapped but labelled none
    assert tactics["Credential Access"]["recall"] == 1.0
    assert tactics["Command and Control"]["recall"] == 0.0


def test_interval_properties_census_strata_and_reproducibility():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    first = score_labels(header, items, _labels_a(), draws=400)
    again = score_labels(header, items, _labels_a(), draws=400)
    assert first["headline"] == again["headline"]  # seeded: identical
    for level in ("strict", "parent"):
        for name, cell in first["headline"][level].items():
            lo, hi = cell["population"]["ci95"]
            assert 0.0 <= lo <= hi <= 1.0, name
    cell = first["headline"]["parent"]["exact_agreement"]["population"]
    assert cell["ci95"][0] <= cell["rate"] <= cell["ci95"][1]
    assert cell["ci95"][1] - cell["ci95"][0] > 0.05  # strata of 2-4 items are not certain

    # only the census stratum (every alert labelled) -> nothing is uncertain
    only_delta = {k: v for k, v in _labels_a().items() if k.startswith("d")}
    out = score_labels(header, items, only_delta, draws=200)
    est = out["headline"]["strict"]["exact_agreement"]["population"]
    assert est["rate"] == 0.5 and est["ci95"] == [0.5, 0.5]
    assert out["items"]["population_covered_share"] == pytest.approx(2 / 162, abs=1e-4)


def test_more_items_narrow_the_interval():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, small = _key()
    big: dict[str, dict[str, Any]] = {}
    labels_small: dict[str, dict[str, Any]] = {}
    labels_big: dict[str, dict[str, Any]] = {}
    for i in range(40):
        base = dict(small["a1"], item_id=f"x{i}", stratum_sampled=40, weight=100 / 40)
        big[f"x{i}"] = base
        labels_big[f"x{i}"] = _label(["T1110.001"] if i % 2 == 0 else [])
    for i in range(4):
        labels_small[f"x{i}"] = labels_big[f"x{i}"]
    keys_small = {k: dict(big[k], stratum_sampled=4) for k in labels_small}
    wide = score_labels(header, keys_small, labels_small, draws=500)["headline"]["parent"]
    narrow = score_labels(header, big, labels_big, draws=500)["headline"]["parent"]

    def width(h: dict[str, Any]) -> float:
        lo, hi = h["exact_agreement"]["population"]["ci95"]
        return hi - lo

    assert width(narrow) < width(wide)


def _one_item_key(items_big: int, population: int = 100_000):
    """A huge stratum sampled `items_big` times plus a small census stratum (so there is a mix)."""
    header, base = _key()
    items: dict[str, dict[str, Any]] = {}
    for i in range(items_big):
        items[f"big{i}"] = dict(
            base["a1"],
            item_id=f"big{i}",
            event_type="big_event",
            stratum="big_event",
            stratum_population=population,
            stratum_sampled=items_big,
            weight=population / items_big,
        )
    for d in ("d1", "d2"):
        items[d] = base[d]
    return header, items


@pytest.mark.parametrize("items_big", [1, 5])
def test_parent_level_interval_has_width_for_a_stratum_of_one_or_all_agreeing_items(items_big):
    """Regression: resampling only the outcomes that were observed gave a stratum of one item (or whose
    items all agree) a single category with probability 1, so every parent-level interval was
    [x, x] while strata with mixed outcomes made the strict ones look fine."""
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _one_item_key(items_big)
    labels = {
        f"big{i}": _label(["T1110.003"]) for i in range(items_big)
    }  # parent agrees, strict not
    labels["d1"], labels["d2"] = _label(["T1486"]), _label(["T1486"])
    out = score_labels(header, items, labels, draws=600)["headline"]
    for level in ("parent", "strict"):
        for metric in ("exact_agreement", "mapped_judged_wrong", "precision"):
            cell = out[level][metric]["population"]
            lo, hi = cell["ci95"]
            assert lo <= cell["rate"] <= hi, (level, metric)
            assert hi - lo > 0.1, (level, metric, cell)
    # the point estimate itself is unchanged: the big stratum agrees at parent level on every item
    assert out["parent"]["exact_agreement"]["population"]["rate"] == 1.0
    assert out["strict"]["exact_agreement"]["population"]["rate"] == pytest.approx(
        2 / 100_002, abs=1e-4
    )


def test_concentration_by_kind_and_sensitivity_hand_computed():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    out = score_labels(header, items, _labels_a(), draws=300)["headline"]["strict"]
    cell = out["exact_agreement"]

    # numerator per stratum (strict agreement): alpha 100*1/4=25, gamma 10*1/2=5, delta 2*1/2=1;
    # beta contributes nothing. Total 31.
    conc = cell["concentration"]
    assert conc["numerator_top3"] == [
        {"event_type": "alpha_event", "share": round(25 / 31, 4)},
        {"event_type": "gamma_event", "share": round(5 / 31, 4)},
        {"event_type": "delta_event", "share": round(1 / 31, 4)},
    ]
    assert conc["numerator_top3_share"] == pytest.approx(1.0, abs=1e-3)
    # denominator: every alert, so the populations 100, 50, 10, 2 of 162
    assert [r["event_type"] for r in conc["denominator_top3"]] == [
        "alpha_event",
        "beta_event",
        "gamma_event",
    ]
    assert conc["denominator_top3"][0]["share"] == round(100 / 162, 4)
    assert conc["denominator_top3_share"] == pytest.approx(160 / 162, abs=1e-3)

    # without the largest stratum (alpha): (31 - 25) / (162 - 100)
    sens = cell["sensitivity"]["without_largest_stratum"]
    assert sens["removed_event_type"] == "alpha_event"
    assert sens["removed_population_share"] == round(100 / 162, 4)
    assert sens["rate"] == pytest.approx(6 / 62, abs=1e-4)
    assert sens["ci95"][0] <= sens["rate"] <= sens["ci95"][1]
    assert "single largest stratum" in sens["note"] and "alpha_event" in sens["note"]

    # per kind: mapped strata alpha+beta+delta (26/152); the unmapped_other stratum gamma (5/10)
    kinds = cell["by_kind"]
    assert set(kinds) == {"mapped", "unmapped_other"}
    assert kinds["mapped"]["strata"] == 3 and kinds["mapped"]["population"] == 152
    assert kinds["mapped"]["population_estimate"]["rate"] == pytest.approx(26 / 152, abs=1e-4)
    assert kinds["unmapped_other"]["population_estimate"]["rate"] == 0.5
    assert kinds["unmapped_other"]["sample"]["rate"] == 0.5
    lo, hi = kinds["mapped"]["population_estimate"]["ci95"]
    assert lo < 26 / 152 < hi
    # a metric undefined for a kind says so instead of inventing a rate
    wrong = out["mapped_judged_wrong"]["by_kind"]
    assert wrong["unmapped_other"]["population_estimate"]["rate"] is None
    assert wrong["mapped"]["population_estimate"]["rate"] == pytest.approx(101 / 152, abs=1e-4)


def test_sensitivity_with_a_single_stratum_has_nothing_left():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    only_alpha = {k: v for k, v in _labels_a().items() if k.startswith("a")}
    cell = score_labels(header, items, only_alpha, draws=100)["headline"]["strict"][
        "exact_agreement"
    ]
    assert cell["sensitivity"]["without_largest_stratum"]["rate"] is None
    assert cell["sensitivity"]["without_largest_stratum"]["ci95"] is None


def test_worst_disagreements_are_ranked_parent_level_first():
    from honeypot_mcp.tools.mapping_audit import score_labels

    header, items = _key()
    out = score_labels(header, items, _labels_a(), draws=100)
    worst = out["worst_disagreements"]
    parent_wrong = [w for w in worst if not w["agrees_at_parent_level"]]
    assert [(w["event_type"], w["labelled"]) for w in parent_wrong] == [
        ("alpha_event", []),  # 25 alerts each: alpha before beta by name
        ("beta_event", ["T1059.004", "T1105"]),
        ("gamma_event", ["T1046"]),
        ("delta_event", ["T1485"]),
    ]
    assert worst[: len(parent_wrong)] == parent_wrong  # strict-only differences come after
    assert parent_wrong[0]["estimated_alerts"] == 25 and parent_wrong[0]["mapped"] == ["T1110.001"]
    assert worst[-1]["agrees_at_parent_level"] is True


def test_inter_annotator_hand_computed():
    from honeypot_mcp.tools.mapping_audit import inter_annotator

    _, items = _key()
    out = inter_annotator(items, _labels_a(), _labels_b())
    assert out["items"] == 10
    # parent: labellers differ on a4, b1, c1 -> 7/10 identical; jaccard (7 + 0.5)/10
    assert out["parent"]["labellers_give_identical_sets"] == 0.7
    assert out["parent"]["mean_jaccard"] == 0.75
    # strict: identical on a1, a3, b2, c2, d1, d2; jaccard (1+0+1+0+.5+1+0+1+1+1)/10
    assert out["strict"]["labellers_give_identical_sets"] == 0.6
    assert out["strict"]["mean_jaccard"] == 0.65
    # parent-level "agrees with the mapping": A has 6 of 10, B 9 of 10, same answer on 7 -> pe .58
    assert out["parent"]["kappa_agrees_with_the_mapping"] == pytest.approx(
        (0.7 - 0.58) / 0.42, abs=1e-3
    )
    assert out["disagreeing_event_types"][0]["items"] >= 1


# ── sampling ──────────────────────────────────────────────────────────────────────────────────────


async def test_seeded_sample_is_reproducible_and_a_new_seed_differs():
    await _seed()
    one = await _sample(seed=11)
    two = await _sample(seed=11)
    other = await _sample(seed=12)
    for r in (one, two, other):
        assert "error" not in r, r
    keys = [
        {i["item_id"]: i["alert_id"] for i in _items(r["key_file"]["name"])}
        for r in (one, two, other)
    ]
    assert keys[0] == keys[1]
    assert set(keys[0].values()) != set(keys[2].values())
    # the blind file is identical apart from nothing time-dependent
    assert _items(one["blind_file"]["name"]) == _items(two["blind_file"]["name"])
    assert one["seed"] == 11 and one["blind_file"]["name"] != two["blind_file"]["name"]


async def test_design_covers_every_type_and_reports_the_population_per_stratum():
    await _seed()
    result = await _sample(sample_size=30, per_type_min=2, seed=3)
    assert result["sampled"] == 30 and result["population_total"] == TOTAL
    rows = {r["event_type"]: r for r in result["strata"]}
    assert set(rows) == set(SEED_COUNTS)
    assert all(rows[et]["population"] == n for et, n in SEED_COUNTS.items())
    assert all(r["sampled"] >= 2 for r in rows.values())  # the floor, including the rare type
    assert rows["mongodb_ransom_note"]["sampled"] == 2
    assert rows["sip_extension_probe"]["sampled"] > rows["ssh_login_success"]["sampled"]
    assert (rows["ssh_login_failed"]["kind"], rows["telnet_session_connect"]["kind"]) == (
        "mapped",
        "unmapped_bookkeeping",
    )
    assert rows["ssh_client_version"]["kind"] == "unmapped_other"
    kinds = result["design"]["strata_by_kind"]
    assert kinds["mapped"]["population"] == TOTAL - 30 - 10  # all but the two unmapped types
    assert sum(k["sampled"] for k in kinds.values()) == 30
    assert "proportional" in result["design"]["allocation"]


async def test_a_budget_below_the_floor_is_refused_not_trimmed():
    await _seed()
    result = await _sample(sample_size=5, per_type_min=1)
    assert "cannot cover" in result["error"] and result["strata"] == len(SEED_COUNTS)
    assert not _reports().exists() or not list(_reports().glob("mapping-audit-*"))


async def test_blind_file_carries_no_mapping_information():
    from honeypot_mcp.intel.mitre import TACTIC_IDS

    await _seed()
    result = await _sample(sample_size=40, seed=5)
    text = (_reports() / result["blind_file"]["name"]).read_text()
    assert not re.search(r"T\d{4}", text)
    assert not re.search(r"TA\d{4}", text)
    for tactic in TACTIC_IDS:
        assert tactic.lower() not in text.lower()
    records = _lines(result["blind_file"]["name"])
    assert records[0]["record"] == "readme" and "item_id" in " ".join(records[0]["instructions"])
    items = records[1:]
    assert len(items) == result["sampled"] == records[0]["items"]
    for item in items:
        assert set(item) == {"record", "item_id", "event_type", "protocol", "severity", "payload"}
        assert item["item_id"].startswith("mi-")
        assert item["protocol"] in {"ssh", "telnet", "mongodb", "sip"}
    # nothing says which strata are mapped: item order is shuffled, not grouped by type
    types = [i["event_type"] for i in items]
    assert types != sorted(types)
    # the key is a different file with the mapping
    assert "T1110.001" in (_reports() / result["key_file"]["name"]).read_text()


async def test_blind_payloads_are_masked_printable_and_stripped(monkeypatch):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType("credential"),
                label="bait",
                token_value="bait-value",
                status=HoneytokenStatus("active"),
                token_meta={
                    "service": "ssh",
                    "credentials": [
                        {"username": "deploy_ab12", "password": PLANTED_PASSWORD, "service": "ssh"}
                    ],
                },
            )
        )
    await _seed(
        {"ssh_command_input": 6},
        payloads={
            "ssh_command_input": {
                "command": f"echo {PLANTED_PASSWORD} \x1b[31m end",
                "password": PLANTED_PASSWORD,
                "enrichment": {"geoip": {"country": "ZZ"}, "virustotal": {"malicious_votes": 9}},
                "src_ip": "192.0.2.9",
                "headers": {"X": "y"},
                "mitre": "T9999",
                "long": "x" * 400,
            }
        },
    )
    result = await _sample(sample_size=6, seed=1)
    text = (_reports() / result["blind_file"]["name"]).read_text()
    assert PLANTED_PASSWORD not in text and "[masked: planted honeytoken" in text
    assert "\\u001b" in text or "\\x1b" in text
    assert "\x1b" not in text
    for forbidden in ("ZZ", "192.0.2.9", "malicious_votes", "T9999", "use alerts_get"):
        assert forbidden not in text
    payload = _items(result["blind_file"]["name"])[0]["payload"]
    assert set(payload) <= {"command", "password", "long"}
    assert "truncated" in payload["long"]


async def test_key_maps_every_item_back_with_weights():
    await _seed()
    result = await _sample(sample_size=30, seed=9)
    header = _lines(result["key_file"]["name"])[0]
    assert header["record"] == "key_header" and header["seed"] == 9
    assert header["blind_file"] == result["blind_file"]["name"]
    blind = {i["item_id"]: i for i in _items(result["blind_file"]["name"])}
    key = {i["item_id"]: i for i in _items(result["key_file"]["name"])}
    assert set(blind) == set(key)
    for item_id, row in key.items():
        assert row["event_type"] == blind[item_id]["event_type"]
        assert row["stratum_population"] == SEED_COUNTS[row["event_type"]]
        assert row["weight"] == pytest.approx(
            row["stratum_population"] / row["stratum_sampled"], abs=1e-5
        )
    by_type = {r["event_type"]: r for r in key.values()}
    assert by_type["ssh_login_failed"]["mapped_techniques"] == ["T1110.001"]
    assert by_type["ssh_login_failed"]["mapped_tactics"] == ["Credential Access"]
    assert set(by_type["ssh_login_success"]["mapped_techniques"]) == {"T1110.001", "T1078"}
    assert by_type["telnet_session_connect"]["mapped_techniques"] == []
    assert by_type["telnet_session_connect"]["kind"] == "unmapped_bookkeeping"
    # weights re-add to the population of the strata that were sampled
    assert sum(r["weight"] for r in key.values()) == pytest.approx(TOTAL, abs=1e-3)


async def test_files_are_owner_only_and_never_overwrite():
    await _seed()
    result = await _sample(seed=1)
    for name in (result["blind_file"]["name"], result["key_file"]["name"]):
        assert (_reports() / name).stat().st_mode & 0o777 == 0o600


async def test_dense_sampler_draws_uniform_distinct_ids_of_the_right_type(monkeypatch):
    from honeypot_mcp.tools import mapping_audit as ma

    await _seed()
    monkeypatch.setattr(ma, "_DENSE_MIN_ROWS", 1)
    monkeypatch.setattr(ma, "_DENSE_MIN_DENSITY", 0.0)
    one = await _sample(sample_size=30, seed=2)
    two = await _sample(sample_size=30, seed=2)
    assert one["sampled"] == 30
    ids = [i["alert_id"] for i in _items(one["key_file"]["name"])]
    assert len(ids) == len(set(ids))
    assert ids == [i["alert_id"] for i in _items(two["key_file"]["name"])]
    by_type = {r["event_type"]: r["sampled"] for r in one["strata"]}
    assert all(by_type[et] >= 1 for et in SEED_COUNTS)


async def test_pruned_alerts_are_reported_as_a_shortfall_not_hidden():
    from sqlalchemy import delete

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    # an earlier hour, so the counts are in the rollups (which survive pruning), not the raw rows
    await _seed(when=datetime.now(UTC) - timedelta(hours=5))
    async with get_session() as session:
        await session.execute(delete(Alert).where(Alert.event_type == "ssh_client_version"))
    result = await _sample(sample_size=30, seed=4)
    assert {s["event_type"] for s in result["design"]["shortfalls"]} == {"ssh_client_version"}


async def test_window_and_analysis_mode_anchor(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools import _window

    await _seed(when=datetime.now(UTC) - timedelta(days=30))
    live = await _sample(since_hours=1)
    assert "No alerts in the window" in live["error"]

    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    _window.reset_for_tests()
    anchored = await _sample(since_hours=1, seed=2)
    assert "error" not in anchored and anchored["population_total"] == TOTAL
    assert anchored["window"]["window_anchor"] == "newest alert"

    assert "since_hours" in (await _sample(since_hours=0))["error"]
    assert "sample_size" in (await _sample(sample_size=0))["error"]


# ── score through the tool ────────────────────────────────────────────────────────────────────────


def _write_labels(name: str, rows: list[dict[str, Any]]) -> None:
    root = _reports()
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n")


async def _sampled_key():
    await _seed()
    result = await _sample(sample_size=40, seed=21)
    key = {i["item_id"]: i for i in _items(result["key_file"]["name"])}
    return result["key_file"]["name"], key


async def test_score_end_to_end_with_perfect_labels_and_with_a_corrupted_one():
    key_name, key = await _sampled_key()
    perfect = [
        {"item_id": i, "techniques": r["mapped_techniques"], "label_confidence": "high"}
        for i, r in key.items()
    ]
    _write_labels("a.jsonl", perfect)
    out = await _score(labels_file="a.jsonl", key_file=key_name, interval_draws=200)
    assert "error" not in out, out
    head = out["labeller_a"]["headline"]
    assert head["strict"]["exact_agreement"]["population"]["rate"] == 1.0
    assert head["strict"]["mapped_judged_wrong"]["sample"]["rate"] == 0.0
    assert head["parent"]["labelled_left_unmapped"]["sample"]["numerator"] == 0
    assert out["labeller_a"]["worst_disagreements"] == []
    assert out["artifact"]["path"].endswith(".json")
    assert "untrusted_content" in out

    # flip every SSH command item to "no technique applies"
    broken = [
        dict(r, techniques=[]) if key[r["item_id"]]["event_type"] == "ssh_command_input" else r
        for r in perfect
    ]
    wrong_items = sum(1 for r in key.values() if r["event_type"] == "ssh_command_input")
    _write_labels("b.jsonl", broken)
    second = await _score(
        labels_file="b.jsonl", key_file=key_name, second_labels_file="a.jsonl", interval_draws=200
    )
    a = second["labeller_a"]["headline"]["strict"]["mapped_judged_wrong"]["sample"]
    assert a["numerator"] == wrong_items
    top = second["labeller_a"]["worst_disagreements"][0]
    assert (
        top["event_type"] == "ssh_command_input"
        and top["labelled"] == []
        and top["mapped"] == ["T1059.004"]
    )
    assert second["inter_annotator"]["items"] == len(key)
    assert second["inter_annotator"]["strict"]["labellers_give_identical_sets"] < 1.0
    assert "labeller_b" in second


async def test_score_rejects_bad_labels_with_every_problem_listed():
    key_name, key = await _sampled_key()
    some = next(iter(key))
    _write_labels(
        "bad.jsonl",
        [
            {"item_id": some, "techniques": ["T1110.001"]},
            {"item_id": some, "techniques": []},  # twice
            {"item_id": "mi-unknown", "techniques": []},
            {"item_id": list(key)[1], "techniques": ["not-an-id"]},
            {"item_id": list(key)[2], "techniques": [], "tactic": "made up"},
            {"item_id": list(key)[3]},
        ],
    )
    out = await _score(labels_file="bad.jsonl", key_file=key_name)
    assert "problem" in out["error"]
    text = " ".join(out["problems"])
    for needle in (
        "labelled twice",
        "not in the key",
        "not a technique id",
        "unknown tactic",
        "techniques must be",
    ):
        assert needle in text


async def test_score_needs_both_files_and_valid_options():
    assert "needs a labels file and a key file" in (await _score())["error"]
    key_name, _ = await _sampled_key()
    _write_labels("e.jsonl", [])
    assert "no labels" in (await _score(labels_file="e.jsonl", key_file=key_name))["error"]
    assert "top" in (await _score(labels_file="e.jsonl", key_file=key_name, top=0))["error"]
    assert (
        "draws must be"
        in (await _score(labels_file="e.jsonl", key_file=key_name, interval_draws=5))["error"]
    )
    from honeypot_mcp.tools.mapping_audit import mapping_audit

    assert "without labels_file" in (await mapping_audit(second_labels_file="e.jsonl"))["error"]
    assert "since_hours" in (await mapping_audit(since_hours="soon"))["error"]  # type: ignore[arg-type]


async def test_score_reads_files_only_from_the_reports_directory(tmp_path, monkeypatch):
    key_name, key = await _sampled_key()
    outside = tmp_path / "outside.jsonl"
    outside.write_text(json.dumps({"item_id": next(iter(key)), "techniques": []}) + "\n")
    root = _reports()

    assert ".." in (await _score(labels_file="../outside.jsonl", key_file=key_name))["error"]
    assert (
        "outside the reports"
        in (await _score(labels_file=str(outside), key_file=key_name))["error"]
    )
    assert "not found" in (await _score(labels_file="missing.jsonl", key_file=key_name))["error"]
    assert "required" in (await _score(labels_file=" ", key_file=key_name))["error"]

    # a symlink inside reports_dir is refused even when it points at a readable file
    link = root / "link.jsonl"
    os.symlink(outside, link)
    assert "symlink" in (await _score(labels_file="link.jsonl", key_file=key_name))["error"]
    real = root / "real.jsonl"
    real.write_text(outside.read_text())
    inner = root / "inner-link.jsonl"
    os.symlink(real, inner)
    assert "symlink" in (await _score(labels_file="inner-link.jsonl", key_file=key_name))["error"]
    os.mkdir(root / "dir.jsonl")
    assert "error" in await _score(labels_file="dir.jsonl", key_file=key_name)

    # a file over the size cap
    from honeypot_mcp.tools import mapping_audit as ma

    monkeypatch.setattr(ma, "_MAX_FILE_BYTES", 10)
    assert "limit" in (await _score(labels_file="real.jsonl", key_file=key_name))["error"]


async def test_the_tool_samples_with_no_arguments_and_scores_by_name_alone():
    from honeypot_mcp.tools.mapping_audit import mapping_audit

    await _seed()
    drawn = await mapping_audit()
    assert "error" not in drawn, drawn
    assert drawn["sampled"] >= len(SEED_COUNTS)
    key = {i["item_id"]: i for i in _items(drawn["key_file"]["name"])}
    _write_labels(
        "mine.jsonl", [{"item_id": i, "techniques": r["mapped_techniques"]} for i, r in key.items()]
    )
    out = await mapping_audit(labels_file="mine.jsonl")  # the matching key is found by itself
    assert "error" not in out, out
    assert out["key_file_used"] == drawn["key_file"]["name"]
    assert out["labeller_a"]["headline"]["strict"]["exact_agreement"]["population"]["rate"] == 1.0
    missing = await mapping_audit(labels_file="missing.jsonl")
    assert "not found" in missing["error"]


async def test_the_tool_is_operator_tier_and_registered():
    from honeypot_mcp import rbac
    from honeypot_mcp.server import mcp

    assert "mapping_audit" in rbac.OPERATOR_TOOLS
    assert "mapping_audit" not in rbac.ADMIN_TOOLS and "mapping_audit" not in rbac.VIEWER_TOOLS
    tool = {t.name: t for t in await mcp.list_tools()}["mapping_audit"]
    assert tool.auth is not None
