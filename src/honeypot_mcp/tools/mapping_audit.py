"""`mapping_audit`: measure the ATT&CK mapping against independent human labels.

`intel/mitre.py` maps an alert to techniques by its event type (and regexes over payload text for
`map_ttps`). Nobody had checked those mappings against anyone's judgement, so every ATT&CK figure the
server prints rested on the author's own reading of each event type. This tool turns that into a
measurement, in two steps that happen days apart and are done by different people:

`action="sample"` draws a seeded, stratified sample of alerts and writes two files into `reports_dir`:

* a **blind** file (JSON Lines): a README record explaining the task and the label format, then one
  record per item carrying only what an independent analyst needs: an opaque item id, the sensor's own
  event type name, the protocol inferred from its prefix, the severity and a clipped, printable digest
  of the captured payload (planted honeytoken secrets masked, enrichment removed). No technique, no
  tactic, no stratum, nothing from the project's mapping;
* a **key** file (JSON Lines): a header record with the design and the stratum table (event type,
  population, sample size), then item id -> the project's mapped techniques and tactics, event type,
  stratum and weight.

`action="score"` takes one (or two) labels files and the key file and reports agreement.

Design of the sample
--------------------
* **Strata are event types**: every distinct event type seen in the window (population counts come from
  `alert_rollups`, so they are exact and fast on millions of rows). The project's mapping is a function of
  the event type, so a stratum has one mapping, and the strata fall in three kinds: `mapped` (maps to at
  least one technique), `unmapped_bookkeeping` (maps to nothing, and is connection/session bookkeeping by
  name) and `unmapped_other` (maps to nothing, is not bookkeeping: the candidates for a missed technique).
* **Allocation**: `min(per_type_min, N_h)` per stratum so every type, rare ones included, is
  represented; then the rest of the budget is spread **in proportion to the stratum population**
  (capped at the population, overflow redistributed). If the budget cannot even cover the minimum the
  call is refused rather than silently dropping rare types.
* **Within a stratum**: uniform without replacement, seeded per stratum (`Random("<seed>:<type>")`), so
  the same seed on the same data gives the same sample and a different seed a different one. Small types
  list their ids and sample the list; dense types (millions of rows) draw random ids and keep the ones
  that match, which is exactly uniform and never scans the table.
* **Weights**: every item carries `N_h / n_h`; the estimates in `score` re-weight to the whole window.

How scoring is estimated
------------------------
Per item the project's technique set M and the labeller's set L are compared strictly (identical ids) and
at the parent level (`T1110.001` and `T1110.003` both count as `T1110`; a label of the parent against a
mapped sub-technique, or the reverse, therefore agrees). Population figures are ratios of stratum-weighted
totals; their 95% intervals come from a **stratified Jeffreys (Dirichlet) Monte Carlo**, run per
metric: each draw re-samples every stratum's mix of item outcomes from Dirichlet(count + 0.5) over all
the outcomes the stratum could have had (so a stratum of one item, or whose items all agree, is not
treated as certain: resampling only the observed outcomes gives such a stratum zero variance); a
stratum in which every alert was labelled stays fixed; the interval is widened to contain the point
estimate. Each headline metric also reports `by_kind`, `concentration` (top 3 strata by share of the
weighted numerator and denominator) and `sensitivity` (the estimate with the single largest stratum
removed). Per-stratum Wilson score intervals are reported for the agreement share.
Inter-annotator agreement is Cohen's kappa on "this labeller agrees with the mapping" and on "any
technique applies", plus per-item Jaccard.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import re
import stat
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from sqlalchemy import func, select

from honeypot_mcp.config import get_settings
from honeypot_mcp.deception.capabilities import BY_TYPE
from honeypot_mcp.intel.mitre import TACTIC_IDS, map_to_attack
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import rollups
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._format import (
    UNTRUSTED_CONTENT_NOTE,
    digest_payload,
    mark_untrusted,
    write_artifact,
)
from honeypot_mcp.tools._planted import Planted, load_planted
from honeypot_mcp.tools._scan import _first_id_since
from honeypot_mcp.tools._window import window_anchor, window_end

Action = Literal["sample", "score"]

SCHEMA_VERSION = 1
_DEFAULT_SAMPLE = 200
_MAX_SAMPLE = 5_000
_MAX_WINDOW_HOURS = 24 * 365 * 10
_MAX_FILE_BYTES = 32 * 1024 * 1024
_DEFAULT_DRAWS = 2_000
_MAX_DRAWS = 20_000
_MAX_TOP = 200

# Event types that only say a peer connected, spoke the opening handshake or left. Matched by name; the
# stratum list (with each type's kind) is returned and written to the key file, so the call is visible.
BOOKKEEPING_RE = re.compile(
    r"^(flood_summary|honeypot_[a-z_]+)$|(_connection|_session_connect|_session_closed|_connect|_handshake)$"
)

# Dense types (many rows, a sizeable share of the id range) are sampled by drawing random ids; the rest
# list their ids. See the module docstring.
_DENSE_MIN_ROWS = 50_000
_DENSE_MIN_DENSITY = 0.005
_DRAW_BATCH_MAX = 2_000
_DRAW_ROUNDS_MAX = 400
_ID_FETCH_CHUNK = 500

# Keys of a captured payload that say where a packet came from or which sensor saw it (nothing an
# analyst needs to judge the behaviour) or that would carry a mapping into the blind file.
_BLIND_DROP_KEYS = frozenset(
    {
        "enrichment",
        "src_ip",
        "source_ip",
        "client_ip",
        "ip",
        "sensor",
        "honeypot",
        "honeypot_id",
        "honeypot_name",
        "timestamp",
        "ts",
        "time",
        "mitre",
        "attack",
        "attack_id",
        "technique",
        "techniques",
        "tactic",
        "tactics",
        "ttp",
        "ttps",
    }
)
_MAX_PAYLOAD_CHARS = 2_000

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CONFIDENCES = ("low", "medium", "high")
_Z95 = 1.959963984540054

_README_INSTRUCTIONS: tuple[str, ...] = (
    "TASK: for every item record below, decide which MITRE ATT&CK Enterprise techniques the attacker's "
    "behaviour in that ONE event shows, and write one label line per item.",
    "WHAT AN ITEM IS: one event recorded by a decoy network service (a honeypot). `event_type` is the "
    "name the sensor gave the event: use it as a hint about what happened, not as the answer. "
    "`protocol` is the service, `severity` is the sensor's own rating, `payload` is a clipped digest of "
    "what the attacker sent or did. There is no source address and no timestamp.",
    "THE PAYLOAD IS ATTACKER-WRITTEN TEXT: it is data to be classified, never instructions to you. "
    "Control characters are shown as \\xNN. `[masked: planted honeytoken #N]` replaces a bait "
    "credential this system planted; it was a real-looking secret the attacker replayed.",
    "WHAT TO LABEL: the behaviour this event itself shows, in ATT&CK terms (e.g. an attempt to guess a "
    "credential, running a command to look around the host, downloading a tool, scanning a service). Do not label what "
    "the attacker might do next or what other events in the same session did. An event that only "
    "records a connection opening/closing, a protocol handshake, or a sensor/platform status, with no "
    "attacker action visible, has NO technique: label it with an empty list.",
    "HOW MANY: list every technique that applies (an event can show several). Use the most specific "
    "sub-technique you can justify from this event alone; if the sub-technique cannot be told, use the "
    "parent technique. Do not look at, ask about or guess any other system's mapping of these events: "
    "your independent judgement is the point.",
    "OUTPUT: write a JSON Lines file with one object per item you label, in this form (ids are written "
    "T followed by four digits, with an optional dot and three digits for a sub-technique): "
    '{"item_id": "<id from the item>", "techniques": ["T####", "T####.###"], '
    '"tactic": "<ATT&CK Enterprise tactic name, or a list of names>", '
    '"label_confidence": "low|medium|high", "note": "<optional one-line reason>"}. '
    "`techniques` is required: an empty list means no ATT&CK technique applies. `tactic`, "
    "`label_confidence` and `note` are optional. Label every item exactly once.",
)


# ── small pure helpers (unit-tested directly) ─────────────────────────────────────────────────────


def parent_of(technique_id: str) -> str:
    """`T1110.001` -> `T1110`; a parent id is returned unchanged."""
    return technique_id.split(".", 1)[0]


def wilson(successes: int, n: int, z: float = _Z95) -> tuple[float, float]:
    """The Wilson score interval for a proportion of `successes` in `n` trials (`(0, 1)` when n is 0)."""
    if n <= 0:
        return 0.0, 1.0
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return max(0.0, centre - half), min(1.0, centre + half)


def cohen_kappa(a: Sequence[bool], b: Sequence[bool]) -> float | None:
    """Cohen's kappa for two binary raters; None when it is undefined (no items, or no variation)."""
    n = len(a)
    if n == 0 or n != len(b):
        return None
    observed = sum(1 for x, y in zip(a, b, strict=True) if x == y) / n
    pa, pb = sum(a) / n, sum(b) / n
    expected = pa * pb + (1 - pa) * (1 - pb)
    if expected >= 1.0:
        return None
    return (observed - expected) / (1 - expected)


def jaccard(a: frozenset[str] | set[str], b: frozenset[str] | set[str]) -> float:
    """|A and B| / |A or B|; two empty sets agree completely (1.0)."""
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def _ratio(num: float, den: float) -> float | None:
    return round(num / den, 4) if den else None


def protocol_of(event_type: str) -> str:
    """The service an event type belongs to, from its prefix (`docker_api_exec` -> `docker_api`)."""
    via = "honeytoken_triggered_credential_via_"
    if event_type.startswith(via):
        rest = event_type[len(via) :]
        return _protocol_prefix(rest) or "honeytoken"
    if event_type.startswith("honeytoken_"):
        return "honeytoken"
    if event_type == "flood_summary" or event_type.startswith("honeypot_"):
        return "platform"
    return _protocol_prefix(event_type) or event_type.split("_", 1)[0]


def _protocol_prefix(event_type: str) -> str | None:
    best = None
    for name in BY_TYPE:
        key = str(name)
        if (event_type == key or event_type.startswith(key + "_")) and (
            best is None or len(key) > len(best)
        ):
            best = key
    return best


def allocate(populations: dict[str, int], size: int, per_type_min: int) -> dict[str, int]:
    """Sample size per stratum: `min(per_type_min, N)` each, then the rest proportional to N.

    The top-up is capped at each stratum's population and the overflow is redistributed, so the total is
    exactly `size` whenever the populations hold that many alerts. Deterministic (ties by name).
    """
    alloc = {h: min(per_type_min, n) for h, n in populations.items() if n > 0}
    remaining = size - sum(alloc.values())
    if remaining < 0:
        raise ValueError(
            f"sample_size {size} cannot cover per_type_min={per_type_min} for {len(alloc)} strata"
        )
    capacity = {h: populations[h] - alloc[h] for h in alloc}
    while remaining > 0:
        active = sorted(h for h, c in capacity.items() if c > 0)
        if not active:
            break
        total = sum(populations[h] for h in active)
        shares = {h: remaining * populations[h] / total for h in active}
        given = {h: min(int(shares[h]), capacity[h]) for h in active}
        if sum(given.values()) == 0:
            order = sorted(
                active, key=lambda h: (-(shares[h] - int(shares[h])), -populations[h], h)
            )
            given = {h: 1 for h in order[:remaining]}
        for h, g in given.items():
            alloc[h] += g
            capacity[h] -= g
        remaining -= sum(given.values())
    return alloc


def _printable(value: Any, planted: Planted) -> Any:
    """Recursively make strings printable (control characters escaped) and mask planted secrets."""
    if isinstance(value, str):
        masked = planted.mask(value) or ""
        masked = planted.redact(masked)
        return "".join(
            ch
            if ch.isprintable()
            else (
                f"\\x{ord(ch):02x}"
                if ord(ch) < 0x100
                else f"\\u{ord(ch):04x}"
                if ord(ch) < 0x10000
                else f"\\U{ord(ch):08x}"
            )
            for ch in masked
        )
    if isinstance(value, list):
        return [_printable(v, planted) for v in value]
    if isinstance(value, dict):
        return {str(k): _printable(v, planted) for k, v in value.items()}
    return value


_CLIP_MARK_RE = re.compile(r"… \[\+(\d+) chars, use alerts_get\]")
_LIST_MARK_RE = re.compile(r"… \[\+(\d+) more\]")


def _unclip(value: Any) -> Any:
    """Re-word the digest's truncation markers: the labeller has no `alerts_get`."""
    if isinstance(value, str):
        value = _CLIP_MARK_RE.sub(r"… [truncated: \1 more characters]", value)
        return _LIST_MARK_RE.sub(r"… [truncated: \1 more entries]", value)
    if isinstance(value, list):
        return [_unclip(v) for v in value]
    return value


def blind_payload(payload: Any, planted: Planted) -> dict[str, Any]:
    """The payload as an independent labeller sees it: digested, printable, masked, size-capped."""
    source = (
        {k: v for k, v in payload.items() if str(k).lower() not in _BLIND_DROP_KEYS}
        if isinstance(payload, dict)
        else {}
    )
    digest = {k: _unclip(v) for k, v in digest_payload(source).items()}
    digest = {k: _printable(v, planted) for k, v in digest.items()}
    omitted = 0
    while digest and len(json.dumps(digest, ensure_ascii=True)) > _MAX_PAYLOAD_CHARS:
        digest.popitem()
        omitted += 1
    if omitted:
        digest["_omitted_fields"] = omitted
    return digest


def _dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":"))


def _kind_of(event_type: str, mapped: bool) -> str:
    if mapped:
        return "mapped"
    return "unmapped_bookkeeping" if BOOKKEEPING_RE.search(event_type) else "unmapped_other"


# ── sampling ──────────────────────────────────────────────────────────────────────────────────────


async def _window(
    since_hours: float | None,
) -> tuple[datetime | None, datetime, dict[str, Any], str | None]:
    """`(since, end, description, error)`; the end is `window_end()` (the newest alert in analysis mode)."""
    end = await window_end()
    anchor = await window_anchor() or {}
    if since_hours is None:
        return None, end, {"since": None, "until": end.isoformat(), "hours": None, **anchor}, None
    try:
        hours = float(since_hours)
    except (TypeError, ValueError):
        return None, end, {}, "since_hours must be a number of hours."
    if not 0 < hours <= _MAX_WINDOW_HOURS:
        return None, end, {}, f"since_hours must be greater than 0 and at most {_MAX_WINDOW_HOURS}."
    since = end - timedelta(hours=hours)
    return (
        since,
        end,
        {"since": since.isoformat(), "until": end.isoformat(), "hours": hours, **anchor},
        None,
    )


async def _draw_ids(
    event_type: str,
    n: int,
    population: int,
    low_id: int,
    high_id: int,
    since: datetime | None,
    rng: random.Random,
) -> list[int]:
    """`n` alert ids of `event_type`, uniform without replacement, in a reproducible order."""
    conds = [Alert.event_type == event_type, Alert.id >= low_id]
    if since is not None:
        conds.append(Alert.timestamp >= since)
    span = high_id - low_id + 1
    dense = population >= _DENSE_MIN_ROWS and population / span >= _DENSE_MIN_DENSITY
    if not dense:
        async with get_session() as session:
            ids = [
                int(i)
                for i in (
                    await session.execute(select(Alert.id).where(*conds).order_by(Alert.id))
                ).scalars()
            ]
        return rng.sample(ids, min(n, len(ids)))

    density = max(population / span, 1e-6)
    chosen: list[int] = []
    seen: set[int] = set()
    for _ in range(_DRAW_ROUNDS_MAX):
        if len(chosen) >= n:
            break
        batch = min(_DRAW_BATCH_MAX, max(100, int((n - len(chosen)) / density * 1.5) + 1))
        draws = [rng.randint(low_id, high_id) for _ in range(batch)]
        probe = list(dict.fromkeys(d for d in draws if d not in seen))
        hits: set[int] = set()
        async with get_session() as session:
            for start in range(0, len(probe), _ID_FETCH_CHUNK):
                part = probe[start : start + _ID_FETCH_CHUNK]
                rows = await session.execute(select(Alert.id).where(Alert.id.in_(part), *conds))
                hits.update(int(i) for i in rows.scalars())
        for d in draws:
            if d in hits and d not in seen:
                seen.add(d)
                chosen.append(d)
                if len(chosen) >= n:
                    break
    return chosen


async def _fetch_alerts(ids: list[int]) -> dict[int, tuple[str, str, Any]]:
    out: dict[int, tuple[str, str, Any]] = {}
    async with get_session() as session:
        for start in range(0, len(ids), _ID_FETCH_CHUNK):
            part = ids[start : start + _ID_FETCH_CHUNK]
            rows = await session.execute(
                select(Alert.id, Alert.event_type, Alert.severity, Alert.payload).where(
                    Alert.id.in_(part)
                )
            )
            for alert_id, event_type, severity, payload in rows.all():
                out[int(alert_id)] = (
                    str(event_type),
                    str(getattr(severity, "value", severity)),
                    payload,
                )
    return out


def _readme_record(item_count: int) -> dict[str, Any]:
    return {
        "record": "readme",
        "title": "ATT&CK labelling task (blind)",
        "schema": SCHEMA_VERSION,
        "items": item_count,
        "instructions": list(_README_INSTRUCTIONS),
        "untrusted_content": UNTRUSTED_CONTENT_NOTE,
    }


async def _sample(
    since_hours: float | None, sample_size: int, seed: int | None, per_type_min: int
) -> dict[str, Any]:
    started = time.monotonic()
    if (
        isinstance(sample_size, bool)
        or not isinstance(sample_size, int)
        or not 1 <= sample_size <= _MAX_SAMPLE
    ):
        return {"error": f"sample_size must be an integer from 1 to {_MAX_SAMPLE}."}
    if isinstance(per_type_min, bool) or not isinstance(per_type_min, int) or per_type_min < 0:
        return {"error": "per_type_min must be an integer of at least 0."}
    if seed is not None and (isinstance(seed, bool) or not isinstance(seed, int)):
        return {"error": "seed must be an integer."}
    if seed is None:
        seed = random.SystemRandom().randrange(1, 2**31)

    since, end, window, error = await _window(since_hours)
    if error:
        return {"error": error}

    async with get_session() as session:
        counts = await rollups.event_type_counts(
            session, since, now=end if since is not None else None
        )
    populations = {et: n for et, n in counts.items() if n > 0}
    if not populations:
        return {"error": "No alerts in the window; nothing to sample.", "window": window}

    mapping: dict[str, list[dict[str, Any]]] = {}
    for event_type in sorted(populations):
        mapping[event_type] = await map_to_attack([event_type])
    kinds = {et: _kind_of(et, bool(mapping[et])) for et in populations}

    try:
        alloc = allocate(populations, sample_size, per_type_min)
    except ValueError as exc:
        return {
            "error": f"{exc}: raise sample_size to at least {len(populations) * per_type_min}, "
            "or lower per_type_min. Rare event types are never dropped silently.",
            "strata": len(populations),
        }

    low = await _first_id_since(since) if since is not None else None
    async with get_session() as session:
        first_id = (await session.execute(select(func.min(Alert.id)))).scalar()
        high_id = (await session.execute(select(func.max(Alert.id)))).scalar()
    if first_id is None or high_id is None:
        return {"error": "The alert table is empty; nothing to sample.", "window": window}
    low_id = max(int(first_id), int(low)) if low is not None else int(first_id)

    drawn: dict[str, list[int]] = {}
    for event_type in sorted(alloc):
        n = alloc[event_type]
        if n == 0:
            drawn[event_type] = []
            continue
        rng = random.Random(f"{seed}:{event_type}")
        drawn[event_type] = await _draw_ids(
            event_type, n, populations[event_type], low_id, int(high_id), since, rng
        )

    all_ids = [i for et in sorted(drawn) for i in drawn[et]]
    fetched = await _fetch_alerts(all_ids)
    planted = await load_planted()

    blind: list[dict[str, Any]] = []
    key: list[dict[str, Any]] = []
    used: set[str] = set()
    for event_type in sorted(drawn):
        stratum_ids = [i for i in drawn[event_type] if i in fetched]
        n_h = len(stratum_ids)
        for alert_id in stratum_ids:
            _, severity, payload = fetched[alert_id]
            width = 12
            item_id = "mi-" + hashlib.sha256(f"{seed}:{alert_id}".encode()).hexdigest()[:width]
            while item_id in used:
                width += 2
                item_id = "mi-" + hashlib.sha256(f"{seed}:{alert_id}".encode()).hexdigest()[:width]
            used.add(item_id)
            blind.append(
                {
                    "record": "item",
                    "item_id": item_id,
                    "event_type": event_type,
                    "protocol": protocol_of(event_type),
                    "severity": severity,
                    "payload": blind_payload(payload, planted),
                }
            )
            key.append(
                {
                    "record": "item",
                    "item_id": item_id,
                    "alert_id": alert_id,
                    "event_type": event_type,
                    "stratum": event_type,
                    "kind": kinds[event_type],
                    "stratum_population": populations[event_type],
                    "stratum_sampled": n_h,
                    "weight": round(populations[event_type] / n_h, 6),
                    "mapped_techniques": [t["technique_id"] for t in mapping[event_type]],
                    "mapped_names": {
                        t["technique_id"]: t["technique_name"] for t in mapping[event_type]
                    },
                    "mapped_tactics": sorted({t["tactic"] for t in mapping[event_type]}),
                }
            )

    order = list(range(len(blind)))
    random.Random(f"{seed}:order").shuffle(order)
    blind = [blind[i] for i in order]
    key = [key[i] for i in order]

    sampled_by = Counter(k["stratum"] for k in key)
    total_population = sum(populations.values())
    strata: list[dict[str, Any]] = [
        {
            "event_type": et,
            "kind": kinds[et],
            "protocol": protocol_of(et),
            "population": populations[et],
            "population_share": round(populations[et] / total_population, 6),
            "requested": alloc[et],
            "sampled": sampled_by.get(et, 0),
        }
        for et in sorted(populations, key=lambda e: (-populations[e], e))
    ]
    by_kind: dict[str, dict[str, int]] = {}
    for row in strata:
        cell = by_kind.setdefault(row["kind"], {"strata": 0, "population": 0, "sampled": 0})
        cell["strata"] += 1
        cell["population"] += row["population"]
        cell["sampled"] += row["sampled"]
    shortfalls = [
        {"event_type": r["event_type"], "requested": r["requested"], "sampled": r["sampled"]}
        for r in strata
        if r["sampled"] < r["requested"]
    ]

    design = {
        "method": "stratified random sample; one stratum per event type seen in the window",
        "strata": len(strata),
        "strata_by_kind": by_kind,
        "kinds": {
            "mapped": "event type maps to at least one ATT&CK technique",
            "unmapped_bookkeeping": "maps to nothing and is connection/session/platform bookkeeping by name "
            f"(rule: {BOOKKEEPING_RE.pattern})",
            "unmapped_other": "maps to nothing and is not bookkeeping: where a missed technique would hide",
        },
        "allocation": f"min(per_type_min={per_type_min}, N_h) per stratum, then the rest of the budget "
        "proportional to N_h (capped at N_h, overflow redistributed)",
        "within_stratum": "uniform without replacement; Random('<seed>:<event_type>'), so the same seed "
        "on the same data reproduces the sample",
        "population_counts": "alert_rollups (exact at hour resolution; unaffected by pruning)",
        "weights": "weight = N_h / n_h per item; score re-weights to the whole window with them",
        "shortfalls": shortfalls,
    }

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    blind_text = "\n".join(_dumps(r) for r in [_readme_record(len(blind)), *blind]) + "\n"
    reports = get_settings().reports_dir
    suffix = ""
    for attempt in range(2, 1000):  # two samples in one second must not collide
        if (
            not (reports / f"mapping-audit-blind-{stamp}{suffix}.jsonl").exists()
            and not (reports / f"mapping-audit-key-{stamp}{suffix}.jsonl").exists()
        ):
            break
        suffix = f"-{attempt}"
    blind_name = f"mapping-audit-blind-{stamp}{suffix}.jsonl"
    key_name = f"mapping-audit-key-{stamp}{suffix}.jsonl"
    header = {
        "record": "key_header",
        "schema": SCHEMA_VERSION,
        "created": datetime.now(UTC).isoformat(),
        "seed": seed,
        "requested": sample_size,
        "per_type_min": per_type_min,
        "sampled": len(key),
        "window": window,
        "population_total": total_population,
        "blind_file": blind_name,
        "design": design,
        "strata": strata,
    }
    key_text = "\n".join(_dumps(r) for r in [header, *key]) + "\n"
    blind_artifact = write_artifact(
        blind_text, prefix="mapping-audit-blind", extension="jsonl", output_path=blind_name
    )
    if "error" in blind_artifact:
        return {"error": f"Could not write the blind file: {blind_artifact['error']}"}
    key_artifact = write_artifact(
        key_text, prefix="mapping-audit-key", extension="jsonl", output_path=key_name
    )
    if "error" in key_artifact:
        return {
            "error": f"Could not write the key file: {key_artifact['error']}",
            "blind_file": blind_artifact,
        }

    return mark_untrusted(
        {
            "action": "sample",
            "seed": seed,
            "window": window,
            "requested": sample_size,
            "sampled": len(key),
            "population_total": total_population,
            "blind_file": {"name": blind_name, **blind_artifact},
            "key_file": {"name": key_name, **key_artifact},
            "design": design,
            "strata": strata,
            "seconds": round(time.monotonic() - started, 2),
            "next_step": (
                "Give ONLY the blind file to each labeller (the key holds the project's mapping). "
                "Each writes a JSON Lines labels file into reports_dir; then call "
                f"mapping_audit(action='score', labels_file=..., key_file='{key_name}', "
                "second_labels_file=...)."
            ),
        }
    )


# ── reading files back ────────────────────────────────────────────────────────────────────────────


class _FileError(Exception):
    pass


def _read_report_text(name: str) -> str:
    """Read one file of `reports_dir` by name: no `..`, no symlink in the path, regular file, size cap."""
    if not isinstance(name, str) or not name.strip():
        raise _FileError("a file name from reports_dir is required")
    if "\x00" in name:
        raise _FileError("the file name contains a NUL byte")
    try:
        candidate = Path(name.strip())
        root = get_settings().reports_dir.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise _FileError(f"not a usable path: {exc}") from None
    if ".." in candidate.parts:
        raise _FileError("'..' is not allowed in a file name; pass a name from reports_dir")
    try:
        if candidate.is_absolute():
            if candidate != candidate.resolve():
                raise _FileError("refusing a path that contains a symlink or is not canonical")
            target = candidate
        else:
            target = root
            for part in candidate.parts:
                target = target / part
                if target.is_symlink():
                    raise _FileError("refusing to follow a symlink inside reports_dir")
        target = target.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise _FileError(f"not a usable path: {exc}") from None
    if root not in target.parents:
        raise _FileError("refusing to read outside the reports directory; pass a file name")
    try:
        fd = os.open(
            target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
    except FileNotFoundError:
        raise _FileError(f"{name!r} not found in the reports directory") from None
    except OSError as exc:
        raise _FileError(
            f"cannot open {name!r}: {exc.strerror or exc.__class__.__name__}"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _FileError(f"{name!r} is not a regular file")
        if info.st_size > _MAX_FILE_BYTES:
            raise _FileError(f"{name!r} is over the {_MAX_FILE_BYTES // 1_048_576} MB limit")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            data = fh.read(_MAX_FILE_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(data) > _MAX_FILE_BYTES:
        raise _FileError(f"{name!r} grew past the {_MAX_FILE_BYTES // 1_048_576} MB limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise _FileError(f"{name!r} is not UTF-8 text") from None


def _json_lines(text: str) -> tuple[list[tuple[int, Any]], list[str]]:
    rows: list[tuple[int, Any]] = []
    problems: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rows.append((number, json.loads(line)))
        except ValueError:
            problems.append(f"line {number}: not valid JSON")
    return rows, problems


def parse_key(text: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """`(header, {item_id: item})` from a key file; raises `_FileError`."""
    rows, problems = _json_lines(text)
    if problems:
        raise _FileError("key file: " + "; ".join(problems[:5]))
    headers = [r for _, r in rows if isinstance(r, dict) and r.get("record") == "key_header"]
    if len(headers) != 1:
        raise _FileError("key file: expected exactly one key_header record")
    items: dict[str, dict[str, Any]] = {}
    for _, row in rows:
        if isinstance(row, dict) and row.get("record") == "item":
            if row.get("item_id") in items:
                raise _FileError(f"key file: duplicate item id {row.get('item_id')!r}")
            items[str(row["item_id"])] = row
    if not items:
        raise _FileError("key file: no item records")
    return headers[0], items


_TACTIC_BY_NORMAL = {re.sub(r"[\s_-]+", " ", t.casefold()): t for t in TACTIC_IDS}
_TACTIC_BY_ID = {v: k for k, v in TACTIC_IDS.items()}


def _norm_tactic(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if text.upper() in _TACTIC_BY_ID:
        return _TACTIC_BY_ID[text.upper()]
    return _TACTIC_BY_NORMAL.get(re.sub(r"[\s_-]+", " ", text.casefold()))


def parse_labels(
    text: str, key_items: dict[str, dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """`({item_id: {techniques, tactics|None, confidence}}, problems)` from a labels file."""
    rows, problems = _json_lines(text)
    labels: dict[str, dict[str, Any]] = {}
    for number, row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("item_id"), str):
            problems.append(f"line {number}: expected an object with an item_id")
            continue
        item_id = row["item_id"]
        if item_id not in key_items:
            problems.append(f"line {number}: item_id {item_id!r} is not in the key file")
            continue
        if item_id in labels:
            problems.append(f"line {number}: item_id {item_id!r} is labelled twice")
            continue
        techniques_raw = row.get("techniques")
        if not isinstance(techniques_raw, list) or not all(
            isinstance(t, str) for t in techniques_raw
        ):
            problems.append(
                f"line {number}: techniques must be a list of strings (empty = none apply)"
            )
            continue
        techniques: set[str] = set()
        bad = False
        for raw in techniques_raw:
            tid = raw.strip().upper()
            if not _TECHNIQUE_RE.match(tid):
                problems.append(
                    f"line {number}: {raw!r} is not a technique id like T1110 or T1110.001"
                )
                bad = True
            else:
                techniques.add(tid)
        tactics: set[str] | None = None
        if row.get("tactic") not in (None, "", []):
            names = row["tactic"] if isinstance(row["tactic"], list) else [row["tactic"]]
            tactics = set()
            for raw in names:
                name = _norm_tactic(raw)
                if name is None:
                    problems.append(f"line {number}: unknown tactic {raw!r}")
                    bad = True
                else:
                    tactics.add(name)
        elif not techniques:
            tactics = set()
        confidence = row.get("label_confidence")
        if confidence is not None and confidence not in _CONFIDENCES:
            problems.append(
                f"line {number}: label_confidence must be one of {', '.join(_CONFIDENCES)}"
            )
            bad = True
        if bad:
            continue
        labels[item_id] = {
            "techniques": frozenset(techniques),
            "tactics": frozenset(tactics) if tactics is not None else None,
            "confidence": confidence,
        }
    return labels, problems


# ── scoring ───────────────────────────────────────────────────────────────────────────────────────

# Each metric maps (mapped set M, labelled set L) to (numerator, denominator) contributions of one item.
_METRICS: dict[str, Any] = {
    "exact_agreement": lambda m, lab: (int(m == lab), 1),
    "mapped_judged_wrong": lambda m, lab: (int(bool(m) and not m <= lab), int(bool(m))),
    "mapped_entirely_wrong": lambda m, lab: (int(bool(m) and not (m & lab)), int(bool(m))),
    "labelled_left_unmapped": lambda m, lab: (int(bool(lab) and not m), int(bool(lab))),
    "labelled_partly_unmapped": lambda m, lab: (int(bool(lab - m)), int(bool(lab))),
    "precision": lambda m, lab: (len(m & lab), len(m)),
    "recall": lambda m, lab: (len(m & lab), len(lab)),
}
_METRIC_NAMES = tuple(_METRICS)
_LEVELS = ("strict", "parent")
_METRIC_NOTES = {
    "exact_agreement": "share of alerts whose mapped technique set equals the labelled set (of all alerts)",
    "mapped_judged_wrong": "share of MAPPED alerts with at least one mapped technique the labeller does not give",
    "mapped_entirely_wrong": "share of MAPPED alerts with no mapped technique in the labelled set",
    "labelled_left_unmapped": "share of alerts the labeller gave a technique to that the project left unmapped",
    "labelled_partly_unmapped": "share of alerts the labeller gave a technique to that has a labelled "
    "technique the project does not map",
    "precision": "mapped techniques the labeller also gave / mapped techniques (micro, per alert-technique)",
    "recall": "labelled techniques the project also maps / labelled techniques (micro)",
}


def _level(ids: Iterable[str], level: str) -> frozenset[str]:
    return frozenset(parent_of(i) for i in ids) if level == "parent" else frozenset(ids)


def _item_vector(mapped: Sequence[str], labelled: frozenset[str]) -> tuple[int, ...]:
    out: list[int] = []
    for level in _LEVELS:
        m, lab = _level(mapped, level), _level(labelled, level)
        for name in _METRIC_NAMES:
            a, b = _METRICS[name](m, lab)
            out.extend((a, b))
    return tuple(out)


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return float("nan")
    pos = q * (len(sorted_values) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def _prf_table(rows: list[tuple[float, frozenset[str], frozenset[str]]]) -> list[dict[str, Any]]:
    keys: set[str] = set()
    for _, predicted, gold in rows:
        keys |= predicted | gold
    table = []
    for key in sorted(keys):
        tp = fp = fn = 0
        wtp = wfp = wfn = 0.0
        for weight, predicted, gold in rows:
            if key in predicted and key in gold:
                tp += 1
                wtp += weight
            elif key in predicted:
                fp += 1
                wfp += weight
            elif key in gold:
                fn += 1
                wfn += weight
        table.append(
            {
                "id": key,
                "support": tp + fn,
                "mapped": tp + fp,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "precision": _ratio(tp, tp + fp),
                "recall": _ratio(tp, tp + fn),
                "f1": _ratio(2 * tp, 2 * tp + fp + fn),
                "weighted_precision": _ratio(wtp, wtp + wfp),
                "weighted_recall": _ratio(wtp, wtp + wfn),
            }
        )
    return table


def _metric_support(
    name: str, mapped_size: int, pooled: set[tuple[int, int]]
) -> set[tuple[int, int]]:
    """The `(numerator, denominator)` outcomes one item of a stratum could have, before looking at data.

    Resampling only the outcomes that happened to be observed treats a stratum whose items all agree
    (or a stratum of one item) as certain: its only category has probability 1 in every draw, so a
    population interval ignores exactly the strata that are least known. The prior support below puts
    pseudo-count mass on the outcomes that did not happen but could have. `mapped_size` is the size of
    the project's technique set for the stratum at this level (the mapping is a function of the event
    type, so it is the same for every item of the stratum).
    """
    if name == "exact_agreement":
        return {(0, 1), (1, 1)}
    if name in ("mapped_judged_wrong", "mapped_entirely_wrong"):
        return {(0, 1), (1, 1)} if mapped_size else {(0, 0)}
    if name == "labelled_left_unmapped":
        return {(0, 0), (0, 1)} if mapped_size else {(0, 0), (0, 1), (1, 1)}
    if name == "labelled_partly_unmapped":
        return {(0, 0), (0, 1), (1, 1)}
    if name == "precision":
        return {(i, mapped_size) for i in range(mapped_size + 1)} if mapped_size else {(0, 0)}
    # recall: how many techniques a labeller gives is open-ended, so use the sizes seen anywhere in
    # the sample, limited to what the stratum's mapping could match.
    return {p for p in pooled if p[0] <= mapped_size} | {(0, 0)}


def _interval(values: list[float], point: float | None) -> list[float] | None:
    """The 2.5th and 97.5th percentiles, widened to contain the point estimate."""
    if not values:
        return None
    ordered = sorted(values)
    lo, hi = _percentile(ordered, 0.025), _percentile(ordered, 0.975)
    if point is not None:
        lo, hi = min(lo, point), max(hi, point)
    return [round(lo, 4), round(hi, 4)]


def _estimate_headline(
    *,
    populations: dict[str, int],
    kinds: dict[str, str],
    by_stratum: dict[str, list[str]],
    vectors: dict[str, tuple[int, ...]],
    mapped_by_stratum: dict[str, Sequence[str]],
    draws: int,
    seed: Any,
) -> dict[str, dict[str, Any]]:
    """Population estimates for every headline metric at both levels (see the module docstring)."""
    n_metrics = len(_METRIC_NAMES)
    n_cols = len(_LEVELS) * n_metrics
    strata = sorted(by_stratum)
    star = max(strata, key=lambda h: (populations[h], h))
    kind_names = sorted({kinds[h] for h in strata})
    kind_index = {k: i + 1 for i, k in enumerate(kind_names)}  # group 0 is "everything"
    n_groups = len(kind_names) + 1
    total_population = sum(populations[h] for h in strata)

    observed: list[dict[str, Counter[tuple[int, int]]]] = [
        {h: Counter() for h in strata} for _ in range(n_cols)
    ]
    for h in strata:
        for item_id in by_stratum[h]:
            vec = vectors[item_id]
            for j in range(n_cols):
                observed[j][h][(vec[2 * j], vec[2 * j + 1])] += 1
    pooled = [set().union(*(c.keys() for c in observed[j].values())) for j in range(n_cols)]

    # Per column: the sample sums (overall and per kind) and the empirical stratum contributions.
    sample = [[[0.0, 0.0] for _ in range(n_cols)] for _ in range(n_groups)]
    emp: list[dict[str, tuple[float, float]]] = [{} for _ in range(n_cols)]
    base = [
        [[0.0, 0.0] for _ in range(n_cols)] for _ in range(n_groups + 1)
    ]  # last group: the star
    specs: list[tuple[int, int, float, list[float], list[float], list[float], bool]] = []
    for j in range(n_cols):
        name = _METRIC_NAMES[j % n_metrics]
        level = _LEVELS[j // n_metrics]
        for h in strata:
            counts = observed[j][h]
            n = sum(counts.values())
            pop = populations[h]
            en = pop * sum(c * a for (a, _), c in counts.items()) / n
            ed = pop * sum(c * b for (_, b), c in counts.items()) / n
            emp[j][h] = (en, ed)
            g = kind_index[kinds[h]]
            for (a, b), c in counts.items():
                for group in (0, g):
                    sample[group][j][0] += a * c
                    sample[group][j][1] += b * c
            cats = sorted(
                counts.keys()
                | _metric_support(name, len(_level(mapped_by_stratum[h], level)), pooled[j])
            )
            if n >= pop or len(cats) == 1:
                targets = [0, g] + ([n_groups] if h == star else [])
                for group in targets:
                    base[group][j][0] += en
                    base[group][j][1] += ed
                continue
            specs.append(
                (
                    j,
                    g,
                    float(pop),
                    [float(a) for a, _ in cats],
                    [float(b) for _, b in cats],
                    [counts.get(cat, 0) + 0.5 for cat in cats],
                    h == star,
                )
            )

    rng = random.Random(f"mapping-audit-score:{seed}:{draws}")
    rep_total: list[list[float]] = [[] for _ in range(n_cols)]
    rep_kind: list[dict[int, list[float]]] = [
        {g: [] for g in range(1, n_groups)} for _ in range(n_cols)
    ]
    rep_star: list[list[float]] = [[] for _ in range(n_cols)]
    for _ in range(draws):
        acc = [[row[:] for row in group] for group in base]
        for j, g, pop_f, cats_a, cats_b, alphas, is_star in specs:
            if len(alphas) == 2:
                x = rng.betavariate(alphas[0], alphas[1])
                ea = x * cats_a[0] + (1 - x) * cats_a[1]
                eb = x * cats_b[0] + (1 - x) * cats_b[1]
            else:
                gam = [rng.gammavariate(al, 1.0) for al in alphas]
                total_gamma = sum(gam)
                ea = sum(w * a for w, a in zip(gam, cats_a, strict=True)) / total_gamma
                eb = sum(w * b for w, b in zip(gam, cats_b, strict=True)) / total_gamma
            num, den = pop_f * ea, pop_f * eb
            acc[0][j][0] += num
            acc[0][j][1] += den
            acc[g][j][0] += num
            acc[g][j][1] += den
            if is_star:
                acc[n_groups][j][0] += num
                acc[n_groups][j][1] += den
        for j in range(n_cols):
            if acc[0][j][1]:
                rep_total[j].append(acc[0][j][0] / acc[0][j][1])
            for g in range(1, n_groups):
                if acc[g][j][1]:
                    rep_kind[j][g].append(acc[g][j][0] / acc[g][j][1])
            rest_den = acc[0][j][1] - acc[n_groups][j][1]
            if rest_den > 1e-9:
                rep_star[j].append((acc[0][j][0] - acc[n_groups][j][0]) / rest_den)

    def rate(num: float, den: float) -> float | None:
        return num / den if den > 1e-9 else None

    headline: dict[str, dict[str, Any]] = {}
    for li, level in enumerate(_LEVELS):
        block: dict[str, Any] = {}
        for mi, name in enumerate(_METRIC_NAMES):
            j = li * n_metrics + mi
            tot_n = sum(v[0] for v in emp[j].values())
            tot_d = sum(v[1] for v in emp[j].values())
            point = rate(tot_n, tot_d)

            by_kind: dict[str, Any] = {}
            for kind in kind_names:
                g = kind_index[kind]
                k_n = sum(emp[j][h][0] for h in strata if kinds[h] == kind)
                k_d = sum(emp[j][h][1] for h in strata if kinds[h] == kind)
                k_point = rate(k_n, k_d)
                by_kind[kind] = {
                    "strata": sum(1 for h in strata if kinds[h] == kind),
                    "population": sum(populations[h] for h in strata if kinds[h] == kind),
                    "sample": {
                        "numerator": sample[g][j][0],
                        "denominator": sample[g][j][1],
                        "rate": _ratio(sample[g][j][0], sample[g][j][1]),
                    },
                    "population_estimate": {
                        "rate": None if k_point is None else round(k_point, 4),
                        "ci95": _interval(rep_kind[j][g], k_point),
                        "estimated_numerator": round(k_n),
                        "estimated_denominator": round(k_d),
                    },
                }

            def top3(index: int, total: float, j: int = j) -> list[dict[str, Any]]:
                if total <= 0:
                    return []
                ranked = sorted(strata, key=lambda h: (-emp[j][h][index], h))[:3]
                return [
                    {"event_type": h, "share": round(emp[j][h][index] / total, 4)}
                    for h in ranked
                    if emp[j][h][index] > 0
                ]

            num_top, den_top = top3(0, tot_n), top3(1, tot_d)
            rest = rate(tot_n - emp[j][star][0], tot_d - emp[j][star][1])
            star_share = populations[star] / total_population
            block[name] = {
                "meaning": _METRIC_NOTES[name],
                "sample": {
                    "numerator": sample[0][j][0],
                    "denominator": sample[0][j][1],
                    "rate": _ratio(sample[0][j][0], sample[0][j][1]),
                },
                "population": {
                    "rate": None if point is None else round(point, 4),
                    "ci95": _interval(rep_total[j], point),
                    "estimated_numerator": round(tot_n),
                    "estimated_denominator": round(tot_d),
                },
                "by_kind": by_kind,
                "concentration": {
                    "numerator_top3": num_top,
                    "numerator_top3_share": round(sum(r["share"] for r in num_top), 4),
                    "denominator_top3": den_top,
                    "denominator_top3_share": round(sum(r["share"] for r in den_top), 4),
                    "note": "share of the population-weighted numerator / denominator contributed "
                    "by each of the three strata (event types) that contribute most",
                },
                "sensitivity": {
                    "without_largest_stratum": {
                        "removed_event_type": star,
                        "removed_population_share": round(star_share, 4),
                        "rate": None if rest is None else round(rest, 4),
                        "ci95": _interval(rep_star[j], rest),
                        "note": (
                            f"The same estimate with the single largest stratum, {star} "
                            f"({star_share:.1%} of the labelled strata's alerts), removed from "
                            "numerator and denominator; the other strata keep their weights."
                        ),
                    }
                },
            }
        headline[level] = block
    return headline


def score_labels(
    header: dict[str, Any],
    key_items: dict[str, dict[str, Any]],
    labels: dict[str, dict[str, Any]],
    *,
    draws: int = _DEFAULT_DRAWS,
    top: int = _MAX_TOP,
) -> dict[str, Any]:
    """Everything `score` reports for one labeller (pure: no I/O)."""
    seed = header.get("seed", 0)
    labelled = {i: key_items[i] for i in labels}
    populations: dict[str, int] = {}
    kinds: dict[str, str] = {}
    for item in key_items.values():
        populations[item["stratum"]] = int(item["stratum_population"])
        kinds[item["stratum"]] = item["kind"]
    by_stratum: dict[str, list[str]] = defaultdict(list)
    for item_id, item in labelled.items():
        by_stratum[item["stratum"]].append(item_id)
    weight = {
        i: populations[labelled[i]["stratum"]] / len(by_stratum[labelled[i]["stratum"]])
        for i in labelled
    }
    covered_population = sum(populations[h] for h in by_stratum)

    vectors = {
        i: _item_vector(it["mapped_techniques"], labels[i]["techniques"])
        for i, it in labelled.items()
    }

    # --- point estimates, intervals, concentration, sensitivity, per-kind ---------------------------
    headline = _estimate_headline(
        populations=populations,
        kinds=kinds,
        by_stratum=by_stratum,
        vectors=vectors,
        mapped_by_stratum={
            h: labelled[ids[0]]["mapped_techniques"] for h, ids in by_stratum.items()
        },
        draws=draws,
        seed=seed,
    )

    # --- per technique / per tactic --------------------------------------------------------------
    techniques_names: dict[str, str] = {}
    for item in key_items.values():
        techniques_names.update(item.get("mapped_names", {}))
    per_technique: dict[str, list[dict[str, Any]]] = {}
    for level in _LEVELS:
        rows = [
            (
                weight[i],
                _level(it["mapped_techniques"], level),
                _level(labels[i]["techniques"], level),
            )
            for i, it in labelled.items()
        ]
        table = _prf_table(rows)
        for row in table:
            row["name"] = techniques_names.get(row["id"])
        per_technique[level] = sorted(table, key=lambda r: (-r["support"] - r["mapped"], r["id"]))
    tactic_rows = [
        (weight[i], frozenset(it["mapped_tactics"]), labels[i]["tactics"])
        for i, it in labelled.items()
        if labels[i]["tactics"] is not None
    ]
    per_tactic = sorted(
        _prf_table(tactic_rows), key=lambda r: (-r["support"] - r["mapped"], r["id"])
    )

    # --- strata -----------------------------------------------------------------------------------
    strata_rows = []
    for h in sorted(by_stratum, key=lambda e: (-populations[e], e)):
        ids = by_stratum[h]
        n_h = len(ids)
        row = {"event_type": h, "kind": kinds[h], "population": populations[h], "labelled": n_h}
        row["mapped"] = list(labelled[ids[0]]["mapped_techniques"])
        for level in _LEVELS:
            agree = sum(
                1
                for i in ids
                if _level(labelled[i]["mapped_techniques"], level)
                == _level(labels[i]["techniques"], level)
            )
            lo, hi = wilson(agree, n_h)
            row[f"agree_{level}"] = agree
            row[f"agree_{level}_wilson95"] = [round(lo, 4), round(hi, 4)]
        row["census"] = n_h >= populations[h]
        strata_rows.append(row)

    # --- worst disagreements ----------------------------------------------------------------------
    groups: dict[tuple[str, tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for i, item in labelled.items():
        m = tuple(sorted(item["mapped_techniques"]))
        lab = tuple(sorted(labels[i]["techniques"]))
        if frozenset(m) == frozenset(lab):
            continue
        entry = groups.setdefault(
            (item["event_type"], m, lab),
            {
                "event_type": item["event_type"],
                "mapped": list(m),
                "labelled": list(lab),
                "agrees_at_parent_level": _level(m, "parent") == _level(lab, "parent"),
                "items": 0,
                "estimated_alerts": 0.0,
                "stratum_population": item["stratum_population"],
                "item_ids": [],
            },
        )
        entry["items"] += 1
        entry["estimated_alerts"] += weight[i]
        entry["item_ids"].append(i)
    worst = sorted(
        groups.values(),
        key=lambda g: (g["agrees_at_parent_level"], -g["estimated_alerts"], g["event_type"]),
    )
    for entry in worst:
        entry["estimated_alerts"] = round(entry["estimated_alerts"])

    confidence_rows = {}
    for level_name in (*_CONFIDENCES, None):
        ids = [i for i in labelled if labels[i]["confidence"] == level_name]
        if not ids:
            continue
        confidence_rows[level_name or "unstated"] = {
            "items": len(ids),
            "exact_agreement_strict": _ratio(
                sum(
                    1
                    for i in ids
                    if frozenset(labelled[i]["mapped_techniques"]) == labels[i]["techniques"]
                ),
                len(ids),
            ),
            "exact_agreement_parent": _ratio(
                sum(
                    1
                    for i in ids
                    if _level(labelled[i]["mapped_techniques"], "parent")
                    == _level(labels[i]["techniques"], "parent")
                ),
                len(ids),
            ),
        }

    return {
        "items": {
            "in_key": len(key_items),
            "labelled": len(labelled),
            "unlabelled": len(key_items) - len(labelled),
            "strata_with_labels": len(by_stratum),
            "population_covered_share": _ratio(covered_population, sum(populations.values())),
            "with_tactic_label": len(tactic_rows),
        },
        "headline": headline,
        "per_technique": {lv: per_technique[lv][:top] for lv in _LEVELS},
        "per_technique_total": {lv: len(per_technique[lv]) for lv in _LEVELS},
        "per_tactic": per_tactic[:top],
        "worst_disagreements": worst[:top],
        "worst_disagreements_total": len(worst),
        "strata": strata_rows,
        "by_label_confidence": confidence_rows,
    }


def inter_annotator(
    key_items: dict[str, dict[str, Any]],
    labels_a: dict[str, dict[str, Any]],
    labels_b: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Agreement between two labellers on the items both labelled."""
    both = sorted(set(labels_a) & set(labels_b))
    if not both:
        return {"items": 0, "note": "the two labels files have no item in common"}
    populations: dict[str, int] = {}
    n_h = Counter(key_items[i]["stratum"] for i in both)
    for i in both:
        populations[key_items[i]["stratum"]] = int(key_items[i]["stratum_population"])
    weight = {i: populations[key_items[i]["stratum"]] / n_h[key_items[i]["stratum"]] for i in both}
    out: dict[str, Any] = {"items": len(both)}
    for level in _LEVELS:
        set_a = {i: _level(labels_a[i]["techniques"], level) for i in both}
        set_b = {i: _level(labels_b[i]["techniques"], level) for i in both}
        mapped = {i: _level(key_items[i]["mapped_techniques"], level) for i in both}
        agree_a = [set_a[i] == mapped[i] for i in both]
        agree_b = [set_b[i] == mapped[i] for i in both]
        same = [set_a[i] == set_b[i] for i in both]
        wsum = sum(weight.values())
        out[level] = {
            "labellers_give_identical_sets": _ratio(sum(same), len(both)),
            "labellers_give_identical_sets_population": round(
                sum(w for i, w in weight.items() if set_a[i] == set_b[i]) / wsum, 4
            ),
            "mean_jaccard": round(sum(jaccard(set_a[i], set_b[i]) for i in both) / len(both), 4),
            "kappa_agrees_with_the_mapping": (
                round(k, 4) if (k := cohen_kappa(agree_a, agree_b)) is not None else None
            ),
            "kappa_any_technique_applies": (
                round(k, 4)
                if (
                    k := cohen_kappa([bool(set_a[i]) for i in both], [bool(set_b[i]) for i in both])
                )
                is not None
                else None
            ),
        }
    disagree: dict[str, dict[str, Any]] = {}
    for i in both:
        if _level(labels_a[i]["techniques"], "parent") != _level(
            labels_b[i]["techniques"], "parent"
        ):
            row = disagree.setdefault(
                key_items[i]["event_type"], {"event_type": key_items[i]["event_type"], "items": 0}
            )
            row["items"] += 1
    out["disagreeing_event_types"] = sorted(
        disagree.values(), key=lambda r: (-r["items"], r["event_type"])
    )[:20]
    out["note"] = (
        "kappa is undefined (null) when a labeller gives one answer to every item. Disagreement between "
        "labellers bounds how much of any mapping disagreement is labeller noise rather than a mapping error."
    )
    return out


def _estimation_note(draws: int) -> str:
    return (
        "Population rates are ratios of stratum-weighted totals (weight N_h/n_h). The 95% interval is a "
        f"stratified Jeffreys (Dirichlet) Monte Carlo, {draws} draws, run per metric: each stratum's "
        "mix of item outcomes is re-sampled from Dirichlet(count + 0.5) over every outcome the stratum "
        "COULD have (not only the ones observed), so a stratum of one item, or whose items all "
        "agreed, is not treated as certain; a stratum with every alert labelled is held fixed. The "
        "interval is widened to contain the point estimate. Per-stratum Wilson intervals are in "
        "`strata`. Each headline metric also carries `by_kind` (the same estimate within mapped / "
        "unmapped_bookkeeping / unmapped_other strata), `concentration` (the three strata that "
        "contribute most of the weighted numerator and denominator) and `sensitivity` (the estimate "
        "with the single largest stratum removed): a few huge event types can carry a rate, so read "
        "the estimate together with them. 'strict' needs identical technique ids; 'parent' collapses "
        "sub-techniques to their parent (T1110.001 = T1110)."
    )


def _summarise(full: dict[str, Any], top: int) -> dict[str, Any]:
    disagreeing = [s for s in full["strata"] if s["agree_parent"] < s["labelled"]]
    return {
        "items": full["items"],
        "headline": full["headline"],
        "per_technique": {lv: full["per_technique"][lv][:top] for lv in _LEVELS},
        "per_technique_total": full["per_technique_total"],
        "per_tactic": full["per_tactic"][:top],
        "worst_disagreements": [
            {k: v for k, v in g.items() if k != "item_ids"}
            for g in full["worst_disagreements"][:top]
        ],
        "worst_disagreements_total": full["worst_disagreements_total"],
        "strata_disagreeing_at_parent_level": [
            {
                k: s[k]
                for k in ("event_type", "kind", "population", "labelled", "agree_parent", "mapped")
            }
            for s in disagreeing[:top]
        ],
        "by_label_confidence": full["by_label_confidence"],
    }


async def _score(
    labels_file: str | None,
    key_file: str | None,
    second_labels_file: str | None,
    top: int,
    draws: int,
) -> dict[str, Any]:
    if not labels_file or not key_file:
        return {
            "error": "action='score' needs labels_file and key_file (file names in reports_dir)."
        }
    if isinstance(top, bool) or not isinstance(top, int) or not 1 <= top <= _MAX_TOP:
        return {"error": f"top must be an integer from 1 to {_MAX_TOP}."}
    if isinstance(draws, bool) or not isinstance(draws, int) or not 100 <= draws <= _MAX_DRAWS:
        return {"error": f"interval_draws must be an integer from 100 to {_MAX_DRAWS}."}
    try:
        header, key_items = parse_key(_read_report_text(key_file))
        parsed: list[tuple[str, dict[str, dict[str, Any]]]] = []
        for name in (labels_file, second_labels_file):
            if not name:
                continue
            labels, problems = parse_labels(_read_report_text(name), key_items)
            if problems:
                return {
                    "error": f"{name}: {len(problems)} problem(s) in the labels file; fix them and re-run.",
                    "problems": problems[:20],
                }
            if not labels:
                return {"error": f"{name}: no labels found."}
            parsed.append((name, labels))
    except _FileError as exc:
        return {"error": str(exc)}

    full_a = score_labels(header, key_items, parsed[0][1], draws=draws)
    result: dict[str, Any] = {
        "action": "score",
        "key_file": key_file,
        "seed": header.get("seed"),
        "sample_window": header.get("window"),
        "population_total": header.get("population_total"),
        "estimation": _estimation_note(draws),
        "labeller_a": {"labels_file": parsed[0][0], **_summarise(full_a, top)},
    }
    full: dict[str, Any] = {"labeller_a": {"labels_file": parsed[0][0], **full_a}}
    if len(parsed) == 2:
        full_b = score_labels(header, key_items, parsed[1][1], draws=draws)
        result["labeller_b"] = {"labels_file": parsed[1][0], **_summarise(full_b, top)}
        full["labeller_b"] = {"labels_file": parsed[1][0], **full_b}
        agreement = inter_annotator(key_items, parsed[0][1], parsed[1][1])
        result["inter_annotator"] = agreement
        full["inter_annotator"] = agreement
    artifact = write_artifact(
        json.dumps(
            {**{k: v for k, v in result.items() if k.startswith(("key", "seed", "estim"))}, **full},
            indent=1,
        ),
        prefix="mapping-audit-score",
        extension="json",
    )
    if "error" in artifact:
        result["artifact_error"] = artifact["error"]
    else:
        result["artifact"] = artifact
    return mark_untrusted(result)


@mcp.tool(auth=require_role("operator"), **hints("mapping_audit"))
async def mapping_audit(
    action: Action,
    since_hours: float | None = None,
    sample_size: int = _DEFAULT_SAMPLE,
    seed: int | None = None,
    per_type_min: int = 1,
    labels_file: str | None = None,
    key_file: str | None = None,
    second_labels_file: str | None = None,
    top: int = 15,
    interval_draws: int = _DEFAULT_DRAWS,
) -> dict[str, Any]:
    """Measure the ATT&CK mapping against independent labels: draw a blind sample, then score it.

    The mapping from event types to techniques (`intel/mitre.py`) is the author's judgement. This
    tool checks it against someone else's, in two steps done by different people.

    `action="sample"` draws a reproducible stratified sample (one stratum per event type seen:
    `per_type_min` of each, the rest of `sample_size` proportional to how common the type is) and writes
    two files into the reports directory: a BLIND file for labellers (a README record, then items with
    only the event type, protocol, severity and a clipped, masked payload digest) and a KEY file with
    the project's mapping per item and the population of each stratum. Give labellers only the blind
    file. Same seed on the same data gives the same sample.

    `action="score"` compares labels against the key. Labellers write JSON Lines
    `{item_id, techniques: ["T1110.001", ...], tactic?, label_confidence?}` (an empty list means no
    technique applies). Reports item agreement, per-technique and per-tactic precision/recall/F1,
    the share of mapped alerts judged wrong and of labelled alerts left unmapped, strict and
    parent-level, re-weighted to the whole window with a 95% interval. Every headline metric also
    carries `by_kind`, `concentration` (the three strata contributing most) and `sensitivity` (the
    estimate without the single largest stratum), because a few huge event types can carry a rate.
    Also the worst disagreements by event type and, with `second_labels_file`, inter-annotator
    agreement (Cohen's kappa, Jaccard). The full result is also written to a JSON artifact.

    Args:
        action: `sample` or `score`.
        since_hours: Sample only the last N hours (analysis mode: ending at the newest alert).
        sample_size: Total items to draw (1 to 5000; default 200).
        seed: Integer seed; omit for a random one (it is returned).
        per_type_min: Minimum items per event type (default 1; 0 turns the floor off).
        labels_file: Score: the labeller's labels file in the reports directory.
        key_file: Score: the key file written by `sample`.
        second_labels_file: Score: a second labeller's file, for inter-annotator agreement.
        top: Score: rows to return in each ranked list.
        interval_draws: Score: Monte Carlo draws for the intervals (100 to 20000).
    """
    if action == "sample":
        result = await _sample(since_hours, sample_size, seed, per_type_min)
        await _audit.record_action(
            "mapping_audit",
            (
                f"Drew a blind ATT&CK mapping sample of {result.get('sampled')} items"
                if "error" not in result
                else "Mapping audit sample refused"
            ),
            arguments={
                "action": action,
                "since_hours": since_hours,
                "sample_size": sample_size,
                "seed": seed,
            },
            target=(result.get("key_file") or {}).get("name"),
            outcome="ok" if "error" not in result else "error",
            error=result.get("error"),
        )
        return result
    if action == "score":
        return await _score(labels_file, key_file, second_labels_file, top, interval_draws)
    return {"error": "action must be 'sample' or 'score'."}
