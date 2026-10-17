"""Attack correlation engine — groups events into campaigns, then ranks them.

Grouping finds every set of sources hitting one event type in one window ("windows"). On a real
run that is thousands of groups, and two things make the list unreadable: most are three sources
sweeping one service in the same hour, and one botnet that keeps coming back produces one near
identical window per hour. So windows of one event type whose sources are largely the same are
merged into one campaign that says how many windows it recurred in (`_merge_recurring`), and
`score_campaign` ranks the result with a formula that is additive, capped per term and reported
term by term, so an analyst can see why one campaign outranks another.
"""

from __future__ import annotations

import math
import statistics
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from honeypot_mcp.storage.models import Alert

RankBy = Literal["score", "sources", "events", "recent"]
RANK_BY_VALUES: tuple[str, ...] = ("score", "sources", "events", "recent")


async def detect_campaigns(
    alerts: list[Alert],
    window_minutes: int = 60,
    min_sources: int = 3,
    rank_by: RankBy = "score",
    merge_recurring: bool = True,
) -> list[dict[str, Any]]:
    """Detect coordinated attack campaigns from a list of alerts, ranked.

    A window is: multiple distinct source IPs all hitting the same event_type within the same
    rolling time window. A campaign is one window, or, with `merge_recurring`, every window of one
    event type that largely shares its sources (see `_merge_recurring`); `occurrences` says how
    many. `merge_recurring=False` returns the windows themselves.

    Each campaign carries a `kind`, a `score` and a `why` (see `score_campaign`), and the list is
    ordered by `rank_by`: `score` (default), `sources`, `events` or `recent` (newest first). Ties
    fall back to score, then to sources, so the order is deterministic.
    """
    if rank_by not in RANK_BY_VALUES:
        raise ValueError(f"rank_by must be one of {', '.join(RANK_BY_VALUES)}; got {rank_by!r}")
    if not alerts:
        return []

    # Group by event_type, then find clusters within time windows
    by_type: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_type[alert.event_type].append(alert)

    campaigns: list[dict[str, Any]] = []

    for event_type, type_alerts in by_type.items():
        sorted_alerts = sorted(type_alerts, key=lambda a: a.timestamp)
        window = timedelta(minutes=window_minutes)

        i = 0
        while i < len(sorted_alerts):
            window_alerts = [sorted_alerts[i]]
            j = i + 1
            while j < len(sorted_alerts):
                if sorted_alerts[j].timestamp - sorted_alerts[i].timestamp <= window:
                    window_alerts.append(sorted_alerts[j])
                    j += 1
                else:
                    break

            unique_ips = {a.source_ip for a in window_alerts}
            if len(unique_ips) >= min_sources:
                start_ts = sorted_alerts[i].timestamp
                end_ts = window_alerts[-1].timestamp
                campaigns.append(
                    {
                        "event_type": event_type,
                        "start_time": start_ts.isoformat(),
                        "end_time": end_ts.isoformat(),
                        "duration_minutes": int((end_ts - start_ts).total_seconds() / 60),
                        "unique_source_ips": len(unique_ips),
                        "total_events": sum(_weight(a) for a in window_alerts),
                        "source_ips": sorted(unique_ips),
                        "targeted_honeypots": list(
                            {a.honeypot_id for a in window_alerts if a.honeypot_id}
                        ),
                        "campaign_id": _make_campaign_id(event_type, start_ts),
                        "severity": _highest_severity(window_alerts),
                    }
                )

            i = j if j > i else i + 1

    if merge_recurring:
        # Merging subsumes de-duplication: a window whose sources are a subset of another's joins
        # it instead of being dropped, so its events and its hour still count.
        campaigns = _merge_recurring(campaigns)
    else:
        # Deduplicate overlapping windows (keep the largest)
        campaigns = [_combine([w]) for w in _deduplicate(campaigns)]
    _attach_scores(campaigns, alerts)
    for campaign in campaigns:
        sources = campaign.pop("_sources")
        campaign["source_ips"] = sources[:MAX_SOURCE_IPS]
        campaign["source_ips_shown"] = len(campaign["source_ips"])
    return _order(campaigns, rank_by)


# ── recurrence ───────────────────────────────────────────────────────────────────────────────

# Most source addresses listed per campaign (`unique_source_ips` is always the full count).
MAX_SOURCE_IPS = 20

# A window joins a campaign of the same event type when at least this share of *its own* sources
# have already taken part in the campaign. Measured against the window's sources, not against the
# union, so a small window that is mostly the same actors as a big campaign joins it (a botnet
# whose active subset changes hour to hour), while a big window that merely contains a few
# addresses a small campaign used does not. Jaccard would split exactly the bursty case.
_RECURRENCE_OVERLAP = 0.5


def _merge_recurring(windows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold windows of one event type that largely share their sources into one campaign.

    This replaces `_deduplicate` when merging: a window that is a subset of another one joins the
    campaign that holds the other instead of being discarded. Windows are taken largest first (so
    the seed is the widest picture of the actors) and each joins the first existing campaign of
    its event type that already holds at least `_RECURRENCE_OVERLAP` of its sources, else starts
    one. Each window therefore belongs to exactly one campaign, and the sum of `occurrences` is
    the number of windows. The campaign keeps the full source list under `_sources` (most
    windows first) until scoring is done."""
    clusters: dict[str, list[tuple[set[str], list[dict[str, Any]]]]] = defaultdict(list)
    for window in sorted(
        windows, key=lambda c: (-len(c["source_ips"]), c["event_type"], c["start_time"])
    ):
        ips = set(window["source_ips"])
        home = None
        for union, members in clusters[window["event_type"]]:
            if sum(1 for ip in ips if ip in union) >= _RECURRENCE_OVERLAP * len(ips):
                home = (union, members)
                break
        if home is None:
            clusters[window["event_type"]].append((set(ips), [window]))
        else:
            home[0].update(ips)
            home[1].append(window)
    return [_combine(members) for group in clusters.values() for _, members in group]


def _combine(members: list[dict[str, Any]]) -> dict[str, Any]:
    """One campaign from its windows: totals, union of sources, first and last window."""
    members = sorted(members, key=lambda c: c["start_time"])
    first, last = members[0], max(members, key=lambda c: c["end_time"])
    participation: Counter[str] = Counter()
    for member in members:
        participation.update(member["source_ips"])
    sources = sorted(participation, key=lambda ip: (-participation[ip], ip))
    per_window = [m["unique_source_ips"] for m in members]
    severity = max(
        (m["severity"] for m in members if m["severity"]),
        key=_SEVERITY_RANK.__getitem__,
        default=None,
    )
    start = datetime.fromisoformat(first["start_time"])
    end = datetime.fromisoformat(last["end_time"])
    return {
        "event_type": first["event_type"],
        "start_time": first["start_time"],
        "end_time": last["end_time"],
        "duration_minutes": int((end - start).total_seconds() / 60),
        "unique_source_ips": len(sources),
        "total_events": sum(m["total_events"] for m in members),
        "source_ips": sources,
        "_sources": sources,
        "targeted_honeypots": sorted({h for m in members for h in m["targeted_honeypots"]}),
        "campaign_id": first["campaign_id"],
        "severity": severity,
        "occurrences": len(members),
        "first_window": first["start_time"],
        "last_window": max(m["start_time"] for m in members),
        "sources_per_window": int(statistics.median_low(per_window)),
        "max_sources_per_window": max(per_window),
    }


# ── ranking ──────────────────────────────────────────────────────────────────────────────────

# Points per term. They sum to 100, so a score reads as a percentage of the most notable
# campaign the formula can describe. `kind` is deliberately the largest term: three sources
# running commands is a more important finding than three hundred sources opening connections.
_W_KIND = 45.0  # behavioural campaigns get all of it, sweeps none
_W_SEVERITY = {"low": 0.0, "medium": 4.0, "high": 10.0, "critical": 15.0}  # max 15
_W_BREADTH_MAX = 12.0  # 3 * log2(distinct sources): 3 sources 4.8, 16 or more sources 12
_W_SHARED_MAX = 9.0  # 3 per other event type that at least half the sources also produced
_W_DURATION_MAX = 4.0  # 1 per hour from the first window to the last
_W_RECURRENCE_MAX = 6.0  # 1.5 * log2(windows): 2 windows 1.5, 16 or more windows 6
_W_INTENSITY_MAX = 9.0  # 2.25 * log10(events per source): 100 per source 4.5, 10,000+ 9

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Event types whose name says "looked, did not act": checked before the behavioural words, so
# `elasticsearch_query_probe` is a sweep although it contains "query".
_SWEEP_WORDS = (
    "probe",
    "scan",
    "recon",
    "connect",
    "closed",
    "negotiate",
    "handshake",
    "client_version",
    "kex",
    "capability",
    "banner",
    "options",
    "invalid",
    "request",
    "health",
    "flood",
)
_BEHAVIOURAL_WORDS = (
    "command",
    "exploit",
    "login",
    "auth",
    "credential",
    "attempt",
    "escape",
    "container",
    "rce",
    "upload",
    "download",
    "outfile",
    "udf",
    "program",
    "destructive",
    "ransom",
    "amplification",
    "toll_fraud",
    "config_set",
    "eval",
    "rogue",
    "module_load",
    "secret",
    "exec",
    "transfer",
    "file_",
    "access",
    "session",
    "honeytoken",
    "forward",
    "query",
    "bind",
    "community",
    "enumerat",
)


def classify_kind(event_type: str, severity: str | None) -> Literal["sweep", "behavioural"]:
    """`behavioural` when the sources did something (ran commands, authenticated, exploited,
    escalated); `sweep` when they only connected or probed.

    In order: critical severity is behavioural; a name that says probe/scan/connect/handshake is a
    sweep whatever its severity (an RDP handshake is rated high, and is still a sweep); a name with
    a behavioural word (command, login, exploit, ...) is behavioural; any other name is
    behavioural only if rated high."""
    if severity == "critical":
        return "behavioural"
    name = event_type.lower()
    if any(word in name for word in _SWEEP_WORDS):
        return "sweep"
    if any(word in name for word in _BEHAVIOURAL_WORDS):
        return "behavioural"
    return "behavioural" if severity == "high" else "sweep"


def score_campaign(
    campaign: dict[str, Any], shared_types: list[str] | None = None
) -> dict[str, Any]:
    """Score one campaign out of 100, and say why. Every term is capped and reported.

    ===============  ===================================================  =====
    term             how it is computed                                   max
    ===============  ===================================================  =====
    kind             45 if behavioural (commands, exploit, credentials,   45
                     escalation), 0 if a sweep (connect/probe)
    severity         highest severity recorded on the event type:         15
                     low 0, medium 4, high 10, critical 15
    breadth          3 * log2(distinct sources over all windows)          12
    shared_types     3 per other event type that at least half the        9
                     sources also produced while the campaign ran
    duration         1 per hour from the first window to the last         4
    recurrence       1.5 * log2(windows the campaign recurred in)         6
    intensity        2.25 * log10(events per source, over all windows)    9
    ===============  ===================================================  =====

    A behavioural campaign therefore scores at least 45 and a sweep at most 50 (a sweep rated
    high that also maxes every other term), so a three-source command campaign outranks a very
    large connection sweep unless that sweep is rated high *and* maxes every other term. The
    terms are returned in `score_breakdown`; nothing else enters the score.
    """
    shared = shared_types or []
    severity = campaign.get("severity")
    kind = classify_kind(campaign["event_type"], severity)
    sources = max(1, int(campaign["unique_source_ips"]))
    events = int(campaign["total_events"])
    per_source = events / sources
    occurrences = max(1, int(campaign.get("occurrences", 1)))

    breakdown = {
        "kind": _W_KIND if kind == "behavioural" else 0.0,
        "severity": _W_SEVERITY.get(severity or "", 0.0),
        "breadth": min(_W_BREADTH_MAX, 3.0 * math.log2(sources)),
        "shared_types": min(_W_SHARED_MAX, 3.0 * len(shared)),
        "duration": min(_W_DURATION_MAX, campaign["duration_minutes"] / 60),
        "recurrence": min(_W_RECURRENCE_MAX, 1.5 * math.log2(occurrences)),
        "intensity": min(_W_INTENSITY_MAX, 2.25 * math.log10(max(1.0, per_source))),
    }
    breakdown = {k: round(v, 1) for k, v in breakdown.items()}

    hours = campaign["duration_minutes"] / 60
    parts = [f"{kind}: {campaign['event_type']} ({severity or 'unrated'} severity)"]
    if occurrences > 1:
        typical = campaign.get("sources_per_window", sources)
        parts.append(
            f"recurred in {occurrences} windows over {hours:g}h "
            f"({campaign['first_window'][:13]} to {campaign['last_window'][:13]})"
        )
        parts.append(
            f"{sources} distinct sources ({typical} per window), {events:,} events "
            f"({per_source:,.0f} per source)"
        )
    else:
        parts.append(f"{sources} sources, {events:,} events ({per_source:,.0f} per source)")
        parts.append(f"{hours:g}h" if hours >= 1 else "within one hour")
    if shared:
        parts.append(
            f"same sources also produced {len(shared)} other event type(s): {', '.join(shared[:3])}"
        )
    return {
        "kind": kind,
        "score": round(sum(breakdown.values()), 1),
        "why": "; ".join(parts),
        "score_breakdown": breakdown,
        "events_per_source": round(per_source, 1),
        "shared_event_types": shared[:5],
    }


def _highest_severity(items: list[Any]) -> str | None:
    """The highest severity among rollup rows that carry one; None for alert-shaped items without."""
    best: str | None = None
    for item in items:
        value = getattr(item, "severity", None)
        value = getattr(value, "value", value)
        if (
            isinstance(value, str)
            and value in _SEVERITY_RANK
            and (best is None or _SEVERITY_RANK[value] > _SEVERITY_RANK[best])
        ):
            best = value
    return best


def _shared_event_types(
    campaign: dict[str, Any], rows_by_source: dict[str, tuple[list[datetime], list[str]]]
) -> list[str]:
    """Other event types that at least half of the campaign's sources produced between its first
    and last window, most widely shared first."""
    start = datetime.fromisoformat(campaign["start_time"])
    end = datetime.fromisoformat(campaign["end_time"])
    sources = campaign["_sources"]
    needed = max(2, -(-len(sources) // 2))
    seen: Counter[str] = Counter()
    for ip in sources:
        times, types = rows_by_source[ip]
        lo, hi = bisect_left(times, start), bisect_right(times, end)
        seen.update(set(types[lo:hi]) - {campaign["event_type"]})
    ranked = [(t, n) for t, n in seen.items() if n >= needed]
    ranked.sort(key=lambda tn: (-tn[1], tn[0]))
    return [t for t, _ in ranked]


def _attach_scores(campaigns: list[dict[str, Any]], alerts: list[Any]) -> None:
    """Score every campaign in place. One pass over the alerts indexes only the sources that are
    in a campaign, so the cost does not grow with the other sources."""
    if not campaigns:
        return
    wanted = {ip for c in campaigns for ip in c["_sources"]}
    raw: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip in wanted:
            raw[alert.source_ip].append((alert.timestamp, alert.event_type))
    rows_by_source: dict[str, tuple[list[datetime], list[str]]] = {}
    for ip, items in raw.items():
        items.sort(key=lambda it: it[0])
        rows_by_source[ip] = ([t for t, _ in items], [e for _, e in items])
    for campaign in campaigns:
        campaign.update(score_campaign(campaign, _shared_event_types(campaign, rows_by_source)))


def _order(campaigns: list[dict[str, Any]], rank_by: str) -> list[dict[str, Any]]:
    """Sort by the chosen key, best first; ties by score, then sources, then id (stable)."""
    ordered = sorted(
        campaigns,
        key=lambda c: (-c["score"], -c["unique_source_ips"], c["campaign_id"], c["start_time"]),
    )
    primary = {
        "score": lambda c: c["score"],
        "sources": lambda c: c["unique_source_ips"],
        "events": lambda c: c["total_events"],
        "recent": lambda c: c["end_time"],
    }[rank_by]
    return sorted(ordered, key=primary, reverse=True)


def _make_campaign_id(event_type: str, start) -> str:
    ts = start.strftime("%Y%m%d%H%M")
    return f"camp-{event_type[:8]}-{ts}"


def _deduplicate(campaigns: list[dict]) -> list[dict]:
    """Remove campaigns that are strict subsets of larger campaigns.

    Processes largest-first. A campaign is only ever compared against ones
    already accepted into `seen`, so if a smaller window were kept ahead of a
    later, larger superset — the common case, since windows for one
    event_type are produced in chronological (not size) order and an
    attacker scanning over hours shows up in more than one of them — the
    smaller one would never get retroactively dropped. Sorting first
    guarantees every superset is in `seen` before any of its subsets are
    considered, regardless of which window was detected earlier.
    """
    seen: list[dict] = []
    for c in sorted(campaigns, key=lambda c: len(c["source_ips"]), reverse=True):
        ips = set(c["source_ips"])
        if not any(
            ips.issubset(set(s["source_ips"])) and c["event_type"] == s["event_type"] for s in seen
        ):
            seen.append(c)
    return seen


@dataclass(frozen=True, slots=True)
class _RolledAlert:
    """One rollup row, shaped like an alert for `detect_campaigns`: it stands for `weight` alerts."""

    timestamp: datetime
    event_type: str
    source_ip: str
    honeypot_id: int
    weight: int
    severity: str | None = None


def rolled_alerts(rows: list[tuple[datetime, str, str, int, int, str]]) -> list[Any]:
    """Rollup rows `(hour, event type, source, sensor id, alerts, severity)` as alert-shaped
    items, so the same sliding-window correlation runs over a whole run instead of the latest few
    thousand."""
    return [_RolledAlert(hour, etype, ip, hp, n, sev) for hour, etype, ip, hp, n, sev in rows]


def _weight(alert: Any) -> int:
    """How many alerts an item stands for: its `weight` if it is a rollup row, else one."""
    weight = getattr(alert, "weight", 1)
    return weight if isinstance(weight, int) else 1
