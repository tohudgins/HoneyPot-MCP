"""Field test, part four: are the read tools' answers RIGHT? Check them against SQL.

    uv run python scripts/field_test_oracle.py --backup ~/hp-backups/<backup>/honeypot_mcp.db \
        --out oracle-report.md

Parts one to three prove the tools answer and obey their roles, and that actions change the live
system. This part takes a *frozen* real backup (so live traffic cannot move the numbers), runs the
analysis tools on a copy of it, and compares each answer with an independent computation written as
plain SQL straight over the `alerts` table. The tools read pre-aggregated rollups and indexes; the
oracle never does, so agreement means the optimised path equals the definition.

The oracles use real attackers, real windows (starting mid-hour, on the hour, and before any data)
and real filters. Anything that cannot be checked this way is listed as NOT
COVERED with the reason, never silently skipped. Nothing is written to the backup you name.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROWS: list[tuple[str, str, bool, str]] = []


def check(group: str, what: str, ok: bool, detail: str = "") -> None:
    ROWS.append((group, what, bool(ok), detail[:200]))
    print(
        f"  [{'PASS' if ok else 'FAIL'}] {group:12} {what}" + ("" if ok else f"  -> {detail[:140]}")
    )


def stamp(moment: datetime) -> str:
    """The stored form of a timestamp: naive UTC, microseconds."""
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")


class Oracle:
    def __init__(self, db: str) -> None:
        self.con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)

    def one(self, sql: str, *params: Any) -> Any:
        return self.con.execute(sql, params).fetchone()[0]

    def rows(self, sql: str, *params: Any) -> list[tuple]:
        return self.con.execute(sql, params).fetchall()

    def window(self, since: datetime | None) -> tuple[str, tuple]:
        return ("WHERE timestamp >= ?", (stamp(since),)) if since else ("", ())


def event_breakdown_ok(got: dict[str, int], want: dict[str, int]) -> bool:
    """The profile lists an address's 20 most frequent event types: each count must be true and
    the counts must be the 20 largest (which types fill a tie at the edge is not defined)."""
    return (
        all(want.get(t) == n for t, n in got.items())
        and sorted(got.values(), reverse=True) == sorted(want.values(), reverse=True)[: len(got)]
        and len(got) == min(20, len(want))
    )


def sev_dict(rows: list[tuple]) -> dict[str, int]:
    return {r[0]: r[1] for r in rows}


async def run(args: argparse.Namespace) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="hp-oracle-"))
    copy = tmp / "honeypot_mcp.db"
    print(f"copying {args.backup} (so the original is never opened for writing)")
    shutil.copy(args.backup, copy)
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{copy}"
    os.environ.setdefault("REPORTS_DIR", str(tmp / "reports"))

    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import alerts as A
    from honeypot_mcp.tools import analysis as N
    from honeypot_mcp.tools import deception as D
    from honeypot_mcp.tools import honeypot as H

    await init_db()
    o = Oracle(str(copy))
    first, last = o.rows("SELECT min(timestamp), max(timestamp) FROM alerts")[0]
    total = o.one("SELECT count(*) FROM alerts")
    print(f"backup holds {total:,} alerts from {first} to {last}\n")
    t_first = datetime.fromisoformat(first).replace(tzinfo=UTC)
    t_last = datetime.fromisoformat(last).replace(tzinfo=UTC)

    def hours_ago(moment: datetime) -> float:
        return (datetime.now(UTC) - moment).total_seconds() / 3600

    on_the_hour = (t_first + (t_last - t_first) / 2).replace(minute=0, second=0, microsecond=0)
    windows = {
        "all time": None,
        "mid-hour start": t_first + (t_last - t_first) / 3 + timedelta(minutes=17, seconds=41),
        "on the hour": on_the_hour,
        "last 40 min of data": t_last - timedelta(minutes=40),
        "after all data": datetime.now(UTC) - timedelta(minutes=1),
    }

    print("== alerts_stats against GROUP BY over the alert table")
    for name, since in windows.items():
        cutoff = (
            None if since is None else stamp(datetime.now(UTC) - timedelta(hours=hours_ago(since)))
        )
        where, params = ("", ()) if cutoff is None else ("WHERE timestamp >= ?", (cutoff,))
        got = (
            await A.alerts_stats(since_hours=hours_ago(since)) if since else await A.alerts_stats()
        )
        want_total = o.one(f"SELECT count(*) FROM alerts {where}", *params)
        check(
            "stats",
            f"{name}: total",
            got["total_alerts"] == want_total,
            f"{got['total_alerts']} != {want_total}",
        )
        check(
            "stats",
            f"{name}: unique sources",
            got["unique_source_ips"]
            == o.one(f"SELECT count(DISTINCT source_ip) FROM alerts {where}", *params),
        )
        want_sev = sev_dict(
            o.rows(f"SELECT severity, count(*) FROM alerts {where} GROUP BY 1", *params)
        )
        check(
            "stats",
            f"{name}: severity split",
            got["by_severity"] == want_sev,
            f"{got['by_severity']} != {want_sev}",
        )
        counts = Counter(
            dict(o.rows(f"SELECT source_ip, count(*) FROM alerts {where} GROUP BY 1", *params))
        )
        top = [(r["ip"], r["count"]) for r in got["top_source_ips"]]
        ok = (
            all(counts[ip] == n for ip, n in top)
            and [n for _, n in top] == sorted(counts.values(), reverse=True)[: len(top)]
        )
        check(
            "stats",
            f"{name}: top sources are the true top sources with true counts",
            ok,
            str(top[:3]),
        )
        tcounts = Counter(
            dict(o.rows(f"SELECT event_type, count(*) FROM alerts {where} GROUP BY 1", *params))
        )
        ttop = [(r["type"], r["count"]) for r in got["top_event_types"]]
        check(
            "stats",
            f"{name}: top event types are the true top with true counts",
            all(tcounts[t] == n for t, n in ttop)
            and [n for _, n in ttop] == sorted(tcounts.values(), reverse=True)[: len(ttop)],
        )
        check(
            "invariant",
            f"{name}: severities add up to the total",
            sum(got["by_severity"].values()) == got["total_alerts"],
        )

    print("== honeypot_list hit counts against GROUP BY honeypot_id")
    listing = await H.honeypot_list()
    listed = listing["honeypots"]
    want = dict(
        o.rows("SELECT honeypot_id, count(*) FROM alerts WHERE honeypot_id IS NOT NULL GROUP BY 1")
    )
    got_hits = {h["id"]: h["hits"] for h in listed if h["hits"]}
    check(
        "sensors",
        "every sensor is listed",
        listing["count"] == len(listed) == o.one("SELECT count(*) FROM honeypots"),
        f"count {listing['count']}, rows {len(listed)}",
    )
    check("sensors", "per-sensor hits", got_hits == want, f"{len(got_hits)} sensors vs {len(want)}")
    check(
        "invariant",
        "sensor hits + events with no sensor = all alerts",
        sum(h["hits"] for h in listed)
        + o.one("SELECT count(*) FROM alerts WHERE honeypot_id IS NULL")
        == total,
    )

    print("== soc_brief against the untriaged definition")
    brief = await D.soc_brief(since_hours=hours_ago(t_first) + 1, max_highlights=10)
    cut = stamp(datetime.now(UTC) - timedelta(hours=hours_ago(t_first) + 1))
    check(
        "brief",
        "volume matches",
        brief["volume"]["total_events"]
        == o.one("SELECT count(*) FROM alerts WHERE timestamp >= ?", cut),
    )
    for sev in ("critical", "high"):
        want_open = o.one(
            "SELECT count(*) FROM alerts WHERE timestamp >= ? AND severity = ? AND acknowledged = 0",
            cut,
            sev,
        )
        check(
            "brief",
            f"untriaged {sev}",
            brief["untriaged_by_severity"][sev] == want_open,
            f"{brief['untriaged_by_severity'][sev]} != {want_open}",
        )
    # needs_attention is one example per (severity, event type): CRITICAL types before HIGH ones
    # and, within a severity, the type with the fewest open alerts first.
    open_types = sorted(
        o.rows(
            "SELECT severity, event_type, count(*) FROM alerts WHERE timestamp >= ? "
            "AND severity IN ('critical', 'high') AND acknowledged = 0 GROUP BY 1, 2",
            cut,
        ),
        key=lambda r: (0 if r[0] == "critical" else 1, r[2], r[1]),
    )
    want_queue = [(r[0], r[1]) for r in open_types][:10]
    got_queue = [(a["severity"], a["event_type"]) for a in brief["needs_attention"]]
    check(
        "brief",
        "needs_attention is one open example per event type, CRITICAL first, rarest type first",
        got_queue == want_queue,
        f"{got_queue[:3]} vs {want_queue[:3]}",
    )
    got_ids = [a["alert_id"] for a in brief["needs_attention"]]
    check(
        "brief",
        "each example is a real open alert of that severity and event type",
        all(
            o.rows(
                "SELECT 1 FROM alerts WHERE id = ? AND severity = ? AND event_type = ? "
                "AND acknowledged = 0 AND timestamp >= ?",
                a["alert_id"],
                a["severity"],
                a["event_type"],
                cut,
            )
            for a in brief["needs_attention"]
        ),
        str(got_ids[:5]),
    )
    check(
        "brief",
        "needs_attention_total is the open CRITICAL + HIGH count",
        brief["needs_attention_total"] == sum(r[2] for r in open_types),
        f"{brief['needs_attention_total']} vs {sum(r[2] for r in open_types)}",
    )

    print("== alerts_recent filters against ORDER BY ... LIMIT")
    busiest = o.rows("SELECT source_ip, count(*) c FROM alerts GROUP BY 1 ORDER BY c DESC LIMIT 1")[
        0
    ][0]
    sensor_id, sensor_name = o.rows(
        "SELECT h.id, h.name FROM honeypots h JOIN alerts a ON a.honeypot_id = h.id GROUP BY h.id ORDER BY count(*) ASC LIMIT 1"
    )[0]
    cases = [
        ("severity=critical", {"severity": "critical"}, "severity = 'critical'", ()),
        ("source_ip", {"source_ip": busiest}, "source_ip = ?", (busiest,)),
        ("event_type", {"event_type": "redis_config_set"}, "event_type = ?", ("redis_config_set",)),
        ("honeypot_name", {"honeypot_name": sensor_name}, "honeypot_id = ?", (sensor_id,)),
        (
            "severity+ip",
            {"severity": "high", "source_ip": busiest},
            "severity = 'high' AND source_ip = ?",
            (busiest,),
        ),
    ]
    for label, kwargs, cond, params in cases:
        got = await A.alerts_recent(limit=30, **kwargs)
        want_ts = [
            r[0]
            for r in o.rows(
                f"SELECT timestamp FROM alerts WHERE {cond} ORDER BY timestamp DESC, id DESC LIMIT 30",
                *params,
            )
        ]
        got_ts = [stamp(datetime.fromisoformat(a["timestamp"])) for a in got["alerts"]]
        check(
            "recent",
            f"{label}: the newest matching rows, newest first",
            got_ts == want_ts,
            f"{len(got_ts)} vs {len(want_ts)}",
        )

    print("== alerts_search against LIKE over source, event type and the payload")
    for q in ("wget", "root", "198.51.100", "CONFIG SET"):
        got = await A.alerts_search(query=q, limit=40)
        want_ts = [
            r[0]
            for r in o.rows(
                "SELECT timestamp FROM alerts WHERE instr(source_ip, ?) > 0 OR instr(event_type, ?) > 0 "
                "OR instr(CAST(payload AS TEXT), ?) > 0 ORDER BY id DESC LIMIT 40",  # ids rise with time
                q,
                q,
                q,
            )
        ]
        got_ts = [stamp(datetime.fromisoformat(a["timestamp"])) for a in got["alerts"]]
        # The reply is cut to a readable size, and says so in `note`: what it shows must still be
        # exactly the newest rows, a prefix of the SQL answer.
        check(
            "search",
            f"'{q}': the newest rows that contain it (case-sensitive), cut only with a note",
            bool(got_ts) == bool(want_ts)
            and got_ts == want_ts[: len(got_ts)]
            and (len(got_ts) == len(want_ts) or bool(got.get("note"))),
            f"{len(got_ts)} vs {len(want_ts)}",
        )

    print("== threat_timeline against the window and ordering")
    tl_hours = int(hours_ago(t_first)) + 1
    tl = await N.threat_timeline(hours=tl_hours)
    tl_cut = stamp(datetime.now(UTC) - timedelta(hours=tl_hours))
    stamps = [e["timestamp"] for e in tl["events"]]
    check("timeline", "entries are oldest first", stamps == sorted(stamps))
    check(
        "timeline",
        "events_in_window is the exact SQL count for the window",
        tl["events_in_window"] == o.one("SELECT count(*) FROM alerts WHERE timestamp >= ?", tl_cut),
        f"{tl['events_in_window']}",
    )
    check(
        "timeline",
        "shows at most its 40 entries, and fewer events than the window when it is cut",
        tl["count"] == len(tl["events"]) <= 40
        and sum(e.get("repeated", 1) for e in tl["events"]) <= tl["events_in_window"],
        f"{tl['count']} entries",
    )
    newest = o.one("SELECT max(timestamp) FROM alerts WHERE timestamp >= ?", tl_cut)
    last_entry = tl["events"][-1] if tl["events"] else {}
    check(
        "timeline",
        "the last entry ends at the newest alert in the window",
        stamp(datetime.fromisoformat(last_entry.get("until", last_entry.get("timestamp", ""))))
        == newest
        if last_entry
        else newest is None,
        f"{last_entry} vs {newest}",
    )

    print("== analyze_attacker for real sources against SQL")
    sample = [
        r[0]
        for r in o.rows("SELECT source_ip FROM alerts GROUP BY 1 ORDER BY count(*) DESC LIMIT 3")
    ]
    sample += [
        r[0]
        for r in o.rows(
            "SELECT source_ip FROM alerts GROUP BY 1 HAVING count(*) BETWEEN 5 AND 50 ORDER BY random() LIMIT 3"
        )
    ]
    for ip in sample:
        if ipaddress.ip_address(ip).is_private:
            continue
        got = await N.analyze_attacker(ip=ip)
        n, lo, hi = o.rows(
            "SELECT count(*), min(timestamp), max(timestamp) FROM alerts WHERE source_ip = ?", ip
        )[0]
        ok = (
            got["total_events"] == n
            and datetime.fromisoformat(got["first_seen"]).replace(tzinfo=None)
            == datetime.fromisoformat(lo)
            and datetime.fromisoformat(got["last_seen"]).replace(tzinfo=None)
            == datetime.fromisoformat(hi)
        )
        check(
            "attacker",
            f"{ip}: {n:,} events, first and last seen",
            ok,
            f"{got['total_events']} vs {n}",
        )
        check(
            "attacker",
            f"{ip}: severity and event-type breakdowns",
            got["severity_breakdown"]
            == sev_dict(
                o.rows("SELECT severity, count(*) FROM alerts WHERE source_ip = ? GROUP BY 1", ip)
            )
            and event_breakdown_ok(
                got["event_breakdown"],
                dict(
                    o.rows(
                        "SELECT event_type, count(*) FROM alerts WHERE source_ip = ? GROUP BY 1",
                        ip,
                    )
                ),
            ),
        )
    j = await N.analyze_attacker_journey(ip=sample[0], hours=int(hours_ago(t_first)) + 1)
    check(
        "attacker",
        "journey total equals SQL for the busiest source",
        j.get("total_alerts")
        == o.one("SELECT count(*) FROM alerts WHERE source_ip = ?", sample[0]),
        str(j.get("total_alerts")),
    )

    print("== export_blocklist against the offender definition")
    hours = int(hours_ago(t_first)) + 1
    res = await N.export_blocklist(format="plain", hours=hours, min_hits=200)
    cutoff = stamp(datetime.now(UTC) - timedelta(hours=hours))
    want = {
        ip: n
        for ip, n in o.rows(
            "SELECT source_ip, count(*) FROM alerts WHERE timestamp >= ? GROUP BY 1 HAVING count(*) >= 200",
            cutoff,
        )
        if ipaddress.ip_address(ip).is_global
    }
    check(
        "blocklist",
        "the offenders are exactly the public sources with >= 200 hits",
        res.get("ip_count") == len(want),
        f"{res.get('ip_count')} vs {len(want)}",
    )
    offender_hits = {t["ip"]: t["hits"] for t in res.get("top_offenders", [])}
    check(
        "blocklist",
        "and their hit counts are true",
        all(want.get(ip) == n for ip, n in offender_hits.items()),
    )
    private = [
        ip
        for ip, _ in o.rows("SELECT source_ip, 1 FROM alerts GROUP BY 1 HAVING count(*) >= 200")
        if not ipaddress.ip_address(ip).is_global
    ]
    body = Path(res["path"]).read_text() if res.get("path") else ""
    check(
        "blocklist",
        f"{len(private)} private/internal source(s) with 200+ hits are NOT in the file",
        not any(ip in body.split() for ip in private),
    )

    print("== deception_coverage against the signature registry")
    cov = await D.deception_coverage()
    from honeypot_mcp.deception import capabilities as caps

    live_types = {t for (t,) in o.rows("SELECT DISTINCT type FROM honeypots")}
    check(
        "coverage",
        "every sensor type in the database is in the registry",
        live_types <= {c.type for c in caps.all_capabilities()},
        str(live_types),
    )
    check(
        "coverage",
        "reports a technique list",
        bool(cov.get("techniques") or cov.get("covered_techniques") or cov.get("tactics")),
        str(list(cov)[:6]),
    )

    print("== analyze_campaign against a raw GROUP BY (hour, event type, source)")
    # The tool shows only its top 10, so the full set is taken from the engine it calls (the hourly
    # rollup rows through detect_campaigns), which is what the raw SQL below is compared against.
    from honeypot_mcp.analysis.correlator import detect_campaigns, rolled_alerts
    from honeypot_mcp.storage import rollups
    from honeypot_mcp.storage.database import get_session

    async with get_session() as session:
        campaign_rows = await rollups.campaign_rows(session, None, 500_001)
    all_campaigns = await detect_campaigns(
        alerts=rolled_alerts(campaign_rows),
        window_minutes=0,
        min_sources=3,
        event_type_contains=None,
        involving_ip=None,
    )
    camp = await N.analyze_campaign(min_sources=3)
    per: dict[tuple[str, str], list[Any]] = {}
    for et, hour, ip, n in o.rows(
        "SELECT event_type, strftime('%Y-%m-%d %H:00:00', timestamp), source_ip, count(*) "
        "FROM alerts GROUP BY 1, 2, 3"
    ):
        group = per.setdefault((et, hour), [set(), 0])
        group[0].add(ip)
        group[1] += n
    # An hour in which at least 3 sources hit one event type is a window; windows of one event
    # type that share their sources are merged into one campaign, none is dropped.
    hour_windows = {key: g for key, g in per.items() if len(g[0]) >= 3}
    want_events = sum(n for _, n in hour_windows.values())
    union_by_type: dict[str, set[str]] = {}
    for (et, _hour), (ips, _n) in hour_windows.items():
        union_by_type.setdefault(et, set()).update(ips)
    check(
        "campaigns",
        "every hour with 3+ sources on one event type is in exactly one campaign",
        sum(c["occurrences"] for c in all_campaigns) == len(hour_windows),
        f"{sum(c['occurrences'] for c in all_campaigns)} vs {len(hour_windows)}",
    )
    check(
        "campaigns",
        "the same number of events inside them as the raw SQL",
        sum(c["total_events"] for c in all_campaigns) == want_events,
        f"{sum(c['total_events'] for c in all_campaigns)} vs {want_events}",
    )
    check(
        "campaigns",
        "campaign event types and sources are exactly those of the raw SQL hour_windows",
        {c["event_type"] for c in all_campaigns} == set(union_by_type)
        and all(
            set(c["source_ips"]) <= union_by_type[c["event_type"]]
            and len(c["source_ips"])
            <= c["unique_source_ips"]
            <= len(union_by_type[c["event_type"]])
            for c in all_campaigns
        )
        and all(
            set().union(*(set(c["source_ips"]) for c in all_campaigns if c["event_type"] == et))
            <= ips
            for et, ips in union_by_type.items()
        ),
    )
    shown = camp["campaigns"]
    pool = Counter(
        (c["event_type"], c["unique_source_ips"], c["total_events"]) for c in all_campaigns
    )
    shown_keys = Counter(
        (c["event_type"], c["unique_source_ips"], c["total_events"]) for c in shown
    )
    check(
        "campaigns",
        "the tool reports the true total and shows the top 10 of them by score",
        camp["campaigns_total"] == len(all_campaigns)
        and camp["count"] == len(shown) == min(10, len(all_campaigns))
        and [c["score"] for c in shown] == sorted((c["score"] for c in shown), reverse=True)
        and not shown_keys - pool
        and [c["score"] for c in shown]
        == [c["score"] for c in sorted(all_campaigns, key=lambda c: -c["score"])[: len(shown)]],
        f"total {camp['campaigns_total']} vs {len(all_campaigns)}, shown {len(shown)}",
    )

    print("== fingerprint_clusters against json_extract over ssh_client_kex")
    cutoff = stamp(datetime.now(UTC) - timedelta(hours=2160))
    want_fp = {
        r[0]: r
        for r in o.rows(
            "SELECT json_extract(payload,'$.hassh'), count(distinct source_ip), "
            "count(distinct json_extract(payload,'$.session')), min(timestamp), max(timestamp) "
            "FROM alerts WHERE event_type='ssh_client_kex' AND timestamp >= ? "
            "AND json_extract(payload,'$.hassh') IS NOT NULL GROUP BY 1",
            cutoff,
        )
    }
    # The tool shows its 10 largest groups; the full comparison uses the clustering it is built on.
    fp = await N.cluster_ssh_clients(2160, 1, 100)
    check(
        "clusters",
        "fingerprint count and no truncation",
        fp["fingerprints_seen"] == len(want_fp) and not fp["truncated"],
        f"{fp['fingerprints_seen']} vs {len(want_fp)}, truncated={fp['truncated']}",
    )
    bad = [
        c["hassh"]
        for c in fp["clusters"]
        if (r := want_fp.get(c["hassh"])) is None
        or (c["distinct_ips"], c["sessions"]) != (r[1], r[2])
        or c["first_seen"][:19].replace("T", " ") != r[3][:19]
        or c["last_seen"][:19].replace("T", " ") != r[4][:19]
    ]
    check(
        "clusters",
        f"distinct IPs, sessions, first/last seen for {len(fp['clusters'])} clusters",
        not bad,
        str(bad[:3]),
    )
    fp_tool = await N.fingerprint_clusters(hours=2160, min_sources=1)
    fp_top = [(c["distinct_ips"], c["sessions"]) for c in fp["clusters"][:10]]
    check(
        "clusters",
        "the tool shows the 10 largest groups and reports how many match",
        fp_tool["clusters_matching"] == fp["clusters_matching"] == len(want_fp)
        and fp_tool["count"] == len(fp_tool["clusters"]) == min(10, len(want_fp))
        and [(c["distinct_ips"], c["sessions"]) for c in fp_tool["clusters"]] == fp_top,
        f"{fp_tool['clusters_matching']} matching, {fp_tool['count']} shown",
    )

    print("== attack_summary against the alert table")
    summary = await N.attack_summary()
    check(
        "attack",
        "total alerts",
        summary["total_alerts"] == total,
        f"{summary['total_alerts']} vs {total}",
    )
    check(
        "attack",
        "event types seen",
        summary["event_types_seen"] == o.one("SELECT count(DISTINCT event_type) FROM alerts"),
        str(summary["event_types_seen"]),
    )

    for what, why in (
        (
            "map_ttps",
            "a regex-to-ATT&CK table: correctness is the mapping table itself, covered by test_mitre_dashboard",
        ),
    ):
        ROWS.append(("not covered", what, True, why))
        print(f"  [NOTE] not covered: {what}: {why}")

    await close_db()
    shutil.rmtree(tmp, ignore_errors=True)
    failed = [r for r in ROWS if not r[2]]
    lines = [
        "# Oracle report\n",
        f"Backup `{args.backup}`: {total:,} alerts, {first} to {last}. {len(ROWS)} checks, {len(failed)} failed.\n",
        "| group | check | result |",
        "|---|---|---|",
    ]
    lines += [f"| {g} | {w} | {'PASS' if ok else 'FAIL ' + d} |" for g, w, ok, d in ROWS]
    if args.out:
        Path(args.out).write_text("\n".join(lines) + "\n")
    print(f"\n{len(ROWS)} checks, {len(failed)} failed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--backup",
        required=True,
        help="a backup's honeypot_mcp.db (never modified; a copy is used)",
    )
    ap.add_argument("--out", help="write a markdown report here")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
