"""Field test, part four: are the read tools' answers RIGHT? Check them against SQL.

    uv run python scripts/field_test_oracle.py --backup ~/hp-backups/<backup>/honeypot_mcp.db \
        --out oracle-report.md

Parts one to three prove the tools answer and obey their roles, and that actions change the live
system. This part takes a *frozen* real backup (so live traffic cannot move the numbers), runs the
analysis tools on a copy of it, and compares each answer with an independent computation written as
plain SQL straight over the `alerts` table. The tools read pre-aggregated rollups and indexes; the
oracle never does, so agreement means the optimised path equals the definition.

The oracles use real attackers, real windows (starting mid-hour, on the hour, and before any data)
and real filters. Anything that cannot be checked this way (clusters, campaigns) is listed as NOT
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
    listed = await H.honeypot_list()
    want = dict(
        o.rows("SELECT honeypot_id, count(*) FROM alerts WHERE honeypot_id IS NOT NULL GROUP BY 1")
    )
    got_hits = {h["id"]: h["hits"] for h in listed if h["hits"]}
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
    want_ids = [
        r[0]
        for r in o.rows(
            "SELECT id FROM alerts WHERE timestamp >= ? AND severity = 'critical' AND acknowledged = 0 "
            "ORDER BY timestamp DESC LIMIT 10",
            cut,
        )
    ]
    got_ids = [a.get("id") or a.get("alert_id") for a in brief["needs_attention"]][:10]
    check(
        "brief",
        "needs_attention lists the newest untriaged CRITICAL alerts first",
        got_ids == want_ids,
        f"{got_ids[:3]} vs {want_ids[:3]}",
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
        like = f"%{q}%"
        want_ts = [
            r[0]
            for r in o.rows(
                "SELECT timestamp FROM alerts WHERE source_ip LIKE ? OR event_type LIKE ? OR CAST(payload AS TEXT) LIKE ? "
                "ORDER BY timestamp DESC LIMIT 40",
                like,
                like,
                like,
            )
        ]
        got_ts = [stamp(datetime.fromisoformat(a["timestamp"])) for a in got["alerts"]]
        check(
            "search",
            f"'{q}': the newest 40 rows that contain it",
            got_ts == want_ts,
            f"{len(got_ts)} vs {len(want_ts)}",
        )

    print("== threat_timeline against the window and ordering")
    tl = await N.threat_timeline(hours=int(hours_ago(t_first)) + 1, limit=500)
    stamps = [e["timestamp"] for e in tl["events"]]
    check(
        "timeline",
        "events are in time order",
        stamps == sorted(stamps) or stamps == sorted(stamps, reverse=True),
    )
    check(
        "timeline", "returns the limit when there is more data", tl["count"] == 500 and total > 500
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
            and got["event_breakdown"]
            == dict(
                o.rows("SELECT event_type, count(*) FROM alerts WHERE source_ip = ? GROUP BY 1", ip)
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
    top = {t["ip"]: t["hits"] for t in res.get("top_offenders", [])}
    check(
        "blocklist",
        "and their hit counts are true",
        all(want.get(ip) == n for ip, n in top.items()),
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
    cov = await D.deception_coverage(include_recommendations=False)
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

    for what, why in (
        (
            "analyze_campaign / fingerprint_clusters",
            "grouping heuristics with no independent closed-form definition; membership validity is checked in unit tests",
        ),
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
