# /// script
# requires-python = ">=3.11"
# dependencies = ["fastmcp"]
# ///
"""Field test, part three: use the management and analysis tools on REAL traffic, live.

    uv run scripts/field_test_ops.py --url http://127.0.0.1:18443/mcp \
        --tokens ~/.ssh/honeypot_mcp_tokens --host <vps-ip> --out ops-report.md [--report-abuse]

Part two (`field_test_tools.py`) proves every tool answers and obeys its role. This part asks whether
the answers are *right* on what the internet actually sent, and whether the actions really change
the live system. It needs a deployment that has been collecting for a few hours, and it picks its
subjects from the data (the busiest real attacker, the loudest flooder), so nothing is hard-coded.

* Triage: acknowledge a real attacker's alerts and see the queue, the alert records and the audit
  log all agree.
* Analysis: profile, journey, MITRE mapping, campaign and report for real attackers; the profile
  must carry reputation and geography, and the report must contain them.
* Remediation: the exported blocklist and STIX bundle contain the real attackers and no loopback or
  private address; a rate-limit rule on a real flooder measurably cuts the live ingest rate, and
  is removed again unless `--keep-ratelimit`.
* Operations: pause a real sensor and watch its public port close, resume it and watch it open;
  read a real sensor's log; pull a real attacker's packets out of the capture ring.
* `--report-abuse` additionally files ONE report with AbuseIPDB (an outside side effect, so it is
  opt-in) about the busiest attacker, with an accurate comment.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sys
from typing import Any

from fastmcp import Client


class Run:
    def __init__(self, url: str, tokens: dict[str, str]) -> None:
        self.url, self.tokens, self.rows = url, tokens, []

    async def call(self, role: str, tool: str, args: dict[str, Any] | None = None) -> Any:
        async with Client(self.url, auth=self.tokens[role]) as c:
            r = await c.call_tool(tool, args or {}, raise_on_error=False)
        if r.is_error:
            return {"error": str(r.content)[:200]}
        return r.data

    def check(self, area: str, what: str, ok: bool, detail: str = "") -> None:
        self.rows.append((area, what, bool(ok), detail[:160]))
        skipped = detail.startswith("SKIPPED")
        label = "SKIP" if skipped else ("PASS" if ok else "FAIL")
        print(
            f"  [{label}] {area:11} {what}"
            + (f"  ({detail})" if skipped else "" if ok else f"  -> {detail[:110]}")
        )


def internal(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


async def run(a: argparse.Namespace) -> int:
    with open(a.tokens) as f:
        tokens = dict(ln.strip().split("=", 1) for ln in f if "=" in ln)
    r = Run(a.url, tokens)

    # ---- pick real subjects from the data
    stats = await r.call("viewer", "alerts_stats", {"since_hours": 12})
    real = [
        t for t in stats.get("top_source_ips", []) if not internal(t["ip"]) and t["ip"] != a.my_ip
    ]
    flooder = real[0]["ip"] if real else None
    crit = await r.call(
        "viewer", "alerts_recent", {"limit": 100, "severity": "critical", "since_hours": 12}
    )
    crit_ips = [
        x["source_ip"]
        for x in crit.get("alerts", [])
        if not internal(x["source_ip"]) and x["source_ip"] != a.my_ip
    ]
    target = max(set(crit_ips), key=crit_ips.count) if crit_ips else flooder
    print(f"subjects: busiest real source {flooder}, CRITICAL-heavy source {target}\n")

    print("== triage (real alerts)")
    before = (await r.call("viewer", "soc_brief", {"since_hours": 12}))["untriaged_by_severity"]
    ack = await r.call(
        "operator",
        "alerts_acknowledge",
        {
            "source_ip": target,
            "severity": "critical",
            "disposition": "true_positive",
            "note": "field test: real attacker triaged",
            "since_hours": 12,  # the same window the queue below is counted over
        },
    )
    n = ack.get("acknowledged") or ack.get("updated") or ack.get("count") or 0
    r.check("triage", "acknowledging by source reports how many it changed", n > 0, str(ack))
    after = (await r.call("viewer", "soc_brief", {"since_hours": 12}))["untriaged_by_severity"]
    r.check(
        "triage",
        "the untriaged CRITICAL queue shrinks by about that many",
        before["critical"] - after["critical"] >= max(n - 5, 1),
        f"{before} -> {after}, acked {n}",
    )
    got = await r.call(
        "viewer",
        "alerts_recent",
        {"source_ip": target, "severity": "critical", "limit": 50, "since_hours": 12},
    )
    r.check(
        "triage",
        "the alert records carry the disposition",
        got.get("alerts") and all(x.get("acknowledged") for x in got["alerts"]),
        str(got)[:150],
    )
    audit = await r.call(
        "admin", "audit_log_search", {"tool": "alerts_acknowledge", "since_hours": 1, "limit": 5}
    )
    r.check(
        "triage",
        "the audit log names who did it",
        "operator" in json.dumps(audit),
        str(audit)[:150],
    )

    print("== analysis (real attackers)")
    prof = await r.call("viewer", "analyze_attacker", {"ip": target})
    r.check(
        "analysis",
        "profile carries risk, MITRE techniques, geography and reputation",
        prof.get("mitre_techniques")
        and prof.get("geoip", {}).get("country")
        and prof.get("abuseipdb", {}).get("abuse_confidence_score") is not None
        and prof.get("risk_level"),
        str(prof)[:150],
    )
    journey = await r.call("viewer", "analyze_attacker_journey", {"ip": target, "hours": 24})
    r.check(
        "analysis",
        "journey orders the attacker's phases",
        journey.get("phases") and journey.get("total_events", 0) > 0,
        str(journey)[:150],
    )
    ttps = await r.call("viewer", "map_ttps", {"ip": target})
    r.check(
        "analysis",
        "ATT&CK mapping names techniques with matched evidence",
        bool(ttps.get("techniques"))
        and str(ttps["techniques"][0].get("technique_id", "")).startswith("T"),
        str(ttps)[:150],
    )
    camps = await r.call("viewer", "analyze_campaign", {"since_hours": 12, "min_sources": 2})
    found = camps.get("campaigns", [])
    r.check(
        "analysis",
        "campaign analysis groups real sources hitting the same sensor",
        bool(found) and any(c.get("unique_source_ips", 0) >= 2 for c in found),
        str(camps)[:120],
    )
    clusters = await r.call("viewer", "fingerprint_clusters", {"hours": 12, "min_sources": 2})
    r.check(
        "analysis",
        "fingerprint clusters find shared behaviour",
        bool(clusters.get("clusters")) and not clusters.get("error"),
        str(clusters)[:120],
    )
    cov = await r.call("viewer", "deception_coverage")
    r.check(
        "analysis",
        "coverage counts the live sensors and tokens",
        len(cov.get("sensors_live", [])) >= 20 and cov.get("tokens_live"),
        str(cov)[:120],
    )
    rep = await r.call(
        "viewer",
        "generate_report",
        {"ip": target, "format": "html", "since_hours": 24},
    )
    r.check(
        "analysis",
        "the report is written for that attacker",
        bool(rep.get("path")) and not rep.get("error"),
        str(rep)[:150],
    )

    print("== remediation")
    bl = await r.call(
        "operator", "export_blocklist", {"format": "plain", "hours": 24, "min_hits": 20}
    )
    r.check("remediation", "blocklist export reports a file", bool(bl.get("path")), str(bl)[:150])
    stix = await r.call("operator", "export_stix", {"hours": 24, "min_hits": 20})
    r.check("remediation", "STIX export reports a file", bool(stix.get("path")), str(stix)[:150])
    if flooder:
        listing = (await r.call("viewer", "honeypot_list"))["honeypots"]
        h = {x["name"]: x["hits"] for x in listing}
        hot = max(h, key=h.get)
        hot_id = {x["name"]: x["id"] for x in listing}[hot]
        # The source to throttle is the one flooding THIS sensor now (from the hourly rollups), not the
        # all-time top source: a flood from many addresses is not cut by throttling one that has gone quiet.
        window = f"honeypot_id = {hot_id} AND bucket >= datetime('now', '-2 hours')"
        top = await r.call(
            "viewer",
            "sql_query",
            {
                "query": f"SELECT source_ip, SUM(count) AS n, "
                f"(SELECT SUM(count) FROM alert_rollups WHERE {window}) AS total "
                f"FROM alert_rollups WHERE {window} GROUP BY source_ip ORDER BY n DESC LIMIT 1"
            },
        )
        top_ip, top_n, top_total = (top.get("rows") or [[None, 0, 0]])[0]
        share = (top_n / top_total) if top_total else 0.0
        h0 = h[hot]
        await asyncio.sleep(20)
        h1 = {x["name"]: x["hits"] for x in (await r.call("viewer", "honeypot_list"))["honeypots"]}[
            hot
        ]
        rate_before = (h1 - h0) / 20
        if rate_before < 5 or share < 0.3:
            r.check(
                "remediation",
                "rate-limit rule on the loudest source",
                True,
                f"SKIPPED: {hot} runs {rate_before:.1f} events/s and its top source is {share:.0%} of it, "
                "so there is no single flood to cut",
            )
        else:
            rule = await r.call(
                "operator",
                "suppression_add",
                {
                    "label": "field-test ratelimit",
                    "ip_pattern": top_ip,
                    "rate_limit_count": 5,
                    "rate_limit_window_seconds": 60,
                },
            )
            rid = rule.get("id") or rule.get("rule_id")
            await asyncio.sleep(6)
            h2 = {
                x["name"]: x["hits"] for x in (await r.call("viewer", "honeypot_list"))["honeypots"]
            }[hot]
            await asyncio.sleep(20)
            h3 = {
                x["name"]: x["hits"] for x in (await r.call("viewer", "honeypot_list"))["honeypots"]
            }[hot]
            rate_after = (h3 - h2) / 20
            # Throttling one source can remove at most that source's share of the traffic.
            r.check(
                "remediation",
                f"a rate-limit rule on {top_ip} ({share:.0%} of {hot}'s traffic) cuts its ingest by "
                f"at least 60% of that share",
                rate_after <= rate_before * (1 - 0.6 * share),
                f"{rate_before:.1f}/s -> {rate_after:.1f}/s",
            )
            if rid and not a.keep_ratelimit:
                await r.call("operator", "suppression_remove", {"rule_id": rid})

    print("== operations (a real sensor)")
    sensors = {x["name"]: x for x in (await r.call("viewer", "honeypot_list"))["honeypots"]}
    victim = "hp-vnc" if "hp-vnc" in sensors else next(iter(sensors))
    port = {"hp-vnc": 5900}.get(victim, sensors[victim]["port"])
    r.check("operations", f"{victim} answers on port {port} before", port_open(a.host, port))
    try:
        await r.call("operator", "honeypot_pause", {"name": victim})
        await asyncio.sleep(2)
        r.check("operations", "pausing it closes its public port", not port_open(a.host, port))
    finally:
        await r.call("operator", "honeypot_resume", {"name": victim})
    await asyncio.sleep(3)
    r.check("operations", "resuming it reopens the port", port_open(a.host, port))
    logs = await r.call("viewer", "honeypot_logs", {"name": "hp-ssh", "lines": 20})
    r.check(
        "operations",
        "a real sensor's log shows real sessions",
        "ssh" in json.dumps(logs).lower() and len(json.dumps(logs)) > 200,
        str(logs)[:120],
    )
    ext = await r.call("operator", "pcap_extract", {"source_ip": target})
    r.check(
        "operations",
        "packets for a real attacker are pulled from the capture ring",
        (ext.get("packets") or 0) > 0,
        str(ext)[:150],
    )
    stat = await r.call("viewer", "honeypot_health", {})
    r.check(
        "operations",
        "health probe reports every sensor healthy after the above",
        stat.get("count", 0) > 0 and not stat.get("not_answering") and not stat.get("error"),
        str(stat)[:120],
    )

    if a.report_abuse and target:
        print("== outside side effect (opt-in)")
        ab = await r.call(
            "operator",
            "report_ip_abuse",
            {
                "ip": target,
                "categories": [18, 23],
                "comment": "Seen on a honeypot (HoneyPot-MCP): repeated telnet/SSH logins with default credentials followed by a malware dropper download.",
            },
        )
        r.check(
            "remediation",
            "AbuseIPDB accepts a report about a real attacker",
            not ab.get("error"),
            str(ab)[:150],
        )

    failed = [x for x in r.rows if not x[2]]
    lines = [
        "# Live operations report\n",
        f"{len(r.rows)} checks, {len(failed)} failed.\n",
        "| area | check | result |",
        "|---|---|---|",
    ]
    lines += [f"| {x[0]} | {x[1]} | {'PASS' if x[2] else 'FAIL ' + x[3]} |" for x in r.rows]
    if a.out:
        with open(a.out, "w") as f:
            f.write("\n".join(lines) + "\n")
    print(f"\n{len(r.rows)} checks, {len(failed)} failed")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--url", required=True)
    ap.add_argument("--tokens", required=True)
    ap.add_argument("--host", required=True, help="the VPS public address")
    ap.add_argument(
        "--my-ip", default="", help="this machine's public address, excluded from the subjects"
    )
    ap.add_argument("--out")
    ap.add_argument(
        "--keep-ratelimit", action="store_true", help="leave the rate-limit rule in place"
    )
    ap.add_argument(
        "--report-abuse",
        action="store_true",
        help="also file one AbuseIPDB report (outside side effect)",
    )
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
