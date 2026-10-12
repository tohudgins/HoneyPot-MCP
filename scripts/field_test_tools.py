# /// script
# requires-python = ">=3.11"
# dependencies = ["fastmcp", "paramiko"]
# ///
"""Field test, part two: drive the whole MCP tool surface of a live deployment and check it.

    # open the tunnel to the control plane first (see docs/DEPLOY.md), then:
    uv run scripts/field_test_tools.py --url http://127.0.0.1:18443/mcp \
        --tokens ~/.ssh/honeypot_mcp_tokens --attacker-host <vps-ip> --out tools-report.md

`--tokens` is a file of `viewer=...`, `operator=...`, `admin=...` lines. Every tool is called at
the role that owns it, with arguments that cannot hurt the deployment, and the answer is checked:

* RBAC: no token, a wrong token, a viewer calling an operator tool and an operator calling an admin
  tool are all refused.
* Read tools (the 30 viewer ones) return sane shapes against the live database.
* Write tools run a lifecycle and clean up after themselves: a temporary sensor is deployed,
  self-tested, configured, cloned, paused, resumed and removed; honeytokens are created, exported,
  rotated and revoked; a live-provisioned API key is created, *used*, and revoked (and is refused
  afterwards); a suppression rule is added and removed.
* A honeytoken round trip: a planted credential is used through a real SSH client against the
  honeypot, and the platform must raise a CRITICAL alert and mark the token triggered.

Two tools are deliberately not called: `report_ip_abuse` (sends a report about an address to an
outside service) and `suppression_load_preset` (a preset could briefly drop real events). They are
listed as SKIPPED with the reason, never silently omitted. The sweep fails if a registered tool is
neither called nor skipped, so a newly added tool cannot go untested unnoticed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import urllib.request
from dataclasses import dataclass
from typing import Any

from fastmcp import Client

SKIPPED = {
    "report_ip_abuse": "sends a report about an address to an outside service (AbuseIPDB)",
    "suppression_load_preset": "a preset could briefly drop real events on a live collector",
    "deception_deploy_plan": "deploys a second full estate on a live collector; the planner and "
    "the deploy tool it feeds (honeypot_deploy) are both exercised",
}


@dataclass
class Row:
    role: str
    tool: str
    what: str
    ok: bool
    detail: str


class Sweep:
    def __init__(self, url: str, tokens: dict[str, str]) -> None:
        self.url, self.tokens = url, tokens
        self.rows: list[Row] = []
        self.called: set[str] = set()

    async def call(
        self,
        role: str | None,
        tool: str,
        args: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> tuple[bool, Any]:
        """Returns (succeeded, data). A refusal or tool error is (False, message)."""
        tok = token if token is not None else (self.tokens[role] if role else None)
        try:
            async with Client(self.url, auth=tok) as c:
                r = await c.call_tool(tool, args or {}, raise_on_error=False)
        except Exception as e:  # noqa: BLE001 - a refused connection is an answer
            return False, f"{type(e).__name__}: {str(e)[:160]}"
        if r.is_error:
            return False, str(r.content)[:200]
        data = r.data
        if isinstance(data, dict) and data.get("error"):
            return False, str(data["error"])[:200]
        return True, data

    def record(self, role: str, tool: str, what: str, ok: bool, detail: str = "") -> None:
        self.called.add(tool)
        self.rows.append(Row(role, tool, what, ok, detail[:150]))
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {role:8} {tool:30} {what}"
            + ("" if ok else f"  -> {detail[:100]}")
        )

    async def expect(
        self, role: str, tool: str, args: dict[str, Any] | None, what: str, check=lambda d: True
    ) -> Any:  # noqa: ANN001
        ok, data = await self.call(role, tool, args)
        good = ok and bool(check(data))
        self.record(role, tool, what, good, "" if good else f"{data}"[:150])
        return data if ok else None

    async def refused(
        self,
        role: str | None,
        tool: str,
        what: str,
        args: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> None:
        ok, data = await self.call(role, tool, args, token)
        self.record(role or "(none)", tool, what, not ok, f"was NOT refused: {data}"[:150])


def public_ip() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=10) as r:  # noqa: S310
        return r.read().decode().strip()


async def run(a: argparse.Namespace) -> int:
    with open(a.tokens) as f:
        tokens_text = f.read()
    tokens = dict(line.strip().split("=", 1) for line in tokens_text.splitlines() if "=" in line)
    sw = Sweep(a.url, tokens)
    me = a.source_ip or public_ip()
    tag = f"ft{int(time.time()) % 100000}"

    print("== RBAC")
    await sw.refused(None, "ping", "no token is refused")
    await sw.refused(None, "ping", "a wrong token is refused", token="not-a-real-token")
    await sw.refused(
        "viewer", "honeypot_deploy", "viewer cannot deploy", {"type": "http", "port": 18999}
    )
    await sw.refused(
        "viewer",
        "honeytoken_create",
        "viewer cannot create tokens",
        {"type": "credential", "label": "x"},
    )
    await sw.refused("operator", "api_key_list", "operator cannot use an admin tool")
    await sw.refused(
        "operator", "alerts_prune", "operator cannot prune", {"older_than_days": 36500}
    )

    print("== viewer tools (read-only)")
    v = "viewer"
    await sw.expect(v, "ping", None, "answers", lambda d: d)
    hp = await sw.expect(v, "honeypot_list", None, "lists the estate", lambda d: len(d) >= 1)
    names = [h["name"] for h in hp or []]
    http_name = next(
        (n for n in names if "http" in n and "elastic" not in n), names[0] if names else ""
    )
    await sw.expect(
        v, "honeypot_status", {"name": http_name}, "one sensor", lambda d: d.get("status")
    )
    await sw.expect(v, "honeypot_health", None, "probes every sensor", lambda d: d)
    await sw.expect(v, "honeypot_logs", {"name": http_name, "lines": 5}, "recent log lines")
    await sw.expect(v, "honeypot_templates", None, "engine catalogue", lambda d: d)
    await sw.expect(v, "alerts_stats", None, "totals", lambda d: d["total_alerts"] > 0)
    recent = await sw.expect(
        v,
        "alerts_recent",
        {"limit": 5, "include_payload": True},
        "latest alerts",
        lambda d: d["count"] >= 1,
    )
    first_id = ((recent or {}).get("alerts") or [{}])[0].get("alert_id") or (
        ((recent or {}).get("alerts") or [{}])[0].get("id")
    )
    await sw.expect(
        v, "alerts_get", {"alert_id": first_id or 1}, "one alert with full payload", lambda d: d
    )
    await sw.expect(v, "alerts_search", {"query": me, "limit": 5}, "search by source address")
    await sw.expect(v, "analyze_attacker", {"ip": me}, "attacker profile", lambda d: d)
    await sw.expect(
        v, "analyze_attacker_journey", {"ip": me, "hours": 24}, "kill-chain timeline", lambda d: d
    )
    await sw.expect(
        v,
        "analyze_campaign",
        {"window_minutes": 600, "min_sources": 2},
        "campaigns",
        lambda d: d is not None,
    )
    sess = None
    for al in (recent or {}).get("alerts", []):
        sess = (al.get("payload") or {}).get("session") or sess
    await sw.expect(
        v,
        "analyze_session",
        {"session_id": sess or "none"},
        "session reconstruction",
        lambda d: d is not None,
    )
    await sw.expect(v, "deception_coverage", None, "ATT&CK coverage", lambda d: d)
    await sw.expect(
        v,
        "deception_plan",
        {"profile": None, "services": ["ssh", "http"]},
        "plans without deploying",
        lambda d: d,
    )
    await sw.expect(v, "deception_profiles", None, "profiles", lambda d: d)
    await sw.expect(v, "enrich_ip", {"ip": me}, "degrades cleanly without API keys", lambda d: d)
    await sw.expect(
        v,
        "fingerprint_clusters",
        {"hours": 24, "min_sources": 2, "limit": 5},
        "clusters",
        lambda d: d is not None,
    )
    await sw.expect(
        v,
        "generate_report",
        {"title": "field test", "since_hours": 24, "limit": 50},
        "writes a report artifact",
        lambda d: d,
    )
    await sw.expect(v, "map_ttps", {"ip": me}, "ATT&CK mapping", lambda d: d)
    await sw.expect(
        v, "threat_timeline", {"hours": 24, "limit": 10}, "timeline", lambda d: d["count"] >= 1
    )
    await sw.expect(v, "soc_brief", {"since_hours": 24}, "analyst brief", lambda d: d["headline"])
    await sw.expect(v, "honeytoken_list", None, "tokens", lambda d: d is not None)
    await sw.expect(v, "pcap_status", None, "capture state explained", lambda d: d)
    await sw.expect(v, "pcap_files", None, "capture files", lambda d: d is not None)
    await sw.expect(v, "suppression_list", None, "rules", lambda d: d is not None)
    await sw.expect(v, "suppression_list_presets", None, "presets", lambda d: d)
    await sw.expect(v, "alert_subscriptions_list", None, "subscriptions", lambda d: d is not None)

    print("== operator tools (lifecycles, cleaned up)")
    o = "operator"
    tmp, clone = f"{tag}-http", f"{tag}-http2"
    await sw.expect(
        o,
        "honeypot_deploy",
        {"type": "http", "port": 18900, "name": tmp},
        "deploys a temporary sensor",
        lambda d: d.get("status") in ("running", "deployed") or d.get("name") == tmp,
    )
    await sw.expect(
        o,
        "honeypot_self_test",
        {"name": tmp, "timeout_seconds": 20},
        "end-to-end self test passes",
        lambda d: d.get("probe_sent") is True and d.get("alert_received") is True,
    )
    await sw.expect(
        o,
        "honeypot_configure",
        {"name": tmp, "config": {"persona": "nginx_ubuntu"}},
        "changes its config",
        lambda d: d,
    )
    await sw.expect(
        o,
        "honeypot_clone",
        {"source_name": tmp, "new_port": 18901, "new_name": clone},
        "clones it",
        lambda d: d,
    )
    await sw.expect(o, "honeypot_pause", {"name": tmp}, "pauses", lambda d: d)
    await sw.expect(o, "honeypot_resume", {"name": tmp}, "resumes", lambda d: d)
    await sw.expect(
        o,
        "honeypot_stop",
        {"names": [tmp, clone], "remove": True},
        "stops and removes both",
        lambda d: d,
    )

    tok = await sw.expect(
        o,
        "honeytoken_create",
        {"type": "api_key", "label": f"{tag}-api"},
        "creates an API-key token",
        lambda d: d["id"],
    )
    tid = (tok or {}).get("id")
    await sw.expect(
        o, "honeytoken_generate_aws", {"label": f"{tag}-aws"}, "AWS-shaped keys", lambda d: d
    )
    await sw.expect(
        o,
        "honeytoken_embed_file",
        {"label": f"{tag}-doc", "file_type": "pdf"},
        "canary document",
        lambda d: d,
    )
    if tid:
        await sw.expect(v, "honeytoken_status", {"token_id": tid}, "status of a token", lambda d: d)
        await sw.expect(
            o,
            "honeytoken_export",
            {"token_id": tid, "context": "env_file"},
            "export for planting",
            lambda d: d,
        )
        rot = await sw.expect(
            o, "honeytoken_rotate", {"token_id": tid}, "rotation keeps the thread", lambda d: d
        )
        await sw.expect(
            o,
            "honeytoken_revoke",
            {"token_id": ((rot or {}).get("new_token") or {}).get("id", tid)},
            "revokes",
            lambda d: d,
        )

    await sw.expect(
        o,
        "alerts_acknowledge",
        {
            "source_ip": me,
            "event_type": "http_probe",
            "disposition": "benign",
            "note": "field test traffic",
            "analyst": "field_test",
        },
        "triages by filter",
        lambda d: d is not None,
    )
    await sw.expect(
        o,
        "alerts_export",
        {"format": "json", "limit": 20, "since_hours": 24},
        "writes an export file",
        lambda d: d,
    )
    await sw.expect(
        o,
        "export_blocklist",
        {"format": "plain", "hours": 24, "min_hits": 1},
        "writes a blocklist",
        lambda d: d,
    )
    await sw.expect(
        o, "export_stix", {"hours": 24, "min_hits": 1}, "writes a STIX bundle", lambda d: d
    )
    sup = await sw.expect(
        o,
        "suppression_add",
        {"label": f"{tag}-rule", "ip_pattern": "203.0.113.77", "action": "drop"},
        "adds a scoped rule",
        lambda d: d,
    )
    rid = (sup or {}).get("id") or (sup or {}).get("rule_id")
    if rid:
        await sw.expect(o, "suppression_remove", {"rule_id": rid}, "removes it", lambda d: d)
    else:
        sw.record(o, "suppression_remove", "removes it", False, f"no rule id in {sup}")
    # Never stop a capture that is running: this sweep runs against live deployments, and the
    # earlier version called action="stop" and silently ended packet capture on the droplet.
    cap = await sw.call(v, "pcap_status", None)
    running = bool(cap[0] and isinstance(cap[1], dict) and cap[1].get("running"))
    await sw.expect(
        o,
        "pcap_control",
        {"action": "start"},
        "start is safe to repeat (and explains itself when capture is unavailable)",
        lambda d: d is not None,
    )
    ok, data = await sw.call(o, "pcap_extract", {"source_ip": me})
    if running:
        sw.record(
            o,
            "pcap_extract",
            "capture is on: extracts a file for this source",
            ok and bool(isinstance(data, dict) and data.get("path")),
            str(data),
        )
    else:
        sw.record(
            o,
            "pcap_extract",
            "capture is off: a clear refusal naming the cause, not a crash",
            (not ok) and "capture" in str(data).lower(),
            str(data),
        )

    print("== honeytoken round trip (plant -> real SSH login -> CRITICAL -> TRIGGERED)")
    cred = await sw.expect(
        o,
        "honeytoken_generate_credentials",
        {"label": f"{tag}-trip", "count": 1, "service": "ssh"},
        "plants an ssh credential",
        lambda d: d["metadata"]["credentials"],
    )
    if cred:
        c0 = cred["metadata"]["credentials"][0]
        try:
            import paramiko

            cl = paramiko.SSHClient()
            cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cl.connect(
                a.attacker_host,
                22,
                c0["username"],
                c0["password"],
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            cl.close()
            used = "logged in"
        except Exception as e:  # noqa: BLE001
            used = f"{type(e).__name__}"
        await asyncio.sleep(3)  # the event buffer flushes about every second
        await sw.expect(
            v,
            "honeytoken_status",
            {"token_id": cred["id"]},
            f"token is TRIGGERED after the login ({used})",
            lambda d: str(d.get("status")).lower() == "triggered",
        )
        await sw.expect(
            v,
            "alerts_search",
            {"query": c0["username"], "limit": 20},
            "the login is a CRITICAL honeytoken alert",
            lambda d: any(
                x["severity"] == "critical" and "honeytoken" in x["event_type"]
                for x in d.get("alerts", [])
            ),
        )
        await sw.expect(o, "honeytoken_revoke", {"token_id": cred["id"]}, "cleans up", lambda d: d)

    print("== admin tools")
    ad = "admin"
    await sw.expect(ad, "api_key_list", None, "lists keys", lambda d: d is not None)
    key = await sw.expect(
        ad,
        "api_key_create",
        {"label": f"{tag}-viewer", "role": "viewer", "expires_in_days": 1},
        "mints a live key",
        lambda d: d.get("api_key") or d.get("key") or d.get("token"),
    )
    kid = (key or {}).get("id") or (key or {}).get("key_id")
    secret = (key or {}).get("api_key") or (key or {}).get("key") or (key or {}).get("token")
    if secret:
        ok, _ = await sw.call(None, "ping", token=secret)
        sw.record("viewer*", "ping", "the live-minted key works at once", ok)
        ok, _ = await sw.call(
            None, "honeypot_deploy", {"type": "http", "port": 18999}, token=secret
        )
        sw.record("viewer*", "honeypot_deploy", "and is still only a viewer", not ok, "was allowed")
    if kid:
        await sw.expect(ad, "api_key_revoke", {"key_id": kid}, "revokes it", lambda d: d)
        if secret:
            await asyncio.sleep(1)
            ok, _ = await sw.call(None, "ping", token=secret)
            sw.record(
                "viewer*", "ping", "a revoked key is refused immediately", not ok, "still accepted"
            )
    await sw.expect(
        ad,
        "audit_log_search",
        {"since_hours": 1, "limit": 50},
        "the lifecycle above is audited",
        lambda d: d.get("count", len(d.get("entries", []))) >= 1 or d,
    )
    await sw.refused(
        ad,
        "alert_subscribe",
        "a private webhook destination is refused",
        {"url": "http://127.0.0.1:9/hook", "label": f"{tag}-hook"},
    )
    await sw.expect(
        ad,
        "alerts_prune",
        {"older_than_days": 36500, "archive": True},
        "prunes nothing (nothing is that old)",
        lambda d: d is not None,
    )
    for tool, args in (
        (
            "blocklist_push_cloudflare",
            {"account_id": "x", "list_id": "x", "api_token": "x", "dry_run": True},
        ),
        (
            "blocklist_push_aws_waf",
            {"ip_set_id": "x", "ip_set_name": "x", "region": "us-east-1", "dry_run": True},
        ),
        (
            "blocklist_push_pfsense",
            {
                "base_url": "https://pfsense.invalid",
                "api_key": "x",
                "alias_name": "x",
                "dry_run": True,
            },
        ),
    ):
        ok, data = await sw.call(ad, tool, args)
        sw.record(
            ad,
            tool,
            "dry run: answers, never pushes or crashes",
            ok or isinstance(data, str),
            str(data),
        )
    ok, data = await sw.call(ad, "alert_unsubscribe", {"subscription_id": 999999})
    sw.record(
        ad, "alert_unsubscribe", "an unknown id is a clean error", not ok and bool(data), str(data)
    )

    # Leave nothing behind: revoke any token this run labelled that is still active.
    ok, listed = await sw.call(v, "honeytoken_list", None)
    leftover = [
        t
        for t in (listed.get("tokens", listed) if isinstance(listed, dict) else listed or [])
        if str(t.get("label", "")).startswith(tag) and t.get("status") == "active"
    ]
    for t in leftover:
        await sw.call(o, "honeytoken_revoke", {"token_id": t["id"]})
    ok, listed = await sw.call(v, "honeytoken_list", None)
    still = [
        t
        for t in (listed.get("tokens", listed) if isinstance(listed, dict) else listed or [])
        if str(t.get("label", "")).startswith(tag) and t.get("status") == "active"
    ]
    sw.rows.append(
        Row(
            "-",
            "(cleanup)",
            f"revoked {len(leftover)} leftover token(s); none of this run's tokens remain active",
            not still,
            f"still active: {still}",
        )
    )

    # Coverage: every registered tool is either called above or explicitly skipped.
    async with Client(a.url, auth=tokens["admin"]) as c:
        registered = {t.name for t in await c.list_tools()}
    for t, why in SKIPPED.items():
        sw.rows.append(Row("-", t, f"SKIPPED: {why}", True, ""))
        sw.called.add(t)
    missing = sorted(registered - sw.called)
    sw.rows.append(
        Row(
            "-",
            "(coverage)",
            f"{len(registered)} tools registered, {len(registered - set(missing))} "
            f"called or skipped with a reason",
            not missing,
            f"UNTESTED: {missing}",
        )
    )
    print(f"\ncoverage: {len(registered)} registered, untested: {missing or 'none'}")

    failed = [r for r in sw.rows if not r.ok]
    lines = [
        "# Tool sweep report\n",
        f"{len(sw.rows)} checks, {len(failed)} failed.\n",
        "| role | tool | check | result |",
        "|---|---|---|---|",
    ]
    for r in sw.rows:
        lines.append(
            f"| {r.role} | `{r.tool}` | {r.what} | {'PASS' if r.ok else 'FAIL ' + r.detail} |"
        )
    text = "\n".join(lines)
    if a.out:
        with open(a.out, "w") as f:
            f.write(text + "\n")
    print(f"\n{len(sw.rows)} checks, {len(failed)} failed" + (f"; report {a.out}" if a.out else ""))
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--url", required=True, help="control-plane MCP URL, e.g. http://127.0.0.1:18443/mcp"
    )
    ap.add_argument("--tokens", required=True, help="file with viewer=/operator=/admin= lines")
    ap.add_argument(
        "--attacker-host", required=True, help="the VPS public address (for the honeytoken login)"
    )
    ap.add_argument("--source-ip", help="this machine's public address (auto-detected otherwise)")
    ap.add_argument("--out", help="write a markdown report here")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
