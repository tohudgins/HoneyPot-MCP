"""MCP tool annotations: what each tool does to the world, stated for the client.

An MCP client decides how to treat a tool call from its annotations. Without them
every tool looks like it might be destructive and reaches the outside world, so a
professional's agent cannot auto-approve `alerts_recent` yet should absolutely stop
and ask before `alerts_prune` or a Cloudflare blocklist push — and the client has
nothing to go on. These hints are that information:

* ``readOnlyHint`` — the tool changes nothing. Safe to run without asking.
* ``destructiveHint`` — (only meaningful when not read-only) it can remove or
  overwrite something, or take an action with no undo tool in this server.
  ``False`` means purely additive.
* ``idempotentHint`` — calling it again with the same arguments changes nothing more.
* ``openWorldHint`` — it talks to systems outside this server (threat-intel APIs,
  a firewall, a webhook receiver, AbuseIPDB).

They are advisory — the real enforcement is `rbac.py` — but they are what makes the
difference between an agent that stops for every read and one that stops for the
right calls.

`hints(name)` raises for a tool that is not listed, so a new tool cannot be
registered without being classified; `test_tool_hints.py` pins the rest.
"""

from __future__ import annotations

from typing import Any

from mcp.types import ToolAnnotations

# Flags: R read-only · D destructive · I idempotent · W open-world.
#
# Notes on the less obvious entries:
#   generate_report / alerts_export / export_* / pcap_extract write a NEW file and
#     refuse to overwrite one, so they are additive, not destructive.
#   honeypot_configure overwrites a sensor's configuration.
#   alerts_acknowledge overwrites an existing triage verdict on every match, and
#     suppression_add can drop future events permanently, so both are destructive.
#   analyze_attacker / generate_report (with enrichment) send the attacker IP to
#     threat-intel services, so they are open-world like enrich_ip.
#   honeytoken_revoke / suppression_remove / alert_unsubscribe / api_key_revoke
#     deactivate something and this server has no tool to bring it back, so they
#     are marked destructive even though the row is kept.
#   report_ip_abuse sends a report about a third party to AbuseIPDB; it cannot be
#     recalled, so it is destructive and open-world.
#   blocklist_push_* only ever add addresses, but to a firewall — open-world.
_FLAGS: dict[str, str] = {
    # ── viewer tier ──────────────────────────────────────────────────────────
    "alert_subscriptions_list": "R",
    "alerts_get": "R",
    "alerts_recent": "R",
    "alerts_search": "R",
    "alerts_stats": "R",
    "analyze_attacker": "RW",
    "analyze_attacker_journey": "R",
    "analyze_campaign": "R",
    "analyze_session": "R",
    "deception_coverage": "R",
    "deception_plan": "R",
    "deception_profiles": "R",
    "enrich_ip": "RW",
    "fingerprint_clusters": "R",
    "generate_report": "W",
    "honeypot_health": "R",
    "honeypot_list": "R",
    "honeypot_logs": "R",
    "honeypot_status": "R",
    "honeypot_templates": "R",
    "honeytoken_list": "R",
    "honeytoken_status": "R",
    "map_ttps": "R",
    "attack_summary": "R",
    # Writes one new ATT&CK Navigator layer file to the reports directory (never overwrites a
    # named file), so it is additive rather than read-only.
    "attack_navigator_layer": "",
    "extract_iocs": "R",
    # Sends the hash to abuse.ch MalwareBazaar.
    "lookup_hash": "RW",
    "sql_query": "R",
    "attack_patterns": "R",
    "bait_trips": "R",
    "pcap_files": "R",
    "pcap_analyze": "R",
    "pcap_status": "R",
    "ping": "R",
    "grafana_status": "R",
    "soc_brief": "R",
    "suppression_list": "R",
    "suppression_list_presets": "R",
    "threat_timeline": "R",
    # ── operator tier ────────────────────────────────────────────────────────
    "alerts_acknowledge": "D",
    "alerts_export": "",
    "deception_deploy_plan": "",
    "export_blocklist": "",
    "export_stix": "",
    "honeypot_clone": "",
    "honeypot_configure": "DI",
    "honeypot_deploy": "",
    "honeypot_pause": "I",
    "honeypot_resume": "I",
    "honeypot_self_test": "",
    "honeypot_stop": "DI",
    "honeytoken_create": "",
    "honeytoken_embed_file": "",
    "honeytoken_export": "R",
    "honeytoken_generate_aws": "",
    "honeytoken_generate_credentials": "",
    "honeytoken_revoke": "DI",
    "honeytoken_rotate": "D",
    "pcap_control": "",
    "pcap_extract": "",
    # Starts a throwaway container (no network) and writes one JSON Lines artifact; the first
    # use pulls the engine image from a registry, hence open-world.
    "pcap_detect": "W",
    # Reads quarantined files (briefly granting itself read on mode-000 ones, then restoring the
    # mode) and writes one new JSON artifact; runs no code and contacts nothing.
    "sample_scan": "",
    # Writes new files into the reports directory (a fixed-name summary that is regenerated each
    # run, plus timestamped exports); calls threat-intel lookups for the busiest sources.
    "run_analysis": "W",
    "report_ip_abuse": "DW",
    "suppression_add": "D",
    "suppression_load_preset": "I",
    "suppression_remove": "DI",
    # ── admin tier ───────────────────────────────────────────────────────────
    "alert_subscribe": "W",
    "alert_unsubscribe": "DI",
    "alerts_prune": "DI",
    "api_key_create": "",
    "api_key_list": "R",
    "api_key_revoke": "DI",
    "audit_log_search": "R",
    # Writes a new directory under the backups directory and never replaces an existing one.
    "database_backup": "",
    # Downloads the Emerging Threats Open ruleset (the only container with a network) and
    # replaces the cached rules after Suricata has validated them.
    "detection_rules_update": "W",
    "blocklist_push_aws_waf": "IW",
    "blocklist_push_cloudflare": "IW",
    "blocklist_push_pfsense": "IW",
    # Downloads the Grafana image (first run) and the pinned SQLite plugin from the internet
    # (open-world), and REMOVES its previous containers, networks and private directory before
    # recreating them (destructive: an instance edited in the UI loses those edits).
    "grafana_start": "WD",
    "grafana_stop": "DI",
    # Adds new files to the quarantine and never overwrites; talks only to the local Docker daemon.
    "sample_collect": "",
}

_ACRONYMS = {
    "ip": "IP", "ttps": "TTPs", "stix": "STIX", "aws": "AWS", "waf": "WAF", "soc": "SOC",
    "api": "API", "pcap": "PCAP", "ssh": "SSH", "mcp": "MCP", "pfsense": "pfSense",
}  # fmt: skip

_TITLES = {
    "alerts_recent": "Recent Alerts",
    "alerts_search": "Search Alerts",
    "alerts_stats": "Alert Statistics",
    "alerts_get": "Get Alert",
    "alerts_acknowledge": "Triage Alerts",
    "alerts_export": "Export Alerts",
    "alerts_prune": "Prune Old Alerts",
    "honeypot_list": "List Honeypots",
    "honeypot_deploy": "Deploy Honeypot",
    "honeypot_stop": "Stop Honeypots",
    "honeytoken_create": "Create Honeytoken",
    "honeytoken_list": "List Honeytokens",
    "map_ttps": "Map to MITRE ATT&CK",
    "attack_summary": "ATT&CK Summary",
    "extract_iocs": "Extract IOCs",
    "attack_navigator_layer": "ATT&CK Navigator Layer",
    "lookup_hash": "Look Up File Hash",
    "sql_query": "Read-only SQL Query",
    "attack_patterns": "Attack Patterns",
    "bait_trips": "Honeytoken Bait Trips",
    "soc_brief": "SOC Shift Brief",
    "ping": "Ping",
}


def _title(name: str) -> str:
    if name in _TITLES:
        return _TITLES[name]
    return " ".join(_ACRONYMS.get(part, part.capitalize()) for part in name.split("_"))


def tool_names() -> frozenset[str]:
    return frozenset(_FLAGS)


def hints(name: str) -> dict[str, Any]:
    """Keyword arguments for ``@mcp.tool(...)``: ``annotations`` and ``title``."""
    flags = _FLAGS[name]  # KeyError on purpose: an unclassified tool must not register
    read_only = "R" in flags
    annotations = ToolAnnotations(
        title=_title(name),
        readOnlyHint=read_only,
        # `destructiveHint` is only defined for tools that change something; a
        # read-only tool leaves it unset rather than claiming False.
        destructiveHint=None if read_only else ("D" in flags),
        idempotentHint=read_only or "I" in flags,
        openWorldHint="W" in flags,
    )
    return {"annotations": annotations, "title": _title(name)}
