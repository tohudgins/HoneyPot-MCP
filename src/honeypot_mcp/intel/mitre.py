"""MITRE ATT&CK mapper — loads local STIX JSON and maps observed events to techniques."""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from typing import Any

log = logging.getLogger(__name__)

# Observed-behaviour keyword → (technique_id, technique_name, tactic).
#
# Tactics follow MITRE ATT&CK Enterprise exactly. This matters more than it
# might seem: SOC analysts know the framework, and a technique filed under the
# wrong tactic discredits every other number on the page. Brute Force (T1110)
# in particular is **Credential Access** — an earlier revision of this table
# filed the SSH/FTP/RDP variants under Initial Access while filing the
# identical technique under Credential Access three entries later.
#
# Coverage is deliberately aligned to what the engines actually capture: every
# high-value event type they emit should map to something, because an
# unmapped capture is invisible in the ATT&CK dashboard and the kill-chain
# timeline. Ordering is longest/most-specific first, since all matches are
# collected and a generic pattern should never be the only hit.
_BUILTIN_MAPPINGS: list[tuple[re.Pattern, str, str, str]] = [
    # ── Impact ───────────────────────────────────────────────────────────────
    # Ransom notes and database wipes are the highest-severity thing a
    # honeypot sees; they must never fall through to a generic mapping.
    (
        re.compile(r"(ransom|bitcoin|btc.address|recover.your.data|encrypted)", re.I),
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
    ),
    (
        re.compile(r"(destructive|dropdatabase|drop.database|deletemany|wipe)", re.I),
        "T1485",
        "Data Destruction",
        "Impact",
    ),
    # ── Execution ────────────────────────────────────────────────────────────
    (
        re.compile(
            r"(copy.program|from.program|to.program|udf.rce|module.load|"
            r"redis.eval|rce.dropper|rogue.replica)",
            re.I,
        ),
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
    ),
    (
        re.compile(r"(command.input|ssh.command|shell.exec|/bin/(ba)?sh|cmd.exe)", re.I),
        "T1059.004",
        "Command and Scripting Interpreter: Unix Shell",
        "Execution",
    ),
    # ── Persistence ──────────────────────────────────────────────────────────
    (
        re.compile(r"(authorized.keys|ssh.key|authorized_keys)", re.I),
        "T1098.004",
        "Account Manipulation: SSH Authorized Keys",
        "Persistence",
    ),
    (
        re.compile(r"(crontab|cron\.d|backdoor|scheduled.task)", re.I),
        "T1053",
        "Scheduled Task/Job",
        "Persistence",
    ),
    (
        re.compile(r"(outfile.write|into.outfile|webshell|web.shell|\.php.*upload)", re.I),
        "T1505.003",
        "Server Software Component: Web Shell",
        "Persistence",
    ),
    # ── Lateral Movement ─────────────────────────────────────────────────────
    (
        re.compile(r"(eternalblue|doublepulsar|smb.exploit|ms17.010)", re.I),
        "T1210",
        "Exploitation of Remote Services",
        "Lateral Movement",
    ),
    (
        re.compile(r"rdp.*(handshake|mcs|connection)", re.I),
        "T1021.001",
        "Remote Services: Remote Desktop Protocol",
        "Lateral Movement",
    ),
    # ── Credential Access ────────────────────────────────────────────────────
    # T1110 is Credential Access in ATT&CK, for every protocol.
    (
        # The negative lookahead keeps `smb_exploit_attempt` out: an exploit is
        # not a password guess, and mislabelling it inflates Credential Access
        # while hiding the Lateral Movement finding that actually matters.
        re.compile(
            r"^(?!.*exploit)"
            r"(ssh|ftp|rdp|smtp|vnc|redis|mysql|mssql|postgresql|smb|telnet)"
            r".*(brute|login|auth|fail|session.setup)",
            re.I,
        ),
        "T1110.001",
        "Brute Force: Password Guessing",
        "Credential Access",
    ),
    (
        re.compile(r"(spray|credential.stuff)", re.I),
        "T1110.003",
        "Brute Force: Password Spraying",
        "Credential Access",
    ),
    (
        re.compile(r"(phpmyadmin|mysqladmin|db.login)", re.I),
        "T1110.001",
        "Brute Force: Password Guessing",
        "Credential Access",
    ),
    (
        re.compile(r"(/etc/shadow|/etc/passwd|pg_shadow|pg_authid|sam.hive|ntds)", re.I),
        "T1003",
        "OS Credential Dumping",
        "Credential Access",
    ),
    (
        re.compile(r"(\.env|\.aws/credentials|wp-config|config\.json|credentials.file)", re.I),
        "T1552.001",
        "Unsecured Credentials: Credentials In Files",
        "Credential Access",
    ),
    (
        re.compile(r"(aws.key|access.key.id|secret.access|bearer.token)", re.I),
        "T1528",
        "Steal Application Access Token",
        "Credential Access",
    ),
    (
        re.compile(r"(credential|password|passwd)", re.I),
        "T1555",
        "Credentials from Password Stores",
        "Credential Access",
    ),
    # ── Initial Access ───────────────────────────────────────────────────────
    # A planted credential being used is the strongest signal the platform
    # produces: someone is replaying secrets they should never have had.
    (
        re.compile(r"(honeytoken.triggered|valid.account|login.success)", re.I),
        "T1078",
        "Valid Accounts",
        "Initial Access",
    ),
    (
        re.compile(
            r"(exploit|shellshock|heartbleed|log4j|log4shell|jndi:|struts|ognl|spring4shell)",
            re.I,
        ),
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
    ),
    (
        re.compile(r"(sql.inject|sqli|union.select)", re.I),
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
    ),
    (
        re.compile(r"(path.travers|lfi|rfi|\.\./)", re.I),
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
    ),
    # ── Collection ───────────────────────────────────────────────────────────
    (
        re.compile(r"(elasticsearch.data|_search|_bulk|data.access|dump)", re.I),
        "T1213",
        "Data from Information Repositories",
        "Collection",
    ),
    (
        re.compile(r"(file.read|file.access|pg_read_file|lo_import|load_file)", re.I),
        "T1005",
        "Data from Local System",
        "Collection",
    ),
    # ── Command and Control ──────────────────────────────────────────────────
    (
        re.compile(r"(dns.tunnel|dns.exfil|dns.canary|dns.*callback|beacon)", re.I),
        "T1071.004",
        "Application Layer Protocol: DNS",
        "Command and Control",
    ),
    (
        re.compile(r"(http.canary|url.trigger|canary.url|token.callback)", re.I),
        "T1071.001",
        "Application Layer Protocol: Web Protocols",
        "Command and Control",
    ),
    (
        re.compile(r"(open.relay|smtp.relay|mail.relay)", re.I),
        "T1071.003",
        "Application Layer Protocol: Mail Protocols",
        "Command and Control",
    ),
    (
        re.compile(r"(c2|command.and.control|reverse.shell)", re.I),
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
    ),
    (
        re.compile(r"(file.upload|wget|curl|tftp|(download).*(payload|script|sh|exe))", re.I),
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
    ),
    # Cowrie's `session.file_download` / `file_upload` are the attacker pulling
    # a payload *into* the honeypot — `wget http://…/bins.sh` is the defining
    # Mirai behaviour — so they are Ingress Tool Transfer. This used to be
    # caught by the `file.download` alternative in the T1041 rule below and
    # filed under Exfiltration, which inverted the direction of the single most
    # valuable artifact a honeypot collects: every captured malware sample
    # appeared on the ATT&CK dashboard as data leaving. Matched ahead of the
    # generic rule, and `file.download` was removed from it, because all
    # matches are collected and both would otherwise fire.
    (
        re.compile(r"(ssh|telnet)_file_(download|upload)", re.I),
        "T1105",
        "Ingress Tool Transfer",
        "Command and Control",
    ),
    # ── Exfiltration ─────────────────────────────────────────────────────────
    (
        re.compile(r"(sftp|scp|lo_export|outfile.*/tmp)", re.I),
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
    ),
    # ── Discovery ────────────────────────────────────────────────────────────
    (
        re.compile(r"(port.scan|nmap|masscan|zmap|smb.negotiate|smb.version)", re.I),
        "T1046",
        "Network Service Discovery",
        "Discovery",
    ),
    (
        re.compile(
            r"(recon.query|info.probe|version\(\)|buildinfo|servetstatus|"
            r"server.status|health.probe|current_user|version.probe)",
            re.I,
        ),
        "T1082",
        "System Information Discovery",
        "Discovery",
    ),
    (
        re.compile(r"(listdatabases|show.databases|information_schema|_cat/indices)", re.I),
        "T1083",
        "File and Directory Discovery",
        "Discovery",
    ),
    (
        re.compile(
            r"(iam|s3|ec2|lambda|metadata\.google|169\.254\.169\.254).*(access|enumerat|)", re.I
        ),
        "T1526",
        "Cloud Service Discovery",
        "Discovery",
    ),
    # ── Reconnaissance ───────────────────────────────────────────────────────
    (
        re.compile(r"(web.scan|nikto|dirb|gobuster|wfuzz|active.recon)", re.I),
        "T1595.003",
        "Active Scanning: Wordlist Scanning",
        "Reconnaissance",
    ),
    (
        re.compile(r"(zone.transfer|axfr|dns.any|dns.query)", re.I),
        "T1590.002",
        "Gather Victim Network Information: DNS",
        "Reconnaissance",
    ),
]


@lru_cache(maxsize=1)
def _load_stix_index() -> dict[str, dict]:
    """Load the MITRE ATT&CK STIX JSON file and pre-build a {technique_id: object}
    index. Cached for the process lifetime — MITRE data is read-only."""
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    path = settings.mitre_data_path

    if not path.exists():
        log.debug("MITRE ATT&CK STIX file not found at %s — using built-in mappings only.", path)
        return {}

    try:
        with path.open() as f:
            bundle = json.load(f)
    except Exception as e:
        log.warning("Failed to load MITRE STIX file: %s", e)
        return {}

    by_id: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id", "")
                if ext_id:
                    by_id[ext_id] = obj
    return by_id


async def map_to_attack(terms: list[str]) -> list[dict[str, Any]]:
    """Map a list of observed event strings to MITRE ATT&CK techniques.

    Uses built-in regex mappings first, then enriches from the STIX bundle if available.
    Returns a deduplicated list of matched techniques sorted by tactic.
    """
    combined_text = " ".join(terms)
    found: dict[str, dict[str, Any]] = {}

    for pattern, tid, name, tactic in _BUILTIN_MAPPINGS:
        if pattern.search(combined_text):
            if tid not in found:
                found[tid] = {
                    "technique_id": tid,
                    "technique_name": name,
                    "tactic": tactic,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
                    "matched_by": [],
                }
            for term in terms:
                if pattern.search(term) and term not in found[tid]["matched_by"]:
                    found[tid]["matched_by"].append(term)

    stix_by_id = _load_stix_index()
    if stix_by_id:
        for tid, entry in found.items():
            base_id = tid.split(".")[0]
            stix_obj = stix_by_id.get(tid) or stix_by_id.get(base_id)
            if stix_obj:
                entry["description"] = stix_obj.get("description", "")[:300]

    return sorted(found.values(), key=lambda x: (x["tactic"], x["technique_id"]))
