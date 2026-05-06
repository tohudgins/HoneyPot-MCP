"""MITRE ATT&CK mapper — loads local STIX JSON and maps observed events to techniques."""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Keyword → (technique_id, technique_name, tactic)
# Covers the most common honeypot-observable techniques
_BUILTIN_MAPPINGS: list[tuple[re.Pattern, str, str, str]] = [
    # Initial Access
    (re.compile(r"ssh.*(brute|login|fail|attempt)", re.I), "T1110.001", "Brute Force: Password Guessing", "Initial Access"),
    (re.compile(r"ssh.*login.*success", re.I), "T1078", "Valid Accounts", "Initial Access"),
    (re.compile(r"ftp.*(login|auth|brute)", re.I), "T1110.001", "Brute Force: Password Guessing", "Initial Access"),
    (re.compile(r"rdp.*(login|brute|attempt)", re.I), "T1110.001", "Brute Force: Password Guessing", "Initial Access"),
    # Discovery
    (re.compile(r"(port.scan|nmap|masscan|zmap)", re.I), "T1046", "Network Service Discovery", "Discovery"),
    (re.compile(r"(web.scan|nikto|dirb|gobuster|wfuzz)", re.I), "T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance"),
    (re.compile(r"dns.query", re.I), "T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance"),
    # Credential Access
    (re.compile(r"(credential|password|passwd|shadow)", re.I), "T1555", "Credentials from Password Stores", "Credential Access"),
    (re.compile(r"(spray|credential.stuff)", re.I), "T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    (re.compile(r"(phpmyadmin|mysqladmin|db.login)", re.I), "T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    # Command & Control
    (re.compile(r"(dns.canary|dns.*callback|beacon)", re.I), "T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
    (re.compile(r"(http.canary|url.trigger|canary.url)", re.I), "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    (re.compile(r"(c2|command.and.control|reverse.shell)", re.I), "T1105", "Ingress Tool Transfer", "Command and Control"),
    # Execution
    (re.compile(r"(command.input|ssh.command|shell.exec)", re.I), "T1059", "Command and Scripting Interpreter", "Execution"),
    (re.compile(r"(wget|curl|download).*(payload|script|sh|exe)", re.I), "T1105", "Ingress Tool Transfer", "Command and Control"),
    # Exfiltration
    (re.compile(r"(file.download|sftp|scp)", re.I), "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    # Persistence
    (re.compile(r"(crontab|authorized.keys|ssh.key|backdoor)", re.I), "T1098", "Account Manipulation", "Persistence"),
    # AWS / Cloud
    (re.compile(r"(aws.key|access.key.id|secret.access)", re.I), "T1528", "Steal Application Access Token", "Credential Access"),
    (re.compile(r"(iam|s3|ec2|lambda).*(access|enumerat)", re.I), "T1526", "Cloud Service Discovery", "Discovery"),
    # Exploit
    (re.compile(r"(exploit|shellshock|heartbleed|log4j|log4shell)", re.I), "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (re.compile(r"(sql.inject|sqli|union.select)", re.I), "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (re.compile(r"(path.travers|lfi|rfi|../)", re.I), "T1190", "Exploit Public-Facing Application", "Initial Access"),
]


@lru_cache(maxsize=1)
def _load_stix() -> list[dict]:
    """Load the MITRE ATT&CK STIX JSON file (cached after first load)."""
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    path = settings.mitre_data_path

    if not path.exists():
        log.debug("MITRE ATT&CK STIX file not found at %s — using built-in mappings only.", path)
        return []

    try:
        with path.open() as f:
            bundle = json.load(f)
        objects = bundle.get("objects", [])
        return [
            obj for obj in objects
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False)
        ]
    except Exception as e:
        log.warning("Failed to load MITRE STIX file: %s", e)
        return []


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

    # Optionally cross-reference with loaded STIX for descriptions
    stix_objects = _load_stix()
    if stix_objects:
        stix_by_id = {}
        for obj in stix_objects:
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    if ext_id:
                        stix_by_id[ext_id] = obj

        for tid, entry in found.items():
            base_id = tid.split(".")[0]
            stix_obj = stix_by_id.get(tid) or stix_by_id.get(base_id)
            if stix_obj:
                entry["description"] = stix_obj.get("description", "")[:300]

    return sorted(found.values(), key=lambda x: (x["tactic"], x["technique_id"]))
