"""Attacker profiler — builds a unified AttackerProfile from all data sources."""

from __future__ import annotations

from collections import Counter
from typing import Any

from honeypot_mcp.intel.mitre import map_to_attack
from honeypot_mcp.storage.models import Alert, AttackerEvent


async def build_profile(
    ip: str,
    alerts: list[Alert],
    events: list[AttackerEvent],
    geoip: dict[str, Any],
    vt: dict[str, Any],
    abuse: dict[str, Any],
) -> dict[str, Any]:
    """Merge all intelligence sources into a unified attacker profile."""

    # Event type frequency
    event_counts = Counter(a.event_type for a in alerts)
    event_counts.update(e.event_type for e in events)

    # Collect all text for TTP mapping
    terms = list(event_counts.keys())
    for alert in alerts:
        terms.extend(str(v) for v in alert.payload.values() if isinstance(v, str))

    ttps = await map_to_attack(terms)

    # Severity breakdown
    sev_counts: dict[str, int] = Counter(a.severity.value for a in alerts)  # type: ignore[assignment]

    # Timeline
    all_timestamps = [a.timestamp for a in alerts] + [e.timestamp for e in events]
    first_seen = min(all_timestamps).isoformat() if all_timestamps else None
    last_seen = max(all_timestamps).isoformat() if all_timestamps else None

    # Risk score: 0-100
    risk_score = _calculate_risk(
        vt, abuse, ttps, sev_counts, len(alerts), event_types=dict(event_counts)
    )

    return {
        "ip": ip,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_events": len(alerts) + len(events),
        "event_breakdown": dict(event_counts.most_common(20)),
        "severity_breakdown": dict(sev_counts),
        "mitre_techniques": ttps,
        "tactic_summary": _tactic_summary(ttps),
        "geoip": geoip,
        "virustotal": {
            "reputation": vt.get("reputation"),
            "malicious_votes": vt.get("malicious_votes"),
            "detection_ratio": vt.get("detection_ratio"),
            "tags": vt.get("tags", []),
            "as_owner": vt.get("as_owner"),
        }
        if vt.get("available")
        else {"available": False},
        "abuseipdb": {
            "abuse_confidence_score": abuse.get("abuse_confidence_score", 0),
            "total_reports": abuse.get("total_reports", 0),
            "num_distinct_users": abuse.get("num_distinct_users", 0),
            "isp": abuse.get("isp", ""),
            "usage_type": abuse.get("usage_type", ""),
            "last_reported_at": abuse.get("last_reported_at"),
            "report_categories": abuse.get("report_categories", {}),
        }
        if abuse.get("available")
        else {"available": False},
        "recommendations": _recommendations(ttps, risk_score, sev_counts, abuse),
    }


# Tactics that mean the attacker got past probing and did something to the
# decoy. Observing these directly is far stronger evidence than any third-party
# reputation score.
_HANDS_ON_TACTICS = frozenset({"Execution", "Impact", "Persistence", "Lateral Movement"})


def _calculate_risk(
    vt: dict,
    abuse: dict,
    ttps: list[dict],
    sev: dict[str, int],
    event_count: int,
    event_types: dict[str, int] | None = None,
) -> int:
    """Score 0-100, weighted toward what we observed rather than what a feed says.

    Two properties this has to hold, and an earlier revision did not:

    1. **Direct observation alone can reach CRITICAL.** VirusTotal and
       AbuseIPDB are optional integrations, and previously supplied 60 of the
       ~90 attainable points. With no API keys — the default — an attacker who
       ran a full RCE chain against a decoy and tripped a planted credential
       could not score above 30, i.e. MEDIUM. For a deception platform that is
       backwards: our own capture is higher-confidence evidence than a
       reputation lookup, not lower.

    2. **A triggered honeytoken dominates.** It is the highest-fidelity signal
       the platform can produce — a planted secret being replayed means someone
       is using credentials they could only have obtained by compromising
       something. It previously contributed nothing beyond its severity.
    """
    events = event_types or {}
    score = 0

    # ── Observed behaviour (max 85) ──────────────────────────────────────────
    # A honeytoken trigger is near-conclusive on its own.
    if any(name.startswith("honeytoken_triggered") for name in events):
        score += 45

    score += min(30, sev.get("critical", 0) * 15)
    score += min(12, sev.get("high", 0) * 3)
    score += min(5, sev.get("medium", 0))

    # Breadth of technique, and whether any of it was hands-on-decoy rather
    # than scanning.
    score += min(8, len(ttps) * 2)
    if any(t.get("tactic") in _HANDS_ON_TACTICS for t in ttps):
        score += 20

    # Sustained volume is weak evidence by itself — one determined scanner
    # produces thousands of events — so it is capped low deliberately.
    if event_count >= 100:
        score += 5
    elif event_count >= 20:
        score += 2

    # ── External corroboration (max 30) ──────────────────────────────────────
    # Additive confirmation, never the backbone of the score.
    rep = vt.get("reputation", 0) or 0
    if rep < 0:
        score += min(8, abs(rep) // 2)
    score += min(7, (vt.get("malicious_votes", 0) or 0))
    score += int((abuse.get("abuse_confidence_score", 0) or 0) * 0.15)

    return min(100, score)


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _tactic_summary(ttps: list[dict]) -> dict[str, int]:
    tactic_count: Counter = Counter(t["tactic"] for t in ttps)
    return dict(tactic_count)


def _recommendations(
    ttps: list[dict],
    risk_score: int,
    sev: dict[str, int],
    abuse: dict[str, Any],
) -> list[str]:
    recs = []
    tactics = {t["tactic"] for t in ttps}

    if "Initial Access" in tactics:
        recs.append("Block this IP at the perimeter firewall immediately.")
    if "Credential Access" in tactics:
        recs.append("Rotate any credentials that may have been exposed to this IP.")
    if "Command and Control" in tactics:
        recs.append("Check for outbound connections to this IP from internal hosts.")
    if "Reconnaissance" in tactics:
        recs.append("Review WAF logs for related scanning activity.")
    if sev.get("critical", 0) > 0:
        recs.append("Escalate to incident response — critical severity events detected.")

    # AbuseIPDB score
    abuse_score = abuse.get("abuse_confidence_score", 0) or 0
    if abuse_score >= 80:
        recs.append(
            f"AbuseIPDB confidence score {abuse_score}% — strongly confirmed malicious. Report and block."
        )
    elif abuse_score >= 50:
        recs.append(
            f"AbuseIPDB confidence score {abuse_score}% — likely malicious. Consider reporting via report_ip_abuse tool."
        )
    elif abuse_score == 0 and abuse.get("available"):
        recs.append("No prior AbuseIPDB reports — this may be a new or VPN-masked attacker.")

    if risk_score >= 75:
        recs.append("Submit this IP to AbuseIPDB using the report_ip_abuse tool.")
    if not recs:
        recs.append("Monitor this IP for continued activity — low risk currently.")

    return recs
