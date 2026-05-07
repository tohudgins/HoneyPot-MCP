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
    risk_score = _calculate_risk(vt, abuse, ttps, sev_counts, len(alerts))

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
        } if vt.get("available") else {"available": False},
        "abuseipdb": {
            "abuse_confidence_score": abuse.get("abuse_confidence_score", 0),
            "total_reports": abuse.get("total_reports", 0),
            "num_distinct_users": abuse.get("num_distinct_users", 0),
            "isp": abuse.get("isp", ""),
            "usage_type": abuse.get("usage_type", ""),
            "last_reported_at": abuse.get("last_reported_at"),
            "report_categories": abuse.get("report_categories", {}),
        } if abuse.get("available") else {"available": False},
        "recommendations": _recommendations(ttps, risk_score, sev_counts, abuse),
    }


def _calculate_risk(
    vt: dict,
    abuse: dict,
    ttps: list[dict],
    sev: dict[str, int],
    event_count: int,
) -> int:
    score = 0

    # VT reputation (max 30 pts)
    rep = vt.get("reputation", 0) or 0
    if rep < 0:
        score += min(20, abs(rep))
    mal_votes = vt.get("malicious_votes", 0) or 0
    score += min(10, mal_votes * 2)

    # AbuseIPDB confidence score (max 30 pts — directly maps 0-100 → 0-30)
    abuse_score = abuse.get("abuse_confidence_score", 0) or 0
    score += int(abuse_score * 0.30)

    # Severity (max 20 pts)
    score += min(10, sev.get("critical", 0) * 5)
    score += min(6, sev.get("high", 0) * 3)
    score += min(4, sev.get("medium", 0))

    # MITRE technique coverage (max 10 pts)
    score += min(10, len(ttps) * 2)

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
        recs.append(f"AbuseIPDB confidence score {abuse_score}% — strongly confirmed malicious. Report and block.")
    elif abuse_score >= 50:
        recs.append(f"AbuseIPDB confidence score {abuse_score}% — likely malicious. Consider reporting via report_ip_abuse tool.")
    elif abuse_score == 0 and abuse.get("available"):
        recs.append("No prior AbuseIPDB reports — this may be a new or VPN-masked attacker.")

    if risk_score >= 75:
        recs.append("Submit this IP to AbuseIPDB using the report_ip_abuse tool.")
    if not recs:
        recs.append("Monitor this IP for continued activity — low risk currently.")

    return recs
