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
    """Prioritised, self-explanatory action list for a human analyst.

    Each line carries its own `[Immediate]` / `[Short-term]` / `[Monitor]`
    tag and, for the ones that can otherwise look alarming next to a low
    aggregate score, says why it fired independently of that score.

    This is deliberate: `risk_score` measures how *sustained and
    multi-signal* this attacker's behaviour looks over the whole profile,
    while a single high-severity finding — an exploit attempt, a triggered
    honeytoken — is actionable the moment it happens and must not wait for
    the aggregate to climb before recommending a block. The previous version
    put strongly-worded, unqualified actions ("block immediately", "escalate")
    next to a bare "LOW (19/100)" badge with nothing tying the two together —
    both numbers were individually correct, but an analyst reading them side
    by side reasonably read that as the tool contradicting itself. Priority
    tags plus an inline reason make the two axes legible instead of adjacent
    and unexplained.
    """
    immediate: list[str] = []
    short_term: list[str] = []
    monitor: list[str] = []

    tactics = {t["tactic"] for t in ttps}
    hands_on = tactics & _HANDS_ON_TACTICS

    # T1078 (Valid Accounts) fires on either a genuine honeytoken trigger or
    # a plain "login success" event — same technique, very different
    # confidence. Only the former can be stated as confirmed compromise;
    # check what actually matched rather than assuming from the tactic alone.
    t1078 = next((t for t in ttps if t.get("technique_id") == "T1078"), None)
    honeytoken_confirmed = bool(
        t1078 and any("honeytoken" in str(m).lower() for m in t1078.get("matched_by", []))
    )

    if sev.get("critical", 0) > 0:
        n = sev["critical"]
        immediate.append(
            f"Escalate to incident response — {n} critical-severity event{'s' if n != 1 else ''} "
            "observed. This is independent of the aggregate risk score below, which reflects "
            "sustained behaviour across the whole profile, not the severity of any single event."
        )

    if honeytoken_confirmed:
        immediate.append(
            "A planted honeytoken credential was used — this cannot be a false positive. "
            "Treat as confirmed compromise and block this IP now."
        )
    elif "Initial Access" in tactics:
        immediate.append(
            "An exploit or valid-account attempt against a decoy was observed (Initial Access). "
            "Block this IP at the perimeter firewall."
        )

    if hands_on:
        immediate.append(
            "Hands-on activity observed, not just scanning — tactic(s): "
            f"{', '.join(sorted(hands_on))}. Treat as an active intrusion."
        )

    abuse_score = abuse.get("abuse_confidence_score", 0) or 0
    if abuse_score >= 80:
        immediate.append(
            f"AbuseIPDB confidence {abuse_score}% — strongly confirmed malicious. Report and block."
        )

    if "Credential Access" in tactics:
        short_term.append("Rotate any credentials that may have been exposed to this IP.")
    if "Command and Control" in tactics:
        short_term.append("Check for outbound connections to this IP from internal hosts.")
    if 50 <= abuse_score < 80:
        short_term.append(
            f"AbuseIPDB confidence {abuse_score}% — likely malicious. Consider reporting via "
            "the report_ip_abuse tool."
        )
    if risk_score >= 75:
        short_term.append("Submit this IP to AbuseIPDB using the report_ip_abuse tool.")

    if "Reconnaissance" in tactics:
        monitor.append("Review WAF/firewall logs for related scanning activity from this IP.")
    if abuse_score == 0 and abuse.get("available"):
        monitor.append("No prior AbuseIPDB reports — this may be a new or VPN-masked attacker.")

    if not (immediate or short_term or monitor):
        monitor.append("No actionable findings yet — continue monitoring this IP.")

    return (
        [f"[Immediate] {r}" for r in immediate]
        + [f"[Short-term] {r}" for r in short_term]
        + [f"[Monitor] {r}" for r in monitor]
    )
