"""Attack correlation engine — groups events into campaigns."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from honeypot_mcp.storage.models import Alert


async def detect_campaigns(
    alerts: list[Alert],
    window_minutes: int = 60,
    min_sources: int = 3,
) -> list[dict[str, Any]]:
    """Detect coordinated attack campaigns from a list of alerts.

    A campaign is defined as: multiple distinct source IPs all hitting the same
    event_type within the same rolling time window.

    Returns a list of campaign summaries sorted by participant count.
    """
    if not alerts:
        return []

    # Group by event_type, then find clusters within time windows
    by_type: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_type[alert.event_type].append(alert)

    campaigns = []

    for event_type, type_alerts in by_type.items():
        sorted_alerts = sorted(type_alerts, key=lambda a: a.timestamp)
        window = timedelta(minutes=window_minutes)

        i = 0
        while i < len(sorted_alerts):
            window_alerts = [sorted_alerts[i]]
            j = i + 1
            while j < len(sorted_alerts):
                if sorted_alerts[j].timestamp - sorted_alerts[i].timestamp <= window:
                    window_alerts.append(sorted_alerts[j])
                    j += 1
                else:
                    break

            unique_ips = {a.source_ip for a in window_alerts}
            if len(unique_ips) >= min_sources:
                start_ts = sorted_alerts[i].timestamp
                end_ts = window_alerts[-1].timestamp
                campaigns.append({
                    "event_type": event_type,
                    "start_time": start_ts.isoformat(),
                    "end_time": end_ts.isoformat(),
                    "duration_minutes": int((end_ts - start_ts).total_seconds() / 60),
                    "unique_source_ips": len(unique_ips),
                    "total_events": len(window_alerts),
                    "source_ips": sorted(unique_ips),
                    "targeted_honeypots": list({a.honeypot_id for a in window_alerts if a.honeypot_id}),
                    "campaign_id": _make_campaign_id(event_type, start_ts),
                })

            i = j if j > i else i + 1

    # Deduplicate overlapping windows (keep the largest)
    campaigns = _deduplicate(campaigns)

    return sorted(campaigns, key=lambda c: c["unique_source_ips"], reverse=True)


def _make_campaign_id(event_type: str, start) -> str:
    ts = start.strftime("%Y%m%d%H%M")
    return f"camp-{event_type[:8]}-{ts}"


def _deduplicate(campaigns: list[dict]) -> list[dict]:
    """Remove campaigns that are strict subsets of larger campaigns."""
    seen: list[dict] = []
    for c in campaigns:
        ips = set(c["source_ips"])
        if not any(ips.issubset(set(s["source_ips"])) and c["event_type"] == s["event_type"] for s in seen):
            seen.append(c)
    return seen
