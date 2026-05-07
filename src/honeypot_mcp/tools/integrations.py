"""SOC platform tools: outbound webhook subscriptions and event suppression.

These are the integration points other SOC tooling plugs into:
- `alert_subscribe` — register a URL to receive real-time alerts (Slack, SIEM, PagerDuty, custom).
- `suppression_add` — drop or rate-limit noisy sources (known scanners, your own scans).

Subscriptions and rules are stored in the DB and survive restarts.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from sqlalchemy import select, update

from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import AlertSeverity, Subscription, SuppressionRule


# ── Subscriptions ─────────────────────────────────────────────────────────────


@mcp.tool
async def alert_subscribe(
    url: str,
    label: str,
    severity_threshold: Literal["low", "medium", "high", "critical"] = "medium",
    hmac_secret: str | None = None,
) -> dict[str, Any]:
    """Register a URL to receive real-time alert deliveries.

    Each new alert at or above the threshold is POSTed as JSON. If `hmac_secret`
    is provided, the request includes an `X-HoneyPot-Signature: sha256=<hex>`
    header (HMAC-SHA256 of the raw body). If you pass an empty string for
    `hmac_secret`, a random 32-byte secret is generated for you and returned.

    Args:
        url: The webhook URL to POST alerts to.
        label: Human-readable label (e.g. 'soc-slack-channel').
        severity_threshold: Minimum severity to deliver — events below are skipped.
        hmac_secret: Shared secret for HMAC signing. None = no signing,
                     "" = generate a fresh secret and return it.
    """
    if hmac_secret == "":
        hmac_secret = secrets.token_urlsafe(32)

    async with get_session() as session:
        sub = Subscription(
            label=label,
            url=url,
            severity_threshold=AlertSeverity(severity_threshold),
            hmac_secret=hmac_secret,
            active=True,
        )
        session.add(sub)
        await session.flush()
        sub_id = sub.id

    return {
        "id": sub_id,
        "label": label,
        "url": url,
        "severity_threshold": severity_threshold,
        "hmac_secret": hmac_secret,
        "active": True,
    }


@mcp.tool
async def alert_unsubscribe(subscription_id: int) -> dict[str, Any]:
    """Deactivate a webhook subscription. Existing rows are kept for audit; only
    `active=False` is set so deliveries stop.

    Args:
        subscription_id: The subscription ID returned by alert_subscribe.
    """
    async with get_session() as session:
        result = await session.execute(
            update(Subscription)
            .where(Subscription.id == subscription_id)
            .values(active=False)
        )
        if result.rowcount == 0:
            return {"error": f"No subscription with id={subscription_id}."}
    return {"id": subscription_id, "active": False}


@mcp.tool
async def alert_subscriptions_list(active_only: bool = True) -> list[dict[str, Any]]:
    """List webhook subscriptions with their delivery health stats.

    Args:
        active_only: If True (default), only return active subscriptions.
    """
    async with get_session() as session:
        q = select(Subscription)
        if active_only:
            q = q.where(Subscription.active.is_(True))
        result = await session.execute(q.order_by(Subscription.created_at.desc()))
        subs = list(result.scalars().all())

    return [
        {
            "id": s.id,
            "label": s.label,
            "url": s.url,
            "severity_threshold": s.severity_threshold.value,
            "active": s.active,
            "delivery_count": s.delivery_count,
            "failure_count": s.failure_count,
            "last_delivery_at": s.last_delivery_at.isoformat() if s.last_delivery_at else None,
            "last_error": s.last_error,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in subs
    ]


# ── Suppression rules ─────────────────────────────────────────────────────────


@mcp.tool
async def suppression_add(
    label: str,
    ip_pattern: str | None = None,
    event_type_pattern: str | None = None,
    action: Literal["drop", "rate_limit"] = "drop",
    rate_limit_count: int | None = None,
    rate_limit_window_seconds: int | None = None,
    expires_in_hours: int | None = None,
) -> dict[str, Any]:
    """Add a suppression rule. Matched events are dropped or rate-limited
    BEFORE they enter the alert pipeline (no DB write, no webhook delivery).

    Patterns:
        ip_pattern: exact IP, CIDR (e.g. '10.0.0.0/8'), or empty for any.
        event_type_pattern: exact name or glob ('ssh_*'), or empty for any.

    For rate_limit, set both `rate_limit_count` and `rate_limit_window_seconds`
    — e.g. (3, 60) means allow up to 3 matching events per minute, drop the rest.

    Args:
        label: Human-readable label (e.g. 'censys-scanner').
        ip_pattern: IP address or CIDR. Empty = match any IP.
        event_type_pattern: Event type name or glob. Empty = match any event type.
        action: 'drop' (silently discard) or 'rate_limit' (keep N per window).
        rate_limit_count: Max events allowed per window (rate_limit only).
        rate_limit_window_seconds: Window length in seconds (rate_limit only).
        expires_in_hours: Auto-deactivate the rule after this many hours.
    """
    if action == "rate_limit" and (rate_limit_count is None or rate_limit_window_seconds is None):
        return {"error": "rate_limit action requires rate_limit_count and rate_limit_window_seconds."}

    if not ip_pattern and not event_type_pattern:
        return {"error": "Specify ip_pattern, event_type_pattern, or both — empty rules would match every event."}

    expires_at = None
    if expires_in_hours is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)

    async with get_session() as session:
        rule = SuppressionRule(
            label=label,
            ip_pattern=ip_pattern or None,
            event_type_pattern=event_type_pattern or None,
            action=action,
            rate_limit_count=rate_limit_count,
            rate_limit_window_seconds=rate_limit_window_seconds,
            expires_at=expires_at,
            active=True,
        )
        session.add(rule)
        await session.flush()
        rule_id = rule.id

    # Force the suppression engine to pick up the new rule on its next event.
    from honeypot_mcp.suppression import invalidate_rule_cache
    invalidate_rule_cache()

    return {
        "id": rule_id,
        "label": label,
        "ip_pattern": ip_pattern,
        "event_type_pattern": event_type_pattern,
        "action": action,
        "rate_limit_count": rate_limit_count,
        "rate_limit_window_seconds": rate_limit_window_seconds,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "active": True,
    }


@mcp.tool
async def suppression_remove(rule_id: int) -> dict[str, Any]:
    """Deactivate a suppression rule.

    Args:
        rule_id: The rule ID returned by suppression_add.
    """
    async with get_session() as session:
        result = await session.execute(
            update(SuppressionRule)
            .where(SuppressionRule.id == rule_id)
            .values(active=False)
        )
        if result.rowcount == 0:
            return {"error": f"No suppression rule with id={rule_id}."}

    from honeypot_mcp.suppression import invalidate_rule_cache
    invalidate_rule_cache()
    return {"id": rule_id, "active": False}


@mcp.tool
async def suppression_list(active_only: bool = True) -> list[dict[str, Any]]:
    """List suppression rules with their hit counts.

    Args:
        active_only: If True (default), only return active rules.
    """
    async with get_session() as session:
        q = select(SuppressionRule)
        if active_only:
            q = q.where(SuppressionRule.active.is_(True))
        result = await session.execute(q.order_by(SuppressionRule.created_at.desc()))
        rules = list(result.scalars().all())

    return [
        {
            "id": r.id,
            "label": r.label,
            "ip_pattern": r.ip_pattern,
            "event_type_pattern": r.event_type_pattern,
            "action": r.action,
            "rate_limit_count": r.rate_limit_count,
            "rate_limit_window_seconds": r.rate_limit_window_seconds,
            "active": r.active,
            "suppressed_count": r.suppressed_count,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]
