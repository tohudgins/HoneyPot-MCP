"""SOC platform tools: outbound webhook subscriptions and event suppression.

These are the integration points other SOC tooling plugs into:
- `alert_subscribe` — send alerts to Slack, Teams, email, a SIEM or a webhook.
- `suppression_add` / `suppression_load_preset` — drop or rate-limit noisy sources.

Subscriptions and rules are stored in the DB and survive restarts.
"""

from __future__ import annotations

import contextlib
import ipaddress
import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from sqlalchemy import select, update

from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import AlertSeverity, Subscription, SuppressionRule
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action

_ACTIONS = ("drop", "rate_limit")
_MAX_RATE_COUNT = 1_000_000
_MAX_RATE_WINDOW = 7 * 24 * 3600
_MAX_PATTERN_LEN = 256


def _wildcard_only(pattern: str) -> bool:
    """True for patterns like `*`, `**`, `?*` that match everything."""
    return bool(pattern) and set(pattern) <= {"*", "?"} and "*" in pattern


def _validate_rule(
    ip_pattern: object,
    event_type_pattern: object,
    action: object,
    rate_limit_count: object,
    rate_limit_window_seconds: object,
    *,
    confirm_match_all: bool,
) -> str | None:
    """Why a suppression rule is unacceptable, or None. Shared by
    `suppression_add` and `suppression_load_preset` so a preset cannot do what
    the tool refuses."""
    if action not in _ACTIONS:
        return f"action must be one of {list(_ACTIONS)}, got {action!r}."
    if action == "rate_limit":
        count, window = rate_limit_count, rate_limit_window_seconds
        if count is None or window is None:
            return "rate_limit action requires rate_limit_count and rate_limit_window_seconds."
        if not (isinstance(count, int) and isinstance(window, int)) or isinstance(count, bool):
            return "rate_limit_count and rate_limit_window_seconds must be integers."
        if not (1 <= count <= _MAX_RATE_COUNT and 1 <= window <= _MAX_RATE_WINDOW):
            return (
                f"rate_limit_count must be 1-{_MAX_RATE_COUNT} and "
                f"rate_limit_window_seconds 1-{_MAX_RATE_WINDOW}."
            )

    ip_matches_all = event_matches_all = True
    if ip_pattern:
        if not isinstance(ip_pattern, str) or len(ip_pattern) > _MAX_PATTERN_LEN:
            return "ip_pattern must be an IP address or CIDR string."
        try:
            network = ipaddress.ip_network(ip_pattern.strip(), strict=False)
        except ValueError:
            return f"ip_pattern {ip_pattern!r} is not a valid IP address or CIDR."
        ip_matches_all = network.prefixlen == 0
    if event_type_pattern:
        if not isinstance(event_type_pattern, str) or len(event_type_pattern) > _MAX_PATTERN_LEN:
            return "event_type_pattern must be a string."
        event_matches_all = _wildcard_only(event_type_pattern)
    if ip_matches_all and event_matches_all and not confirm_match_all:
        return (
            "This rule would match every event and silently end all collection. "
            "Narrow it, or pass confirm_match_all=True if that is really the intent."
        )
    return None


# ── Subscriptions ─────────────────────────────────────────────────────────────

_HUMAN_FORMATS = ("slack", "teams", "email")
_TEAMS_HOST_SUFFIXES = ("office.com", "office365.com", "logic.azure.com", "powerplatform.com")


def _infer_format(url: str) -> str:
    """The delivery format a URL is most plausibly meant for; `json` when nothing fits."""
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if scheme in ("udp", "tcp"):
        return "syslog"
    if scheme in ("smtp", "smtps"):
        return "email"
    if host == "slack.com" or host.endswith(".slack.com"):
        return "slack"
    if any(host == s or host.endswith("." + s) for s in _TEAMS_HOST_SUFFIXES):
        return "teams"
    if path.startswith("/services/collector"):
        return "splunk_hec"
    if path.endswith("/loki/api/v1/push"):
        return "loki"
    if "datadoghq" in host or "datadog" in host:
        return "datadog"
    return "json"


def _error(message: str, hint: str) -> dict[str, Any]:
    return {"error": message, "hint": hint}


@mcp.tool(auth=require_role("admin"), **hints("alert_subscribe"))
async def alert_subscribe(
    url: str,
    label: str | None = None,
    severity_threshold: Literal["low", "medium", "high", "critical"] | None = None,
    secret: str | None = None,
    format: Literal[
        "json",
        "splunk_hec",
        "elastic_ecs",
        "cef",
        "syslog",
        "loki",
        "datadog",
        "slack",
        "teams",
        "email",
    ]
    | None = None,
) -> dict[str, Any]:
    """Send new alerts to Slack, Teams, email, a SIEM or any webhook as they happen.

    Use it for "alert me in Slack", "send critical alerts to Splunk", "email the SOC when a bait credential is used". Only `url` is needed: the format is recognised from the address (Slack, Teams, Splunk HEC, Loki, Datadog, `smtp://` email, `udp://`/`tcp://` syslog, anything else a signed JSON webhook). Slack, Teams and email default to high and critical alerts and are throttled (repeats merged, critical always sent); other formats default to medium and up.

    Args:
        url: Where to send. Email: `smtp://user:pass@host:587/?from=a@x.org&to=b@x.org` (`smtps://` for port 465, `&tls=none` for a plain relay).
        label: A name for it (default: from the format and host).
        severity_threshold: Lowest severity to send ("only critical" is critical; "everything" is low).
        secret: What the receiver needs: Splunk HEC token, Datadog API key, Loki basic-auth value. Plain JSON webhooks get a generated HMAC key, returned once.
        format: Only to override the guess from the url.
    """
    parsed = urlparse(url.strip())
    url = url.strip()
    if not parsed.hostname:
        return _error(
            f"URL {url!r} has no host.",
            "Give the full address, e.g. https://hooks.slack.com/services/..., "
            "smtp://host:587/?from=...&to=..., or udp://siem.example.com:514.",
        )
    inferred = format is None
    format = format or _infer_format(url)  # type: ignore[assignment]
    assert format is not None
    if format == "syslog":
        allowed_schemes = {"udp", "tcp"}
    elif format == "email":
        allowed_schemes = {"smtp", "smtps"}
    else:
        allowed_schemes = {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        return _error(
            f"format={format} requires a URL scheme in {sorted(allowed_schemes)}, "
            f"got {parsed.scheme!r}.",
            "Fix the scheme of the address, or pass format= to match it "
            "(syslog uses udp:// or tcp://, email smtp:// or smtps://, the rest http(s)://).",
        )
    if format == "email":
        # Parse now rather than at first delivery: a typo that only surfaces as a
        # silently failing subscription is how people end up believing they are covered.
        from honeypot_mcp.webhooks import _parse_smtp_url

        try:
            _parse_smtp_url(url)
        except ValueError as e:
            return _error(
                str(e), "Email URLs look like smtp://user:pass@host:587/?from=a@x.org&to=b@x.org"
            )

    if label is None or not label.strip():
        label = f"{format} {parsed.hostname}"[:128]
    label = label.strip()[:128]

    # This tool sends captured attack data to an address of the caller's choosing, so it must
    # not reach cloud metadata, loopback or internal ranges (unless the operator opted in).
    # Checked again before every delivery; this is the fail-fast copy.
    from honeypot_mcp.webhooks import check_destination, redact_url

    refusal, _addresses = await check_destination(url, format)
    # A name that does not resolve *right now* is not a policy violation (the delivery-time
    # check records it in `last_error`); only an address captured data must not go to is refused.
    if refusal and refusal.startswith("destination refused"):
        await record_action(
            "alert_subscribe",
            f"Refused subscription {label!r} to {redact_url(url)}: {refusal}",
            arguments={"label": label, "format": format, "destination": redact_url(url)},
            target=redact_url(url),
            outcome="error",
            error=refusal,
        )
        return _error(
            refusal,
            "Use a publicly reachable address. Internal destinations are refused unless the "
            "operator sets WEBHOOK_ALLOW_PRIVATE_DESTINATIONS=true on the server.",
        )

    threshold = severity_threshold or ("high" if format in _HUMAN_FORMATS else "medium")
    generated_secret = None
    if not secret and format == "json":
        generated_secret = secrets.token_urlsafe(32)
        secret = generated_secret
    elif not secret:
        secret = None

    async with get_session() as session:
        sub = Subscription(
            label=label,
            url=url,
            severity_threshold=AlertSeverity(threshold),
            hmac_secret=secret,
            active=True,
            format=format,
        )
        session.add(sub)
        await session.flush()
        sub_id = sub.id

    from honeypot_mcp.webhooks import invalidate_subscription_cache

    invalidate_subscription_cache()

    await record_action(
        "alert_subscribe",
        f"Subscribed #{sub_id} ({label}) to {redact_url(url)} as {format}",
        arguments={
            "label": label,
            "format": format,
            "severity_threshold": threshold,
            "destination": redact_url(url),
        },
        target=redact_url(url),
    )
    out: dict[str, Any] = {
        "id": sub_id,
        "label": label,
        "url": redact_url(url),
        "format": format,
        "format_guessed_from_url": inferred,
        "severity_threshold": threshold,
        "active": True,
        "note": (
            f"Alerts of {threshold} severity and above will be sent to {redact_url(url)} as "
            f"{format}. Stop with alert_unsubscribe(subscription_id={sub_id})."
        ),
    }
    if generated_secret:
        out["secret"] = generated_secret
        out["secret_note"] = (
            "Shown once. Verify deliveries with HMAC-SHA256 of the body in the "
            "`X-HoneyPot-Signature: sha256=<hex>` header."
        )
    return out


@mcp.tool(auth=require_role("admin"), **hints("alert_unsubscribe"))
async def alert_unsubscribe(subscription_id: int) -> dict[str, Any]:
    """Stop sending alerts to a subscription (the row is kept for audit).

    Use it for "stop the Slack alerts". Find the id with `alert_subscriptions_list`.

    Args:
        subscription_id: The subscription's id (from alert_subscribe or alert_subscriptions_list).
    """
    async with get_session() as session:
        result = await session.execute(
            update(Subscription).where(Subscription.id == subscription_id).values(active=False)
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            return _error(
                f"No subscription with id={subscription_id}.",
                "Call alert_subscriptions_list (active_only=false for old ones) to see the ids.",
            )

    from honeypot_mcp.webhooks import invalidate_subscription_cache

    invalidate_subscription_cache()
    await record_action(
        "alert_unsubscribe",
        f"Deactivated subscription #{subscription_id}",
        arguments={"subscription_id": subscription_id},
        target=str(subscription_id),
    )
    return {
        "id": subscription_id,
        "active": False,
        "note": "Deliveries to this subscription have stopped.",
    }


@mcp.tool(**hints("alert_subscriptions_list"))
async def alert_subscriptions_list(active_only: bool = True) -> dict[str, Any]:
    """Where are alerts being sent, and are the deliveries working?

    Use it for "who gets alerted?", "is the Slack channel still receiving?". Destinations show as `scheme://host` only; secrets are never returned.

    Args:
        active_only: True (default) hides subscriptions that were stopped; set False to include them.
    """
    from honeypot_mcp.webhooks import redact_url

    async with get_session() as session:
        q = select(Subscription)
        if active_only:
            q = q.where(Subscription.active.is_(True))
        result = await session.execute(q.order_by(Subscription.created_at.desc()))
        subs = list(result.scalars().all())

    rows = [
        {
            "id": s.id,
            "label": s.label,
            "url": redact_url(s.url),
            "severity_threshold": s.severity_threshold.value,
            "format": s.format,
            "active": s.active,
            "delivery_count": s.delivery_count,
            "suppressed_count": s.suppressed_count,
            "failure_count": s.failure_count,
            "last_delivery_at": s.last_delivery_at.isoformat() if s.last_delivery_at else None,
            "last_error": (s.last_error or "")[:160] or None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in subs
    ]
    if not rows:
        note = (
            "Nobody is subscribed, so alerts are only stored: a CRITICAL waits until someone "
            "looks. Add a channel with alert_subscribe(url=...)."
            if active_only
            else "No subscription has ever been created."
        )
    else:
        failing = [r["label"] for r in rows if r["active"] and r["last_error"]]
        note = (
            f"{len(failing)} subscription(s) recorded a delivery error: {failing}."
            if failing
            else f"{len(rows)} subscription(s)."
        )
    return {"count": len(rows), "subscriptions": rows, "note": note}


# ── Suppression rules ─────────────────────────────────────────────────────────

_MAX_LISTED_RULES = 100


def _rule_label(ip_pattern: str | None, event_type_pattern: str | None, action: str) -> str:
    what = " ".join(p for p in (ip_pattern, event_type_pattern) if p)
    return f"{action} {what}"[:128]


@mcp.tool(auth=require_role("operator"), **hints("suppression_add"))
async def suppression_add(
    ip_pattern: str | None = None,
    event_type_pattern: str | None = None,
    label: str | None = None,
    rate_limit_count: int | None = None,
    rate_limit_window_seconds: int | None = None,
    expires_in_hours: int | None = None,
    confirm_match_all: bool = False,
) -> dict[str, Any]:
    """Stop recording noisy events before they become alerts (nothing is stored or delivered).

    Use it for "ignore my scanner 203.0.113.7", "drop SSH noise from 203.0.113.0/24 for a day", "keep only 3 a minute of http_request from this IP". For well-known scanners such as Shodan or Censys use `suppression_load_preset` instead. Give an address, an event type, or both. A rule that would match everything is refused.

    Args:
        ip_pattern: One IP or one CIDR range (`203.0.113.0/24`). One rule per address; omit to match any address.
        event_type_pattern: An event type or a glob (`ssh_*`, `http_request`); omit to match any type.
        label: A name for the rule (default: made from the patterns).
        rate_limit_count: Instead of dropping everything, keep only this many matches per window.
        rate_limit_window_seconds: Length of that window; 60 (a minute) when only a count is given.
        expires_in_hours: Switch the rule off by itself after this long: "for a day" is 24, "a week" 168.
        confirm_match_all: Only when the person explicitly wants to stop ALL collection.
    """
    ip_pattern = ip_pattern.strip() if ip_pattern else None
    event_type_pattern = event_type_pattern.strip() if event_type_pattern else None
    if not ip_pattern and not event_type_pattern:
        return _error(
            "Give an ip_pattern, an event_type_pattern, or both: a rule with neither would "
            "match every event.",
            "For Shodan, Censys or private ranges use suppression_load_preset "
            "(suppression_list shows them); otherwise name the address or event type.",
        )
    if ip_pattern and ("," in ip_pattern or " " in ip_pattern):
        return _error(
            f"ip_pattern {ip_pattern!r} holds more than one address.",
            "Make one rule per address or use a CIDR range that covers them all.",
        )
    if rate_limit_window_seconds is not None and rate_limit_count is None:
        return _error(
            "rate_limit_window_seconds needs rate_limit_count.",
            "Say how many events to keep per window, or drop the window to discard every match.",
        )
    action = "drop"
    if rate_limit_count is not None:
        action = "rate_limit"
        if rate_limit_window_seconds is None:
            rate_limit_window_seconds = 60
    if expires_in_hours is not None and expires_in_hours <= 0:
        return _error(
            "expires_in_hours must be greater than 0.",
            "Leave it out for a rule that lasts until suppression_remove; a day is 24, a week 168.",
        )

    problem = _validate_rule(
        ip_pattern,
        event_type_pattern,
        action,
        rate_limit_count,
        rate_limit_window_seconds,
        confirm_match_all=confirm_match_all,
    )
    if problem:
        return _error(
            problem,
            "ip_pattern is an address or CIDR like 203.0.113.0/24; event_type_pattern is a "
            "name or glob like ssh_*; counts and windows are whole numbers above 0. "
            "confirm_match_all is only for a deliberate stop of all collection.",
        )

    label = (label or "").strip()[:128] or _rule_label(ip_pattern, event_type_pattern, action)
    expires_at = None
    if expires_in_hours is not None:
        expires_at = datetime.now(UTC) + timedelta(hours=expires_in_hours)

    async with get_session() as session:
        rule = SuppressionRule(
            label=label,
            ip_pattern=ip_pattern,
            event_type_pattern=event_type_pattern,
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

    await record_action(
        "suppression_add",
        f"Added {action} suppression rule #{rule_id} ({label})",
        arguments={
            "label": label,
            "ip_pattern": ip_pattern,
            "event_type_pattern": event_type_pattern,
            "action": action,
            "confirm_match_all": confirm_match_all,
        },
        target=str(rule_id),
    )
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
        "note": (
            "Matching events are no longer recorded"
            + (
                f" except {rate_limit_count} per {rate_limit_window_seconds}s"
                if rate_limit_count
                else ""
            )
            + (f", until {expires_at:%Y-%m-%d %H:%M} UTC" if expires_at else "")
            + f". Undo with suppression_remove(rule_id={rule_id})."
        ),
    }


@mcp.tool(auth=require_role("operator"), **hints("suppression_remove"))
async def suppression_remove(rule_id: int) -> dict[str, Any]:
    """Switch a suppression rule off so its events are recorded again.

    Use it for "stop ignoring that scanner". Find ids with `suppression_list`.

    Args:
        rule_id: The rule's id (from suppression_add or suppression_list).
    """
    async with get_session() as session:
        result = await session.execute(
            update(SuppressionRule).where(SuppressionRule.id == rule_id).values(active=False)
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            return _error(
                f"No suppression rule with id={rule_id}.",
                "Call suppression_list to see the rule ids.",
            )

    from honeypot_mcp.suppression import invalidate_rule_cache

    invalidate_rule_cache()
    await record_action(
        "suppression_remove",
        f"Deactivated suppression rule #{rule_id}",
        arguments={"rule_id": rule_id},
        target=str(rule_id),
    )
    return {
        "id": rule_id,
        "active": False,
        "note": "Events this rule matched are recorded again.",
    }


@mcp.tool(**hints("suppression_list"))
async def suppression_list(active_only: bool = True) -> dict[str, Any]:
    """Which events are currently being ignored, and which known-noise presets can be loaded?

    Use it for "what are we suppressing?", "is the Shodan rule loaded?", "can we ignore Shodan?".
    `rules` shows how many events each rule hid; `presets` lists what suppression_load_preset can
    switch on (shodan, censys, internal-rfc1918) and whether each is loaded.

    Args:
        active_only: True (default) shows only rules in effect; set False to include removed and expired ones.
    """
    async with get_session() as session:
        q = select(SuppressionRule)
        if active_only:
            q = q.where(SuppressionRule.active.is_(True))
        result = await session.execute(q.order_by(SuppressionRule.created_at.desc()))
        rules = list(result.scalars().all())

    now = datetime.now(UTC)
    in_effect = {
        r.label
        for r in (rules if active_only else [r for r in rules if r.active])
        if r.label and (r.expires_at is None or r.expires_at > now)
    }
    if active_only:
        rules = [r for r in rules if r.expires_at is None or r.expires_at > now]
    total = len(rules)
    shown = rules[:_MAX_LISTED_RULES]
    rows = [
        {
            "id": r.id,
            "label": r.label,
            "ip_pattern": r.ip_pattern,
            "event_type_pattern": r.event_type_pattern,
            "action": r.action,
            "rate_limit_count": r.rate_limit_count,
            "rate_limit_window_seconds": r.rate_limit_window_seconds,
            "active": r.active and (r.expires_at is None or r.expires_at > now),
            "suppressed_count": r.suppressed_count,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in shown
    ]
    if not total:
        note = (
            "No suppression rules are in effect: every event is recorded. Add one with "
            "suppression_add, or load a known-scanner list with suppression_load_preset."
        )
    elif total > len(rows):
        note = f"Showing the newest {len(rows)} of {total} rules."
    else:
        note = f"{total} rule(s)."
    presets = _describe_presets(in_effect)
    if presets:
        note += " Presets: load one with suppression_load_preset(preset_name=...)."
    return {
        "count": total,
        "shown": len(rows),
        "rules": rows,
        "presets": presets,
        "note": note,
    }


@mcp.tool(auth=require_role("operator"), **hints("suppression_load_preset"))
async def suppression_load_preset(preset_name: str) -> dict[str, Any]:
    """Stop alerting on a known group of noisy sources in one step.

    Use it for "stop alerting on Shodan", "ignore Censys", "ignore my internal network". Names come from `suppression_list` (shodan, censys, internal-rfc1918). Loading again re-enables rules that were removed.

    Args:
        preset_name: The preset's name, e.g. "shodan".
    """
    import yaml

    available = _list_available_presets()
    if not _PRESET_NAME_RE.fullmatch(preset_name):
        return _error(
            "Preset names are letters, digits, '_' and '-' only (max 64).",
            f"Available presets: {available}.",
        )
    preset_text = _read_preset(preset_name)
    if preset_text is None:
        return _error(
            f"Preset '{preset_name}' not found.",
            f"Available presets: {available}. suppression_list describes each.",
        )

    try:
        raw = yaml.safe_load(preset_text)
    except yaml.YAMLError as e:
        return _error(
            f"Preset '{preset_name}' is not valid YAML: {e}"[:300],
            "Fix the preset file under config/suppression_presets/ or remove it to use the bundled one.",
        )
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        return _error(
            f"Preset '{preset_name}' must be a mapping with a list of `rules`.",
            "See the bundled presets for the format.",
        )
    preset_rules = raw["rules"]
    if not preset_rules:
        return _error(f"Preset '{preset_name}' contains no rules.", "Add rules to it first.")

    applied: list[dict[str, Any]] = []
    reactivated: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []

    async with get_session() as session:
        for entry in preset_rules:
            if not isinstance(entry, dict):
                skipped.append({"entry": str(entry)[:80], "reason": "not a mapping"})
                continue
            label = entry.get("label")
            if not label or not isinstance(label, str):
                skipped.append({"entry": str(entry)[:80], "reason": "missing label"})
                continue
            # A preset gets exactly the validation suppression_add applies, and
            # no way to confirm a match-all: that must be an explicit human call.
            problem = _validate_rule(
                entry.get("ip_pattern"),
                entry.get("event_type_pattern"),
                entry.get("action", "drop"),
                entry.get("rate_limit_count"),
                entry.get("rate_limit_window_seconds"),
                confirm_match_all=False,
            )
            if problem:
                skipped.append({"label": label, "reason": problem})
                continue
            existing = (
                (
                    await session.execute(
                        select(SuppressionRule)
                        .where(SuppressionRule.label == label)
                        .order_by(SuppressionRule.active.desc(), SuppressionRule.id.desc())
                    )
                )
                .scalars()
                .first()
            )
            if existing is not None:
                if existing.active and (
                    existing.expires_at is None or existing.expires_at > datetime.now(UTC)
                ):
                    skipped.append({"label": label, "reason": "already in effect"})
                else:  # removed or expired earlier: loading the preset again means "back on"
                    existing.active = True
                    existing.expires_at = None
                    reactivated.append({"id": existing.id, "label": label})
                continue

            rule = SuppressionRule(
                label=label,
                ip_pattern=entry.get("ip_pattern") or None,
                event_type_pattern=entry.get("event_type_pattern") or None,
                action=entry.get("action", "drop"),
                rate_limit_count=entry.get("rate_limit_count"),
                rate_limit_window_seconds=entry.get("rate_limit_window_seconds"),
                active=True,
            )
            session.add(rule)
            await session.flush()
            applied.append({"id": rule.id, "label": label, "ip_pattern": rule.ip_pattern})

    if applied or reactivated:
        from honeypot_mcp.suppression import invalidate_rule_cache

        invalidate_rule_cache()

    summary = f"{len(applied)} added, {len(reactivated)} switched back on, {len(skipped)} skipped"
    await record_action(
        "suppression_load_preset",
        f"Loaded suppression preset {preset_name!r}: {summary}",
        arguments={"preset_name": preset_name},
        target=preset_name,
    )
    return {
        "preset": preset_name,
        "description": raw.get("description", ""),
        "applied": applied,
        "reactivated": reactivated,
        "skipped": skipped,
        "summary": summary,
        "note": (
            f"{preset_name}: {summary}. Undo each rule with suppression_remove; "
            "suppression_list shows the ids."
        ),
    }


# Operator-supplied presets, relative to wherever the server was launched.
# Bundled presets ship inside the package instead, so they survive a pip
# install — an earlier version looked for them next to the repo root, which
# resolves to a non-existent path in site-packages and made every bundled
# preset silently invisible to anyone who installed from a wheel.
_LOCAL_PRESET_DIR = Path("config") / "suppression_presets"


def _bundled_presets():  # type: ignore[no-untyped-def]
    from importlib.resources import files

    return files("honeypot_mcp") / "presets"


_PRESET_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _read_preset(name: str) -> str | None:
    """Return a preset's YAML, preferring an operator override on disk.

    `name` is a bare stem: anything else (path separators, dots, NUL) is
    refused before it can reach the filesystem, and the resolved operator path
    must still sit inside the preset directory.
    """
    if not _PRESET_NAME_RE.fullmatch(name):
        return None
    local_dir = _LOCAL_PRESET_DIR.resolve()
    local = (_LOCAL_PRESET_DIR / f"{name}.yaml").resolve()
    if local.parent == local_dir and local.is_file():
        return local.read_text(encoding="utf-8")
    with contextlib.suppress(FileNotFoundError, ModuleNotFoundError):
        resource = _bundled_presets() / f"{name}.yaml"
        if resource.is_file():
            return resource.read_text(encoding="utf-8")
    return None


def _list_available_presets() -> list[str]:
    presets: list[str] = []
    with contextlib.suppress(FileNotFoundError, ModuleNotFoundError):
        presets.extend(
            r.name.removesuffix(".yaml")
            for r in _bundled_presets().iterdir()
            if r.name.endswith(".yaml")
        )
    if _LOCAL_PRESET_DIR.is_dir():
        presets.extend(f.stem for f in _LOCAL_PRESET_DIR.glob("*.yaml"))
    return sorted(set(presets))


def _describe_presets(in_effect: set[str]) -> list[dict[str, Any]]:
    """Each available preset: name, what it covers, rule count and whether it is fully loaded."""
    import yaml

    presets: list[dict[str, Any]] = []
    for name in _list_available_presets():
        description, labels = "", []
        text = _read_preset(name)
        if text is not None:
            try:
                raw = yaml.safe_load(text)
            except yaml.YAMLError:
                raw = None
            if isinstance(raw, dict):
                description = str(raw.get("description") or "")[:200]
                if isinstance(raw.get("rules"), list):
                    labels = [
                        e["label"] for e in raw["rules"] if isinstance(e, dict) and e.get("label")
                    ]
        presets.append(
            {
                "name": name,
                "description": description,
                "rules": len(labels) if labels else None,
                "loaded": bool(labels) and all(label in in_effect for label in labels),
            }
        )
    return presets
