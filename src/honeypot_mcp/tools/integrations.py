"""SOC platform tools: outbound webhook subscriptions and event suppression.

These are the integration points other SOC tooling plugs into:
- `alert_subscribe` — register a URL to receive real-time alerts (Slack, SIEM, PagerDuty, custom).
- `suppression_add` — drop or rate-limit noisy sources (known scanners, your own scans).

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


@mcp.tool(auth=require_role("admin"), **hints("alert_subscribe"))
async def alert_subscribe(
    url: str,
    label: str,
    severity_threshold: Literal["low", "medium", "high", "critical"] = "medium",
    hmac_secret: str | None = None,
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
    ] = "json",
) -> dict[str, Any]:
    """Register a URL to receive real-time alert deliveries in a SIEM-native format.

    The `format` argument picks the body shape and auth scheme:

    * `json` (default) — raw JSON envelope, optionally HMAC-signed via
      `X-HoneyPot-Signature: sha256=<hex>` (set `hmac_secret`). Works with
      Slack/Discord/PagerDuty/generic webhook consumers.
    * `splunk_hec` — Splunk HTTP Event Collector. URL ends in
      `/services/collector/event`. Pass your Splunk HEC token via
      `hmac_secret` — it's sent as `Authorization: Splunk <token>`.
    * `elastic_ecs` — Elastic Common Schema field re-mapping (source.ip,
      event.action, event.severity, @timestamp). POST as JSON; works with
      Elastic Bulk API receivers and Filebeat HTTP input.
    * `cef` — ArcSight CEF pipe-delimited text. Compatible with QRadar
      Universal CEF Connector as well.
    * `syslog` — RFC 5424 framed message. URL scheme picks the transport:
      `udp://host:514` for UDP datagrams, `tcp://host:514` for TCP.
    * `loki` — Grafana Loki push API. URL ends in `/loki/api/v1/push`. If
      `hmac_secret` is set, it rides as `Authorization: Basic <secret>`
      (Grafana Cloud expects `<userid>:<token>` pre-encoded — encode that
      yourself and pass the result).
    * `datadog` — Datadog Logs API v2. URL is
      `https://http-intake.logs.datadoghq.com/api/v2/logs` (or your
      regional equivalent). Pass your DD API key via `hmac_secret` — it's
      sent as `DD-API-KEY: <key>`.

    Human-facing channels, which notify a person rather than fill an index:

    * `slack` — Slack incoming webhook (`https://hooks.slack.com/services/...`).
      Formatted Block Kit message: severity-coloured, source IP and captured
      credentials/command/path up front, honeytoken trips called out.
    * `teams` — Microsoft Teams incoming webhook. MessageCard, which renders
      on both the classic Office 365 connector and the newer Workflows path.
    * `email` — SMTP. The URL carries everything:
      `smtp://user:pass@smtp.example.com:587/?from=honeypot@example.com&to=soc@example.com`
      Comma-separate multiple recipients. `smtps://` for implicit TLS (465);
      `smtp://` upgrades via STARTTLS unless you add `&tls=none` for a local
      relay that has none.

    These three are **coalesced**: the same (event_type, source_ip) notifies at
    most once per `NOTIFY_THROTTLE_SECONDS` (default 300), with the suppressed
    count carried on the next message. CRITICAL bypasses that window (capped
    per event type per minute). One
    scanner produces thousands of events an hour, and a channel that relays
    them one-to-one gets muted — which is worse than no integration, because
    everyone then believes they are covered. Set `severity_threshold="high"`
    or `"critical"` for these unless you want a busy channel.

    Args:
        url: Webhook URL (`udp://`/`tcp://` for syslog, `smtp://` for email).
        label: Human-readable label (e.g. 'splunk-prod', 'qradar-cef').
        severity_threshold: Minimum severity to deliver — events below are skipped.
        hmac_secret: Auth secret. JSON: HMAC key. Splunk HEC: HEC token.
                     Loki: pre-encoded basic-auth. Datadog: API key. Pass
                     empty string ("") to generate a random 32-byte secret.
        format: Output format — see above.
    """
    # Validate the URL up front — a malformed or wrong-scheme URL otherwise
    # sits in the DB silently failing every delivery. syslog uses udp://tcp://;
    # every other format is HTTP(S).
    parsed = urlparse(url)
    if not parsed.hostname:
        return {"error": f"URL {url!r} has no host."}
    if format == "syslog":
        allowed_schemes = {"udp", "tcp"}
    elif format == "email":
        allowed_schemes = {"smtp", "smtps"}
    else:
        allowed_schemes = {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        return {
            "error": (
                f"format={format} requires a URL scheme in {sorted(allowed_schemes)}, "
                f"got {parsed.scheme!r}."
            )
        }
    if format == "email":
        # Parse now rather than at first delivery. An address typo that only
        # surfaces as a silently failing subscription is exactly how people end
        # up believing they have alerting when they do not.
        from honeypot_mcp.webhooks import _parse_smtp_url

        try:
            _parse_smtp_url(url)
        except ValueError as e:
            return {"error": str(e)}

    # Destination policy: this tool sends captured attack data to an address
    # of the caller's choosing, so it must not reach cloud metadata, loopback
    # or internal ranges (unless the operator opted in). Checked again before
    # every delivery; this is the fail-fast copy.
    from honeypot_mcp.webhooks import check_destination, redact_url

    refusal, _addresses = await check_destination(url, format)
    # A name that does not resolve *right now* is not a policy violation (DNS
    # can be briefly down, and the delivery-time check records it in
    # `last_error`); only an address captured data must not go to is refused.
    if refusal and refusal.startswith("destination refused"):
        await record_action(
            "alert_subscribe",
            f"Refused subscription {label!r} to {redact_url(url)}: {refusal}",
            arguments={"label": label, "format": format, "destination": redact_url(url)},
            target=redact_url(url),
            outcome="error",
            error=refusal,
        )
        return {"error": refusal}

    if hmac_secret == "":
        hmac_secret = secrets.token_urlsafe(32)

    async with get_session() as session:
        sub = Subscription(
            label=label,
            url=url,
            severity_threshold=AlertSeverity(severity_threshold),
            hmac_secret=hmac_secret,
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
            "severity_threshold": severity_threshold,
            "destination": redact_url(url),
        },
        target=redact_url(url),
    )
    return {
        "id": sub_id,
        "label": label,
        "url": url,
        "severity_threshold": severity_threshold,
        "hmac_secret": hmac_secret,
        "format": format,
        "active": True,
    }


@mcp.tool(auth=require_role("admin"), **hints("alert_unsubscribe"))
async def alert_unsubscribe(subscription_id: int) -> dict[str, Any]:
    """Deactivate a webhook subscription. Existing rows are kept for audit; only
    `active=False` is set so deliveries stop.

    Admin-only, like `alert_subscribe`: it changes where captured data flows.

    Args:
        subscription_id: The subscription ID returned by alert_subscribe.
    """
    async with get_session() as session:
        result = await session.execute(
            update(Subscription).where(Subscription.id == subscription_id).values(active=False)
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            return {"error": f"No subscription with id={subscription_id}."}

    from honeypot_mcp.webhooks import invalidate_subscription_cache

    invalidate_subscription_cache()
    await record_action(
        "alert_unsubscribe",
        f"Deactivated subscription #{subscription_id}",
        arguments={"subscription_id": subscription_id},
        target=str(subscription_id),
    )
    return {"id": subscription_id, "active": False}


@mcp.tool(**hints("alert_subscriptions_list"))
async def alert_subscriptions_list(active_only: bool = True) -> list[dict[str, Any]]:
    """List webhook subscriptions with their delivery health stats.

    This is viewer-tier, so destinations are redacted to `scheme://host[:port]`:
    webhook URLs carry their credential in the path or userinfo, and SMTP URLs
    carry recipient addresses. Secrets are never returned.

    Args:
        active_only: If True (default), only return active subscriptions.
    """
    from honeypot_mcp.webhooks import redact_url

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
            "url": redact_url(s.url),
            "severity_threshold": s.severity_threshold.value,
            "format": s.format,
            "active": s.active,
            "delivery_count": s.delivery_count,
            "failure_count": s.failure_count,
            "last_delivery_at": s.last_delivery_at.isoformat() if s.last_delivery_at else None,
            "last_error": (s.last_error or "")[:160] or None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in subs
    ]


# ── Suppression rules ─────────────────────────────────────────────────────────


@mcp.tool(auth=require_role("operator"), **hints("suppression_add"))
async def suppression_add(
    label: str,
    ip_pattern: str | None = None,
    event_type_pattern: str | None = None,
    action: Literal["drop", "rate_limit"] = "drop",
    rate_limit_count: int | None = None,
    rate_limit_window_seconds: int | None = None,
    expires_in_hours: int | None = None,
    confirm_match_all: bool = False,
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
        confirm_match_all: A rule that would match EVERY event (a wildcard-only
            event pattern, a /0 CIDR) silently ends all collection; it is refused
            unless this is explicitly True.
    """
    if not ip_pattern and not event_type_pattern:
        return {
            "error": "Specify ip_pattern, event_type_pattern, or both — empty rules would match every event."
        }

    problem = _validate_rule(
        ip_pattern,
        event_type_pattern,
        action,
        rate_limit_count,
        rate_limit_window_seconds,
        confirm_match_all=confirm_match_all,
    )
    if problem:
        return {"error": problem}

    expires_at = None
    if expires_in_hours is not None:
        expires_at = datetime.now(UTC) + timedelta(hours=expires_in_hours)

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
    }


@mcp.tool(auth=require_role("operator"), **hints("suppression_remove"))
async def suppression_remove(rule_id: int) -> dict[str, Any]:
    """Deactivate a suppression rule so the events it was dropping are recorded again. Find rule
    ids with `suppression_list`.

    Args:
        rule_id: The rule ID returned by suppression_add.
    """
    async with get_session() as session:
        result = await session.execute(
            update(SuppressionRule).where(SuppressionRule.id == rule_id).values(active=False)
        )
        if result.rowcount == 0:  # type: ignore[attr-defined]
            return {"error": f"No suppression rule with id={rule_id}."}

    from honeypot_mcp.suppression import invalidate_rule_cache

    invalidate_rule_cache()
    await record_action(
        "suppression_remove",
        f"Deactivated suppression rule #{rule_id}",
        arguments={"rule_id": rule_id},
        target=str(rule_id),
    )
    return {"id": rule_id, "active": False}


@mcp.tool(**hints("suppression_list"))
async def suppression_list(active_only: bool = True) -> list[dict[str, Any]]:
    """List suppression rules (the filters that drop or rate-limit noisy events such as known
    scanners) with their ids and how many events each has matched.

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


@mcp.tool(auth=require_role("operator"), **hints("suppression_load_preset"))
async def suppression_load_preset(preset_name: str) -> dict[str, Any]:
    """Apply a bundled suppression preset (e.g. 'shodan', 'censys',
    'internal-rfc1918').

    Bundled presets ship inside the package; a matching file under
    `config/suppression_presets/<name>.yaml` overrides one. Each bundles a set
    of suppression rules for known-noise sources so the operator doesn't have
    to build the same `suppression_add` chain on every deployment.

    Args:
        preset_name: Filename stem of the preset (without `.yaml`).
    """
    import yaml

    if not _PRESET_NAME_RE.fullmatch(preset_name):
        return {"error": "Preset names are letters, digits, '_' and '-' only (max 64)."}
    preset_text = _read_preset(preset_name)
    if preset_text is None:
        return {
            "error": (f"Preset '{preset_name}' not found. Available: {_list_available_presets()}")
        }

    try:
        raw = yaml.safe_load(preset_text)
    except yaml.YAMLError as e:
        return {"error": f"Preset '{preset_name}' is not valid YAML: {e}"[:300]}
    if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
        return {"error": f"Preset '{preset_name}' must be a mapping with a list of `rules`."}
    preset_rules = raw["rules"]
    if not preset_rules:
        return {"error": f"Preset '{preset_name}' contains no rules."}

    applied: list[dict[str, Any]] = []
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
            # Avoid duplicate: if a rule with this label already exists and is
            # active, skip rather than re-creating.
            existing = (
                await session.execute(select(SuppressionRule).where(SuppressionRule.label == label))
            ).scalar_one_or_none()
            if existing is not None:
                skipped.append({"label": label, "reason": "already exists"})
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

    if applied:
        from honeypot_mcp.suppression import invalidate_rule_cache

        invalidate_rule_cache()

    await record_action(
        "suppression_load_preset",
        f"Loaded suppression preset {preset_name!r}: {len(applied)} applied, {len(skipped)} skipped",
        arguments={"preset_name": preset_name},
        target=preset_name,
    )
    return {
        "preset": preset_name,
        "description": raw.get("description", ""),
        "applied": applied,
        "skipped": skipped,
        "summary": f"{len(applied)} applied, {len(skipped)} skipped",
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


@mcp.tool(**hints("suppression_list_presets"))
async def suppression_list_presets() -> list[str]:
    """List bundled suppression presets available to `suppression_load_preset`.

    Presets are curated rule sets for known-benign noise sources — internet
    scanning services (shodan, censys) and internal RFC1918 ranges — so their
    traffic stops drowning out real attacks. Worth loading before exposing a
    honeypot to the internet.
    """
    return _list_available_presets()
