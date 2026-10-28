"""Alert and monitoring MCP tools."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from honeypot_mcp import rbac, retention
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries, rollups
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert, AlertDisposition, AlertSeverity
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import (
    digest_payload,
    mark_untrusted,
    truncate_payload,
    validate_ip,
    write_artifact,
)
from honeypot_mcp.tools._window import annotate_window, window_bounds, window_end

# An MCP reply lands in a model's context, so a list is cut to what fits and says so. The rows get
# this many bytes of JSON; the envelope and notes bring a reply to about 12 KB at most.
_ROWS_BUDGET = 10_000
_MAX_LIMIT = 100
# Alerts one filtered `alerts_acknowledge` call may triage: an over-broad filter must not clear the
# whole board in one go. The reply says when more still match.
_TRIAGE_CAP = 500
_SINCE_HINT = (
    "Use a number of hours, e.g. 1 for 'the last hour', 24 for 'today', 168 for 'this week'."
)
_QUOTE_CLIP = 60


def _quote(value: Any) -> str:
    """A captured value as a one-line inline-code span of at most 60 characters.

    Headlines are prose a model reads as the answer, and everything captured from the network is
    attacker-written: a quoted value is clipped, flattened to one line and fenced in backticks so
    it reads as evidence, never as a sentence of the headline."""
    text = " ".join(str(value).replace("`", "'").split())
    if len(text) > _QUOTE_CLIP:
        text = text[: _QUOTE_CLIP - 1] + "…"
    return f"`{text}`"


def _pct(part: int, whole: int) -> str:
    if whole <= 0 or part <= 0:
        return "0%"
    share = 100 * part / whole
    if share < 1:
        return "<1%"
    return f"{round(share)}%"


def _is_trip(event_type: str, payload: dict[str, Any] | None = None) -> bool:
    return event_type.startswith("honeytoken_") or bool((payload or {}).get("honeytoken_id"))


# What an event type means in plain words, first match wins. Fixed vocabulary only.
_MEANINGS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("honeytoken",), "planted bait was used, so someone is using stolen or scraped material"),
    (("exploit", "escape", "ransom", "amplification", "toll_fraud"), "an attack attempt"),
    (("command", "download", "upload", "file_"), "activity inside a session or a file transfer"),
    (("login", "auth", "ntlm", "bind", "credential"), "a login attempt with captured credentials"),
    (("scan", "probe", "sweep", "enumeration", "recon"), "reconnaissance"),
    (("connection", "handshake"), "a bare connection, usually internet-wide scanning"),
)


def _meaning(event_type: str) -> str:
    low = event_type.lower()
    for words, meaning in _MEANINGS:
        if any(w in low for w in words):
            return meaning
    return "an event this sensor recorded"


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def _stats_headline(stats: dict[str, Any], since_hours: float | None) -> str:
    """The reading of `alerts_stats`: volume, how much is noise, concentration, what needs a look."""
    total = int(stats.get("total_alerts") or 0)
    where = f"in the last {since_hours:g} h" if since_hours is not None else "recorded"
    if not total:
        return f"No alerts {where}."
    by_sev = stats.get("by_severity") or {}
    low = int(by_sev.get("low", 0)) + int(by_sev.get("medium", 0))
    crit = int(by_sev.get("critical", 0))
    high = int(by_sev.get("high", 0))
    unique = int(stats.get("unique_source_ips") or 0)
    parts = [f"{total:,} alerts {where} from {_plural(unique, 'source')}"]
    mix = f"{_pct(low, total)} LOW/MEDIUM"
    top_types = stats.get("top_event_types") or []
    if top_types and low * 2 >= total:
        mix += f" (mostly {_quote(top_types[0]['type'])})"
    parts.append(mix)
    top_ips = stats.get("top_source_ips") or []
    if len(top_ips) >= 3 and unique > 3:
        share = sum(int(r["count"]) for r in top_ips[:3])
        if share * 2 >= total:
            parts.append(f"3 sources account for {_pct(share, total)} of events")
    trips = sum(int(t["count"]) for t in top_types if _is_trip(str(t["type"])))
    look: list[str] = []
    if trips:
        look.append(f"{_plural(trips, 'honeytoken trip')} (bait_trips)")
    other_crit = max(crit - trips, 0)
    if other_crit:
        look.append(f"{other_crit:,} CRITICAL")
    if high:
        look.append(f"{high:,} HIGH")
    text = ": ".join([parts[0], ", ".join(parts[1:])]) if len(parts) > 1 else parts[0]
    if look:
        text += "; needs a look: " + ", ".join(look) + " (alerts_recent with severity)"
    else:
        text += "; nothing CRITICAL or HIGH"
    return text + "."


def _narrowing(
    alerts: list[Alert], *, severity: str | None, source_ip: str | None, event_type: str | None
) -> str:
    """The one extra filter most likely to shrink a truncated list, as exact arguments."""
    sevs = {a.severity.value for a in alerts}
    if not severity and len(sevs) > 1:
        top = next(s for s in ("critical", "high", "medium", "low") if s in sevs)
        return f"severity='{top}'"
    if not source_ip and alerts:
        counts: dict[str, int] = {}
        for a in alerts:
            counts[a.source_ip] = counts.get(a.source_ip, 0) + 1
        ip, n = max(counts.items(), key=lambda kv: kv[1])
        if len(counts) > 1 and n * 2 >= len(alerts):
            return f"source_ip={_quote(ip)}"
    if not event_type and alerts:
        kinds: dict[str, int] = {}
        for a in alerts:
            kinds[a.event_type] = kinds.get(a.event_type, 0) + 1
        if len(kinds) > 1:
            return f"event_type={_quote(max(kinds, key=lambda k: kinds[k]))}"
    return "since_hours=1 (or the window you care about)"


def _list_headline(
    alerts: list[Alert], shown: int, total: int | None, *, narrow: str | None, ordered: str
) -> str:
    """One line for a list of alerts: how many of how many, severity, type and source mix."""
    sample = alerts[:shown]
    sevs: dict[str, int] = {}
    kinds: dict[str, int] = {}
    for a in sample:
        sevs[a.severity.value] = sevs.get(a.severity.value, 0) + 1
        kinds[a.event_type] = kinds.get(a.event_type, 0) + 1
    sources = len({a.source_ip for a in sample})
    if len(sevs) == 1:
        sev = f"all {next(iter(sevs)).upper()}"
    else:
        sev = ", ".join(
            f"{n} {s.upper()}"
            for s, n in sorted(
                sevs.items(),
                key=lambda kv: ("critical", "high", "medium", "low").index(kv[0]),
            )
        )
    top_kind = max(kinds, key=lambda k: kinds[k])
    what = (
        _quote(top_kind)
        if len(kinds) == 1
        else f"{len(kinds)} event types, mostly {_quote(top_kind)}"
    )
    if total is None:
        count = f"first {shown} matches"
    elif total > shown:
        count = f"{shown} of {total:,} matches"
    else:
        count = _plural(shown, "match", "matches")
    text = f"{count} ({ordered}): {sev}, {what}, from {_plural(sources, 'source')}."
    if (total is None or total > shown) and narrow:
        text += f" Truncated: narrow with {narrow}."
    return text


def _alert_headline(a: Alert, honeypot: str | None) -> str:
    """What one alert is, in plain words, with the enrichment verdict when it has one."""
    payload = a.payload or {}
    text = (
        f"Alert {a.id} is a {a.severity.value.upper()} {_quote(a.event_type)} from "
        f"{_quote(a.source_ip)}"
        + (f" on sensor {_quote(honeypot)}" if honeypot else "")
        + f": {_meaning(a.event_type)}."
    )
    if _is_trip(a.event_type, payload):
        text += " It is a honeytoken trip: see bait_trips."
    enrich = payload.get("enrichment")
    if isinstance(enrich, dict):
        abuse = enrich.get("abuseipdb")
        vt = enrich.get("virustotal")
        bits: list[str] = []
        if isinstance(abuse, dict) and isinstance(abuse.get("abuse_confidence_score"), int | float):
            bits.append(f"AbuseIPDB confidence {int(abuse['abuse_confidence_score'])}/100")
        if isinstance(vt, dict) and isinstance(vt.get("malicious_votes"), int | float):
            bits.append(f"{int(vt['malicious_votes'])} VirusTotal engines flag it")
        if bits:
            text += " Enrichment: " + ", ".join(bits) + "."
    if a.acknowledged:
        verdict = a.disposition.value.replace("_", " ") if a.disposition else "acknowledged"
        text += f" Already triaged ({verdict})."
    return text


def _fit(rows: list[dict[str, Any]], budget: int = _ROWS_BUDGET) -> list[dict[str, Any]]:
    """The leading rows whose JSON fits `budget` (always at least one)."""
    used = 0
    shown: list[dict[str, Any]] = []
    for row in rows:
        size = len(json.dumps(row, default=str)) + 2
        if shown and used + size > budget:
            break
        used += size
        shown.append(row)
    return shown


def _alert_row(a: Alert, names: dict[int, str]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": a.id,
        "source_ip": a.source_ip,
        "event_type": a.event_type,
        "severity": a.severity.value,
        "honeypot": names.get(a.honeypot_id) if a.honeypot_id else None,
        "timestamp": a.timestamp.isoformat(),
    }
    if a.acknowledged:
        row["acknowledged"] = True
        # Surfacing the verdict is what lets a shift skip what the previous one resolved.
        if a.disposition is not None:
            row["disposition"] = a.disposition.value
    if digest := digest_payload(a.payload):
        row["digest"] = digest
    return row


async def _since(since_hours: float | None) -> tuple[Any, Any, dict[str, Any] | None]:
    """`(since, window_end, error)` for an optional `since_hours`."""
    if since_hours is None:
        return None, None, None
    if since_hours <= 0:
        return None, None, {"error": "since_hours must be greater than 0.", "hint": _SINCE_HINT}
    since, end = await window_bounds(since_hours)
    return since, end, None


@mcp.tool(**hints("alerts_recent"))
async def alerts_recent(
    limit: int = 20,
    since_hours: float | None = None,
    source_ip: str | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    honeypot_name: str | None = None,
    event_type: str | None = None,
) -> dict[str, Any]:
    """What are the latest alerts, newest first, optionally from one address, sensor, severity or type?

    Use it for "what just happened", "anything critical today", "alerts from 203.0.113.7". Each
    alert has a short `digest` (credentials, path, command, exploit, country); `alerts_get` gives
    one alert in full, `alerts_search` finds alerts by what the attacker sent. The reply says how
    many alerts match in total.

    Args:
        limit: How many alerts to show (default 20; the reply is cut to a readable size).
        since_hours: Only the last N hours: "the last hour" is 1, "today" 24, "this week" 168.
        source_ip: Only alerts from this attacker address.
        severity: Only low, medium, high or critical alerts.
        honeypot_name: Only alerts from this sensor (names are in honeypot_list).
        event_type: Only this exact event type, e.g. ssh_login_failed.
    """
    limit = max(1, min(limit, _MAX_LIMIT))
    if source_ip and (bad := validate_ip(source_ip)):
        return {"error": bad, "hint": "Pass one attacker address, e.g. 203.0.113.7."}
    since, window_to, err = await _since(since_hours)
    if err:
        return err

    honeypot_id: int | None = None
    async with get_session() as session:
        names = await queries.get_honeypot_names(session)
        if honeypot_name:
            honeypot_id = next((i for i, n in names.items() if n == honeypot_name), None)
            if honeypot_id is None:
                return {
                    "error": f"No honeypot named '{honeypot_name}'.",
                    "hint": "Use one of: "
                    + (", ".join(sorted(names.values())) or "(none deployed)"),
                }
        sev = AlertSeverity(severity) if severity else None
        alerts = await queries.get_recent_alerts(
            session,
            limit=limit,
            source_ip=source_ip.strip() if source_ip else None,
            severity=sev,
            honeypot_id=honeypot_id,
            event_type=event_type,
            since=since,
        )
        total = await queries.count_alerts(
            session,
            since=since,
            now=window_to,
            source_ip=source_ip.strip() if source_ip else None,
            severity=sev,
            honeypot_id=honeypot_id,
            event_type=event_type,
        )
        types_here = (
            await rollups.event_type_counts(session, since, now=window_to)
            if event_type and not alerts
            else {}
        )

    rows = _fit([_alert_row(a, names) for a in alerts])
    result: dict[str, Any] = {"count": len(rows), "total_matching": max(total, len(rows))}
    result["alerts"] = rows
    if since is not None:
        result["window"] = f"last {since_hours}h (since {since.isoformat()})"
        await annotate_window(result)
    filtered = any((source_ip, severity, honeypot_name, event_type, since_hours is not None))
    if not rows:
        if event_type and types_here:
            top = sorted(types_here, key=lambda t: -types_here[t])[:10]
            result["note"] = (
                f"No alerts of type '{event_type}'. Event types seen in this window: "
                + ", ".join(top)
                + "."
            )
        elif filtered:
            result["note"] = (
                "No alerts match these filters. Try a longer time window or drop a filter."
            )
        else:
            result["note"] = "No alerts have been recorded yet."
    narrow = (
        _narrowing(alerts, severity=severity, source_ip=source_ip, event_type=event_type)
        if rows
        else None
    )
    if rows and len(rows) < result["total_matching"]:
        result["note"] = (
            f"Showing the newest {len(rows)} of {result['total_matching']:,} matching alerts. "
            f"To see others, narrow with {narrow}."
        )
    if rows:
        headline = _list_headline(
            alerts, len(rows), result["total_matching"], narrow=narrow, ordered="newest first"
        )
    else:
        headline = result["note"]
    return mark_untrusted({"headline": headline, **result})


@mcp.tool(**hints("alerts_get"))
async def alerts_get(alert_id: int) -> dict[str, Any]:
    """Show everything captured for one alert: "what exactly did alert 4312 contain?"

    The drill-down for an id from `alerts_recent` or `alerts_search`: full request headers, decoded
    bodies, command input, enrichment and triage state; only single oversized values are clipped.

    Args:
        alert_id: The numeric alert id (the `id` field of an alert in alerts_recent or alerts_search).
    """
    from sqlalchemy import func, select

    async with get_session() as session:
        alert = (
            await session.execute(select(Alert).where(Alert.id == alert_id))
        ).scalar_one_or_none()
        if alert is None:
            low, high = (
                await session.execute(select(func.min(Alert.id), func.max(Alert.id)))
            ).one()
            where = (
                f"Alert ids currently run from {low} to {high}; some may have been pruned. "
                if low is not None
                else "There are no alerts yet. "
            )
            return {
                "error": f"No alert with id {alert_id}.",
                "hint": where + "Find ids with alerts_recent or alerts_search (the `id` field).",
            }
        names = await queries.get_honeypot_names(session)

        return mark_untrusted(
            {
                "headline": _alert_headline(
                    alert, names.get(alert.honeypot_id) if alert.honeypot_id else None
                ),
                "id": alert.id,
                "honeypot": names.get(alert.honeypot_id) if alert.honeypot_id else None,
                "honeypot_id": alert.honeypot_id,
                "source_ip": alert.source_ip,
                "source_port": alert.source_port,
                "event_type": alert.event_type,
                "severity": alert.severity.value,
                "payload": truncate_payload(alert.payload),
                "acknowledged": alert.acknowledged,
                "disposition": alert.disposition.value if alert.disposition else None,
                "triage_note": alert.triage_note,
                "triaged_by": alert.triaged_by,
                "triaged_at": alert.triaged_at.isoformat() if alert.triaged_at else None,
                "timestamp": alert.timestamp.isoformat(),
            }
        )


@mcp.tool(**hints("alerts_search"))
async def alerts_search(
    query: str,
    limit: int = 20,
    since_hours: float | None = None,
) -> dict[str, Any]:
    """Find alerts by what the attacker sent: "who ran wget", "who tried the password admin123".

    Case-sensitive substring match over the attacker address, event type and the whole captured
    payload (commands, usernames, passwords, paths, user agents, file names, hashes), newest
    first. On a large capture a rare term takes a while: the search stops after a few seconds and
    says how far back it read. Use `alerts_recent` to browse by time or severity.

    Args:
        query: The text to look for, e.g. "wget", "/.env", "root", a file hash.
        limit: How many matches to show (default 20; the reply is cut to a readable size).
        since_hours: Only search the last N hours: "today" is 24, "this week" 168.
    """
    if not query or not query.strip():
        return {
            "error": "query is empty.",
            "hint": "Say what to look for, e.g. query='wget' or query='/.env' (a literal text).",
        }
    limit = max(1, min(limit, _MAX_LIMIT))
    since, _end, err = await _since(since_hours)
    if err:
        return err

    async with get_session() as session:
        found = await queries.search_alerts(session, query=query, limit=limit, since=since)
        names = await queries.get_honeypot_names(session)

    rows = _fit([_alert_row(a, names) for a in found.alerts])
    result: dict[str, Any] = {"query": query, "count": len(rows), "alerts": rows}
    if since is not None:
        result["window"] = f"last {since_hours}h (since {since.isoformat()})"
        await annotate_window(result)
    notes: list[str] = []
    truncated = len(rows) < len(found.alerts) or found.more
    narrow = _narrowing(found.alerts, severity=None, source_ip=None, event_type=None)
    search_narrow = (
        "since_hours=1 (or the window you care about) or a longer phrase"
        if narrow.startswith("since_hours")
        else f"a longer phrase, since_hours, or alerts_recent({narrow})"
    )
    if truncated:
        notes.append(
            f"Showing the newest {len(rows)} matches; there are more. To see others, narrow with "
            f"{search_narrow}."
        )
    if not found.complete:
        back = found.searched_back_to.isoformat() if found.searched_back_to else "an earlier time"
        notes.append(
            f"The search stopped after a few seconds and read alerts back to {back}; older "
            "alerts were NOT searched. Restrict it with a time window (since_hours) to cover "
            "them."
        )
    if not rows and found.complete:
        notes.append(
            "No matches. The search is a literal, case-sensitive substring: try a shorter or more "
            "distinctive fragment, or check the spelling."
        )
    if notes:
        result["note"] = " ".join(notes)
    if rows:
        headline = f"Search for {_quote(query)}: " + _list_headline(
            found.alerts,
            len(rows),
            None if truncated else len(rows),
            narrow=search_narrow,
            ordered="newest first",
        )
        if not found.complete:
            headline += " The search timed out, so older alerts were not read."
    elif found.complete:
        headline = f"No alert contains {_quote(query)}; the match is literal and case-sensitive."
    else:
        headline = (
            f"No match for {_quote(query)} yet, but the search timed out before reading all "
            "alerts: retry with since_hours."
        )
    return mark_untrusted({"headline": headline, **result})


@mcp.tool(**hints("alerts_stats"))
async def alerts_stats(since_hours: float | None = None) -> dict[str, Any]:
    """What is the overall picture: alert totals, severities, top attackers and event types?

    The quickest answer to "how busy are we", "who are the top attackers today". No individual
    alerts; use `alerts_recent` for those.

    Args:
        since_hours: Only the last N hours ("today" is 24, "this week" 168). Omit for all time.
    """
    since, window_to, err = await _since(since_hours)
    if err:
        return err

    async with get_session() as session:
        stats = await queries.get_alert_stats(session, since=since, now=window_to)
    if since is not None:
        stats["window"] = f"last {since_hours}h (since {since.isoformat()})"
        await annotate_window(stats)
    if not stats.get("total_alerts"):
        stats["note"] = "No alerts in this period." if since is not None else "No alerts recorded."
    return {"headline": _stats_headline(stats, since_hours), **stats}


@mcp.tool(auth=require_role("operator"), **hints("alerts_acknowledge"))
async def alerts_acknowledge(
    alert_ids: list[int] | None = None,
    disposition: Literal["true_positive", "false_positive", "benign", "duplicate"] | None = None,
    note: str | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    since_hours: float | None = None,
) -> dict[str, Any]:
    """Mark alerts as handled, with a verdict: "mark all alerts from 203.0.113.7 as false positive".

    Name `alert_ids` (from alerts_recent), or describe a set with source_ip / event_type /
    severity / since_hours and every matching untriaged alert is triaged at once (up to 500 per
    call; the reply says if more remain). Alerts already triaged are skipped when selecting by
    filter; name their ids to change a verdict. At least one selector is required, so nothing is
    ever triaged by accident. Recorded under the caller's identity.

    Args:
        alert_ids: Alert ids to triage, as shown by alerts_recent.
        disposition: The verdict: true_positive (a real attack), false_positive (detection wrong),
              benign (expected activity, e.g. our own pentest) or duplicate.
        note: Why; shown to whoever reviews this later.
        source_ip: Triage every untriaged alert from this address.
        event_type: Triage every untriaged alert of this exact event type.
        severity: Triage every untriaged alert at this severity.
        since_hours: Only alerts from the last N hours ("today" is 24).
    """
    if source_ip and (bad := validate_ip(source_ip)):
        return {"error": bad, "hint": "Pass one attacker address, e.g. 203.0.113.7."}
    if alert_ids is not None and any(i < 1 for i in alert_ids):
        return {
            "error": "alert_ids must be positive whole numbers.",
            "hint": "Take ids from the `id` field of alerts_recent or alerts_search.",
        }
    has_filters = any((source_ip, event_type, severity, since_hours is not None))
    if not alert_ids and not has_filters:
        return {
            "error": "Nothing selected: say which alerts to triage.",
            "hint": (
                "Pass alert_ids (from alerts_recent), or at least one of source_ip, event_type, "
                "severity or since_hours to triage every matching untriaged alert."
            ),
        }

    since, _end, err = await _since(since_hours)
    if err:
        return err
    disp = AlertDisposition(disposition) if disposition else None
    sev = AlertSeverity(severity) if severity else None
    # `triaged_by` is shown on shift handover and by alerts_get, so it is who actually made the
    # call: the caller's token label, or "stdio" for a local session. A name typed into a
    # parameter could only name someone else (or be set by an injected instruction).
    triaged_by = rbac.current_actor()[:128]  # String(128): longer raises on PostgreSQL

    async with get_session() as session:
        result = await queries.triage_alerts(
            session,
            alert_ids=alert_ids,
            disposition=disp,
            note=note,
            triaged_by=triaged_by,
            source_ip=source_ip.strip() if source_ip else None,
            event_type=event_type,
            severity=sev,
            since=since,
            max_alerts=_TRIAGE_CAP,
        )

    await record_action(
        "alerts_acknowledge",
        summary=(
            f"triaged {result['acknowledged']} alert(s)"
            + (f" as {disposition}" if disposition else "")
        ),
        arguments={
            "alert_ids": alert_ids,
            "disposition": disposition,
            "source_ip": source_ip,
            "event_type": event_type,
            "severity": severity,
            "since_hours": since_hours,
        },
        target=source_ip,
    )

    if result["acknowledged"] == 0:
        result["note"] = "No alerts matched, nothing was changed. " + (
            "Those ids do not exist (check alerts_recent)."
            if alert_ids
            else "Alerts that are already triaged are skipped when selecting by filter."
        )
    elif result.get("capped"):
        result["note"] = (
            f"Triaged the newest {_TRIAGE_CAP}; more alerts still match. "
            f"Repeating the same call triages the next {_TRIAGE_CAP} (already-triaged alerts are "
            "skipped); or narrow with source_ip, event_type, severity or since_hours."
        )
    elif result.get("not_matched_ids"):
        result["note"] = "Some ids were not found or did not match the other filters."
    return result


@mcp.tool(auth=require_role("admin"), **hints("alerts_prune"))
async def alerts_prune(
    older_than_days: int = 90,
    archive: bool = True,
    archive_path: str | None = None,
) -> dict[str, Any]:
    """Delete old alerts to free space: "delete alerts older than 3 months" (keeps a copy first).

    Deleting alerts is permanent and destroys evidence, so by default every alert about to go is
    first written to a JSON Lines file (full payloads) and nothing is deleted if that write fails.
    Lifetime statistics are unaffected. Use `archive=False` only when the user explicitly wants
    the data destroyed without a copy.

    Args:
        older_than_days: Delete alerts older than this many days (default 90; "3 months" is 90,
              "a year" 365).
        archive: Keep a copy before deleting (default True).
        archive_path: Optional file name for the copy, a plain name inside the reports directory.
              Named automatically if omitted.
    """
    if older_than_days < 1:
        return {
            "error": "older_than_days must be at least 1, so that current data is never deleted.",
            "hint": "Pass a whole number of days, e.g. 90 for alerts older than three months.",
        }

    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)

    archive_info: dict[str, Any] | None = None
    max_id: int | None = None
    if archive:
        try:
            # Streamed in chunks (retention.archive_alerts): the whole archive used to be built as
            # one string in memory, gigabytes on a table of millions of rows. A failure raises, and
            # nothing is deleted unless every row it would remove is on disk first.
            max_id, archive_info = await retention.archive_alerts(
                cutoff,
                prefix=f"alerts-archive-before-{cutoff.date().isoformat()}",
                output_path=archive_path,
            )
            if max_id is None:
                max_id = 0  # nothing old enough to archive: no alert is deletable
        except Exception as e:
            # Refusing to delete is the safe failure. Pruning anyway would
            # destroy exactly the data the archive existed to keep.
            await record_action(
                "alerts_prune",
                summary=f"refused to prune alerts older than {older_than_days}d: archive failed",
                arguments={"older_than_days": older_than_days, "archive_path": archive_path},
                outcome="error",
                error=str(e),
            )
            return {
                "error": f"The archive could not be written, so nothing was deleted: {e}",
                "hint": (
                    "Check that archive_path is a plain file name (no folders) that does not "
                    "exist yet, and that the reports directory has free space. Do not retry with "
                    "archive=False unless the user explicitly wants the alerts destroyed "
                    "without a copy."
                ),
            }

    alerts_deleted, events_deleted = await retention.delete_before(cutoff, max_id)
    result = {"alerts_deleted": alerts_deleted, "attacker_events_deleted": events_deleted}
    await record_action(
        "alerts_prune",
        summary=(
            f"deleted {alerts_deleted} alert(s) and "
            f"{events_deleted} event(s) older than "
            f"{older_than_days}d"
            + (f", archived to {archive_info['path']}" if archive_info else ", NOT archived")
        ),
        arguments={
            "older_than_days": older_than_days,
            "cutoff": cutoff.isoformat(),
            "archived": bool(archive_info),
        },
    )
    out: dict[str, Any] = {
        "older_than_days": older_than_days,
        "cutoff": cutoff.isoformat(),
        "archive": archive_info
        or ("nothing matched the cutoff" if archive else "skipped (archive=False)"),
        **result,
    }
    if not alerts_deleted and not events_deleted:
        out["note"] = f"No alerts were older than {older_than_days} days; nothing was deleted."
    return out


@mcp.tool(auth=require_role("operator"), **hints("alerts_export"))
async def alerts_export(
    format: Literal["json", "csv"] = "json",
    limit: int = 1000,
    since_hours: float | None = None,
    severity: Literal["low", "medium", "high", "critical"] | None = None,
    source_ip: str | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Save alerts to a file for a SIEM or spreadsheet: "export today's critical alerts as CSV".

    Writes complete records (payloads included) to a new file in the reports directory and returns
    its path, size and a five-row preview, never the content. Newest alerts first. To read alerts
    in the conversation use `alerts_recent` or `alerts_search`.

    Args:
        format: "json" (default) or "csv".
        limit: How many alerts to export (default 1000, at most 50000).
        since_hours: Only the last N hours ("today" is 24, "this week" 168).
        severity: Only low, medium, high or critical alerts.
        source_ip: Only alerts from this attacker address.
        output_path: File name for the export, a plain name inside the reports directory
              (never overwrites). Named automatically if omitted.
    """
    limit = max(1, min(limit, 50_000))
    if source_ip and (bad := validate_ip(source_ip)):
        return {"error": bad, "hint": "Pass one attacker address, e.g. 203.0.113.7."}
    sev = AlertSeverity(severity) if severity else None
    since, _end, err = await _since(since_hours)
    if err:
        return err

    async with get_session() as session:
        alerts = await queries.get_recent_alerts(
            session,
            limit=limit,
            severity=sev,
            since=since,
            source_ip=source_ip.strip() if source_ip else None,
        )

    rows = [
        {
            "id": a.id,
            "honeypot_id": a.honeypot_id,
            "source_ip": a.source_ip,
            "source_port": a.source_port,
            "event_type": a.event_type,
            "severity": a.severity.value,
            "acknowledged": a.acknowledged,
            "timestamp": a.timestamp.isoformat(),
            "payload": json.dumps(a.payload),
        }
        for a in alerts
    ]
    if not rows:
        return {
            "alerts_exported": 0,
            "note": "No alerts matched, so no file was written. Try a longer time window or "
            "fewer filters.",
        }

    if format == "json":
        content = json.dumps(rows, indent=2)
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        content = buf.getvalue()

    written = write_artifact(content, prefix="alerts", extension=format, output_path=output_path)
    if "error" in written:
        written.setdefault(
            "hint",
            "Use a plain file name inside the reports directory that does not exist yet, or "
            "leave output_path out to have it named automatically.",
        )
        return written

    exported: dict[str, Any] = {
        "path": written["path"],
        "format": format,
        "alerts_exported": len(rows),
        "bytes": len(content.encode("utf-8")),
        "preview": [
            {k: r[k] for k in ("id", "source_ip", "event_type", "severity", "timestamp")}
            for r in rows[:5]
        ],
    }
    if len(rows) == limit:
        exported["note"] = (
            f"Exported the newest {limit} matching alerts; there may be more. "
            "Narrow by time or severity, or ask for a larger limit."
        )
    if since is not None:
        await annotate_window(exported)
    return exported


@mcp.tool(auth=require_role("admin"), **hints("audit_log_search"))
async def audit_log_search(
    tool: str | None = None,
    target: str | None = None,
    actor: str | None = None,
    since_hours: float | None = None,
    outcome: Literal["ok", "error"] | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """What did the control plane do, and who did it: "who stopped that honeypot", "any failed actions?"

    The append-only record of every state-changing call (deploy, stop, prune, triage, token and key
    changes), newest first.

    Args:
        tool: Only this tool, e.g. alerts_prune or honeypot_stop.
        target: Only actions on this honeypot name, address or token id.
        actor: Only actions by this person or role (substring, so "alice" matches "alice (operator)").
        since_hours: Only the last N hours ("today" is 24, "this week" 168).
        outcome: "ok" for successful actions, "error" for failed ones.
        limit: How many entries to show (default 25; cut to a readable size).
    """
    from sqlalchemy import desc, func, select

    from honeypot_mcp.storage.models import AuditLog

    limit = max(1, min(limit, 200))
    cutoff = None
    if since_hours is not None:
        if since_hours <= 0:
            return {"error": "since_hours must be greater than 0.", "hint": _SINCE_HINT}
        cutoff = await window_end() - timedelta(hours=since_hours)

    filters = []
    if tool:
        filters.append(AuditLog.tool == tool)
    if target:
        filters.append(AuditLog.target == target)
    if actor:
        filters.append(AuditLog.actor.contains(actor, autoescape=True))
    if outcome:
        filters.append(AuditLog.outcome == outcome)
    if cutoff is not None:
        filters.append(AuditLog.timestamp >= cutoff)

    async with get_session() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(*filters).order_by(desc(AuditLog.timestamp)).limit(limit)
                )
            )
            .scalars()
            .all()
        )
        total = (
            await session.execute(select(func.count()).select_from(AuditLog).where(*filters))
        ).scalar_one()
        known_tools = (
            [r[0] for r in (await session.execute(select(AuditLog.tool).distinct())).all()]
            if not rows
            else []
        )

    entries: list[dict[str, Any]] = []
    for r in rows:
        entry: dict[str, Any] = {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "tool": r.tool,
            "actor": r.actor,
            "summary": r.summary,
            "target": r.target,
            "outcome": r.outcome,
        }
        if r.error:
            entry["error"] = r.error[:300]
        if r.arguments:
            text = json.dumps(r.arguments, default=str)
            entry["arguments"] = r.arguments if len(text) <= 300 else text[:300] + "…"
        entries.append(entry)
    shown = _fit(entries)
    result: dict[str, Any] = {"count": len(shown), "total_matching": total, "actions": shown}
    if not shown:
        if filters and known_tools:
            result["note"] = (
                "No control-plane actions match these filters. Tools with recorded actions: "
                + ", ".join(sorted(known_tools))
                + "."
            )
        else:
            result["note"] = (
                "No control-plane actions recorded. Only state-changing calls are logged; reads "
                "such as alerts_recent are not."
            )
    elif len(shown) < total:
        result["note"] = (
            f"Showing the newest {len(shown)} of {total:,} matching actions. Narrow by tool, "
            "actor, target or time ('last 24 hours') to see others."
        )
    return mark_untrusted(result)
