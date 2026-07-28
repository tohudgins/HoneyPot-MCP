"""Turn a live HoneyPot MCP database into publishable campaign statistics.

Point this at a deployment that has been collecting for a while and it produces
the numbers you'd actually want to write up or put in a README: volume, unique
attackers, geographic spread, which credentials get tried, which exploits get
thrown, and what the honeytokens caught.

    # Human-readable summary of the last 30 days
    uv run python scripts/attack_report.py --days 30

    # Markdown, ready to paste into a README or a writeup
    uv run python scripts/attack_report.py --days 30 --format markdown

    # Machine-readable, for charting elsewhere
    uv run python scripts/attack_report.py --days 30 --format json

Reads from `DATABASE_URL` (same default as the server). Read-only — it never
writes to the database.

Credential pairs are reported because they are what *attackers* guessed, not
your secrets. Source IPs are attacker-controlled and safe to publish; pass
`--anonymise-ips` if you'd rather mask the final octet anyway.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Make the package importable when running straight from a checkout.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC = _PROJECT_ROOT / "src"
if _SRC.exists():
    sys.path.insert(0, str(_SRC))

# Payload keys that plausibly carry a password an attacker submitted. We report
# these as attack telemetry; they are guesses aimed at us, not local secrets.
_PASSWORD_KEYS = ("password", "pass", "passwd", "pwd")
_USERNAME_KEYS = ("username", "user", "login", "email")


def _anonymise(ip: str) -> str:
    """Mask the host portion so the network is still visible."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        return ".".join(ip.split(".")[:3]) + ".x"
    return ":".join(ip.split(":")[:4]) + "::x"


def _dig(payload: Any, keys: tuple[str, ...]) -> str | None:
    """Find the first matching key anywhere in a nested payload dict."""
    if not isinstance(payload, dict):
        return None
    for key, value in payload.items():
        if key.lower() in keys and isinstance(value, str | int):
            return str(value)
    for value in payload.values():
        if isinstance(value, dict):
            found = _dig(value, keys)
            if found is not None:
                return found
    return None


async def collect(days: int, anonymise: bool) -> dict[str, Any]:
    db_url = os.environ.get(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{(_PROJECT_ROOT / 'honeypot_mcp.db').as_posix()}",
    )
    os.environ["DATABASE_URL"] = db_url

    from sqlalchemy import func, select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import Alert, Honeypot, Honeytoken, HoneytokenStatus

    event_buffer.reset_for_tests()  # clears any stale singleton; safe outside tests
    await init_db()

    cutoff = datetime.now(UTC) - timedelta(days=days)
    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "window_days": days,
        "database": db_url.split("://", 1)[0],
    }

    async with get_session() as session:
        alerts = (
            (await session.execute(select(Alert).where(Alert.timestamp >= cutoff))).scalars().all()
        )

        report["total_events"] = len(alerts)
        if not alerts:
            report["note"] = "No events in the selected window."
            await close_db()
            return report

        first = min(a.timestamp for a in alerts)
        last = max(a.timestamp for a in alerts)
        span_hours = max((last - first).total_seconds() / 3600, 1.0)
        report["first_event"] = first.isoformat()
        report["last_event"] = last.isoformat()
        report["events_per_day"] = round(len(alerts) / max(span_hours / 24, 1 / 24), 1)

        ips = Counter(a.source_ip for a in alerts)
        report["unique_source_ips"] = len(ips)
        report["severity_breakdown"] = dict(
            Counter(
                a.severity.value if hasattr(a.severity, "value") else str(a.severity)
                for a in alerts
            )
        )
        report["top_event_types"] = Counter(a.event_type for a in alerts).most_common(15)
        report["top_attackers"] = [
            {"ip": _anonymise(ip) if anonymise else ip, "hits": n} for ip, n in ips.most_common(15)
        ]

        # Geography + network, from whatever enrichment landed on the payload.
        countries: Counter[str] = Counter()
        asns: Counter[str] = Counter()
        credentials: Counter[tuple[str, str]] = Counter()
        usernames: Counter[str] = Counter()
        exploits: Counter[str] = Counter()

        for alert in alerts:
            payload = alert.payload if isinstance(alert.payload, dict) else {}
            geo = (payload.get("enrichment") or {}).get("geoip") or {}
            if isinstance(geo, dict):
                if country := geo.get("country") or geo.get("country_name"):
                    countries[str(country)] += 1
                if org := geo.get("asn_org") or geo.get("as_org"):
                    asns[str(org)] += 1

            user = _dig(payload, _USERNAME_KEYS)
            password = _dig(payload, _PASSWORD_KEYS)
            if user is not None:
                usernames[user] += 1
            if user is not None and password is not None:
                credentials[(user, password)] += 1

            for category in payload.get("exploit_categories") or []:
                exploits[str(category)] += 1

        report["top_countries"] = countries.most_common(15)
        report["top_networks"] = asns.most_common(10)
        report["top_usernames"] = usernames.most_common(15)
        report["top_credential_pairs"] = [
            {"username": u, "password": p, "attempts": n}
            for (u, p), n in credentials.most_common(20)
        ]
        report["exploit_categories"] = exploits.most_common(15)

        # Which engines actually saw traffic.
        engine_rows = (
            await session.execute(
                select(Honeypot.type, func.count(Alert.id))
                .join(Alert, Alert.honeypot_id == Honeypot.id)
                .where(Alert.timestamp >= cutoff)
                .group_by(Honeypot.type)
            )
        ).all()
        report["events_by_engine"] = sorted(
            ((t.value if hasattr(t, "value") else str(t), n) for t, n in engine_rows),
            key=lambda row: row[1],
            reverse=True,
        )

        triggered = (
            await session.execute(
                select(func.count(Honeytoken.id)).where(
                    Honeytoken.status == HoneytokenStatus.TRIGGERED
                )
            )
        ).scalar_one()
        report["honeytokens_triggered"] = int(triggered)

    await close_db()
    return report


def render_text(r: dict[str, Any]) -> str:
    if not r.get("total_events"):
        return f"No events in the last {r['window_days']} days."
    lines = [
        f"HoneyPot MCP — {r['window_days']}-day attack report",
        "=" * 52,
        f"Window          : {r['first_event'][:19]} → {r['last_event'][:19]}",
        f"Total events    : {r['total_events']:,}  (~{r['events_per_day']:,}/day)",
        f"Unique attackers: {r['unique_source_ips']:,}",
        f"Tokens triggered: {r['honeytokens_triggered']:,}",
        "",
        "Severity        : "
        + ", ".join(f"{k}={v:,}" for k, v in sorted(r["severity_breakdown"].items())),
        "",
    ]

    def block(title: str, rows: list[Any], fmt) -> None:
        if not rows:
            return
        lines.append(title)
        for row in rows[:10]:
            lines.append("  " + fmt(row))
        lines.append("")

    block("Top event types", r["top_event_types"], lambda x: f"{x[1]:>7,}  {x[0]}")
    block("Top countries", r["top_countries"], lambda x: f"{x[1]:>7,}  {x[0]}")
    block("Top networks (ASN)", r["top_networks"], lambda x: f"{x[1]:>7,}  {x[0]}")
    block("Events by engine", r["events_by_engine"], lambda x: f"{x[1]:>7,}  {x[0]}")
    block(
        "Top attackers",
        r["top_attackers"],
        lambda x: f"{x['hits']:>7,}  {x['ip']}",
    )
    block(
        "Most-guessed credentials",
        r["top_credential_pairs"],
        lambda x: f"{x['attempts']:>7,}  {x['username']} / {x['password']}",
    )
    block("Exploit categories", r["exploit_categories"], lambda x: f"{x[1]:>7,}  {x[0]}")
    return "\n".join(lines)


def render_markdown(r: dict[str, Any]) -> str:
    if not r.get("total_events"):
        return f"No events in the last {r['window_days']} days."
    out = [
        f"## {r['window_days']} days of attack traffic",
        "",
        f"Collected {r['first_event'][:10]} → {r['last_event'][:10]}.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total events | **{r['total_events']:,}** |",
        f"| Unique attacker IPs | **{r['unique_source_ips']:,}** |",
        f"| Events per day | ~{r['events_per_day']:,} |",
        f"| Honeytokens triggered | {r['honeytokens_triggered']:,} |",
        "",
    ]

    def table(title: str, header: tuple[str, str], rows: list[Any], fmt) -> None:
        if not rows:
            return
        out.extend([f"### {title}", "", f"| {header[0]} | {header[1]} |", "|---|---:|"])
        out.extend(fmt(row) for row in rows[:10])
        out.append("")

    table(
        "Where it came from",
        ("Country", "Events"),
        r["top_countries"],
        lambda x: f"| {x[0]} | {x[1]:,} |",
    )
    table(
        "What they went after",
        ("Event type", "Count"),
        r["top_event_types"],
        lambda x: f"| `{x[0]}` | {x[1]:,} |",
    )
    table(
        "Most-guessed credentials",
        ("Username / password", "Attempts"),
        r["top_credential_pairs"],
        lambda x: f"| `{x['username']}` / `{x['password']}` | {x['attempts']:,} |",
    )
    table(
        "Exploits thrown",
        ("Category", "Count"),
        r["exploit_categories"],
        lambda x: f"| {x[0]} | {x[1]:,} |",
    )
    return "\n".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--days", type=int, default=30, help="Look-back window in days (default: 30)"
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--anonymise-ips",
        action="store_true",
        help="Mask the host portion of attacker IPs before printing",
    )
    args = parser.parse_args()

    report = asyncio.run(collect(args.days, args.anonymise_ips))
    if args.format == "json":
        print(json.dumps(report, indent=2, default=str))
    elif args.format == "markdown":
        print(render_markdown(report))
    else:
        print(render_text(report))


if __name__ == "__main__":
    main()
