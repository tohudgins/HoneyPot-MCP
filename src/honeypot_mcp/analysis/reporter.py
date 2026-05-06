"""Report generator — Jinja2 HTML and Markdown attack reports."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from honeypot_mcp.storage.models import Alert


async def generate(
    title: str,
    alerts: list[Alert],
    stats: dict[str, Any],
    target_ip: str | None,
    format: str = "html",
) -> str:
    """Generate an attack report from alert data."""
    from honeypot_mcp.intel.mitre import map_to_attack

    # Build summary data
    event_terms = [a.event_type for a in alerts]
    for a in alerts:
        event_terms.extend(str(v) for v in a.payload.values() if isinstance(v, str))

    ttps = await map_to_attack(event_terms)
    event_counts = Counter(a.event_type for a in alerts)
    ip_counts = Counter(a.source_ip for a in alerts)
    sev_counts = Counter(a.severity.value for a in alerts)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    timeline = sorted(
        [
            {
                "timestamp": a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": a.source_ip,
                "event": a.event_type,
                "severity": a.severity.value,
            }
            for a in alerts
        ],
        key=lambda x: x["timestamp"],
    )[-50:]  # Last 50 events for timeline

    context = {
        "title": title,
        "generated_at": generated_at,
        "target_ip": target_ip,
        "total_alerts": len(alerts),
        "total_unique_ips": len(set(a.source_ip for a in alerts)),
        "top_ips": ip_counts.most_common(10),
        "top_events": event_counts.most_common(10),
        "severity_counts": dict(sev_counts),
        "ttps": ttps,
        "timeline": timeline,
    }

    if format == "html":
        return _render_html(context)
    return _render_markdown(context)


def _render_html(ctx: dict) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{ctx['title']}</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: .5rem; }}
  h2 {{ color: #79c0ff; margin-top: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
  th {{ background: #21262d; color: #58a6ff; padding: .6rem 1rem; text-align: left; }}
  td {{ padding: .5rem 1rem; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .8rem; font-weight: bold; }}
  .critical {{ background: #da3633; color: #fff; }}
  .high {{ background: #e3b341; color: #000; }}
  .medium {{ background: #388bfd; color: #fff; }}
  .low {{ background: #3d444d; color: #c9d1d9; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }}
  .stat-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
  .ttp-tag {{ display: inline-block; background: #21262d; border: 1px solid #388bfd; border-radius: 4px; padding: 3px 8px; margin: 2px; font-size: .8rem; }}
</style>
</head>
<body>
<h1>{ctx['title']}</h1>
<p>Generated: {ctx['generated_at']}{f" &nbsp;|&nbsp; Target IP: <code>{ctx['target_ip']}</code>" if ctx['target_ip'] else ""}</p>

<h2>Summary</h2>
<div class="stat-grid">
  <div class="stat-card"><div class="num">{ctx['total_alerts']}</div>Total Alerts</div>
  <div class="stat-card"><div class="num">{ctx['total_unique_ips']}</div>Unique Attackers</div>
  <div class="stat-card"><div class="num">{ctx['severity_counts'].get('critical', 0)}</div>Critical Events</div>
  <div class="stat-card"><div class="num">{len(ctx['ttps'])}</div>MITRE Techniques</div>
</div>

<h2>MITRE ATT&CK Techniques Observed</h2>
{"".join(f'<span class="ttp-tag"><a href="{t["url"]}" target="_blank" style="color:#58a6ff;text-decoration:none">{t["technique_id"]}</a> — {t["technique_name"]} <em>({t["tactic"]})</em></span>' for t in ctx['ttps']) or "<p>No techniques mapped.</p>"}

<h2>Top Attacker IPs</h2>
<table><tr><th>IP Address</th><th>Alert Count</th></tr>
{"".join(f"<tr><td><code>{ip}</code></td><td>{cnt}</td></tr>" for ip, cnt in ctx['top_ips'])}
</table>

<h2>Top Event Types</h2>
<table><tr><th>Event Type</th><th>Count</th></tr>
{"".join(f"<tr><td>{evt}</td><td>{cnt}</td></tr>" for evt, cnt in ctx['top_events'])}
</table>

<h2>Severity Breakdown</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
{"".join(f'<tr><td><span class="badge {sev}">{sev.upper()}</span></td><td>{cnt}</td></tr>' for sev, cnt in ctx['severity_counts'].items())}
</table>

<h2>Recent Event Timeline</h2>
<table><tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Severity</th></tr>
{"".join(f'<tr><td>{e["timestamp"]}</td><td><code>{e["ip"]}</code></td><td>{e["event"]}</td><td><span class="badge {e["severity"]}">{e["severity"].upper()}</span></td></tr>' for e in reversed(ctx['timeline']))}
</table>
</body></html>"""


def _render_markdown(ctx: dict) -> str:
    ttps_md = "\n".join(
        f"| [{t['technique_id']}]({t['url']}) | {t['technique_name']} | {t['tactic']} |"
        for t in ctx["ttps"]
    )
    top_ips_md = "\n".join(f"| {ip} | {cnt} |" for ip, cnt in ctx["top_ips"])
    top_evts_md = "\n".join(f"| {evt} | {cnt} |" for evt, cnt in ctx["top_events"])
    timeline_md = "\n".join(
        f"| {e['timestamp']} | {e['ip']} | {e['event']} | {e['severity'].upper()} |"
        for e in reversed(ctx["timeline"])
    )

    return f"""# {ctx['title']}

**Generated:** {ctx['generated_at']}
{f"**Target IP:** `{ctx['target_ip']}`" if ctx["target_ip"] else ""}

## Summary

| Metric | Value |
|---|---|
| Total Alerts | {ctx['total_alerts']} |
| Unique Attacker IPs | {ctx['total_unique_ips']} |
| Critical Events | {ctx['severity_counts'].get('critical', 0)} |
| MITRE Techniques Observed | {len(ctx['ttps'])} |

## MITRE ATT&CK Techniques

| ID | Technique | Tactic |
|---|---|---|
{ttps_md or "| — | No techniques mapped | — |"}

## Top Attacker IPs

| IP Address | Alerts |
|---|---|
{top_ips_md or "| — | 0 |"}

## Top Event Types

| Event Type | Count |
|---|---|
{top_evts_md or "| — | 0 |"}

## Recent Event Timeline

| Timestamp | Source IP | Event | Severity |
|---|---|---|---|
{timeline_md or "| — | — | — | — |"}
"""
