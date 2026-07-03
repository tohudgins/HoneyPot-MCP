"""Report generator — Jinja2 HTML and Markdown attack reports.

HTML rendering uses Jinja2 with autoescape so attacker-controlled fields
(IPs, event types, payloads) cannot break out into executable markup.
Markdown rendering escapes pipe and backslash characters in cell values.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from jinja2 import BaseLoader, Environment, select_autoescape

from honeypot_mcp.storage.models import Alert


async def generate(
    title: str,
    alerts: list[Alert],
    stats: dict[str, Any],
    target_ip: str | None,
    format: str = "html",
    intel: dict[str, Any] | None = None,
) -> str:
    """Generate an attack report from alert data.

    `intel` is an optional enrichment block (geo/ASN/reverse-DNS + VT/AbuseIPDB
    reputation + risk score + recommendations) for an IP-scoped report. When
    present, an "IP Intelligence" section is rendered so the report carries the
    context a SOC analyst needs to action it, not just raw event counts."""
    from honeypot_mcp.intel.mitre import map_to_attack

    event_terms = [a.event_type for a in alerts]
    for a in alerts:
        event_terms.extend(str(v) for v in a.payload.values() if isinstance(v, str))

    ttps = await map_to_attack(event_terms)
    event_counts = Counter(a.event_type for a in alerts)
    ip_counts = Counter(a.source_ip for a in alerts)
    sev_counts = Counter(a.severity.value for a in alerts)

    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

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
    )[-50:]

    context = {
        "title": title,
        "generated_at": generated_at,
        "target_ip": target_ip,
        "total_alerts": len(alerts),
        "total_unique_ips": len({a.source_ip for a in alerts}),
        "top_ips": ip_counts.most_common(10),
        "top_events": event_counts.most_common(10),
        "severity_counts": dict(sev_counts),
        "ttps": ttps,
        "timeline": timeline,
        "intel": _flatten_intel(intel) if intel else None,
    }

    if format == "html":
        return _render_html(context)
    return _render_markdown(context)


def _flatten_intel(intel: dict[str, Any]) -> dict[str, Any]:
    """Normalise a `build_profile()` block into the flat fields the report
    templates render. The profiler's vt/abuse sub-blocks omit an `available`
    flag when they carry data, so presence is detected by content."""
    geo = intel.get("geoip") or {}
    vt = intel.get("virustotal") or {}
    abuse = intel.get("abuseipdb") or {}
    loc = ", ".join(p for p in (geo.get("city"), geo.get("country")) if p)
    asn = geo.get("asn")
    asn_str = f"AS{asn} {geo.get('as_org', '')}".strip() if asn else ""
    vt_has_data = "detection_ratio" in vt
    abuse_has_data = "abuse_confidence_score" in abuse
    return {
        "risk_score": intel.get("risk_score"),
        "risk_level": intel.get("risk_level"),
        "location": loc,
        "asn": asn_str,
        "reverse_dns": geo.get("reverse_dns"),
        "vt_detection_ratio": vt.get("detection_ratio") if vt_has_data else None,
        "vt_reputation": vt.get("reputation") if vt_has_data else None,
        "abuse_score": abuse.get("abuse_confidence_score") if abuse_has_data else None,
        "abuse_reports": abuse.get("total_reports") if abuse_has_data else None,
        "isp": abuse.get("isp") or geo.get("as_org") or "",
        "usage_type": abuse.get("usage_type", ""),
        "recommendations": intel.get("recommendations", []),
    }


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{{ title }}</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; max-width: 1100px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: .5rem; }
  h2 { color: #79c0ff; margin-top: 2rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th { background: #21262d; color: #58a6ff; padding: .6rem 1rem; text-align: left; }
  td { padding: .5rem 1rem; border-bottom: 1px solid #21262d; }
  tr:hover td { background: #161b22; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: .8rem; font-weight: bold; }
  .critical { background: #da3633; color: #fff; }
  .high { background: #e3b341; color: #000; }
  .medium { background: #388bfd; color: #fff; }
  .low { background: #3d444d; color: #c9d1d9; }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1rem 0; }
  .stat-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-card .num { font-size: 2rem; font-weight: bold; color: #58a6ff; }
  .ttp-tag { display: inline-block; background: #21262d; border: 1px solid #388bfd; border-radius: 4px; padding: 3px 8px; margin: 2px; font-size: .8rem; }
  .ttp-tag a { color: #58a6ff; text-decoration: none; }
</style>
</head>
<body>
<h1>{{ title }}</h1>
<p>Generated: {{ generated_at }}{% if target_ip %} &nbsp;|&nbsp; Target IP: <code>{{ target_ip }}</code>{% endif %}</p>

<h2>Summary</h2>
<div class="stat-grid">
  <div class="stat-card"><div class="num">{{ total_alerts }}</div>Total Alerts</div>
  <div class="stat-card"><div class="num">{{ total_unique_ips }}</div>Unique Attackers</div>
  <div class="stat-card"><div class="num">{{ severity_counts.get('critical', 0) }}</div>Critical Events</div>
  <div class="stat-card"><div class="num">{{ ttps|length }}</div>MITRE Techniques</div>
</div>

{% if intel %}
<h2>IP Intelligence</h2>
<table>
  {% if intel.risk_level %}<tr><th>Risk</th><td><span class="badge {{ (intel.risk_level|lower) if intel.risk_level in ['CRITICAL','HIGH','MEDIUM','LOW'] else 'low' }}">{{ intel.risk_level }}</span> &nbsp; {{ intel.risk_score }}/100</td></tr>{% endif %}
  {% if intel.location %}<tr><th>Location</th><td>{{ intel.location }}</td></tr>{% endif %}
  {% if intel.asn %}<tr><th>Network (ASN)</th><td>{{ intel.asn }}</td></tr>{% endif %}
  {% if intel.reverse_dns %}<tr><th>Reverse DNS</th><td><code>{{ intel.reverse_dns }}</code></td></tr>{% endif %}
  {% if intel.isp %}<tr><th>ISP / Org</th><td>{{ intel.isp }}{% if intel.usage_type %} ({{ intel.usage_type }}){% endif %}</td></tr>{% endif %}
  {% if intel.vt_detection_ratio %}<tr><th>VirusTotal</th><td>{{ intel.vt_detection_ratio }} engines flag malicious (reputation {{ intel.vt_reputation }})</td></tr>{% endif %}
  {% if intel.abuse_score is not none %}<tr><th>AbuseIPDB</th><td>{{ intel.abuse_score }}% confidence, {{ intel.abuse_reports }} reports</td></tr>{% endif %}
</table>
{% if intel.recommendations %}
<h3>Recommended actions</h3>
<ul>{% for r in intel.recommendations %}<li>{{ r }}</li>{% endfor %}</ul>
{% endif %}
{% endif %}

<h2>MITRE ATT&amp;CK Techniques Observed</h2>
{% if ttps %}
{% for t in ttps %}
<span class="ttp-tag"><a href="{{ t.url }}" target="_blank" rel="noopener noreferrer">{{ t.technique_id }}</a> — {{ t.technique_name }} <em>({{ t.tactic }})</em></span>
{% endfor %}
{% else %}
<p>No techniques mapped.</p>
{% endif %}

<h2>Top Attacker IPs</h2>
<table><tr><th>IP Address</th><th>Alert Count</th></tr>
{% for ip, cnt in top_ips %}
<tr><td><code>{{ ip }}</code></td><td>{{ cnt }}</td></tr>
{% endfor %}
</table>

<h2>Top Event Types</h2>
<table><tr><th>Event Type</th><th>Count</th></tr>
{% for evt, cnt in top_events %}
<tr><td>{{ evt }}</td><td>{{ cnt }}</td></tr>
{% endfor %}
</table>

<h2>Severity Breakdown</h2>
<table><tr><th>Severity</th><th>Count</th></tr>
{% for sev, cnt in severity_counts.items() %}
<tr><td><span class="badge {{ sev }}">{{ sev|upper }}</span></td><td>{{ cnt }}</td></tr>
{% endfor %}
</table>

<h2>Recent Event Timeline</h2>
<table><tr><th>Timestamp</th><th>Source IP</th><th>Event</th><th>Severity</th></tr>
{% for e in timeline|reverse %}
<tr><td>{{ e.timestamp }}</td><td><code>{{ e.ip }}</code></td><td>{{ e.event }}</td><td><span class="badge {{ e.severity }}">{{ e.severity|upper }}</span></td></tr>
{% endfor %}
</table>
</body></html>
"""

_env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html", "xml"]))
_html_template = _env.from_string(_HTML_TEMPLATE)


def _render_html(ctx: dict) -> str:
    return _html_template.render(**ctx)


def _md_cell(value: Any) -> str:
    """Escape pipe / backslash / newline so attacker-controlled values can't
    break the surrounding Markdown table."""
    s = str(value)
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _render_intel_md(intel: dict[str, Any] | None) -> str:
    if not intel:
        return ""
    rows = []
    if intel.get("risk_level"):
        rows.append(
            f"| Risk | **{_md_cell(intel['risk_level'])}** ({intel.get('risk_score')}/100) |"
        )
    if intel.get("location"):
        rows.append(f"| Location | {_md_cell(intel['location'])} |")
    if intel.get("asn"):
        rows.append(f"| Network (ASN) | {_md_cell(intel['asn'])} |")
    if intel.get("reverse_dns"):
        rows.append(f"| Reverse DNS | `{_md_cell(intel['reverse_dns'])}` |")
    if intel.get("isp"):
        usage = f" ({_md_cell(intel['usage_type'])})" if intel.get("usage_type") else ""
        rows.append(f"| ISP / Org | {_md_cell(intel['isp'])}{usage} |")
    if intel.get("vt_detection_ratio"):
        rows.append(
            f"| VirusTotal | {_md_cell(intel['vt_detection_ratio'])} malicious (rep {intel.get('vt_reputation')}) |"
        )
    if intel.get("abuse_score") is not None:
        rows.append(
            f"| AbuseIPDB | {intel['abuse_score']}% confidence, {intel.get('abuse_reports')} reports |"
        )
    if not rows:
        return ""
    table = "\n## IP Intelligence\n\n| Field | Value |\n|---|---|\n" + "\n".join(rows) + "\n"
    recs = intel.get("recommendations") or []
    if recs:
        table += (
            "\n**Recommended actions:**\n\n" + "\n".join(f"- {_md_cell(r)}" for r in recs) + "\n"
        )
    return table


def _render_markdown(ctx: dict) -> str:
    ttps_md = "\n".join(
        f"| [{_md_cell(t['technique_id'])}]({t['url']}) | {_md_cell(t['technique_name'])} | {_md_cell(t['tactic'])} |"
        for t in ctx["ttps"]
    )
    top_ips_md = "\n".join(f"| {_md_cell(ip)} | {cnt} |" for ip, cnt in ctx["top_ips"])
    top_evts_md = "\n".join(f"| {_md_cell(evt)} | {cnt} |" for evt, cnt in ctx["top_events"])
    timeline_md = "\n".join(
        f"| {_md_cell(e['timestamp'])} | {_md_cell(e['ip'])} | {_md_cell(e['event'])} | {e['severity'].upper()} |"
        for e in reversed(ctx["timeline"])
    )

    target_line = f"**Target IP:** `{_md_cell(ctx['target_ip'])}`" if ctx["target_ip"] else ""

    return f"""# {_md_cell(ctx["title"])}

**Generated:** {ctx["generated_at"]}
{target_line}
{_render_intel_md(ctx.get("intel"))}
## Summary

| Metric | Value |
|---|---|
| Total Alerts | {ctx["total_alerts"]} |
| Unique Attacker IPs | {ctx["total_unique_ips"]} |
| Critical Events | {ctx["severity_counts"].get("critical", 0)} |
| MITRE Techniques Observed | {len(ctx["ttps"])} |

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
