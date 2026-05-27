# HoneyPot MCP

[![CI](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)

A Model Context Protocol server for deploying, monitoring, and analysing honeypots and honeytokens — built on [FastMCP](https://github.com/jlowin/fastmcp) and Python 3.11+.

> **Read first:** [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — a frank rundown of what works (Cowrie SSH, HTTP personas, canary URLs, credential cross-reference) and what doesn't (DOCX/PDF file tokens, AWS-key callback path, HTTP TLS). Acknowledging the gaps is the point.
>
> **Ready to deploy?** [docs/DEPLOY.md](docs/DEPLOY.md) walks through "rent a $5 VPS → catch real attack traffic in under 30 minutes" plus ongoing-operations guidance.
>
> **Want to see it work in 5 minutes?** Jump to [Quick demo with Grafana](#quick-demo-with-grafana-dashboards) — `docker compose up` plus a seed script gives you pre-populated dashboards including a geo-mapped threat map and MITRE ATT&CK coverage view.

Ask Claude to deploy an SSH honeypot, generate fake AWS credentials, reconstruct an attacker's session, map their TTPs to MITRE ATT&CK, push alerts to Slack, or export a STIX 2.1 IOC bundle — all through natural language.

---

## Technical highlights

- **Async Python** end-to-end — `asyncio`, async SQLAlchemy 2.x, `aiohttp`, `httpx`, FastMCP. No blocking calls on the event loop.
- **Plugin architecture** — new honeypot types implement a `HoneypotEngine` ABC; new honeytoken types implement `HoneytokenProvider`. Adding a protocol doesn't touch any tool code.
- **Event-driven ingestion pipeline** — engines submit `PendingEvent`s to an asyncio queue → in-memory suppression rules drop noise → batched DB transactions (up to 50 events / transaction) → fan-out to webhook subscribers on a separate worker so slow consumers can't back-pressure ingest.
- **Schema migrations** — Alembic with an idempotent baseline so existing dev DBs adopt cleanly. `init_db()` falls back to `create_all` if migrations fail, so the server always starts.
- **Security practices** — Jinja2 autoescape on attacker-controlled report fields, HMAC-SHA256 signed webhooks (GitHub-webhook convention), per-deploy server personas to defeat fingerprinting, in-memory CIDR/glob suppression with sliding-window rate limiting.
- **SOC tradecraft** — MITRE ATT&CK technique mapping (built-in regex + optional STIX bundle), cross-honeypot kill-chain reconstruction grouped by tactic, STIX 2.1 IOC bundle export, fail2ban / iptables / CIDR blocklist export.
- **Operational signals** — periodic health watchdog probes each running honeypot and emits CRITICAL alerts on failure; `honeypot_self_test` confirms the full pipeline end-to-end.
- **Modern dev tooling** — `uv` for env management, `ruff` for lint, `mypy` for types, `pytest-asyncio` for async tests, `alembic` for migrations.
- **160 unit tests** covering security-critical paths: XSS escape, HMAC correctness, suppression matching (CIDR + glob + rate limit), all 7 honeytoken types' cross-reference matching, SMTP/FTP/HTTP fidelity, HTTPS + STARTTLS, RDP X.224 parsing, DNS realistic responses, GraphQL/OIDC/Swagger probe detection, auto-enrichment of CRITICAL alerts, Prometheus metrics exposition, suppression presets, canary-callback rate limiting, JSON-structured logging, event-buffer timestamp preservation, persona consistency, Alembic idempotency. **Strict mypy passes** — no `Any` leaks, no untyped corners.

---

## Features

| Category | Capabilities |
|---|---|
| **Honeypots** | SSH + Telnet (Cowrie/Docker, persona-based identity, Telnet via `telnet_enabled` flag), HTTP / HTTPS (persona-based fingerprint resistance, self-signed TLS, session cookies, realistic well-known endpoints, GraphQL/OIDC/Swagger API attack-surface), SMTP (Postfix-style EHLO + real STARTTLS upgrade), FTP (ProFTPD-style anonymous flow + PASV), DNS (realistic A/AAAA/MX/NS/TXT/SOA responses), RDP (X.224 handshake parsing) — plug-in architecture, full payload capture |
| **Honeytokens** | Fake AWS credentials, canary URLs, fake credential pairs (auto-matched), PDF/DOCX file tokens (DOCX with real external-image relationship), SSH keys (fingerprint-matched), JWTs (jti-matched on Authorization headers), DB rows (canary email matched on SMTP RCPT TO) |
| **Canary callback** | Built-in HTTP server receives canary URL hits and PDF pixel-tracker pings |
| **Threat Intel** | VirusTotal v3, AbuseIPDB (with auto-report), MaxMind GeoIP — all with TTL caching |
| **Analysis** | MITRE ATT&CK TTP mapping, attacker profiling, SSH session reconstruction, cross-honeypot attacker journey, campaign correlation |
| **Reporting** | XSS-safe HTML (Jinja2 autoescape) and Markdown attack reports |
| **SIEM integration** | Native delivery formats: JSON (HMAC-signed), Splunk HEC, Elastic ECS, ArcSight CEF, Syslog RFC 5424 over UDP/TCP, Grafana Loki, Datadog Logs API v2. Per-subscription severity threshold and delivery health stats. |
| **Cloud honeytokens** | Cloud audit-log ingest endpoint (`/cloud-event`, HMAC-signed) wired to AWS API keys, Azure service principals, GCP service accounts. Ready-to-deploy forwarders under `examples/cloud-forwarders/{aws,azure,gcp}/` (Lambda + Terraform, Azure Function + Bicep, Cloud Function + gcloud). |
| **RDP fingerprinting** | Beyond the X.224 banner: when a client requests SSL/HYBRID, the engine upgrades to TLS and captures the MCS Connect Initial — `clientName`, `clientBuild`, keyboard layout, screen resolution, and encryption methods land in an `rdp_mcs_handshake` event. |
| **Blocklist push** | One-shot tools push offender IPs straight to live appliances: Cloudflare custom lists, pfSense firewall aliases, AWS WAFv2 IPSets. Idempotent + `dry_run` support. |
| **Platform** | Webhook subscriptions, suppression rules + rate limiting + bundled presets (Shodan / Censys / RFC1918), blocklist + STIX exports |
| **Operations** | Periodic health watchdog, end-to-end self-test, Alembic-managed schema migrations, Prometheus `/metrics` endpoint, JSON-structured logging (`LOG_FORMAT=json`), canary-callback rate limiting |
| **MCP Resources** | Live feeds: active honeypots, alert stream, triggered tokens, stats dashboard |

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Docker Desktop (for the Cowrie SSH honeypot)

### 2. Install

```bash
cd "HoneyPot MCP"
uv sync --extra dev
# or: pip install -e ".[dev]"
```

> The `--extra dev` flag pulls in test/lint tooling (pytest, pytest-asyncio,
> ruff, mypy) — without it, `uv run pytest` would silently fall through to
> any system-wide pytest on your PATH. Drop `--extra dev` only if you're
> running the server in a pure-runtime install with no intent to develop.

> If you go the pip route, drop the `uv run` prefix on every command in this
> README. `pytest`, `alembic`, `ruff`, `mypy` are all on PATH after the pip
> install, and you can run the server with `python -m honeypot_mcp.server` or
> the installed `honeypot-mcp` script.

### 3. Configure

```bash
cp .env.example .env
```

**Optional API keys** (everything degrades gracefully without them):
- `VIRUSTOTAL_API_KEY` — free at [virustotal.com](https://www.virustotal.com)
- `ABUSEIPDB_API_KEY` — free at [abuseipdb.com](https://www.abuseipdb.com) (1,000 checks/day)
- `GEOIP_DB_PATH` — download `GeoLite2-City.mmdb` from [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free with registration)

**Optional — full MITRE ATT&CK descriptions:**
```bash
# Place enterprise-attack.json from https://github.com/mitre/cti at:
config/mitre_attack.json
```
Without this, the built-in regex mapper still covers the common honeypot-observable techniques.

### 4. Run

```bash
uv run python -m honeypot_mcp.server
# or
honeypot-mcp
```

---

## Deployment

There's no long-running server process to manage. MCP clients (Claude Desktop, Claude Code) launch the server as a stdio subprocess on demand and tear it down when the chat ends. You configure the client once, then talk to honeypots through Claude.

### Claude Desktop (recommended for end users)

1. Open `%APPDATA%\Claude\claude_desktop_config.json`. Resolves to `C:\Users\<you>\AppData\Roaming\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS. Create the file if it doesn't exist.

2. Add (or merge into the existing `mcpServers` dict):

   ```json
   {
     "mcpServers": {
       "honeypot-mcp": {
         "command": "uv",
         "args": ["run", "--project", "C:\\path\\to\\HoneyPot MCP", "honeypot-mcp"],
         "cwd": "C:\\path\\to\\HoneyPot MCP"
       }
     }
   }
   ```

   Replace `C:\\path\\to\\HoneyPot MCP` with the absolute path to this repo. On macOS / Linux, single forward slashes are fine.

3. Fully quit Claude Desktop (system tray → Quit, not just close-window) and relaunch. The MCP indicator near the chat input should show the honeypot tools as available.

### Claude Code

Already configured — `.claude/settings.json` is committed with the
honeypot MCP server entry. Open the repo in Claude Code and the honeypot
tools become available in chat once the venv is synced
(`uv sync --extra dev`). No per-user setup required.

For reference, the file ships exactly this:

```json
{
  "mcpServers": {
    "honeypot-mcp": {
      "command": "uv",
      "args": ["run", "honeypot-mcp"]
    }
  }
}
```

Note: `.claude/settings.json` is shared (committed); `.claude/settings.local.json`
is your personal overlay (gitignored) — drop per-developer permission grants
or model preferences there.

### Verify the deployment

In a fresh chat, ask Claude:

```
Deploy an HTTP honeypot on port 8080.
Run honeypot_self_test on it.
```

Expected: the deploy returns `{status: "running", ...}`, and the self-test reports `alert_received: True` within a second. That confirms the full pipeline (probe → engine → suppression → buffer → DB) is healthy.

### Troubleshooting

- **Tools don't appear in Claude.** Claude Desktop never launched the server. Check Help → Show Logs and look for the `honeypot-mcp` stdout/stderr. The most common cause is `uv` not being on Claude Desktop's PATH — replace `"command": "uv"` with the absolute path returned by `where.exe uv` (Windows) or `which uv` (macOS).
- **Self-test reports `alert_received: False`.** Run `honeypot_health` first. If the honeypot is alive but the alert never lands, check for an active suppression rule with `suppression_list`.
- **Canary callbacks don't fire.** Port `8888` is already in use — usually a leftover standalone `python -m honeypot_mcp.server`. The Claude-launched copy logs `Canary callback server could not bind 0.0.0.0:8888` in this case (non-fatal but disables canary tokens).

---

## MCP Tools Reference

### Honeypot management
| Tool | Description |
|---|---|
| `ping` | Verify server + DB connectivity |
| `honeypot_deploy` | Deploy a new honeypot (type, port, config) |
| `honeypot_list` | List all honeypots with status and hit counts |
| `honeypot_status` | Detailed status + recent events for one honeypot |
| `honeypot_stop` | Stop/remove a honeypot |
| `honeypot_pause` / `honeypot_resume` | Pause/resume without destroying |
| `honeypot_configure` | Update honeypot config |
| `honeypot_logs` | Fetch raw container logs |
| `honeypot_templates` | List available profiles |
| `honeypot_clone` | Clone a honeypot on a new port |
| `honeypot_health` | Probe each running honeypot to confirm it's actually responding (port + container) |
| `honeypot_self_test` | End-to-end pipeline check: send a marked probe and confirm it lands as an alert |

### Honeytoken management
| Tool | Description |
|---|---|
| `honeytoken_create` | Create any token type |
| `honeytoken_list` | List all tokens with status |
| `honeytoken_status` | Trigger history for a token |
| `honeytoken_revoke` | Deactivate a token |
| `honeytoken_generate_aws` | Generate fake AWS key pair |
| `honeytoken_generate_credentials` | Generate fake username/password sets |
| `honeytoken_embed_file` | Create PDF/DOCX with embedded tracker |
| `honeytoken_export` | Format a token for planting (env, AWS creds, bash, JSON) |

### Alerts & monitoring
| Tool | Description |
|---|---|
| `alerts_recent` | Get recent alerts (filter by IP, severity, honeypot, event_type) |
| `alerts_get` | Full detail for one alert |
| `alerts_search` | Substring search across IP, event type, AND payload contents |
| `alerts_stats` | Aggregated stats snapshot |
| `alerts_acknowledge` | Mark alert as reviewed |
| `alerts_export` | Export as JSON or CSV |
| `alerts_prune` | Retention — delete alerts older than N days |

### Analysis & intelligence
| Tool | Description |
|---|---|
| `enrich_ip` | VT + AbuseIPDB + GeoIP (parallel, cached) |
| `report_ip_abuse` | Submit an abuse report to AbuseIPDB |
| `analyze_attacker` | Full attacker profile with MITRE TTPs and risk score |
| `analyze_session` | Reconstruct one Cowrie SSH session — credentials tried, commands run, file transfers |
| `analyze_attacker_journey` | Cross-honeypot timeline for one IP — events grouped by ATT&CK phase, with transitions |
| `analyze_campaign` | Detect coordinated attack campaigns |
| `map_ttps` | Map events/text to MITRE ATT&CK techniques |
| `generate_report` | XSS-safe HTML or Markdown attack report |
| `threat_timeline` | Chronological event timeline |
| `export_blocklist` | Export top attacker IPs as `plain` / `iptables` / `fail2ban` / `cidr` |
| `export_stix` | Export attacker IPs as a STIX 2.1 indicator bundle |

### Platform integration
| Tool | Description |
|---|---|
| `alert_subscribe` | Register a URL for real-time alert delivery in your SIEM's native format (json, splunk_hec, elastic_ecs, cef, syslog, loki, datadog) |
| `alert_unsubscribe` | Deactivate a subscription |
| `alert_subscriptions_list` | List subscriptions with delivery health stats |
| `suppression_add` | Add a drop or rate-limit rule (exact IP / CIDR / event-type glob) |
| `suppression_remove` | Deactivate a suppression rule |
| `suppression_list` | List rules with hit counts |
| `blocklist_push_cloudflare` | Push offender IPs to a Cloudflare custom list (idempotent + `dry_run`) |
| `blocklist_push_pfsense` | Push offender IPs to a pfSense firewall alias via the Netgate REST API |
| `blocklist_push_aws_waf` | Push offender IPs to an AWS WAFv2 IPSet (uses standard boto3 cred chain) |

### MCP Resources
| Resource | Description |
|---|---|
| `honeypot://active` | Live list of running honeypots |
| `alerts://stream` | 25 most recent alerts |
| `honeytoken://triggered` | All triggered tokens |
| `stats://dashboard` | Aggregated dashboard snapshot |

---

## SIEM integration

`alert_subscribe` takes a `format` argument that picks the body shape and auth scheme. Seven formats are supported out of the box — every common SIEM landing zone has a native option.

| Format | Body shape | Auth | Transport |
|---|---|---|---|
| `json` (default) | raw JSON envelope | HMAC-SHA256 via `X-HoneyPot-Signature` | HTTPS POST |
| `splunk_hec` | Splunk HEC `{time, host, sourcetype, event}` | `Authorization: Splunk <token>` | HTTPS POST |
| `elastic_ecs` | Elastic Common Schema (`source.ip`, `event.action`, `@timestamp`) | `Authorization: ApiKey <key>` | HTTPS POST |
| `cef` | ArcSight CEF pipe-delimited text | — | HTTPS POST (works with QRadar Universal CEF Connector too) |
| `syslog` | RFC 5424 framed message | — | UDP or TCP — URL scheme picks the transport |
| `loki` | Grafana Loki push API `{streams: [...]}` with stringified-ns timestamps | `Authorization: Basic <pre-encoded userid:token>` (optional) | HTTPS POST to `/loki/api/v1/push` |
| `datadog` | Datadog Logs API v2 JSON list | `DD-API-KEY: <key>` | HTTPS POST to `/api/v2/logs` |

Subscription failure stats (`delivery_count`, `failure_count`, `last_error`) are tracked per subscription so you see which integrations are dead at a glance.

### Splunk HEC

```text
# Through Claude:
> alert_subscribe(
    url="https://splunk.example.com:8088/services/collector/event",
    label="splunk-prod",
    severity_threshold="medium",
    hmac_secret="<your-Splunk-HEC-token>",
    format="splunk_hec"
  )
```

Each delivery POSTs the HEC envelope with `Authorization: Splunk <token>`. Index `honeypot:alert` shows up in Splunk under `sourcetype=honeypot:alert` immediately.

### Elastic / OpenSearch (ECS)

```text
> alert_subscribe(
    url="https://elastic.example.com:9200/honeypot-alerts/_doc",
    label="elastic-soc",
    severity_threshold="medium",
    hmac_secret="<your-api-key>",
    format="elastic_ecs"
  )
```

Body is a single ECS-shaped document. Fields land under `source.ip`, `source.port`, `event.action`, `event.category` (taxonomy-classified: authentication / network / process / file / intrusion_detection), `event.severity` (numeric 0-9), `@timestamp`, plus the full native payload preserved under `event.original`. Compatible with Filebeat HTTP input, Logstash `http` input, and the Elasticsearch Bulk API.

### ArcSight / QRadar (CEF)

```text
> alert_subscribe(
    url="https://cef-receiver.example.com/cef",
    label="qradar-cef",
    severity_threshold="high",
    format="cef"
  )
```

Body is a single CEF line: `CEF:0|HoneyPotMCP|server|1.0|<event_type>|<event_type>|<severity>|src=<ip> spt=<port> cs1=<honeypot_id> cs1Label=honeypot_id …`. QRadar's Universal CEF Connector ingests this directly; ArcSight Smart Connectors with CEF input do the same.

### Syslog (RFC 5424)

```text
# UDP
> alert_subscribe(
    url="udp://syslog.example.com:514",
    label="rsyslog",
    severity_threshold="medium",
    format="syslog"
  )

# TCP (RFC 6587 octet-counted framing)
> alert_subscribe(
    url="tcp://syslog.example.com:514",
    label="rsyslog-tcp",
    severity_threshold="medium",
    format="syslog"
  )
```

Messages use facility 16 (`local0`) so you can grep for honeypot traffic separately from system logs at the ingest tier. Severity maps to syslog's inverted scale (CRITICAL → 2, HIGH → 3, MEDIUM → 4, LOW → 6). The MSG body is JSON-encoded so the SIEM still has structured fields to parse out of the syslog message.

### Grafana Loki

```text
> alert_subscribe(
    url="https://logs-prod-us-central1.grafana.net/loki/api/v1/push",
    label="grafana-cloud-loki",
    severity_threshold="medium",
    hmac_secret="<base64 of userid:token>",  # see note below
    format="loki"
  )
```

Body is `{"streams": [...]}` with stringified-nanosecond timestamps (Loki silently 400s on integer timestamps — use the format as-is). Stream labels carry `severity`, `event_type`, `source_ip`, and a fixed `job=honeypot-mcp` so you can pin one panel per honeypot kind without high-cardinality blowups. Self-hosted Loki ignores the auth header; Grafana Cloud expects HTTP basic auth where the credential is `<userid>:<token>` — pre-encode it (`echo -n 'userid:token' | base64`) and pass the result as `hmac_secret`.

### Datadog Logs API

```text
> alert_subscribe(
    url="https://http-intake.logs.datadoghq.com/api/v2/logs",
    label="datadog-soc",
    severity_threshold="medium",
    hmac_secret="<your-DD-API-KEY>",
    format="datadog"
  )
```

Body is the Datadog v2 logs JSON list shape — `ddsource=honeypot-mcp`, `service=honeypot`, `ddtags` includes `severity:` and `event_type:` for fast slicing. Severity maps to Datadog's `status` field: `low→info`, `medium→warning`, `high→error`, `critical→critical`. Regional endpoints (EU / AP1) work identically — swap the URL prefix.

### Slack / Discord / PagerDuty / generic webhooks

Use the default `json` format. The body is the raw native event shape (`source_ip`, `event_type`, `severity`, `payload`, `timestamp`) suitable for direct ingestion by SOAR platforms (Tines, n8n, Splunk SOAR, FortiSOAR), incident management (PagerDuty, Opsgenie), and chat (Slack, Discord, MS Teams via incoming webhooks).

```text
> alert_subscribe(
    url="https://hooks.slack.com/services/T.../B.../...",
    label="soc-slack",
    severity_threshold="high",
    hmac_secret="",  # auto-generates a 32-byte secret and returns it
    format="json"
  )
```

---

## Launching and using the project

> First-time SIEM operator? Read this whole section once before deploying — the order matters (move admin SSH off port 22 BEFORE the honeypot binds it).

### 1. Decide where to run it

Two reasonable paths:

| Path | Best for | Setup time |
|---|---|---|
| **Local Docker stack** | Demos, dashboards, screenshots, learning the tool | ~5 min |
| **Cheap VPS (Hetzner / DigitalOcean / Linode)** | Catching real internet attack traffic | ~30 min |

For the VPS path, see [`docs/DEPLOY.md`](docs/DEPLOY.md) which walks through "rent a $5 VPS → catch real attack traffic" end-to-end with safety guard-rails.

### 2. Stand up the stack

```bash
git clone https://github.com/tohudgins/HoneyPot-MCP.git
cd HoneyPot-MCP
cp .env.example .env       # then edit; the file is well-commented

cd docker
docker compose up -d --build
```

This starts six services on an internal Docker network: the MCP server (canary callback + `/metrics` exporter), a Docker socket proxy, Cowrie SSH, the HTTP honeypot, Prometheus, and Grafana. Confirm everything is healthy:

```bash
docker compose ps
# All services should be Up. Allow ~30s on first start for the MCP
# container's Alembic migration to run.
```

### 3. See it work in 5 minutes

```bash
# Seed ~5,000 realistic demo attack events spread across 24h.
docker compose exec honeypot-mcp python scripts/seed_demo_data.py

# Open Grafana — admin / honeypot (override with GRAFANA_ADMIN_PASSWORD).
open http://localhost:3000
```

Three dashboards are pre-loaded: **Overview** (severity stack, top attackers, engine pie), **Threat Map** (geo-located attacker IPs from the GeoIP enrichment), **MITRE ATT&CK Coverage** (tactic distribution, top techniques observed).

### 4. Drive it through Claude

Configure your MCP client to talk to the server (Claude Desktop config snippet is in `README.md` § Deployment; for Claude Code the repo's `.claude/settings.json` is already wired up). Then in a chat:

```text
> Deploy a Redis honeypot on port 6379.
> Deploy a Cowrie SSH honeypot on port 2222.
> Run honeypot_self_test on both — confirm the alert pipeline lands events.
> Show me the alert stream.
```

### 5. Plant a honeytoken

```text
> Generate a fake AWS credential token labelled "planted-aws-key".
> Generate a kubeconfig honeytoken named "prod-cluster-config".
> Generate a Slack-webhook honeytoken named "fake-deploy-webhook".
> Show me the plant instructions for each.
```

Claude returns:
- The token artefact (key pair / YAML / URL)
- A specific "drop this file at …" instruction
- For cloud tokens: the field to forward to `/cloud-event` for real detection

### 6. Wire up your SIEM

Pick the section above that matches your SIEM. For example, Elastic:

```text
> alert_subscribe(
    url="https://elastic.mysoc.io:9200/honeypot-alerts/_doc",
    label="elastic-soc",
    severity_threshold="medium",
    hmac_secret="<my-api-key>",
    format="elastic_ecs"
  )
```

Within seconds of the next alert, a document shows up in your Elastic index with ECS-conformant field names. From there, Kibana / Grafana / Opensearch Dashboards can visualise it without any field mapping.

Confirm deliveries are landing:

```text
> alert_subscriptions_list
# Shows delivery_count, failure_count, last_error for every subscription.
```

### 7. Day-to-day operations

```text
> alerts_recent severity=high              # quick triage
> analyze_attacker_journey ip=1.2.3.4      # cross-honeypot timeline
> enrich_ip 1.2.3.4                        # VT + AbuseIPDB + GeoIP
> generate_report format=markdown          # weekly write-up
> export_blocklist format=iptables hits=10 # firewall rules for top attackers
> alerts_prune older_than_days=30          # retention sweep — schedule weekly
```

### 8. Forward cloud audit logs (optional — closes AWS / Azure / GCP token detection)

If you generated `api_key` / `azure_credential` / `gcp_service_account` tokens and want them to actually trigger on use, your cloud provider's audit log forwarder needs to POST to the canary server's `/cloud-event` endpoint with an HMAC signature:

```bash
# In .env, set the shared secret (cryptographically random, 32+ bytes):
CLOUD_EVENT_HMAC_SECRET=$(openssl rand -hex 32)
docker compose restart honeypot-mcp
```

Then in your AWS Lambda / Azure Function / GCP Pub/Sub trigger, do something like:

```python
# AWS CloudTrail → honeypot-mcp/cloud-event
import hashlib, hmac, json, urllib.request

def lambda_handler(event, _ctx):
    body = json.dumps(event).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        "https://canary.your-domain.com/cloud-event",
        data=body,
        headers={"Content-Type": "application/json", "X-HoneyPot-Signature": sig},
    )
    urllib.request.urlopen(req)
```

When an attacker tries the planted credentials against AWS/Azure/GCP and triggers a CloudTrail/Activity/Audit event with the matching `accessKeyId` / `client_id` / `principalEmail`, your forwarder routes the event into `/cloud-event`, which fires a CRITICAL alert through the normal pipeline.

**Ready-to-deploy forwarders ship under [`examples/cloud-forwarders/`](./examples/cloud-forwarders/):**

- **AWS** (`aws/`) — Lambda + Terraform module + EventBridge rule on CloudTrail. `terraform apply` deploys end-to-end.
- **Azure** (`azure/`) — Function App (Python v2) + Bicep template + Activity Log → Event Hub diagnostic setting.
- **GCP** (`gcp/`) — Cloud Function (Gen2) + Log Sink + Pub/Sub topic provisioned via `deploy.sh`.

Each subdirectory has its own README with deployment steps. The inline snippet above is just the signing primitive every forwarder reuses.

---

## SOC analyst workflow example

```
> Deploy an SSH honeypot on port 2222.
> Run a self-test to make sure the pipeline is working end-to-end.
> Show me the alert stream.
> Reconstruct the journey for IP 1.2.3.4 — what did they actually do across all my honeypots?
> Generate an HTML report for the last 24h.
> Export an iptables blocklist for IPs with 10+ hits.
> Subscribe my Slack webhook so I get notified on critical alerts.
```

---

## Docker Compose (full stack)

```bash
cd docker
cp ../.env .env
docker compose up -d --build
```

Starts six services on an internal Docker network:

| Service | Purpose | Port |
|---|---|---|
| `honeypot-mcp` | MCP server, canary callback, `/metrics` exporter | 8888 (canary), 9090 (metrics, localhost-only) |
| `socket-proxy` | Restricted Docker API access for the MCP container — replaces the dangerous `/var/run/docker.sock` mount | internal only |
| `cowrie-ssh` | Cowrie SSH/Telnet honeypot | 2222 |
| `http-honeypot` | HTTP honeypot | 8080 |
| `prometheus` | Scrapes `/metrics` from the MCP server | 9091 (localhost-only) |
| `grafana` | Pre-provisioned dashboards (overview, threat map, MITRE coverage) | 3000 |

The socket-proxy sidecar means the MCP container can manage Cowrie via the Docker API without sharing the host socket — so MCP process compromise can't escalate to root-on-host.

---

## Quick demo with Grafana dashboards

The fastest way to see what this project actually does:

```bash
# 1. Bring the stack up
cd docker
docker compose up -d --build

# 2. Seed ~5,000 realistic demo attack events across 24h
docker compose exec honeypot-mcp python scripts/seed_demo_data.py

# 3. Open Grafana (admin / honeypot)
#    Three dashboards are pre-loaded:
#    - HoneyPot MCP — Overview
#    - HoneyPot MCP — Threat Map
#    - HoneyPot MCP — MITRE ATT&CK Coverage
open http://localhost:3000
```

The seed script generates events with realistic source IPs and geo coordinates spread across the top attacker countries (CN, RU, US, BR, IN, …) so the threat map lights up immediately — no waiting for real traffic to arrive.

### Screenshots

> _Drop captured screenshots into `docs/screenshots/` and reference them here. Suggested:_
> - `overview.png` — top-level dashboard with severity stack, top attackers
> - `threat-map.png` — geomap with attacker origins
> - `mitre.png` — ATT&CK tactic coverage

### Architecture of the observability stack

```
                                       ┌──────────────┐
                                       │   Grafana    │  :3000
                                       │ (dashboards) │
                                       └──────┬───────┘
                                              │
                       ┌──────────────────────┼──────────────────────┐
                       │ Prometheus DS (time-series)  SQLite DS (JOIN/JSON)
                       ▼                                              ▼
                 ┌───────────┐                                ┌──────────────┐
                 │Prometheus │ :9091 ←── scrape /metrics ──── │ honeypot_mcp │
                 │  (TSDB)   │                                │   server     │
                 └───────────┘                                │              │
                                                              │   SQLite     │
                                                              │ (WAL mode    │
                                                              │  → readable  │
                                                              │   while live)│
                                                              └──────────────┘
```

The SQLite WAL mode (`database.py`) is what makes the SQLite datasource panels (geo map, top attackers) safe to run against the live alerts DB while the MCP server is still writing events. Grafana reads the file `read-only`; the MCP server writes via the same volume.

---

## Development

```bash
uv run pytest tests/unit/ -v                                  # 160 tests
uv run pytest tests/unit/ --cov=src/honeypot_mcp              # with coverage
uv run ruff check src/ tests/
uv run mypy src/
```

Without `uv`, run `pytest tests/unit/ -v`, `ruff check src/ tests/`,
`mypy src/` directly after `pip install -e ".[dev]"`.

### Schema migrations (Alembic)

Schema is managed by Alembic. The server runs `alembic upgrade head`
automatically at startup, so day-to-day you don't think about it.

When you change a model:

```bash
# 1. Generate a migration from the model diff
uv run alembic revision --autogenerate -m "describe what changed"

# 2. Inspect the generated file under src/honeypot_mcp/migrations/versions/

# 3. Apply (also runs at next server start)
uv run alembic upgrade head
```

Pip users: drop the `uv run` prefix — `alembic revision …` and
`alembic upgrade head` work directly once the project is installed.

In-memory test DBs skip Alembic entirely (we just `create_all`). If a
migration fails for any reason, the server falls back to `create_all`
so you never end up with an unstartable server — the warning is logged.

---

## Project structure

```
src/honeypot_mcp/
├── server.py            — FastMCP app, lifespan, MCP resources
├── canary.py            — HTTP callback server for canary URLs and PDF trackers
├── webhooks.py          — Outbound webhook delivery worker (HMAC, retries)
├── suppression.py       — Drop / rate-limit rule engine (in-memory cache)
├── watchdog.py          — Periodic health checks of running honeypots
├── config.py            — Pydantic settings (.env + YAML)
├── engines/             — Honeypot engines (SSH/HTTP/SMTP/FTP/DNS/RDP/MySQL/Redis/Elasticsearch/VNC)
├── tokens/              — Honeytoken providers (api_key, canary_url, credential, file, ssh_key, jwt, db_row, kubeconfig, slack_webhook, azure_credential, gcp_service_account)
├── storage/             — SQLAlchemy models, queries, async DB layer, event buffer
├── intel/               — VT, AbuseIPDB, GeoIP, MITRE ATT&CK (all cached)
├── analysis/            — Campaign correlator, attacker profiler, Jinja2 reporter
├── tools/               — MCP-exposed tools (honeypot, honeytoken, alerts, analysis, integrations, blocklist_push)
└── migrations/          — Alembic schema migrations
```

---

## Architecture highlights

- **Event buffer** — engines submit events to an asyncio queue; a single background flusher batches up to 50 events per DB transaction. Suppression rules apply at submit time, so dropped events never touch the DB or webhook layer.
- **Webhook fan-out** — every flushed batch is forwarded to active subscriptions on a separate worker, so slow consumers can't back-pressure honeypot ingestion.
- **Canary callback server** — a real aiohttp server runs on the configured callback port. Returns generic `200 OK` so attackers can't fingerprint canary URLs.
- **TTL-cached threat intel** — VT cached 30 min, AbuseIPDB 15 min, GeoIP 24 h. Repeated `enrich_ip` calls don't burn rate limit. Errors are NOT cached so retry works.
- **XSS-safe reports** — HTML rendering uses Jinja2 with autoescape; attacker-controlled IPs/event types/payloads can't break out into executable markup.
- **Watchdog** — every 30s a background task probes each running honeypot. A dead container or unresponsive port flips status to ERROR and emits a CRITICAL alert through the normal pipeline (so you find out the same way you'd find out about an attack).
- **HTTP fingerprint resistance** — at deploy time the HTTP honeypot picks one of several server "personas" (Apache on Ubuntu / Apache on CentOS / Nginx variants / IIS) and pins it. The persona drives Server header, X-Powered-By, session cookie name, 404 page, and per-response timing jitter. Two honeypots in one project pick different personas, so a scanner can't pivot off identical headers.
- **SSH persona identity** — same idea for Cowrie. At deploy time the SSH engine picks an OS persona (Ubuntu 22.04 / Ubuntu 20.04 / Debian 12 / RHEL 8) plus a random hostname from that persona's pool. The OpenSSH banner, kernel version, kernel build string, and distro identity are passed to Cowrie via `COWRIE_*` env vars. Default Cowrie's identical "ubuntu-server" identity on every deploy was the first thing curious attackers checked.
- **Plug-in engines / tokens** — add a honeypot type via `HoneypotEngine`, a token type via `HoneytokenProvider`. No changes to `server.py` or tools.
- **SQLite → PostgreSQL** — swap `DATABASE_URL`. Zero code changes.
- **Offline by default** — VirusTotal, AbuseIPDB, GeoIP, and MITRE STIX all degrade gracefully when missing.

---

## What this is / isn't

**Good fit for:**
- SOC research and training labs
- Internal trip-wire deception inside corporate networks
- Small-to-medium SOC alert pipelines (with the webhook fan-out as the integration spine)
- Demo / portfolio projects showing real engineering depth

**Less good for, without further work:**
- Studying advanced persistent threats — Cowrie is high-fidelity but the in-process HTTP/SMTP/FTP/DNS engines are minimal asyncio implementations; sophisticated attackers may fingerprint them quickly.
- Internet-facing high-volume deployment — needs perimeter hardening, host isolation, and TLS termination in front of the canary callback. Log shipping itself *is* shipped — Splunk HEC, Elastic ECS, Loki, Datadog, ArcSight CEF, and RFC 5424 syslog renderers are built in (see `alert_subscribe format=...`).
- Comprehensive deception platforms — see [T-Pot](https://github.com/telekom-security/tpotce), OpenCanary, or Conpot for higher fidelity across more protocols.

The honeytoken stack, threat-intel enrichment, MITRE mapping, session reconstruction, and integration layer (webhooks + suppression + exports) are all production-grade.

---

## Scaling toward production

1. Replace `DATABASE_URL` with PostgreSQL — Alembic migrations handle schema upgrades cleanly across versions.
2. Deploy honeypot containers to dedicated cloud VMs (one host per honeypot type for isolation).
3. Use a public IP or reverse tunnel (ngrok / Cloudflare Tunnel) for `CANARY_PUBLIC_URL` so canary tokens trigger from the internet.
4. Subscribe your SIEM/SOAR via `alert_subscribe` and verify HMAC signatures on the consumer side.
5. Add suppression rules for known scanners (Censys, internal vuln scanners) before going live.
6. Schedule `alerts_prune` weekly to keep the DB bounded.
7. Run `honeypot_self_test` after deploy to confirm the alert pipeline works end-to-end.
8. The watchdog catches honeypot deaths automatically — subscribe a CRITICAL-threshold webhook so you actually see the `honeypot_health_failed` alerts.

---

## License

Released under the [MIT License](LICENSE).
