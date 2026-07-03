# HoneyPot MCP

[![CI](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)

A Model Context Protocol server that lets Claude (or any MCP client) deploy honeypots, plant honeytokens, monitor alerts, and analyse attacker behaviour — all through natural language. Built on [FastMCP](https://github.com/jlowin/fastmcp), async Python 3.11+.

You ask in plain English; it deploys real honeypots (14 protocols), captures what attackers actually do, enriches each hit with threat intel, and ships the result to your SIEM or into a report.

```
> Deploy an SSH honeypot on port 2222.
> Generate a fake AWS credential token and show me where to plant it.
> Reconstruct the journey for IP 1.2.3.4 across all my honeypots.
> Export an iptables blocklist for IPs with 10+ hits.
```

> **Read first:** [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) — what works (Cowrie SSH, HTTP personas, canary URLs, credential cross-reference) and what doesn't (PDF token prompts, AWS-key callback path). Acknowledging the gaps is the point.
>
> **Deploying to the internet?** [docs/DEPLOY.md](docs/DEPLOY.md) — "$5 VPS → real attack traffic in under 30 minutes," with safety guard-rails.

---

## Honeypots

Fourteen protocols. SSH is Cowrie (industrial-grade); the rest are custom async engines that capture the actual attack, not just the connection. Server identity is randomised per deploy (personas) to resist fingerprinting.

| Protocol (default port) | What it captures |
|---|---|
| **SSH + Telnet** (22/23) | Cowrie — full sessions, commands, file uploads, credentials |
| **HTTP/HTTPS** (80/443) | Exploit signatures (Log4Shell, SQLi, traversal, webshell, RCE…), credentials, recon escalation |
| **SMB** (445) | EternalBlue / DoublePulsar exploit probes |
| **RDP** (3389) | X.224 handshake + TLS-upgraded MCS client fingerprint |
| **FTP** (21) | Credentials + uploaded malware (SHA-256'd + classified) |
| **SMTP** (25) | Credentials (AUTH LOGIN/PLAIN), message bodies, open-relay probes |
| **MySQL / PostgreSQL / MSSQL** (3306/5432/1433) | Login creds + post-auth RCE queries (`INTO OUTFILE`, `COPY FROM PROGRAM`) |
| **Redis** (6379) | Full unauth-RCE dropper chain — the attacker's SSH key + target path |
| **MongoDB** (27017) | Unauth commands, `dropDatabase`, ransom notes |
| **Elasticsearch** (9200) | Recon + data-exfil query patterns |
| **DNS** (53) | Tunneling/exfil + recon (AXFR, `version.bind`, ANY) |
| **VNC** (5900) | RFB auth challenge/response |

## Platform

| Category | Capabilities |
|---|---|
| **Honeytokens** | Fake AWS keys, canary URLs, credential pairs (auto-matched on honeypot logins), PDF/DOCX file tokens, SSH keys, JWTs, DB rows, kubeconfigs, Slack webhooks, Azure/GCP cloud credentials |
| **Detection pipeline** | Batched async ingestion → suppression (CIDR/glob + rate limit) → honeytoken cross-reference (auto-CRITICAL) → auto-enrichment of CRITICAL alerts (VT + AbuseIPDB + GeoIP/ASN/reverse-DNS, TTL-cached) |
| **Analysis** | MITRE ATT&CK mapping, attacker profiling + risk score, SSH session reconstruction, cross-honeypot kill-chain timeline, campaign correlation, enriched XSS-safe HTML/Markdown reports |
| **SIEM delivery** | JSON (HMAC-signed), Splunk HEC, Elastic ECS, ArcSight CEF, Syslog RFC 5424 (UDP/TCP), Grafana Loki, Datadog — per-subscription severity thresholds + delivery health stats |
| **Response** | Blocklist push to Cloudflare / pfSense / AWS WAFv2, blocklist + STIX 2.1 export, AbuseIPDB reporting |
| **Operations** | Health watchdog, restart reconciliation, end-to-end self-test, Prometheus `/metrics`, Alembic migrations, JSON logging, Grafana dashboards |
| **Cloud honeytokens** | HMAC-signed `/cloud-event` ingest + ready-to-deploy CloudTrail/Azure/GCP forwarders under [`examples/cloud-forwarders/`](examples/cloud-forwarders/) |

297 unit tests cover the security-critical paths; strict mypy passes.

---

## Quick start

**Prerequisites:** Python 3.11+, [uv](https://docs.astral.sh/uv/) (or pip), Docker Desktop (only needed for the Cowrie SSH honeypot).

```bash
git clone https://github.com/tohudgins/HoneyPot-MCP.git
cd HoneyPot-MCP

uv sync --extra dev          # or: pip install -e ".[dev]"
cp .env.example .env         # optional API keys — see below

uv run python -m honeypot_mcp.server   # or just: honeypot-mcp
```

> `--extra dev` pulls in pytest/ruff/mypy. If you install with pip, drop the
> `uv run` prefix on every command in this README.

**Optional integrations** (everything degrades gracefully without them):

- `VIRUSTOTAL_API_KEY` — IP reputation ([free](https://www.virustotal.com))
- `ABUSEIPDB_API_KEY` — abuse reports ([free, 1k checks/day](https://www.abuseipdb.com))
- `GEOIP_DB_PATH` — [GeoLite2-City.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free with registration)
- `config/mitre_attack.json` — [enterprise-attack.json](https://github.com/mitre/cti) for full ATT&CK technique descriptions (built-in regex mapper works without it)

---

## Connect an MCP client

Two modes, and the difference matters:

- **Local (stdio)** — Claude Desktop/Code spawn the server per chat. Simplest for trying it out, but the server (and any honeypot you deploy) lives only as long as the chat. Use this for local testing.
- **Persistent daemon (HTTP)** — the server runs 24/7 (e.g. via systemd on a VPS) and your MCP client connects over the network with a bearer token (`MCP_AUTH_TOKEN`, required — the daemon refuses to start unauthenticated). **This is the mode for real deployments**, because honeypots run inside the server process and must outlive any single chat. See [docs/DEPLOY.md](docs/DEPLOY.md) for the full VPS walkthrough (systemd unit, token auth, SSH-tunneled control port, observability stack).

The rest of this section covers local stdio setup.

### Claude Code

Already configured: the repo ships `.claude/settings.json` with the server entry. Open the repo in Claude Code, run `uv sync --extra dev` once, and the tools appear in chat.

### Claude Desktop

Add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`, Windows: `%APPDATA%\Claude\`):

```json
{
  "mcpServers": {
    "honeypot-mcp": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/HoneyPot-MCP", "honeypot-mcp"],
      "cwd": "/path/to/HoneyPot-MCP"
    }
  }
}
```

Fully quit and relaunch Claude Desktop (system tray → Quit, not just close-window).

### Verify

In a fresh chat:

```
Deploy an HTTP honeypot on port 8080, then run honeypot_self_test on it.
```

Expected: deploy returns `{status: "running"}` and the self-test reports `alert_received: True` — confirming the full pipeline (probe → engine → suppression → buffer → DB).

**Troubleshooting**

- **Tools don't appear** — Claude Desktop can't find `uv`. Replace `"command": "uv"` with the absolute path from `which uv` / `where.exe uv`. Check Help → Show Logs.
- **`alert_received: False`** — run `honeypot_health`; if alive, check `suppression_list` for a rule eating the event.
- **Canary callbacks don't fire** — port 8888 already in use (usually a leftover standalone server). Non-fatal, but canary tokens won't trigger.

---

## Deploy — catching traffic

Pick by what you want to catch:

| Goal | Run it on | Effort |
|---|---|---|
| Try it / see the dashboards | Your laptop | ~5 min ([demo stack](#docker-stack--grafana-demo)) |
| Catch attacks **on your own network** | A spare box/VM on your LAN | ~15 min |
| Catch **real internet attack traffic** | A cheap throwaway VPS ($5/mo) | ~30 min ([docs/DEPLOY.md](docs/DEPLOY.md)) |

Both "real" paths use the **persistent daemon** so honeypots run 24/7, independent of any chat:

```bash
# On the host, in .env:  MCP_TRANSPORT=http   MCP_AUTH_TOKEN=$(openssl rand -hex 32)
sudo cp deploy/honeypot-mcp.service /etc/systemd/system/   # edit paths inside
sudo systemctl enable --now honeypot-mcp

# From your laptop — tunnel the control port (never firewall-expose it):
ssh -N -L 8000:127.0.0.1:8000 you@host &
claude mcp add --transport http honeypot-mcp http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer <your-MCP_AUTH_TOKEN>"
```

Then just ask Claude to deploy honeypots and watch the alerts roll in.

**On your own network (internal tripwire).** Deploy honeypots on ports nothing else uses. Anything on your LAN that connects to them — a compromised laptop scanning for open SSH/SMB/Redis, an insider poking around — is by definition not legitimate, so **every hit is high-signal**. Plant credential honeytokens and canary URLs on real hosts and file shares so lateral movement trips them too. Nothing needs to be internet-exposed.

**On the public internet (catch real attackers).** Run the daemon on a VPS you don't care about and open the honeypot ports (22, 80, 443, 445, 3389…) to the internet — you'll see Mirai/Hydra SSH brute force, RDP/SMB exploit scanners, and web exploit probes within minutes. **Safety: use a dedicated throwaway host, move your admin SSH off port 22 first, and never reuse production keys.** The full guarded walkthrough (firewall, alerting, ongoing ops) is in [docs/DEPLOY.md](docs/DEPLOY.md).

---

## MCP tools

### Honeypots
| Tool | Description |
|---|---|
| `honeypot_deploy` | Deploy (ssh, http, smtp, ftp, dns, rdp, vnc, redis, mysql, elasticsearch, smb, postgresql, mongodb, mssql) |
| `honeypot_list` / `honeypot_status` | List all / detail + recent events for one |
| `honeypot_stop` / `honeypot_pause` / `honeypot_resume` | Lifecycle control |
| `honeypot_configure` / `honeypot_clone` / `honeypot_logs` / `honeypot_templates` | Config, cloning, raw logs, profiles |
| `honeypot_health` | Probe ports/containers — catches silent deaths |
| `honeypot_self_test` | End-to-end pipeline check: synthetic probe → alert in DB |

### Honeytokens
| Tool | Description |
|---|---|
| `honeytoken_create` | Create any token type |
| `honeytoken_generate_aws` / `honeytoken_generate_credentials` | Fake AWS key pair / username-password sets |
| `honeytoken_embed_file` | PDF/DOCX with embedded canary tracker |
| `honeytoken_list` / `honeytoken_status` / `honeytoken_revoke` / `honeytoken_export` | Manage + format for planting |

### Alerts
| Tool | Description |
|---|---|
| `alerts_recent` / `alerts_get` / `alerts_search` | Triage (filter by IP/severity/type), detail, payload substring search |
| `alerts_stats` / `alerts_export` / `alerts_acknowledge` / `alerts_prune` | Stats, JSON/CSV export, review workflow, retention |

### Analysis
| Tool | Description |
|---|---|
| `enrich_ip` | VT + AbuseIPDB + GeoIP (parallel, cached) |
| `analyze_attacker` / `analyze_session` / `analyze_attacker_journey` | Profile + risk score / Cowrie session reconstruction / cross-honeypot ATT&CK timeline |
| `analyze_campaign` / `map_ttps` / `threat_timeline` | Campaign correlation, MITRE mapping, chronological timeline |
| `generate_report` | XSS-safe HTML or Markdown report |
| `export_blocklist` / `export_stix` / `report_ip_abuse` | plain/iptables/fail2ban/cidr, STIX 2.1 bundle, AbuseIPDB submission |

### Integrations
| Tool | Description |
|---|---|
| `alert_subscribe` / `alert_unsubscribe` / `alert_subscriptions_list` | SIEM/webhook delivery with health stats |
| `suppression_add` / `suppression_remove` / `suppression_list` | Drop or rate-limit noise (exact IP / CIDR / event-type glob) |
| `suppression_load_preset` / `suppression_list_presets` | Bundled presets (shodan, censys, internal-rfc1918) |
| `blocklist_push_cloudflare` / `blocklist_push_pfsense` / `blocklist_push_aws_waf` | Push offender IPs to live appliances (idempotent, `dry_run`) |

### MCP resources
`honeypot://active` · `alerts://stream` · `honeytoken://triggered` · `stats://dashboard`

---

## SIEM integration

`alert_subscribe(url=..., format=...)` picks the body shape and auth scheme. The `hmac_secret` field carries whatever credential the format needs:

| `format` | Body | Auth (`hmac_secret` is…) |
|---|---|---|
| `json` (default) | native JSON envelope | HMAC key → `X-HoneyPot-Signature` (GitHub-webhook convention) |
| `splunk_hec` | HEC `{time, host, sourcetype, event}` | HEC token → `Authorization: Splunk <token>` |
| `elastic_ecs` | ECS document (`source.ip`, `event.action`, `@timestamp`, raw payload in `event.original`) | API key → `Authorization: ApiKey <key>` |
| `cef` | ArcSight CEF line (QRadar Universal CEF Connector compatible) | — |
| `syslog` | RFC 5424; URL scheme picks transport (`udp://host:514` or `tcp://host:514`) | — |
| `loki` | Loki push API with stringified-ns timestamps | pre-encoded `base64(userid:token)` → `Authorization: Basic` |
| `datadog` | Logs API v2 list | API key → `DD-API-KEY` |

Example — Splunk:

```text
> alert_subscribe(
    url="https://splunk.example.com:8088/services/collector/event",
    label="splunk-prod",
    severity_threshold="medium",
    hmac_secret="<your-HEC-token>",
    format="splunk_hec"
  )
```

The same shape works for every format — swap `url`, `format`, and the credential. For Slack / Discord / PagerDuty / SOAR platforms use the default `json` format; passing `hmac_secret=""` auto-generates and returns a 32-byte signing secret. Check delivery health any time with `alert_subscriptions_list` (`delivery_count`, `failure_count`, `last_error` per subscription).

Notes:
- **Syslog** uses facility 16 (`local0`); severity maps CRITICAL→2, HIGH→3, MEDIUM→4, LOW→6. The MSG body is JSON so the SIEM still gets structured fields.
- **Loki** stream labels carry `severity`, `event_type`, `source_ip`, `job=honeypot-mcp`. Self-hosted Loki ignores the auth header.
- **Datadog** regional endpoints (EU/AP1) work identically — swap the URL prefix.

---

## Docker stack + Grafana demo

The fastest way to see the whole thing working — an all-in-one demo stack (server + static honeypots + Prometheus + Grafana):

```bash
cd docker
docker compose up -d --build

# Seed ~5,000 realistic demo attack events across 24h
docker compose exec honeypot-mcp python scripts/seed_demo_data.py

# Grafana: admin / honeypot (override with GRAFANA_ADMIN_PASSWORD)
open http://localhost:3000
```

Three pre-provisioned dashboards: **Overview** (severity stack, top attackers), **Threat Map** (geo-located attacker IPs), **MITRE ATT&CK Coverage**. The seed script spreads events across realistic source countries so the map lights up immediately.

> This all-in-one `docker-compose.yml` is for demos and dashboards. For a **public deployment** driven by natural language, run the server as a persistent daemon on the host and use `docker-compose.observability.yml` for just Grafana + Prometheus against that daemon's data — see [docs/DEPLOY.md](docs/DEPLOY.md).

| Service | Purpose | Port |
|---|---|---|
| `honeypot-mcp` | MCP server, canary callback, `/metrics` | 8888 (canary), 9090 (metrics, localhost) |
| `socket-proxy` | Restricted Docker API — MCP container manages Cowrie without the host socket, so MCP compromise can't escalate to root-on-host | internal |
| `cowrie-ssh` / `http-honeypot` | Honeypots | 2222 / 8080 |
| `prometheus` / `grafana` | Metrics + dashboards | 9091 (localhost) / 3000 |

Grafana reads the SQLite alerts DB read-only while the server writes (WAL mode makes this safe).

---

## Cloud honeytoken detection (optional)

Generated AWS / Azure / GCP credential tokens only trigger if your cloud audit logs are forwarded to the canary server's `/cloud-event` endpoint (HMAC-signed):

```bash
# .env
CLOUD_EVENT_HMAC_SECRET=$(openssl rand -hex 32)
```

Ready-to-deploy forwarders ship under [`examples/cloud-forwarders/`](examples/cloud-forwarders/): AWS (Lambda + Terraform + EventBridge), Azure (Function App + Bicep), GCP (Cloud Function + Log Sink via `deploy.sh`). Each has its own README. When an attacker uses planted credentials, the resulting CloudTrail / Activity Log / Audit Log event routes through the forwarder and fires a CRITICAL alert.

Without a forwarder, cloud credential tokens are believable decoys with no callback — see [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

---

## Day-to-day operations

```text
> alerts_recent severity=high              # quick triage
> analyze_attacker_journey ip=1.2.3.4      # cross-honeypot timeline
> enrich_ip 1.2.3.4                        # VT + AbuseIPDB + GeoIP
> generate_report format=markdown          # weekly write-up
> export_blocklist format=iptables hits=10 # firewall rules for top attackers
> alerts_prune older_than_days=30          # retention sweep — schedule weekly
```

Going to production: swap `DATABASE_URL` to PostgreSQL (zero code changes), point `CANARY_PUBLIC_URL` at a public address (ngrok / Cloudflare Tunnel / real domain), load suppression presets for known scanners before going live, and subscribe a CRITICAL-threshold webhook so you see `honeypot_health_failed` watchdog alerts. Full walkthrough: [docs/DEPLOY.md](docs/DEPLOY.md).

---

## Development

```bash
uv run pytest tests/unit/ -v          # 297 tests
uv run ruff check src/ tests/
uv run mypy src/
```

**Schema migrations** are Alembic-managed; the server runs `alembic upgrade head` at startup. After changing a model:

```bash
uv run alembic revision --autogenerate -m "what changed"
# inspect the generated file, then it auto-applies on next start
```

### Project structure

```
src/honeypot_mcp/
├── server.py            — FastMCP app, lifespan, MCP resources
├── canary.py            — Callback server: canary URLs, PDF trackers, /cloud-event
├── webhooks.py          — Outbound SIEM/webhook delivery worker (HMAC, retries)
├── suppression.py       — Drop / rate-limit rule engine
├── credential_match.py  — Planted-credential cross-reference (auto-CRITICAL)
├── watchdog.py          — Periodic health checks of running honeypots
├── reconcile.py         — Re-establishes RUNNING honeypots on server restart
├── engines/             — Honeypot engines (plugin ABC: HoneypotEngine)
├── tokens/              — Honeytoken providers (plugin ABC: HoneytokenProvider)
├── storage/             — Models, async DB layer, batched event buffer
├── intel/               — VirusTotal, AbuseIPDB, GeoIP, MITRE (TTL-cached)
├── analysis/            — Correlator, profiler, Jinja2 reporter
├── tools/               — MCP tool modules
└── migrations/          — Alembic versions
```

Architecture details (event pipeline, persona system, plugin patterns) are documented in [CLAUDE.md](CLAUDE.md).

---

## What this is / isn't

**Good fit:** SOC research and training labs, internal trip-wire deception, small-to-medium SOC alert pipelines, and catching internet-scale automated attack traffic on a public IP. The engines capture real attack artifacts — Redis RCE dropper chains (the attacker's SSH key + target path), FTP malware uploads (hashed + classified), MySQL `INTO OUTFILE` webshell drops, SMB EternalBlue/DoublePulsar probes, MongoDB ransom notes — enriched (geo, ASN, reverse DNS, VT/AbuseIPDB reputation) and shipped to your SIEM.

**Not a fit without further work:** fooling a skilled human probing by hand. SSH is Cowrie (high-fidelity); the custom protocol engines are detection-focused rather than full protocol stacks, so a manual expert can eventually fingerprint them. For maximal-fidelity deception across more protocols, see [T-Pot](https://github.com/telekom-security/tpotce), [OpenCanary](https://github.com/thinkst/opencanary), or [Thinkst Canary](https://canary.tools/).

The full honest rundown is in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md).

---

## License

Released under the [MIT License](LICENSE).
