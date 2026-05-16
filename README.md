# HoneyPot MCP

[![CI](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)

A Model Context Protocol server for deploying, monitoring, and analysing honeypots and honeytokens — built on [FastMCP](https://github.com/jlowin/fastmcp) and Python 3.11+.

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
- **85 unit tests** covering security-critical paths: XSS escape, HMAC correctness, suppression matching (CIDR + glob + rate limit), event-buffer timestamp preservation, persona consistency, Alembic idempotency.

---

## Features

| Category | Capabilities |
|---|---|
| **Honeypots** | SSH (Cowrie/Docker, persona-based identity), HTTP (with persona-based fingerprint resistance), SMTP, FTP, DNS — plug-in architecture, full payload capture |
| **Honeytokens** | Fake AWS credentials, canary URLs, fake credential pairs, PDF/DOCX file tokens |
| **Canary callback** | Built-in HTTP server receives canary URL hits and PDF pixel-tracker pings |
| **Threat Intel** | VirusTotal v3, AbuseIPDB (with auto-report), MaxMind GeoIP — all with TTL caching |
| **Analysis** | MITRE ATT&CK TTP mapping, attacker profiling, SSH session reconstruction, cross-honeypot attacker journey, campaign correlation |
| **Reporting** | XSS-safe HTML (Jinja2 autoescape) and Markdown attack reports |
| **Platform** | Webhook subscriptions (HMAC-signed), suppression rules + rate limiting, blocklist + STIX exports |
| **Operations** | Periodic health watchdog, end-to-end self-test, Alembic-managed schema migrations |
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
| `alert_subscribe` | Register a URL for real-time alert webhooks (HMAC signed, severity filter) |
| `alert_unsubscribe` | Deactivate a subscription |
| `alert_subscriptions_list` | List subscriptions with delivery health stats |
| `suppression_add` | Add a drop or rate-limit rule (exact IP / CIDR / event-type glob) |
| `suppression_remove` | Deactivate a suppression rule |
| `suppression_list` | List rules with hit counts |

### MCP Resources
| Resource | Description |
|---|---|
| `honeypot://active` | Live list of running honeypots |
| `alerts://stream` | 25 most recent alerts |
| `honeytoken://triggered` | All triggered tokens |
| `stats://dashboard` | Aggregated dashboard snapshot |

---

## Platform integration: pushing alerts to other tools

Webhook subscriptions let you fan alerts out to any HTTP endpoint — Slack, PagerDuty, SIEM, n8n, custom tooling.

```
# Through Claude:
> Subscribe https://hooks.slack.com/services/... to receive HIGH+ severity alerts.
> Add a suppression rule for 10.0.0.0/8 — that's our internal scanner.
> Show me which subscriptions are failing.
```

Each delivery includes:
- The full alert JSON in the body
- `X-HoneyPot-Signature: sha256=<hex>` if `hmac_secret` is set (verify like a GitHub webhook)
- 3 retries with exponential backoff (1s, 5s, 30s) on failure

Subscription failure stats are tracked per subscription so you can see which integrations are dead.

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
docker compose up -d
```

Starts Cowrie on 2222, the HTTP honeypot on 8080, and the MCP server with canary callback on 8888.

---

## Development

```bash
uv run pytest tests/unit/ -v                                  # 85 tests
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
├── engines/             — Honeypot engines (SSH/HTTP/SMTP/FTP/DNS)
├── tokens/              — Honeytoken providers (api_key/canary_url/credential/file)
├── storage/             — SQLAlchemy models, queries, async DB layer, event buffer
├── intel/               — VT, AbuseIPDB, GeoIP, MITRE ATT&CK (all cached)
├── analysis/            — Campaign correlator, attacker profiler, Jinja2 reporter
├── tools/               — MCP-exposed tools (honeypot, honeytoken, alerts, analysis, integrations)
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
- Internet-facing high-volume deployment — needs perimeter hardening, host isolation, log shipping to Elastic/Splunk/Loki (the webhook layer enables this but doesn't ship integrations out of the box).
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
