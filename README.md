# HoneyPot MCP

A professional-grade MCP (Model Context Protocol) server for deploying, managing, and analysing honeypots and honeytokens — built with [FastMCP](https://github.com/jlowin/fastmcp) and Python 3.11+.

Ask Claude to deploy an SSH honeypot, generate fake AWS credentials, map attacker behaviour to MITRE ATT&CK, or produce an HTML threat report — all through natural language.

---

## Features

| Category | Capabilities |
|---|---|
| **Honeypots** | SSH (Cowrie), HTTP, SMTP, FTP, DNS — Docker-isolated, plug-in architecture |
| **Honeytokens** | Fake AWS credentials, Canary URLs, Fake credential pairs, PDF/DOCX file tokens with DNS callbacks |
| **Threat Intel** | VirusTotal v3 IP reputation, Shodan host data, MaxMind GeoIP2 geolocation |
| **Analysis** | MITRE ATT&CK TTP mapping (offline STIX), attacker profiling, campaign correlation, risk scoring |
| **Reporting** | HTML and Markdown attack reports with timeline, top IPs, TTP table |
| **MCP Resources** | Live feeds: active honeypots, alert stream, triggered tokens, stats dashboard |

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Docker Desktop (for SSH/container-based honeypots)

### 2. Install

```bash
# Clone or open the project directory
cd "HoneyPot MCP"

# Install with uv
uv sync

# Or with pip
pip install -e ".[dev]"
```

### 3. Configure

```bash
cp .env.example .env
# Edit .env — add your VIRUSTOTAL_API_KEY and SHODAN_API_KEY
```

**Required for full functionality:**
- `VIRUSTOTAL_API_KEY` — free at [virustotal.com](https://www.virustotal.com)
- `SHODAN_API_KEY` — free at [shodan.io](https://www.shodan.io)
- `GEOIP_DB_PATH` — download `GeoLite2-City.mmdb` from [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free with registration)

**Optional — MITRE ATT&CK full data:**

Download the enterprise ATT&CK STIX JSON and place it at `config/mitre_attack.json`:
```bash
# Download from MITRE (https://github.com/mitre/cti)
# Enterprise ATT&CK: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```
Without this file, the built-in regex mappings cover the most common honeypot techniques.

### 4. Run

```bash
uv run python -m honeypot_mcp.server
# or
honeypot-mcp
```

---

## Connect to Claude

### Claude Desktop (claude.ai/download)

Add to `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "honeypot-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "C:\\Users\\tohud\\OneDrive\\Desktop\\HoneyPot MCP",
        "honeypot-mcp"
      ],
      "cwd": "C:\\Users\\tohud\\OneDrive\\Desktop\\HoneyPot MCP"
    }
  }
}
```

### Claude Code (this tool)

Add to your project's `.claude/settings.json`:
```json
{
  "mcpServers": {
    "honeypot-mcp": {
      "command": "uv",
      "args": ["run", "honeypot-mcp"],
      "cwd": "C:\\Users\\tohud\\OneDrive\\Desktop\\HoneyPot MCP"
    }
  }
}
```

---

## MCP Tools Reference

### Honeypot Management
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

### Honeytoken Management
| Tool | Description |
|---|---|
| `honeytoken_create` | Create any token type |
| `honeytoken_list` | List all tokens with status |
| `honeytoken_status` | Trigger history for a token |
| `honeytoken_revoke` | Deactivate a token |
| `honeytoken_generate_aws` | Generate fake AWS key pair |
| `honeytoken_generate_credentials` | Generate fake credential sets |
| `honeytoken_embed_file` | Create PDF/DOCX with embedded tracker |
| `honeytoken_export` | Export token for planting (multiple formats) |

### Alerts & Monitoring
| Tool | Description |
|---|---|
| `alerts_recent` | Get recent alerts (filterable) |
| `alerts_get` | Full detail for one alert |
| `alerts_search` | Full-text search across alerts |
| `alerts_stats` | Aggregated stats snapshot |
| `alerts_acknowledge` | Mark alert as reviewed |
| `alerts_export` | Export as JSON or CSV |

### Analysis & Intelligence
| Tool | Description |
|---|---|
| `enrich_ip` | VT + Shodan + GeoIP lookup |
| `analyze_attacker` | Full attacker profile with MITRE TTPs |
| `analyze_campaign` | Detect coordinated attack campaigns |
| `map_ttps` | Map events/text to MITRE ATT&CK techniques |
| `generate_report` | HTML or Markdown attack report |
| `threat_timeline` | Chronological event timeline |

### MCP Resources
| Resource | Description |
|---|---|
| `honeypot://active` | Live list of running honeypots |
| `alerts://stream` | 25 most recent alerts |
| `honeytoken://triggered` | All triggered tokens |
| `stats://dashboard` | Aggregated dashboard snapshot |

---

## Docker Compose (Full Stack)

```bash
cd docker
cp ../.env .env
docker compose up -d
```

This starts:
- Cowrie SSH honeypot on port 2222
- HTTP honeypot on port 8080
- MCP server with canary callback listener on port 8888

---

## Development

```bash
# Run tests
uv run pytest tests/unit/ -v

# With coverage
uv run pytest tests/unit/ --cov=src/honeypot_mcp --cov-report=term-missing

# Lint
uv run ruff check src/ tests/

# Type check
uv run mypy src/
```

---

## Project Structure

```
src/honeypot_mcp/
├── server.py           — FastMCP app, tool registration, MCP resources
├── config.py           — Pydantic settings (env + YAML)
├── engines/            — Honeypot engines (SSH/HTTP/SMTP/FTP/DNS)
├── tokens/             — Honeytoken providers (API key/URL/credential/file)
├── storage/            — SQLAlchemy models, queries, database layer
├── intel/              — VT, Shodan, GeoIP, MITRE ATT&CK
└── analysis/           — Campaign correlator, attacker profiler, reporter
```

---

## Architecture Highlights

- **Plugin pattern** — add a new honeypot type by subclassing `HoneypotEngine`; add a token type by subclassing `HoneytokenProvider`. No changes to `server.py`.
- **Docker-isolated honeypots** — real Cowrie SSH honeypot with TTY capture; each engine type runs in its own container namespace.
- **Async throughout** — all tools, engines, and intel clients use `async/await`. No blocking calls on the event loop.
- **Offline MITRE ATT&CK** — built-in regex mappings work without any download; optional STIX bundle enriches descriptions.
- **SQLite → PostgreSQL** — swap `DATABASE_URL` in `.env`. Zero code changes.

---

## Scaling to Production

1. Replace `DATABASE_URL` with PostgreSQL
2. Deploy honeypot containers to cloud VMs (AWS EC2, DigitalOcean Droplets)
3. Use ngrok or a public IP for `CANARY_PUBLIC_URL` to receive real internet callbacks
4. Add Prometheus metrics endpoint (FastMCP supports middleware)
5. Route alerts to SIEM via `alerts_export` + webhook or Kafka

---

## License

MIT
