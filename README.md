# HoneyPot MCP

[![CI](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tohudgins/HoneyPot-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)](pyproject.toml)

**An MCP server that deploys 25 honeypot protocol engines and honeytokens, and turns what attackers do into telemetry you analyse by talking to an AI client.**

```
> Deploy an SSH honeypot on port 2222 and an HTTP one on 8080.
> Anything critical in the last hour?
> Reconstruct what <ip> did across all my honeypots.
> Export an iptables blocklist for anyone with 10+ hits.
```

## Results

Run on a public-IP DigitalOcean droplet for 116 hours (since destroyed); the full database backup is kept.

| Measured | Value | Source |
|---|---|---|
| Alerts captured | 17.7M stored (17,726,494 rows); the flood guard counted a further 55.5M sip probes from 13 sources without storing them, so the sensors saw about 73M events | `alerts` table of the backup; [docs/RESULTS.md](docs/RESULTS.md) section 1.4 |
| Distinct source addresses | 3,337 | attacker-event report over the backup (`report.txt`) |
| Duration | 116.4 h (2026-10-11 18:18 to 2026-10-16 14:42 UTC) | first and last alert timestamps |
| Sensors / engine types | 23 sensors, 23 types (SMTP and DNS exist but were off on the public host) | `honeypots` table |
| MCP tools | 70 | [docs/FIELD_TEST.md](docs/FIELD_TEST.md) |
| Unit tests | 2,221 passed, 4 skipped (the last full run, before the final docs) | `pytest tests/unit` |
| Independent oracle | 73 raw-SQL checks, 0 failed (first run: 4.9M alerts, in 31 s; the final run was on 17.5M) | `scripts/field_test_oracle.py`, [docs/FIELD_TEST.md](docs/FIELD_TEST.md) |
| End-to-end engine proof | 23 of 23 deployed engines attacked from outside with real clients and recorded | `scripts/field_test.py` |
| Console load on 17.6M alerts | over 100 s, now 0.2 to 3 s live | [CHANGELOG.md](CHANGELOG.md) |

Not verified: GreyNoise enrichment and the pfSense / Cloudflare / AWS WAF push tools were never run against real services (tests drive strict stubs of the vendors' published contracts).

## What it is

Most honeypot stacks are a single-protocol toy or a 30-container distribution you read as raw JSON. This is one process on one box: in-process asyncio engines for 23 protocols plus Cowrie (Docker) for SSH and Telnet, honeytokens that trip on use, and an analysis layer exposed over [Model Context Protocol](https://modelcontextprotocol.io), so Claude Desktop, Claude Code or any MCP client is the console. Engines capture artifacts (the SSH key from a Redis dropper chain, the ransom note from a MongoDB wipe, NetNTLMv2 responses from RDP/SMB) and the tools answer questions about them (ATT&CK mapping, campaigns, triage, reports, blocklists). [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) states plainly what it will and will not catch: internet-scale automated traffic yes, a skilled human probing by hand no.

## How data flows

Engines never touch the database. Everything passes one ingestion path ([CLAUDE.md](CLAUDE.md) has the detail):

```mermaid
flowchart LR
    ENG["25 engine types<br/>Cowrie SSH/Telnet + in-process asyncio"] --> SUB["submit_event()"]
    subgraph BUF["Event buffer"]
        direction TB
        SUP{"Suppression<br/>CIDR / glob / rate limit"} -->|passes| CM{"Credential match<br/>planted creds -> CRITICAL"}
        CM --> FG{"Flood guard<br/>600 stored/min per source+type<br/>CRITICAL never dropped"}
        FG --> Q["Queue -> flusher<br/>batches of 50, max 1 s"]
    end
    SUB --> SUP
    SUP -->|dropped| X["discarded"]
    Q --> DB[("alerts + alert_rollups<br/>SQLite / PostgreSQL<br/>rollups written in the same transaction")]
    DB --> MCP["MCP tools<br/>+ operations console"]
    DB --> GF["Grafana"]
    DB --> WH["Webhook worker<br/>SIEM, Slack, Teams, email"]
    DB -.->|CRITICAL| ENR["Enrichment<br/>VT, AbuseIPDB, GeoIP"] -.-> DB
```

Design points:

- **Batched writes carry their own timestamps**, so a batch of 50 does not share one `func.now()` and session reconstruction stays chronological.
- **Statistics read hourly rollups, never the alert table.** The cost of a figure depends on the size of the answer, not of the database; this is what kept the tools usable at 17.7M rows.
- **The webhook worker is decoupled from the flusher**; a SIEM that takes 30 s cannot back-pressure ingestion.
- **Enrichment is fire-and-forget and TTL-cached**; repeat CRITICALs from one IP cost no external calls.
- **Tool responses are shaped for a context window.** List tools return digests, `alerts_get` expands one alert, bulk output goes to disk.

## Screenshots

Real run (the 116-hour droplet; the Grafana captures stop at 2026-10-16 10:00 UTC, about four hours before the end):

![Grafana overview, real run](docs/screenshots/real-run/overview.png)
<p align="center"><em>Real run: Grafana overview. 17.5M alerts and 3.3K sources in the window, the two flood windows on 12 October, and the per-engine split (the "(removed sensors)" slice is alerts from sensors that were recreated during the run). The top-attackers table is cropped out: it lists real addresses.</em></p>

![Operations console, real run](docs/screenshots/real-run/operations-console.png)
<p align="center"><em>Real run: the built-in operations console on the live droplet, 24 h window: 4,013,956 events, 913 attackers, 23 of 23 sensors up, 1 honeytoken triggered, and per-sensor counts. The attacker and live-feed panels are cropped out for the same reason.</em></p>

![Threat map, real run](docs/screenshots/real-run/threat-map.png)
<p align="center"><em>Real run: Grafana threat map of attacker origins.</em></p>

![MITRE ATT&CK coverage, real run](docs/screenshots/real-run/mitre-coverage.png)
<p align="center"><em>Real run: ATT&CK tactic coverage from the same database.</em></p>

![ATT&CK Navigator layer, real run](docs/screenshots/real-run/attack-navigator.png)
<p align="center"><em>Real run: Navigator layer from <code>attack_navigator_layer</code>, scored with the same exact counts (<a href="docs/screenshots/real-run/attack-navigator-layer.json">layer JSON</a>).</em></p>

Demo stack (seeded synthetic events, regenerated by [`scripts/capture_screenshots.sh`](scripts/capture_screenshots.sh)):

<table>
<tr>
<td width="50%"><a href="docs/screenshots/console.png"><img src="docs/screenshots/console.png" alt="Operations console"></a><br><em>Demo stack: built-in operations console (live feed, sensor health, severity volume).</em></td>
<td width="50%"><a href="docs/screenshots/overview.png"><img src="docs/screenshots/overview.png" alt="Grafana overview"></a><br><em>Demo stack: Grafana overview.</em></td>
</tr>
</table>

## What running it on the real internet taught us

Defects and measurements that unit tests and the demo stack did not surface. Detail in [CHANGELOG.md](CHANGELOG.md), [docs/FIELD_TEST.md](docs/FIELD_TEST.md) and [docs/RESULTS.md](docs/RESULTS.md).

- **Passive FTP and NFS were unreachable behind a default-drop firewall.** FTP data ports were random, so every session stalled after login: 9 anonymous logins, 9 passive attempts, no listing or download. NFS clients ask the portmapper on 111 before 2049, so `showmount -e` got nothing; its portmapper also answered every version in the v2 format and broke nmap's RPC library. Fixed with a bounded passive range and a 111/2049 redirect.
- **`analyze_campaign` read only the newest 5,000 alerts.** On a flood-dominated database it reported 7 campaigns from the last 16 minutes; the raw-SQL oracle found 274. It now reads the exact hourly rollups.
- **The console did not load on 17.6M alerts.** `/api/overview` did not answer in 100 to 120 s, re-aggregating the raw table ten times per poll; it now reads rollups and answers in 0.2 to 3 s.
- **The SSH bait credential sat in the wrong home directory.** It was under the persona user, but attackers log in as `root` (105,066 logins in the first run) or `admin` (70,460), so nobody could see it. It now also lives in `/root`; replaying it against the MySQL sensor produced a CRITICAL token trip.
- **`asyncio.wait_for` cannot stop a SQLite scan in aiosqlite's worker thread.** `sql_query` ran 87 s past its 15 s limit and left the session in `PendingRollbackError`; the deadline is now a SQLite progress handler.
- **The three blocklist-push tools were wrong against the vendors' real contracts.** pfSense: wrong auth header, lookup and HTTP verb; Cloudflare: asynchronous operation reported done; AWS WAF: the operator's description blanked each push. They had only been tested against mocks of themselves.

## Documentation map

| Document | What it covers |
|---|---|
| [docs/RESULTS.md](docs/RESULTS.md) | What the 116-hour run captured and found |
| [docs/DEPLOY.md](docs/DEPLOY.md) | Step-by-step VPS deployment, go-live checklist, backups, offline analysis |
| [docs/HARDENING.md](docs/HARDENING.md) | Host hardening: default-drop firewall, Docker guard, sandboxed units |
| [docs/FIELD_TEST.md](docs/FIELD_TEST.md) | The scripts that attack every engine and check the answers, and what they found |
| [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) | What works, what does not, and why |
| [CHANGELOG.md](CHANGELOG.md) | What changed, including live-run findings |
| [CLAUDE.md](CLAUDE.md) | Architecture and plugin patterns |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup and the non-obvious rules |
| [SECURITY.md](SECURITY.md) | Private vulnerability reporting |

---

## Try it in 2 minutes

No API keys, no config, no MCP client required:

```bash
git clone https://github.com/tohudgins/HoneyPot-MCP.git
cd HoneyPot-MCP/docker
docker compose up -d --build

# Seed ~5,000 synthetic attack events across the last 24h
docker compose exec honeypot-mcp python scripts/seed_demo_data.py

open http://localhost:8090   # operations console
open http://localhost:3000   # Grafana, admin / honeypot
```

This brings up the server, a live Cowrie SSH honeypot on `:2222`, an HTTP honeypot on `:8080`, Prometheus, and five provisioned Grafana dashboards (overview, threat map, ATT&CK coverage, a **Query** box that runs read-only SQL, and an **Alerts** browser). SSH into `localhost:2222` with any password and your session appears in the console within seconds.

---

## Capabilities

<table>
<tr><td><b>25 protocols</b></td><td>SSH, Telnet (Cowrie), HTTP/S, SMB, RDP, FTP, SMTP, DNS, VNC, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, Docker API, Kubernetes API, LDAP, SNMP, Memcached, IMAP, POP3, SIP/VoIP, rsync, NFS</td></tr>
<tr><td><b>Past the login</b></td><td>RDP lets a planted credential (or one weak pair) into a desktop session over NLA or plain TLS, with a fake <code>cmd</code>/PowerShell that executes nothing and has no route out; every command, keystroke, click and pasted text is recorded. POP3 and IMAP serve the mailbox the SMTP honeypot filled; HTTP has an admin console. Nothing is ever sent onward</td></tr>
<tr><td><b>Anti-fingerprinting</b></td><td>Per-deploy SSH + HTTP personas (coherent banner/kernel/header bundles), response jitter, per-honeypot self-signed TLS shaped per service, realistic <code>robots.txt</code>/<code>favicon.ico</code>/<code>security.txt</code></td></tr>
<tr><td><b>Honeytokens</b></td><td>AWS/Azure/GCP keys, canary URLs, credential pairs, PDF/DOCX trackers, SSH keys, JWTs, DB rows, kubeconfigs, Slack webhooks</td></tr>
<tr><td><b>Credential correlation</b></td><td>Planted creds auto-match on any honeypot login and escalate to CRITICAL, including MySQL and VNC, where the plaintext never crosses the wire (the engine recomputes the scramble/DES response)</td></tr>
<tr><td><b>Analysis</b></td><td>MITRE ATT&CK mapping, attacker profiling + risk score, SSH session reconstruction, cross-honeypot kill-chain timelines, campaign correlation, XSS-safe HTML/Markdown reports</td></tr>
<tr><td><b>SIEM delivery</b></td><td>JSON (HMAC-signed), Splunk HEC, Elastic ECS, ArcSight CEF, RFC 5424 syslog, Grafana Loki, Datadog; per-subscription severity thresholds and delivery health</td></tr>
<tr><td><b>Human notifications</b></td><td>Slack, Microsoft Teams, email; severity-coloured, credentials up front, coalesced so one scanner cannot bury the channel. CRITICAL is never held back</td></tr>
<tr><td><b>Packet capture</b></td><td>Optional tcpdump ring buffer scoped to the deployed ports; <code>pcap_extract</code> pulls one attacker's packets for Wireshark, Suricata or Zeek. Disk bounded by construction</td></tr>
<tr><td><b>Response</b></td><td>Blocklist push to Cloudflare / pfSense / AWS WAFv2, iptables/fail2ban/CIDR export, STIX 2.1 bundles, AbuseIPDB reporting</td></tr>
<tr><td><b>Console</b></td><td>Read-only web dashboard on <code>:8090</code> served by the server itself: live feed, sensor health, severity volume, top attackers and origins</td></tr>
<tr><td><b>Triage</b></td><td>Bulk acknowledge by filter with a disposition, note and analyst; append-only audit log of every control-plane action</td></tr>
<tr><td><b>Operations</b></td><td>Health watchdog, restart reconciliation, retention sweep, per-IP connection caps, end-to-end self-test, Prometheus <code>/metrics</code>, Alembic migrations, JSON logging</td></tr>
</table>

Ruff and mypy are blocking in CI across Python 3.11 to 3.14; a CI job also runs the whole suite on PostgreSQL. Docker- and network-gated integration tests skip without them.

---

## Install

**Prerequisites:** Python 3.11+. Docker only for the Cowrie SSH/Telnet honeypot.

```bash
pipx install honeypot-mcp          # or: pip install honeypot-mcp
honeypot-mcp                        # starts the server
```

PostgreSQL: `pip install "honeypot-mcp[postgres]"`.

**Container:**

```bash
docker run -d --name honeypot-mcp \
  -e MCP_TRANSPORT=none -e CONSOLE_HOST=0.0.0.0 \
  -p 127.0.0.1:8090:8090 -p 8888:8888 \
  -v honeypot-data:/app/data \
  ghcr.io/tohudgins/honeypot-mcp:latest
```

**From source:**

```bash
git clone https://github.com/tohudgins/HoneyPot-MCP.git
cd HoneyPot-MCP
uv sync --extra dev          # or: pip install -e ".[dev]"
cp .env.example .env         # optional; everything works without keys
```

> `--extra dev` pulls in pytest/ruff/mypy. With a pip install, drop the `uv run` prefix from the commands below.

**Optional integrations** each degrade to `{"available": false}`:

| Variable | Gets you | Cost |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | IP reputation | free |
| `ABUSEIPDB_API_KEY` | Abuse reports + outbound reporting | free, 1k/day |
| `GEOIP_DB_PATH` | Country/city/coords on every alert (City DB) | free, registration |
| `GEOIP_ASN_DB_PATH` | Origin AS number + org (ASN DB) | free, same account |
| `CANARY_PUBLIC_URL` | Honeytokens that fire from the internet | ngrok / a domain |
| `GREYNOISE_API_KEY` | GreyNoise scanner/crawler classification in `enrich_ip` | free community tier |
| `ABUSECH_AUTH_KEY` | abuse.ch (MalwareBazaar, URLhaus, ThreatFox), `lookup_hash` | free |
| `OTX_API_KEY` | AlienVault OTX pulses an address appears in | free |
| `SHODAN_INTERNETDB_ENABLED=true` | Shodan InternetDB open ports/CPEs (no key) | free |

The last four are off unless set, cached and bounded by one 3 s fan-out deadline. All are tested against stubs of the vendors' published contracts; abuse.ch, OTX and InternetDB were also run live against real attacker addresses and a captured malware hash. **GreyNoise was never run live** (its free key requires a business email). `scripts/intel_smoke.py` makes one live call per provider.

---

## Run it

| Mode | `MCP_TRANSPORT` | Lives as long as | Use for |
|---|---|---|---|
| **Local** | `stdio` (default) | the chat session | trying it out, development |
| **Daemon** | `http` | the systemd unit | real deployments driven by chat |
| **Collector** | `none` | the systemd unit | capture-only hosts, containers |

### Local (stdio)

Claude Code users: the repo ships `.claude/settings.json`, so the tools appear when you open it. For Claude Desktop, add to `claude_desktop_config.json` (macOS `~/Library/Application Support/Claude/`, Windows `%APPDATA%\Claude\`):

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

Fully quit and relaunch Claude Desktop, then:

```
Deploy an HTTP honeypot on port 8080, then run honeypot_self_test on it.
```

`alert_received: true` confirms probe, engine, suppression, buffer and database end to end.

### Daemon (http)

Honeypots outlive any chat:

```bash
# In .env:  MCP_TRANSPORT=http   MCP_AUTH_TOKEN=$(openssl rand -hex 32)
sudo cp deploy/honeypot-mcp.service /etc/systemd/system/   # edit paths inside
sudo systemctl enable --now honeypot-mcp

# From your laptop: tunnel the control port, never firewall-expose it
ssh -N -L 8000:127.0.0.1:8000 you@host &
claude mcp add --transport http honeypot-mcp http://127.0.0.1:8000/mcp \
  --header "Authorization: Bearer <your-MCP_AUTH_TOKEN>"
```

The networked control plane can deploy honeypots and read everything they capture, so it is **fail-closed**: the server refuses to start on a networked transport unless `MCP_AUTH_TOKEN` is set (or you opt out with `MCP_ALLOW_UNAUTHENTICATED`).

**Role-based access.** `MCP_AUTH_TOKENS` hands out scoped tokens: `viewer` (read-only triage, analysis, reports), `operator` (also deploy/stop honeypots, manage honeytokens, acknowledge alerts: everything reversible and contained to this system's data), `admin` (also prune alerts, push to an external firewall/WAF, read the audit log, manage access). [`rbac.py`](src/honeypot_mcp/rbac.py) lists which tool needs which role; [docs/DEPLOY.md](docs/DEPLOY.md) has the format.

**Per-person access.** Env-var tokens need a restart to change and carry no identity beyond a role. An admin token can mint per-person API keys live (`api_key_create` / `api_key_revoke` / `api_key_list`), so `audit_log_search` says *who* deployed a honeypot or pruned alerts. Keys take effect within 30 s; the plaintext is shown once.

### Collector (none)

Runs the capture plane (engines, canary callbacks, watchdog, webhook delivery, `/metrics`) with **no control plane**. Nothing can be deployed or queried remotely; events flow to the database and your SIEM. This is what the Docker stack runs.

**Two processes, one database.** The first server to start owns the sensors (an OS file lock beside the SQLite file). A second, such as another chat session, starts read-only: it can query, triage and report, and refuses to deploy or stop. `ping` reports the role.

---

## Deploy: catching real traffic

| Goal | Run it on | Effort |
|---|---|---|
| See the dashboards | your laptop | ~2 min (above) |
| Catch attacks on **your own network** | a spare box/VM | ~15 min |
| Catch **real internet attack traffic** | a throwaway VPS | ~30 min ([docs/DEPLOY.md](docs/DEPLOY.md)) |

- Before exposing a VPS, run `scripts/preflight.sh`: it checks the control plane, bind addresses, disk, ports, backups, and probes every sensor end to end.
- Harden the host first with [docs/HARDENING.md](docs/HARDENING.md) (default-drop firewall, validating Docker guard, sandboxed units, key-only SSH, moved control ports). The honeypots stay reachable; everything around them does not.
- Prove it works: `scripts/field_test.py` attacks every engine through its public port with real clients and checks the database recorded each one; `field_test_tools.py` exercises all 70 tools at their roles; `field_test_ops.py`, `field_test_injection.py` and `field_test_oracle.py` cover operations, prompt injection and an independent check of the numbers ([docs/FIELD_TEST.md](docs/FIELD_TEST.md)). A quiet sensor is ambiguous (nobody tried, or it is broken); this removes the ambiguity.

**Internal tripwire.** Put honeypots on ports nothing legitimate uses; anything on your LAN that connects is by definition unexpected. Plant credential tokens and canary URLs on real file shares so lateral movement trips them too.

**Public internet.** Use a dedicated throwaway host, move your admin SSH off port 22 first, and never reuse production keys. Scanners arrive within minutes.

**Analysing a backup offline.** `ANALYSIS_MODE=true` opens a database without starting any sensor, capture, canary, watchdog or notification. `scripts/analyze_backup.py <backup-dir|db>` copies a backup, runs the server in that mode over real MCP stdio and writes headline numbers, ATT&CK techniques, top-source journeys, campaigns, fingerprint clusters and report/STIX/blocklist exports to `<workdir>/reports/` ([DEPLOY.md](docs/DEPLOY.md), step 13). For a live database, `scripts/attack_report.py --days 30 --format markdown` writes campaign statistics.

---

## MCP tools

<details>
<summary><b>Honeypots</b>: deploy, lifecycle, health</summary>

| Tool | Description |
|---|---|
| `deception_plan` | **Describe an environment, get a coherent deployment plan**: conflict-free ports, consistent identities, tokens tied to sensors that can detect them |
| `deception_deploy_plan` | Bring a plan up atomically, rolling back everything on failure |
| `deception_coverage` | What the live deployment detects per ATT&CK tactic, and the ranked blind spots |
| `soc_brief` | Shift handover: what needs a human, separated from the background radiation |
| `honeypot_deploy` | Deploy any of the 25 engine types |
| `honeypot_stop` | Stop one, several by name, or every honeypot matching a type/status filter |
| `honeypot_list` / `honeypot_status` | List all / detail + recent events for one |
| `honeypot_pause` / `honeypot_resume` | Lifecycle control |
| `honeypot_configure` / `honeypot_clone` / `honeypot_logs` / `honeypot_templates` | Config, cloning, raw logs, profiles |
| `honeypot_health` | Probe ports/containers; catches silent deaths |
| `honeypot_self_test` | End-to-end pipeline check: synthetic probe, alert in DB |

</details>

<details>
<summary><b>Honeytokens</b>: generate, plant, track</summary>

| Tool | Description |
|---|---|
| `honeytoken_create` | Create any token type |
| `honeytoken_generate_aws` / `honeytoken_generate_credentials` | Fake AWS key pair / username-password sets |
| `honeytoken_embed_file` | PDF/DOCX with an embedded canary tracker |
| `honeytoken_list` / `honeytoken_status` / `honeytoken_revoke` / `honeytoken_export` | Manage and format for planting |
| `honeytoken_rotate` | Replace a token's secret while keeping its identity and history |

</details>

<details>
<summary><b>Alerts</b>: triage, search, export</summary>

| Tool | Description |
|---|---|
| `alerts_recent` | Triage by time window, severity, IP, or honeypot; a compact digest per alert |
| `alerts_get` | Full captured payload for one alert |
| `alerts_search` | Find alerts by payload content: a command, username, path, User-Agent, or hash |
| `alerts_stats` | Totals by severity, top attacker IPs, top event types, optionally windowed |
| `alerts_acknowledge` | Triage in bulk with a disposition (true/false positive, benign), note and analyst |
| `alerts_export` / `alerts_prune` | Write JSON/CSV to disk, retention |
| `audit_log_search` | Review every state-changing action the control plane took |

</details>

<details>
<summary><b>Analysis</b>: enrichment, profiling, reporting</summary>

| Tool | Description |
|---|---|
| `enrich_ip` | VirusTotal + AbuseIPDB + GeoIP, plus GreyNoise / abuse.ch / OTX / Shodan InternetDB when configured; parallel and cached |
| `analyze_attacker` / `analyze_session` / `analyze_attacker_journey` | Profile + risk score / Cowrie session reconstruction / cross-honeypot ATT&CK timeline (exact totals, bounded sample; safe on an attacker with 100k+ events) |
| `fingerprint_clusters` | Group sources by SSH client fingerprint (HASSH); the same tooling behind many IPs is one operator |
| `analyze_campaign` / `map_ttps` / `threat_timeline` | Campaign correlation, MITRE mapping, chronological timeline |
| `generate_report` | Write an XSS-safe HTML or Markdown report to disk |
| `export_blocklist` / `export_stix` | Write iptables/fail2ban/CIDR list or a STIX 2.1 bundle to disk |
| `report_ip_abuse` | Submit an attacker IP to AbuseIPDB |
| `attack_summary` / `attack_navigator_layer` | Exact totals by tactic/technique for a window / an ATT&CK Navigator layer scored with the same counts |
| `extract_iocs` / `lookup_hash` | Distinct URLs, hosts and file hashes from payloads / MalwareBazaar lookup of a hash |
| `sql_query` | One read-only `SELECT` over `alerts`, `alert_rollups` and `honeypots` (secret tables refused, 1,000 rows, 15 s); also the **Query** box on Grafana dashboard 04 |
| `ping` | Server role (owner or read-only) and liveness |

</details>

<details>
<summary><b>Integrations</b>: SIEM, suppression, blocklist push</summary>

| Tool | Description |
|---|---|
| `alert_subscribe` / `alert_unsubscribe` / `alert_subscriptions_list` | SIEM, Slack, Teams and email delivery with health stats |
| `suppression_add` / `suppression_remove` / `suppression_list` | Drop or rate-limit noise (exact IP / CIDR / event-type glob) |
| `suppression_load_preset` / `suppression_list_presets` | Bundled presets: shodan, censys, internal-rfc1918 |
| `blocklist_push_cloudflare` / `blocklist_push_pfsense` / `blocklist_push_aws_waf` | Push offenders to live appliances (idempotent, `dry_run`); never run against a real service |

</details>

<details>
<summary><b>Packet capture</b>: optional, off by default</summary>

| Tool | Description |
|---|---|
| `pcap_extract` | **One attacker's packets as a single file** for Wireshark, or replay through Suricata/Zeek |
| `pcap_status` | Running? Disk used? If not running, the actual reason plus the fix |
| `pcap_files` | Ring contents and how far back the capture reaches |
| `pcap_control` | Start / stop / restart (deploy and stop refresh the filter automatically) |

</details>

**MCP resources:** `honeypot://active` · `alerts://stream` · `honeytoken://triggered` · `stats://dashboard`

**MCP prompts:** `shift_handover` · `investigate_ip` · `honeytoken_tripped` · `hunt_campaigns` · `deploy_deception` · `weekly_report`. Each tells the model that captured text was written by an attacker and that destructive actions need confirmation.

Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) and a title, so a client can auto-approve reads and prompt on deletes. Classification lives in one table (`tool_hints.py`); a tool not in it cannot register.

---

## SIEM integration

`alert_subscribe(url=..., format=...)` picks the body shape and auth scheme. `hmac_secret` carries whatever credential that format needs:

| `format` | Body | `hmac_secret` is |
|---|---|---|
| `json` (default) | native JSON envelope | HMAC key, sent as `X-HoneyPot-Signature` |
| `splunk_hec` | HEC `{time, host, sourcetype, event}` | HEC token, `Authorization: Splunk` |
| `elastic_ecs` | ECS document, raw payload in `event.original` | API key, `Authorization: ApiKey` |
| `cef` | ArcSight CEF line (QRadar-compatible) | n/a |
| `syslog` | RFC 5424; `udp://host:514` or `tcp://host:514` | n/a |
| `loki` | Loki push API, stringified-ns timestamps | `base64(userid:token)`, `Basic` |
| `datadog` | Logs API v2 list | API key, `DD-API-KEY` |

```text
> alert_subscribe(
    url="https://splunk.example.com:8088/services/collector/event",
    label="splunk-prod", severity_threshold="medium",
    hmac_secret="<your-HEC-token>", format="splunk_hec"
  )
```

**Slack, Teams and email are first-class formats**: severity-coloured, with captured credentials, command or exploit category up front and honeytoken trips called out.

```
> alert_subscribe(url="https://hooks.slack.com/services/...",
                  label="soc-slack", format="slack", severity_threshold="high")

> alert_subscribe(url="smtp://user:pw@smtp.example.com:587/?from=hp@example.com&to=soc@example.com",
                  label="soc-mail", format="email", severity_threshold="critical")
```

These three are **coalesced**: the same (event_type, source_ip) notifies at most once per `NOTIFY_THROTTLE_SECONDS` (default 300), with the suppressed count carried on the next message. CRITICAL always goes through. For Discord / PagerDuty / SOAR use the default `json` format; `hmac_secret=""` generates and returns a 32-byte signing secret. Check delivery health with `alert_subscriptions_list`.

---

## Packet capture (optional)

Payloads capture what the engines *understood*; carving a dropper's second stage, replaying traffic through Suricata or Zeek, or handing IR an artefact needs the wire bytes.

```bash
PCAP_ENABLED=true
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)   # or run as root
```

```
> pcap_status                                  # running? why not? disk used?
> pcap_extract source_ip=203.0.113.44          # that attacker's packets, as one file
> pcap_files                                   # how far back the ring reaches
```

The capture filter is built from the deployed honeypot ports (your own admin SSH is never recorded) and refreshes on deploy/stop. Disk is bounded: `PCAP_FILE_MB × PCAP_FILES` is a ceiling tcpdump enforces itself.

---

## Cloud honeytokens (optional)

Generated AWS/Azure/GCP credentials fire only if your cloud audit logs reach the canary server's HMAC-signed `/cloud-event` endpoint. Forwarders ship under [`examples/cloud-forwarders/`](examples/cloud-forwarders/): AWS (Lambda + Terraform + EventBridge), Azure (Function App + Bicep), GCP (Cloud Function + Log Sink).

```bash
# .env
CLOUD_EVENT_HMAC_SECRET=$(openssl rand -hex 32)
```

Without a forwarder these are believable decoys with no callback ([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md)).

---

## Development

```bash
uv run pytest tests/unit/ -v
uv run ruff check src/ tests/
uv run mypy src/
```

**PostgreSQL:** `pip install -e ".[postgres]"` and `DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/honeypot`. CI runs the whole suite against a real PostgreSQL on every push.

Schema changes are Alembic-managed and apply at startup: `uv run alembic revision --autogenerate -m "what changed"` (review before committing).

```
src/honeypot_mcp/
├── server.py            FastMCP app, lifespan, transports, MCP resources
├── canary.py            Callback server: canary URLs, PDF trackers, /cloud-event
├── webhooks.py          SIEM + Slack/Teams/email delivery worker (HMAC, retries, coalescing)
├── pcap.py              Optional tcpdump ring buffer + per-attacker extract
├── suppression.py       Drop / rate-limit rule engine
├── credential_match.py  Planted-credential cross-reference (auto-CRITICAL)
├── credential_verify.py Hashed-auth verification (MySQL scramble, VNC DES)
├── flood_guard.py       Per (source, event type) storage cap
├── watchdog.py          Health checks + opt-in retention sweep
├── reconcile.py         Re-establishes RUNNING honeypots after a restart
├── engines/             Honeypot engines (plugin ABC: HoneypotEngine)
├── tokens/              Honeytoken providers (plugin ABC: HoneytokenProvider)
├── storage/             Models, async DB layer, batched event buffer, rollups
├── intel/               VirusTotal, AbuseIPDB, GeoIP, MITRE, optional GreyNoise / abuse.ch / OTX / InternetDB
├── analysis/            Correlator, profiler, Jinja2 reporter
└── tools/               MCP tool modules
```

Adding an engine or token type is a subclass plus a registry line; [CLAUDE.md](CLAUDE.md) documents both plugin patterns, the event pipeline and the persona systems.

---

## What this is and isn't

**Good fit:** SOC research and training labs, internal tripwire deception, small-to-medium alert pipelines, collecting internet-scale automated attack traffic on a public IP.

**Not a fit without more work:** fooling a skilled human probing by hand. SSH is Cowrie and high-fidelity; the custom engines are detection-focused, so an expert can eventually fingerprint them. For fidelity across more protocols see [T-Pot](https://github.com/telekom-security/tpotce), [OpenCanary](https://github.com/thinkst/opencanary) or [Thinkst Canary](https://canary.tools/).

**Not verified:** GreyNoise enrichment and the pfSense, Cloudflare and AWS WAF push tools were never run against real services.

Full rundown: [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go privately through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
