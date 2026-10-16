# Reference

The detailed product reference for HoneyPot MCP: what it can do, how to install and run it, every MCP tool, and how alerts leave the system. The [README](../README.md) is the short introduction; architecture and plugin patterns are in [CLAUDE.md](../CLAUDE.md).

## Contents

- [Capabilities](#capabilities)
- [Install](#install)
- [Run it](#run-it)
- [Deploy: catching real traffic](#deploy-catching-real-traffic)
- [MCP tools](#mcp-tools)
- [SIEM and notification delivery](#siem-and-notification-delivery)
- [Packet capture](#packet-capture-optional)
- [Cloud honeytokens](#cloud-honeytokens-optional)
- [Development](#development)
- [What this is and isn't](#what-this-is-and-isnt)

---

## Capabilities

<table>
<tr><td><b>25 protocols</b></td><td>SSH, Telnet (Cowrie), HTTP/S, SMB, RDP, FTP, SMTP, DNS, VNC, MySQL, PostgreSQL, MSSQL, MongoDB, Redis, Elasticsearch, Docker API, Kubernetes API, LDAP, SNMP, Memcached, IMAP, POP3, SIP/VoIP, rsync, NFS. SSH and Telnet run in a Cowrie container (Docker); the other 23 are in-process asyncio engines</td></tr>
<tr><td><b>Past the login</b></td><td>RDP lets a planted credential (or one weak pair) into a desktop session over NLA or plain TLS, with a fake <code>cmd</code>/PowerShell that executes nothing and has no route out; every command, keystroke, click and pasted text is recorded. POP3 and IMAP serve the mailbox the SMTP honeypot filled; HTTP has an admin console. Nothing is ever sent onward</td></tr>
<tr><td><b>Anti-fingerprinting</b></td><td>Per-deploy SSH and HTTP personas (coherent banner, kernel and header bundles), response jitter, per-honeypot self-signed TLS shaped per service, realistic <code>robots.txt</code>, <code>favicon.ico</code> and <code>security.txt</code></td></tr>
<tr><td><b>Honeytokens</b></td><td>AWS, Azure and GCP keys, canary URLs, credential pairs, PDF/DOCX trackers, SSH keys, JWTs, database rows, kubeconfigs, Slack webhooks</td></tr>
<tr><td><b>Credential correlation</b></td><td>Planted credentials auto-match on any honeypot login and escalate to CRITICAL, including MySQL and VNC, where the plaintext never crosses the wire (the engine recomputes the scramble or DES response)</td></tr>
<tr><td><b>Analysis</b></td><td>MITRE ATT&amp;CK mapping, attacker profiling and risk score, SSH session reconstruction, cross-honeypot kill-chain timelines, campaign correlation, XSS-safe HTML and Markdown reports</td></tr>
<tr><td><b>SIEM delivery</b></td><td>JSON (HMAC-signed), Splunk HEC, Elastic ECS, ArcSight CEF, RFC 5424 syslog, Grafana Loki, Datadog; per-subscription severity thresholds and delivery health</td></tr>
<tr><td><b>Human notifications</b></td><td>Slack, Microsoft Teams, email; severity-coloured, credentials up front, coalesced so one scanner cannot bury the channel. CRITICAL is never held back</td></tr>
<tr><td><b>Packet capture</b></td><td>Optional tcpdump ring buffer scoped to the deployed ports; <code>pcap_extract</code> pulls one attacker's packets for Wireshark, Suricata or Zeek. Disk bounded by construction</td></tr>
<tr><td><b>Response</b></td><td>Blocklist push to Cloudflare, pfSense and AWS WAFv2; iptables, fail2ban and CIDR export; STIX 2.1 bundles; AbuseIPDB reporting</td></tr>
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

> `--extra dev` pulls in pytest, ruff and mypy. With a pip install, drop the `uv run` prefix from the commands in this document.

**Optional integrations** each degrade to `{"available": false}` when not configured:

| Variable | Gets you | Cost |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | IP reputation | free |
| `ABUSEIPDB_API_KEY` | Abuse reports and outbound reporting | free, 1k/day |
| `GEOIP_DB_PATH` | Country, city and coordinates on every alert (City DB) | free, registration |
| `GEOIP_ASN_DB_PATH` | Origin AS number and organisation (ASN DB) | free, same account |
| `CANARY_PUBLIC_URL` | Honeytokens that fire from the internet | ngrok or a domain |
| `GREYNOISE_API_KEY` | GreyNoise scanner/crawler classification in `enrich_ip` | free community tier |
| `ABUSECH_AUTH_KEY` | abuse.ch (MalwareBazaar, URLhaus, ThreatFox), `lookup_hash` | free |
| `OTX_API_KEY` | AlienVault OTX pulses an address appears in | free |
| `SHODAN_INTERNETDB_ENABLED=true` | Shodan InternetDB open ports and CPEs (no key) | free |

The last four are off unless set, cached and bounded by one 3 s fan-out deadline. All are tested against stubs of the vendors' published contracts. abuse.ch, OTX and InternetDB were also run against live data (attacker addresses and a captured malware hash); GreyNoise was not run against the live service. `scripts/intel_smoke.py` makes one live call per provider.

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

The networked control plane can deploy honeypots and read everything they capture, so it is **fail-closed**: the server refuses to start on a networked transport unless `MCP_AUTH_TOKEN` (or `MCP_AUTH_TOKENS`) is set, or you opt out with `MCP_ALLOW_UNAUTHENTICATED`.

**Role-based access.** `MCP_AUTH_TOKENS` hands out scoped tokens in three tiers, each a superset of the one before:

| Role | Tools | Can |
|---|---|---|
| `viewer` | 35 | read-only triage, analysis and reports |
| `operator` | +25 | also deploy and stop honeypots, manage honeytokens, acknowledge alerts, run exports and packet capture (everything reversible and contained to this system's data) |
| `admin` | +10 | also prune alerts, push to an external firewall or WAF, manage subscriptions, read the audit log, manage API keys |

[`rbac.py`](../src/honeypot_mcp/rbac.py) lists which tool needs which role; [DEPLOY.md](DEPLOY.md) has the token format.

**Per-person access.** Env-var tokens need a restart to change and carry no identity beyond a role. An admin token can mint per-person API keys live (`api_key_create`, `api_key_revoke`, `api_key_list`), so `audit_log_search` says *who* deployed a honeypot or pruned alerts. Keys take effect within 30 s; the plaintext is shown once.

### Collector (none)

Runs the capture plane (engines, canary callbacks, watchdog, webhook delivery, `/metrics`) with **no control plane**. Nothing can be deployed or queried remotely; events flow to the database and your SIEM. This is what the Docker stack runs.

**Two processes, one database.** The first server to start owns the sensors (an OS file lock beside the SQLite file). A second, such as another chat session, starts read-only: it can query, triage and report, and refuses to deploy or stop. `ping` reports the role.

---

## Deploy: catching real traffic

| Goal | Run it on | Effort |
|---|---|---|
| See the dashboards | your laptop | ~2 min (demo stack in the [README](../README.md)) |
| Catch attacks on **your own network** | a spare box or VM | ~15 min |
| Catch **real internet attack traffic** | a throwaway VPS | ~30 min ([DEPLOY.md](DEPLOY.md)) |

- Before exposing a VPS, run `scripts/preflight.sh`: it checks the control plane, bind addresses, disk, ports and backups, and probes every sensor end to end.
- Harden the host first with [HARDENING.md](HARDENING.md) (default-drop firewall, validating Docker guard, sandboxed units, key-only SSH, moved control ports). The honeypots stay reachable; everything around them does not.
- Prove it works: `scripts/field_test.py` attacks every engine through its public port with real clients and checks the database recorded each one; `field_test_tools.py` exercises all 70 tools at their roles; `field_test_ops.py`, `field_test_injection.py` and `field_test_oracle.py` cover operations, prompt injection and an independent check of the numbers ([FIELD_TEST.md](FIELD_TEST.md)). A quiet sensor is ambiguous (nobody tried, or it is broken); this removes the ambiguity.

**Internal tripwire.** Put honeypots on ports nothing legitimate uses; anything on your LAN that connects is by definition unexpected. Plant credential tokens and canary URLs on real file shares so lateral movement trips them too.

**Public internet.** Use a dedicated throwaway host, move your admin SSH off port 22 first, and never reuse production keys. Scanners arrive within minutes.

**Analysing a backup offline.** `ANALYSIS_MODE=true` opens a database without starting any sensor, capture, canary, watchdog or notification. Everything done in the [results](RESULTS.md) is available as MCP tools there: `run_analysis` for the whole post-run workflow, `attack_patterns` and `bait_trips` for what attackers did, `pcap_analyze` for capture files, `sql_query` for anything else, and `grafana_start` for dashboards. `scripts/analyze_backup.py <backup-dir|db>` copies a backup, runs the server in that mode over real MCP stdio and calls `run_analysis` ([DEPLOY.md](DEPLOY.md), step 13). For a live database, `scripts/attack_report.py --days 30 --format markdown` writes campaign statistics.

---

## MCP tools

78 tools in three roles (39 viewer, 26 operator, 13 admin; see [Run it](#run-it)). Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) and a title, so a client can auto-approve reads and prompt on deletes. Classification lives in one table (`tool_hints.py`); a tool not in it cannot register. Roles live in [`rbac.py`](../src/honeypot_mcp/rbac.py), and a test fails the build if a registered tool has no role.

### Honeypots and deception planning

| Tool | Description |
|---|---|
| `deception_plan` | **Describe an environment, get a coherent deployment plan**: conflict-free ports, consistent identities, tokens tied to sensors that can detect them |
| `deception_deploy_plan` | Bring a plan up atomically, rolling back everything on failure |
| `deception_coverage` | What the live deployment detects per ATT&CK tactic, and the ranked blind spots |
| `deception_profiles` | Environment profiles (a Windows domain, a Linux web app, a container platform) and every deployable sensor type; call before `deception_plan` |
| `soc_brief` | Shift handover: what needs a human, separated from the background radiation |
| `honeypot_deploy` | Deploy any of the 25 engine types |
| `honeypot_stop` | Stop one, several by name, or every honeypot matching a type or status filter |
| `honeypot_list` / `honeypot_status` | List all / detail and recent events for one |
| `honeypot_pause` / `honeypot_resume` | Lifecycle control |
| `honeypot_configure` / `honeypot_clone` / `honeypot_logs` / `honeypot_templates` | Config, cloning, raw logs, profiles |
| `honeypot_health` | Probe ports and containers; catches silent deaths |
| `honeypot_self_test` | End-to-end pipeline check: synthetic probe, alert in DB |

### Honeytokens

| Tool | Description |
|---|---|
| `honeytoken_create` | Create any token type |
| `honeytoken_generate_aws` / `honeytoken_generate_credentials` | Fake AWS key pair / username-password sets |
| `honeytoken_embed_file` | PDF/DOCX with an embedded canary tracker |
| `honeytoken_list` / `honeytoken_status` / `honeytoken_revoke` / `honeytoken_export` | Manage and format for planting |
| `honeytoken_rotate` | Replace a token's secret while keeping its identity and history |

### Alerts

| Tool | Description |
|---|---|
| `alerts_recent` | Triage by time window, severity, IP or honeypot; a compact digest per alert |
| `alerts_get` | Full captured payload for one alert |
| `alerts_search` | Find alerts by payload content: a command, username, path, User-Agent or hash |
| `alerts_stats` | Totals by severity, top attacker IPs, top event types, optionally windowed |
| `alerts_acknowledge` | Triage in bulk with a disposition (true/false positive, benign), note and analyst |
| `alerts_export` / `alerts_prune` | Write JSON/CSV to disk / retention (prune archives first and cancels the delete if the archive fails) |
| `audit_log_search` | Review every state-changing action the control plane took |

### Analysis

| Tool | Description |
|---|---|
| `enrich_ip` | VirusTotal, AbuseIPDB and GeoIP, plus GreyNoise, abuse.ch, OTX and Shodan InternetDB when configured; parallel and cached |
| `analyze_attacker` / `analyze_session` / `analyze_attacker_journey` | Profile and risk score / Cowrie session reconstruction / cross-honeypot ATT&CK timeline (exact totals, bounded sample; safe on an attacker with 100k+ events) |
| `fingerprint_clusters` | Group sources by SSH client fingerprint (HASSH); the same tooling behind many IPs is one operator |
| `analyze_campaign` / `map_ttps` / `threat_timeline` | Campaign correlation, MITRE mapping, chronological timeline |
| `generate_report` | Write an XSS-safe HTML or Markdown report to disk |
| `export_blocklist` / `export_stix` | Write an iptables, fail2ban or CIDR list, or a STIX 2.1 bundle, to disk |
| `report_ip_abuse` | Submit an attacker IP to AbuseIPDB |
| `attack_summary` / `attack_navigator_layer` | Exact totals by tactic and technique for a window / an ATT&CK Navigator layer scored with the same counts |
| `extract_iocs` / `lookup_hash` | Distinct URLs, hosts and file hashes from payloads / MalwareBazaar lookup of a hash |
| `sql_query` | One read-only `SELECT` over `alerts`, `alert_rollups` and `honeypots` (secret tables refused, 1,000 rows, `SQL_QUERY_TIMEOUT_SECONDS`, default 15, up to 300); also the **Query** box on Grafana dashboard 04. Whole-run questions over millions of rows belong in `attack_patterns` or `alert_rollups` |
| `attack_patterns` | **What attackers actually did, without SQL.** `kind` = `credentials` (top pairs, usernames, passwords, accepted vs refused, per service), `commands` (classified by shape: shell-menu words, writable-directory probes, download chains with staging hosts, fingerprint checks, execution-capability probes), `files` (by hash, with *written by the session* separated from *fetched from the network*), `clients` (SSH versions and HASSH families, shared-fingerprint clusters), `sip_dialling` (dial-prefix cycling toward each destination, number masked), `http`, `concentration` (share held by the busiest sources, the long tail, per-day volume). Planted honeytoken passwords are masked, including inside commands |
| `bait_trips` | **Who used the bait, and what they did first.** For each tripped honeytoken: creation time, delay to the first trip, each source's earlier contact, decoy fetches and how many seconds before the trip, user-agent rotation, commands, replays on other services, and the sources that reached the bait with no earlier contact. Never returns token secrets |
| `ping` | Server role (owner or read-only) and liveness |

### Integrations, suppression and access

| Tool | Description |
|---|---|
| `alert_subscribe` / `alert_unsubscribe` / `alert_subscriptions_list` | SIEM, Slack, Teams and email delivery with health stats |
| `suppression_add` / `suppression_remove` / `suppression_list` | Drop or rate-limit noise (exact IP, CIDR or event-type glob) |
| `suppression_load_preset` / `suppression_list_presets` | Bundled presets: shodan, censys, internal-rfc1918 |
| `blocklist_push_cloudflare` / `blocklist_push_pfsense` / `blocklist_push_aws_waf` | Push offenders to live appliances (idempotent, `dry_run`); tested against stubs of the vendors' contracts, not run against a real service |
| `api_key_create` / `api_key_revoke` / `api_key_list` | Live-provisioned per-person keys with a role and label |

### Packet capture (optional, off by default)

| Tool | Description |
|---|---|
| `pcap_extract` | **One attacker's packets as a single file** for Wireshark, or replay through Suricata or Zeek |
| `pcap_status` | Running? Disk used? If not running, the actual reason plus the fix |
| `pcap_files` | Ring files and written extracts (`kind`), sizes, and how far back the ring reaches |
| `pcap_analyze` | **Read a capture back**: protocol and conversation digest, SIP/HTTP/DNS/SSH/TLS decoding, credentials, payload samples; works on extracts in `REPORTS_DIR` with capture off |
| `pcap_control` | Start, stop or restart (deploy and stop refresh the filter automatically) |

### Dashboards and backups

| Tool | Description |
|---|---|
| `grafana_start` | **Put the dashboards on your data.** Runs a pinned Grafana container on `127.0.0.1` only, with the five dashboards and a read-only SQLite datasource over the server's database (a private directory holding only the database files, hardlinked, not copied). Returns the URL, the path of a generated admin-password file (never the password) and whether the datasource answers. Admin role: Grafana can read every table. Works on a live server and in analysis mode |
| `grafana_status` / `grafana_stop` | Is it running, where, serving which database / stop and remove only the container this server started, plus its private files |
| `database_backup` | Verified SQLite backup: online backup API (safe under WAL), integrity check, free-space check, 0600 file plus `MANIFEST.json` with alert count, sources, window and checksum, inside `BACKUP_DIR`. Admin role. PostgreSQL: use `pg_dump` |
| `run_analysis` | The post-run workflow as one call: headline numbers, ATT&CK by tactic, the busiest sources' journeys, campaigns, SSH-client clusters, coverage and the report, STIX and blocklist exports, with `analysis-summary.md` written to `REPORTS_DIR`. A failing part is reported and the rest still lands |

**MCP resources:** `honeypot://active` · `alerts://stream` · `honeytoken://triggered` · `stats://dashboard`

**MCP prompts:** `shift_handover` · `investigate_ip` · `honeytoken_tripped` · `hunt_campaigns` · `deploy_deception` · `weekly_report`. Each tells the model that captured text was written by an attacker and that destructive actions need confirmation.

---

## SIEM and notification delivery

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

These three are **coalesced**: the same (event_type, source_ip) notifies at most once per `NOTIFY_THROTTLE_SECONDS` (default 300), with the suppressed count carried on the next message. CRITICAL always goes through. For Discord, PagerDuty or SOAR use the default `json` format; `hmac_secret=""` generates and returns a 32-byte signing secret. Check delivery health with `alert_subscriptions_list`.

---

## Packet capture (optional)

Payloads capture what the engines *understood*; carving a dropper's second stage, replaying traffic through Suricata or Zeek, or handing incident response an artefact needs the wire bytes.

```bash
PCAP_ENABLED=true
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)   # or run as root
```

```
> pcap_status                                  # running? why not? disk used?
> pcap_extract source_ip=203.0.113.44          # that attacker's packets, as one file
> pcap_files                                   # ring files and the extracts already written, with sizes
> pcap_analyze path=pcap-203.0.113.44-<stamp>.pcap   # decode an extract: protocols, SIP/HTTP/DNS/SSH detail, credentials
```

The capture filter is built from the deployed honeypot ports (your own admin SSH is never recorded) and refreshes on deploy and stop. Disk is bounded: `PCAP_FILE_MB × PCAP_FILES` is a ceiling tcpdump enforces itself.

`pcap_analyze` reads a capture file back as a bounded digest, in pure Python with no Wireshark dependency. It accepts classic pcap and pcapng (Ethernet, Linux cooked, raw IP and loopback framing; IPv4 and IPv6) and reports the capture window, per-port and per-conversation totals, TCP scan indicators, and what each protocol said: SIP methods, user agents and dialled numbers grouped by dial prefix, HTTP requests, DNS names, cleartext Telnet/FTP/POP3/IMAP/SMTP/Redis commands and credentials, SSH identification strings with HASSH, TLS ClientHello with SNI and JA3, plus a few clipped payload samples. It only opens files inside `REPORTS_DIR` or `PCAP_DIR` (no `..`, no symlink escapes), refuses files above `PCAP_ANALYZE_MAX_FILE_MB` (512), stops at `PCAP_ANALYZE_MAX_PACKETS` (2,000,000) and says so when it truncates. It works on a backup with `ANALYSIS_MODE=true`: put the extracts you want analysed in `REPORTS_DIR`.

---

## Cloud honeytokens (optional)

Generated AWS, Azure and GCP credentials fire only if your cloud audit logs reach the canary server's HMAC-signed `/cloud-event` endpoint. Forwarders ship under [`examples/cloud-forwarders/`](../examples/cloud-forwarders/): AWS (Lambda, Terraform and EventBridge), Azure (Function App and Bicep), GCP (Cloud Function and Log Sink).

```bash
# .env
CLOUD_EVENT_HMAC_SECRET=$(openssl rand -hex 32)
```

Without a forwarder these are believable decoys with no callback ([KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md)).

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
├── rbac.py              Roles and per-tool access
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
├── deception/           Engine capability registry, planner, coverage map
├── storage/             Models, async DB layer, batched event buffer, rollups
├── intel/               VirusTotal, AbuseIPDB, GeoIP, MITRE, optional GreyNoise / abuse.ch / OTX / InternetDB
├── analysis/            Correlator, profiler, Jinja2 reporter
├── console/             Read-only operations console
└── tools/               MCP tool modules
```

Adding an engine or token type is a subclass plus a registry line; [CLAUDE.md](../CLAUDE.md) documents both plugin patterns, the event pipeline and the persona systems. See also [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## What this is and isn't

**Good fit:** SOC research and training labs, internal tripwire deception, small-to-medium alert pipelines, and collecting internet-scale automated attack traffic on a public IP.

**Not a fit without more work:** fooling a skilled human probing by hand. SSH is Cowrie and high-fidelity; the custom engines are detection-focused, so an expert can eventually fingerprint them. For fidelity across more protocols see [T-Pot](https://github.com/telekom-security/tpotce), [OpenCanary](https://github.com/thinkst/opencanary) or [Thinkst Canary](https://canary.tools/).

**Not verified:** GreyNoise enrichment and the pfSense, Cloudflare and AWS WAF push tools were not run against real services.

Full rundown: [KNOWN_LIMITATIONS.md](../KNOWN_LIMITATIONS.md). Security issues go privately through [SECURITY.md](../SECURITY.md).
