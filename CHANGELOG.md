# Changelog

Reverse-chronological summary of meaningful changes. Not a release log —
the project isn't on a version cadence — but each section represents a
distinct iteration with a coherent goal.

## Protocol-fidelity audit — real clients and `nmap -sV`

Pointed the actual client software (redis-py, pymongo, psycopg) and
`nmap -sV --version-intensity 9` at every in-process engine. Before this pass
nmap could not identify five of them; an engine a scanner fingerprints stops
receiving the attack traffic it exists to collect, so these were detection
failures rather than cosmetic ones. All findings are pinned by
`tests/unit/test_protocol_fidelity.py`, which quotes the nmap signature each
check encodes.

- **The persona system was defeated by one malformed request.** aiohttp rejects
  protocol-level errors inside `handle_error`, before any middleware runs, so
  those `400`s carried `Server: Python/3.x aiohttp/3.y.z` no matter which
  Apache/IIS/nginx persona the HTTP honeypot was wearing. The same banner
  appeared on the *internet-facing* canary callback server, which exists to
  return a bare `200 OK` precisely so token callbacks can't be fingerprinted,
  and on Elasticsearch, whose flawless ES 8.11.3 JSON was served under an
  aiohttp banner nmap duly reported. New `http_identity.py` pins the header on
  application responses and neutralises aiohttp's default for the error path
  that middleware cannot reach.
- **Redis rejected `HELLO`** while advertising 7.0.5 — a version that requires
  it. Every modern client (redis-py, ioredis, go-redis) opens with `HELLO`, so
  connections failed at the handshake and no attack was ever captured. Now
  answers both RESP2 and RESP3, captures credentials passed via `HELLO AUTH`,
  and hands out increasing per-connection ids.
- **MSSQL's PRELOGIN was structurally wrong**: 2 of the 4 options real SQL
  Server always sends, yielding a 0x1a-byte packet when every signature expects
  0x25–0x2b. Now identified as "Microsoft SQL Server 2019 15.00.2000".
- **PostgreSQL closed silently on malformed input.** The FATAL ErrorResponse it
  should send is exactly how scanners identify PostgreSQL; error frames now also
  carry the `V` field modern servers include.
- **MongoDB claimed 5.0.14 while negotiating wire version 8** (that's 4.0),
  answered `serverStatus` with a bare `{ok: 1.0}`, and reported `localTime: 0`
  (1970-01-01 in any client). Now self-consistent and identified as
  "MongoDB 5.0.14".
- **SMB did not echo the client's TID/PID/UID/MID** — a protocol requirement
  for request/response correlation, not just a fingerprint — always selected
  dialect index 0 (the client's first offer, typically the 1987-era "PC NETWORK
  PROGRAM 1.0"), and sent `SystemTime: 0` (1601-01-01). Now identified as
  microsoft-ds.

Residual, documented in KNOWN_LIMITATIONS.md: malformed requests to an HTTP
honeypot answer with a generic `nginx` banner rather than the deployed persona,
because that path is unreachable from application code. No implementation
detail leaks, and scanner version detection still keys off the persona.

## Tool-layer audit — response shaping, time windows, validation

The MCP tool layer is this project's entire user interface, so it got the same
scrutiny as the engines. Findings and fixes:

- **Triage calls no longer flood the context window.** `alerts_recent` returned
  each alert's complete payload for up to 200 alerts. Because the HTTP engine
  captures every request header plus up to 64 KB of base64 body per event, one
  call could return ~2 MB — enough to consume a context in a single turn. List
  tools now return a `digest` of the fields analysts triage on (credentials
  tried, path, command, exploit category, lifted geo/VT/abuse verdicts);
  `include_payload=True` opts back into the full capture. Measured against the
  live demo stack, a 5-alert triage call is now ~1 KB. New `tools/_format.py`
  holds `digest_payload` / `truncate_payload` / `validate_ip`.
- **`alerts_export` no longer returns bulk content inline** — at its 5,000-alert
  ceiling that was tens of megabytes into the conversation. It now writes to
  `reports_dir` (new setting) and returns the path, byte count, and a 5-row
  preview, with added `since_hours` / `severity` filters.
- **Time windows everywhere they were missing.** `alerts_recent`, `alerts_stats`
  and `alerts_search` gained `since_hours`. "Anything critical in the last
  hour?" was previously inexpressible despite being the README's own example
  query — only `threat_timeline` had a time filter.
- **Descriptions that undersold the tools.** `alerts_search` was documented as
  matching "IP addresses and event types" when it also substring-matches
  payloads — so a model reading the description would never reach for it to
  find an alert by captured command or username, its best use. Rewrote that
  plus the thin `alerts_stats` / `honeypot_templates` /
  `suppression_list_presets` descriptions.
- **List responses report their own truncation.** List tools now return
  `{count, alerts: [...]}` with a `note` when results hit the limit, so a
  capped list is never mistaken for the complete picture.
- **Input validation with actionable errors.** A malformed IP previously
  returned "no activity found", which reads as a clean bill of health rather
  than a bad request; `enrich_ip` / `analyze_attacker` /
  `analyze_attacker_journey` now reject it explicitly. `honeypot_deploy`
  validates the port range and names the honeypot already holding a port
  instead of surfacing a bind error from inside the engine.
- **Composite alert indexes** (`0010_add_alert_query_indexes`) for the
  time-window access pattern the above makes primary. At 500k rows:
  severity+window 30.7 ms → 5.4 ms, ip+window 23.6 ms → 0.04 ms. `severity`
  previously had no index at all despite being filterable.
- **19 new tests** covering the alert tool surface, which previously had **zero**
  test coverage — a breaking change to its return shape passed the whole suite
  silently before this.

## Front-door + demo-stack repair pass

- **Collector mode (`MCP_TRANSPORT=none`)** — runs the full capture plane
  (engines, canary callbacks, watchdog, webhook delivery, `/metrics`) with no
  MCP control plane. This fixes the demo stack's `honeypot-mcp` container,
  which previously restart-looped forever: it ran the default stdio transport
  with no stdin attached, so FastMCP read EOF and exited immediately. Since
  collector mode exposes no control plane, the fail-closed auth gate treats it
  like stdio. Covered by three new tests (config validation, auth gate, and a
  lifespan-entry + SIGINT-shutdown test for `_run_collector`).
- **socket-proxy crash-loop fixed** — `read_only: true` prevented the
  tecnativa entrypoint from rendering `haproxy.cfg` at boot. Dropped the
  read-only rootfs (the sidecar's real hardening is its restricted API surface
  + `no-new-privileges`) and documented the reasoning in the compose file.
- **Grafana dashboards actually render** — every SQLite-backed panel showed
  "No data" because targets carried only `queryText`; the frser plugin's
  frontend interpolates from `rawQueryText`, so the browser sent empty
  queries. Added `rawQueryText` to all 12 targets. The engine pie chart and
  MITRE tactic bars also collapsed to a single value — added `rowsToFields`
  transformations so each row becomes a series.
- **Reproducible screenshots** — `scripts/capture_screenshots.sh` +
  `docker/docker-compose.screenshots.yml` (grafana-image-renderer sidecar)
  regenerate `docs/screenshots/*.png` from the live stack; the README now
  embeds them. The seed-freshness check counts events inside the render
  window, not table rows, so a stale DB reseeds instead of rendering empty.
- **`scripts/attack_report.py`** — read-only campaign statistics from a live
  DB (volume, unique IPs, countries, ASNs, credential pairs, exploit
  categories, per-engine counts) in text / Markdown / JSON, with
  `--anonymise-ips`. Turns a VPS collection run into publishable numbers.
- **MaxMind EULA compliance** — `config/GeoLite2-ASN.mmdb` was committed;
  GeoLite2 forbids redistribution. Untracked it and widened the ignore rule
  to `config/*.mmdb` so no .mmdb can slip in again.
- **README rewritten** — leads with the rendered dashboards, a mermaid
  diagram of the ingestion pipeline, and the three-mode run matrix
  (stdio / http / none); tool tables collapsed behind `<details>`.

## Security + ops hardening pass

- **Migration chain idempotency** — `ALTER TABLE` migrations now guard
  themselves with `inspect().get_columns(...)` so fresh boots no longer hit
  the `create_all` fallback path. New regression test
  `test_init_db_does_not_log_alembic_fallback_warning` fails loudly if the
  chain breaks again, keeping the signal visible instead of buried inside
  the fallback noise.
- **Doc accuracy** — `CLAUDE.md`, `KNOWN_LIMITATIONS.md`, and `README.md`
  rewritten to match what actually ships today (no more "doesn't ship
  integrations out of the box" claim now that Loki / Datadog / cloud
  forwarders / blocklist push are all in).

## High-ROI gap closure

- **Loki + Datadog SIEM formats** in addition to the existing JSON / Splunk
  HEC / Elastic ECS / CEF / Syslog renderers. Seven SIEM landing zones
  covered, configurable via `alert_subscribe(format=...)`.
- **Cloud audit-log forwarders** — ready-to-deploy Lambda / Azure Function /
  GCP Cloud Function ship under `examples/cloud-forwarders/{aws,azure,gcp}/`,
  each with IaC (Terraform / Bicep / gcloud) and a per-cloud README. The
  receiver (`canary.py:_handle_cloud_event`) was already in place; what was
  missing was the operator-side glue.
- **Blocklist push integrations** — three new MCP tools push offender IPs
  straight to Cloudflare custom lists, pfSense firewall aliases, and AWS
  WAFv2 IPSets. All idempotent + `dry_run` support.
- **Deeper RDP capture** — when a client requests SSL or HYBRID/CredSSP,
  the engine now upgrades to TLS and parses the MCS Connect Initial PDU.
  `clientName`, `clientBuild`, keyboard layout, screen resolution, and
  encryption methods land in an `rdp_mcs_handshake` HIGH-severity event
  instead of dying at the X.224 banner.
- **Schema cleanup** — dropped the unused `AttackerProfile.shodan_data`
  column (legacy from removed Shodan integration).

## Initial scope (pre-iteration baseline)

Honeypot engines: SSH (Cowrie-wrapped via Docker), plus in-process asyncio
engines for HTTP, SMTP, FTP, DNS, RDP, MySQL, Redis, Elasticsearch, and VNC.
Persona systems for SSH and HTTP defeat default-fingerprint identification.
Self-signed TLS certs per honeypot for HTTPS / SMTP STARTTLS / RDP NLA.

Honeytoken stack: AWS keys, canary URLs, credential pairs (auto-matched
against incoming SSH/HTTP/FTP/SMTP logins), PDF/DOCX file tokens with
pixel-tracker callbacks, SSH keys (fingerprint-matched), JWTs
(jti-matched), canary email rows (SMTP RCPT TO matched), kubeconfig, Slack
webhooks, Azure service principals, GCP service accounts.

Threat-intel enrichment: VirusTotal v3, AbuseIPDB (with auto-report option),
MaxMind GeoIP — all TTL-cached. MITRE ATT&CK technique mapping with bundled
STIX index. Attacker profiling, SSH session reconstruction, cross-honeypot
attacker journey, campaign correlation.

Platform: XSS-safe HTML and Markdown reports (Jinja2 autoescape), webhook
fan-out with HMAC signing + retries, suppression rules with bundled presets
(Shodan / Censys / RFC1918), blocklist + STIX 2.1 exports, Prometheus
metrics endpoint, Grafana dashboards, watchdog for honeypot health,
end-to-end self-test tool, Alembic-managed schema, FastMCP tool registration.
