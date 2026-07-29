# Changelog

Reverse-chronological summary of meaningful changes. Not a release log —
the project isn't on a version cadence — but each section represents a
distinct iteration with a coherent goal.

## Operations console — the product gets a face

Everything visual belonged to Grafana: a third-party tool with generic styling,
a provisioning step, and a login. The product itself had no interface, which is
a strange gap for something whose whole job is to show you what is attacking
you. `console/` closes it — a read-only dashboard served by the same process as
the honeypots, on `127.0.0.1:8090` by default, no extra container and nothing to
provision.

It answers the three questions someone walking up to a screen actually has:
*is everything up, is anything on fire, what just happened.* Live attack feed
with the captured credentials and paths inline, sensor health, volume by
severity over any window, top attackers and origins. It refreshes every five
seconds and stops polling when the tab is hidden.

Design decisions worth recording, because they were forced rather than chosen:

- **Read-only by construction.** The page has no authentication, so it registers
  GET routes only and a test asserts no other method ever appears. Deploying and
  stopping honeypots stays on the MCP control plane.
- **Two series, not four severity bands.** A green→amber→orange→red ramp fails
  both the colour-vision and normal-vision separation floors however it is
  stepped — adjacent warm hues are simply not distinguishable as stacked marks.
  The chart splits routine (low+medium) from serious (high+critical), which is
  also the only split that drives a decision. Per-event severity is carried by a
  text label with colour as reinforcement, never colour alone.
- **The feed ships digests, not payloads.** At a five-second poll, full captures
  would move megabytes a minute to show the viewer nothing extra.
- **Port 8090, not 8080** — 8080 is `default_http_port` and would collide with
  the first HTTP honeypot deployed.

Grafana keeps the historical dashboards and the geo map. 8 new tests (404 total).

## Analysis-quality pass — ATT&CK mapping and risk scoring

Previous passes asked whether features existed and whether the wire protocols
were convincing. This one asks whether the analyst-facing *outputs* are any
good. Two were not, in ways that matter more than a missing feature would:
being wrong in front of a SOC analyst costs more credibility than being absent.

- **ATT&CK tactics were factually wrong in places.** Brute Force (T1110) was
  filed under Initial Access for SSH/FTP/RDP while the identical technique was
  filed under Credential Access three entries later. T1110 is Credential Access
  in ATT&CK Enterprise, for every protocol. Analysts know this cold.
- **Half the platform's headline captures mapped to nothing.** The Redis
  unauth-RCE dropper chain, MongoDB ransom notes and `dropDatabase`, DNS
  tunnelling, MySQL `INTO OUTFILE` webshell drops, PostgreSQL
  `COPY … FROM PROGRAM`, SMTP open relay, Elasticsearch data exfil and RDP
  handshakes all returned no technique — meaning they were invisible in the
  ATT&CK dashboard and the kill-chain timeline the README advertises. The
  mapping table is now aligned to the event types the engines actually emit,
  covering Impact, Execution, Persistence, Lateral Movement and Collection,
  which had almost no representation before. `smb_exploit_attempt` also
  matched the brute-force rule (it contains "attempt"), inflating Credential
  Access while hiding the Lateral Movement finding; a negative lookahead fixes
  it.
- **The risk score could not flag a serious attacker without API keys.**
  VirusTotal and AbuseIPDB are optional integrations but supplied 60 of the
  ~90 attainable points, so on a default install an attacker who ran a full
  RCE chain against a decoy *and* tripped a planted credential topped out at
  30/100 — MEDIUM. That is backwards for a deception platform: a first-hand
  capture is stronger evidence than a third-party reputation lookup. Scoring is
  now weighted toward observed behaviour, external intel corroborates rather
  than carries it, and a triggered honeytoken — the highest-fidelity signal the
  platform produces, previously worth nothing beyond its severity — dominates.
  Sustained volume stays weighted low so the ranking is not led by whoever is
  noisiest. Measured on the same scenarios: an RCE chain now scores 52/HIGH
  with no API keys (was 30/MEDIUM at best), a honeytoken trigger 64/HIGH, and
  the two together 100/CRITICAL, while a 200-event scanner sweep stays LOW.

22 new tests pin both, written as ordering and band-reachability assertions so
the weights can be retuned without churn (396 total).

Also verified and left alone, having found no defect: all 11 honeytoken types
produce valid artifacts (the JWT decodes with matching `jti`, the kubeconfig's
`current-context` and user references resolve, the GCP service account carries
a real parseable RSA-2048 key); CEF and RFC 5424 syslog resist log-injection
via attacker-controlled payload values; ECS carries the required fields.

## SOC workflow pass — triage, audit trail, and the rest of the tool sweep

Audited all 49 MCP tools for the defect classes the previous pass turned up,
then closed the gaps that stop a real analyst using this across a shift.

- **The remaining context blowouts.** The response-shaping rule had only been
  applied to `alerts_export`. Measured on 300 alerts from 250 IPs,
  `export_stix` returned **138 KB inline** (~35k tokens), `export_blocklist`
  13 KB and `generate_report` 10 KB — all destined for a firewall, a TIP or a
  browser, and all scaling with attacker count. All three now write via
  `_format.write_artifact()` and return the path plus headline figures. The
  `.gitignore` had expected `reports/*.html` and `reports/*.md` since the
  beginning; the file-based design was intended and simply never implemented.
- **Triage that survives a scanner sweep.** `alerts_acknowledge` took a single
  id and set a boolean, so clearing a few hundred alerts meant a few hundred
  tool calls, and nothing recorded *what was concluded*. It now takes explicit
  ids or a filter (`source_ip`/`event_type`/`severity`/`since_hours`) and
  records a `disposition` (true_positive / false_positive / benign /
  duplicate), a note, and the analyst. `benign` is kept distinct from
  `false_positive` — one means the detection was wrong, the other that it fired
  correctly on authorised activity, and conflating them makes tuning metrics
  meaningless. Selection SELECTs before it UPDATEs so the caller learns the
  match count and whether the `max_alerts` cap truncated it; a call with
  neither ids nor filters is refused rather than clearing the board.
- **A control-plane audit trail.** Nothing recorded that a honeypot was stopped
  or that `alerts_prune` had deleted months of evidence. New `audit_log` table,
  `tools/_audit.py`, and an `audit_log_search` tool covering
  `honeypot_deploy` (success and failure), `honeypot_stop`,
  `honeytoken_revoke`, `alerts_prune` and `alerts_acknowledge`. This matters
  more here than in a conventional tool because the control plane is driven by
  a language model: "what did the agent actually do?" needs an answer.
  Auditing never breaks the action it records, and credential-shaped arguments
  are redacted before they are persisted.
- **Smaller sweep findings.** `generate_report` took `format: str` (no enum
  guidance for the model) and had no time window, so "report on the last 24
  hours" was inexpressible; it now takes a `Literal` and `since_hours`, and
  validates its `ip`. `honeypot_logs` had an uncapped `lines`.

Migration `0011_add_triage_and_audit_log`, idempotent per the project
convention and verified against both a fresh database and a simulated pre-0011
one with existing rows preserved. 32 new tests (374 total).

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
