# CLAUDE.md

Guidance for Claude Code when working with this repository.

Each section states rules and invariants: what to do, what not to do, and why in one line. The longer
accounts (what broke, what was measured) are in [docs/LESSONS.md](docs/LESSONS.md), organised by topic; read the
matching section there before changing a rule. Product reference: [docs/REFERENCE.md](docs/REFERENCE.md).

## Commands

> Every `uv run X` line below is equivalent to plain `X` if the project was
> installed with `pip install -e ".[dev]"` instead of `uv sync`. `pytest`,
> `alembic`, `ruff`, `mypy`, and the `honeypot-mcp` script are all on PATH
> after a pip install.

```bash
# Install (Python 3.11–3.14)
pip install -e ".[dev]"
# or (note: --extra dev is required for pytest/ruff/mypy — uv sync alone
# only installs runtime deps and pytest will silently fall through to PATH)
uv sync --extra dev

# Run the MCP server
uv run python -m honeypot_mcp.server
# or via the installed script
honeypot-mcp

# Tests (2,896 unit tests covering security-critical paths; about 2 minutes on 4 workers: `-n 4`)
uv run pytest tests/unit/ -n 4 -q
uv run pytest tests/unit/test_tokens.py -v
uv run pytest tests/unit/test_tokens.py::test_aws_key_format
uv run pytest tests/unit/ --cov=src/honeypot_mcp --cov-report=term-missing
# Count: uv run pytest tests/unit --collect-only -q | tail -1

# Lint / format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check
uv run mypy src/ scripts/
```

- Integration tests under `tests/integration/` are Docker-gated (`RUN_DOCKER_TESTS=1`); unit tests cannot catch
  wire-level regressions in Cowrie capture, the firewall, the Docker guard or FreeRDP.
- Launch with `honeypot-mcp` or `python -m honeypot_mcp.server` (it delegates to the canonical module: tools register on
  `honeypot_mcp.server.mcp`, not `__main__.mcp`).
- Tests run on SQLite by default; `TEST_DATABASE_URL=postgresql+asyncpg://...` runs the same suite on PostgreSQL
  (each test gets an empty schema). Test modules must read that variable, never hard-assign a URL, or the CI
  PostgreSQL job silently tests SQLite.

## Architecture

### Event ingestion data path

Engines never write to the DB directly. The path is:

```
Engine (any of the 25 — see deception/capabilities.py)
  → submit_event(PendingEvent)             # storage/event_buffer.py
  → suppression.should_suppress(event)     # in-memory rules; dropped here is gone
  → credential_match / token_matchers      # planted creds, SSH keys, JWTs, DB-row emails → CRITICAL + honeytoken_id
  → flood_guard.admit(event)               # per (source, event type): 600 stored/min, the rest counted into one
                                           # flood_summary per window; CRITICAL and honeytoken hits never dropped
  → EventBuffer queue (unbounded)
  → flusher task (single async task, batches of 50, max 1s wait)
  → DB transaction (Alert + AttackerEvent rows); credential-trigger events mark the Honeytoken TRIGGERED
  → CRITICAL events fire background _enrich_alert_async() (VT + AbuseIPDB + GeoIP merged into Alert.payload)
  → on_flush hook → WebhookDelivery queue (separate worker) → POST to subscribers
```

- `submit_event()` is the ONLY way engines write events. Direct `get_session()` writes from engines bypass
  suppression, flood control and webhook delivery. Canary/token triggers also go through it.
- Each `PendingEvent` carries its own `timestamp` so batched writes keep chronological order.
- `flood_guard` never hides volume: dropped events are counted into a `flood_summary`, and a source that stops
  mid-window still gets its summary. Its state is bounded in memory.
- `attacker_events` holds only honeytoken-linked events.
- The queue is unbounded, so `submit_event` never blocks and nothing is dropped on the way in; commit rate
  (~1,550 events/s on SQLite) is the ceiling. The one loss path is `stop()`, which drains for
  `shutdown_drain_seconds` (default 5) and then discards the rest, logging the count at ERROR. Raise it for
  slow or remote databases. `honeypot_event_queue_depth` (Prometheus) must oscillate around one flush
  interval's traffic; a climbing value means ingest is outrunning the database.
- Transient DB errors are retried, permanent ones are not (`EventBuffer._write_retrying`).
- Auto-enrichment (`_enrich_alert_async`) runs only for globally routable source IPs (`_is_enrichable_ip`),
  fans out VT + AbuseIPDB + GeoIP in parallel, swallows failures (UX, not a guarantee), and merges into
  `payload.enrichment`. `intel/_cache.py` (monotonic TTL dict; VT 30 min, AbuseIPDB 15 min, GeoIP 24 h) caches
  successful responses only; errors and rate limits are never cached.

### MCP tool registration

`server.py` creates the `FastMCP` instance (`mcp`) and the lifespan hook. Tool modules are imported at the
bottom of `server.py`; the import *is* the registration. A new module needs an `import honeypot_mcp.tools.<name>`
line there. `@mcp.tool` returns the original function, so tools are plain async functions in tests.

There are 67 tools. Modules (`src/honeypot_mcp/tools/`):

- `honeypot.py` — deploy, list, status (no name probes every sensor), stop, pause, resume, configure, self_test
- `honeytoken.py` — create (every type; `api_key`/`credential`/`file` take `metadata`), list (`token_id` for one trail), rotate, revoke, export
- `alerts.py` — recent/get/search/stats/acknowledge/export/prune, `audit_log_search`
- `analysis.py` — `enrich_ip`, `report_ip_abuse`, `analyze_*` (attacker, journey, campaign, session), `fingerprint_clusters`, `attack_summary` (also `ip`/`event_types`/`raw_text`), `generate_report` (incl. `format="attack_navigator"`), `export_indicators` (plain/iptables/fail2ban/cidr/stix), `threat_timeline`
- `integrations.py` — subscriptions (webhook/SIEM/Slack/Teams/email), suppression rules and presets (`suppression_list` carries `presets`)
- `deception.py` — `deception_profiles` (also sensor types), `deception_plan`, `deception_deploy_plan`, `deception_coverage`, `soc_brief`
- `pcap.py` — `pcap_files` (also capture status), `pcap_extract`, `pcap_control`, `pcap_analyze` (parser `pcap_analysis.py`: pure Python, bounded, confined to `reports_dir`/`pcap_dir`)
- `detect.py` — `pcap_detect`, `detection_rules_update`: Suricata/Zeek replay in a sandbox container (no network, read-only root, caps dropped, no-new-privileges, non-root, limits, label `honeypot-mcp=detect`, always removed; only the rules update gets a network)
- `samples.py` — `sample_scan`, `sample_collect` (rules in `yara_rules/`): YARA over the mode-000 quarantine without executing anything, joined to the DB by hash; collection goes through the Docker guard's read-only allowlist (`COWRIE_SAMPLE_DIRS`)
- `patterns.py` — `attack_patterns` (credentials, commands, files, clients, sip_dialling, http, concentration), `bait_trips`: indexed, time-budgeted; planted-token passwords are masked
- `ioc.py` (`extract_iocs`, `lookup_hash`), `sql.py` (`sql_query`, read-only), `mapping_audit.py` (see ATT&CK mapping), `api_keys.py` (see RBAC)
- `workflows.py` — `run_analysis` (post-run workflow composing existing tools in-process), `database_backup` (SQLite online backup into `backup_dir`, verified, manifest)
- `grafana.py` — `grafana_start/stop/status`: pinned loopback container, read-only SQLite datasource over a private directory with only the DB files; the password goes to a 0600 file, never returned or audited

Rules:
- **Anything an analyst does by hand with the data must exist as a tool.** If a shell step has no tool, that is a
  missing tool, not a one-off. The point of the project is that a user can reproduce an analysis on their own
  traffic through the MCP interface.
- The vendor firewall pushes (Cloudflare/AWS WAF/pfSense) do not exist and `boto3` is not a dependency: a
  blocklist is produced by `export_indicators` and loaded by the operator.
- Every tool needs an entry in `tool_hints.py` (`hints(name)` raises for an unlisted tool;
  `test_tool_hints.py` pins it): read-only, destructive, idempotent and open-world hints for the client.
- Prompts (`shift_handover`, `investigate_ip`, `honeytoken_tripped`, `hunt_campaigns`, `deploy_deception`,
  `weekly_report`) live in `prompts.py` and must name current tools only.

### Plugin patterns

**Honeypot engines** — subclass `HoneypotEngine` (`engines/base.py`), implement `start`, `stop`, `status`,
`get_logs`; override `health_check(container_id, port)` when a TCP probe is wrong (UDP, Docker). Register in
`engines/__init__.py:get_engine()`. Push events with `submit_event(PendingEvent(honeypot_id=..., source_ip=...,
event_type=..., payload=..., severity=AlertSeverity.X))`. No direct DB sessions in engines.

Adding a honeypot type touches six places: `HoneypotType` (`storage/models.py`), the default port in `config.py`,
the `Literal` and `default_ports` in `tools/honeypot.py`, `get_engine()`, an Alembic migration (`Enum(...)` is a
native PostgreSQL type: `ALTER TYPE … ADD VALUE`, one statement per value; see `0012_add_five_types`) and the
`deception/capabilities.py` entry (`transport` when not TCP: the pcap filter derives from it). A test asserts
the capability registry matches `HoneypotType` exactly.

**Honeytoken providers** — subclass `HoneytokenProvider` (`tokens/base.py`), implement `create` (returns
`(token_value, metadata)`) and `plant_instructions`, register in `tokens/__init__.py`. Registering is not
shipping: the type must also be in `HoneytokenType`, the `Literal` on `honeytoken_create`, a migration, the ATT&CK
mapping in `deception/coverage.py`, and the planner (`deception/planner.py`) when a sensor pairs with it.
`test_honeytoken_create_offers_every_registered_type` asserts the `Literal` equals `HoneytokenType`. **For a
natural-language-driven system the tool signature is the capability surface.**

### Database layer

- `storage/database.py` exposes one context manager, `get_session()`: auto-commit on clean exit, rollback on
  exception; every `async with` is its own transaction.
- SQLite by default (`honeypot_mcp.db`). PostgreSQL: `pip install -e ".[postgres]"` and
  `DATABASE_URL=postgresql+asyncpg://...`; CI runs the suite against a real PostgreSQL.
- **Alembic owns schema** for persistent DBs: `init_db()` runs `alembic upgrade head`; `":memory:"` URLs use
  `create_all`. Add one with `uv run alembic revision --autogenerate -m "..."`; the autogenerated file is a
  starting point, review it. Migrations that add or drop columns guard themselves with `inspect().get_columns(...)`
  so the chain stays idempotent against fresh DBs; `test_init_db_does_not_log_alembic_fallback_warning` asserts
  no fallback warning on boot. Keep revision ids short (`alembic_version.version_num` is `VARCHAR(32)`; SQLite
  ignores it, PostgreSQL enforces it; a test covers this). If Alembic fails, `init_db()` falls back to `create_all()`
  and logs a warning.
- **Statistics read rollups, never the alert table** (`storage/rollups.py`, table `alert_rollups`: counts per hour
  per severity/event type/source/sensor). A `before_flush` hook on `Session` (`rollups.install()`, run when
  `database` is imported) counts every Alert writer in the same transaction, so nobody calls a helper and a
  rollback takes its counts. `rollups.window` takes whole hours from rollups and the two partial edges from alert
  rows (exact to the second); pruning raw alerts does not change lifetime figures. `alerts_stats`, `soc_brief`,
  `honeypot_list`, profiles, journey totals, blocklist/campaign candidates and `/metrics` read it. When adding a
  query over alerts, first ask whether it belongs on rollups. `tests/unit/test_rollups.py` checks every windowed
  statistic against a brute-force count; `tests/unit/test_query_plans.py` pins plans.
- Indexes: `ix_alerts_acked` and `ix_alerts_urgent` are partial (acknowledged rows; CRITICAL/HIGH rows) so triage
  never touches the LOW/MEDIUM flood (untriaged = total minus acknowledged). Two composite indexes
  (`0010_add_alert_query_indexes`) serve severity+window and ip+window. An unindexed filter on a hot path is
  invisible until the DB is large.
- PostgreSQL: `coalesce(x, $3)` in SELECT and `coalesce(x, $5)` in GROUP BY are different expressions; use a
  literal. The in-memory test DB is one shared connection, so the engine disables reset-on-return for `:memory:`
  (see `test_database.py`).
- **Timestamps are aware everywhere** (`storage/models.py:UTCDateTime`: normalises on bind, re-attaches UTC on
  load; stored SQLite string unchanged). A naive `.isoformat()` has no offset and JavaScript reads it as local.
  Renderers over `PendingEvent` are always aware.
- **Pruning archives before it deletes** (`retention.py`, shared by `alerts_prune` and the retention sweep):
  `archive_alerts` streams keyset-paginated chunks to a `.partial` file, renames when complete and returns the
  highest id written; `delete_before` deletes only up to that id, in bounded chunks, one transaction each. A
  failed archive cancels the delete. `archive=False` / `RETENTION_ARCHIVE=false` opts out. Helpers that return
  `{"error": ...}` do not raise: callers must check the result.
- **`honeypot_stop` takes a set** (`name`, `names`, or a `type`/`status` filter; `type="all"` for everything). A
  call with none of them is rejected rather than read as "everything". An unknown name aborts the whole call.
- **`honeytoken_rotate` keeps the thread**: new secret, label/type/settings/`planted_at` carried over, old token
  marked REVOKED but retained, linked by `rotated_from`/`rotated_to`. Provider-generated fields are excluded from
  the carry-over.
- **Triage state**: `acknowledged` plus `disposition` (`true_positive`/`false_positive`/`benign`/`duplicate`),
  `triage_note`, `triaged_by`, `triaged_at`. `benign` (fired correctly on authorised activity) is distinct from
  `false_positive` (detection wrong). `alerts_acknowledge` takes `alert_ids` or a filter (`source_ip`,
  `event_type`, `severity`, `since_hours`); a call with neither is rejected. `queries.triage_alerts` SELECTs before
  it UPDATEs to report the match count and whether `max_alerts` truncated it.

### Instance ownership

`instance_lock.py`: one process owns a deployment's sensors (flock file beside a SQLite DB; a PostgreSQL advisory
lock on a dedicated connection). A process that cannot take it starts read-only (queries, analysis, triage,
tokens) and does not touch ports, reconcile, or run delivery/canary servers; the sensor-changing tools say who
owns them. It retries every `owner_check_seconds` and promotes itself, re-establishing the sensors as a restart
would. The OS releases the lock when the owner dies; there is no stale lock.

### Suppression engine

`suppression.py` runs at `submit_event`. Rules are cached in memory, refreshed every 30 s and invalidated
explicitly by `suppression_add`/`suppression_remove`.
- IP: CIDR first, then exact string; empty matches anything. Event type: `fnmatch` glob; empty matches anything.
- `action="drop"` discards; `action="rate_limit"` passes the first N per `rate_limit_window_seconds` (monotonic
  sliding window).
- A rule must set at least one of `ip_pattern` / `event_type_pattern`; empty rules are rejected (they would drop
  every event).

### Credential honeytoken cross-reference

`credential_match.py` runs after suppression. It indexes active CREDENTIAL tokens by `(service, username_lower,
password)`, refreshes every 30 s, and is invalidated on `honeytoken_create`/`honeytoken_revoke`. On a match the
event is mutated in place: `severity` → CRITICAL, `honeytoken_id` set, `event_type` →
`honeytoken_triggered_credential_via_<original>`; the flusher then calls `mark_honeytoken_triggered()` for events
with that prefix. `token_matchers.py` does the same for SSH-key fingerprints, JWT `jti` and DB-row canary emails.
- Matching runs on the payload **before** it is clamped; a planted credential inside a dropped `post_data` must
  still escalate. The HTTP engine keeps credential-aliased form fields however much junk precedes them.
- *Plaintext* extraction: `username`/`password` keys; HTTP `post_data` aliases (`username|user|email|login`,
  `password|pass|passwd|pwd`); SMTP `AUTH PLAIN` (base64, split on `\0`, RFC 4616).
- *Hashed* services (`_HASHED_SERVICES` = `{mysql, vnc}`): the engine generated the salt/challenge and stores it with
  the captured response; `credential_verify.py` recomputes the digest per planted-password candidate (`_candidates`
  dict). MySQL also matches on the plaintext username; VNC is password-only.
- Service is inferred from the event_type prefix (`_SERVICE_PREFIXES`); `service="any"` tokens match everywhere.
  Engines must set `service` on credential events (RDP/SMB NTLM, SNMP, PostgreSQL, MSSQL, …) so planted tokens
  cross-reference.
- Limitation: it only fires when planted creds hit one of our own honeypots (documented in `KNOWN_LIMITATIONS.md`).

### TLS / HTTPS / STARTTLS

- `engines/tls.py:ensure_cert` generates a self-signed RSA-2048 cert per honeypot, persisted at
  `tls/<honeypot_name>/server.{crt,key}` (stable identity across restarts). `tls/` is gitignored. A persisted cert
  that no longer matches its profile or has < 30 days left is reissued.
- The cert is shaped per service by `tls.CertProfile`; pass the profile of the service being impersonated to
  `ensure_cert`/`build_server_ssl_context(_async)`, and pass the *same* profile from any caller that reads the
  cert back (RDP's CredSSP public key), or the file ping-pongs. Kubernetes and MySQL are leaves from a named CA
  (CA key discarded), RDP is self-signed and named for the computer FQDN, the default is a bare backdated
  `CN=<name>` with no organisation and no `localhost` SAN.
- **Any new TLS listener on an aiohttp runner must use `engines/tls_front.start_tls_site`**, not a bare `TCPSite`.
  It `MSG_PEEK`s the first 16 bytes (5 s sniff deadline, 256 unclassified connections, 32 per source), hands a
  TLS 1.2+ ClientHello to asyncio via `loop.connect_accepted_socket`, answers a pre-1.2 hello with `protocol_version`,
  and answers plaintext HTTP with `plaintext_reply` (fixed bytes, a callable given the Host header, or `None`).
  The HTTP engine passes `http_personas.plaintext_on_tls_reply`. HTTP enables TLS with `config["tls"] = True`.
- SMTP STARTTLS completes a real handshake with `asyncio.start_tls()` and clears protocol state (RFC 3207): the
  client must re-issue EHLO. MySQL advertises `CLIENT_SSL`, drives TLS through `ssl.MemoryBIO` (`_TLSTransport`) and
  tags logins `tls: true`; `mariadb` ≥ 11.4 refuses the self-signed cert by default (test with
  `--ssl-verify-server-cert=0`). Kubernetes serves TLS only.

### Personas

Fingerprint surfaces must agree; a mismatch is itself a fingerprint.
- **SSH** (`engines/ssh_personas.py`): a persona is (hostname pool, kernel + build string, OpenSSH banner, distro
  identity). `SSHEngine.start()` picks one if the config has no `ssh_persona` and persists persona and hostname to
  `Honeypot.config`. `cowrie_env_vars()` passes them as `COWRIE_*` (both legacy `COWRIE_HOSTNAME` and modern
  `COWRIE_HONEYPOT_HOSTNAME`); explicit `fake_hostname`/`fake_kernel` override. A new persona must be
  distro-consistent (a Debian persona has no Ubuntu kernel build string).
- **Cowrie capture needs three settings in `cowrie_env_vars()` and in the compose `cowrie-ssh` service**:
  `COWRIE_HONEYPOT_LOGTYPE=plain`, `COWRIE_OUTPUT_JSONLOG_ENABLED=true`, `COWRIE_OUTPUT_JSONLOG_LOGFILE=/proc/self/fd/1`.
  Without them `_ingest_logs` fails `json.loads` on every line and nothing is recorded while health checks pass.
  Only `tests/integration/test_ssh_capture.py` can catch a regression.
- Cowrie's persona is env vars (`[shell]` settings `COWRIE_SHELL_*`) plus a rewritten `fs.pickle` (`engines/cowrie_fs.py`),
  extracted by `ssh.py` into an anonymous volume at `/cowrie/persona` before the container starts; failure falls back to the
  default with a warning. Never write `/etc/issue.net` (non-empty is a pre-auth banner). A container only picks up persona
  changes when recreated (`honeypot_stop remove=True`, then deploy).
- Its fingerprint is patched from inside the container by `engines/cowrie_sitecustomize.py` (import hook delivered with the
  persona filesystem via `PYTHONPATH=/cowrie/persona/patch:/cowrie/cowrie-git/src`; keep the second entry): narrowed KEXINIT
  offer (a strict subset of the persona's real OpenSSH), telnet negotiation and prompt, coreutils-like `head`/`tail`, and
  per-hostname `uptime`/`w`/`/proc/uptime`. Compose values are literals pinned by
  `test_compose_sensor_carries_the_same_algorithm_environment_as_the_engine`; `tests/integration/test_cowrie_fingerprint.py`
  reads the real wire.
- The persona filesystem carries a tracked bait credential (`~/.bash_history` mysql line, `~/.my.cnf` mode 600) from
  `planted_credential("mysql")` (a deterministic untracked decoy without a token), written to **both** `/root` and the persona
  user. Cowrie's root filesystem is read-only and `COWRIE_HONEYPOT_OUT_ADDR=127.0.0.1` (default; `cowrie_allow_egress`
  opts out) makes its wget/curl/tftp/nc emulation fail in-process.
- **Telnet** is a ~10-line `SSHEngine` subclass (one Cowrie container, SSH on 2222, Telnet on 2223,
  `_PRIMARY_CONTAINER_PORT`/`_PRIMARY_IS_TELNET`); events are retagged `telnet_*` in `ssh.py:_retag_for_protocol`.
- **HTTP** (`engines/http_personas.py`, bodies in `http_templates.py`): a persona bundles Server header,
  X-Powered-By, cookie name, 404 page and jitter. `start()` picks one if `config` has no `persona` and persists it.
  Keep bundles consistent (no `PHP` X-Powered-By on Nginx).

### Engine notes

All in-process asyncio engines use the same buffer path; validate behaviour with the tool an attacker would use.
- **RDP** (`rdp*.py`): parses X.224 and the `mstshash` cookie, negotiates TLS or CredSSP, captures a crackable NetNTLMv2. A
  planted token or the weak pair derived from the honeypot name (`accepted_logins`/`sessions` in config) is let in (session
  key from the password, sealed public-key binding), then a static framebuffer desktop records keys, clicks and clipboard; the
  console is a pure fake shell (no network, no execution); repainting runs in `asyncio.to_thread`. `rdp_handshake` HIGH,
  `rdp_invalid_probe` LOW, `rdp_command` CRITICAL on a download. Tests: aardwolf (`test_rdp_session.py`, incl. mutation-replay
  fuzz) and FreeRDP 3 (integration).
- **SMB** (`smb.py`, `smb2.py`): an SMB1-only negotiate gets a Windows-shaped reply; DoublePulsar/EternalBlue Trans2 is
  `smb_exploit_attempt` (CRITICAL). Anything offering SMB2 goes to `smb2.py` (dialect 2.1, NTLM using RDP's `build_challenge`
  so one host discloses one identity); AUTHENTICATE is `smb_ntlm_auth` (HIGH, `service="smb"`, `hashcat -m 5600` line) refused
  with `STATUS_LOGON_FAILURE`; no tree connect; echo TID/PID/UID/MID. `test_attacker_tool_fidelity.py` drives it with impacket.
- **PostgreSQL** declines SSL, requests cleartext auth, captures the password, then ACCEPTS and classifies simple
  queries (`COPY … PROGRAM` CRITICAL, UDF loads and `pg_read_file`/`lo_export` HIGH, recon MEDIUM). Malformed startup
  gets the FATAL ErrorResponse a real server sends.
- **MongoDB** (hand-written BSON, OP_MSG/OP_QUERY): answers `isMaster`/`hello`/`buildInfo`/`listDatabases`; flags
  `mongodb_destructive` (dropDatabase) and `mongodb_ransom_note` (CRITICAL); replies `ok:1`, persists nothing.
- **MSSQL** (TDS): PRELOGIN with `ENCRYPT_NOT_SUP` and all four options, Login7 parsed, password de-obfuscated
  (`_decode_tds_password`), `service="mssql"`, error 18456, no query phase.
- **Memcached**: records reconnaissance; the stage-then-fetch *sequence* raises `memcached_amplification_attempt`
  (CRITICAL) with a measured factor. **SNMP** (udp/161, hand BER): v1/v2c community strings are credential captures
  (`service: "snmp"`); only `public`/`private` answer (answering everything fingerprints the sensor); a small ordered
  MIB makes GetNext/GetBulk/walk behave (`endOfMibView`, `noSuchObject`, advancing `sysUpTime`). **Neither memcached
  nor SNMP ever amplifies**: reflection vectors with spoofable sources.
- **LDAP** (tcp/389, hand BER): simple binds are captured and refused with `invalidCredentials`; `looks_like_jndi()`
  separates Log4Shell's second stage (opaque base object, no `dc=`/`cn=`/`ou=`, or `javaClassName`/`javaCodeBase`);
  persona is Active Directory; the rootDSE is readable anonymously, other searches are `operationsError`.
- **Docker API** (2375) and **Kubernetes** (6443): `analyse_container_create()`/`analyse_pod_spec()` return *named* escape
  reasons (host root bind, privileged, host namespaces, dangerous caps, miner image, payload command); any hit is CRITICAL
  (`docker_api_container_escape`), else HIGH. Kubernetes: Secrets reads are CRITICAL; replies carry `Audit-Id`,
  `X-Kubernetes-Pf-*` and `Status`-shaped errors; presents as `nginx`, TLS only via `start_tls_site`; identity is stable
  (UIDs, names, secrets derive from the honeypot name via `_uid`; only `Audit-Id` varies); objects come from `_Cluster`, a
  pure function of the name, so list/get/describe/`-o yaml`/`NotFound`/`?watch=1` agree; `_RESOURCES` drives discovery.
- **Mail**: `smtp.py` analyses a completed `DATA` (`mail_message.py`: headers, links, SHA-256 of attachments; executable
  attachment CRITICAL) and routes per recipient (`SMTPProtocol._route`): local → `maildrop.py` (process-wide, bounded, seeded
  with ordinary mail), reserved TLD → RFC 3464 bounce after `_DSN_DELAY`, else recorded as relayed. **Nothing is ever sent
  onward** (a test fails on any non-loopback connect). `pop3.py`/`imap.py` serve the maildrop to a planted credential or the
  derived weak pair; POP3 `DELE` and IMAP flags/expunge/CREATE/APPEND/COPY live on the connection only (visitor mail
  numbered from 1,000,000); `AUTH PLAIN/LOGIN` share `_attempt_login` (`engines/_sasl.py`). IMAP omits `LOGINDISABLED` on
  purpose, advertises only what it implements and keeps logic in pure `imap_mailbox.py` (BODY sections as stored, CRLF). POP3
  stores `APOP` digests with their challenge. Tests: `test_mail_system.py`, `test_imap_session.py`, `test_imap_mailbox.py`.
- **SIP** (tcp+udp/5060, both): separates `OPTIONS` sweeps (named scanners), bare-`REGISTER` extension enumeration, and
  `INVITE` to satellite/premium prefixes (`sip_toll_fraud_attempt`, CRITICAL); digest auth uses a fresh nonce stored
  with the response. **rsync** (873): module listing is `rsync_module_enumeration` (HIGH); selecting a module with no
  `auth users` is `rsync_anonymous_access` (CRITICAL). **NFS** (2049, hand ONC RPC/XDR): the export-list terminator must
  be right or `showmount` hangs; MNT of a world-shared export is CRITICAL and granted, a restricted one HIGH and
  refused. `nmap -sV` hard-matches Dovecot, Asterisk 18.10.0, rsync 31 and rpcbind.
- **DNS** answers as a recursive resolver (`ra`, never `aa`/`ad`; dnslib defaults to `aa=1` and echoes AD) on UDP **and**
  TCP/53 (zone transfers are TCP-only; AXFR/IXFR recorded and REFUSED). `version.bind` returns the BIND string matching
  `_host_identity`; `ANY` returns an RFC 8482 `HINFO`. `transport="both"` for capture/firewall/preflight but
  `spoofable_source=True`: `source_is_spoofable`, not `transport`, decides which sources a blocklist must not contain.
- **HTTP endpoints and sessions** (`http_endpoints.py`): persona-aware `/robots.txt` (advertising the bait), `/favicon.ico`,
  `/sitemap.xml`, `/.well-known/security.txt` (a 404 there is a tell). A per-honeypot session table keyed by the persona's
  cookie escalates after `_RECON_THRESHOLD` (5) hits to MEDIUM `http_active_recon`; sessions expire after
  `_SESSION_TTL_SECONDS` (1 h), pruned on lookup. Every request (path, query, headers, UA, body, also URL-decoded) goes
  through `_classify_http_attack`/`_HTTP_ATTACK_SIGNATURES`; a hit becomes `http_exploit_attempt` with
  `payload.exploit_categories`. Broad patterns are fine: a honeypot has no legitimate users.
- **Per-IP caps** (`engines/conn_limit.py`): `ConnectionLimiter(max_per_ip)` with `limited_factory()` (protocol
  factories) and `limited_handler()` (`start_server` handlers), sized from `max_connections_per_ip` (default 32,
  0 = unlimited); over-cap peers are accepted then closed without driving the protocol. aiohttp engines rely on
  aiohttp's own limits.

### Protocol fidelity

An engine distinguishable from what it impersonates is broken: a scanner that fingerprints the decoy stops sending
the traffic the honeypot exists to collect. Validate against real clients (redis-py, pymongo, psycopg, impacket,
ftplib, smtplib, httpx, pyspnego, `nmap -sV --version-intensity 9`) and re-run the sweep after any wire-format
change; `tests/unit/test_protocol_fidelity.py` pins each finding with the nmap signature it encodes. Check new
engines for: missing handshake commands (Redis `HELLO`), self-inconsistent versions (one constant per engine:
`_REDIS_VERSION`, `_MONGO_VERSION`, `_SQL_VERSION`), structurally thin responses (MSSQL PRELOGIN options), silence
where the real service speaks (PostgreSQL FATAL), uncorrelated fields (SMB TID/PID/UID/MID), and epoch/zero
placeholders (SMB `SystemTime`, Mongo `localTime`). Listing, size and bytes come from one source (FTP tree; HTTP
backups reuse it).

### aiohttp server identity

`http_identity.py` controls the `Server` header for every aiohttp server (HTTP, Elasticsearch, canary).
- **A new aiohttp server must use `identity_runner(app, banner)` and set its own identity**; a bare `web.AppRunner`
  leaks `Python/3.x aiohttp/3.y.z` on protocol-level errors (malformed requests never enter the app, which is what
  `nmap -sV` sends). It subclasses `AppRunner`/`Server`/`RequestHandler` so `handle_error` stamps that listener's own
  banner.
- `server_identity_middleware(server, extra)` pins the header on application responses; a module-import side effect
  rebinds `aiohttp.web_response.SERVER_SOFTWARE` as the fallback (explicit headers still win). Neither alone is enough.
- `ExactHeaderResponse` suppresses `Server` entirely and pins header order: scanner signatures are anchored regexes
  over the whole response (nmap's Docker rule wants `Content-Type`, `Date`, `Content-Length: 29`, in that order).

### Webhook delivery and notification channels

`webhooks.py` runs one background worker draining a queue, decoupled from the flusher.
- Signature `X-HoneyPot-Signature: sha256=<hex>` (HMAC-SHA256 of the raw body); compare with `compare_digest`.
- Failure tracking is per subscription (`delivery_count`, `failure_count`, `last_error`). Active subscriptions are
  cached 30 s (`_active_subscriptions`); invalidate on `alert_subscribe`/`alert_unsubscribe`, worker `start()`, or
  call `invalidate_subscription_cache()` after inserting a `Subscription` directly in a test. Rows are
  `expunge_all`'d from the loading session.
- Destination policy (`webhook_allow_private_destinations`, default off) is enforced at subscribe **and on every
  delivery** (`WebhookDelivery._dispatch` → `check_destination`, 10 s cache); syslog connects to the validated
  address. `alert_subscribe` is admin-tier.
- **Output formats are someone else's detection content: conformance is correctness.** `tests/unit/test_siem_formats.py`
  pins each rule; verify by rendering a real event and reading it:
  - `event.outcome` is never guessed (`_ecs_outcome()` returns `unknown` when it cannot tell).
  - `user.name` and `related.ip`/`related.user` are always set (they drive Elastic's pivots).
  - Never mix a dotted key with its object (nest `event.original`).
  - CEF: use standard slots (`suser`), the signature id is the raw `event_type`, the name is humanised via
    `_humanize_event_type` (knows acronyms), device product is real.
  - Loki stream labels stay low-cardinality: `source_ip` is never a label.
  - Enrichment reaches ECS fields (`_ecs_enrichment()`: `source.geo.*` with `location` as `{lat, lon}`,
    `source.as.*`, reputation as `threat.enrichments[]`, not `threat.indicator.*`); VirusTotal confidence bands on the
    absolute detection count, not the share of engines.
- **Human channels** (`slack`, `teams`, `email`): Slack sets `text` as well as `blocks` (mobile push) and at most 8
  section fields (10 is the rejection limit); Teams emits a **MessageCard** (works on both connector kinds) with a
  mandatory `summary` and a bare-hex `themeColor` (no `#`); email goes over SMTP via `asyncio.to_thread`, URL
  `smtp://user:pw@host:587/?from=…&to=a@x,b@y&tls=starttls|implicit|none` (`smtps://` defaults to 465), plain text
  only (content is attacker-controlled), `_parse_smtp_url` also runs at subscribe time.
- **`_NotifyThrottle`**: a `(subscription, event_type, source_ip)` fires at most once per `notify_throttle_seconds`;
  the suppressed count rides the next message (never hide volume). CRITICAL is exempt. Throttled events return
  `(True, None)`, not an error.

### Packet capture

`pcap.py` runs one `tcpdump` ring over the deployed honeypot ports, because payloads record what engines
*understood* and three jobs need wire bytes (carving second stages, Suricata/Zeek replay, an artefact not an assertion).
- `probe_capability()` reports why capture is off as a value, not an exception (runs `tcpdump -L`; the message names
  the fix, `setcap cap_net_raw,cap_net_admin=eip`). Capture needs `NET_ADMIN`+`NET_RAW` and host networking in Docker;
  `-U` is set so a fresh extract is not missing the latest packets.
- The ring is bounded by construction: `pcap_file_mb × pcap_files`. A full disk stops the database.
- The filter derives from the deployed port set through `capabilities.transport_for` (no private "UDP ones" list);
  `honeypot_deploy`/`honeypot_stop` call `refresh_capture()` (a silent no-op when disabled). An empty port set never
  becomes capture-everything (it would record the operator's own SSH).
- `pcap_extract(source_ip)` filters with tcpdump's BPF (link framing varies; `any` yields Linux SLL) and merges by hand
  (no `mergecap` dependency; every ring file shares a link type). No match writes a valid empty pcap (a 0-byte file
  reads as corrupt); a truncated trailing record is kept-up-to.

### Watchdog, reconciliation, adoption

- `watchdog.py` runs every 30 s and health-checks every RUNNING **and ERROR** honeypot (watching only RUNNING made
  ERROR a one-way door). Failure → status ERROR + one CRITICAL `honeypot_health_failed` alert (`_reported_dead`
  prevents spam; recovery clears it); recovery → `_mark_recovered` back to RUNNING with no alert.
- `HoneypotEngine.health_check()` defaults to a TCP probe; SSH also checks Docker (probing the host port, then the
  container's own IP on `COWRIE_INTERNAL_PORT`, because in the compose stack `127.0.0.1:2222` is the server's own
  loopback); DNS sends a real query.
- **Probes must not become attack data**: any new probe that opens a connection to an engine calls
  `self_probe.register()` with the probe socket's local `(ip, port)`; `submit_event` drops the one event from exactly
  that tuple. Never suppress `*_connection` from loopback, which is a genuine signal.
- The watchdog hosts the retention sweep (`_maybe_prune`): opt-in via `retention_days > 0` (default 0), at most once per
  `retention_sweep_interval_hours` (monotonic `_last_prune_at`).
- `reconcile.py` runs once from `lifespan`, AFTER the event buffer starts and BEFORE the watchdog (otherwise the
  watchdog marks restartable honeypots dead). Every start is a process restart, so anything left RUNNING is
  re-established through `reattach(name, port, config, container_id)` (base default `start()`; SSH re-attaches log
  ingestion to the live container). One that cannot be re-established becomes ERROR with a CRITICAL
  `honeypot_restart_failed`; startup never aborts. `SSHEngine` keeps strong references to ingestion tasks
  (`_ingest_tasks`): asyncio only weakly references tasks.
- `adopt_labelled_containers()` runs straight after: containers labelled `honeypot-mcp=true` (compose `cowrie-ssh`
  above all) are claimed by creating or re-pointing a row and attaching ingestion, matched on the published host
  port; containers with no published port are skipped; rows stuck in ERROR are re-adopted.

### Canary callback server

`canary.py` (aiohttp, `canary_callback_host:canary_callback_port`, default `0.0.0.0:8888`, started in `lifespan`).
`GET /t/{token_id}` matches `token_meta.token_id` (URL tokens) or `token_uid` (file tokens); on match it marks
TRIGGERED, writes a CRITICAL alert through the buffer and an `AttackerEvent`, and returns a generic `200 OK`.
`GET /t/{token_uid}.png` is the same with a 1x1 PNG (PDF tokens). The global rate ceiling applies only to requests
that matched a token, so random ids cannot starve a real trigger.

### MITRE ATT&CK and risk scoring

Analyst-facing; wrong is worse than absent.
- `intel/mitre.py` maps event-type/payload regexes to techniques (`_load_stix_index()` is `lru_cache`d;
  `config/mitre_attack.json` is optional and adds descriptions). Tactics follow ATT&CK Enterprise exactly (Brute Force
  T1110 is Credential Access). Patterns are ordered most-specific-first and all matches are collected; a generic rule
  must never be the only hit. Watch cross-category false positives (`smb_exploit_attempt` contains "attempt").
  Tactic IDs (`TACTIC_IDS`) live there.
- Coverage must match what engines emit: grep engines for `event_type=` and make sure every high-value one maps; an
  unmapped capture is invisible. Change mappings only with evidence from `mapping_audit` (blind sample stratified by
  event type, independent labellers, `score` at strict and parent-technique level with Jeffreys intervals, and the
  estimate without the largest stratum).
- **The Grafana ATT&CK dashboard is generated**: `scripts/generate_mitre_dashboard.py` derives the SQL by pushing every
  `signature_events` entry through `map_to_attack`; `tests/unit/test_mitre_dashboard.py` regenerates and diffs. Re-run
  it after touching mappings or adding an engine. Multi-tactic events count under every tactic (UNION ALL, not CASE).
  The tactic-timeline styling is hand-maintained (generator only patches `queryText`/`rawQueryText`): fixed per-tactic
  colour overrides, unique, log scale, not stacked (`test_every_tactic_has_a_fixed_color_override`,
  `test_tactic_colors_are_unique`, `test_tactic_timeline_is_not_stacked`).
- Threat-map basemap renders no place labels (`showLabels: false`; `test_threat_map_basemap_has_no_labels`). Grafana
  timeseries bucket on `MAX((($__to) - ($__from)) / 240000, 60)` (`$__from`/`$__to`, not `$__interval_ms`); tables never
  `SELECT MAX(timestamp)` raw: use `strftime('%Y-%m-%dT%H:%M:%SZ', …)` and declare the column in `timeColumns`.
- `scripts/seed_demo_data.py` must feed every engine it deploys (`_ENGINE_MIX` weights, checked by
  `_check_engine_mix()` against `_EVENT_PROFILES`); honeypot ids use `HoneypotType.value` (`docker_api` →
  `demo-docker-api`).
- `analysis/profiler.py:_calculate_risk` weights local observation over feeds: direct observation alone can reach
  CRITICAL (VT/AbuseIPDB are optional), a triggered honeytoken dominates, volume is weighted low. Tests assert
  ordering and band reachability, not exact numbers.

### Intent-level tools (`deception/`)

- `deception_plan` turns an environment description into sensors and tokens; the model reads the prose, the planner
  supplies only what it cannot know (free ports, identities that must agree, inert tokens). It deploys nothing.
- `deception_coverage` pushes each engine's real `signature_events` through `intel.mitre`; an unmapped engine shows as
  missing coverage, as it is on the dashboard.
- `soc_brief` separates untriaged CRITICAL/HIGH, token trips and dead sensors from volume. **Headline counts come
  from their own aggregate query, never `len(needs_attention)`** (that list is capped at `max_highlights`);
  CRITICAL has its own line; `needs_attention_total`/`_showing` make the cap explicit.
- `deception/capabilities.py` is the single source of truth for an engine (port, OS family, roles, credential
  `service` label, signature events, transport). Templates, planner and coverage read it; do not keep copies.
- `check_coherence` flags a directory server with no Windows services, RDP with no SMB, and, as an *error*, a
  credential token for a service no sensor captures (it can never fire).
  `test_planned_tokens_always_target_a_deployed_service` asserts the planner never emits that.

### Tool response shaping and the agent-first contract

An MCP result lands in a model's context, so size is correctness. **List tools summarise, detail tools expand, bulk
goes to disk** (`tools/_format.py`):
- `digest_payload()` keeps triage fields, drops bulk (`headers`, `raw_body_b64`, `cookies`, nested `enrichment`), clips
  values at 160 chars; unknown keys pass through. `truncate_payload()` keeps structure, clips values over 4,000
  chars with a marker. `validate_ip()` runs on every IP argument (a typo otherwise reads as a clean bill of health).
- `alerts_recent`/`alerts_search` return digests, `alerts_get` the full payload; `alerts_export`, `export_indicators`,
  `generate_report` write files via `_format.write_artifact()` and return path plus headline figures.
- List tools return `{count, <items>: [...]}` with a `window` and a `note` when truncated; a capped list must never read
  as complete. Anything asked "recently" takes `since_hours`.
- Result shapes are dicts everywhere (`honeypot_list` → `{count, honeypots, note}`, `alert_subscriptions_list` →
  `{subscriptions}`, `honeytoken_list` → `{tokens}`, `api_key_list` → `{keys}`).

`tests/unit/test_tool_contract.py` fails the build when a tool:
- returns anything but `dict[str, Any]` (a bare list is an *empty* MCP response);
- has a parameter with no `Args:` description (the docstring becomes the schema description);
- requires more than 3 parameters or has more than 8 (`MORE_PARAMETERS_BECAUSE` is the exception list, currently
  empty);
- opens with a weak first line (models choose tools from it);
- exceeds the weight budget: 3,000 characters per tool, 70,000 in total (trim prose; FastMCP drops schema titles).

Design consequences: tools size their own answers (a default that fits, a count and a `note` for what was cut; no
`rank_by`/`window_minutes`/`timeout_seconds`/`output_path` knobs; a bigger answer comes from a narrower question),
files go to `reports_dir` under generated names, tools that reach outside this system default to a dry run or are
operator/admin gated, and an error carries a `hint` naming the next step. Logic two tools share lives in a helper
(`cluster_ssh_clients`, `write_report`), never one tool calling another's public signature.

### Reports, console, Docker, settings

- `analysis/reporter.py` uses Jinja2 with `autoescape=select_autoescape(["html", "xml"])`; Markdown cell values go
  through `_md_cell()` (pipe/backslash/newline). Attacker-controlled fields must never break out of either format.
- **Console** (`console/`, `127.0.0.1:8090`, `CONSOLE_PORT=0` disables; port 8090 because 8080 is `default_http_port`): one HTML
  file plus `/api/overview` polled every 5 s, started from `lifespan`, bind failure logged not fatal. **Read-only
  structurally** (no auth, so GET routes only; `test_console_is_read_only`); the feed ships `digest_payload` digests.
  Severity is two series (routine low+medium, serious high+critical; `#3987e5`/`#e66767`) plus a text label
  (`LOW`/`MED`/`HIGH`/`CRIT`), never colour alone; re-run the palette validator if colours change.
- **Docker**: SSH honeypots use Cowrie (`docker/cowrie/build_persona_fs.py`), HTTP has `docker/http-honeypot/`; the
  stack runs from `docker/` with `docker compose up -d`. Other engines are in-process.
- **Settings**: `config.py` (`pydantic-settings`, env and `.env`, `get_settings()` singleton) is the only configuration
  mechanism; do not add a second source. `tls_dir`/`reports_dir` are settings (tests redirect both to `tmp_path`).
  `config.warn_on_world_readable_env()` fires at startup when `.env` is readable beyond its owner.
- Optional dependencies degrade gracefully, returning `{"available": False, "note": "..."}` instead of raising:
  `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` (also outbound reporting), `GEOIP_DB_PATH` (GeoLite2-City.mmdb),
  `CANARY_PUBLIC_URL` (default `http://localhost:8888`).

### MCP transport, RBAC, API keys

- `server.py:main()` dispatches on `mcp_transport`: `stdio` (default, local, no auth), `http`/`sse`/`streamable-http`
  (persistent networked daemon), `none` (collector: `_run_collector()` runs `lifespan` until SIGTERM/SIGINT; the only
  correct mode for a detached container, where stdio reads EOF and restart-loops; compose sets `MCP_TRANSPORT=none`).
- **Networked transports are fail-closed**: `_networked_auth_error()` (pure) makes `main()` raise `SystemExit` unless
  `mcp_auth_token`, `mcp_auth_tokens` or `mcp_allow_unauthenticated` is set; stdio and `none` need no token.
  `_build_auth()` attaches `StaticTokenVerifier` (`Authorization: Bearer`, 401 otherwise) and returns `None` for stdio,
  so the test suite is unaffected.
- **Three roles, each a strict superset of the one before** (`rbac.py`): *viewer* (31 tools: read-only), *operator* (24:
  manage this system's own resources, reversible and contained: deploy/stop/pause/resume/configure, token
  create/rotate/revoke/export, acknowledge, suppression, `alerts_export`, `export_indicators`, pcap, samples scan,
  `run_analysis`, `mapping_audit`, `report_ip_abuse`, `deception_deploy_plan`), *admin* (12: blast radius outside this
  system's database or the control plane: `alerts_prune`, `alert_subscribe`/`alert_unsubscribe`, `api_key_*`,
  `audit_log_search`, `database_backup`, `detection_rules_update`, `grafana_start`/`grafana_stop`, `sample_collect`).
  Read the lists in `rbac.py`; do not trust this summary for placement.
- Enforcement is per tool: `@mcp.tool(auth=require_role("operator"|"admin"))` on the decorator (FastMCP skips it for
  stdio; `require_role` allows `ctx.token is None` only for networked `MCP_ALLOW_UNAUTHENTICATED`). Viewer tools carry
  no `auth=`. **A new tool must be in exactly one of `VIEWER_TOOLS`/`OPERATOR_TOOLS`/`ADMIN_TOOLS` and, if gated, carry
  the decorator**: `test_rbac_covers_every_registered_tool` (fail-closed, unclassified fails) and
  `test_operator_and_admin_tools_actually_carry_an_auth_check`.
- `MCP_AUTH_TOKENS` (`token:role,token:role`) replaces `MCP_AUTH_TOKEN`; `parse_auth_tokens()` treats a lone
  `MCP_AUTH_TOKEN` as one admin token. Role goes in the verifier's `claims["role"]`. Static tokens are restart-only and
  are the break-glass bootstrap credential (`api_key_create` is admin-gated, so one must exist first); with zero static
  tokens `_build_auth()` still returns `None`.
- **API keys** (`tools/api_keys.py`): `ApiKey` rows, only a SHA-256 digest stored (plaintext returned once, at creation),
  checked by `rbac.build_combined_verifier()`'s `_CombinedTokenVerifier` after static tokens. A 30 s cache
  (`rbac.API_KEY_REFRESH_SECONDS`) is invalidated on create/revoke (`invalidate_api_key_cache()`). Keys are additive:
  never a way around `_networked_auth_error`. Each carries a per-person/automation `label`.

### Control-plane audit log

Every state-changing tool call appends to `audit_log` via `tools/_audit.py:record_action()`; `audit_log_search` (admin) reads
it. **A new tool that changes state or reaches outside this system must call `record_action`** (deploy/stop/pause/resume/
configure, token revoke/rotate, plan deploy, pcap, prune, acknowledge, subscriptions, suppression, API keys, backup, rules
update, reports, grafana, samples, `mapping_audit`, `report_ip_abuse`, `run_analysis`). Reads are not audited. The table is
append-only and the retention sweep never touches it.
- Auditing never breaks the action: `record_action` swallows and logs its own failures.
- Secrets never land in the log: `redact_arguments()` masks keys containing secret/token/password/api_key/credential/auth.
- Every row says who: `record_action` resolves `rbac.current_actor()` itself (`"alice (operator)"` for an API key, a bare
  role for a legacy token, `stdio` locally), never an `actor=` parameter. `actor IS NULL` means "recorded before actor
  tracking", not "unknown caller".

### Operations and hardening

- `/healthz` (process) and `/readyz` (runs a real query against a real table; 503s on a runaway backlog) answer
  different questions: alert on `/readyz`, since honeypots keep answering with no database. The metrics and console
  servers bind loopback by default.
- `scripts/backup.sh` uses `VACUUM INTO`, never `cp` (WAL) and not `.backup` (restarts forever under write load);
  `restore.sh` refuses to run while the server is up.
- Host hardening surrounds the decoys and never makes them less reachable: every honeypot port stays open to everyone
  with no rate limit, ban or geo-block (`docs/HARDENING.md`).
  - The service user is **not** in the `docker` group; it talks to `hardening/docker_guard.py`, which forwards only the
    Cowrie operations the SSH engine makes and 403s the rest. Its create policy is built from `engines/cowrie_limits.py`
    (the constants `ssh.py` reads); `test_the_engines_own_create_requests_pass_the_guard` runs the real engine, so a
    container-setting change means a guard change. The guard runs under a syscall deny-list that forbids `chown`.
  - The guard validates what the daemon reads (`tests/integration/test_docker_guard.py`): it sets `Content-Type` itself per
    endpoint, refuses bodies on endpoints that take none, parses create bodies strictly (a repeated key at any depth is
    refused) and applies the `kill` signal allowlist to `stop`/`restart`. A new endpoint needs an explicit content type and
    an explicit "takes a body or not".
  - `hardening/firewall.py` renders nftables table `inet hp_fw` (the only thing it touches): default-drop input, redirects
    only for `fib daddr type local`, container egress closed or `limited`, service-user output restricted; `harden-host.sh`
    calls its CLI (`--print-listen`) so firewall and pre-flight share one port list. `hardening/hostcheck.py` adds pure-parser
    Linux checks to `preflight.py`; `check_env_permissions` accepts `root:honeypot 0640`.
  - `deploy/harden-host.sh`: `prepare` (sshd on 22 and the admin port) → `finalize` (admin port only, firewall with rollback
    timer) → `confirm` → `status`/`teardown`. `prepare` after `finalize` must not reopen 22; poll for the listener.
  - The venv needs an interpreter the service user can execute (`UV_PYTHON_INSTALL_DIR=/opt/uv-python`).
  - `scripts/fetch_backup.sh` treats the VPS as hostile: refuse archive paths leaving `honeypot-<stamp>/` before unpacking,
    delete symlinks after, one ControlMaster connection (6 new admin SSH connections a minute), macOS bash 3.2 compatible.
    Reports run read-only with `trusted_schema=OFF`, excluding `selftest_` probes and `0.0.0.0` platform alerts.
  - Docker-gated `test_firewall_rules.py` and `test_docker_guard.py` check both against a real kernel/daemon.

### Security boundaries and parsing

The control plane is driven by a model that reads attacker-authored data (usernames, paths, commands, User-Agents), so
"the caller is trusted" is not sufficient reasoning. Pinned by `tests/unit/test_security_boundaries.py`.
- **Artifact writes are confined to `reports_dir`** through `_format.resolve_artifact_path()`; any new tool that writes a
  file uses it, never a raw `Path`. Caller-named artifact paths refuse to overwrite.
- **Honeypot names cannot become paths**: `_format.validate_honeypot_name()` (Docker-compatible charset) and a re-check in
  `tls._cert_dir()` (reconciliation also reaches it). Private files are created 0600, never chmod'd afterwards
  (`secure_io`).
- Already verified sound, do not re-litigate without new evidence: HMAC comparisons use `compare_digest`; no
  `eval`/`exec`/`pickle`/`yaml.load`; SQL uses SQLAlchemy binding (the one raw `text()` binds parameters); the console
  escapes every interpolation of attacker data; `/cloud-event` refuses all requests until `CLOUD_EVENT_HMAC_SECRET` is set.
- **Nothing parses attacker bytes without a bound**: check every length field against the buffer and a hard cap before use,
  advance `pos` strictly in loops, run regexes only over clipped input with bounded gaps (`.{0,40}`, never `.*`).
  `contextlib.suppress(Exception)` cannot catch an infinite loop and a regex cannot be interrupted.
- Shared helpers: `engines/_tasks.spawn` (retained fire-and-forget tasks), `engines/_bounds.write_backlogged`,
  `engines/conn_limit` (per-IP cap, idle and lifetime timeouts, `extract_lines`, `LineWorker`, `UdpReplyLimiter`,
  `close_after_error`, `shutdown_server`), `secure_io`, `_loop_bound.LoopBound` (loop-safe locks).
- **UDP replies are bounded to a small multiple of the request** (SNMP 4x, SIP 3x, DNS 2x) and rate limited per source; the
  event is recorded either way. Not 1x: a plain `snmpget` would come back `tooBig` and a short REGISTER would get no digest
  challenge, both of which identify the decoy.

### Packaging

Non-Python assets must be declared in `pyproject.toml`'s `tool.hatch.build.targets.wheel.artifacts` **and** loaded through
`importlib.resources`, never by walking up from `__file__`. In the package: `console/static/index.html`, `presets/*.yaml`
(bundled suppression presets; config-dir overrides are gitignored), `grafana_assets/{provisioning,dashboards}` (the one
copy read by compose files, dashboard generators and `grafana.py`). Failure is silent (wheel builds and imports, then
misbehaves): `tests/unit/test_operational.py` asserts the resources resolve and the release workflow installs the wheel
into a clean environment outside the source tree. The version lives in `pyproject.toml` and `__init__.py`; a test asserts
they agree and the release workflow refuses a mismatched tag.

### Testing gotchas

- Test modules set `DATABASE_URL=sqlite+aiosqlite:///:memory:` (or read `TEST_DATABASE_URL`) at module top BEFORE importing
  anything from `honeypot_mcp.*`: `config.get_settings()` is cached.
- `EventBuffer` is a process-lifetime singleton: fixtures that touch it call `event_buffer.reset_for_tests()` in setup AND
  teardown (`asyncio.Queue` is bound to its loop).
- `tests/conftest.py` sets `EVENT_FLUSH_INTERVAL_SECONDS=0.05` because fixed `asyncio.sleep(1.0)` waits sit on the default
  flush boundary and lose on a loaded runner. Poll until the row appears (`test_pipeline.py:_alerts_after_flush`) instead of
  sleeping. The interval is a real setting.
- Schema changes need a migration. `.env` and `tls/` hold secrets and are gitignored.
