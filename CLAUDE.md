# CLAUDE.md

Guidance for Claude Code when working with this repository.

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

# Tests (625 unit tests covering security-critical paths)
uv run pytest tests/unit/ -v
uv run pytest tests/unit/test_tokens.py -v
uv run pytest tests/unit/test_tokens.py::test_aws_key_format
uv run pytest tests/unit/ --cov=src/honeypot_mcp --cov-report=term-missing

# Lint / format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check
uv run mypy src/
```

## Architecture

### Event ingestion data path

Engines do NOT write to the DB directly. The path is:

```
Engine (any of the 25 — see deception/capabilities.py)
  → submit_event(PendingEvent)             # storage/event_buffer.py
  → suppression.should_suppress(event)     # in-memory rules, dropped here are gone
  → credential_match.match(event)          # planted creds → CRITICAL + honeytoken_id tag
  → EventBuffer queue
  → flusher task (single async task, batches up to 50, max 1s wait)
  → DB transaction (Alert + AttackerEvent rows); credential-trigger events
    also mark the matched Honeytoken row as TRIGGERED
  → CRITICAL events fire a background _enrich_alert_async() that merges
    VT + AbuseIPDB + GeoIP into Alert.payload (cached via intel/_cache.py
    so repeat CRITICALs cost zero external calls)
  → on_flush hook
  → WebhookDelivery queue (separate worker, slow consumers don't back-pressure)
  → POST to subscribers (HMAC-signed if configured), 3 retries with backoff
```

Each `PendingEvent` carries its own `timestamp` so batched writes preserve chronological order — without that, every event in a batch shares `func.now()` and SOC analysis breaks.

### MCP tool registration

`server.py` creates the `FastMCP` instance (`mcp`) and registers the lifespan hook. Tool modules are imported at the bottom of `server.py` so their `@mcp.tool` decorators execute at load time — the import *is* the registration. Add new tool modules to that block.

Current tool modules:
- `tools/honeypot.py` — deploy/list/stop/configure/clone, plus `honeypot_health` (probe) and `honeypot_self_test` (end-to-end pipeline check)
- `tools/honeytoken.py` — token CRUD + AWS/credential/file generators
- `tools/alerts.py` — recent/get/search/stats/acknowledge/export/prune
- `tools/analysis.py` — enrich, profile, session reconstruction, `analyze_attacker_journey` (cross-honeypot kill-chain timeline), campaign correlation, MITRE mapping, reports, blocklist + STIX exports
- `tools/integrations.py` — webhook subscriptions, suppression rules
- `tools/blocklist_push.py` — push blocked IPs to Cloudflare / AWS WAF / pfSense
- `tools/deception.py` — the intent-level tools: `deception_plan`,
  `deception_deploy_plan`, `deception_coverage`, `soc_brief`, `deception_profiles`

The `@mcp.tool` decorator returns the original function unchanged, so tools are directly callable in tests (no `.fn` accessor needed).

### Plugin patterns

**Honeypot engines** — subclass `HoneypotEngine` (in `engines/base.py`) and implement `start`, `stop`, `status`, `get_logs`. Optionally override `health_check(container_id, port)` if the default TCP probe isn't appropriate (UDP, Docker container check, etc.). Register in `engines/__init__.py:get_engine()`. Inside the engine, push events to the buffer:
```python
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
await submit_event(PendingEvent(
    honeypot_id=hp_id, source_ip=ip, event_type="...",
    payload=p, severity=AlertSeverity.HIGH,
))
```
No direct DB sessions in engines — go through the buffer.

**Honeytoken providers** — subclass `HoneytokenProvider` (in `tokens/base.py`) and implement `create` (returns `(token_value, metadata)`) and `plant_instructions`. Register in `tokens/__init__.py`.

### Database layer

`storage/database.py` exposes a single context manager `get_session()`. Auto-commits on clean exit, auto-rolls back on exception. Sessions aren't shared across blocks — each `async with` is its own transaction.

Default is SQLite (`honeypot_mcp.db`). For PostgreSQL, install the driver
extra and swap the URL — no code changes:

```bash
pip install -e ".[postgres]"
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/honeypot
```

A CI job runs the full suite against a real PostgreSQL, because this path was
broken for the project's entire life without anyone noticing: Alembic's
`alembic_version.version_num` is `VARCHAR(32)`, revision
`0007_drop_attacker_profile_shodan_data` was 38 characters, SQLite ignores
VARCHAR limits and PostgreSQL enforces them. The chain died mid-way, `init_db`'s
`create_all` fallback silently produced a working-looking schema with no version
stamp, and every restart re-ran every migration. Keep revision ids short — there
is a test for it.

**Alembic** owns schema for persistent DBs. `init_db()` runs `alembic upgrade head` at startup; in-memory DBs (`":memory:"` in URL) skip Alembic and use `create_all` directly. Migrations live at `src/honeypot_mcp/migrations/versions/`.

The baseline migration uses `Base.metadata.create_all(op.get_bind())` so it's idempotent against pre-Alembic dev DBs — first run on an existing DB is a no-op that just stamps the version row.

To add a migration when a model changes:
```bash
uv run alembic revision --autogenerate -m "what changed"
# Inspect, then it auto-applies on next server start
```

If Alembic fails for any reason (corrupted version table, missing migration file, etc.), `init_db()` falls back to `create_all()` so the server still starts. The warning is logged.

Migrations that ADD or DROP columns guard themselves with `inspect().get_columns(...)` so the chain stays idempotent against fresh DBs (where `0001_baseline`'s `create_all` already reflects current `models.py`). The regression test `test_init_db_does_not_log_alembic_fallback_warning` asserts no fallback warning fires on boot — keep new migrations idempotent the same way so that signal stays clean.

### SSH personas

`engines/ssh_personas.py` defines OS personas — coherent bundles of (hostname
pool, kernel version + build string, OpenSSH banner string, distro identity).
At `SSHEngine.start()` time, if the honeypot's `config` has no `ssh_persona`,
one is picked randomly, a hostname is sampled from the persona's pool, and
both are persisted to `Honeypot.config` for stability across restarts.

The persona is passed to Cowrie via `COWRIE_*` env vars built by
`cowrie_env_vars()`. Both legacy (`COWRIE_HOSTNAME`) and modern
(`COWRIE_HONEYPOT_HOSTNAME`) naming conventions are set so the persona takes
effect regardless of Cowrie version.

**`cowrie_env_vars()` also carries the three settings that make capture work
at all** — do not treat them as cosmetic:

```
COWRIE_HONEYPOT_LOGTYPE=plain
COWRIE_OUTPUT_JSONLOG_ENABLED=true
COWRIE_OUTPUT_JSONLOG_LOGFILE=/proc/self/fd/1
```

`_ingest_logs` reads `container.logs()` and `json.loads` each line. Cowrie's
stdout is Twisted's *text* log, so on image defaults every line fails to parse
and the honeypot records nothing while running, answering SSH, and passing
health checks — the failure is completely silent. `logtype` matters as much as
the path: the default `rotating` wraps the file in Twisted's `LogFile`, which
seeks on open and dies with "Illegal seek" on a pipe, disabling the jsonlog
plugin entirely. `plain` uses a bare `open(path, "w")`.

The same three variables are set on the `cowrie-ssh` service in
`docker/docker-compose.yml`, which had the identical problem.
`tests/integration/test_ssh_capture.py` (Docker-gated, `RUN_DOCKER_TESTS=1`)
is the only test that can catch a regression here — unit tests feed synthetic
JSON to the parser and pass either way.

User escape hatch: explicit `fake_hostname` / `fake_kernel` keys in config
override the persona-chosen values. The `cowrie.cfg` defaults are the baseline
those env vars override.

Adding a persona: append to `_PERSONAS` in `ssh_personas.py`. Keep distro
identity consistent across all fields — a "Debian" persona must not have an
"Ubuntu" kernel build string, because mismatched fingerprint surfaces are
themselves a fingerprint.

### HTTP personas

`engines/http_personas.py` defines server "personas" — coherent bundles of
(Server header, X-Powered-By, cookie name, 404 page, jitter) that make the
HTTP honeypot look like a specific real-world stack. `engines/http_templates.py`
holds the body templates (login pages, fake `.env` files) — kept persona-
independent so a Laravel `.env` doesn't change with the server identity.

When `HTTPEngine.start()` runs and the honeypot's `config` has no `persona`
key, it picks one randomly via `pick_random_persona_id()` and writes it back
to the `Honeypot.config` JSON column. Subsequent restarts read the same
persona, so a scanner that hits the same honeypot twice can't detect rotation.

Adding a persona: append to `_PERSONAS` in `http_personas.py`. Keep the bundle
internally consistent — an Nginx persona must NOT have `x_powered_by="PHP/..."`
because real Nginx setups rarely do, and inconsistency is itself a fingerprint.

### Suppression engine

`suppression.py` runs at `submit_event` time. Rules are cached in memory and refreshed every 30s; the cache is also explicitly invalidated when `suppression_add`/`suppression_remove` MCP tools modify rules.

- IP matching: tries CIDR first (e.g. `10.0.0.0/8`), falls back to exact string match. Empty pattern matches anything.
- Event-type matching: glob via `fnmatch` (`ssh_*`). Empty matches anything.
- `action="drop"`: silently discard.
- `action="rate_limit"`: monotonic-clock sliding window; passes the first N within `rate_limit_window_seconds`, drops the rest.

A rule must specify at least one of `ip_pattern` / `event_type_pattern` — empty rules are rejected at the tool layer (would otherwise drop every event).

### Credential honeytoken cross-reference

`credential_match.py` runs after suppression in `submit_event`. It loads all
active CREDENTIAL honeytokens into an in-memory dict keyed by
`(service, username_lower, password)`, refreshed every 30s and invalidated
explicitly on `honeytoken_create` / `honeytoken_revoke`.

When a login-attempt event payload contains a planted pair, the event is
mutated in place: `severity` → `CRITICAL`, `honeytoken_id` → the matched
token's id, `event_type` → `honeytoken_triggered_credential_via_<original>`.
The flusher then calls `mark_honeytoken_triggered()` for any flushed event
with that event_type prefix.

Two match paths:

*Plaintext* (`_index`, keyed by `(service, username_lower, password)`) — the
common case. Payload extraction handles:
- SSH/FTP/HTTP form `{"username": ..., "password": ...}` keys directly.
- HTTP `post_data` nested dicts — checks common field aliases
  (`username|user|email|login`, `password|pass|passwd|pwd`).
- SMTP `AUTH PLAIN <b64>` — base64-decodes and splits on `\0` per RFC 4616.

*Hashed* (`_match_hashed`, services in `_HASHED_SERVICES` = `{mysql, vnc}`) —
these protocols never send the plaintext password. MySQL sends a
`mysql_native_password` scramble over a server salt; VNC sends the server
challenge DES-encrypted under the password. Since the engine generated the
salt/challenge (and includes `salt_hex` / `challenge_hex` + the captured
response in the event payload), `credential_verify.py` recomputes the expected
digest for each planted-password candidate and compares. MySQL also matches on
the plaintext username it sends in the clear; VNC is password-only. A parallel
`_candidates` dict (service → `[(user_lower, password, token_id)]`) is built
alongside `_index` at load time to feed this path.

Service is inferred from `event_type` prefix via `_SERVICE_PREFIXES`
(`ssh_*`, `http_*`, `ftp_*`, `smtp_*`, `postgresql_*`, `mssql_*`, `redis_*`,
`mysql_*`, `vnc_*`). Tokens planted with `service="any"` match across all
services (including the hashed ones).

Limitation: the matcher only fires when the planted creds hit one of our own
honeypots. It doesn't observe production-system logins — that needs an IdP
audit-log feed which this project doesn't ship. Documented in
`KNOWN_LIMITATIONS.md`.

### Auto-enrichment of CRITICAL alerts

`event_buffer._enrich_alert_async` is scheduled as a fire-and-forget task
for every CRITICAL event that lands with a globally-routable source IP
(filtered via `_is_enrichable_ip` — drops loopback, RFC1918, link-local,
TEST-NET, and any address Python's `ipaddress` module marks as non-global).
The task fans out parallel VT + AbuseIPDB + GeoIP lookups, then re-opens a
session and merges the result into the alert's `payload.enrichment` dict.

Failures here are swallowed — auto-enrichment is a UX improvement, not a
guarantee. The `intel/_cache.py` TTL dict means repeat CRITICALs from the
same IP within the cache window cost zero external API calls.

### TLS / HTTPS / STARTTLS

`engines/tls.py:ensure_cert` generates a self-signed RSA-2048 cert per
honeypot, persisted to `tls/<honeypot_name>/server.{crt,key}` so a scanner
pinning the cert SHA sees a stable identity across restarts. `cryptography`
is a direct dep.

HTTP: deploy with `config["tls"] = True` to serve HTTPS on the configured
port. The engine wires the cert via aiohttp's `web.TCPSite(ssl_context=...)`.

SMTP: STARTTLS uses `asyncio.start_tls()` to actually complete the TLS
handshake (the previous behaviour announced STARTTLS but dropped on the
ClientHello — itself a fingerprint). After upgrade, the engine clears
protocol state per RFC 3207 and requires the client to re-issue EHLO.

`tls/` is gitignored — keys are private, certs are deployment-specific.

### RDP engine

`engines/rdp.py` is banner-only: parses the X.224 Connection Request,
extracts the leaked `Cookie: mstshash=user[@DOMAIN]` field (almost every
RDP client and brute-force tool sends this in the clear), and returns a
TPKT + X.224 Connection Confirm with a believable NLA-required
negotiation-failure response. No real RDP protocol stack — that's NOT the
goal here; the goal is to catch RDP brute-force traffic, which is one of
the largest internet attack categories.

Logs `rdp_handshake` at HIGH severity when the X.224 parses, `rdp_invalid_probe`
at LOW for port-scan garbage.

### SMB / PostgreSQL / MongoDB engines

Three database/file-share engines aimed at the highest-value public-internet
attack surfaces. All in-process asyncio, same buffer path as the others.

- `engines/smb.py` — tcp/445, the top ransomware initial-access surface.
  Parses the NetBIOS-framed SMB1/SMB2 negotiate, replies to an SMB1 negotiate
  to keep the exploit tool talking, then classifies follow-up packets:
  `smb_exploit_attempt` (CRITICAL) on a DoublePulsar Trans2 SESSION_SETUP
  (0x000e) or EternalBlue pre-auth Trans2, `smb_session_setup` (HIGH) capturing
  readable NTLM strings. Detection-focused, no real file server — same tier as
  RDP.
- `engines/postgresql.py` — tcp/5432. Declines SSL (`N`) so the client falls
  back to cleartext, parses the StartupMessage (user + database), requests
  cleartext auth, and captures the password from the PasswordMessage before
  rejecting with `28P01`. Emits `postgresql_login_attempt` with
  `service="postgresql"` so `credential_match` cross-references planted tokens.
- `engines/mongodb.py` — tcp/27017. Minimal BSON encode/decode + OP_MSG/OP_QUERY
  framing. Answers `isMaster`/`hello`/`buildInfo`/`listDatabases` believably so
  the scanner proceeds, captures each command, and flags `mongodb_destructive`
  (dropDatabase) and `mongodb_ransom_note` (CRITICAL — bitcoin/recover language
  in an insert) with the note text. Replies `ok:1` so the ransom note lands.
  Nothing is persisted or dropped.
- `engines/mssql.py` — tcp/1433 (TDS). Replies to PRELOGIN with `ENCRYPT_NOT_SUP`
  so the client sends Login7 in the clear, then parses the Login7 variable-data
  table to extract hostname/username/password/appname. The password is
  de-obfuscated (`_decode_tds_password`: XOR 0xA5 + nibble-swap over UTF-16LE).
  Emits `mssql_login_attempt` with `service="mssql"`; returns an 18456 ERROR
  token and closes. No query/RPC phase.

Post-auth query capture (like MySQL) also lives in `postgresql.py`: after the
password is captured it ACCEPTS the login (AuthenticationOk + ParameterStatus +
ReadyForQuery) and classifies simple-query traffic — `COPY … FROM/TO PROGRAM`
(CRITICAL RCE), UDF loads, `pg_read_file`/`lo_export` (HIGH), recon (MEDIUM).

### Telnet / Memcached / SNMP / LDAP / Docker API engines

Five additions aimed at surfaces the original catalogue missed entirely.

- `engines/telnet.py` — a ~10-line subclass of `SSHEngine`. One Cowrie
  container serves SSH on 2222 and Telnet on 2223; `_PRIMARY_CONTAINER_PORT`
  and `_PRIMARY_IS_TELNET` decide which one gets published and whether Cowrie's
  telnet listener is switched on. Telnet was previously reachable only as
  `config={"telnet_enabled": True}` on an SSH honeypot, so `honeypot_deploy(
  type="telnet")` failed and captures were filed under type `ssh` — for an
  NL-driven system, a capability that cannot be asked for barely exists.
  Retagging to `telnet_*` happens in `ssh.py:_retag_for_protocol`.
- `engines/memcached.py` — tcp/11211 text protocol. The point is not cache
  data, it is amplification: `stats` measures the reflector, a large `set`
  stages a payload, and a `get` of that key reflects it. The stage-then-fetch
  *sequence* is what raises `memcached_amplification_attempt` (CRITICAL) with a
  measured amplification factor; either half alone is ordinary traffic.
- `engines/snmp.py` — udp/161, BER by hand. v1/v2c put the community string in
  the clear, so every request is a credential capture (`service: "snmp"`, so
  planted community strings cross-reference). Only `public`/`private` are
  answered — a real agent is silent on a wrong community, and answering
  everything would fingerprint the sensor in one packet.
- `engines/ldap.py` — tcp/389, BER by hand. Two populations: simple binds carry
  the DN and password in the clear (invalidCredentials keeps brute-forcers
  cycling), and Log4Shell's second stage arrives here as a searchRequest.
  `looks_like_jndi()` separates the two — a JNDI base object is an opaque token
  from the payload URL with no `dc=`/`cn=`/`ou=` components, or it asks for
  `javaClassName`/`javaCodeBase`.
- `engines/docker_api.py` — tcp/2375, aiohttp. An unauthenticated daemon is
  host compromise, not a foothold. `analyse_container_create()` inspects the
  create body and returns *named* reasons (host root bind, privileged, host PID
  namespace, dangerous caps, miner image, payload command); any hit makes it
  `docker_api_container_escape` (CRITICAL) rather than
  `docker_api_container_create` (HIGH). "Someone POSTed to /containers/create"
  is not actionable; "mounts host / at /mnt and runs chroot" is.

**Neither memcached nor SNMP ever amplifies.** Both are reflection vectors with
trivially spoofed sources, so a faithful large reply would enlist the honeypot
in someone else's DDoS. Both record the reconnaissance and answer minimally.

Adding a type touches five places: `HoneypotType` in `storage/models.py`, the
default port in `config.py`, the `Literal` and `default_ports` dict in
`tools/honeypot.py`, `engines/__init__.py:get_engine()`, and an Alembic
migration (`Enum(...)` is a native PostgreSQL type — `ALTER TYPE … ADD VALUE`,
one statement per value; see `0012_add_five_types`).

### IMAP / SIP / rsync / NFS engines

Four more surfaces, each chosen because its traffic means something specific.

- `engines/imap.py` — tcp/143. Mail is where credential stuffing cashes out: a
  working mailbox owns password resets everywhere else. The greeting
  deliberately omits `LOGINDISABLED` — a hardened server advertises it to force
  STARTTLS, but then the attacker never sends the password, and impersonating
  the misconfigured server is the entire point. Handles `LOGIN` (with IMAP
  quoted-string parsing, so a password containing a space survives) and SASL
  `AUTHENTICATE PLAIN`, both SASL-IR and two-step.
- `engines/sip.py` — tcp+udp/5060, both because a service on only one is a
  tell. Separates the three phases that mean different things: `OPTIONS`
  sweeps (`friendly-scanner` and friends are named in the alert), extension
  enumeration via bare `REGISTER`, and `INVITE` to a satellite or premium
  prefix, which is `sip_toll_fraud_attempt` at CRITICAL. Digest auth is
  challenged with a fresh nonce so the tool computes a response — captured
  *with* its nonce, since that is what makes it crackable.
- `engines/rsync.py` — tcp/873. Backup servers are the usual victim, so the
  exposure is the archive itself. Listing modules is the whole discovery phase
  in one command (`rsync_module_enumeration`, HIGH); selecting a module with no
  `auth users` is `rsync_anonymous_access` at CRITICAL, because the next thing
  the client sends is a file request.
- `engines/nfs.py` — tcp/2049, ONC RPC and XDR by hand. `showmount -e` is one
  MOUNT EXPORT call and discloses everything, so the alert names the exports
  *and* which are shared to `*` — the detail that decides the attacker's next
  move. A MNT of a world-shared export is CRITICAL and granted; a restricted
  one is HIGH and refused. Getting the export list's terminator wrong makes
  `showmount` hang, which is louder than not answering at all.

`nmap -sV` hard-matches all four: `Dovecot imapd`, `Asterisk PBX 18.10.0`
(with `Device: PBX`), `rsync (protocol version 31)`, `rpcbind`.

### POP3 / Kubernetes API engines

The pair that takes the catalogue to 25.

- `engines/pop3.py` — tcp/110. The same botnets sweep 110 and 143 in one pass,
  so a host answering IMAP but refusing POP3 is an odd configuration a scanner
  notices. `USER`/`PASS` sends the password with no encoding at all. `APOP` is
  offered too and its digest is stored *with the challenge that produced it* —
  a hash without its salt is not crackable, and the challenge is ours, so
  keeping both is what makes the capture worth anything.
- `engines/kubernetes.py` — tcp/6443, the cloud sibling of `docker_api`.
  `analyse_pod_spec()` names escape indicators the same way
  `analyse_container_create()` does: `hostPath: /`, host namespaces,
  `privileged`, dangerous capabilities, miner images, payload commands. Reading
  Secrets is CRITICAL on its own, because service-account tokens there are
  usually the whole cluster rather than one workload. Responses carry
  `Audit-Id` and the `X-Kubernetes-Pf-*` flow-control UIDs that a real API
  server always sends, and errors use the `Status` object shape — their absence
  identifies a decoy in one request. It presents as `nginx` because that is
  what actually fronts 6443 in practice.

### HTTP realistic endpoints + sessions

`engines/http_endpoints.py` serves `/robots.txt`, `/favicon.ico`,
`/sitemap.xml`, `/.well-known/security.txt` with persona-aware content.
A 404 on any of these is a single-curl tell for a honeypot. The
`robots.txt` deliberately advertises `/admin/`, `/.env`, etc. — pointing
attackers at exactly the bait.

The engine maintains a per-honeypot in-memory session table keyed by
cookie value (persona's `cookie_name`: `PHPSESSID` / `ASP.NET_SessionId`).
Sessions track hit count; after `_RECON_THRESHOLD` (5) hits, severity
escalates from LOW to MEDIUM and the event type becomes
`http_active_recon`. Sessions older than `_SESSION_TTL_SECONDS` (1h) are
pruned opportunistically on each lookup — no separate sweeper task.

Every request is also scanned for exploit signatures (`_classify_http_attack`
over `_HTTP_ATTACK_SIGNATURES`) across the full surface — path, query, all
header values, User-Agent, and body — with the surface additionally URL-decoded
so `%`-encoded payloads don't slip past. A hit re-tags the event to
`http_exploit_attempt`, raises severity to at least the matched level, and adds
`payload.exploit_categories`. Covers Log4Shell, Shellshock, command injection,
webshell upload, OGNL/Struts, Spring4Shell, SQLi, path traversal, LFI/RFI,
SSRF, deserialization, and XSS. Broad patterns are fine here — a honeypot has
no legitimate users, so false positives cost nothing.

### Webhook delivery

`webhooks.py` runs a single background worker that drains a queue. Decoupled from the buffer's flusher — slow webhook endpoints can't slow honeypot ingestion.

Signature: `X-HoneyPot-Signature: sha256=<hex>` (HMAC-SHA256 of raw body) — same convention as GitHub webhooks. Consumers verify with the shared secret.

Failure tracking is per subscription: `delivery_count`, `failure_count`, `last_error`. After repeated failures, an admin can deactivate via `alert_unsubscribe` or repair via DB.

Active subscriptions are cached in-process (`_active_subscriptions`, 30s TTL) so delivery doesn't issue a `SELECT … WHERE active` per event on the ingest hot path — the same pattern as the suppression-rule cache. The cache is invalidated on `alert_subscribe`/`alert_unsubscribe` and on worker `start()`. Rows are `expunge_all`'d from the loading session so the per-delivery stat UPDATEs (`_record_outcome`) never interact with the cache. If a test inserts a `Subscription` directly (not via the tool), call `invalidate_subscription_cache()` or start a fresh delivery worker to pick it up.

### Watchdog

`watchdog.py` runs every 30s. For each `RUNNING` honeypot, calls
`engine.health_check(container_id, port)`. On failure: flips DB status to
ERROR, emits a CRITICAL `honeypot_health_failed` alert through the normal
event pipeline (so it lands in DB + fires webhooks).

`HoneypotEngine.health_check()` default is a TCP probe. SSH overrides to also
check Docker container status. DNS overrides because UDP — sends a real DNS
query and waits for any reply.

The `_reported_dead` set prevents alert spam: a dead honeypot generates exactly
one alert. If it later recovers (becomes alive again), the entry is cleared, so
a subsequent failure will alert again.

**Probes must not become attack data.** Ten in-process engines log a bare
`<proto>_connection` event on TCP connect, and a health probe is
indistinguishable from a real peer at the engine. `self_probe.py` closes that
loop: `tcp_probe` (and the DNS UDP probe) calls `self_probe.register()` with
the local `(ip, port)` the kernel gave the probe socket, and `submit_event`
drops the single event arriving from exactly that address. Matching the full
socket tuple — rather than suppressing `*_connection` from loopback — is
deliberate: loopback traffic to a honeypot is a genuine signal (container
escape, malicious process on the host) and must keep alerting. Any new probe
that opens a connection to an engine needs the same `register()` call, or it
will show up as an attacker.

The watchdog also hosts the **retention sweep** (`_maybe_prune`): opt-in via
`retention_days > 0` (default 0 = off), it deletes alerts + attacker_events
older than the cutoff at most once per `retention_sweep_interval_hours`
(default 24h), tracked with a monotonic `_last_prune_at`. Folded in here rather
than as a separate lifespan task — same operation as the manual `alerts_prune`
tool, just automatic. On a public IP the DB otherwise grows without bound.

### Per-IP connection caps

`engines/conn_limit.py` caps concurrent connections per source IP for the
in-process TCP engines. `ConnectionLimiter(max_per_ip)` counts live
connections; `limited_factory()` wraps a `create_server` protocol factory
(VNC/Redis/MySQL/PostgreSQL/MSSQL/MongoDB/SMTP) and `limited_handler()` wraps a
`start_server` coroutine handler (SMB). Each engine holds one limiter in
`__init__`, sized from `max_connections_per_ip` (default 32, 0 = unlimited).
Over-cap connections are accepted then immediately closed, and the wrapped
`_LimitedProtocol` never drives the real protocol for a rejected peer — so its
state machine only ever runs for admitted connections. The aiohttp engines
(HTTP/Elasticsearch) are not wrapped; they rely on aiohttp's own limits.

### Startup reconciliation

`reconcile.py` runs once from `lifespan`, AFTER the event buffer starts and
BEFORE the watchdog (ordering matters — otherwise the watchdog races it to
mark restartable honeypots dead). MCP clients relaunch this server per chat
session, so every start is a process restart, and anything the DB left
`RUNNING` must be re-established:

- In-process engines (HTTP/SMTP/FTP/DNS/RDP/VNC/Redis/MySQL/Elasticsearch)
  died with the previous process — they get restarted on their recorded port.
- Cowrie SSH containers survive (`restart_policy=unless-stopped`), but the
  log-ingestion task doesn't — without re-attaching it, attacks land in
  Cowrie's logs and never become alerts while health checks still pass.

Each engine's `reattach(name, port, config, container_id)` encapsulates the
right behaviour (base default = `start()` fresh; SSH overrides to re-attach
ingestion to the live container). A honeypot that can't be re-established is
flipped to ERROR with a CRITICAL `honeypot_restart_failed` alert; startup
never aborts.

Note: `SSHEngine` holds strong references to ingestion tasks in
`self._ingest_tasks` — asyncio only weakly references tasks, so an unreferenced
one can be GC'd mid-run, silently stopping capture.

**Container adoption.** `adopt_labelled_containers()` runs straight after
reconciliation. A Cowrie container only produces alerts if something tails its
logs, and that only happens for containers with a `Honeypot` row pointing at
them — so anything started outside this process (the compose stack's
`cowrie-ssh`, above all) captured attacks into its own logs and raised nothing,
while `docker ps` and the port both looked healthy. Adoption claims containers
labelled `honeypot-mcp=true`, creating or re-pointing the row and attaching
ingestion. It matches on the published host port, skips containers with no
published port (unreachable, so registering one would be a lie), and re-adopts
rows stuck in ERROR rather than skipping on container id alone.

**SSH health checks probe twice.** `port` is the *host* published port, which
is only on loopback when the server runs on the host. In the compose stack the
server is a container and Cowrie is a sibling, so `127.0.0.1:2222` there is the
server's own empty loopback — probing only that marked a working honeypot dead
every 30s. On failure the check falls back to the container's own IP on
`COWRIE_INTERNAL_PORT`.

**The watchdog sweeps ERROR honeypots too, not just RUNNING.** Watching only
RUNNING made ERROR a one-way door: the first failed probe set ERROR, and ERROR
rows were excluded from every later sweep, so a honeypot that recovered stayed
marked dead forever and was never checked again. A honeypot that answers again
is flipped back to RUNNING (`_mark_recovered`), with no alert — recovery is
good news, and alerting on it would make a flapping honeypot noisy.

### Canary callback server

`canary.py` runs an aiohttp server on `canary_callback_host:canary_callback_port` (default `0.0.0.0:8888`). Started/stopped from `lifespan` alongside the DB.

Routes:
- `GET /t/{token_id}` — matches against `token_meta.token_id` (canary URL tokens) or `token_meta.token_uid` (file tokens). On match: marks `TRIGGERED`, writes a CRITICAL alert, creates an `AttackerEvent`. Returns generic `200 OK` so attackers can't fingerprint.
- `GET /t/{token_uid}.png` — same matching, returns a 1x1 transparent PNG. Used by PDF file tokens that embed `<img src="...">`.

### Threat intel caching

`intel/_cache.py` is a monotonic-clock TTL dict. Used by `virustotal`, `abuseipdb`, `geoip` lookups. **Only successful responses are cached** — errors and rate-limit hits are NOT cached so callers always retry.

TTLs: VT 30 min, AbuseIPDB 15 min, GeoIP 24 h.

### MITRE ATT&CK

`intel/mitre.py` ships built-in regex mappings keyed by event-type/payload patterns. `_load_stix_index()` is `lru_cache`d and returns `{technique_id: stix_object}` — the index is built once, not on every `map_to_attack` call. If `config/mitre_attack.json` exists, technique descriptions are added; otherwise the built-in mappings still produce technique IDs and tactics.

### Protocol fidelity

An engine that accepts connections but is distinguishable from the software it
impersonates is broken, not merely imperfect: a scanner that fingerprints the
decoy stops sending the attack traffic the honeypot exists to collect. So
engines are validated against **real clients** (redis-py, pymongo, psycopg) and
against `nmap -sV --version-intensity 9`, not just unit tests.

`tests/unit/test_protocol_fidelity.py` pins every finding and quotes the nmap
signature each check encodes, so a change that breaks identification fails
loudly. Re-run the sweep after touching any engine's wire format.

Recurring failure modes found this way, worth checking in new engines:

- **Missing handshake commands.** Redis advertised 7.0.5 but never implemented
  `HELLO`, so every modern client failed at connect and captured nothing.
- **Self-inconsistent version claims.** MongoDB reported 5.0.14 in `buildInfo`
  while negotiating wire version 8 (that's 4.0). Keep one constant per engine
  (`_REDIS_VERSION`, `_MONGO_VERSION`, `_SQL_VERSION`) and derive everything.
- **Structurally thin responses.** MSSQL's PRELOGIN carried 2 of the 4 options
  real SQL Server always sends, producing a packet length no signature matches.
- **Silence where the real service speaks.** PostgreSQL closed mutely on a
  malformed startup packet; the FATAL ErrorResponse it *should* send is
  precisely how scanners identify PostgreSQL.
- **Not echoing correlation fields.** SMB must echo the client's TID/PID/UID/MID
  — a protocol requirement, and its absence broke nmap's signature.
- **Zero/epoch placeholder values.** SMB `SystemTime` of 0 is 1601-01-01;
  MongoDB `localTime` of 0 is 1970-01-01. Both render in any real client.

### aiohttp server identity

`http_identity.py` controls the `Server` header for every aiohttp server in the
process (HTTP engine, Elasticsearch engine, canary callback). Two mechanisms,
because one is not enough:

1. `server_identity_middleware(server, extra)` pins the header on application
   responses — used for the HTTP persona, Elasticsearch, and the canary.
2. A module-import side effect rebinds `aiohttp.web_response.SERVER_SOFTWARE`.
   Middleware **cannot** reach protocol-level errors: a malformed request line
   is rejected in `RequestHandler.handle_error` without ever entering the app,
   and that response would otherwise carry `Server: Python/3.x aiohttp/3.y.z`.
   One junk request thereby exposed the stack behind every persona. aiohttp
   offers no supported hook, so rebinding the default is the available fix; it
   only changes the fallback, and explicit headers still win.

3. `identity_runner(app, banner)` covers the case middleware cannot reach *and*
   the global gets wrong: protocol-level errors. It subclasses `AppRunner`,
   `Server` and `RequestHandler` so `handle_error` stamps that listener's own
   banner. Before it, one process-global served every listener, so an
   Apache-persona honeypot answered a malformed probe as nginx — and since
   `nmap -sV` deliberately sends malformed probes, that is what it matched on.
   Every persona leaked at the same seam.

`ExactHeaderResponse` handles the last mile: it suppresses the `Server` header
entirely (aiohttp's `setdefault` otherwise guarantees one) and pins header
order. Both matter because scanner signatures are anchored regexes over the
whole response — nmap's Docker rule wants `Content-Type`, `Date`,
`Content-Length: 29` in that order with nothing else, and `Content-Length`
before `Date` is enough to miss. Header order is semantically irrelevant to
HTTP and entirely relevant to fingerprinting.

Any new aiohttp server must use `identity_runner` and set its own identity;
`web.AppRunner` alone leaves the protocol-error path wearing the wrong name.

### Intent-level tools (`deception/`)

Most tools map one-to-one onto an operation — deploy this, list that. Three do
not, and they are the reason a natural-language interface beats a thinner
wrapper over the same API:

- `deception_plan` — an environment description becomes a coherent set of
  sensors and tokens. The division of labour is deliberate: the *model* reads
  "a customer portal and a Postgres warehouse behind it" perfectly well, so the
  planner supplies only what the model cannot know — which ports are taken,
  which identities have to agree, which tokens would be inert. It deploys
  nothing; answering a question must not open listeners.
- `deception_coverage` — sensors and tokens mapped to ATT&CK. Computed by
  pushing each engine's real `signature_events` through `intel.mitre`, so it
  cannot drift from what the alerts actually say. An engine whose events are
  unmapped shows up as missing coverage, which is correct — it is invisible on
  the dashboard too.
- `soc_brief` — separates untriaged CRITICAL/HIGH, token trips and dead sensors
  from the volume that makes up most honeypot traffic.

`deception/capabilities.py` is the single source of truth for what an engine
is: port, OS family, roles, the `service` label its credentials carry, and its
signature events. `honeypot_templates`, the planner and the coverage map all
read from it. They previously each held a copy, and `honeypot_templates` had
already drifted — still describing fourteen types after five more shipped, with
nothing erroring. A test asserts the registry matches `HoneypotType` exactly.

**Coherence checking is the differentiating logic.** Hand-built deception fails
on mismatched detail more often than on missing detail: an attacker who touches
two decoys and finds they disagree has learned more than one who finds nothing.
`check_coherence` flags a directory server with no Windows services behind it,
RDP with no SMB, and — as an *error* rather than a warning — a credential token
targeting a service no deployed sensor captures, which can never fire and fails
silently. `test_planned_tokens_always_target_a_deployed_service` asserts the
planner never emits that for its own output.

### Tool response shaping

An MCP tool result lands directly in a model's context window, so response
*size* is a correctness concern, not a style preference. Honeypot payloads are
the worst case: the HTTP engine captures every request header plus up to 64 KB
of base64 body per event (`_MAX_RAW_BODY_BYTES`), so an unshaped 200-row
triage query returns megabytes and can consume a whole context in one call.

The rule: **list tools summarise, detail tools expand, bulk goes to disk.**

`tools/_format.py` implements it:
- `digest_payload()` — keeps the fields analysts triage on (credentials, path,
  command, exploit categories, lifted geo/VT/AbuseIPDB verdicts), drops bulk
  (`headers`, `raw_body_b64`, `cookies`, nested `enrichment`), clips values at
  160 chars. Unknown keys still pass through, so a new engine's fields aren't
  invisible just because the allow-list predates it.
- `truncate_payload()` — full structure, clips only individually oversized
  values (4,000 chars) with an explicit marker. For detail tools.
- `validate_ip()` — every IP reaching a tool was transcribed by a model reading
  an alert, so a typo is realistic. Without validation the query matches
  nothing and reports "no activity", which reads as a clean bill of health.

So: `alerts_recent`/`alerts_search` return digests, `alerts_get` returns the
full payload, and every bulk producer — `alerts_export`, `export_stix`,
`export_blocklist`, `generate_report` — writes a file via
`_format.write_artifact()` and returns the path plus headline figures. Those
outputs are destined for a firewall, a TIP or a browser, and they scale with
attacker count rather than with anything the caller chose: a STIX bundle for a
few hundred alerts exceeds 100 KB. New tools that return per-row captured data
or bulk artifacts should follow the same split. List tools also
return `{count, alerts: [...]}` rather than a bare list, so they can carry a
`window` and a `note` when results were truncated at the limit — a caller must
never read a capped list as the complete picture.

Time filtering (`since_hours`) belongs on anything an analyst asks about
"recently" — it is the single most common natural-language qualifier.

### Alert query indexes

`alerts` carries two composite indexes (`0010_add_alert_query_indexes`) because
every triage path filters on a time window plus either severity or source IP.
Measured at 500k rows: severity+window 30.7 ms → 5.4 ms, ip+window 23.6 ms →
0.04 ms. The single-column indexes can't serve those pairs, and `severity` had
no index at all. Keep new query patterns in mind here — an unindexed filter on
a hot path is invisible until the DB is large.

### Reports

`analysis/reporter.py` uses Jinja2 with `autoescape=select_autoescape(["html", "xml"])`. Markdown rendering escapes pipe / backslash / newline in cell values via `_md_cell()`. Attacker-controlled fields (IPs, event types, payload values) cannot break out of either format.

### Docker

SSH honeypots use Cowrie via Docker (`docker/cowrie/cowrie.cfg`). The HTTP honeypot has a minimal Docker image at `docker/http-honeypot/`. Run the full stack from `docker/`:
```bash
docker compose up -d
```
SMTP, FTP, DNS engines run in-process as asyncio servers — no Docker.

### Settings

`config.py` uses `pydantic-settings` (`BaseSettings`). Values come from environment variables and `.env`, accessed through the `get_settings()` singleton — that is the only configuration mechanism.

A `config/settings.yaml` overlay used to be loaded alongside it. Nothing ever read from it: the accessor was defined and never called, so editing that file silently changed nothing while this document presented it as a config source. It was removed rather than wired up — every value it described already exists as a setting, and one authoritative mechanism beats two where one is a decoy. `config/` now holds only operator-supplied runtime files (GeoLite2 databases, override suppression presets), all gitignored.

### MCP transport + control-plane auth

`server.py:main()` dispatches on `mcp_transport`. `stdio` (default) is the per-chat subprocess Claude Desktop/Code spawn — inherently local, no auth. `http`/`sse`/`streamable-http` run a persistent networked daemon.

`none` is collector mode: `_run_collector()` enters the `lifespan` context and waits on an `asyncio.Event` armed by SIGTERM/SIGINT, so the whole capture plane (engines, canary server, watchdog, webhook delivery, `/metrics`) runs with no MCP transport at all. This is the only correct mode for a detached container — stdio there reads EOF from an unattached stdin and exits immediately, which restart-loops forever. `docker-compose.yml` sets `MCP_TRANSPORT=none` for exactly this reason. Since it exposes no control plane, `_networked_auth_error()` treats it like stdio and requires no token.

The networked control plane can deploy honeypots and read all captured data, so it's **fail-closed**: `main()` calls `_networked_auth_error()` and refuses to start (`SystemExit`) if the transport isn't stdio and neither `mcp_auth_token` nor `mcp_allow_unauthenticated` is set. When `mcp_auth_token` is set, `_build_auth()` attaches FastMCP's `StaticTokenVerifier` (from `fastmcp.server.auth.providers.jwt`) at construction, so clients must send `Authorization: Bearer <token>` (401 otherwise). `_build_auth()` returns `None` for stdio, so the auth object never affects the local path or the test suite (which runs over in-memory stdio). `_networked_auth_error()` is a pure function for testability.

## Optional external dependencies

All degrade gracefully when missing — they return `{"available": False, "note": "..."}` instead of raising.

- `VIRUSTOTAL_API_KEY` — IP reputation via `intel/virustotal.py`
- `ABUSEIPDB_API_KEY` — IP abuse reports + outbound reporting via `intel/abuseipdb.py`
- `GEOIP_DB_PATH` — path to `GeoLite2-City.mmdb` (free MaxMind registration)
- `CANARY_PUBLIC_URL` — public URL where canary tokens phone home (default `http://localhost:8888`; use ngrok for testing from the internet)

## Common gotchas

- Tools decorated with `@mcp.tool` are still plain async functions — call them directly in tests, no `.fn` accessor.
- `submit_event()` is the ONLY way engines should write events. Direct `get_session()` writes from engines bypass suppression and webhook delivery.
- Adding a new MCP tool module? Add an `import honeypot_mcp.tools.<name>` line at the bottom of `server.py` or it won't register.
- Test files set `DATABASE_URL=sqlite+aiosqlite:///:memory:` at module top BEFORE importing anything from `honeypot_mcp.*` — order matters because `config.get_settings()` is cached.
- The `EventBuffer` is a process-lifetime singleton. Test fixtures that touch it must call `event_buffer.reset_for_tests()` in setup AND teardown — `asyncio.Queue` is bound to the event loop it was created in, and pytest-asyncio gives each test a fresh loop.
- Schema changes need a migration: `uv run alembic revision --autogenerate -m "description"`. The autogenerated file is a starting point, not a final answer — review it before committing.
- `uv sync` without `--extra dev` installs runtime deps only — pytest, ruff, mypy land outside the venv and `uv run pytest` then silently falls through to whatever's on PATH (often Anaconda). Always use `uv sync --extra dev` when developing or testing.

### Data lifecycle: bulk operations, archival, rotation

Three operations that only matter once the tool has been running a while, and
were missing for exactly that reason.

**`honeypot_stop` takes a set, not a name.** A deployment is twenty-plus
sensors, so one call per sensor is not a workflow. It accepts `name`, `names`,
or a `type`/`status` filter (`type="all"` for the whole estate). A call with
none of those is *rejected* rather than interpreted — the natural default would
be "everything", and silently ending all collection is not recoverable. An
unknown name aborts the whole call rather than partially stopping, so the
caller can fix the list and retry.

**Pruning archives before it deletes.** `alerts_prune` and the retention sweep
destroy evidence permanently — a campaign that began eleven months ago, gone,
along with anything a later investigation would have needed. Both now write
matching alerts to JSON Lines (full payloads, one object per line, streams into
`jq`/Splunk/S3) before removing anything, and **a failed archive cancels the
delete** rather than proceeding without one. `archive=False` /
`RETENTION_ARCHIVE=false` opts out deliberately. The unattended sweep matters
most here: nobody is watching when it runs.

**`honeytoken_rotate` keeps the thread.** Revoke-then-create severs it — "this
credential has fired three times in eight months" becomes three unrelated
incidents, and the old value stops being attributable. Rotation issues a new
secret, carries label/type/settings/`planted_at` across, marks the old token
REVOKED but *retains* it so historical triggers still resolve, and links the
pair with `rotated_from`/`rotated_to`. Provider-generated fields are
deliberately excluded from the carry-over set, or the "new" token would be the
old one.

### Triage state

`alerts.acknowledged` alone only records that somebody looked. `disposition`
(`true_positive` / `false_positive` / `benign` / `duplicate`), `triage_note`,
`triaged_by` and `triaged_at` record what they concluded, which is what lets a
shift hand over and what makes "what are we dismissing, and should it be
suppressed instead?" answerable.

`benign` is deliberately distinct from `false_positive`: a false positive means
the detection was wrong, benign means it fired correctly on authorised activity.
Conflating them makes tuning metrics meaningless.

`alerts_acknowledge` takes either explicit `alert_ids` or a filter
(`source_ip` / `event_type` / `severity` / `since_hours`) and triages the whole
match — a scanner sweep is hundreds of alerts and one-at-a-time acknowledgement
is not a workflow. `queries.triage_alerts` deliberately SELECTs before it
UPDATEs so it can report the match count and whether `max_alerts` truncated the
set; an over-broad filter silently clearing thousands of alerts is not
recoverable. A call with neither ids nor filters is rejected.

### Control-plane audit log

Every state-changing tool call appends to `audit_log` via
`tools/_audit.py:record_action()`; `audit_log_search` reads it back. The control
plane is driven by a language model, so "what did the agent do?" is a question
an operator will need answered — `alerts_prune` can delete months of evidence
and `honeypot_stop` can silently end collection.

Two invariants:
- **Auditing never breaks the action.** `record_action` swallows and logs its
  own failures; refusing to stop a honeypot because the audit table is
  unavailable would be the worse outcome.
- **Secrets never land in the log.** Arguments are recorded, so
  `redact_arguments()` masks anything whose key contains secret/token/password/
  api_key/credential/auth before persisting.

Currently audited: `honeypot_deploy` (success and failure), `honeypot_stop`,
`honeytoken_revoke`, `alerts_prune`, `alerts_acknowledge`. Add a
`record_action` call to any new tool that changes state. Reads are not audited —
they are high-volume and low-consequence. The table is append-only and the
retention sweep does not touch it.

### ATT&CK mapping and risk scoring

Both are analyst-facing outputs where being *wrong* is worse than being absent,
because SOC analysts know ATT&CK and will check the numbers.

**`intel/mitre.py`** — tactics follow ATT&CK Enterprise exactly. Brute Force
(T1110) is **Credential Access**, not Initial Access; an earlier revision filed
the SSH/FTP/RDP variants under Initial Access while filing the identical
technique under Credential Access three entries later. Coverage is aligned to
what the engines actually emit — grep the engines for `event_type=` and make
sure every high-value one maps, because an unmapped capture is invisible in the
ATT&CK dashboard and the kill-chain timeline. Patterns are ordered
most-specific-first and all matches are collected, so a generic rule must never
be the only hit. Watch for cross-category false positives: `smb_exploit_attempt`
contains "attempt" and previously matched the brute-force rule, inflating
Credential Access while hiding the Lateral Movement finding.

**`analysis/profiler.py:_calculate_risk`** — weighted toward what was observed
locally, not what a feed says. Two properties the tests pin:

- *Direct observation alone can reach CRITICAL.* VirusTotal and AbuseIPDB are
  optional; they previously supplied 60 of ~90 attainable points, so with no
  API keys (the default) an attacker who ran a full RCE chain and tripped a
  planted credential could not exceed 30 — MEDIUM. For a deception platform
  that is backwards: our own capture outranks a reputation lookup.
- *A triggered honeytoken dominates.* It is the highest-fidelity signal the
  platform produces and previously contributed nothing beyond its severity.

Volume is deliberately weighted low — one determined scanner produces thousands
of events, and ranking by noise buries the dangerous attacker. Retune the
weights freely; the tests assert ordering and band reachability, not exact
numbers.

### Operations console

`console/` serves a read-only web dashboard (default `127.0.0.1:8090`, set
`CONSOLE_PORT=0` to disable) from the same process as the honeypots: one HTML
file plus a `/api/overview` JSON endpoint the page polls every 5s. Started from
`lifespan` alongside canary and metrics; a bind failure is logged, never fatal.

Three constraints shape it:

1. **Read-only, structurally.** The page has no authentication, so it must not
   be a second control plane — the router registers GET routes only and
   `test_console_is_read_only` asserts that no other method ever appears.
   Deploying and stopping stays on the MCP interface.
2. **The feed ships digests, not payloads.** At a 5-second poll, sending full
   captures would move megabytes a minute to tell the viewer nothing extra; it
   reuses `tools/_format.digest_payload`.
3. **Port 8090, not 8080.** 8080 is `default_http_port`, so the console would
   collide with the first HTTP honeypot anyone deploys.

Chart colours are not free choices. The severity split is **two** series
(routine = low+medium, serious = high+critical) rather than four bands, because
four adjacent stacked marks cannot be told apart reliably — a green→amber→
orange→red ramp fails both the CVD and normal-vision separation floors no
matter how it is stepped. Two well-separated hues (`#3987e5` / `#e66767`) pass
on the console's dark surface; magnitude bars use a single hue. Severity per
event is carried by a **text label** (`LOW`/`MED`/`HIGH`/`CRIT`) with colour as
reinforcement, never colour alone. Re-run the palette validator if these change.

Grafana still owns historical dashboards and the geo map; the console answers
the three questions someone walking up to a screen has — is everything up, is
anything on fire, what just happened.

### Security boundaries

A security review found two crossable boundaries; both are now enforced and
pinned by `tests/unit/test_security_boundaries.py`. The threat model that makes
them matter is unusual and worth holding in mind when adding tools:

**The control plane is driven by a model that reads attacker-authored data.**
Captured usernames, paths, commands and User-Agents are attacker-chosen strings
that reach the same context deciding which tools to call with which arguments.
So a tool parameter that reaches the filesystem is reachable, in principle, by
someone who never authenticated. "The caller is trusted" is not sufficient
reasoning for this codebase.

- **Artifact writes are confined to `reports_dir`** via
  `_format.resolve_artifact_path()`. Exports embed captured payloads, so an
  unconstrained `output_path` was an arbitrary-file-write primitive with
  attacker-chosen content. Any new tool that writes a file must route through
  that helper rather than taking a `Path` directly.
- **Honeypot names cannot become paths.** `_format.validate_honeypot_name()`
  restricts them to a Docker-compatible character set; `tls._cert_dir()`
  re-checks at the point a name becomes a path, because reconciliation and
  cloning also reach it.

Already verified sound, so don't re-litigate without new evidence: HMAC
comparisons use `compare_digest`; there is no `eval`/`exec`/`pickle`/`yaml.load`
anywhere; SQL goes through SQLAlchemy parameter binding (the one raw `text()`
uses bound parameters); the console escapes every interpolation of
attacker-controlled data before it reaches the DOM; `/cloud-event` refuses all
requests until `CLOUD_EVENT_HMAC_SECRET` is set.

### Packaging

Non-Python assets must be declared in `pyproject.toml`'s
`tool.hatch.build.targets.wheel.artifacts` **and** loaded through
`importlib.resources`, never by walking up from `__file__`. Two things live
inside the package for this reason:

- `console/static/index.html` — the console 500s without it.
- `presets/*.yaml` — bundled suppression presets. These previously sat in
  `config/suppression_presets/` beside the source tree with a fallback that
  resolved to a path inside site-packages that never exists, so a pip-installed
  user saw an empty preset list for a feature the README advertises. Nothing
  failed loudly; the list was just empty.

The failure mode is identical in both cases: the wheel builds, installs and
imports cleanly, then misbehaves at runtime. `tests/unit/test_operational.py`
asserts both resources resolve, and the release workflow installs the wheel
into a clean environment *outside the source tree* and checks them again —
running from the repo root hides the bug entirely.

Version lives in two places (`pyproject.toml` and `__init__.py`); a test
asserts they agree and the release workflow refuses a mismatched git tag.

### Ingest throughput and the one way data is lost

Measured, not estimated (SQLite, batch=50, flush_interval=1.0):

| | |
|---|---|
| Sustained commit rate | ~1,550 events/sec |
| 20,000-event burst | zero loss, drains in 12.9s |
| 200 events/sec sustained | zero loss, queue depth stays at ~200 |
| Storage | 477 bytes/event |

The queue is **unbounded**, so nothing is ever dropped on the way in and
`submit_event` never blocks — enqueue benchmarks around 149k/sec and that
number means nothing. Commit rate is the real ceiling.

That leaves exactly one path where a captured event disappears: `stop()` drains
for `shutdown_drain_seconds` (default 5) and discards whatever is still queued.
A load test queued 50,000 events and lost 40,850 that way while logging only
"flusher did not exit cleanly" — no count, no cause. It now logs at ERROR with
the number discarded and names the setting that fixes it, and
`honeypot_event_queue_depth` exposes the backlog as a Prometheus gauge so the
condition is visible before a restart converts it into loss. Depth should
oscillate around one flush interval's worth of traffic; a number that climbs
means ingest is outrunning the database.

Raise `shutdown_drain_seconds` for a slow or remote database — the same backlog
takes proportionally longer there.

### Test timing

`tests/conftest.py` sets `EVENT_FLUSH_INTERVAL_SECONDS=0.05`. This is not
cosmetic: the suite contains ~44 `await asyncio.sleep(1.0)` calls followed
immediately by a query for rows the event buffer wrote, and the buffer's
default `flush_interval` is also 1.0 second. Those waits sit exactly on the
boundary — they win on an idle laptop and lose on a loaded CI runner, so the
failure appears on whichever engine test lost the race that run, in whichever
Python version happened to be slow. Two separate CI failures were traced to it.

Shortening the interval for tests gives a 20x margin without rewriting the
assertions, and made the unit suite ~26% faster as a side effect. If you add a
test that waits for a flush, prefer polling until the row appears (see
`tests/integration/test_pipeline.py:_alerts_after_flush`) over a fixed sleep.

The interval is a real setting, not a test-only hook — operators can lower it
to reduce alert latency.
