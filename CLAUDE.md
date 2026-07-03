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

# Tests (257 unit tests covering security-critical paths)
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
Engine (SSH/HTTP/SMTP/FTP/DNS/RDP)
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

Default is SQLite (`honeypot_mcp.db`). Swap `DATABASE_URL` in `.env` to a PostgreSQL URL — zero code changes.

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

Payload extraction handles:
- SSH/FTP/HTTP form `{"username": ..., "password": ...}` keys directly.
- HTTP `post_data` nested dicts — checks common field aliases
  (`username|user|email|login`, `password|pass|passwd|pwd`).
- SMTP `AUTH PLAIN <b64>` — base64-decodes and splits on `\0` per RFC 4616.

Service is inferred from `event_type` prefix (`ssh_*`, `http_*`, `ftp_*`,
`smtp_*`). Tokens planted with `service="any"` match across all services.

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

### Webhook delivery

`webhooks.py` runs a single background worker that drains a queue. Decoupled from the buffer's flusher — slow webhook endpoints can't slow honeypot ingestion.

Signature: `X-HoneyPot-Signature: sha256=<hex>` (HMAC-SHA256 of raw body) — same convention as GitHub webhooks. Consumers verify with the shared secret.

Failure tracking is per subscription: `delivery_count`, `failure_count`, `last_error`. After repeated failures, an admin can deactivate via `alert_unsubscribe` or repair via DB.

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

### Reports

`analysis/reporter.py` uses Jinja2 with `autoescape=select_autoescape(["html", "xml"])`. Markdown rendering escapes pipe / backslash / newline in cell values via `_md_cell()`. Attacker-controlled fields (IPs, event types, payload values) cannot break out of either format.

### Docker

SSH honeypots use Cowrie via Docker (`docker/cowrie/cowrie.cfg`). The HTTP honeypot has a minimal Docker image at `docker/http-honeypot/`. Run the full stack from `docker/`:
```bash
docker compose up -d
```
SMTP, FTP, DNS engines run in-process as asyncio servers — no Docker.

### Settings

`config.py` uses `pydantic-settings` (`BaseSettings`). Values come from `.env` (highest priority) then `config/settings.yaml`. Access via the `get_settings()` singleton.

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
