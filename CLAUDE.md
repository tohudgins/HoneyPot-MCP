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

# Tests (67 unit tests covering security-critical paths)
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
Engine (SSH/HTTP/SMTP/FTP/DNS)
  → submit_event(PendingEvent)             # storage/event_buffer.py
  → suppression.should_suppress(event)     # in-memory rules, dropped here are gone
  → EventBuffer queue
  → flusher task (single async task, batches up to 50, max 1s wait)
  → DB transaction (Alert + AttackerEvent rows)
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

Known schema leftover: `AttackerProfile.shodan_data` JSON column is unused (Shodan was removed). Left in place — when you next touch the model, generate a migration that drops it.

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
