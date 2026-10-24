# Lessons

The stories behind the rules in [../CLAUDE.md](../CLAUDE.md). CLAUDE.md states each invariant as a rule
with a one-line reason; this file keeps the longer account of what went wrong, what was measured and why
the rule exists, organised by topic. Read it when you are about to change one of those rules, or when a
rule looks arbitrary.

Notes on reading it:

- The text is preserved from the time it was written. Where it says "now" or "used to", it means relative to
  that incident, and tool names are those of the time: several tools have since been merged (for example
  `honeytoken_generate_*` into `honeytoken_create`, `export_blocklist`/`export_stix` into `export_indicators`,
  `honeypot_health` into `honeypot_status`, `map_ttps` into `attack_summary`) and the vendor blocklist pushes
  were removed. CLAUDE.md describes the current tool set.
- Section titles are the ones CLAUDE.md's rules were distilled from; the rules themselves are in CLAUDE.md.


## Ingest, storage and data volume

What the database and the ingest path taught us: statistics must not scan the alert table, queries need indexes, and a flood is volume rather than intelligence.


### Database layer

`storage/database.py` exposes a single context manager `get_session()`. Auto-commits on clean exit, auto-rolls back on exception. Sessions aren't shared across blocks — each `async with` is its own transaction.

**Statistics read rollups, never the alert table (`storage/rollups.py`, `alert_rollups`).** A public
host's alert table grows by millions of rows a day (one SIP flood took it from 1.1M to 4.9M rows in
nine hours, 3.8 GB, past the host's RAM) and every aggregate over it becomes a full scan:
`honeypot_list` took 51 s and `alerts_stats`/`soc_brief` timed out. So the cost of a statistic must
depend on the size of the answer. `alert_rollups` counts alerts per hour per (severity, event type,
source, sensor). It is written by a `before_flush` hook on `Session` (`rollups.install()`, called
when `database` is imported), so **every** Alert writer is counted in the same transaction as the
row, a rolled-back transaction takes its counts with it, and nobody can forget to call a helper. A
windowed query (`rollups.window`) takes whole hours from the rollups and the two partial edges from
the alert rows, unioned and aggregated in the database, so it is exact to the second; pruning raw
alerts does not change lifetime figures. `alerts_stats`, `soc_brief`, `honeypot_list`, the
analyst's per-source profile and journey totals, the blocklist/campaign candidates and `/metrics` all
read it. `ix_alerts_acked` and `ix_alerts_urgent` are small *partial* indexes (acknowledged rows;
CRITICAL/HIGH rows) so the triage queue never touches the LOW/MEDIUM flood: untriaged = total minus
acknowledged, and the "needs attention" list seeks `ix_alerts_urgent`. `attacker_events` now keeps
only honeytoken-linked events (it used to copy every event, payload included). When adding a query
over alerts, ask first whether it belongs on the rollups; `tests/unit/test_rollups.py` checks every
windowed statistic against a brute-force count and `tests/unit/test_query_plans.py` pins plans.
Two traps found the hard way: on PostgreSQL `coalesce(x, $3)` in SELECT and `coalesce(x, $5)` in
GROUP BY are different expressions (use a literal), and the in-memory test database is one shared
connection, whose pool reset rolled back other sessions' uncommitted writes (the engine disables
reset-on-return for `:memory:`; see `test_database.py`).

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


### Alert query indexes

`alerts` carries two composite indexes (`0010_add_alert_query_indexes`) because
every triage path filters on a time window plus either severity or source IP.
Measured at 500k rows: severity+window 30.7 ms → 5.4 ms, ip+window 23.6 ms →
0.04 ms. The single-column indexes can't serve those pairs, and `severity` had
no index at all. Keep new query patterns in mind here — an unindexed filter on
a hot path is invisible until the DB is large.


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


### Production operations

`/healthz` and `/readyz` on the metrics port answer different questions, and
the difference is the whole point. Every in-process engine keeps serving
attackers whether or not the database is reachable — the listeners never touch
it — so removing the database underneath a running server leaves the honeypots
working perfectly while nothing persists, and a liveness probe sees a healthy
process throughout. Chaos testing found exactly that: engines kept answering
and a deploy still returned success. `/readyz` runs a real query against a real
table, so it is the only signal that separates "running" from "collecting".
Alert on it, not on `/healthz`. It also 503s on a runaway ingest backlog, since
the unbounded queue becomes a memory problem before a data-loss one.

`scripts/backup.sh` uses SQLite's `VACUUM INTO`, never `cp` and no longer `.backup`: the server
runs in WAL mode, so a file copy taken mid-write opens cleanly and is quietly missing recent
transactions. `.backup` copies in small steps and restarts whenever the server writes between
steps: on the live 3.8 GB database (about 190 events a second) it ran 38 minutes and never
finished, while `VACUUM INTO` (one read transaction, writers unblocked in WAL mode) took 203 s and
gives a compact rollback-mode file that opens read-only anywhere. `restore.sh` refuses to run while
the server is up,
because restoring underneath a live process leaves it writing into a replaced
file it still holds open.

`config.warn_on_world_readable_env()` fires at startup when `.env` is readable
beyond its owner. A default umask makes `cp .env.example .env` mode 0644, which
on a shared host hands the control-plane token — and with it every captured
credential — to any local account.


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


## Engine and protocol fidelity

A decoy that can be told apart from the software it imitates stops receiving the traffic it exists to collect. These are the ways engines were found out.


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

Registering a provider is **not** enough to ship it. `kubeconfig`,
`slack_webhook`, `azure_credential` and `gcp_service_account` each had a
provider module, a registry entry, a `HoneytokenType` value, a migration and an
ATT&CK mapping in `deception/coverage.py` — and could not be created, because
the `Literal` on `honeytoken_create` listed seven types. The tool body is fully
generic (`get_provider(HoneytokenType(type))`), so the annotation was the whole
blocker and nothing failed loudly; everything downstream was ready and the front
door was locked. Same defect as Telnet before it became a first-class honeypot
type: **for a natural-language-driven system, the tool signature is the
capability surface.** `test_honeytoken_create_offers_every_registered_type`
asserts the `Literal` equals `HoneytokenType` exactly — add new types to both,
and to the planner in `deception/planner.py` when a sensor pairs with one.


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
override the persona-chosen values. Cowrie's own `cowrie.cfg` defaults are the baseline
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


### TLS / HTTPS / STARTTLS

`engines/tls.py:ensure_cert` generates a self-signed RSA-2048 cert per
honeypot, persisted to `tls/<honeypot_name>/server.{crt,key}` so a scanner
pinning the cert SHA sees a stable identity across restarts. `cryptography`
is a direct dep.

HTTP: deploy with `config["tls"] = True` to serve HTTPS on the configured
port. The listener is `engines/tls_front.py` (`start_tls_site`, a drop-in for
`web.TCPSite(ssl_context=...).start()`), not a bare `TCPSite`: asyncio's TLS layer closes
silently when the first bytes are not a usable ClientHello, so `nmap -sV` could not tell
the port was HTTPS (`m2ap?`) and the `ssl-cert` script never ran. The front `MSG_PEEK`s the
first 16 bytes (bounded: 5 s sniff deadline, 256 unclassified connections overall, 32 per
source) and then hands a TLS 1.2+ ClientHello to asyncio untouched via
`loop.connect_accepted_socket` (the handler still sees the real peer), answers a pre-1.2
ClientHello with Go's `protocol_version` alert, and answers plaintext HTTP with
`plaintext_reply`: fixed bytes (Go's one-line 400, the default, used by the Kubernetes API),
a callable given the request's Host header, or `None` to close silently. The HTTP engine
passes `http_personas.plaintext_on_tls_reply`, so Apache explains itself in its HTML page
naming host and port, nginx sends its own 400 page, and IIS sends nothing. Any new TLS
listener on an aiohttp runner must use `start_tls_site`.

The certificate itself is shaped per service by `tls.CertProfile` (CN, optional issuer CN,
validity, SANs, key usage, EKU): `ensure_cert(name, profile=...)` / `build_server_ssl_context(_async)`
take one. Kubernetes and MySQL are leaves from a named CA (the CA key is generated and
discarded, since servers send only the leaf), RDP is self-signed and named for the computer
FQDN (`_cert_profile` in rdp.py, so `ssl-cert` and `rdp-ntlm-info` agree), and the default is
a bare backdated `CN=<name>` with no organisation and no `localhost` SAN. A persisted cert
that no longer matches its profile, or has < 30 days left, is reissued. A new TLS engine
should pass the profile of the service it impersonates, and callers that read the cert back
(RDP's CredSSP public key) must pass the same profile or the file ping-pongs.

SMTP: STARTTLS uses `asyncio.start_tls()` to actually complete the TLS
handshake (the previous behaviour announced STARTTLS but dropped on the
ClientHello — itself a fingerprint). After upgrade, the engine clears
protocol state per RFC 3207 and requires the client to re-issue EHLO.

`tls/` is gitignored — keys are private, certs are deployment-specific.


### RDP engine

`engines/rdp.py` parses the X.224 Connection Request, extracts the leaked
`Cookie: mstshash=user[@DOMAIN]` field (almost every RDP client and brute-force tool sends
this in the clear), and negotiates TLS or CredSSP. `rdp_nla.py` plays the server side of
CredSSP/NTLM (bare or SPNEGO-wrapped NTLM, as Windows' own client sends) and captures a
crackable NetNTLMv2 response. A planted honeytoken credential or the one weak pair derived
from the honeypot's name (`accepted_logins` / `sessions` in its config) is let in:
`rdp_nla.py` derives the NTLM session key from the password and seals the server's
public-key binding (which is how a client that checks it, FreeRDP, aardwolf, proceeds), then
`rdp_session.py` runs a short MCS/capability exchange, paints a static desktop and records
keystrokes, clicks and pasted clipboard text (`rdp_cliprdr.py`, MS-RDPECLIP over the `cliprdr`
static channel: Format List -> Format Data Request -> recorded text; an optional `clipboard_text`
is announced only after the client's own initial Format List, because clients ignore anything
else until then). The desktop is `rdp_desktop.py` (a framebuffer `Screen` with Spleen 8x16 glyphs
from `rdp_font.py`, and a `Desktop` state machine: icons, Start menu, Win+R, a console window;
`commit()` repaints and returns only the changed rectangle, found by XOR-ing rows as big
integers), and the console's answers come from `rdp_shell.py` (a pure fake `cmd`/PowerShell:
no network, no execution, session-local files and `net user /add`). Input becomes `actions`
via `InputRecorder`; repainting runs in `asyncio.to_thread`. `rdp_command` events carry the
command and extracted URLs (CRITICAL on a download attempt). The tests drive it with aardwolf (`tests/unit/test_rdp_session.py`,
including a mutation-replay fuzz of a recorded session) and FreeRDP 3
(`tests/integration/test_rdp_freerdp.py`, Docker-gated, checks pixels).

Logs `rdp_handshake` at HIGH severity when the X.224 parses, `rdp_invalid_probe`
at LOW for port-scan garbage.


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
  everything would fingerprint the sensor in one packet. The agent has a small
  ordered MIB (system group, `ifNumber`, a four-port `ifTable`), so GetNext and
  GetBulk behave as against a real agent: each step returns the next OID, a
  walk ends in `endOfMibView` (v1: `noSuchName`), a missing OID is
  `noSuchObject`, and `sysUpTime` advances. Before that, every GetNext was
  answered with sysDescr and `snmpwalk` aborted with "OID not increasing".
- `engines/ldap.py` — tcp/389, BER by hand. Two populations: simple binds carry
  the DN and password in the clear (invalidCredentials keeps brute-forcers
  cycling), and Log4Shell's second stage arrives here as a searchRequest.
  `looks_like_jndi()` separates the two — a JNDI base object is an opaque token
  from the payload URL with no `dc=`/`cn=`/`ou=` components, or it asks for
  `javaClassName`/`javaCodeBase`. The persona is Active Directory (the bind
  error text is AD's): the rootDSE (empty base, base scope) is readable
  anonymously and lists naming contexts and capabilities, honouring the
  requested attributes; other searches before a bind are `operationsError`,
  as AD does with anonymous access disabled.
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

Adding a type touches six places (`transport` on the capability entry is the
sixth if it isn't TCP — the pcap filter derives from it): `HoneypotType` in `storage/models.py`, the
default port in `config.py`, the `Literal` and `default_ports` dict in
`tools/honeypot.py`, `engines/__init__.py:get_engine()`, and an Alembic
migration (`Enum(...)` is a native PostgreSQL type — `ALTER TYPE … ADD VALUE`,
one statement per value; see `0012_add_five_types`).


### DNS engine

`engines/dns.py` answers as a **recursive resolver** (`ra`, never `aa` or `ad`; dnslib defaults `aa=1`
and echoes the request's AD bit, so `dig` once saw `aa ra ad` together, which no real server sends). It
serves **UDP and TCP/53** on one port: zone transfers are TCP-only, so with UDP alone the
`dns_zone_transfer` detection could only fire on a rare UDP attempt, and a TCP/53 that refuses
connections is itself a tell. AXFR/IXFR is recorded and REFUSED. CHAOS `version.bind` answers with a
BIND version string (Ubuntu 22.04's, matching `_host_identity`), `ANY` with an RFC 8482 `HINFO`
(consistent with the `A` answer and not an amplification vector). Its capability says
`transport="both"` for capture, firewall and preflight, but `spoofable_source=True`: UDP reflection
traffic carries forged sources, so `source_is_spoofable` (not `transport`) decides which sources a
blocklist must not contain.

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
  what actually fronts 6443 in practice. It serves **TLS only** (a plaintext
  6443 is unusable by `kubectl` and identifies itself to every scanner) with the
  per-honeypot self-signed cert, and its identity is **stable**: commit, UIDs,
  pod names, secret values and the flow-control UIDs derive from the honeypot
  name (`_uid`), because a scanner that asks twice and gets two identities has
  found the decoy; only `Audit-Id` varies. Discovery (`/api/v1`,
  `/apis/{group}/{version}`, shortNames), `/healthz`, nodes, server-side Table
  output (what makes `kubectl get pods` print `READY STATUS RESTARTS AGE`
  instead of a bare `NAME AGE`) and `kubectl auth can-i` are served; `_RESOURCES`
  drives both the discovery document and the generic empty-list handler. Objects come
  from `_Cluster`, a pure function of the honeypot name, so a list, a single GET
  (`get pod X`, `describe`, `-o yaml`, a missing name is a real `NotFound` Status) and a
  `?watch=1` stream agree; namespaces the model does not have contain nothing. It
  listens through `tls_front.start_tls_site`.
- `engines/mysql.py` also offers TLS. The greeting advertises `CLIENT_SSL`; a TLS-capable
  client sends a 32-byte SSLRequest and starts its handshake without waiting, so the same
  read can hold both. `loop.start_tls` cannot replay bytes the protocol already received, so
  the session is driven through `ssl.MemoryBIO` (`_TLSTransport`, which keeps the raw
  transport as the one the connection limiter and write-backlog check track). Logins over
  TLS carry `tls: true`. `mariadb` >= 11.4 verifies the certificate by default and refuses a
  self-signed one, as it does a real MySQL; use `--ssl-verify-server-cert=0` to test.


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


## Delivery: webhooks and notification channels

Output formats are someone else's detection content; a notification nobody reads is worse than none.


### Webhook delivery

`webhooks.py` runs a single background worker that drains a queue. Decoupled from the buffer's flusher — slow webhook endpoints can't slow honeypot ingestion.

Signature: `X-HoneyPot-Signature: sha256=<hex>` (HMAC-SHA256 of raw body) — same convention as GitHub webhooks. Consumers verify with the shared secret.

Failure tracking is per subscription: `delivery_count`, `failure_count`, `last_error`. After repeated failures, an admin can deactivate via `alert_unsubscribe` or repair via DB.

Active subscriptions are cached in-process (`_active_subscriptions`, 30s TTL) so delivery doesn't issue a `SELECT … WHERE active` per event on the ingest hot path — the same pattern as the suppression-rule cache. The cache is invalidated on `alert_subscribe`/`alert_unsubscribe` and on worker `start()`. Rows are `expunge_all`'d from the loading session so the per-delivery stat UPDATEs (`_record_outcome`) never interact with the cache. If a test inserts a `Subscription` directly (not via the tool), call `invalidate_subscription_cache()` or start a fresh delivery worker to pick it up.

**The output formats are someone else's detection content, so conformance is
correctness, not polish.** A regression here is invisible locally and breaks a
consumer you can't see. `tests/unit/test_siem_formats.py` pins each rule to the
consumer behaviour it protects; all of these were found by rendering a real
event and reading the output, never by reading the renderers:

- **`event.outcome` must not be guessed.** It was hardcoded `"success"`, so
  rejected brute-force attempts arrived in Kibana's Security app as successful
  logins. `_ecs_outcome()` infers from the event type and returns `unknown` —
  a valid ECS value — where it genuinely cannot tell.
- **`user.name` and `related.*` decide whether these events are first-class in
  Elastic.** `related.ip`/`related.user` drive the click-an-IP-see-everything
  pivot; without them the data is an island the built-in views can't correlate.
  A username only inside `event.original` is present but unsearchable.
- **Never mix a dotted key with its object.** `event.original` sat beside an
  `event` object; Elasticsearch expands dots at index time so it usually
  survived, but Logstash/OpenSearch/Vector are ambiguous. Nest it.
- **CEF standard slots beat custom ones.** `suser` is what correlation rules
  read; the username was only in a `cs4` JSON blob. Device product was the
  literal string `"server"`. The signature ID stays the raw `event_type` (rules
  key on it) while the event *name* is humanised via `_humanize_event_type`,
  which knows protocol acronyms — `SSH Login Attempt`, not `Ssh Login Attempt`.
- **Loki stream labels must stay low-cardinality.** `source_ip` was a label,
  which creates one stream per attacker; an internet-facing honeypot sees tens
  of thousands a day, blows past `max_streams_per_user` and degrades the whole
  tenant. The IP lives in the line and LogQL parses it out — the idiomatic
  pattern, and free at ingest.
- **Enrichment must reach ECS fields, not just ride in `event.original`.**
  Auto-enrichment resolves geo, ASN and reputation for every CRITICAL event, and
  all of it used to reach the wire only inside the `event.original` JSON string.
  Elastic cannot map, aggregate or filter what it cannot see as a field, so
  Security's network map stayed empty while the coordinates that would populate
  it sat in the same document — the `user.name` defect again, one layer out.
  `_ecs_enrichment()` writes `source.geo.*` (with `location` as a `{lat, lon}`
  geo_point, the form the default index template maps), `source.as.*`, and
  reputation as `threat.enrichments[]` — the shape Elastic's own indicator-match
  rules emit, rather than `threat.indicator.*`, which describes a threat-intel
  document *about* an indicator instead of an enrichment *of* this event.
  VirusTotal confidence bands on the **absolute** detection count, not the share
  of engines: VT polls ~94 engines and most do not score IP reputation at all,
  so 11 detections is 12% — which every ratio-based band calls "Low" and every
  analyst calls "block".

Note the split that makes this safe to reason about: renderers operate on
`PendingEvent`, whose timestamp is always `datetime.now(UTC)` and therefore
aware. The naive-datetime problem was confined to values read back from the
database (see `UTCDateTime`), so webhook `rt=`/`time`/`@timestamp` were never
affected.


### Human notification channels

`slack`, `teams` and `email` are subscription formats like the SIEM ones, but the
failure mode is different and drives every design choice. A SIEM that receives a
slightly-wrong document still stores it and an analyst finds it later; a
notification that is malformed, or that arrives four thousand times, is simply not
read — and the operator believes they have alerting either way.

- **Slack** sets `text` as well as `blocks`. Slack uses `text` for the mobile push
  and tab preview, so a blocks-only message arrives on a phone as "This content
  can't be displayed" — useless for the case notification exists to serve. Sections
  are capped at 8 of 10 allowed fields; Slack rejects the *whole message* above 10.
- **Teams** emits a MessageCard, not an Adaptive Card. Adaptive Cards over an
  incoming webhook need the Power Automate Workflows connector, while MessageCard
  renders on both that and the classic O365 connector — and the operator only pastes
  a URL, so we cannot tell which they have. `summary` is mandatory (Teams 400s
  without it, an easy way to ship a notifier that never posts). `themeColor` is a
  bare hex triplet; a leading `#` silently renders grey.
- **Email** goes over SMTP via `asyncio.to_thread` (smtplib blocks, and blocking the
  delivery worker stalls every other subscription). The URL carries everything:
  `smtp://user:pw@host:587/?from=…&to=a@x,b@y&tls=starttls|implicit|none`.
  `smtps://` defaults to 465, `smtp://` to 587. Body is **plain text on purpose** —
  the content is attacker-controlled and HTML would be an injection surface for no
  benefit. `_parse_smtp_url` is called at *subscribe* time too, so a typo fails
  immediately rather than at first delivery.

**`_NotifyThrottle` is what makes these usable.** One scanner produces thousands of
events an hour; relaying them one-to-one gets the channel muted, leaving an
integration strictly worse than none because everyone believes they are covered. A
given `(subscription, event_type, source_ip)` fires at most once per
`notify_throttle_seconds`, and the suppressed count rides on the next message that
does go out — throttling must never hide volume, only stop volume being the delivery
mechanism. **CRITICAL is exempt**: it is rare by construction (honeytoken trip,
container escape, ransom note) and is exactly what someone must see immediately.
Throttled events return `(True, None)` from dispatch, not an error — the event is
stored and queryable, we simply declined to interrupt a human twice.


## Capture, supervision and recovery

Packet capture, the watchdog, reconciliation after a restart, and the control plane's own failure modes.


### Packet capture

`pcap.py` runs one `tcpdump` ring buffer over the deployed honeypot ports. It exists
because per-event payloads record what the engines *understood*, and three jobs need
the wire bytes: carving a dropper's second stage, replaying through Suricata/Zeek,
and producing an artefact rather than an assertion by our own code.

Shelling out to tcpdump rather than sniffing in-process is deliberate — raw sockets
need the same privileges either way, and BPF filtering, rotation and file format are
all things a hand-rolled sniffer reimplements worse.

- **`probe_capability()` reports why capture is off**, as a value, not an exception.
  "Packet capture is silently not running" is the state an operator must never be
  in: they discover it when they go looking for evidence, which is always after the
  incident. The check runs `tcpdump -L` — the cheapest operation that actually
  exercises the permission — and the message names the fix (`setcap
  cap_net_raw,cap_net_admin=eip`).
- **Disk is the hazard, so the ring is bounded by construction.** `pcap_file_mb ×
  pcap_files` is a ceiling tcpdump enforces itself. A full disk stops the database,
  which ends collection entirely — much worse than having no pcap.
- **The filter comes from the deployed port set**, via `capabilities.transport_for`
  rather than a private list of "the UDP ones" (that duplication is what drifted
  twice already). `honeypot_deploy`/`honeypot_stop` call `refresh_capture()`, which
  is a silent no-op when disabled. An empty port set never becomes a
  capture-everything filter — that would record the operator's own SSH session.
- **`pcap_extract(source_ip)` is the point.** A 1 GB ring is not an answer to "what
  did this IP send". Filtering runs through tcpdump's own BPF because link framing
  varies by interface (`any` yields Linux SLL, not Ethernet) and hand-parsing it
  wrong would silently return zero packets. Merging is hand-written rather than
  `mergecap`, which ships with Wireshark and is far less likely to be installed;
  safe because every ring file shares a link type. A merge with no input writes a
  valid empty pcap — a 0-byte file reads as *corrupt* in Wireshark, which looks like
  a bug rather than an honest "no matching packets". A truncated trailing record is
  kept-up-to, since tcpdump may be mid-write on the live file and those are the most
  recent packets.

Capture needs `NET_ADMIN`+`NET_RAW` and host networking in Docker; `-U`
(packet-buffered) is set so an extract run moments after an attack does not miss the
packets being asked about.


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


### Host hardening (`hardening/`, `deploy/`)

A public honeypot host is attacked on purpose, so hardening is about what surrounds the decoys,
never about making them less reachable: every honeypot port stays open to everyone with no rate
limit, ban or geo-block. `docs/HARDENING.md` is the guide; the invariants worth knowing:

- **The service is not in the `docker` group.** It talks to `hardening/docker_guard.py`
  (`honeypot-docker-guard.service`), a separate process that forwards only the Cowrie container
  operations the SSH engine makes and 403s everything else. Its create-body policy is built from
  `engines/cowrie_limits.py`, the same constants `ssh.py` reads, and
  `test_the_engines_own_create_requests_pass_the_guard` runs the real engine and checks its request
  passes: change the engine's container settings and that test (and the guard) must change with it.
  The guard runs under a syscall deny-list that forbids `chown`, so it must never ask to.
  The guard validates, then forwards: it is only as strong as the agreement between what it checks and
  what the daemon reads. A real daemon showed three gaps in that agreement, all fixed and pinned by
  `tests/integration/test_docker_guard.py`: (1) the client's `Content-Type` was forwarded, and Go
  merges an `application/x-www-form-urlencoded` body into the parameters the query check had already
  approved (`kill?signal=TERM` with body `signal=HUP` delivered HUP; a body on `images/create` made the
  daemon import from a URL), so the guard now sets `Content-Type` itself per endpoint and refuses a
  body on endpoints that take none; (2) a create body with a repeated key (`HostConfig` twice) was
  validated as its last value while the daemon merged both and created a `Privileged` container, so
  bodies are parsed strictly and a repeated key at any depth is refused; (3) `stop` and `restart`
  take `?signal=` too and now use the same allowlist as `kill`. Add any new endpoint with an explicit
  content type and an explicit "takes a body or not".
- **`hardening/firewall.py` renders the nftables ruleset** (table `inet hp_fw`, the only thing it
  touches): default-drop input, redirects only for `fib daddr type local` (a bare `dport 80
  redirect` also caught containers' outbound web requests), container egress closed or `limited`,
  the service user's output restricted. `harden-host.sh` calls the module's CLI so the ports the
  operator names once are the ports the firewall and the pre-flight both use (`--print-listen`).
- **`hardening/hostcheck.py`** adds the Linux host checks to `preflight.py` (public listeners vs
  the planned ports, firewall loaded, docker access, guard probed *as the service user*, sshd, sysctl,
  updates). Pure parsers take text so they are tested off Linux. `preflight.check_env_permissions`
  accepts the documented `root:honeypot 0640` layout.
- **`scripts/fetch_backup.sh`** (laptop side) pulls a backup, verifies it (SHA-256 vs the VPS,
  `integrity_check`), quarantines Cowrie samples and prints the run report. The VPS is hostile:
  archive paths are listed and refused if they leave `honeypot-<stamp>/` before anything is
  unpacked, symlinks are deleted after. Everything shares one ControlMaster connection because
  admin SSH is limited to 6 new connections a minute. It must keep working under macOS bash 3.2
  (no `mapfile`, no associative arrays). Report rows are `LEVEL|message` from SQL run on a read-only
  connection with `trusted_schema=OFF`; self-test probes (`selftest_` marker) and platform alerts
  (`0.0.0.0`) are excluded from "attacker activity". Cowrie's samples are inside the container (an
  anonymous volume on the pinned image; `docker cp` cannot read a tmpfs, so the script runs Python
  inside the container, which works for either layout).
- **`deploy/harden-host.sh`** is `prepare` (sshd on 22 *and* the admin port) -> `finalize` (admin
  port only, firewall loaded with a rollback timer) -> `confirm` -> `status` / `teardown`. Re-running
  `prepare` after `finalize` must not reopen port 22; sshd re-binds after the reload returns, so
  the script polls for the listener instead of checking once.
- **The venv needs an interpreter the service user can execute.** `uv sync` as root puts Python
  under `/root/.local/share/uv/python`; build with `UV_PYTHON_INSTALL_DIR=/opt/uv-python`.
- Verified on an Ubuntu 22.04 systemd rehearsal host with a real dockerd (see HARDENING.md); the
  Docker-gated `tests/integration/test_firewall_rules.py` and `test_docker_guard.py` repeat the
  firewall-in-a-real-kernel and engine-through-the-guard checks.


## Detection content: ATT&CK mapping and risk scoring

Analyst-facing numbers are checked by analysts; being wrong is worse than being absent.


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

**The Grafana ATT&CK dashboard is generated, not hand-written.** SQL cannot call
Python, so `03-mitre-coverage.json` used to carry its own CASE-expression copy of
the event-type → tactic mapping — and it drifted exactly the way a duplicated
table always does, re-introducing both bugs above (SSH/FTP/RDP brute force under
Initial Access, `ssh_file_download` under Exfiltration) after `intel/mitre.py`
had fixed them. It also predated most of the 25 engines, so `docker_api`,
`kubernetes`, `sip` and the rest fell through to "Uncategorised" on the one
dashboard whose entire job is showing what you can detect.

`scripts/generate_mitre_dashboard.py` now derives the SQL by pushing every
`signature_events` entry through `map_to_attack`, and
`tests/unit/test_mitre_dashboard.py` regenerates and diffs, so drift fails CI.
Re-run the generator after touching mappings or adding an engine. Tactic IDs
(`TACTIC_IDS`) live in `intel/mitre.py` for the same single-source reason.
Multi-tactic events count under *every* tactic they map to — hence UNION ALL
rather than CASE, which can only bucket a row once and would under-report the
later tactic.

**The "Tactic timeline" panel's styling is hand-maintained, not generated** —
`generate_mitre_dashboard.py` only rewrites the two panels' SQL (`_set_panel_sql`
patches `queryText`/`rawQueryText` in place), so `fieldConfig`/`options` survive
regeneration untouched and can be edited directly without fighting
`test_dashboard_matches_the_generator`. That panel now carries fixed, per-tactic
`fieldConfig.overrides` colors (up to 14 series — Grafana's auto-palette repeats
hues past ~8, which is exactly the range this panel needs) and
`scaleDistribution: {type: "log"}`, not just distinct colors: un-stacking the
chart to fix color legibility (a filled, stacked area blends overlapping bands
into a muddy blob) revealed a second, different problem — Credential Access
outweighs the other tactics by 10-100x in raw count, so on a linear axis every
smaller series still flattens to invisible near zero even with correct colors.
Log scale is what actually makes a Persistence spike of 3 events visible next to
a Credential Access band in the thousands. `test_every_tactic_has_a_fixed_color_override` /
`test_tactic_colors_are_unique` / `test_tactic_timeline_is_not_stacked` pin this.

**The threat map's basemap must not render place labels.** Its `"type": "default"`
basemap resolves to CARTO's free `basemaps.cartocdn.com` raster XYZ tiles, which
render OSM's local-language place names with no English-only variant available at
that endpoint — country/city labels showed up in a mix of Portuguese, Arabic and
Chinese script. `showLabels: false` in the basemap config removes labels entirely
rather than chasing a tile provider that promises consistent English (which would
also add an API-key dependency this docker-compose demo doesn't otherwise need);
the adjacent "Top countries" table already carries that detail in the viewer's own
language. `test_threat_map_basemap_has_no_labels` pins it.

**Timeseries panels derive their bucket width from the window, never hardcode
it.** Every Grafana timeseries query buckets on
`MAX((($__to) - ($__from)) / 240000, 60)` — about 240 points across whatever
range the viewer picked, floored at 60s — and `$__from`/`$__to` are used rather
than `$__interval_ms` because those two are already proven to interpolate in
these dashboards. A fixed width is wrong in both directions: the severity panel
grouped by a literal `strftime('%Y-%m-%dT%H:%M')`, which is 1,440 points per
series over 24h and 43,200 over 30 days across four series, while an hourly
bucket over a five-minute window is a single column. `console/server.py`'s
`_bucket_size` already did this correctly, so the two halves of the same product
disagreed. Table panels have the matching rule: never `SELECT MAX(timestamp)`
raw — that returns SQLite's storage string (`2026-07-30 20:22:10.632767`, no
`T`, no offset), which renders as an ambiguous string and cannot be shown in the
viewer's timezone. Format with `strftime('%Y-%m-%dT%H:%M:%SZ', …)` and declare
the column in the target's `timeColumns`.

**`scripts/seed_demo_data.py` must feed every engine it deploys.** Its budget
named five while it created twenty-five, so the demo data that exists to show
the platform off implied a five-protocol tool and left the ATT&CK dashboard
showing a fraction of the tactics the sensors detect. `_ENGINE_MIX` now carries
a weight per engine and `_check_engine_mix()` fails the run if it and
`_EVENT_PROFILES` disagree. Honeypot ids are keyed by `HoneypotType.value`, not
display name — `docker_api` deploys as `demo-docker-api` because Docker object
names disallow underscores.

**Timestamps are aware everywhere** (`storage/models.py:UTCDateTime`). The
columns were declared `DateTime(timezone=True)`, which PostgreSQL honours and
SQLite — the default — silently does not, so DB reads came back naive. A naive
`.isoformat()` has no offset, and JavaScript reads an offset-less date-time as
*local*: the console rendered its header clock from an aware timestamp and its
feed from naive ones, showing the newest event four hours in the future on a
UTC-4 host. `UTCDateTime` normalises on bind and re-attaches UTC on load. The
stored SQLite string format is unchanged, so Grafana's `datetime()` comparisons
and existing databases are unaffected.

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


## The agent-facing tool surface

The tool signature is the capability surface of a natural-language-driven system; response size is a correctness concern.


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
  from the volume that makes up most honeypot traffic. **The headline counts
  come from their own aggregate query, never from `len(needs_attention)`** —
  that list is capped at `max_highlights`, so counting it announced a queue of
  841 untriaged alerts as "8 untriaged high-severity alert(s)", which reads as
  a quiet shift. CRITICAL gets its own headline line rather than being folded
  into a combined figure, and `needs_attention_total` / `_showing` make the cap
  explicit. This is the list-tool truncation rule from "Tool response shaping"
  applied to the tool where being wrong costs the most.

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


### Agent-first tool contract

The server is driven by a model from a sentence a person typed, so a tool that needs flags is a
defect. `tests/unit/test_tool_contract.py` reads the registry and fails the build when a tool:
- returns anything but `dict[str, Any]` (a bare list is an *empty* MCP response, and an agent
  cannot tell "nothing matched" from "failed");
- has a parameter with no `Args:` description (the docstring becomes the schema description; without
  it the model guesses);
- requires more than 3 parameters or has more than 8 (`MORE_PARAMETERS_BECAUSE` is the exception
  list, with a reason);
- opens with a weak first line (models choose tools from it);
- pushes the tool list over its weight budget: 3,000 characters per tool and 70,000 in total, because
  every tool's description plus parameter schema sits in the model's context for the whole
  conversation. Trim prose (repeated "every argument is optional", examples); FastMCP already drops
  schema titles.

Design consequences worth knowing: tools size their own answers (a default that fits, and a count and a
`note` saying what was cut; knobs such as `rank_by`, `window_minutes`, `timeout_seconds` and, on the
export and report tools, `output_path` are gone, while the few a person plausibly says, like
`alerts_recent`'s `limit` or `attack_patterns`' `top`, stay optional), files go to `reports_dir` under
generated names, tools that reach outside this system default to a dry run
(`blocklist_push_*`), and an error carries a `hint` naming the next step. A tool that needs a bigger
answer than its default shows should be asked a narrower question (an address, an event type), not
given a knob. Logic that two tools share lives in a helper (`cluster_ssh_clients`, `write_report`),
never in one tool calling another's public signature: a removed parameter then breaks the caller only
when that path runs.


### Role-based access control (`rbac.py`)

Three roles, each a strict superset of the one before it — **viewer** (read-only:
list/get/search/analyse/report), **operator** (viewer + manage this system's own
resources: deploy/stop honeypots, create/rotate/revoke honeytokens, acknowledge
alerts, suppression rules, webhooks, pcap, deception deploy — every effect reversible
and contained to this system's own data), **admin** (operator + the tools whose blast
radius reaches outside this system's own database: `alerts_prune`, the
`blocklist_push_*` tools, `audit_log_search`).

`MCP_AUTH_TOKENS` (`token:role,token:role,...`) replaces the single `MCP_AUTH_TOKEN`
when set, so an operator can hand out tokens with less than full access instead of one
shared admin token; `parse_auth_tokens()` falls back to treating a lone
`MCP_AUTH_TOKEN` as one implicit admin token, so existing single-token deployments are
unaffected. `_build_auth()` puts the resolved role in each token's `claims["role"]` on
the verifier's static-token entries.

**Static tokens are restart-only** — `MCP_AUTH_TOKENS` is read once at process start,
so revoking one team member's access without restarting the whole shared server, or
adding someone mid-operation, isn't possible through env vars alone. `tools/api_keys.py`
(`api_key_create`/`api_key_revoke`/`api_key_list`, all admin-only) is the live
counterpart: `ApiKey` rows in the DB, only a SHA-256 digest stored (never the
plaintext — returned exactly once, at creation), checked by
`rbac.build_combined_verifier()`'s `_CombinedTokenVerifier` after the static tokens
fail to match. A 30s in-memory cache (`rbac.API_KEY_REFRESH_SECONDS`, mirrors
`suppression.py`'s rule cache exactly) avoids a DB round-trip per request, invalidated
immediately on create/revoke (`invalidate_api_key_cache()`) so a change is live on the
process that made it well before the TTL would otherwise expire it. Static tokens
remain supported specifically as the break-glass bootstrap credential — `api_key_create`
is itself admin-gated, so at least one credential has to exist before any `ApiKey` row
can be minted; with zero static tokens configured, `_build_auth()` still returns `None`
exactly as before; DB-backed keys are purely additive; never a way around the
`_networked_auth_error` fail-closed gate.

Every `ApiKey` carries a `label` — a real per-person or per-automation identity, not
just a role — which `rbac.current_actor()` reads into `AuditLog.actor` (see
"Control-plane audit log" below) as `"alice (operator)"`. This is what makes the audit
log answer "who," not just "what": under the static-token-only model every operator
sharing one token was indistinguishable.

Enforcement is per-tool, not global middleware: gated tools carry
`@mcp.tool(auth=require_role("operator"))` (or `"admin"`) directly on the decorator —
FastMCP checks `tool.auth` itself before every call and already short-circuits it for
stdio (`server.py:_get_auth_context`'s `skip_auth`), so `require_role`'s own
`ctx.token is None → True` branch only ever fires for a networked transport running via
`MCP_ALLOW_UNAUTHENTICATED` (no token configured at all — see the rbac.py module
docstring for why that's safe: `_networked_auth_error` guarantees the server never
reaches that state *with* a token required). Viewer-tier tools carry no `auth=` kwarg
at all — any caller holding a valid token of any role can use them, matching the "no
gate below the lowest tier" model.

New tools **must** be added to exactly one of `VIEWER_TOOLS` / `OPERATOR_TOOLS` /
`ADMIN_TOOLS` in `rbac.py`, and gated ones need the matching decorator —
`test_rbac_covers_every_registered_tool` (fail-closed: unclassified fails the build,
never defaults to viewer-open) and `test_operator_and_admin_tools_actually_carry_an_auth_check`
(catches listing a tool without also decorating it) pin this the same way
`test_honeytoken_create_offers_every_registered_type` pins `HoneytokenType`.


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

Three invariants:
- **Auditing never breaks the action.** `record_action` swallows and logs its
  own failures; refusing to stop a honeypot because the audit table is
  unavailable would be the worse outcome.
- **Secrets never land in the log.** Arguments are recorded, so
  `redact_arguments()` masks anything whose key contains secret/token/password/
  api_key/credential/auth before persisting.
- **Every row says who, not just what.** `record_action` resolves
  `rbac.current_actor()` itself rather than taking an `actor=` parameter, so
  every one of its ~11 call sites gets correct attribution without having to
  thread identity through each one individually, and any future call site
  gets it for free. The actor is an `ApiKey`'s `label (role)` when the caller
  used one, a bare role for an unlabelled legacy `MCP_AUTH_TOKEN`, or `stdio`
  for a local chat session — never blank. `audit_log_search(actor=...)`
  substring-matches it. Rows written before this column existed have `actor
  IS NULL`, which means "recorded before actor tracking existed", not
  "caller unknown" — the two are deliberately kept distinguishable.

Currently audited: `honeypot_deploy` (success and failure), `honeypot_stop`,
`honeytoken_revoke`, `honeytoken_rotate`, `deception_deploy_plan`,
`pcap_control`, `pcap_extract`, `alerts_prune`, `alerts_acknowledge`,
`api_key_create`, `api_key_revoke`. Add a `record_action` call to any new tool
that changes state. Reads are not audited — they are high-volume and
low-consequence. The table is append-only and the retention sweep does not
touch it.


## Security boundaries, packaging and audit hardening

Boundaries that were crossable, assets that vanished from wheels, and the invariants the audits produced.


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
`importlib.resources`, never by walking up from `__file__`. Three things live
inside the package for this reason:

- `console/static/index.html` — the console 500s without it.
- `presets/*.yaml` — bundled suppression presets. These previously sat in
  `config/suppression_presets/` beside the source tree with a fallback that
  resolved to a path inside site-packages that never exists, so a pip-installed
  user saw an empty preset list for a feature the README advertises. Nothing
  failed loudly; the list was just empty.
- `grafana_assets/{provisioning,dashboards}` — the Grafana provisioning and the five dashboards. They
  used to sit in `docker/grafana/`, outside the package, so a pip-installed server could not start
  Grafana. The compose files, the dashboard generators and `grafana.py` all read this one copy.

The failure mode is identical in both cases: the wheel builds, installs and
imports cleanly, then misbehaves at runtime. `tests/unit/test_operational.py`
asserts both resources resolve, and the release workflow installs the wheel
into a clean environment *outside the source tree* and checks them again —
running from the repo root hides the bug entirely.

Version lives in two places (`pyproject.toml` and `__init__.py`); a test
asserts they agree and the release workflow refuses a mismatched git tag.


### Audit hardening invariants

- **Nothing parses attacker bytes without a bound.** Every length field is
  checked against the buffer and a hard cap before use, loops must advance
  `pos` strictly, and regexes run only over clipped input with bounded gaps
  (`.{0,40}`, never `.*`). `contextlib.suppress(Exception)` cannot catch an
  infinite loop; a regex cannot be interrupted either.
- **Shared helpers:** `engines/_tasks.spawn` (retained fire-and-forget tasks),
  `engines/_bounds.write_backlogged`, `engines/conn_limit` (per-IP cap, idle and
  lifetime timeouts, `extract_lines`, `LineWorker`, `UdpReplyLimiter`,
  `close_after_error`, `shutdown_server`), `secure_io` (private files are created
  0600, never chmod'd afterwards) and `_loop_bound.LoopBound` (loop-safe locks).
- **UDP replies are bounded to a small multiple of the request** (SNMP 4x, SIP
  3x, DNS 2x) and rate limited per source; the event is recorded either way. The
  multiple is not 1x on purpose: at 1x an ordinary `snmpget` (40 B in, ~140 B out)
  comes back `tooBig` and a short REGISTER gets a 401 with no digest challenge —
  both identify the decoy and capture nothing. With the per-source limiter the
  platform adds a few KB/s to a reflection, which is noise.
- **Write helpers that return `{"error": ...}` do not raise.** Callers must
  check the result (`alerts_prune` deletes nothing unless the archive succeeded);
  caller-named artifact paths refuse to overwrite.
- **Webhook destinations are policed** (`webhook_allow_private_destinations`,
  default off) at subscribe and delivery time; `alert_subscribe` is admin-tier.
- Canary/token triggers are submitted through the event buffer so they reach
  webhook delivery; the metrics/console servers bind loopback by default.
- **Tests run on SQLite by default; `TEST_DATABASE_URL=postgresql+asyncpg://...`
  runs the same suite on PostgreSQL** (each test gets an empty schema). Test
  modules must read that variable rather than hard-assigning a URL, or the CI
  PostgreSQL job silently tests SQLite again.
- Launch with `honeypot-mcp` or `python -m honeypot_mcp.server`; the latter
  delegates to the canonical module because the tool modules register on
  `honeypot_mcp.server.mcp`, not on `__main__.mcp`.
- Cowrie's root filesystem is read-only. Its wget/curl/tftp/nc emulation makes
  real outbound requests, so `COWRIE_HONEYPOT_OUT_ADDR=127.0.0.1` (default;
  `cowrie_allow_egress` / `COWRIE_OUT_ADDR=0.0.0.0` to opt out) makes every such
  connect fail in-process — no host firewall needed.
- **Honeytoken matching runs on the payload before it is clamped** (the clamp
  drops whole keys over budget, and a planted credential inside a dropped
  `post_data` must still escalate). The HTTP engine keeps credential-aliased form
  fields however much junk precedes them.
- **The webhook destination policy is enforced on every delivery**
  (`WebhookDelivery._dispatch` → `check_destination`, 10 s cache), not only in
  `alert_subscribe`; syslog connects to the validated address.
- **The canary's global rate ceiling applies only to requests that matched a
  token**, so a flood of random ids cannot starve a real trigger.
- **Fidelity invariants.** Listing, size and bytes come from one source (FTP file
  tree; HTTP backups reuse it). SMTP/FTP/HTTP/RDP answer in the dialect of the product
  they claim, verified with the real client (`ftplib`, `smtplib`, `httpx`, `nmap`,
  pyspnego), not only unit-level parsers. A new engine behaviour should be checked
  with the tool an attacker would use.
- **Cowrie persona = env vars + a rewritten `fs.pickle`.** Kernel/OS/platform are
  `[shell]` settings (`COWRIE_SHELL_*`); everything else an attacker `cat`s comes from
  `engines/cowrie_fs.py`. Do not write `/etc/issue.net` (non-empty = pre-auth banner).
  `ssh.py` creates the container, extracts the rewritten pickle into an anonymous
  volume at `/cowrie/persona`, then starts it; failure falls back to Cowrie's default
  with a warning. The compose stack builds the same file in `cowrie-persona-init`.
- **Cowrie's fingerprint is patched from inside the container.** nmap names a telnet
  service that opens `IAC DO NAWS` + `login:` "Cowrie Honeypot telnetd", and Twisted's SSH
  offer (3des-cbc, cast128-cbc, hmac-md5, group14-sha1, bare `ssh-rsa`) contradicts the
  OpenSSH banner. `cowrie_env_vars` sets `COWRIE_SSH_CIPHERS/MACS/COMPRESSION` (real `[ssh]`
  options) plus `HONEYPOT_SSH_KEX/HOSTKEYS/TELNET_ISSUE`, and `engines/cowrie_sitecustomize.py`
  (a plain file, imported by Python as `sitecustomize` via `PYTHONPATH=/cowrie/persona/patch:
  /cowrie/cowrie-git/src`, delivered by `persona_tar` with the persona filesystem) installs an
  import hook that patches `cowrie.ssh.factory` (narrow the KEXINIT offer) and
  `cowrie.telnet.userauth` (open with `DO TTYPE/TSPEED/XDISPLOC/NEW-ENVIRON`, then the issue
  and `<host> login: `). The offer is a strict *subset* of the persona's real OpenSSH (Twisted
  has no chacha20/GCM/`-etm`/sntrup). `PYTHONPATH` replaces the image's, so it must keep
  `/cowrie/cowrie-git/src`. If the persona filesystem cannot be delivered the container falls
  back without the patch and a warning says so. The compose values are literals pinned to
  `cowrie_env_vars` by `test_compose_sensor_carries_the_same_algorithm_environment_as_the_engine`;
  `tests/integration/test_cowrie_fingerprint.py` reads the wire of the real image.
- **Cowrie behaves like coreutils where scripts lean on it.** `cowrie_sitecustomize` also patches
  `head`/`tail` (legacy `-N` form to `-n N`, which stock Cowrie rejects with "invalid option -- '2'") and
  `uptime`/`w`/`/proc/uptime` (a per-hostname boot offset of 3-27 days plus real elapsed time; stock Cowrie
  counted from container start, so every restart read "up 11 min"). The persona filesystem carries a
  **tracked credential** as bait: `~/.bash_history` has a `mysql -u USER '-pPASS' -h db1.internal` line and
  `~/.my.cnf` the same pair (mode 600), resolved in `ssh.py:start` from `planted_credential("mysql")` (a
  deterministic untracked decoy when no token exists). It is written to **both** `/root` and the persona's
  own user: 105k of the first run's successful logins were `root` and 70k `admin`, and never the persona's
  user, so bait only under `/home/<persona-user>` was never read. A Cowrie container only picks all of this up
  when it is recreated (`honeypot_stop remove=True`, then deploy).
- **Transient DB errors are retried, permanent ones are not.** `EventBuffer._write_retrying`.
- `tls_dir` / `reports_dir` are settings; tests redirect both to `tmp_path` (conftest).
