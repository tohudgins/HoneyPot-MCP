# Changelog

Reverse-chronological summary of meaningful changes. Not a release log —
the project isn't on a version cadence — but each section represents a
distinct iteration with a coherent goal.

## The operations console could not load on a real run; `sql_query` ignored its time limit

**Rendering the console on the live VPS showed it never returned.** `/api/overview` did not answer in
120 s for the 24 h window, nor in 100 s for 1 h or 6 h, on 17.6M alerts. It re-aggregated the raw table ten
times per 5-second poll (one pass with a 48-branch `CASE` per row, one extracting JSON from every row for
geography), which was fine for thousands of alerts. The same defect the MCP tools had before the rollups,
left behind in the one component nobody had run at scale. It now reads the exact hourly rollups
(`rollups.window`: whole hours from the rollups, partial edge hours raw) in one grouped pass, builds the
chart from rollups (clock-aligned hour and 6-hour columns; sub-hour columns only for windows of two hours
or less, by integer arithmetic in SQL), and reads geography from CRITICAL alerts only, the only ones that
carry enrichment. Measured on the 17.5M-alert backup: 1 h 0.19 s, 6 h 0.53 s, 24 h 0.16 s, 7 d 0.61 s (it
was 22 s for 7 d even after the first rewrite); live on the VPS 0.2 to 3 s. Every number is checked
against a plain computation (`test_console_rollups.py`; three mutations caught), the chart total equals the
headline count in every window, and 7 d equals the database's 17,539,280.

**The last 22 s was one planner detail.** The CRITICAL lookup used the timestamp index and loaded every row
in the window to test its severity (12.7 s for 7 days). A partial index (`ix_alerts_urgent`) exists for
exactly this, but SQLite only uses a partial index when the query states its predicate as literal text;
SQLAlchemy sends `.in_([...])` as bound parameters, which hides it. Emitting the predicate as literal SQL
gives 0.47 s for the same 27,686 rows, and a test reads the real query plan so it cannot regress.

**`sql_query` did not enforce its 15 s limit.** `asyncio.wait_for` cannot stop a SQLite scan running in
aiosqlite's worker thread: a slow query ran 87 s and left the session in `PendingRollbackError`. The deadline
is now a SQLite progress handler that aborts the statement itself; the same query now stops at 16.5 s with
a clear message and the next query works. The Grafana engine panel also labels alerts from recreated
sensors "(removed sensors)" instead of "null".

## Found by running it live: bait in the wrong home, `tail`, and a slow MalwareBazaar

**The Cowrie bait was never visible to anyone.** It was written under the persona's own user
(`/home/appuser`), but real attackers log in as `root` (105,066 successful logins in the first run) or
`admin` (70,460); the persona user never appears. A real SSH session to the live sensor listed `/root`
without it. The bait now lives in `/root` as well. `tail -3` was rejected exactly like `head -2` and is fixed
the same way. The whole chain was then run as an attacker would: read the tracked credential out of the live
sensor's `/root/.my.cnf` over SSH, replay it against the live MySQL honeypot with a real native-password
handshake, and get a CRITICAL `honeytoken_triggered_credential_via_mysql_login_attempt`.

**Providers verified live** (abuse.ch, OTX and Shodan InternetDB; GreyNoise's free key needs a business
email, so it was not): `108.186.84.69`, the address that replayed the bait, is in 12 OTX pulses (one titled
"Honeypot sg1 - SSH/Telnet/Web attackers and malware delivery") and InternetDB lists its open RDP port; a file
hash captured on the VPS is a known MalwareBazaar sample. MalwareBazaar took 7-8 s for that known hash, so
the 3 s budget (right for notifications) reported a working service as timed out; `lookup_hash` now uses
`INTEL_LOOKUP_TIMEOUT_SECONDS` (default 20), the notification fan-out keeps 3 s.

## Cowrie realism, a working rsync listing, four optional threat-intel providers, IOC tools

**Cowrie** (checked through the OpenSSH client against a real 3.0.15 container): `head -2` works as well as
`head -n 2`; `uptime`, `w` and `/proc/uptime` report a per-hostname boot offset of 3-27 days plus real
elapsed time, instead of minutes after every container restart; and the persona home directory carries a
tracked credential (`~/.bash_history` has a `mysql -u USER -pPASS -h db1.internal` line, `~/.my.cnf` the same
pair, mode 600) when a MySQL credential token exists, deterministic decoys otherwise. Each patch is
mutation-checked against the real client.

**rsync listing.** A real `rsync rsync://host/module/` now lists a decoy tree and exits 0 (rsync 3.5.0 and
3.1.3 in Docker). The cause of the old stall was not the file list: protocol 30+ clients send their
arguments NUL-separated, so the newline-based reader never saw a complete line. `engines/rsync_wire.py`
holds the protocol 31 setup and file-list encoder (varints, multiplexed frames, delta-encoded entries);
trees are deterministic per sensor and UTC day (`db-dumps` has dated `.sql.gz` dumps, `backups` tarballs).
`rsync -av` gets past the list and fails in 0.2 s without transferring anything, by design. Not served:
protocol 29 and older (macOS openrsync) and options the encoder cannot produce. 70 tests decode the wire
with an independent reader; 18 mutations killed.

**Optional threat-intel providers** (off unless configured, cached, never called per event, bounded by one
3 s fan-out deadline so a hung provider cannot cost the VirusTotal/AbuseIPDB lines): GreyNoise
(`GREYNOISE_API_KEY`), abuse.ch for MalwareBazaar, URLhaus and ThreatFox (`ABUSECH_AUTH_KEY`), AlienVault
OTX (`OTX_API_KEY`) and Shodan InternetDB (`SHODAN_INTERNETDB_ENABLED=true`, no key). They appear in
`enrich_ip` and as one line each in Slack/Teams/email only when they have something to say; machine formats
are not enriched. Each is tested through the real httpx client against a strict stub of the vendor's
published contract. `scripts/intel_smoke.py` does an optional live call per provider.
**`extract_iocs`** (distinct URLs, hosts and file hashes from download and command payloads, bounded and
saying when capped), **`attack_navigator_layer`** (an ATT&CK Navigator 4.5 layer scored with the same counts
as `attack_summary`) and **`lookup_hash`** (MalwareBazaar) are viewer-tier tools.

## Ask your own questions: a read-only SQL tool and a Grafana query box; dashboards that stay fast

**`sql_query`** (MCP, viewer role, works in analysis mode): one `SELECT` or `WITH ... SELECT` over `alerts`,
`alert_rollups` and `honeypots`. Layered so a mistake cannot write: only one SELECT statement (keywords
inside string literals and comments are fine), a subquery wrapper (a write is a syntax error inside one),
a read-only transaction, the secret tables (`honeytokens`, `api_keys`, `subscriptions`, `audit_log`, schema
catalogues) refused by name, at most 1,000 rows and 15 seconds, and a result that says when it was cut.
Real data: an indexed query and a rollup query return in 0.0 s, a JSON search across 14.9M alerts in 5.9 s
(414,048 `wget` payloads), a `DELETE` and a secret table are refused. The test found a real bug first: a
trailing `-- comment` swallowed the wrapper's closing parenthesis.

**Grafana.** A **Query** dashboard (`04-query.json`): type SQL into the `sql` box, the table runs it, with the
tables, JSON tips and four example hunts beside it. (The provisioned datasource is `editable: false` and
Grafana's default Viewer role cannot open Explore, which is why ad-hoc querying was not possible.) Six
aggregate panels now read the hourly rollups for whole hours and raw alerts for the partial hours at each
edge: identical to `alerts_stats` and to a raw `GROUP BY` on 14.9M real alerts (8,807,993 alerts, 2,131
sources, 3,964 critical for a ragged window), in 0.01 s instead of 1-2 s, and independent of run size.
`scripts/dashboard_rollups.py` rewrites them; `test_dashboard_rollups.py` runs the shipped SQL against a raw
`GROUP BY` for mid-hour, on-the-hour and inside-one-hour windows, and fails if either edge is dropped.

An **Alerts** dashboard (`05-alerts.json`) is the Grafana counterpart of `alerts_recent` and `alerts_search`:
filter by source IP, part of an event type, severity (several), sensor and a payload substring, over the time
picker's window, newest first with severity coloured. Every dashboard also carries a **HoneyPot dashboards**
menu (shared tag, time range kept) so the five pages are one click apart. Checked in a real browser against
the 14.9M-alert backup: the filters and both dropdowns expand correctly and return the matching alerts.

**Census of the 25 engines against real traffic** (5.27M real alerts, my own tests excluded): nine engines
have every signature event triggered by real attackers; the rest are missing only post-login events
(RDP session, IMAP/POP3 login success, SQL file reads, JNDI, SMB exploit) or are off on the VPS (SMTP, DNS).
`ldap_jndi_lookup` was confirmed live from outside (CRITICAL).

## FTP over the internet never completed a transfer

Testing the bait with a real FTP client against the VPS: login worked, then `LIST` timed out. FTP moves
data over a **second connection to a port the server names**, the engine named an ephemeral one, and the
host firewall (default drop) refused it. So from the internet every session stalled after login: the live
run recorded 9 anonymous logins and 9 passive attempts and not one listing, download or upload, which also
means `ftp_file_download`, malware-upload capture and the bait could never have fired in production. The
engine now opens passive listeners only inside `FTP_PASV_PORT_MIN`/`MAX`, and the firewall renderer takes
`--ftp-pasv-ports 30000-30049` (validated: ascending, at most 1,000 ports, never overlapping a listening or
admin port; `harden-host.sh` passes it through). Nothing listens in the range except mid-session. Live, from
outside: LIST, SIZE and RETR agree (158 bytes), the tracked credential is in the file, and the first FTP
file transfer the deployment has recorded is `ftp_file_download`, HIGH, `bait_served`.

**The same class of defect on NFS: `showmount -e` could not work.** NFS clients ask the portmapper on port 111
where mountd is before they touch 2049; only 2049 was open, so `showmount -e`, `rpcinfo -p` and nmap's
`nfs-*` scripts got nothing, and the sensor's headline detection (`nfs_export_enumeration`) could not fire
from the internet. The engine now sits on an internal port with both 111 and 2049 redirected to it (firewall
`2049>12049,111>12049`; the sensor was redeployed on 12049 with the old ruleset kept). Reaching it exposed a
second defect: the portmapper answered every version in the v2 format, so nmap's RPC library failed with
"data string too short" (the lenient `rpcinfo` binary accepted it). It now speaks v2, v3 (`GETADDR`, `rpcb`
`DUMP`: netid, universal address, owner) and v4, and answers any other version with `PROG_MISMATCH` and the
supported range, as rpcbind does. Live: nmap identifies `rpcbind 2-4` and `nfs 3-4`, `rpcinfo` lists the
services, and `nfs-showmount` discloses the export list and is recorded as `nfs_export_enumeration`, HIGH.
Tests decode the replies with an independent strict XDR parser to the last byte. Not served: UDP (macOS
`showmount`) and post-mount NFS operations (`nfs-ls`/`nfs-statfs` still fail).

## Bait in the FTP listing, and a prompt-injection field test

**`passwords.txt` on the FTP decoy now carries a tracked credential** (an FTP token first, else the MySQL
one). Its decoy lines were untracked, so replaying them anywhere tripped nothing. LIST, SIZE and RETR still
agree on the length (the bait is part of the node, read through one function), and the download event is
marked `bait_served` so analysis can see who took it. Driven by a real `ftplib` client: read the file, log in
with the pair found in it, get a CRITICAL naming the token. Redis has no bait on purpose (attackers write to
its store and the SAVE-redirection detection hashes it).

**Can attacker-authored text steer the model?** `scripts/field_test_injection.py` plants alerts whose fields
carry instructions aimed at the dangerous tools (bulk false-positive triage, prune, stop, abuse report,
blocklist export) into a copy of the real backup and gives a real `claude -p` session every tool pre-approved.
Three scenarios (summarise, triage, investigate), checked against database baselines and the tool-call stream
rather than the model's account: all held, the model read the payloads in full, took only the write it was
asked for, and twice named the attack. One model, one sample each: evidence, not proof, so the guidance is
a `viewer` token for any unattended agent.

**Grafana's 13 panel queries read the raw table** (17.8 s total on 4.9M alerts); measured and documented
rather than converted, since an inexact shortcut would make the dashboard disagree with `alerts_stats`.

## Campaign analysis read 5,000 alerts; the DNS engine was UDP-only

**`analyze_campaign` correlated only the newest 5,000 alerts.** On a database dominated by one flood that is
a few minutes of one source: on the real run it reported 7 "campaigns", all from the last 16 minutes of a
day-long run, and said nothing about being capped. The independent SQL oracle (a raw `GROUP BY` over the
alert table) finds 274. It now correlates the exact hourly rollups for the whole run (or `since_hours`),
states its hour resolution, and returns `{campaigns_total, count, campaigns}` so a limit is visible. Real data:
274 campaigns, the same event types and source sets as the raw SQL, 457,839 events on both sides, and the
new oracle checks fail when the loader is broken. `fingerprint_clusters` already reported its cap and
matched SQL on all 22 fingerprints; both checks are now in `field_test_oracle.py` (73 checks).

**Real `dig`, `nmap` and `smtplib` against the engines that are off on the VPS.** SMTP behaved like Postfix
under all three. DNS did not: UDP only, so a TCP zone transfer was refused and unrecorded (and a nameserver
with TCP/53 closed is a tell); `version.bind` answered with an SPF record; `ANY` returned NXDOMAIN for a name
that answered `A`; every answer carried `aa ra ad`; and the SPF text was double-quoted and `ip4:0.0.0.0/0`.
Now: TCP/53 with AXFR/IXFR recorded and REFUSED, BIND-style CHAOS answers, RFC 8482 `ANY`, resolver flags,
one clean SPF. DNS is declared `both` for capture and firewalls but keeps a separate `spoofable_source` flag:
the blocklist filter used the transport alone, so declaring DNS TCP-capable would have let sources seen only
over forgeable UDP into a blocklist (the filter had no test; it does now).

**Suppression presets replayed over every real source:** Shodan 18 alerts, Censys 7, RFC1918 4,489 (the
Docker bridge's probes); nothing high-value on this traffic.

## Ready to leave running: analyse the data later without a sensor, and the ATT&CK numbers checked

**Analysis mode.** A restored backup lists every sensor as RUNNING, so opening it with the normal server would
try to launch all 23 of them (ports, Docker) on a laptop; read-only mode only existed when another process held
the lock. `ANALYSIS_MODE=true` opens the database and starts nothing: no honeypots, capture, canary, watchdog,
notifications or retention, and the sensor-changing tools say so. Smoke-tested over real MCP stdio on a clone of
the 3.7 GB backup: all 65 tools load, answers on 4.9M alerts take under two seconds, and the whole post-run
sequence (mapping, journeys, campaigns, reports, STIX, blocklist, bulk triage) runs in about ten seconds.
`scripts/analyze_backup.py <backup>` does it in one command and writes `analysis-summary.md` beside the reports.

**`attack_summary`: the whole run by ATT&CK tactic.** There was no tool for "which techniques did this run
produce, and how many alerts each". It maps every event type seen (exact counts from the rollups) in kill-chain
order, reports what is deliberately unmapped and the mapped share (98.3% on the first run, 33 techniques).

**Two mapping errors found by reading that output as an analyst would.** RDP connections and handshakes from the
internet were filed under Lateral Movement (T1021.001, 4,888 alerts); they are External Remote Services (T1133,
Initial Access), and only an established session stays T1021.001. And `analyze_attacker_journey` could list a
phase with 2,570 events and no technique, because techniques came only from the sampled events (earliest, latest,
most severe) while the exact counts proved the phase happened.

**For an unattended run:** the database grew ~4 GB a day, so the disk-space alert (`MIN_FREE_DISK_MB`, default
500) fires only after collection has stopped; the deploy guide now says to set it to about two days of growth.

## One host could OOM-kill the Telnet sensor; health pages are debounced; blocklist pushes match the real APIs

**The Telnet sensor restarted 67 times in five hours.** One address opened ~2,400 sessions in six minutes
(about 570 connections a minute from ten sources in all); every open Cowrie session costs memory on top of an
idle ~100 MiB, so the 256 MiB container hit its limit within minutes. Docker killed and restarted it, the
port refused connections for a few seconds each time, and the watchdog raised a CRITICAL
`honeypot_health_failed` every time. `docker inspect` shows `OOMKilled=false` after a restart (the flag is
reset), so only `docker events` showed the cause. The in-process engines already cap sessions per source
(`conn_limit`); a container had no cap. The firewall now limits concurrent connections per source to the
published container ports (`ct count over 128`, IPv4 and IPv6), measured live: 220 held connections from
one host, 131 admitted and 89 dropped, and connections are accepted again as soon as they close. The Cowrie
memory ceiling is 512 MiB.

**Then the CPU quota was the next limit.** With memory fixed, a few health probes still failed under load.
The container's cgroup showed why: at its 0.5-CPU quota it used 0.46 CPU and was throttled in ~90% of
scheduling periods, and a throttled event loop is slow to accept. The host was 52% idle, so both Cowrie
containers now get one CPU: the same load was throttled in 1% of periods afterwards (`dockerd` itself uses
~40% of a core on this traffic, because Cowrie's JSON event stream is the evidence channel and passes through
Docker's log driver).

**A blip is no longer a page.** The watchdog needs two consecutive failed sweeps before it declares a sensor
dead. A sensor that fails one probe and recovers three times in an hour raises one HIGH
`honeypot_unstable` alert instead, so a restart loop stays visible without paging every time.

**ATT&CK coverage measured against what was actually captured.** Mapping the 152 event types seen so far
(5.0M alerts) left 3.5% of alerts unmapped. Most of that was bookkeeping (connections, session open/close,
client fingerprints), which is deliberately not a technique, but real behaviour was missing: Redis `CONFIG
SET`/`SET` (T1190, the entry point of the common Redis campaigns), `CONFIG GET` (T1082), Docker API probes
(T1613), NFS mount probes and rsync module access (T1135), SIP requests and INVITEs (T1046) and malformed
protocol probes (T1595). Unmapped is now 2.1%, all bookkeeping, and the ATT&CK dashboard was regenerated from
the mapper. A test pins that connection and platform events stay unmapped, since mapping them would inflate
every tactic count.

**Memcached `stats` no longer restarts its uptime on every connection** and keeps one pid; counters grow with
uptime and `get_hits + get_misses` stays equal to `cmd_get`.

**The three blocklist push tools were only ever tested against mocks of themselves.** Checked against the
vendors' own contracts they were wrong, or incomplete, in four places. pfSense: the REST API (pfrest v2)
authenticates with `X-API-Key`, addresses an alias by integer `id` from `GET /firewall/aliases`, and updates
with `PATCH`; the tool sent `Authorization`, queried by name and used a `PUT` that does not exist, so it
failed against a real appliance. Cloudflare: creating list items is an asynchronous bulk operation and an
account may have one pending, so chunks sent back to back were refused after the first, and a 200 was
reported as "added" before the change had happened; each operation is now awaited and a failed or stuck one
is reported as failed. AWS WAF: `UpdateIPSet` replaces the description, so every push blanked the
operator's own; it is now preserved. The tests drive real `httpx` through strict stubs of each contract and
botocore's `Stubber`, which validates against the WAFv2 service model; all were checked to fail against the
previous code.

## Decoy tells found by stock nmap scripts: frozen clocks, constant ids, three kernels on one host

Running the NSE scripts (`ldap-rootdse`, `mysql-info`, `mongodb-info`, `redis-info`, `docker-version`)
against the live VPS showed what a scanner sees. The LDAP rootDSE `currentTime` was frozen six days in
the past; every MySQL connection reported thread id 12345; Redis and MongoDB uptime never advanced; and
Redis, the Docker API and the Kubernetes node reported three different kernels although they share one
IP. LDAP now reports the real clock (`directory_time`), MySQL ids count up from a random start, uptimes
grow from one shared base (`engines/_uptime.py`), and `engines/_host_identity.py` is the single source of
the kernel and OS string. `tests/unit/test_engine_identity.py` pins each; every test was checked to fail
against the old behaviour.

## Notifications carry reputation; sensor ids are never reused; stopped sensors can be removed

**Slack, Teams and email now show who the attacker is.** A notification used to carry only the event,
so whoever was paged had to look the address up. A "Reputation" block now shows location, network,
the AbuseIPDB score with its report count, and VirusTotal's engine verdicts: for example
`United States (Dallas) · AS36352 · RackNerd LLC · AbuseIPDB 71/100 · 66 report(s) · VirusTotal 0 of 92
engines` on a real SIP toll-fraud scanner. It is looked up through the per-IP cache the background
enrichment already uses (VirusTotal 30 min, AbuseIPDB 15 min, GeoIP 24 h), **only when a message is
actually about to be sent** (after the throttle has decided), waiting at most
`NOTIFY_ENRICH_TIMEOUT_SECONDS` (4; 0 turns it off); a slow or failing third party never delays or
blocks the alert. Cost, from the real 20-hour run of 619 source IPs: 29 distinct CRITICAL sources
(27 public), 49 distinct (type, source) pairs and at most 6 CRITICAL sources in the busiest hour, so
at most a few dozen lookups a day against the free tiers' 500 (VirusTotal) and 1,000 (AbuseIPDB). Third-party text is escaped
like everything else shown to a human. The machine formats (JSON, ECS, CEF, Splunk, Loki, Datadog)
are unchanged: the SIEM enriches those.

**A removed sensor's id was handed to the next sensor.** SQLite reuses the highest rowid after a
delete, so removing the newest sensor and deploying another gave the new one the old id and quietly
attached the old sensor's alerts and rollups to it. The table is AUTOINCREMENT now (migration 0019,
which seeds the counter past every id ever referenced by alerts or rollups, not just surviving rows).
Removal also left the rollups pointing at the removed sensor while the raw alerts were NULLed, so the
rollups stopped agreeing with the alerts; they are re-filed under "no sensor" in step. And
`honeypot_stop(name=..., remove=True)` on an already-stopped sensor did nothing and answered
`stopped: []`, so a stopped sensor could never be removed and its name stayed reserved; it now is.

## Answers checked against SQL; prune no longer needs gigabytes; notification counters told the truth

**The read tools are checked against independent SQL.** `scripts/field_test_oracle.py` runs the
analysis tools on a copy of a frozen real backup and compares each answer with plain SQL over the
alert table: `alerts_stats` over five window shapes, per-sensor hits, `soc_brief` counts and queue
order, `alerts_recent` filters, `alerts_search`, `threat_timeline`, `analyze_attacker`/journey for
heavy and light sources (count and first/last seen to the microsecond), the blocklist's membership,
and cross-tool invariants. On 4,896,441 real alerts: 67 checks, 0 failed, 28 s; changing one rollup
count by one makes the total, severity split, top sources and per-sensor hits fail.

**`alerts_prune` streams.** The manual tool built the whole archive as one string and deleted with
one statement: on copies of the live database 1,000,000 rows peaked at 1.35 GB (about 6.6 GB for the
real table on a 4 GB host). The retention sweep already streamed, so both now share
`retention.archive_alerts` / `delete_before`: 4,000,000 rows archived in 54 s at 181 MB peak, integrity
ok, lifetime rollups untouched; a `.partial` file is renamed only when complete, a caller-named path
is never overwritten, a failure deletes nothing, deletion is confined to archived ids and chunked.

**A throttled notification was counted as a delivery.** The Slack subscription reported 13,025
deliveries in nine hours while its channel had received a handful of messages: a suppressed event
returned success and was recorded as one. Worse, that "success" reset `failure_count` and cleared
`last_error`, so a broken webhook would have looked healthy as soon as the throttle swallowed the next
event. Throttled events now increment `suppressed_count` (migration 0018, shown by
`alert_subscriptions_list`) and touch nothing else.

**The field-test sweep stopped packet capture on the live VPS.** It called `pcap_control stop`
(written when capture was off) and ended capture on a deployment where it was on; it now starts
capture (idempotent) and checks `pcap_extract` against the real state. Capture was restarted at once.

## The telnet sensor was being OOM-killed every few minutes; backups; status behind the guard

The first full backup of the 3.8 GB database finished with one warning: 33 health failures on the
telnet sensor. Following it found that **`honeypot-hp-telnet` had been OOM-killed 246 times in 20
hours** (54 in the last 12), each time discarding every session, recording and sample in the
container and showing as "running" in between. The container's memory cgroup counts the kernel
memory of every file in its tmpfs on top of the `size=` cap, which does not limit the *number* of
files: 54,000 files cost ~80 MiB of a 256 MiB limit. 99.8% of the 43,591 files in `downloads/` were
0-byte `tmp…`/`redir_…` leftovers of failed fetches (egress is closed by default and Cowrie never
removes them), and the 10,654 session recordings came to ~85 MB against a 64 MB tmpfs, so the
directory was also full and new recordings and real downloads were failing to write.

The fix runs inside the container as part of the existing `sitecustomize` patch
(`cowrie_sitecustomize.prune_artifacts`): empty download leftovers older than five minutes are
deleted and only the newest 5,000 recordings are kept (settings
`cowrie_janitor_interval_seconds` and `cowrie_max_tty_files`, `COWRIE_JANITOR_INTERVAL_SECONDS` /
`COWRIE_MAX_TTY_FILES` in `.env`; 0 disables it; symlinks are never
followed). A first design that used `docker exec` from the host was refused by the Docker guard,
which denies `exec` by design; the guard was left alone. The patch applies to containers created
after the change, so existing sensors need a stop/redeploy.

Also found on the way, each with a test that fails on the old code. `honeypot_status` on any
Docker-backed sensor failed with a 403 from the guard (`container.image` makes the SDK fetch the
image): it worked on every in-process sensor and broke on every Cowrie one in the hardened
deployment; it now reads the container's own record and also reports `restart_count` and
`oom_killed`, because a flapping sensor reads "running" between kills. And `scripts/backup.sh` used
`sqlite3 .backup`, which ran 38 minutes on the live database without finishing; it uses
`VACUUM INTO` (203 s on the same database; the full fetch of 3.8 GB takes about 10 minutes).

## Built for scale: statistics read rollups, one flood cannot fill the table, PostgreSQL parity

The previous entry fixed one scan; the cause was the design. Every aggregate read the alert table,
and a public host's table grows by millions of rows a day. Three changes, each proven on real data.

**`alert_rollups` (migration 0017).** Alerts counted per hour per (severity, event type, source,
sensor), written by a `before_flush` hook so every Alert writer is counted in its own transaction
(a rollback takes its counts with it; nobody can forget a helper). `alerts_stats`, `soc_brief`,
`honeypot_list`, `analyze_attacker` and journey totals, the blocklist/campaign candidates and
`/metrics` read it; partial indexes `ix_alerts_acked` and `ix_alerts_urgent` keep the triage queue
off the LOW/MEDIUM flood. On a copy of the real 1.1M-row database the migration takes 11 s and
1,096,510 alerts become 1,311 rollup rows with the identical total; `alerts_stats`, `soc_brief` and
`honeypot_list` went from 27 s, over 100 s and 51 s to 0.01 s or less. Windowed answers are exact to
the second (whole hours from the rollups, the edges from the rows) and are tested against a brute
force count for six window shapes; lifetime figures survive `alerts_prune`. `analyze_attacker` used
to describe a source from its newest 200 alerts plus 200 duplicate event rows, so a 39,916-hit
attacker was reported with a capped, doubled count and first/last seen from the sample; the totals
are exact now. `attacker_events` keeps only honeytoken-linked events (it copied every event,
payload included, doubling the table).

**Flood guard (`flood_guard.py`, on by default).** A source keeps its first 600 events a minute per
event type; the rest are counted into one `flood_summary` event per window, so volume stays visible
while it stops being the storage mechanism. CRITICAL events and honeytoken hits are never dropped
and different event types from one source are independent. `FLOOD_GUARD_PER_MINUTE=0` disables it.

**Bugs the work surfaced.** On PostgreSQL `coalesce(x, $3)` in SELECT and `coalesce(x, $5)` in
GROUP BY are different expressions and the query was rejected (SQLite accepted it): found only by
running the new migration and queries against a real PostgreSQL 16, pinned by a compile-level test.
The in-memory test database is one shared connection and the pool's reset-on-return rolled back
other sessions' uncommitted writes, which made three honeytoken tests lose the flusher's Alert row
depending on interleaving; reset-on-return is off for `:memory:` with a test that fails without it.

## Found at 5 million rows: the per-sensor count scanned the whole table

Reading the data the morning after the first night: one SIP source sent about 190 events a second
and the database grew from 1.1M to 4.9M alerts (3.8 GB, past the 4 GB VPS's RAM). `honeypot_list`,
the most basic tool, took 51 seconds because `alerts.honeypot_id` had no index and the per-sensor
count read every row. Migration `0016_alert_honeypot_idx` adds it (a covering index, so no table
read): 0.02 s on a 1.1M-row copy and 2.7 s live (1.5 s of that is connection overhead), 34 s to build
on the 4.9M-row table. A test pins the query plan. A rate-limit rule on the flooder (the shipped
`suppression_add` remedy) cut ingest from 198 to 11 events a second and the service's CPU from 112%
to 23%, the first live proof of that tool against a real flood.

Not fixed by this: `alerts_stats` (27 s all-time, over 100 s over a one-hour window) and `soc_brief`
(over 100 s) still time out at this size, because their aggregates read millions of rows and the
table no longer fits in memory. Extra composite indexes did not change the query plans in a local
test, so the answer is bounding what is stored (flood guard, rollups), not more indexes.

## The platform stopped recording its own probes as an attacker; dashboards work from a backup

Found by reading the live data and by opening the dashboards on a restored backup in a browser.

The watchdog probes each Cowrie container through its published port from `127.0.0.1`; the
container sees that connection from the Docker bridge gateway (`172.17.0.1`) with the port
unchanged, and only the loopback address was registered with the self-probe filter, so every probe
was recorded as an attacker: 1,060 connect/close pairs per sensor in nine hours, listed as a source
in campaign analysis and "top attackers". `tcp_probe` now also claims its bound port under the
container's bridge gateway. Live: 48 such events in six minutes before the fix, none in four after.

The Grafana `Active honeypots` tile was the only panel on the Prometheus datasource and read "No
data" anywhere without Prometheus (a laptop reading a backup); it now counts running rows in the
`honeypots` table. The threat map's default basemap resolves to CARTO's free tiles, which now stamp
"API KEY REQUIRED" over every tile while still answering HTTP 200; it is now an explicit keyless,
label-free Esri Dark Gray Base layer. Tests pin both and fail on the old dashboards.

## Management tools tested on live traffic: two real bugs

`scripts/field_test_ops.py` (see [docs/FIELD_TEST.md](docs/FIELD_TEST.md)) uses the triage,
analysis, remediation and operations tools on what the internet actually sent and asserts on the
answers, not their shape. It found two bugs the unit tests could not.

`honeypot_pause` was a lie for every in-process engine: it returned `paused` while the port kept
answering and recording, because `pause()` is a no-op for anything that is not a Docker container.
Pausing now closes the listener and resume starts a fresh one on the same port (a resume that cannot
bind says so and leaves the sensor paused); Docker-backed SSH/Telnet keep their real pause.
Proven live: `hp-vnc`'s public port closed on pause and reopened on resume.

Bulk triage by filter re-selected the 500 newest matches whether or not they were already triaged
and overwrote the first analyst's disposition, note and name; with the cap a repeat run never reached
older untriaged alerts. A filter now selects untriaged alerts only, and naming ids re-triages
deliberately. Both fixes have regression tests that fail on the old code.

Also confirmed on live data: every alert from a real attacker carries GeoIP, VirusTotal and
AbuseIPDB (196 of 196 CRITICALs sampled); campaign analysis groups the Mirai-style loader sources;
all 12 SQLite panels in the three Grafana dashboards return rows from a restored backup.

## Public traffic can trip tokens; repeated CRITICALs no longer flood a channel

Two findings from the live VPS, both fixed and proven from outside.

**Honeytokens could not be tripped by the public.** The HTTP decoys (`/.env`, `/config.json`,
`/wp-config.php`) were random, so no scanner could ever find a tracked credential, and the canary
callback server binds loopback and is closed by the firewall, so a canary URL could never call
back. Now a tracked MySQL credential token is served as the database login in those files
(`credential_match.planted_credential`, lowest active token id, revoked tokens never served), and an
active canary-URL token is embedded as an error-reporting webhook. The HTTP honeypot answers
`/t/<token>` on its own public port (`canary.serve_if_token`; an unknown id is a plain 404 so `/t/`
is not itself a fingerprint), with no new exposure. Proven from outside against the VPS: read
`/.env` on port 80, replayed the pair on the public MySQL port, and followed the webhook URL; both
tokens tripped with CRITICAL alerts.

**One scanner could turn Slack into a firehose.** CRITICAL was exempt from the notification
throttle on the assumption it is rare; one source sending ~700 SIP toll-fraud INVITEs an hour is a
message every five seconds, and the only cap (30 a minute per event type) sat far above it. The
first CRITICAL of each (event type, source) still pages immediately; identical repeats within
`NOTIFY_CRITICAL_REPEAT_SECONDS` (300) are coalesced into a "+N suppressed" count, and honeytoken
triggers are never coalesced. `NOTIFY_CRITICAL_PER_MINUTE` existed but was never passed to the
throttle; it is wired now. Live: 24 messages in ten minutes against the real flood, about 12 a
minute from SIP alone before.

## Field test: proving a live deployment, and what it found

Two scripts that run from a machine other than the VPS, documented in
[docs/FIELD_TEST.md](docs/FIELD_TEST.md). `scripts/field_test.py` attacks every deployed engine
through its public port with a real client (paramiko, redis-py, pymongo, pymysql, asyncpg, impacket,
ldap3, httpx, kubectl, rsync) and checks the downloaded database for the expected event types from
the attacker's address: 23 probe groups over 22 engines, all recorded. `scripts/field_test_tools.py`
calls all 65 MCP tools at their proper roles (78 checks, including refusals across roles, a
live-provisioned API key that is refused the moment it is revoked, and a honeytoken round trip: a
planted credential used through a real SSH login raises a CRITICAL alert and marks the token
triggered). It fails if a registered tool is neither called nor explicitly skipped.

Run against a real DigitalOcean VPS it found, besides the three bugs in the entry below:
`fetch_backup.sh --samples` reported "0 files" with a clean verdict while the Cowrie containers held
32 downloads and 18 TTY recordings (it looked in `/cowrie/var/lib/cowrie`; the image keeps its state
under `/cowrie/cowrie-git`; a missing directory is now a failure), and `http_active_recon`
overwrote `http_credential_submit` once a session had made five requests, so a login attempt by a
scanner that had crawled first was filed as recon. The backup test rig's fake `docker exec` ignored
the script it was given, which is why the first could not fail a test; it now runs the real script
against a fake container filesystem. New tests fail against the old code.

## Getting the data off the VPS: `scripts/fetch_backup.sh`

A laptop-side script for the end of a run (and mid-run): it takes a consistent backup on the VPS,
streams it back over one SSH connection (the admin port allows 6 new connections a minute),
verifies the transfer (the database's SHA-256 here equals the VPS's) and the database
(`integrity_check`), quarantines Cowrie's downloaded files and TTY recordings (no permission bits,
symlinks removed, SHA-256 list), and prints a report that answers "did the run work": time window,
events per sensor, dead or silent sensors, hours with no activity, top sources and credentials,
honeytoken trips, platform alerts, and a PASS/WARN/FAIL verdict (`--expect-types` names the
honeypots you deployed). The VPS is treated as hostile: archive paths are checked before unpacking.
Self-test probes and platform alerts are not counted as attacker activity. Works with macOS's bash
3.2. Run once over a real sshd with `sudo`, a real `docker exec` into a real Cowrie container, and
a real tmpfs: `docker cp` returns nothing for a tmpfs path, so samples are copied by running Python
inside the container. 19 unit tests drive the real `backup.sh` through fake `ssh`/`sudo`/`docker`
shims, including a hostile archive, a checksum mismatch and symlinks.

## Host hardening for a public VPS

Everything around the honeypots is now locked down while the honeypots themselves stay open to the
whole internet (`docs/HARDENING.md`). Rehearsed end to end on an Ubuntu 22.04 systemd host with a real
`dockerd`, an attacker container and the MCP client over an SSH tunnel:

- **Docker guard** (`hardening/docker_guard.py`, `honeypot-docker-guard.service`): the service is no
  longer in the root-equivalent `docker` group. It reaches Docker through a validating proxy that
  forwards only the Cowrie container operations the SSH engine makes (pinned image, `honeypot-*`
  names, the engine's own security settings, labelled containers only) and refuses privileged
  containers, host mounts, exec, other images and every daemon-wide call. The container spec moved
  to `engines/cowrie_limits.py` so the engine and the guard read one definition.
- **Firewall** (`hardening/firewall.py`): default-drop input with exactly the planned honeypot ports
  and a rate-limited admin SSH port; privileged ports redirected to the engines'; containers cannot
  start connections or reach the host (or, in the opt-in `limited` mode, only public web servers at a
  capped rate, never private space or the metadata service); the service user can only answer,
  resolve and open HTTPS.
- **`deploy/harden-host.sh`** (`prepare`/`finalize`/`confirm`/`status`/`teardown`): key-only sshd with
  local forwarding only, kernel hardening, Docker daemon settings (`userland-proxy`/`icc` off),
  unattended security updates, and a two-phase SSH move that cannot lock you out (sshd on both ports
  first; the firewall loads with a rollback timer).
- **Units**: `honeypot-mcp.service` tightened (syscall deny-list, `ProtectProc=invisible`, no core
  dumps; systemd score 1.4), the guard (0.6) and firewall units added. **`deploy/env.production.example`**
  moves the control plane (18443), metrics (19090) and canary (18888, loopback) off their defaults,
  turns the console off and uses three role tokens.
- **Pre-flight host checks** (`hardening/hostcheck.py`): unplanned public listeners, firewall loaded,
  service not in the docker group, the guard refusing a daemon-wide call, sshd, sysctl, updates.
- Bugs the rehearsal found that tests had passed: the documented `uv sync` as root left the service
  unable to execute its interpreter; re-running `prepare` reopened port 22; the guard's `chown` is
  forbidden by its own syscall filter; sshd was checked for its new port before it had re-bound; the
  pre-flight rejected the documented `root:honeypot 0640` `.env` and probed the guard as root.

## Real attacker tools against the engines

Every in-process engine was deployed and attacked with the tools an intruder uses (nmap with
version detection and scripts, snmpwalk, ldapsearch, kubectl, smbclient, impacket, mariadb,
redis-cli, psql, hydra, SIPVicious). The decoys that passed their unit tests were still
identifiable, or could not be used at all, by these:

- **SMB2 NTLM capture.** The SMB honeypot closed on SMB2, so `smbclient`, impacket, NetExec
  and Metasploit never reached a login. `engines/smb2.py` negotiates dialect 2.1 and plays the
  server side of NTLM session setup: the response is captured as `smb_ntlm_auth` with a
  hashcat `-m 5600` line (verified to crack against the password impacket used), planted
  credentials with `service: smb` trip their token, and the login is refused. The SMB1 answer
  now matches nmap's Windows 7–10 signature and names the same host/domain as the NTLM
  challenge. `smb` declares `captures_credentials_as="smb"`; the ATT&CK dashboard was
  regenerated.
- **SNMP walks.** A small ordered MIB with GetNext/GetBulk semantics, `endOfMibView`,
  `noSuchObject`/`noSuchName`, `notWritable` on Set and an advancing `sysUpTime`; before,
  `snmpwalk` stopped at once ("OID not increasing").
- **Kubernetes API.** TLS-only (plain HTTP made `kubectl` unusable), stable identity (the
  commit, UIDs, pod names and flow-control UIDs were random per request), discovery, `/healthz`,
  nodes, shortNames, server-side Table output and `auth can-i`: `kubectl get pods|nodes|secrets`
  prints what a cluster prints.
- **LDAP rootDSE** (naming contexts, capabilities) and AD-style refusal of anonymous searches.
- **MySQL** AuthSwitch (libmariadb's password was never captured), `auth_plugin` no longer
  misfiled as the database, `SHOW DATABASES`. **MSSQL** answers in the client's TDS version and
  names the account in the login failure. **PostgreSQL** error frames carry `F`/`L`/`R`
  (nmap now reports 14.10 - 14.15), a real `version()` string and real command tags.
  **Redis** Redis 7 error wording and `CLIENT`/`ECHO`/`TIME`.
- **The open gaps from that sweep, closed.** `engines/tls_front.py` fronts TLS listeners (the
  Kubernetes API and the HTTP engine's `tls` mode): a pre-1.2 ClientHello gets Go's
  `protocol_version` alert and plaintext HTTP gets a reply, instead of a silent close that left
  `nmap -sV` printing `m2ap?` and the `ssl-cert` script unrun. The HTTP engine's plaintext reply is
  the persona's own (Apache's explanatory page naming host and port, nginx's 400 page, nothing
  from IIS); the Kubernetes API uses Go's one-line 400. MySQL offers TLS (`CLIENT_SSL`) and
  completes it through memory BIOs, because the client's ClientHello can arrive in the same
  segment as its SSLRequest and `start_tls` cannot replay bytes already read (30/30 logins from
  the `mariadb` client). The Kubernetes decoy resolves single objects, namespaces, nodes and
  RBAC from one model, answers `describe`/`get pod X`/`-o yaml`, a real `NotFound` for a missing
  name, empty results for a namespace that does not exist, and `?watch=1`.
- **Certificates have the shape of the service.** One generic self-signed `O=Internal` cert with
  a `localhost` SAN served every engine, and `ssl-cert` / `openssl s_client` read it first.
  `tls.CertProfile` now describes each: Kubernetes is `CN=kube-apiserver` from a CA named
  `kubernetes` (one year from the cluster's creation, service-name and IP SANs, serverAuth),
  MySQL is the `..._Auto_Generated_Server_Certificate` from an auto-generated CA (ten years, no
  SAN), RDP is self-signed and named for the computer FQDN the NTLM challenge discloses, and the
  default is a bare backdated `CN=<name>`. Persisted certificates that no longer match, or have
  under 30 days left, are reissued. Apache's 404 page no longer claims `Port 80` on every
  listener and no longer prints the Host header's port as part of the host name.
- **Cowrie no longer announces itself to nmap and ssh-audit.** Sweeping the SSH/Telnet
  honeypots found `nmap -sV` printing "Cowrie Honeypot telnetd" (a rule for the `IAC DO NAWS` +
  `login:` opening) and an SSH offer (3des-cbc, cast128-cbc, hmac-md5, group14-sha1, bare
  ssh-rsa, zlib) that contradicts the OpenSSH banner. A `sitecustomize` delivered into the
  container with the persona filesystem narrows the offer to the persona's OpenSSH defaults and
  makes telnet open like a Linux telnetd (`Linux telnetd` in nmap). Checked on the real image by
  a Docker-gated test that reads the KEXINIT and the telnet opening. Also: the SMB honeytoken
  test's poll raced the flusher on in-memory SQLite (~44% on Python 3.11) and multidict is bumped
  for an advisory.

## A console behind the RDP login, and the last mail gaps

- **The RDP desktop works.** Double-click the `cmd` icon, use Start, or Win+R `cmd`/`powershell`,
  and a console opens. A fake shell (`rdp_shell.py`) answers `whoami`, `dir`, `cd`, `type`,
  `echo > file` (readable back), `ipconfig`, `systeminfo`, `net user` (incl. `/add`),
  `tasklist`, `netstat`, `quser`, PowerShell cmdlets and Windows' exact error wording. It
  executes nothing and has **no route out**: every download tool fails the way a firewalled
  server fails, `ping` times out, and the URL is extracted into a CRITICAL `rdp_command`
  event. Rendering is a framebuffer with Spleen 8x16 glyphs and dirty-rectangle updates (a
  keystroke costs ~1 KB). Checked with FreeRDP 3 driven by xdotool (double-click, typed
  commands, screenshot) and recorded events.
- **The clipboard goes both ways**: an optional `clipboard_text` is announced as the
  server's own and served to a visitor who pastes it. aardwolf showed that clients ignore a
  server Format List until their own initial exchange completes, so the offer follows it.
- **IMAP**: Sent/Drafts/Trash/Junk hold ordinary seeded mail; CREATE/DELETE/RENAME of the
  visitor's own folders, APPEND (recorded as `imap_append`) and COPY work for the connection
  only and are bounded.
- **An independent review of this round** found no security-class defect (120,000 hostile
  commands with socket/file/subprocess patched to raise; every update rectangle reconstructed
  the screen exactly on a simulated client) and these, now fixed: an unbounded glyph cache (85,000
  distinct Unicode characters = 121 MB); INBOX mail the visitor appended was numbered from
  1,000,000 so UIDs went 1 2 3 1000001 4 and UIDNEXT never rose when new mail arrived (appended
  mail now takes a number from the shared counter); UIDVALIDITY did not change when a folder was
  deleted and recreated; APPEND with no literal stored an earlier literal as the message; text
  in an appended message body was read as its flags; COPY stopped half-way over quota; the
  128 KB literal allowance applied to any line containing the word APPEND; no cap on what one
  connection may be sent; the console did not know `cmd` (so `cmd /c ...`, the commonest launcher,
  failed from a window titled cmd.exe), `cd..`, `ipconfig/all`, `dir/w`, `echo.`, quoted paths
  with spaces, `rmdir`/`ren`/`move`, `shutdown`/`logoff` (which now end the session, as they
  would), `powershell -w hidden -c ...` (flag values were run as the command), and answered
  `ping localhost` with a timeout; `echo curl` was treated as a download and raised CRITICAL;
  the console claimed Server 2019 whatever build the honeypot reported over NLA; files differed
  by case, `> nul` made a file; a PowerShell window turned into cmd on `exit`; Run opened under
  a message box that then swallowed its input; dialogs overflowed small screens; Ctrl+V typed a
  `v` (it now pastes the visitor's clipboard) and a lost Win key-up swallowed all later typing;
  the server's clipboard offer could cancel the visitor's first paste, so it now follows it.
- A FreeRDP integration test was writing its honeypots into the developer's own
  `honeypot_mcp.db` (the settings were cached before the test set `DATABASE_URL`); it now uses a
  throwaway database like the SSH tests.

## Mail clients, the clipboard, and a pre-flight

- **IMAP serves the maildrop** the SMTP honeypot fills, to the same logins as POP3 (a planted
  credential or the one weak pair). SELECT/EXAMINE, LIST/LSUB/STATUS/NAMESPACE, FETCH
  (ENVELOPE, BODYSTRUCTURE, sections and partials), SEARCH (NOT/OR/groups/dates), STORE,
  EXPUNGE, IDLE, UID variants and literals. Checked with stdlib `imaplib` and with `curl`.
  Flags and expunges last for the connection only. CAPABILITY now advertises only what is
  implemented (`AUTH=LOGIN` and `LITERAL+` were advertised before they worked).
  Found along the way: serialising a message with the default line ending (bare LF) made
  every IMAP octet count short by one per line, which desyncs real clients.
- **POP3 `AUTH PLAIN` / `AUTH LOGIN`** are decoded, so a credential sent that way is matched
  against planted tokens and can log in like `USER`/`PASS`.
- **RDP clipboard (MS-RDPECLIP).** Text a visitor pastes into the session is recorded
  (`rdp_clipboard`, and in the session summary): the command they were about to run.
- **`python -m honeypot_mcp.preflight` / `scripts/preflight.sh`**: configuration, bind
  addresses, token strength, disk, ports (including the lock-out of the SSH port you are
  connected on), Docker, backups, `/readyz`, ownership, per-sensor health, an end-to-end
  probe of *every* sensor, and whether anyone is subscribed to alerts. Run against a real
  daemon it found that **the SMTP `honeypot_self_test` had been failing**: the probe expected
  its marker in the raw command after AUTH began to be decoded into username/password, and no
  test covered SMTP, FTP or DNS. Fixed, and all three are now in the self-test suite.
- `docs/DEPLOY.md` gains the go-live checklist.
- **An independent review of this round found, and this fixes** (no auth bypass; the rest
  would break real clients or allow resource exhaustion): a non-ASCII attachment name
  (RFC 2231) made BODYSTRUCTURE raise and the command never got a reply; one hostile message
  in a mailbox (nested multiparts, nested `message/rfc822`, address-group syntax) overflowed
  the stack and broke FETCH for everyone reading that mailbox; an ordinary multi-line APPEND
  was answered `BYE Too fast` because literal bytes were counted as command lines; a 512 KB
  write-backlog limit aborted FETCH of a larger mailbox for a merely slow client (now
  backpressure with a 15 s no-progress cutoff); thousands of FETCH items or `1:4294967296`
  sets were built before anything was sent (capped at 16 items, parsed off the event loop,
  4 at a time); `LIST` patterns went through `fnmatch`'s process-wide cache; tags and numbers
  could carry CR/LF or 5,000 digits into a reply or an uncaught exception; POP3 `AUTH` was
  reachable after login and swallowed the next command as a credential; the clipboard could
  be blinded by one oversized message; the client's MCS user id could collide with a static
  channel id. Pre-flight: guessable long tokens passed, a disabled console was reported as
  exposed, the packet ring was charged to the wrong volume, a failed backup left a directory
  that counted as one (`backup.sh` now publishes only a complete snapshot), a port in
  TIME_WAIT read as taken, UDP ports were never probed, and an error object where a list was
  expected read as "no sensor is dead".

## Depth: mail, RDP sessions, ownership, cloud tokens

Closing the limitations that could be closed (APT research, real TLS termination and
internet exposure remain out of scope).

- **RDP has a session after authentication.** A planted honeytoken credential, or the one
  weak pair derived from the honeypot's name, is let in. Over NLA the CredSSP exchange now
  runs to completion (session key from the password, sealed public-key binding; FreeRDP 3
  and aardwolf both accept it), and the server reads SPNEGO-wrapped NTLM, which is what
  Windows' own client sends (the old code only understood bare NTLM, so it never worked
  against mstsc-style clients). The visitor gets a static desktop, painted and checked
  pixel-for-pixel in FreeRDP, and their keystrokes, clicks and mouse movement are recorded
  as `rdp_session`. Verified by a mutation-replay fuzz of a recorded session.
- **SMTP has a queue.** Messages are analysed (attachments hashed, links listed, executable
  attachments CRITICAL), local mail goes to a maildrop, undeliverable destinations bounce
  with a real RFC 3464 notice to a local sender. Nothing is ever sent onward.
- **POP3 serves that maildrop** to a planted credential or its weak pair.
- **Ownership.** A read-only server promotes itself when the owner exits; PostgreSQL
  ownership is an advisory lock, so servers on different hosts are detected.
- **Disk.** `disk_space_low` notifies subscribers before it tries to write itself;
  `honeypot_database_size_bytes` makes a remote database's growth visible.
- **Cloud tokens can adopt a real decoy identity** (Terraform / `az` / `gcloud` provided),
  which is what makes them observable; a generated key leaves no audit-log trail.
- `aardwolf` (an independent pure-Python RDP client) added as a dev dependency for the RDP session tests.
- **An independent review of this work found, and this fixes:** an authentication bypass
  (a planted *canary email* typed as the RDP/POP3 password set `honeytoken_id`, which was read
  as "a planted credential", so any username got a session); planted credentials that never
  worked over plain-TLS RDP; a logged-in RDP peer getting ~35,000x amplification from repeated
  Font List / Refresh Rect PDUs (now one desktop, 3 refreshes, 16 MB per session); CR/LF
  injection into generated bounce notices; binary attachments hashed after being re-encoded
  as text; a 3 s event-loop stall from nested MIME (now off-loop, capped); executables hidden
  by `a.exe.` / RTL-override names or by being the 11th attachment; unbounded POP3 output
  buffering; lock handling that read "could not ask the database" as an answer (owner losing
  its lock to a no-op, a reader promoting itself during an outage), failed promotions that
  held the lock with nothing running, and a PostgreSQL lock connection that an
  `idle_in_transaction_session_timeout` would kill; cloud-token validation holes, duplicate
  identities that shadowed each other, a unique-constraint error that echoed the secret, the
  raw GCP key file stored twice, and decoy keys whose most likely first call
  (`sts:GetCallerIdentity`, which IAM cannot deny) the AWS forwarder did not forward.

## Agent surface, scale and self-monitoring

A gap audit of the product as an *agent* sees it, at scale, and when something goes wrong.

- **Tool annotations and titles** on all 65 tools (`tool_hints.py`), fail-closed: an
  unclassified tool cannot register. The viewer tier is pinned read-only (except
  `generate_report`, which writes a file). Eighteen terse descriptions were rewritten;
  a test requires every parameter to be documented.
- **MCP prompts** (`prompts.py`) and rewritten server instructions.
- **`analyze_attacker_journey` was 12.2 MB in 5 s** for the busiest source in a
  250k-alert database. Now exact totals plus a bounded sample: 26 KB in 0.3 s.
- **SSH client fingerprints.** Cowrie's `client.kex` (HASSH) and `direct-tcpip.data`
  events were being discarded as unmapped. Now recorded, `ssh_port_forward_data` maps to
  T1090, and `fingerprint_clusters` groups sources by HASSH.
- **Two servers on one database** raised false CRITICAL `honeypot_restart_failed`
  alerts. An `flock` ownership lock makes the second one read-only; a killed owner
  releases it automatically. Checked with two real processes.
- **Disk space is watched.** A full disk stops persistence while the listeners keep
  answering. `/readyz` goes 503, `honeypot_disk_free_bytes` is exported, and the watchdog
  raises one CRITICAL `disk_space_low` (re-armed after recovery). `MIN_FREE_DISK_MB`,
  default 500, 0 disables. New `honeypot_sensor_up{name,type}` gauge.
- **`honeypot_webhook_dropped_total` was never exported** (the metrics code read an
  attribute the class did not have). Fixed and pinned.
- **RDP TLS-upgrade race** (latent): a client sending its TLS hello immediately after the
  Connection Confirm could be reset on a cold certificate. Found only by running the suite
  on Python 3.12.
- `fastmcp>=3.4,<4` — the old `>=2.0.0` floor was never true. Suite verified on Python
  3.11, 3.12, 3.13 and 3.14.

## Fidelity: what a human probing by hand would notice

The limitations list named the places a skilled person could tell the engines from
the real thing. Each was measured against the real tool and fixed, not described.

- **FTP** serves files. `LIST`, `SIZE`, `MDTM`, `CWD`, `REST` and `RETR` come from one
  file tree (`engines/ftp_fs.py`), so a listed size is the length of the bytes that
  download; the archives really gunzip/untar; `EPSV` (advertised in FEAT but never
  implemented) works; unknown commands get ProFTPD's `500`. A data listener closed
  before the `226` used to be able to kill the client's *next* `PASV`.
- **SMTP** speaks Postfix: out-of-sequence commands get `503`, an unknown local
  mailbox is `550 5.1.1`, `VRFY` distinguishes mailboxes (it answered `252` to
  everything), the EHLO greeting is the bare hostname. `nmap smtp-enum-users` now
  finds the real mailboxes and only those.
- **HTTP** has an authenticated area (`engines/http_admin.py`): a planted honeytoken
  credential or one per-honeypot weak pair logs in; the console, its downloads and
  uploads are recorded as `http_authenticated_request`. `accepted_logins` overrides it.
- **RDP** does CredSSP/NTLM. The negotiation response carries Windows' flags
  (`nmap -sV` now says `Microsoft Terminal Services`), `rdp-ntlm-info` reads a stable
  Windows identity, and the NetNTLMv2 response is captured as a `hashcat -m 5600` line
  and verified against an independent client (pyspnego); a planted RDP password trips
  its honeytoken from the response alone. NTLMv2 maths is checked against MS-NLMP's
  published vector.
- **Cowrie persona.** The persona's kernel/OS settings were set in the wrong Cowrie
  config section (`[honeypot]` instead of `[shell]`), so `uname` kept reporting the
  image's own Debian kernel whatever persona was chosen — invisible to the unit
  tests, which pinned the wrong names. Fixed, and the bundled filesystem is now
  rewritten per persona (`/etc/hostname`, `issue`, `os-release`, `/proc/version`,
  accounts, MOTD, a home directory; `phil` gone). Delivered into the container through
  an anonymous volume — Docker refuses to extract an archive into a read-only
  rootfs — and the compose stack builds the same filesystem with a one-shot init job.
  A Docker-gated test deploys all four personas and compares what an attacker reads.
  One mistake worth recording: filling `/etc/issue.net` made Cowrie send it as a
  pre-auth banner on every connection, which a stock `sshd` does not do; found by
  reading stderr of a live login, now asserted.
- `tls/` and `reports/generated/` follow settings instead of the working directory;
  tcpdump rings are `0600` in a private directory (via an `sh` `umask` wrapper, not
  `preexec_fn`, which is unsafe with threads); Grafana can read a host database through
  one dedicated group instead of a looser directory.
- **Event buffer:** a transient database error (`OperationalError`: a locked SQLite
  file, a dropped connection, a deadlock) used to be retried immediately and then each
  event was dropped as "refused by the database". It now backs off for ~1.5 s before
  giving up; a genuinely rejected row still costs only itself. Found because the new
  tests flaked on shared in-memory SQLite.
- **Compose:** `honeypot-net` pinned `172.20.0.0/24`, inside the range Docker
  auto-assigns to the other networks, so `up` failed on hosts where creation order or
  existing networks collided. The pin was never needed and is gone.

## Second independent review, hostile-traffic run, and Cowrie egress

Two more reviewers (control plane/secrets, engines/deployment) and a run of real
hostile traffic against the server on its LAN interface. The traffic run was
clean: `nmap -sV --version-intensity 9` identified every engine as the product it
imitates, 3,600 fuzzed connections plus 9,000 UDP datagrams left `/readyz` at a
worst latency of 0.4 s with zero failures, per-IP caps held at exactly 32, and
memory settled at ~175 MB. The reviewers found real defects:

- **The shipped container could not write exports or retention archives.** The
  config anchored `reports_dir`/`pcap_dir` to `parents[2]` of `config.py`, which
  in a non-editable install is `/opt/venv/lib/python3.12` (root-owned, container
  runs as uid 10001); a failed archive cancels the delete, so retention never
  pruned. The root is now the checkout if there is a `pyproject.toml`, else the
  working directory.
- **Backups ignored `DATABASE_URL`**: the documented cron entry found no file and
  exited 1 nightly, and a stale `./honeypot_mcp.db` shadowed a PostgreSQL URL.
  `restore.sh` also never restored `reports/` (honeytoken SSH private keys exist
  only there). Fixed and round-trip tested.
- **CI could not fail where it claimed to**: the PostgreSQL fallback detector
  looked for "fallback" but the log says "falling back", a `| tee` hid crashes,
  and the integration step failed on every leg (loopback receiver vs. the new
  SSRF guard). Fixed; a Docker-gated job now exercises real Cowrie.
- **Cowrie egress is closed** by binding its outgoing sockets to loopback
  (`cowrie_allow_egress` opts out), its resolver is pinned to loopback so hostname
  fetches send no DNS query, and adopting an older container logs a warning.
- **Cowrie log ingestion lost windows**: it quit on a paused/restarting container,
  restarted from "two seconds ago" after any crash, treated a Docker API error as
  "container gone", and `resume` never restarted it. It now keeps a cursor across
  respawns, waits through pause/restart, retries Docker errors, and resume/reattach
  respawn ingestion (reattach unpauses instead of calling `start`).
- **Control plane**: IPv6 zone ids (`fe80::1%x?k=1`) passed `validate_ip` and were
  interpolated into the VirusTotal URL path; `honeypot_stop(remove=True)` loaded
  every alert the sensor ever captured; a deployment plan whose first sensor
  failed still created tokens that could never fire; `honeypot_deploy` skipped the
  config validation `honeypot_configure` does; `pcap_extract` could overwrite an
  alert archive (now exclusive, 0600); blocklist exports ignored the never-block
  allowlist; Cloudflare/pfSense pushes raised on network errors without an audit
  row; a WAFv2 push mixed address families and was rejected whole; triage was
  attributed to a caller-supplied name; audit rows used four outcome spellings
  (so `audit_log_search(outcome="ok")` missed most successes) and an over-long
  target silently dropped the row on PostgreSQL; `$`-anchored validators accepted a
  trailing newline; collector mode crashed on a malformed `MCP_AUTH_TOKENS` it
  never uses.
- Malformed HTTP no longer writes an aiohttp traceback per request (a scanner
  could flood the log pipeline).
- Left as documented limitations (`KNOWN_LIMITATIONS.md`): CWD-relative `tls/`,
  tcpdump ring permissions, Grafana vs. a 0700 data directory.
- Two reviewer claims did not reproduce (`limited_handler` socket leak; a `/` in an
  IPv6 zone id) and were not acted on.

## Independent review of the remediation

A reviewer agent with no stake in the code attacked the two commits and
reproduced defects the 1037-test suite did not catch. All are fixed, and
each has a test that fails when its fix is reverted (`test_audit_review.py`).

- **The webhook destination policy was only enforced at subscribe time**, despite
  the changelog, a code comment and the module docstring all saying "re-checked
  at delivery". A stored subscription, a name that later re-resolved to cloud
  metadata, or a tightened setting were all still posted to. It is now enforced
  in `WebhookDelivery._dispatch` (short cache bounds the rebinding window) and
  syslog connects to the validated address.
- **One Redis connection could hold the event loop ~20 s** with 1 MiB of
  one-token commands; commands are now capped per read and per connection.
- **The payload clamp ran before honeytoken matching** and could discard the
  whole `post_data` holding a planted credential. Matching now runs first, and
  the HTTP engine always keeps credential-aliased form fields.
- **Ten engines still hung `stop()` on a connected idle client** (redis, mongodb,
  postgresql, nfs, mssql, mysql, ldap, memcached, vnc, smb); they use
  `shutdown_server` now.
- SMTP and FTP now drop a peer that pipelines commands but never reads (an `EHLO`
  answers ~55x its size); the canary's global ceiling no longer counts requests
  for unknown ids; `honeytoken_rotate` no longer copies the old trigger history;
  IMAP/POP3 no longer raise when a queued line replies after the flood half-close.
- **The strict "UDP reply never larger than the request" rule was too strict:** a
  normal `snmpget` came back `tooBig` and a short SIP REGISTER got a 401 with no
  challenge. Replies are now bounded to 4x (SNMP) / 3x (SIP), still per-source
  rate limited.
- Four audit tests passed with their fix removed (delivery-time check, pfSense
  audit, SIP TCP flood, per-IP cap); they were rewritten to fail on revert.
- Not reproduced and therefore not changed: a claim that `limited_handler` leaks
  sockets when a handler swallows its own exception (asyncio closes the transport
  when the handler task finishes).

## Closing the verification gaps

Follow-up to the audit remediation: the things that were only unit-tested were
run for real, and that turned up more.

- **`python -m honeypot_mcp.server` served no tools.** Running the file with
  `-m` makes it `__main__`, a different module object from
  `honeypot_mcp.server`; the tool modules register on the latter's FastMCP
  instance, so the served instance answered every call "Unknown tool" with no
  error at startup. The `__main__` guard now delegates to the canonical module.
  Found by driving a real streamable-HTTP server with an MCP client; pinned by
  `test_audit_launch.py`.
- **`close_db()` returned early when no async engine existed yet**, which is the
  normal state for a persistent database (migrations use a separate sync
  connection). A write scheduled just before shutdown then built an engine
  nobody disposed. It now yields first, then checks.
- **CI's "full unit suite against PostgreSQL" ran on SQLite.** 73 test files
  hard-assigned an in-memory URL at import. They now read `TEST_DATABASE_URL`
  (opt-in, deliberately not `DATABASE_URL`, so a stray shell variable can never
  point the suite at a real database) and `tests/conftest.py` gives each test an
  empty schema. The whole suite passes on PostgreSQL 16.
- **Cowrie runs with a read-only root filesystem** (compose: persistent
  `cowrie-state` volume for samples and tty replays; SDK deploys: bounded
  tmpfs). Its emulated `wget`/`curl` really fetch public addresses — verified
  by downloading from 1.1.1.1 inside the container — so downloads are capped at
  2 MiB; blocking egress needs a host firewall rule (DOCKER-USER), and disabling
  masquerade on the bridge does not do it under Docker Desktop.
- Verified live: RBAC tool visibility per role, SSRF refusal, redacted
  subscription list, canary hits reaching a real webhook receiver (and re-arming),
  kubectl `/version`, UDP reply sizes and rate limits against a running server,
  and the hostile Mongo/Redis packets with the control plane still responsive.

## Security audit remediation — hangs, ReDoS, fail-open paths

A read-only audit found that one unauthenticated packet could freeze the whole
process and that several guard rails were decorative. All of it is fixed, with a
bounded regression test per finding (`tests/unit/test_audit_*.py`).

- **Event-loop freezers.** MongoDB's BSON walk and Redis's RESP parser made no
  forward progress on a negative length (a 33-byte packet hung all 25 engines);
  catastrophic-backtracking regexes in the Docker/K8s/HTTP/SIP engines,
  `intel/mitre.py` and the JWT matcher ran synchronously on the shared loop. All
  parsers now bound lengths, depth and counts and move strictly forward; every
  regex has bounded gaps and runs over clipped input.
- **Bounded engines.** Per-connection buffers, message counts and write
  backlogs are capped; `conn_limit` adds a central idle timeout, session
  lifetime and process-wide connection ceiling, and `stop()` no longer hangs on a
  live client. UDP replies (SNMP, SIP, DNS) are bounded to a small multiple of the
  request (see the review entry below) and rate limited per source.
- **Ingest pipeline.** Payloads are clamped and the queue is bounded
  (`event_queue_max`, LOW shed first, drops counted); one poison event drops only
  itself; matcher caches refresh under a lock and keep serving stale data on a DB
  error; triggered honeytokens stay armed and keep a capped `triggers` history;
  retention archives in chunks off the loop and a failed archive deletes nothing.
- **Control plane.** `alerts_prune` no longer deletes after a failed archive;
  `MCP_AUTH_TOKENS=","` no longer fails open; `alert_subscribe`/`unsubscribe` are
  admin-only, refuse metadata/link-local/internal destinations (re-checked at
  delivery) and the viewer-tier list redacts URLs; suppression rules reject
  match-everything patterns without `confirm_match_all`; webhook output escapes
  attacker strings, the delivery queue is bounded and one slow subscription no
  longer blocks the rest.
- **Canary.** Canary, Slack and cloud triggers now reach webhook delivery; kubectl
  paths (`/t/<id>/version`) fire the token; triggered tokens re-arm.
- **Infra.** Grafana binds loopback with no anonymous access or default password;
  the Docker socket proxy sits on an internal network; containers are
  resource-capped and capability-dropped; the image installs from the lock;
  vulnerable `pyjwt`/`urllib3` floors raised; the systemd unit is sandboxed.
- `tests/unit/test_security_boundaries.py` now exports into a temp reports dir:
  caller-named exports refuse to overwrite an existing file.

## Housekeeping — remove what was never wired up

A custodial pass over the repository, looking for things that were outdated,
unused, or actively misleading rather than merely imperfect.

- **`config/settings.yaml` was a decoy.** It was loaded at startup and described
  six sections of configuration — database URL, honeypot profiles, canary,
  intel, analysis, logging — and *nothing ever read from it*. The accessor
  (`Settings.get_yaml`) was defined and never called, so anyone editing that
  file to change the SSH persona or the database URL would have seen no effect
  and no error, while CLAUDE.md presented it as a live config source ranked
  below `.env`. Removed along with the accessor and the YAML overlay; the
  documentation now says plainly that environment variables and `.env` are the
  only mechanism.
- **Three dependencies were never imported.** `pyftpdlib` — an entire FTP server
  library — was pulled in despite the FTP engine being a hand-written asyncio
  implementation. `click` and `rich` were speculative CLI dependencies for a
  CLI that does not exist and, given the natural-language interface is the
  point, is not planned. 21 dependencies down to 18.
- **`docs/screenshots/README.md` still described capturing images by hand**
  through Grafana's share menu, and did not mention the console at all — for
  screenshots that have been script-generated since the console shipped.
  Rewritten around `capture_screenshots.sh`.
- **Stale paths after the preset move**: the Dockerfile copied a `config/`
  directory for presets that now ship inside the package, and a tool docstring
  still pointed at the old location.
- **`config/` had no tracked files**, so it did not exist on a fresh clone even
  though the code and DEPLOY.md both point at it. It now carries a README
  explaining what an operator puts there and why nothing is committed.

Verified the container still builds and that the built image resolves both the
bundled presets and the console asset.

## 0.2.0 — installable

The project was only usable by cloning it. This pass makes
`pip install honeypot-mcp` and `docker run ghcr.io/...` real, which is the
difference between a repository people read and software people run.

- **The wheel was incomplete, and silently so.** Installing it into a clean
  environment and running from outside the source tree — the first time that
  had ever been tried — showed the bundled suppression presets missing
  entirely. They lived in `config/suppression_presets/` beside the source, with
  a pip fallback that resolved to a path inside site-packages which never
  exists. The README advertises those presets and DEPLOY.md tells you to load
  them before going live; for anyone installing from a wheel the feature simply
  returned an empty list, with no error. They now ship inside the package and
  load through `importlib.resources`, with an operator-supplied
  `config/suppression_presets/` still taking precedence.
- **Release workflow** (`.github/workflows/release.yml`), tag-driven and
  manual, because a PyPI version can never be reused and a container tag is
  public on landing. It builds sdist + wheel, runs `twine check --strict`,
  installs the wheel into a clean environment *outside the source tree* and
  asserts the presets and console asset resolve, publishes to PyPI via trusted
  publishing (no stored token), and pushes a multi-arch amd64 + arm64 image to
  GHCR — arm64 because the cheap VPSes this runs on increasingly are.
- **Version drift is now impossible to ship.** The version lives in
  `pyproject.toml` and `__init__.py`; a new test caught them already
  disagreeing, and the release job refuses a git tag that doesn't match.
- Full PyPI metadata: keywords, classifiers, and project URLs for the
  changelog, issues, security policy and known limitations.

## Security review — two crossable boundaries, closed

A security review of the codebase, framed around a threat model that is
specific to this design and worth stating plainly: **the control plane is
driven by a language model that reads attacker-authored data.** Captured
usernames, request paths, shell commands and User-Agent strings are
attacker-chosen strings, and they reach the same context that decides which
tools to call with which arguments. An attacker who never authenticates to
anything can therefore put text in front of the decision-making component just
by attacking a honeypot — which is the entire point of the product. "The caller
is trusted" is not sufficient reasoning here.

- **HIGH — arbitrary file write with attacker-influenced content.** The
  `output_path` parameter added to the four export tools in an earlier pass was
  unconstrained. Confirmed by writing an alert payload into a file outside the
  project, both by absolute path and by `../` traversal. Because exports embed
  captured payloads, this was a primitive for writing attacker-chosen content
  to any path the process could reach. Writes are now resolved through
  `_format.resolve_artifact_path()` and confined to `reports_dir`; ordinary
  filenames and subdirectories still work.
- **MEDIUM — path traversal via honeypot name.** `honeypot_deploy` performed no
  validation on `name`, and the name becomes a filesystem path
  (`tls/<name>/server.key`) and a Docker container name. A name of `../../etc`
  attempted to create a directory outside the tree. Names are now restricted to
  a Docker-compatible character set at the tool layer, and `tls._cert_dir()`
  re-checks at the point the name becomes a path, since reconciliation and
  cloning also reach it.

28 regression tests cover both, plus the boundaries that were already sound.

Verified and deliberately left alone, having found no defect: HMAC comparisons
use `compare_digest`; there is no `eval`/`exec`/`pickle`/`yaml.load` anywhere;
SQL goes through SQLAlchemy parameter binding; the console escapes every
interpolation of attacker-controlled data before it reaches the DOM (tested with
`"><img src=x onerror=...>` in the source IP, username, path and command
fields); and `/cloud-event` refuses every request until its HMAC secret is
configured.

SECURITY.md now documents the model-in-the-loop threat model explicitly, so the
reasoning survives for the next person adding a tool.

## Ship-readiness pass — PostgreSQL was broken the whole time

- **The documented production database never worked.** The docs offer swapping
  `DATABASE_URL` to PostgreSQL as the production path. Following that
  instruction verbatim failed immediately — `asyncpg` was not a dependency at
  all. Adding the driver exposed the real bug underneath: Alembic's
  `alembic_version.version_num` column is `VARCHAR(32)` and the revision id
  `0007_drop_attacker_profile_shodan_data` is 38 characters. SQLite does not
  enforce VARCHAR limits, so it passed locally forever; PostgreSQL does, so the
  migration chain died at 0007 with `StringDataRightTruncation` — and
  `init_db`'s `create_all` fallback caught the exception, produced a
  working-*looking* schema with no version stamp, and logged a warning nobody
  read. The consequence: **every startup on PostgreSQL re-ran all seven
  migrations**, surviving only because those migrations happen to be
  idempotent, and one non-idempotent revision away from damaging a real
  database. Renamed the revision (with an in-place stamp rewrite so any
  database already carrying the old id keeps working), added a `postgres`
  install extra, and verified the whole application — JSON-payload search, enum
  filters, bulk triage updates, audit log, profiler, console — against a real
  PostgreSQL 16.
- **CI now proves the claim instead of asserting it.** A new blocking job runs
  migrations against a real PostgreSQL service, fails if `init_db` falls back
  to `create_all`, fails if a second startup re-runs any migration, and then
  runs the full unit suite against it. Two unit tests guard the class of bug
  directly: every revision id must fit `VARCHAR(32)`, and the migration chain
  must be linear with exactly one root and one head.
- **`tests/integration/` was an empty directory.** Every one of the 400+ tests
  was a unit test, so nothing exercised the wiring *between* stages — an engine
  that captured perfectly but never reached the buffer would have passed the
  entire suite. Five end-to-end tests now drive real engines over real sockets:
  attack → database, planted credential → CRITICAL escalation → token marked
  triggered, suppression dropping events before they persist, webhook delivery
  to a live HTTP receiver, and HTTP exploit classification. CI runs them.
  (Writing them surfaced a test-isolation trap worth knowing: the suppression
  and credential caches are process-global with a 30s TTL, so a rule loaded by
  one test stays in force for the next.)
- **SECURITY.md and CONTRIBUTING.md.** A security tool with no vulnerability
  disclosure policy is conspicuous. SECURITY.md also draws the line between
  intentional behaviour (accepting hostile input, generating fake credentials)
  and an actual vulnerability (escaping the deception boundary, forging events
  into a SIEM, leaking secrets). CONTRIBUTING.md records the non-obvious rules
  that were each learned the hard way.

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
