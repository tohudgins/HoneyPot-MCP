# Field test: prove your deployment works

Unit tests prove the code. A field test proves **your deployment**: that traffic from the public
internet reaches each sensor through the firewall and port mapping, that the engine understands it,
and that the event lands in the database and is reachable through the control plane.

Passive traffic cannot prove this. A public host is mostly scanned for SSH, Telnet and a few web
paths: in the first 3.5 hours of the run this was written from, 98% of events came from the two
Cowrie sensors, and the Elasticsearch and Docker sensors had seen nothing at all. "No events" on a
sensor is then ambiguous: nobody has tried, or it is broken. So run both scripts once, from a machine
that is not the VPS, before trusting a quiet sensor.

| Script | Question it answers |
|---|---|
| `scripts/field_test.py` | Does each engine record what a real client does to it, from outside, through the firewall? |
| `scripts/field_test_tools.py` | Does every MCP tool work at the role that owns it, and are the other roles refused? |

Both run with `uv run` (their dependencies are declared in the script header), so nothing is added
to the project's own dependencies.

## 1. Engines: `field_test.py`

```bash
# from your laptop, against the VPS's public address
uv run scripts/field_test.py attack --host 203.0.113.7 --out field-run.json

# take a backup (this also exercises the backup path), then check what was recorded
scripts/fetch_backup.sh --host 203.0.113.7 --port 2200 --key ~/.ssh/honeypot_deploy --dest ~/hp-backups
uv run scripts/field_test.py verify --manifest field-run.json \
    --db ~/hp-backups/<latest>/honeypot_mcp.db --report field-report.md
```

`attack` sends one probe group per engine through its **public** port, using a real client library
(paramiko, redis-py, pymongo, pymysql, asyncpg, impacket, ldap3, httpx, `kubectl`, `rsync`) or a raw
socket where the protocol is a few lines (SNMP, SIP, NFS, RDP, VNC, memcached, Telnet). `verify`
then queries the downloaded database for rows from your address after the run began and checks that
every expected event type for each probe is present. Probes use inert payloads; Cowrie's egress is
closed and no engine executes anything. `--only ssh,redis` runs a subset; probes for engines you did
not deploy (SMTP and DNS are off in the recommended deployment) are not part of the set.

A `CLIENT ERROR` means the probe itself failed, not the engine: read the note under it. A `FAIL`
means the client ran but the platform did not record the expected event, which is a finding.

## 2. Tools: `field_test_tools.py`

```bash
# with the tunnel to the control plane open (docs/DEPLOY.md)
uv run scripts/field_test_tools.py --url http://127.0.0.1:18443/mcp \
    --tokens ~/.ssh/honeypot_mcp_tokens --attacker-host 203.0.113.7 --out tools-report.md
```

It calls every registered tool at its proper role and checks the answer: the read-only tools against
the live database, and the write tools through lifecycles that clean up after themselves (a
temporary sensor is deployed, self-tested, configured, cloned, paused, resumed and removed;
honeytokens are created, exported, rotated and revoked; a suppression rule is added and removed).
Also checked: no token, a wrong token, a viewer calling an operator tool and an operator calling an
admin tool are all refused; a live-provisioned API key works at once and is refused the moment it is
revoked; a private webhook destination is refused; capture being off is a clear refusal, not a crash.

**The honeytoken round trip** is the one check that crosses every layer: it plants an SSH credential,
logs in to the honeypot with a real SSH client using it, and requires the platform to raise a
CRITICAL alert and mark the token `triggered`.

`report_ip_abuse` (sends a report about an address to an outside service) and
`suppression_load_preset` (could briefly drop real events) are never called; they are listed as
skipped with the reason. The sweep **fails if a registered tool is neither called nor skipped**, so a
newly added tool cannot go untested unnoticed.

## 3. Management and analysis on real traffic: `field_test_ops.py`

Part two shows every tool answers. This part asks whether the answers are *right* on what the
internet actually sent, and whether actions really change the live system. It picks its subjects
from the data (the busiest source, the CRITICAL-heaviest source), so run it once the deployment has
been collecting for a few hours.

```bash
uv run scripts/field_test_ops.py --url http://127.0.0.1:18443/mcp --tokens ~/.ssh/honeypot_mcp_tokens \
    --host 203.0.113.7 --my-ip <your public ip> --out ops-report.md   # add --report-abuse to file one AbuseIPDB report
```

Triage (acknowledge a real attacker's alerts and see the queue, the records and the audit log
agree), analysis (profile, journey, ATT&CK mapping, campaigns, clusters, coverage and a report for
real attackers; the profile must carry reputation and geography), remediation (blocklist and STIX
exports; a rate-limit rule on a real flooder must cut the live ingest rate by 80%, skipped honestly
when no flood is active), and operations (pause a real sensor and watch its public port close,
resume it, read a real sensor's log, pull a real attacker's packets from the capture ring).

## 4. Are the answers right? `field_test_oracle.py`

Parts two and three show the tools answer and act. This part checks the *numbers*. It takes a
frozen backup (so live traffic cannot move anything), runs the read tools on a copy of it, and
compares each answer with an independent computation written as plain SQL over the `alerts` table.
The tools read pre-aggregated rollups and partial indexes; the oracle never does, so agreement means
the optimised path equals the definition.

```bash
uv run python scripts/field_test_oracle.py --backup ~/hp-backups/<latest>/honeypot_mcp.db --out oracle.md
```

It covers `alerts_stats` over five window shapes (all time, mid-hour start, on the hour, the last
40 minutes of data, after all data: total, unique sources, severity split, true top sources and
event types with their true counts), per-sensor hit counts, `soc_brief`'s volume and untriaged
counts and the order of its queue, `alerts_recent` filters, `alerts_search`, `threat_timeline`,
`analyze_attacker` and the journey for heavy and light real sources (count, first and last seen to
the microsecond, breakdowns), the blocklist's membership, and cross-tool invariants. Campaign
and cluster analysis are listed as not covered, with the reason, rather than skipped silently.

First run, on 4,896,441 real alerts: 67 checks, 0 failed, in 28 seconds. To prove the oracle can
fail, one rollup count was changed by one in a copy: the total, severity split, top sources and
per-sensor hits all failed (`4896442 != 4896441`). The original is never opened for writing.

## Seeing the data yourself

Everything above can also be read on your own machine from a backup, with no SSH:
`scripts/fetch_backup.sh` the data, then point the project's Grafana dashboards (overview, threat
map, MITRE ATT&CK coverage) at a copy of the database. A downloaded snapshot is in WAL mode, which
Grafana's read-only mount cannot open, so make a rollback-mode copy first:

```bash
mkdir -p ~/hp-grafana && cp ~/hp-backups/<latest>/honeypot_mcp.db ~/hp-grafana/
sqlite3 ~/hp-grafana/honeypot_mcp.db "PRAGMA journal_mode=DELETE;"
docker run -d --name hp-grafana -p 127.0.0.1:3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=<choose one> -e GF_INSTALL_PLUGINS=frser-sqlite-datasource \
  -e GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS=frser-sqlite-datasource \
  -v "$PWD/docker/grafana/provisioning:/etc/grafana/provisioning:ro" \
  -v "$PWD/docker/grafana/dashboards:/etc/grafana/dashboards:ro" \
  -v ~/hp-grafana:/mcp-data:ro grafana/grafana:11.3.0
```

Open http://localhost:3000 and set the time range to the days the run covered: the dashboards
default to the last 24 hours, so a backup older than that shows empty panels until you widen it.
Bind it to localhost only: this Grafana can query the whole database, including captured
credentials and honeytoken values. Every panel reads the database alone (the "Active honeypots" tile
used to need Prometheus and showed "No data" on a laptop; a test now pins that), and the map uses a
keyless label-free Esri base layer, because Grafana's default CARTO basemap now stamps "API KEY
REQUIRED" across every tile while still answering HTTP 200. All 12 data panels returned rows.
The same restored database also runs the MCP server locally over stdio for the analysis tools.

## What the first live run found

Run against a DigitalOcean droplet (Ubuntu 22.04, 22 engines) after the unit suite passed. All of
these were invisible to the unit tests:

| Found by | Finding | Fix |
|---|---|---|
| Backup report on the droplet | The server's database is in WAL mode; a plain read-only open of a downloaded snapshot needs side files it does not have, so every report query failed | open the snapshot `immutable=1` |
| Backup report | The Docker bridge address (the source Cowrie sees for self-tests and probes) was counted as an attacker | private ranges are reported separately |
| Server start | The documented `root:honeypot 0640` `.env` triggered a "world readable" warning the pre-flight accepted | one shared rule (`config.env_group`) |
| Backup `--samples` | The script looked in `/cowrie/var/lib/cowrie`; the image keeps its state under `/cowrie/cowrie-git`. Every run said "0 files" with a clean verdict while the containers held 32 downloads and 18 TTY recordings | both roots searched; "directory not found" is a failure, never "0 files" |
| `field_test.py` (HTTP) | After 5 requests in a session, `http_active_recon` overwrote `http_credential_submit`, so a login attempt by a scanner that had crawled first was filed as recon | only a plain probe is relabelled |
| `field_test.py` (probes) | SIP: a bare `REGISTER` is classified as extension enumeration (by design); `sip_register_attempt` needs a digest | expectation fixed, both sent |
| `field_test_ops.py` (operations) | `honeypot_pause` returned `paused` while the port kept answering and recording: `pause()` is a no-op for every engine that is not a Docker container | pausing an in-process sensor closes its listener, resume starts a fresh one on the same port |
| `field_test_ops.py` (triage) | Triaging a real flooder twice: a filter re-selected the 500 newest matches (already triaged) and overwrote the first analyst's disposition, note and name, and never reached older untriaged alerts | a filter selects untriaged alerts only; naming ids re-triages deliberately |

The first two are why the test rig for the backup script now runs the real embedded script against a
fake container filesystem instead of a stub that ignores it.

## Live checks that no script can replace

Run these once from outside against your own VPS (all were run against the droplet above):

- **Scan the whole port range and compare.** `nmap` without root does a slow connect scan (about
  45 minutes for 65,535 ports); a short asyncio connect scanner with 1,500 concurrent connections
  and a 1.5 s timeout covers it in about a minute. Expect exactly the public honeypot ports plus
  the admin SSH port. The first run found **seven extra ports** (1110, 1143, 1389, 2121, 4445, 8080,
  8873): the post-redirect ports were reachable directly, so a scan showed POP3 on both 110 and
  1110. The firewall now accepts redirect targets only for redirected packets (`ct status dnat`),
  proven against real nftables by `tests/integration/test_firewall_rules.py`. Re-render the
  firewall and load it (`harden-host.sh finalize`) on a host built before this change.
- **Fingerprint with a real scanner.** `nmap -sV --version-intensity 9` over the honeypot ports
  identified every TCP engine as the product it imitates (ProFTPD, Dovecot, Asterisk, MySQL 8.0.36,
  SQL Server 2019, Docker 24.0.7, Redis 7.0.5, MongoDB 5.0.14, ...). It also reports mixed
  hostnames and a Windows plus Linux OS mix for one address; that is a coherence tell if the
  estate mixes both families (see `deception_plan`'s coherence check).
- **Threat-intel enrichment.** Put `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` and the two GeoLite2
  paths in the VPS `.env`, restart, then `enrich_ip` a real attacker: all three sources answered on
  the first try.
- **Webhook delivery and signatures.** Temporarily set `WEBHOOK_ALLOW_PRIVATE_DESTINATIONS=true`,
  run a tiny receiver on the VPS, subscribe every format at `critical`, trigger criticals with
  `field_test.py`, and compare: all eight formats delivered every event, and the JSON body's
  `X-HoneyPot-Signature` matched an independent HMAC. Then **remove the setting and restart**; the
  policy refusing a loopback destination again is the check that you did.
- **Canary callbacks.** The callback server is loopback-only by design, so test it from the VPS:
  `curl http://127.0.0.1:18888/t/<token-id>` flips the token to `triggered` with a CRITICAL alert
  for both the plain and `.png` forms. An unknown id still answers 200, so a scanner cannot tell
  real tokens from fake ones.
- **Packet capture.** Needs the unit drop-in in `deploy/honeypot-mcp.service`; `pcap_extract` by
  source address returned 1,157 packets of the field test, valid per `tcpdump -r`.
- **Natural language.** Registered in Claude Code over the SSH tunnel, a viewer-scoped prompt
  produced a correct analyst brief, and an operator-scoped prompt planned, deployed, self-tested
  and tore down a two-sensor deception plus an AWS honeytoken, touching nothing it had not created.

## Behaviours of real services that are not recording defects

What the probes revealed about the services themselves:

- **paramiko reports "Channel closed" for an SSH exec request** (`ssh host cmd`) against Cowrie,
  because Cowrie closes the channel before answering the request. The OpenSSH client gets the output
  and exit status normally, and the command is recorded either way. An interactive shell works in both.
- **A real `rsync` client timed out** (10 s) after selecting a module: the honeypot recorded the
  anonymous access and the file request (both CRITICAL) but the client received no file list. The
  recording is complete; the session does not look like a real rsync daemon after that point.
- Cowrie's emulated `head` rejects `head -2` (it accepts `-n 2`); a real `head` accepts both.
