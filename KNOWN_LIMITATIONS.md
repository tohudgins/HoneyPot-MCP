# Known Limitations

What will not work, and why. Fixed items live in [CHANGELOG.md](CHANGELOG.md), not here; the
results of the live run are in [docs/RESULTS.md](docs/RESULTS.md) and the test guide in
[docs/FIELD_TEST.md](docs/FIELD_TEST.md).

## Scope

The project collects the **automated** population that reaches a public IP (scanners, credential
sprayers, exploit kits, droppers) and turns it into telemetry: alerts, captured credentials and
hashes, payloads, ATT&CK mappings, campaigns. The in-process engines are protocol facades, not real
servers. They are checked against real clients and `nmap -sV --version-intensity 9`
(`tests/unit/test_protocol_fidelity.py`, `tests/unit/test_attacker_tool_fidelity.py`), and they hold a
scanner or a tool; a skilled human probing by hand for an extended session will find the edge of one.
Each entry below is a gap that remains after the fixable ones were fixed, or a decision with a reason.

For higher fidelity or other protocols see [T-Pot](https://github.com/telekom-security/tpotce),
[OpenCanary](https://github.com/thinkst/opencanary), Conpot (ICS) or Thinkst Canary (commercial).

## 1. Not served, or partly served, by choice

| Limitation | Why | Impact on research | Status |
|---|---|---|---|
| rsync: the daemon lists a decoy tree to protocol 30+ clients (rsync 3.x). No transfer, no upload, no protocol 29 or older (macOS `openrsync`), some options refused. | Emulating a transfer needs a real file layer; the listing is the discovery phase (`engines/rsync_wire.py`). | `rsync_module_enumeration` (HIGH) and `rsync_anonymous_access` (CRITICAL) fire; `rsync -av` gets past the list, then fails in 0.2 s. What the attacker would have pulled is not captured. | Accepted |
| NFS: TCP only. No UDP (macOS `showmount`), no post-mount operations (`nfs-ls`, `nfs-statfs` fail). | The detection is the export list, which one MOUNT EXPORT call discloses. | `nfs_export_enumeration` (HIGH) fires for `showmount -e`, `rpcinfo -p` and nmap's `nfs-showmount`; mount-and-browse behaviour is not seen. | Accepted |
| Grafana time-series, tactic-timeline and geo panels read the raw `alerts` table. | They need sub-hour buckets or payload fields (geo country) that `alert_rollups` does not hold. | 5-14 s per panel at 14.9M alerts, growing with the run. The six aggregate panels read rollups (0.00-0.03 s) and equal `alerts_stats`; MCP tools and `sql_query` do not depend on table size. | Open, by cost |
| Redis has no bait. | Attackers write to its per-connection store and the SAVE-redirection detection hashes it; seeded keys would pollute that evidence. | A credential found on Redis is never tracked. | By design |
| SMB has no bait and no file server: the NTLM AUTHENTICATE is captured, then refused (`STATUS_LOGON_FAILURE`). | A share needs a real SMB file layer. | NetNTLMv2 hashcat line (`-m 5600`) and exploit probes are captured; post-login behaviour is not. | Accepted |

Smaller edges, one line each (all still record the attack):

- **Kubernetes API:** only pod create among writes; resources without data (deployments, services) return empty lists.
- **IMAP:** no SORT/THREAD/CONDSTORE/MOVE/UIDPLUS; `STARTTLS` is advertised and answered `NO` (`imap_starttls_declined`, LOW) so the password stays capturable. Mailbox changes (CREATE/DELETE/RENAME, APPEND, COPY) last for the connection only; the shared maildrop is never changed.
- **RDP:** a visitor who is let in (planted credential or the derived weak pair) gets a short session (2 minutes, 10 once they type commands) on a Windows-style desktop with a fake `cmd`/PowerShell: a table of answers over a small virtual filesystem, not Windows. It executes nothing and has no route out. Explorer, Task Manager, drives, printers and audio are not modelled; Standard RDP security (no TLS) is refused. Clipboard text and commands are recorded (`rdp_clipboard`, `rdp_command`, CRITICAL on a download attempt).
- **SMTP:** nothing is ever sent onward, so an attacker testing relay sees `250 queued` and nothing arrives (see "Operational guidance" for why the engine is off on a public VPS).

## 2. Accepted by design

| Limitation | Why | Impact on research | Status |
|---|---|---|---|
| Cowrie's canned `ps`, `df`, `mount`, `free` are not per persona; command timing is uniform. | Cowrie's own behaviour; the project patches the persona files and `[shell]` settings, not the emulator. | A human who compares these against the persona's kernel/distro will notice. Automated tools do not. | Accepted |
| Cowrie's SSH key-exchange offer is a strict subset of the persona's OpenSSH (no `chacha20-poly1305`, AES-GCM, `-etm` MACs, `sntrup761x25519`, group-exchange/group16/group18). | Twisted does not implement them (`engines/cowrie_sitecustomize.py` narrows the rest). | A HASSH server fingerprint differs from real OpenSSH; `ssh-audit` guesses a version range, not the banner's version. | Partly patched |
| Memcached never amplifies (TCP only, no UDP/11211). SNMP, SIP and DNS replies are capped at a small multiple of the request (4x / 3x / 2x) and rate limited per source. | Reflection vectors with spoofable sources; a faithful reply would enlist the sensor in someone's DDoS. The cap is not 1x because at 1x `snmpget` returns `tooBig` and a short REGISTER gets no digest challenge, both of which expose the decoy. | The reconnaissance is recorded in full; large replies are never produced. | By design |
| HTTP has a narrow authenticated area: a planted credential or the one weak pair derived from the honeypot name logs in to a decoy admin console (`http_authenticated_request`). | A bot that moves on only after success would otherwise never show what it does with a foothold. `accepted_logins: []` turns it off. | It is a login surface, decoy-only and accepting nothing beyond those credentials. | By design |
| RDP and POP3/IMAP accept a planted credential or the derived weak pair; `accepted_logins` replaces it, `[]` lets nobody in (RDP `sessions: false` disables sessions). | Same reasoning: capture post-login behaviour. | The derived pair differs per honeypot, so "admin/admin everywhere" is not a fingerprint. | By design |
| Planted credentials are served as bait only by the HTTP decoys (`/.env`, `/config.json`, `/wp-config.php`: tracked MySQL credential and tracked canary URL), the FTP `passwords.txt` (`bait_served`) and the Cowrie persona home (`/root` and the persona user: `~/.bash_history`, `~/.my.cnf`). | Tokens fire only when a tracked value is used; what a scanner can find decides what it can trip. | The cloud keys in those HTTP files and in `/.aws/credentials` are random lookalikes that exist in no cloud account; `/.kube/config` has a random token; Elasticsearch and mail decoys serve static or random content. Which bait a scanner reads and replays is observed, not assumed: check `honeytoken_list` after a run. The HTTP, FTP and Cowrie baits share one MySQL credential, so a trip identifies the token, not which file the scanner read. In the 116-hour run that credential was replayed against the MySQL sensor from 3 outside sources (8 trip alerts; [docs/RESULTS.md](docs/RESULTS.md), section 3). | By design |
| DNS answers as a recursive resolver (UDP and TCP). | Its job is catching resolver abuse; file tokens fire over HTTP against the canary server (a `dns_canary` name is published only for operators running a wildcard `*.canary.<domain>`). | AXFR/IXFR are recorded and refused. | By design |

## 3. Outside the project's control

| Limitation | Why | Impact on research | Status |
|---|---|---|---|
| AWS / Azure / GCP key tokens need an audit-log forwarder and a real decoy identity in your cloud account. | Only the cloud sees API calls made with its keys. `examples/cloud-forwarders/{aws,azure,gcp}/` ships the forwarders (HMAC-signed `/cloud-event`) and decoy-identity scripts; a generated key does not exist in the cloud and is bait only for scanners that grep key patterns. | The Terraform validates but was never applied to a live account. Adopt a real key through `honeytoken_generate_aws` / `honeytoken_create`. [Canarytokens](https://canarytokens.org) is the zero-setup alternative. | Needs operator action |
| PDF tokens fire on open, but Acrobat asks "Trust this URL?" first. | `/OpenAction` URI plus a full-page link annotation (`tokens/file_token.py`); Preview and browser viewers ignore `/OpenAction`, so they fire on the first click. | High-confidence, not guaranteed; a canary URL token is more reliable. | Viewer behaviour |
| DOCX tokens: Word's Protected View can block the external image fetch until "Enable Editing". | The fetch hits `CANARY_PUBLIC_URL/t/<uid>.png`. | Both file types embed `CANARY_PUBLIC_URL` verbatim; the default `http://localhost:8888` fires only on the honeypot host. Setting it to a reachable address is the usual fix for a silent token. | Viewer behaviour |
| The credential tripwire fires only when a value is tried on one of our own honeypots. | Production logins are invisible to this project. | No signal from a real system; not a substitute for an identity-provider audit-log canary. Covered services: SSH, HTTP form, FTP, SMTP AUTH, Redis AUTH, PostgreSQL, MSSQL, plus MySQL and VNC by recomputing the digest from the honeypot's own salt/challenge. | Outside control |
| pfSense, Cloudflare and AWS WAF blocklist push tools were rewritten to the vendors' published contracts and driven through strict stubs; they never ran against real accounts. | No credentials here. | First live use is the first real test. | Unverified live |
| GreyNoise has never been run live. (abuse.ch, OTX and Shodan InternetDB were, against real attacker IPs and a captured malware hash.) | Its free API key needs a business or custom-domain email (free-mail accounts get none), and the free tier is 50 lookups a week. `scripts/intel_smoke.py` does a live call once a key exists. | Off unless configured; failures never block VirusTotal/AbuseIPDB lines (3 s fan-out deadline). | Unverified live |
| Host hardening reduces risk, it does not remove it (`docs/HARDENING.md`, "Residual risks"). | Cowrie shares the host kernel; in-process engines share a process with the control plane; HTTPS egress is open for webhooks and threat intel; container-egress rules were verified by hand on a real `dockerd`, not by an automated test. | A kernel or runtime exploit escapes a container; an engine code-execution bug reaches the control plane. | Residual risk |

## 4. Out of scope

- **High-volume production deployment:** needs perimeter hardening, host isolation and TLS termination in front of the canary callback (nginx, Caddy or a tunnel). Log shipping is in scope and shipped (Splunk HEC, Elastic ECS, Loki, Datadog, CEF, RFC 5424 syslog via `alert_subscribe(format=...)`), as are the cloud forwarders and the Cloudflare/pfSense/AWS WAF push tools (`tools/blocklist_push.py`).
- **APT and targeted-attacker research:** the engines are too thin.
- **Real TLS termination, ICS/SCADA and IoT protocols:** see Conpot or T-Pot.

## Operational guidance

- **What to leave off a cloud VPS.** SMTP and DNS look like an open relay and open resolver to automated checks, and several cloud acceptable-use policies prohibit both. They are verified locally with real clients (`smtplib`, `dig`, `nmap`) but are off in the recommended deployment. The remaining 23 engine types run there.
- **How detection survives partial emulation.** The alert fires on the first discriminating step (rsync module request, NFS export listing, SMB negotiate, NTLM AUTHENTICATE, `COPY ... FROM PROGRAM`), before the point where the emulation stops.
- **FTP needs a passive port range** on the internet: set `FTP_PASV_PORT_MIN`/`MAX` and pass the firewall renderer `--ftp-pasv-ports` (`docs/DEPLOY.md`). **NFS** sits on an internal port with 111 and 2049 redirected to it (firewall `2049>12049,111>12049`), because clients ask the portmapper first.
- **Unattended agents:** use a `viewer` token. The prompt-injection field test (`scripts/field_test_injection.py`) held for one model with one sample per scenario: evidence, not proof.
- **`scripts/fetch_backup.sh`** reports on SQLite backups only, and only from containers still running: Cowrie downloads and TTY recordings live inside the container (on the pinned image, checked with the real engine, in an anonymous volume under `/cowrie/cowrie-git/var/lib/cowrie`; the tmpfs mounted at `/cowrie/var/lib/cowrie` stays empty), so they survive a restart but are removed with the container, and you must fetch before `teardown` or a rebuild. A sensor that is up but unreachable looks the same as a quiet one, hence every-sensor-silent is called out separately.
- **One server owns the sensors.** A second process on the same database starts read-only (deploy/stop/pause/clone/configure/`pcap_control` refuse) and takes over when the owner exits (`OWNER_CHECK_SECONDS`, default 10). SQLite ownership is an `flock`; PostgreSQL uses a session advisory lock. If the PostgreSQL lock is lost the owner re-takes it or raises CRITICAL `sensor_ownership_lost` (it does not stop its own sensors, so the new owner fails to bind until it is stopped). Read-only mode does not probe in-process sensors, since a probe from a second process looks like an attacker.
- **Disk watch** covers the database directory, `reports_dir` and the pcap ring, alerts below `MIN_FREE_DISK_MB` (500) and does not prevent a full disk. A remote PostgreSQL volume is not visible; alert on `honeypot_database_size_bytes`.
- **Event volume.** At most 600 events per source and event type per minute are stored (`flood_guard_per_minute`); the rest are counted in one `flood_summary` event per window.
- **Suricata, Zeek and YARA need extra pieces.** `pcap_detect` needs Docker and pulls an engine image on first use; the Emerging Threats ruleset comes from `detection_rules_update`, the only tool that gives a container network, and detection runs offline against that cache. Suricata 7 cannot read the Linux cooked (SLL2) captures `tcpdump -i any` writes, so the image is pinned to 8. On host-captured packets Suricata reports many "invalid checksum" alerts (NIC checksum offload); the tool sorts them last and labels them, so on the first SIP capture 7,276 of 7,286 alerts were artifacts and the real signal was ten generic SIP flood alerts. `sample_scan` needs the `forensics` extra (yara-python, or yara-x on Python 3.14); without it the tool says `available: false`. `sample_collect` reads Cowrie's capture directories out of a running container through Docker's archive API, which works for the image's state volume (checked on the pinned image with the engine's flags) but cannot see a tmpfs; the files go with the container when it is rebuilt, so collect before redeploying.

## Updating this document

When a change closes a gap, delete its row; when a new limitation appears, add it with one measured
claim and one reason. Do not park unfinished work here.
