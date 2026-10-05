# Known Limitations

A frank list of what this project does and doesn't do. Anyone with experience
in deception tech knows where the gaps are; pretending they aren't there is the
fastest way to lose credibility. This document exists so you can decide whether
HoneyPot MCP fits your use case before you spend time on it.

The short version: **this catches the automated population — which is the
overwhelming majority of what reaches a public IP — and it is built to be
indistinguishable to a scanner.** `nmap -sV` identifies most engines as the
software they impersonate, by name and version. What it does not attempt is
fooling a skilled human who probes by hand for an extended session; the
in-process engines are protocol facades, not real servers, and a determined
operator will eventually find the edge of one.

Every entry below is one of three things, and they are kept separate on
purpose: a boundary set by software outside this codebase, a deliberate design
decision, or something explicitly out of scope. Anything that was simply
unfinished has been fixed rather than documented — a limitations file is not a
place to park work.

For higher-fidelity needs, look at [T-Pot](https://github.com/telekom-security/tpotce)
(full distribution with 30+ honeypots), [OpenCanary](https://github.com/thinkst/opencanary),
or [Thinkst Canary](https://canary.tools/) (commercial, with the external
infrastructure to make tokens actually fire).

---

## What works well

**SSH (Cowrie-wrapped, Docker).** This is the strongest piece. Cowrie is what
the SANS Internet Storm Center uses for parts of their public attack feed. The
wrapper handles Docker lifecycle, incremental JSON log ingestion via the `since`
parameter (no event loss on burst load), hash-based dedup, and a persona system
that randomises the hostname / kernel version / OpenSSH banner per deploy.
Default Cowrie installs are trivial to identify on Shodan because every one
ships with `hostname=ubuntu-server` and the same OpenSSH banner; the persona
system fixes that. On a public IP this catches Mirai-family scanners,
libssh-based credential stuffers, Hydra / Patator brute force, and
default-credential sweeps within minutes.

**HTTP / HTTPS (custom asyncio).** The persona system is competent against
automated scanners (ZGrab, Nuclei, dirb). Coherent header bundles — Nginx
personas correctly omit `X-Powered-By: PHP`, IIS adds `X-AspNet-Version`,
the Apache 404 page embeds the same `Server` header in its `<address>` line
that real Apache uses — plus per-response timing jitter to defeat sub-
millisecond fingerprinting. TLS is supported via a per-honeypot self-signed
cert (`config["tls"] = True`), unlocking HTTPS scanner traffic and giving
JA3/JA4-aware scanners something to fingerprint. Realistic `/robots.txt`,
`/favicon.ico`, `/sitemap.xml`, `/.well-known/security.txt` are served, and
session cookies persist across a connection (a scanner that hits 5+ paths
gets escalated to `http_active_recon`).

**Database / service engines (custom asyncio).** PostgreSQL and MSSQL
decline/deny encryption so the client falls back to cleartext, capturing
full login credentials — both are cross-referenced against planted
credential honeytokens. MySQL accepts the login and captures post-auth SQL
(recon, `INTO OUTFILE` / UDF RCE attempts); PostgreSQL does the same for
`COPY … FROM PROGRAM` and friends. Redis captures the complete unauth-RCE
dropper chain including the attacker's SSH key and target path. MongoDB
answers `isMaster`/`buildInfo` believably and flags `dropDatabase` and
ransom notes. Elasticsearch classifies recon and data-exfil query patterns.
SMB classifies EternalBlue / DoublePulsar exploit probes and captures NTLM
session-setup strings. VNC captures the RFB auth challenge/response. All of
these are detection-focused protocol facades, not real servers — they hold
automated tools and scanners (the overwhelming majority of traffic), not a
skilled human probing manually.

**Canary URLs.** The aiohttp callback server on port 8888 is real. Hitting
the URL triggers a CRITICAL alert with full request metadata. Set
`CANARY_PUBLIC_URL` to a publicly reachable address (ngrok, Cloudflare Tunnel,
or a real domain) and these fire from the internet.

**DOCX file tokens.** `tokens/file_token.py` injects an External-mode image
relationship into `word/_rels/document.xml.rels` and references it from a
`<w:drawing>` in the document body. When Word opens the file it fetches the
external image — that fetch hits `CANARY_PUBLIC_URL/t/<uid>.png` on the
canary server and triggers an alert. Word's Protected View can block the
first fetch (user must click "Enable Editing"); enterprise deployments with
Protected View disabled or auto-trust on certain locations skip the prompt
entirely.

Both file types embed `CANARY_PUBLIC_URL` verbatim, so that setting must be
an address the target machine can actually reach — the default
`http://localhost:8888` only ever fires if the document is opened on the
honeypot host itself. This is the single most common reason a planted file
token stays silent.

**HTTP recon endpoint decoys.** Probes for `/.env`, `/config.json`,
`/wp-config.php`, `/.aws/credentials`, `/.kube/config` get plausible bait
responses seeded with fresh throwaway tokens (random AWS-shaped keys, JWTs,
DB passwords). These tokens are decorative — not persisted, not matched —
purely to look like real exfil targets. A scanner that picks up "an AWS
key" from `/.env` and starts trying it elsewhere is now visibly an
attacker, not a misconfigured tool.

**HTTP login response variation.** `POST /login` rotates across six
plausible auth-failed strings and adds 180–650ms of random per-request
delay on top of the persona's existing jitter. A scanner that submits the
same creds twice and diffs the responses can no longer confirm "no real
auth backend present" from response bytes or response time.

**DNS honeypot.** Not designed to look discoverable — it exists to catch
resolver abuse and record who probes it. Returning NXDOMAIN for everything
is correct behaviour for that role. It is *not* the callback path for file
tokens; those fire over HTTP against the canary server (see above). File
tokens do publish a `dns_canary` name in their metadata for operators who
run a wildcard `*.canary.<domain>` record and want a second, DNS-based
signal, but nothing is embedded in the document for it.

**Credential token cross-reference (post-fix).** If you plant fake creds via
`honeytoken_generate_credentials` and an attacker tries them on one of your
own honeypots, the alert pipeline now auto-escalates severity to CRITICAL and
links the alert back to the originating token. Tokens also record where they
were planted, so a trigger months later says which system the attacker
reached rather than only which token fired. See "What is partially functional"
below for the caveat on scope.

---

## Verified against real clients and scanners

The in-process engines are periodically driven with the actual client software
and with `nmap -sV --version-intensity 9`, because "it accepts a connection" and
"it is indistinguishable from the real service" are very different bars. The
regression tests in `tests/unit/test_protocol_fidelity.py` pin each finding,
quoting the nmap signature involved so a future change can tell what it breaks.

As of the last sweep, `nmap -sV` identifies SSH, FTP (ProFTPD 1.3.5), SMTP
(Postfix), MySQL (8.0.36), PostgreSQL, MSSQL (SQL Server 2019 15.00.2000),
MongoDB (5.0.14), Redis (7.0.5), VNC (RFB 3.8), RDP, SMB (microsoft-ds) and
HTTP (the deployed persona) as the software they impersonate.

**Malformed requests wear the same identity as valid ones.** aiohttp rejects
unparseable requests inside `RequestHandler.handle_error`, below any
middleware, so those replies used to fall back to a process-wide banner — an
Apache-persona honeypot answered a malformed probe as nginx, and every persona
in the process leaked at the same seam. `http_identity.identity_runner`
subclasses the runner, server and request handler so each listener stamps its
own banner on protocol errors too. Verified: malformed and well-formed requests
now return identical `Server` headers on all five aiohttp listeners.

**Memcached never amplifies; SNMP, SIP and DNS are bounded.** All are reflection
vectors, and the engines are built to watch the reconnaissance rather than take
part in it. `memcached` speaks TCP only — UDP/11211 is where reflection actually
happens, and a UDP listener that answered spoofed traffic would enlist the
honeypot in someone else's DDoS. The UDP engines (SNMP, SIP, DNS) do answer, but
a reply is capped at a small multiple of the request (SNMP 4x, SIP 3x, DNS 2x —
a `GetBulk` is cut back to a single varbind) and replies per source address are
token-bucket rate limited, so the traffic they could add to a reflection is a few
KB/s per victim. The cap is not 1x on purpose: at 1x an ordinary `snmpget` came
back `tooBig` and a short SIP REGISTER got a 401 with no digest challenge, both
of which identify the decoy and capture nothing. Every probe is recorded either
way. This is a design decision, not an omission.

**The Docker API engine identifies as Docker, byte-for-byte.** `nmap -sV`
returns `docker  Docker 24.0.7` — a hard match, not a softmatch. Getting there
took matching nmap's published rule exactly, because it is an exact rule: a
real daemon's 404 carries `Content-Type`, `Date`, `Content-Length: 29` and the
body `{"message":"page not found"}`, with **no `Server` header and nothing
else**. Three separate things were breaking it — an extra `Server` header from
aiohttp's global fallback, `Content-Length` emitted before `Date`, and the
request path interpolated into the message so the body was not 29 bytes — and
the port read as `nginx`, which nobody runs on 2375.

The general lesson, since it applies to any engine added later: header
*order* is semantically irrelevant to HTTP and entirely relevant to
fingerprinting, and scanner rules are anchored regexes over the whole
response. `http_identity.ExactHeaderResponse` exists for this — it suppresses
the `Server` header and pins header order. `test_protocol_fidelity.py` quotes
the nmap rule it satisfies.

## What is partially functional

**Credential tokens.** The match-and-escalate pipeline (see above) fires when
the planted credentials hit one of *your own* honeypots, across every service
that captures a login — SSH, HTTP form POST, FTP login, SMTP AUTH, Redis AUTH
(legacy AUTH maps to the `default` user), and PostgreSQL / MSSQL logins (both
DB engines force cleartext auth precisely so the password is capturable).
MySQL and VNC never put the plaintext on the wire (MySQL sends a
`mysql_native_password` scramble over a server salt; VNC a DES
challenge/response), but because the honeypot generated the salt/challenge it
recomputes the expected digest for each planted password and matches on that
(`credential_verify.py`) — so those two are covered too, just verified rather
than compared. The one true limitation is scope: if an attacker tries the
credentials against a real production system you have nothing visible there,
there's no signal back to HoneyPot MCP. Worth it for trip-wire deception
inside the honeypot stack; not a substitute for real credential canaries that
hook into an identity provider's audit log.

**SMTP engine.** Speaks Postfix's dialect rather than accepting everything:
commands out of sequence get the 503 Postfix gives (`RCPT` before `MAIL`, nested
`MAIL`, `DATA` with no recipients), a mailbox the host does not have is
`550 5.1.1 User unknown in local recipient table` while `postmaster`, `root`,
`info` and friends are accepted, `VRFY` distinguishes the two, and an external
sender mailing an external recipient is still accepted — that is the open-relay
behaviour the engine exists to observe. `nmap --script smtp-enum-users`
therefore finds the real mailboxes and only those. STARTTLS completes a real TLS
handshake and the protocol continues over it. What it does not do is deliver
mail: there is no queue, so a completed `DATA` is acknowledged and recorded but
never bounces or relays, and a patient human watching for a delivery failure
notice will not get one.

**FTP engine.** Backed by a small, internally consistent file tree
(`engines/ftp_fs.py`): `LIST`, `NLST`, `SIZE`, `MDTM`, `CWD`, `REST` and `RETR`
all derive from the same nodes, so the size in a listing is the length of the
bytes `RETR` then serves, and the archives are real gzip/tar files that
extract. A file an attacker uploads is visible to the rest of that session.
Downloads are recorded with a SHA-256 of what was served. `DELE`, `MKD`, `RMD`
and `RNFR` answer `550 Permission denied` and are recorded; nothing is ever
changed. The tree is the same for every connection to one honeypot, and
different between honeypots.

**RDP engine.** Answers the way a Windows host does. A client that asks for
Network Level Authentication is given CredSSP (the negotiation response carries
the flags Windows sends, which is what makes `nmap -sV` report `Microsoft
Terminal Services`), and the NTLM exchange runs for real: the CHALLENGE discloses
a stable Windows identity (NetBIOS/DNS names, build, time — exactly what `nmap
--script rdp-ntlm-info` reads), the client's AUTHENTICATE is parsed, and the
NetNTLMv2 response is recorded as a ready-to-crack `hashcat -m 5600` line
(`-m 5500` for NTLMv1). The capture was checked against an independent NTLM
implementation (pyspnego): the right password reproduces the response, a wrong
one does not — which is also how a planted honeytoken password is recognised from
the response alone, with no plaintext on the wire. Authentication then fails with
`STATUS_LOGON_FAILURE`. A client that asks only for plain TLS still gets the MCS
Connect Initial capture (`clientName`, build, layout). There is no RDP session
beyond authentication: no MCS Connect Response, no channel join, no desktop.

---

## Boundaries imposed from outside this codebase

Nothing in this section is a defect that could be fixed here — each is a
constraint set by software we do not control. They are listed because knowing
where the edges are is the point of this document, not because they are
outstanding work.

**PDF file tokens — fires on open but Acrobat prompts on first use.** The
current implementation (`tokens/file_token.py:_create_pdf`) injects an
`/OpenAction` URI dict on the document catalog plus a full-page `linkAbsolute`
click annotation as a safety net. The `/OpenAction` is what fires on document
open in Acrobat, Foxit, and most desktop readers — but Acrobat shows a "Trust
this URL?" prompt on first open from an unknown domain, and the user has to
click Allow. Enterprise installs with the domain whitelisted skip the prompt;
default home-user installs prompt every time. Preview on macOS and most
browser-embedded viewers ignore `/OpenAction` entirely but still resolve
link annotations (the safety-net path), so the click trigger fires there
once the user clicks anywhere in the document. Treat PDF tokens as a
high-confidence-but-not-guaranteed trigger — the canary URL token is still
the most reliable wire for adversarial detection.

**AWS / Azure / GCP key tokens require a forwarder in your cloud account.**
This is not a gap in the token — it is how cloud credential canaries work at
all, including commercial ones. Nothing observes an API call made against
AWS except AWS, so detection has to come from an audit-log feed you own.
The generated keys look real (correct AKIA/ASIA prefix, correct character
set, correct length) and will sit plausibly in a `.env` file or
`~/.aws/credentials`. But the key alone has no callback path — detection
only works if use of the key generates an audit-log event you route back to
HoneyPot MCP. The operator-side glue for that now ships:
`examples/cloud-forwarders/{aws,azure,gcp}/` contains ready-to-deploy
Lambda / Azure Function / GCP Cloud Function forwarders (with Terraform /
Bicep / gcloud IaC) that relay CloudTrail / Activity Log / Audit Log events
to the HMAC-signed `/cloud-event` receiver on the canary server. You still
have to register the decoy key in your own cloud account and deploy the
forwarder — without that step the generated key is a believable decoy and
nothing more. [Thinkst's Canarytokens](https://canarytokens.org) (free)
remains the zero-setup alternative with a hosted detection backend. The
token's `plant_instructions` text says this explicitly.

---

## Deliberate design decisions

These are choices, with the reasoning, not things left undone. Changing any of
them is a product decision rather than a bug fix.

**HTTP — a narrow authenticated area, on purpose.** `POST /login` used to reject
everything, which meant a credential-spraying bot (it moves on only after a
success) never showed us what it does with a foothold. Now a planted honeytoken
credential, or the single weak username/password pair derived from the honeypot's
name, logs in and is redirected to a small admin console (users, settings,
backups, logs, uploads — all decoy, with downloads served from the same file tree
the FTP engine uses). Everything after the login is recorded as
`http_authenticated_request`, uploads included. The derived pair differs between
honeypots so "admin/admin works everywhere" is not a fingerprint, and
`accepted_logins` in a honeypot's config replaces it (an empty list turns the
area off). The cost is real: this is a login surface, so it is decoy-only and
accepts nothing beyond those credentials, and an operator who does not want it
sets `accepted_logins: []`.

**Cowrie — what is fixed and what is not.** The persona now covers the whole
story rather than a few strings. Cowrie's bundled filesystem is rewritten per
persona (`engines/cowrie_fs.py`): `/etc/hostname`, `/etc/hosts`, `/etc/issue`,
`/etc/os-release`, `/etc/lsb-release`, `/proc/version`, the MOTD, accounts
(`passwd`/`group`/`shadow`) and a home directory with history, with Cowrie's own
`phil` account gone. A live check against a container found the persona's kernel
settings had never applied at all (they were set in the wrong Cowrie config
section), so `uname` kept reporting the image's Debian kernel; that is fixed and
pinned by a Docker-gated test that deploys each persona and compares ten things an
attacker reads. Cowrie's emulated `wget`/`curl` can no longer reach real hosts
(outgoing sockets bind to loopback; the resolver is pinned to loopback too). What
remains is Cowrie's own behaviour, which this project does not patch: `uptime`
starts from zero at every container start (it counts the Cowrie process, so it is
only wrong shortly after a restart), `ps`, `df`, `mount` and `free` come from
Cowrie's canned output and are not tailored per persona, command timing is
uniform, and the SSH key-exchange offer is Cowrie's. A skilled human who knows
what to compare will still find it.

---

## What is intentionally out of scope

- **Internet-facing high-volume production deployment** — needs perimeter
  hardening, host isolation, and TLS termination in front of the canary
  callback (a reverse proxy like nginx / Caddy / Cloudflare Tunnel does
  the job). Log shipping is *in scope* and shipped: Splunk HEC, Elastic
  ECS, Grafana Loki, Datadog, ArcSight CEF, and RFC 5424 syslog renderers
  are all built into the webhook layer — configure via
  `alert_subscribe(format=...)`. CloudTrail / Azure Activity Log /
  GCP Audit Log forwarders ship under `examples/cloud-forwarders/`,
  and blocklist push integrations for Cloudflare / pfSense / AWS WAFv2
  ship under `tools/blocklist_push.py`.
- **APT / targeted-attacker research** — the custom engines are too thin.
- **Real TLS termination, ICS / SCADA protocols, IoT-specific protocols** —
  see Conpot or T-Pot.

---

## Updating this document

This file should stay accurate. If you add a feature that closes one of these
gaps, edit the relevant section so it reflects reality. If you discover a new
limitation, add it — silent rot is the failure mode this document exists to
prevent.

## Operational notes

- **One server owns the sensors.** With a local SQLite database, a second server process
  starts read-only (queries, triage, reports work; deploy/stop/pause/clone/configure/
  pcap_control refuse). Over PostgreSQL the lock is per-host file only, so two servers on
  different hosts sharing one database are not detected.
  A read-only session does not take over when the owner exits; restart it. In that mode
  `honeypot_health`/`honeypot_status` do not probe in-process sensors (a probe from a
  second process looks like an attacker to the owner) and say so.
- **Disk watch covers the database directory, `reports_dir` and the pcap ring.** It
  alerts below `MIN_FREE_DISK_MB` (500); it does not prevent the disk filling, and a
  remote PostgreSQL's own volume is not visible to it.

- **Dashboards against a host daemon need one group, not a looser directory.**
  The daemon keeps `data/` private (`0700`), which Grafana (a container, uid 472)
  cannot read. `docs/DEPLOY.md` step 9 gives read access to a dedicated
  `honeypot-db` group and hands only the Grafana container that group
  (`HONEYPOT_DB_GID`, required by `docker-compose.observability.yml`); the
  `deploy/grafana-readable.conf` drop-in makes the daemon write group-readable
  files. Skip all of it if you do not run the dashboards. The all-in-one compose
  stack shares a volume and needs none of this.
- **Packet-capture rings are owner-only.** tcpdump runs under `umask 077` in a
  private directory, and when started as root it drops to a user that owns the
  directory. Extracts written by `pcap_extract` are `0600` and refuse to overwrite.
- **`tls/` and `reports/generated/` follow settings, not the working
  directory** (`tls_dir`, `reports_dir`), so starting the server from another
  directory no longer mints a second certificate or a second copy of generated
  honeytoken keys.
