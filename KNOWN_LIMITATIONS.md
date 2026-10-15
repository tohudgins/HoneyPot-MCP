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
SMB classifies EternalBlue / DoublePulsar exploit probes and, over SMB2, captures
NTLM logins as NetNTLMv2 with their hashcat line (and refuses them: there is no
file server). VNC captures the RFB auth challenge/response. All of
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
a `GetBulk` is cut back to as many varbinds as fit) and replies per source address are
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

**Attacker tooling, not just scanners (2026-10-06).** Pointing `snmpwalk`, `ldapsearch`,
`kubectl`, `smbclient`, impacket, `mariadb`, `redis-cli`, `psql` and nmap's scripts at the
engines found defects that synthetic-byte unit tests had passed through, each now pinned by
`tests/unit/test_attacker_tool_fidelity.py`:

- **SNMP had no MIB, so `snmpwalk` stopped after one line** ("OID not increasing": every
  GetNext was answered with sysDescr). It now serves a small ordered MIB (system group,
  `ifNumber`, a four-port `ifTable`) with real GetNext/GetBulk semantics, `endOfMibView`,
  `noSuchObject`/`noSuchName`, `notWritable` for Set, and a `sysUpTime` that advances.
- **LDAP's rootDSE was empty** and every other search succeeded with no entries, which is not
  what the Active Directory persona (the bind error text is AD's) does. The rootDSE now lists
  naming contexts and capabilities, and other anonymous searches are `operationsError`.
- **The Kubernetes API answered plain HTTP**, which `kubectl` cannot use, and gave a different
  `gitCommit`, UID, pod name and flow-control UID on every request. It is TLS-only, its
  identity is derived from the honeypot name, `/api/v1` and `/apis/{group}/{version}`
  discovery, `/healthz`, `nodes`, shortNames and server-side Table output exist (so
  `kubectl get pods` prints `READY STATUS RESTARTS AGE`, not a bare `NAME AGE`), and
  `kubectl auth can-i` is answered. Single objects (`get pod X`, `describe`, `-o yaml`),
  nodes, namespaces, secrets and RBAC objects resolve from one model (`_Cluster`), so a list,
  a GET and a watch agree; a name that does not exist is a real `NotFound` Status and a
  namespace that does not exist has no objects. Watch (`?watch=1`) replays current objects
  as `ADDED` and ends at `timeoutSeconds` (capped at 30, 32 at once). Resources with no data
  (deployments, services, ...) return empty lists; writes other than pod create are not
  modelled. The TLS port is fronted by `engines/tls_front.py`: a pre-1.2 ClientHello gets
  the `protocol_version` alert and plaintext HTTP gets Go's 400 text, so `nmap -sV` reports
  `ssl/http nginx 1.25.3`. The certificate is what `kubeadm init` issues: `CN=kube-apiserver`
  from a CA named `kubernetes`, no organisation, valid a year from the cluster's creation
  date, the in-cluster service names and IPs as SANs, `serverAuth` only (see `CertProfile`
  below). *Open:* a ClientHello of TLS 1.2+ that then fails inside the handshake (no shared
  cipher) still closes without an alert.
- **SMB spoke SMB1 only.** Modern clients start with SMB2 and were disconnected, so no sprayer
  could hand over a credential. SMB2 negotiate (2.1) and NTLM session setup are served; the
  SMB1 persona now names the same host and domain as the NTLM challenge and the RDP honeypot,
  and matches nmap's Windows 7–10 signature.
- **MySQL never captured the password of a libmariadb client**, which names a placeholder
  plugin and waits for an auth switch. The engine now sends the switch. It also files the
  plugin name as `auth_plugin` instead of as the database, and answers `SHOW DATABASES`.
  The greeting now offers TLS (`CLIENT_SSL`, nmap's `Capabilities flags: 65535`) with a
  certificate named like MySQL 8's auto-generated one. The client's TLS handshake can
  arrive in the same segment as its SSLRequest, so the engine drives TLS through memory
  BIOs (`_TLSTransport`) rather than `start_tls`, which cannot replay bytes already read;
  verified 30/30 logins from the `mariadb` client over TLS. `mariadb` >= 11.4 verifies the
  server certificate by default and refuses a self-signed one (a real MySQL with its
  auto-generated certificate fails the same way), so use `--ssl-verify-server-cert=0` or
  `--skip-ssl`. The certificate is `CN=MySQL_Server_8.0.36_Auto_Generated_Server_Certificate`
  issued by `..._Auto_Generated_CA_Certificate`, ten years, no SAN.
- **MSSQL answered every login in the TDS 7.2+ encoding**, which impacket (TDS 7.1) read as a
  stray token, and omitted the account from `Login failed for user '...'`.
- **PostgreSQL's startup errors lacked the `F`/`L`/`R` source fields** every real
  ErrorResponse ends with; nmap now reads `PostgreSQL DB 14.10 - 14.15` instead of an
  unversioned match. `version()` agrees with `server_version`, and command tags are real
  (`CREATE TABLE`, `INSERT 0 1`) instead of `OK`.
- **Certificates were one generic self-signed `O=Internal` certificate** with a `localhost`
  SAN, which `ssl-cert` and `openssl s_client` read straight after the handshake. They now
  have the shape of the service (`tls.CertProfile`): Kubernetes and MySQL are leaves from a
  named CA (the CA key is generated for the purpose and discarded, as servers send only the
  leaf); RDP is self-signed, named for the computer FQDN the NTLM challenge discloses
  (`rdp-ntlm-info` and the certificate agree), valid about six months, with the Remote Desktop
  Authentication usage; the default is a bare snakeoil-style `CN=<name>` with no organisation
  and no `localhost` SAN, backdated a stable 1-13 months. A persisted certificate that no
  longer matches its profile (an upgrade, a changed hostname) or has under 30 days left is
  reissued, as an operator would renew it, so a deployment upgraded to this version presents
  a new certificate once. *Open:* the HTTP and SMTP certificates are named after the honeypot
  or its configured hostname, which is a guess at the real hostname; the RSA key is always
  2048-bit.
- **Apache's 404 page hard-coded `Port 80`** and included any port in the Host header in the
  host name. It now names the host without a port and the port the request used (the Host
  header's, else the one the connection arrived on).
- **Redis** answered unknown commands in the Redis 5 wording and had no `CLIENT` command
  (redis-py 5 sends `CLIENT SETINFO` on every connection).
- **Cowrie announced itself.** `nmap -sV` labelled the telnet port "Cowrie Honeypot telnetd"
  (an `IAC DO NAWS` + `login:` opening has its own nmap rule), and `ssh-audit` reported an
  OpenSSH 9.2 banner offering `3des-cbc`, `cast128-cbc`, `hmac-md5`, `diffie-hellman-group14-sha1`,
  a bare `ssh-rsa` host key and `zlib`, none of which OpenSSH 9.2 sends. Telnet now opens like a
  Linux telnetd (`DO TTYPE, TSPEED, XDISPLOC, NEW-ENVIRON`, the distro issue, `<host> login:`;
  nmap reports `Linux telnetd`) and the SSH offer is narrowed to the persona's real defaults,
  in its order (`engines/cowrie_sitecustomize.py`, mounted into the container). *Open:* the
  offer is a strict subset, not a copy: Twisted has no `chacha20-poly1305`, AES-GCM, `-etm`
  MACs, `sntrup761x25519` or the group-exchange/group16/group18 key exchanges, so a HASSH
  server fingerprint still differs from a real OpenSSH's and `ssh-audit`'s version guess is a
  range, not the banner's version.

**What public traffic can trip (2026-10).** Honeytokens fire only when someone uses a tracked value,
so what a scanner can *find* decides what it can trip. Today that is the HTTP decoys: a tracked MySQL
credential as the database login and a tracked canary URL as an error webhook in `/.env`,
`/config.json` and `/wp-config.php`, with the canary answered on the honeypot's public port. Not
covered: the cloud keys in those files and in `/.aws/credentials` are random lookalikes that exist in
no AWS account (a token that fires when used needs a real decoy IAM user and the cloud forwarder, see
`examples/cloud-forwarders`); `/.kube/config` carries a random token; the FTP, Redis, Cowrie,
Elasticsearch and mail decoys serve static or random content, so a credential found there is not
tracked. Which of those a scanner reads and replays on a given host is observed, not assumed: check
`honeytoken_list` after a run.

**Session fidelity gaps seen with real clients (field test, 2026-10).** All of these record the
attack completely; they are places where the session does not look like the real service to a
client that goes further. The rsync honeypot returns the module list and records the anonymous
access and the file request, but a real `rsync` client then times out waiting for a file list.
Cowrie's emulated `head` rejects `head -2` (`-n 2` works), where a real `head` accepts both. A
paramiko client reports "Channel closed" for an SSH exec request (`ssh host cmd`) because Cowrie
closes the channel before answering it; OpenSSH's client gets the output and exit status, and the
command is recorded either way. See [docs/FIELD_TEST.md](docs/FIELD_TEST.md).

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

**Where tracked credentials are served as bait.** The HTTP decoys (`/.env`, `/config.json`,
`/wp-config.php`) serve the tracked MySQL credential and a tracked canary URL, and the FTP decoy
`passwords.txt` carries a tracked pair (an FTP token first, else the MySQL one; LIST, SIZE and RETR
agree on its length and the download event is marked `bait_served`). Redis deliberately has no bait:
its per-connection store is what attackers write to, and the SAVE-redirection detection hashes it, so
seeded keys would pollute that evidence. No real public trip had been observed on the first run.

**rsync stalls after the module is chosen.** The daemon lists modules, records anonymous access and the
file request, but a real `rsync` client then waits for a file list, which needs protocol 31's
compat flags, checksum negotiation and varint-encoded entries inside multiplexed framing. The detection
(CRITICAL on the anonymous module request) is unaffected; the transfer itself is not emulated.

**Grafana: aggregate panels read rollups, time series and geo panels still read raw alerts.** Six panels
(window totals, unique sources, critical count, alerts by sensor, top attackers, top event types) read
the hourly rollups for whole hours and the raw table only for the partial hours at each edge, so they are
exact (identical to `alerts_stats` and to a raw `GROUP BY` on 14.9M real alerts) and answer in 0.00-0.03 s
however large the run gets (`scripts/dashboard_rollups.py`, pinned by `test_dashboard_rollups.py`). The
six that remain on `alerts` need sub-hour buckets (the time series, the tactic timeline) or a payload field
the rollups do not hold (geo country, observed tactics), and take 5-14 s each at 14.9M alerts, growing
with the run. The MCP tools and `sql_query`, which analysis uses, are independent of table size.

**SMTP engine.** Speaks Postfix's dialect rather than accepting everything:
commands out of sequence get the 503 Postfix gives (`RCPT` before `MAIL`, nested
`MAIL`, `DATA` with no recipients), a mailbox the host does not have is
`550 5.1.1 User unknown in local recipient table` while `postmaster`, `root`,
`info` and friends are accepted, `VRFY` distinguishes the two, and an external
sender mailing an external recipient is still accepted — that is the open-relay
behaviour the engine exists to observe. `nmap --script smtp-enum-users`
therefore finds the real mailboxes and only those. STARTTLS completes a real TLS
handshake and the protocol continues over it. A completed `DATA` is analysed
(headers, links, every attachment hashed; an executable attachment makes the event
CRITICAL) and routed per recipient: mail for a local mailbox lands in a maildrop the
POP3 honeypot serves, mail to a name that can never resolve (`.invalid`, `.test`, ...)
bounces with a real RFC 3464 delivery-status notice to the sender's mailbox when the
sender is local, and anything else is recorded as relayed. **Nothing is ever sent
onward**: relaying or bouncing to external addresses would make the honeypot a spam and
backscatter source for whoever's address was forged, so a bounce owed to an external
sender is recorded as suppressed. The consequence is that an attacker testing relay
sees the same `250 queued` a working relay gives, and nothing arrives on their side.
POP3 and IMAP serve that maildrop to the same two kinds of login (a planted credential,
or the one weak pair derived from the honeypot's name; `accepted_logins` replaces it, `[]`
lets nobody in). `USER`/`PASS`, `APOP`, `AUTH PLAIN`, `AUTH LOGIN`, IMAP `LOGIN` and
`AUTHENTICATE PLAIN`/`LOGIN` all end in the same capture and the same check. Flags,
expunges and deletes are remembered for the session only; one visitor cannot change what the
next sees. IMAP implements SELECT/EXAMINE, LIST/LSUB/STATUS/NAMESPACE, FETCH (ENVELOPE,
BODYSTRUCTURE, BODY sections and partials, the macros), SEARCH (including NOT/OR/groups and
dates), STORE, EXPUNGE, IDLE, UID variants and literals; it does **not** implement
SORT/THREAD/CONDSTORE/MOVE/UIDPLUS (not advertised). Sent, Drafts, Trash and Junk hold a few
ordinary messages. CREATE/DELETE/RENAME of the visitor's own folders, APPEND and COPY work
**for the connection only** (8 folders, 50 messages, 512 KB; an APPEND is recorded as
`imap_append`, since a visitor drafting a message into a mailbox is worth knowing about); the
shared mailbox is never changed, and system folders cannot be deleted or renamed. APPEND
reports no `APPENDUID` (UIDPLUS is not advertised).
STARTTLS is still declined, deliberately. `imap_append` is deliberately not mapped to an
ATT&CK technique (none describes appending to a mailbox; a wrong mapping is worse than none); it
is recorded and visible in alerts.

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
Connect Initial capture (`clientName`, build, layout). **A planted honeytoken
credential, or the one weak pair derived from the honeypot's name, is let in** (config
`accepted_logins` replaces it, `[]` lets nobody in, `sessions: false` turns sessions off).
Over NLA the exchange is completed for real (the NTLM session key is derived from the
password and the server's public-key binding sealed with it; FreeRDP 3 and aardwolf both
accept it), over plain TLS the password arrives in the Client Info PDU. The visitor gets a
session (two minutes, ten once they start typing commands) on a Windows-style desktop that
**works as far as a console does**: double-click the `cmd` icon, use the Start menu, or press
Win+R and run `cmd` / `powershell`, and a console window opens in which a fake shell
answers (`whoami`, `dir`, `cd`, `type`, `echo > file`, `ipconfig`, `systeminfo`, `net user`
(including `/add`, which the visitor can read back), `tasklist`, `netstat`, `quser`, `ping`,
PowerShell's `Get-Process`, `Get-ChildItem`, `$PSVersionTable`...). Every command is recorded
(`rdp_command`, CRITICAL when it tries to download something, with the URLs extracted). The
shell **executes nothing and the machine has no route out**: `ping` times out, names do not
resolve, `curl`/`certutil`/`bitsadmin`/`Invoke-WebRequest` fail the way a firewalled server
fails, and protected processes refuse to die. Limits: it is a table of answers over a small
virtual filesystem, not Windows, so a command we do not model prints nothing (real commands
that exist) or "not recognized" (names that do not); command output appears instantly where
`ping` would take four seconds, and a command that would run for a long time (a download, a
`dir /s` of the whole disk) answers at once; `shutdown /r` and `logoff` end the session;
the machine answers `ping` for itself only; there is no Explorer, no Task Manager, no Notepad, and
programs launched from Run that exist on Windows simply open no window; windows cannot be
dragged. The **clipboard channel** is served both ways: text a visitor pastes is recorded
as `rdp_clipboard` (20 items of 4,000 characters), and an optional `clipboard_text` is
announced as the server's own clipboard and served to a visitor who pastes it (counted in the
session summary). Other static channels (drives, printers, audio) are not served. Standard
RDP security (no TLS) is still refused.

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
to the HMAC-signed `/cloud-event` receiver on the canary server. The decoy
identity is a few commands: `aws/terraform/decoy_user.tf` (a deny-all IAM user and
its key), `azure/decoy_sp.sh` (a service principal with no role) and `gcp/decoy_sa.sh`
(a service account with no roles); the resulting key is adopted by passing it to
`honeytoken_generate_aws` / `honeytoken_create` (`access_key_id` + `secret_access_key`,
`client_id` + `client_secret` + `tenant_id`, or `service_account_json`). A *generated*
key does not exist in the cloud, so it leaves no audit-log entry and is only bait for
scanners that grep for key patterns; the token's plant instructions say which kind it
is. What still needs your hands is running those scripts in your account (nothing here
has credentials to do it) and deploying the forwarder; the Terraform validates but was
not applied to a live account. [Thinkst's Canarytokens](https://canarytokens.org) (free)
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

- **`scripts/fetch_backup.sh` reports on SQLite backups only** (a PostgreSQL backup is fetched but
  not analysed) and only from containers that are running when it runs: Cowrie's downloads and TTY
  recordings live in a tmpfs and are gone once the container is removed or restarts, so fetch before
  `teardown`. Its verdict rests on the alerts the honeypots recorded; a sensor that is up but
  unreachable from the internet looks the same as a quiet one, which is why every-sensor-silent is
  called out separately. It was exercised over a real sshd but not against a real DigitalOcean droplet.
- **Host hardening reduces risk and does not remove it** (`docs/HARDENING.md`, "Residual risks").
  Cowrie shares the host's kernel, so a kernel or container-runtime exploit from inside a container
  escapes; the in-process engines share a process with the control plane, so a code-execution bug in
  an engine yields the control plane (its sandbox bounds what that process can do, not whether it can
  be taken); HTTPS egress from the service is open for webhooks and threat intel. The container-egress
  rules on Docker's own bridges were verified by hand on a real `dockerd` (and by the firewall text
  tests), not by an automated test, because they need a Docker daemon whose bridges this suite does
  not control. The Docker guard checks the structure of a create request, not what runs inside the
  image, so it assumes the pinned Cowrie image is what it claims. SMTP and DNS honeypots look like an
  open relay/resolver to an automated check and several cloud acceptable-use policies prohibit those:
  leave them out of a first run on a cloud provider.
- **One server owns the sensors.** A second server process on the same database starts
  read-only (queries, triage, reports work; deploy/stop/pause/clone/configure/pcap_control
  refuse) and **takes over by itself when the owner exits**, re-establishing the sensors
  the old owner left RUNNING (`OWNER_CHECK_SECONDS`, default 10). SQLite ownership is an
  `flock` beside the database file; PostgreSQL ownership is a session advisory lock on a
  dedicated connection, so servers on different hosts are detected too. If a PostgreSQL
  connection blips the lock is released silently; the owner notices within one check,
  re-takes it if free, and otherwise raises a CRITICAL `sensor_ownership_lost` alert (it
  does not stop its own sensors, so the new owner will fail to bind their ports until it is
  stopped). In read-only mode `honeypot_health`/`honeypot_status` do not probe in-process
  sensors (a probe from a second process looks like an attacker to the owner) and say so.
- **Disk watch covers the database directory, `reports_dir` and the pcap ring.** It
  alerts below `MIN_FREE_DISK_MB` (500) and does not prevent the disk filling. The
  alert notifies subscribers directly before it tries to record itself, since the
  normal path notifies only after the row is written, which is what a full disk
  prevents. A remote PostgreSQL's own volume is not visible; `honeypot_database_size_bytes`
  (from `pg_database_size`) is exported so its growth can be alerted on from there.

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
