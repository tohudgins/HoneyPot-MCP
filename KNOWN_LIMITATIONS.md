# Known Limitations

A frank list of what this project does and doesn't do. Anyone with experience
in deception tech knows where the gaps are; pretending they aren't there is the
fastest way to lose credibility. This document exists so you can decide whether
HoneyPot MCP fits your use case before you spend time on it.

The short version: **this is a homelab / SOC-training / automated-attack-
collection project, not an APT-research or commercial-grade deception
platform.** It will catch internet-scale automated traffic on a public IP. It
will not fool a skilled human attacker probing manually.

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
external image — that fetch hits the canary callback and triggers an alert.
Word's Protected View can block the first fetch (user must click "Enable
Editing"); enterprise deployments with Protected View disabled or auto-trust
on certain locations skip the prompt entirely.

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

**DNS as canary infrastructure.** The DNS honeypot isn't designed to look
discoverable — it's the callback path for file-token DNS lookups. Returning
NXDOMAIN for everything is correct behaviour for that role.

**Credential token cross-reference (post-fix).** If you plant fake creds via
`honeytoken_generate_credentials` and an attacker tries them on one of your
own honeypots, the alert pipeline now auto-escalates severity to CRITICAL and
links the alert back to the originating token. See "What is partially
functional" below for the caveat.

---

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

**SMTP / FTP engines.** They catch automated traffic — open-relay scanners,
FTP credential brute force, port-scanner banner grabs. Post-fidelity-upgrade,
they advertise realistic feature sets (Postfix-style EHLO, ProFTPD-style FEAT,
anonymous FTP flow). SMTP STARTTLS completes a real TLS handshake using the
per-honeypot self-signed cert **and continues the protocol over TLS** —
scanners that EHLO-after-STARTTLS see the same extension list and can
follow through to AUTH or DATA. FTP `LIST` over PASV actually opens a
listening data port, accepts the client's connection, and serves a
believable ProFTPD-flavoured `ls -l` listing — scanners that hammer LIST
get fed real directory bytes. A skilled human probing manually will still
identify the SMTP engine because we don't implement a real mail queue or
DSN delivery, and FTP because RETR / STOR still return 550. Comparable to
OpenCanary fidelity, not a real Postfix or ProFTPD deployment.

**RDP honeypot.** Parses the X.224 Connection Request (TPKT layer) and
extracts the leaked `Cookie: mstshash=user@DOMAIN` field that virtually
every RDP scanner and brute-force tool sends in the clear. When the client
requests SSL or HYBRID/CredSSP (most modern clients and tools do), the
engine upgrades the connection to TLS and parses the MCS Connect Initial
PDU — capturing the attacker's `clientName`, `clientBuild`, keyboard
layout, screen resolution, and requested encryption methods as an
`rdp_mcs_handshake` event. RDP brute-force is one of the largest
categories of public-internet attack traffic, so this catches real
traffic immediately on a public IP. We do NOT implement the rest of the
protocol stack (no MCS Connect Response, no channel join, no CredSSP), so
the connection closes after the MCS capture — CredSSP would let us
capture NTLM hashes but is a large implementation for marginal gain.

---

## What does not work today

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

**AWS / Azure / GCP key tokens — detection requires deploying a forwarder.**
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

**HTTP — no authenticated session flow.** Sessions are issued and tracked
(cookie persistence + repeat-visit escalation), and `POST /login` now
rotates across six plausible auth-failed wordings with variable per-
request timing (see above), so a single diff-the-responses probe no
longer confirms the absence of an auth backend. But we still never
accept a login — every credential is rejected. A determined attacker
who tries enough username/password combinations and observes that none
ever succeed will eventually infer there's no real backend. Accepting
some logins (selective acceptance) is possible but increases the risk
of the honeypot itself becoming a useful login surface for attackers.

**Cowrie known fingerprints.** Cowrie itself has well-known tells in `df` /
`uname` / filesystem layout output that experienced attackers check. The
persona system fixes the deployment-time fingerprint problem but doesn't
address Cowrie's internal behaviour. That's a Cowrie limitation, not ours;
covers ~99% of internet attack traffic regardless.

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
