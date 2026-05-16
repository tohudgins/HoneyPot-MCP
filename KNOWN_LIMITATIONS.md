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

**Canary URLs.** The aiohttp callback server on port 8888 is real. Hitting
the URL triggers a CRITICAL alert with full request metadata. Set
`CANARY_PUBLIC_URL` to a publicly reachable address (ngrok, Cloudflare Tunnel,
or a real domain) and these fire from the internet.

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

**Credential tokens.** The match-and-escalate pipeline (see above) only fires
when the planted credentials hit one of *your own* honeypots — SSH, HTTP form
POST, FTP login, SMTP AUTH. If an attacker tries the credentials against a
real production system you have nothing visible there, there's no signal back
to HoneyPot MCP. Worth it for trip-wire deception inside the honeypot stack;
not a substitute for real credential canaries that hook into an identity
provider's audit log.

**SMTP / FTP engines.** They catch automated traffic — open-relay scanners,
FTP credential brute force, port-scanner banner grabs. Post-fidelity-upgrade,
they advertise realistic feature sets (Postfix-style EHLO, ProFTPD-style FEAT,
anonymous FTP flow). SMTP STARTTLS actually completes a real TLS handshake
using the per-honeypot self-signed cert. A skilled human probing manually
will still identify them eventually because we don't implement the full
state machines (no actual data connections for FTP transfers, no SMTP mail
queuing or DSN delivery). Comparable to OpenCanary fidelity, not Mailoney
or a real Postfix deployment.

**RDP banner honeypot.** Parses the X.224 Connection Request (TPKT layer),
extracts the leaked `Cookie: mstshash=user@DOMAIN` field that virtually
every RDP scanner and brute-force tool sends in the clear, and returns a
believable "NLA required" negotiation-failure response. RDP brute-force
is one of the largest categories of public-internet attack traffic, so
this catches real traffic immediately on a public IP. We do NOT implement
the rest of the protocol stack (no MCS, no TLS post-handshake, no CredSSP),
so the connection closes after the banner exchange — looks like a hardened
server rejecting an insecure protocol negotiation.

---

## What does not work today

**DOCX file tokens.** Don't use these for adversarial detection right now.
The current implementation in `tokens/file_token.py` writes the tracking URL
as null-prefixed text in a footer paragraph. Word will never make a network
request from that — it's display text, not a document relationship. To
actually fire on open you need to inject an `External`-mode relationship
into `word/_rels/document.xml.rels` and reference it from the document body
(`<v:imagedata>` or a modern equivalent). That's planned as a follow-up but
not in the current code; treat DOCX tokens as a planted-decoy lookalike, not
a live tripwire.

**PDF file tokens.** Uncertain. The current implementation uses ReportLab's
`Paragraph("<img src=...>")` HTML mode. Whether the resulting PDF actually
fetches the image when opened depends entirely on the reader: Adobe Acrobat
sandboxes external resources by default, Preview (macOS) usually ignores them
silently, browser-based viewers prompt the user, and most enterprise environments
strip external references at the gateway. The Canarytokens-style approach
uses a `/URI` open-action or `app.launchURL` JavaScript — both more reliable
than embedded HTML, both not yet implemented here. Don't rely on PDF tokens
to fire in the wild; use canary URLs as the trip-wire path instead.

**AWS API key tokens — no built-in detection.** The generated keys look real
(correct AKIA/ASIA prefix, correct character set, correct length) and will sit
plausibly in a `.env` file or `~/.aws/credentials`. **But there is no callback
path.** Detection requires external infrastructure that HoneyPot MCP does not
ship: either you register the key in your own AWS account and route CloudTrail
`AccessDenied` / `ConsoleLogin` events into the MCP webhook, or you use
[Thinkst's Canarytokens](https://canarytokens.org) (free) for AWS keys with
the real detection backend. By itself, the generated key is a believable
decoy and nothing more. The token's `plant_instructions` text now says this
explicitly.

**HTTP — no authenticated session flow.** Sessions are now issued and
tracked (cookie persistence + repeat-visit escalation), but the engine
doesn't model a real authentication state machine — every `POST /login`
gets the same "invalid credentials" response regardless of input, because
"accepts any password" is itself a fingerprint. A scanner that submits
the same creds twice and notices identical responses can infer no real
auth backend is present. Adding randomized "credential check" timing or
selective acceptance is possible but increases the risk of the honeypot
itself becoming a useful login surface for attackers.

**Cowrie known fingerprints.** Cowrie itself has well-known tells in `df` /
`uname` / filesystem layout output that experienced attackers check. The
persona system fixes the deployment-time fingerprint problem but doesn't
address Cowrie's internal behaviour. That's a Cowrie limitation, not ours;
covers ~99% of internet attack traffic regardless.

---

## What is intentionally out of scope

- **Internet-facing high-volume production deployment** — needs perimeter
  hardening, host isolation, log shipping to Elastic / Splunk / Loki. The
  webhook layer enables this but doesn't ship integrations out of the box.
- **APT / targeted-attacker research** — the custom engines are too thin.
- **Real TLS termination, ICS / SCADA protocols, IoT-specific protocols** —
  see Conpot or T-Pot.

---

## Updating this document

This file should stay accurate. If you add a feature that closes one of these
gaps, edit the relevant section so it reflects reality. If you discover a new
limitation, add it — silent rot is the failure mode this document exists to
prevent.
