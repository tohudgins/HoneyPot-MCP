# Security Policy

## Reporting a vulnerability

Please report security issues privately, **not** as a public GitHub issue.

Use [GitHub's private vulnerability reporting](https://github.com/tohudgins/HoneyPot-MCP/security/advisories/new)
(Security → Report a vulnerability). Include what you were running, what you
observed, and a reproduction if you have one.

Expect an acknowledgement within a few days. This is a personally maintained
project, not a vendor with an on-call rota — please size your expectations
accordingly, and say so in the report if you have a disclosure deadline.

## What this software is

HoneyPot MCP deliberately exposes services to attackers and processes hostile
input as its entire purpose. That makes some behaviour *intentional* that would
be a defect elsewhere:

- **Honeypot engines accept malformed, malicious and exploit traffic.** Capturing
  an EternalBlue probe or a Log4Shell payload is the feature.
- **Fake credentials, keys and tokens are generated on purpose.** Anything that
  looks like a leaked AWS key or private key in this repo's output is decoy
  material with no access to anything.
- **Engines return believable-but-false data** to keep an attacker engaged.

## The threat model that is specific to this design

Worth stating plainly, because it is unusual: **the control plane is driven by
a language model that reads attacker-authored data.**

Captured usernames, request paths, shell commands and User-Agent strings are
attacker-chosen strings. They are shown to an analyst through a model, which
means they reach the same context that decides which tools to call and with
which arguments. An attacker who never authenticates to anything can therefore
put text in front of the decision-making component simply by attacking a
honeypot — which is the entire point of the product.

The mitigation is not to hope the model resists persuasion. It is to make sure
that a tool call the attacker *wanted* is still harmless:

- **Bulk writes are confined to the reports directory.** Export tools take an
  `output_path`, and exports embed captured payloads; an unconstrained path
  would turn "attacker writes a string into a honeypot" into an arbitrary file
  write with attacker-chosen content. Paths that resolve outside are refused.
- **Honeypot names cannot become paths.** Names are used as directory and
  container names, and are restricted to a conservative character set, checked
  both at the tool layer and again where a name becomes a path.
- **Destructive actions are audited** so an unexpected prune or a stopped
  sensor is attributable after the fact, with credential-shaped arguments
  redacted before they are stored.
- **The console cannot change anything** — it registers GET routes only.

If you find a tool parameter that reaches the filesystem, the network, or a
subprocess without an equivalent constraint, that is a vulnerability worth
reporting even though "the caller is trusted" on paper.

## What would be a real vulnerability

Roughly, anything that lets an attacker escape the deception boundary or reach
the operator:

- **Escape from an engine to the host** — code execution in the server process,
  path traversal that writes outside the intended directories, or anything that
  turns captured input into execution.
- **Compromise of the control plane** — bypassing the bearer token on a
  networked MCP transport, or any state-changing action reachable from the
  read-only console.
- **Injection into downstream systems** — a payload that breaks out of the CEF,
  syslog, ECS or JSON renderers to forge events in a SIEM, or that escapes
  escaping in the HTML/Markdown reports.
- **Secret disclosure** — API keys, HMAC secrets or honeytoken values leaking
  into logs, alert payloads, the audit log, or generated artifacts.
- **Denial of service against the collector** — an input that kills the process
  or the ingestion pipeline rather than being captured and recorded.
- **Fingerprinting that reveals the platform itself** — not a classic
  vulnerability, but a disclosure bug in a deception tool, and treated as one
  here (see `tests/unit/test_protocol_fidelity.py`).

## Deployment guidance

The default configuration is conservative; several things become dangerous only
if you change them deliberately.

- **Never run this on a host you care about.** Use a dedicated, disposable VM,
  and move your admin SSH off port 22 before exposing honeypot ports. See
  [docs/DEPLOY.md](docs/DEPLOY.md).
- **The MCP control plane can deploy honeypots and read every captured
  attack.** On a networked transport it refuses to start without
  `MCP_AUTH_TOKEN`. Do not open that port to the internet — reach it over an
  SSH tunnel.
- **The operations console has no authentication** and shows all captured
  attack data. It binds `127.0.0.1` by default; putting it on `0.0.0.0` should
  be a deliberate decision behind a reverse proxy or a VPN.
- **The canary callback server is meant to be internet-reachable** so tokens can
  phone home. It accepts unauthenticated GETs by design; the `/cloud-event`
  ingest endpoint is separately HMAC-signed and refuses everything until
  `CLOUD_EVENT_HMAC_SECRET` is set.
- **Never plant honeytokens that are real credentials.** The generators produce
  decoys; do not substitute live secrets.

## Known limitations

[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) is a frank account of where the
deception is thin and what a skilled attacker can detect. Those are documented
constraints rather than vulnerabilities — but if you find a *new* way to
fingerprint the platform that isn't listed there, it's worth reporting.
