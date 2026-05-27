# Changelog

Reverse-chronological summary of meaningful changes. Not a release log —
the project isn't on a version cadence — but each section represents a
distinct iteration with a coherent goal.

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
