from __future__ import annotations

import logging
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _find_project_root(config_file: Path, cwd: Path) -> Path:
    """The directory defaults (database, reports, pcap, .env) are anchored to.

    A source checkout is recognised by its `pyproject.toml`, and that root is
    used so the defaults work whatever cwd an MCP client launched the server
    from (Claude Desktop starts them in C:\\WINDOWS\\system32, where relative
    paths fail). An *installed* package has no such file: `parents[2]` is then
    the venv's `lib/pythonX.Y` directory — root-owned in a container, and not
    somewhere to put a database — so the working directory is used instead."""
    candidate = config_file.resolve().parents[2]
    return candidate if (candidate / "pyproject.toml").is_file() else cwd


# Project root: src/honeypot_mcp/config.py → parents[2] for a checkout.
_PROJECT_ROOT = _find_project_root(Path(__file__), Path.cwd())

log = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = f"sqlite+aiosqlite:///{(_PROJECT_ROOT / 'honeypot_mcp.db').as_posix()}"

    # Threat intel API keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # GeoIP
    geoip_db_path: Path = _PROJECT_ROOT / "config" / "GeoLite2-City.mmdb"
    # Optional separate MaxMind ASN database (GeoLite2-ASN.mmdb, also free).
    # When present, GeoIP enrichment adds the origin AS number + organisation —
    # the single most useful pivot for "is this a hosting/VPN/botnet network?".
    geoip_asn_db_path: Path = _PROJECT_ROOT / "config" / "GeoLite2-ASN.mmdb"
    # Reverse-DNS (PTR) lookup during enrichment. Cheap and high-signal
    # (bulletproof-hosting and residential-proxy PTRs are a strong tell), but
    # it's a network round-trip — set False to disable on an air-gapped host.
    geoip_reverse_dns: bool = True

    # Canary callback server
    canary_callback_host: str = "0.0.0.0"
    canary_callback_port: int = 8888
    canary_public_url: str = "http://localhost:8888"

    # Shared secret for the /cloud-event ingest endpoint. Empty means the
    # endpoint refuses all requests with 503 — the safe default. Set to a
    # cryptographically random string (32+ bytes) on a public deployment
    # and configure your CloudTrail / Azure Activity / GCP Audit log
    # forwarder to sign POST bodies with HMAC-SHA256 over the raw body.
    cloud_event_hmac_secret: str = ""

    # Prometheus /metrics endpoint — separate port from honeypot listeners
    # so scrapers can be locked down independently. Set port to 0 to disable.
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9090

    # MCP transport. `stdio` (default) is what Claude Desktop / Claude Code
    # spawn per chat — the server lives only as long as the client session.
    # `http` (or `sse`) runs a persistent networked server, required for a
    # public deployment: honeypots must outlive any single chat, and in-process
    # engines hold their listeners in the server process. Run it as a daemon
    # (systemd) and point your MCP client at http://<host>:<port>/mcp.
    # `none` is collector mode: run the capture plane (honeypots, canary
    # callbacks, watchdog, webhook delivery, /metrics) with NO control plane
    # at all. That's the right mode for a detached container — stdio there
    # reads EOF from an unattached stdin and exits immediately — and for any
    # host that should collect attacks but never accept control commands.
    mcp_transport: str = "stdio"
    mcp_host: str = "127.0.0.1"
    mcp_port: int = 8000
    # Bearer token that clients must present to the networked (http/sse) MCP
    # control plane. The control plane can deploy honeypots and read all
    # captured data, so on a networked transport it MUST be authenticated:
    # if this is empty and the transport isn't stdio, the server refuses to
    # start (fail-closed) unless `mcp_allow_unauthenticated` is set. stdio is
    # inherently local (a per-chat subprocess) and needs no token.
    # Generate one with `openssl rand -hex 32`. Clients send it as
    # `Authorization: Bearer <token>`.
    mcp_auth_token: str = ""
    # Multiple role-scoped tokens: "token:role,token:role,..." where role is
    # one of viewer/operator/admin (see rbac.py for what each can do). Takes
    # priority over mcp_auth_token when set, so an operator can hand out
    # tokens with less than full access instead of one shared admin token.
    # When this is empty, mcp_auth_token (if set) becomes a single implicit
    # admin token — existing single-token deployments are unaffected.
    mcp_auth_tokens: str = ""
    # Escape hatch: run a networked control plane without a token because you
    # front it with your own auth (e.g. an authenticating reverse proxy or an
    # SSH tunnel you fully trust). Off by default so an open control plane is
    # never the accidental result of a missing token.
    mcp_allow_unauthenticated: bool = False

    # Alert retention. On a public IP the DB grows continuously from internet
    # background radiation. Set >0 to have the watchdog auto-delete alerts +
    # attacker_events older than this many days (the same operation as the
    # manual `alerts_prune` tool). 0 = disabled (never auto-delete) — the safe
    # default, so nobody loses data they didn't opt into discarding.
    retention_days: int = 0
    # How often the retention sweep runs, in hours. Independent of the
    # watchdog's health-check cadence — pruning daily is plenty.
    retention_sweep_interval_hours: float = 24.0
    # Write matching alerts to a JSON Lines archive in `reports_dir` before the
    # retention sweep deletes them. On by default: the sweep runs unattended,
    # so it is the likeliest way to lose a months-old campaign nobody had
    # finished investigating. Set false only if you genuinely want the data
    # destroyed. A failed archive cancels that sweep rather than pruning
    # without one.
    retention_archive: bool = True

    # Per-source-IP concurrent-connection cap for the in-process TCP engines
    # (VNC/Redis/MySQL/PostgreSQL/MSSQL/MongoDB/SMTP/SMB). A single hostile or
    # broken peer can otherwise hold arbitrarily many sockets open. Excess
    # connections from an IP already at the cap are accepted then immediately
    # closed. 0 = unlimited. Does not apply to the aiohttp engines (HTTP/
    # Elasticsearch), which rely on aiohttp's own limits.
    max_connections_per_ip: int = 32

    # ── connection infrastructure (slice A2, engines/conn_limit.py) ─────────
    # Central slowloris protection for every TCP engine wrapped by
    # `limited_factory` / `limited_handler`: a connection that sends nothing
    # for `engine_idle_timeout_seconds` is closed, and no connection outlives
    # `engine_max_session_seconds`. 0 disables either.
    engine_idle_timeout_seconds: float = 120.0
    engine_max_session_seconds: float = 900.0
    # Process-wide ceiling on concurrent connections across ALL wrapped TCP
    # engines (the per-IP cap alone is defeated by many source addresses).
    # 0 = unlimited.
    max_total_connections: int = 2000
    # Per-source-IP token bucket for UDP replies (SNMP/SIP/DNS): sustained
    # replies per second and burst size. Events are still recorded for
    # rate-limited datagrams; only the reply is withheld. rate 0 disables.
    udp_reply_rate_per_second: float = 10.0
    udp_reply_burst: int = 20

    # ── aiohttp engine timeouts (slice A3) ──────────────────────────────────
    # Every aiohttp listener (HTTP/Elasticsearch/Docker API/Kubernetes/canary/
    # metrics) also honours `max_connections_per_ip`. A connection that has not
    # delivered a complete request head within this many seconds is closed
    # (slowloris), and a request body that takes longer than the body timeout
    # to arrive is abandoned with whatever was received. 0 disables either.
    http_first_request_timeout_seconds: float = 15.0
    http_body_timeout_seconds: float = 10.0

    # Docker
    docker_socket: str = Field(default="", description="Docker socket URI")

    # Honeypot default ports
    default_ssh_port: int = 2222
    default_http_port: int = 8080
    default_ftp_port: int = 2121
    default_smtp_port: int = 2525
    default_dns_port: int = 5353
    default_rdp_port: int = 3389
    default_vnc_port: int = 5900
    default_redis_port: int = 6379
    default_mysql_port: int = 3306
    default_elasticsearch_port: int = 9200
    default_smb_port: int = 445
    default_postgresql_port: int = 5432
    default_mongodb_port: int = 27017
    default_mssql_port: int = 1433
    # Telnet, SNMP and LDAP live on privileged ports in the wild (23/161/389).
    # These follow the same convention as ssh/ftp/smtp/dns above and default to
    # an unprivileged equivalent, so the server never needs root; publish the
    # real port with a container mapping or a firewall redirect.
    default_telnet_port: int = 2323
    default_snmp_port: int = 1161
    default_ldap_port: int = 1389
    default_memcached_port: int = 11211
    default_docker_api_port: int = 2375
    # IMAP (143) and rsync (873) are privileged in the wild; SIP and NFS are
    # not, so those keep their real ports.
    default_imap_port: int = 1143
    default_sip_port: int = 5060
    default_rsync_port: int = 8873
    default_nfs_port: int = 2049
    # POP3 is privileged (110); the Kubernetes API server is not.
    default_pop3_port: int = 1110
    default_kubernetes_port: int = 6443

    # MITRE ATT&CK data path
    mitre_data_path: Path = _PROJECT_ROOT / "config" / "mitre_attack.json"

    # How long the event buffer waits before flushing a partial batch. Lower
    # means alerts reach the database (and your SIEM) sooner at the cost of
    # more, smaller transactions. The test suite drops this so assertions
    # don't race a 1-second flush.
    event_flush_interval_seconds: float = 1.0
    # How long shutdown waits for the event buffer to drain. Anything still
    # queued when this expires is discarded — captured attack data, gone — so
    # the buffer logs the count at ERROR rather than losing it quietly.
    # Measured drain is ~1,550 events/sec on SQLite; raise this for a slow or
    # remote database, where the same backlog takes proportionally longer.
    shutdown_drain_seconds: float = 5.0

    # ── Ingest pipeline bounds (slice B1) ───────────────────────────────────
    # High-water mark for events waiting to be written. Normal load never gets
    # near it (measured commit rate ~1,550 events/sec), so nothing is dropped
    # on the way in. Past it the buffer sheds by severity so an attacker-rate
    # flood cannot exhaust memory: LOW is dropped from `event_queue_max`,
    # MEDIUM from 1.5x, HIGH/CRITICAL only from 2x. Drops are counted and
    # logged (at most once per 10s). 0 disables the bound.
    event_queue_max: int = 100_000
    # Same idea in bytes (estimated), because a queue of 100k events carrying
    # 64 KB bodies is not the same memory as 100k small ones.
    event_queue_max_bytes: int = 256 * 1024 * 1024
    # Payloads are attacker-authored, so they are clamped before they are
    # queued: each string to `event_payload_max_string_chars`, the whole
    # payload to `event_payload_max_bytes` (serialized). A clamped payload
    # carries `payload_truncated: true`. `raw_body_b64` — the HTTP engine's
    # verbatim, already-capped (64 KB) forensic copy of a request body — keeps
    # its own, larger per-string allowance and sits outside the total.
    event_payload_max_string_chars: int = 4096
    event_payload_max_bytes: int = 65_536
    event_raw_body_max_chars: int = 98_304

    # Coalescing window for human-facing notification channels (Slack, Teams,
    # email). The same (event_type, source_ip) notifies at most once per
    # window; the suppressed count rides on the next message that goes out, so
    # volume stays visible without being the delivery mechanism. CRITICAL is
    # always exempt.
    #
    # This is not a nicety. One scanner produces thousands of events an hour,
    # and a channel that relays them one-to-one gets muted within a minute —
    # leaving an alerting integration that is worse than none, because
    # everyone believes they are covered. 0 disables coalescing.
    notify_throttle_seconds: float = 300.0

    # ── Cowrie ──────────────────────────────────────────────────────────────
    # Cowrie's emulated wget/curl/tftp/nc make REAL outbound connections to
    # whatever an attacker names, so by default their source address is bound to
    # loopback, which makes every such connect fail (EINVAL) — no firewall needed,
    # and it works on Docker Desktop where DOCKER-USER rules do not. Set true to
    # let it fetch malware samples; then block or monitor egress at the host.
    cowrie_allow_egress: bool = False

    # ── Packet capture ──────────────────────────────────────────────────────
    # Off by default: it needs elevated privileges, and on a public IP it
    # writes continuously. Enable deliberately.
    pcap_enabled: bool = False
    # Interface to capture on. "any" works on Linux; a VPS is usually eth0.
    pcap_interface: str = "any"
    # Ring buffer. tcpdump rotates at `pcap_file_mb` and keeps `pcap_files`
    # of them, so the ceiling is the product — bounded by construction, which
    # matters because a filled disk stops the database and ends collection.
    pcap_file_mb: int = 100
    pcap_files: int = 10
    # Bytes per packet. 0 = whole packet, which is what you want for malware
    # carving and Suricata replay; lower it to headers-only if disk is tight.
    pcap_snaplen: int = 0
    pcap_dir: Path = _PROJECT_ROOT / "pcap"

    # Live operations console — a read-only wall display served by the server
    # itself (see console/). Bound to localhost by default: it exposes every
    # captured attack, so putting it on 0.0.0.0 is an explicit choice.
    # 0 disables it entirely.
    # 8090, not 8080 — 8080 is `default_http_port`, so the console would
    # collide with the first HTTP honeypot anyone deploys.
    console_host: str = "127.0.0.1"
    console_port: int = 8090

    # Where generated artifacts land (alert exports, HTML/Markdown reports).
    # Tools write here instead of returning bulk content inline — a full export
    # is far too large to put in an MCP response. The Docker image pre-creates
    # /app/reports and mounts a volume over it.
    reports_dir: Path = _PROJECT_ROOT / "reports"

    # ── Control plane / delivery hardening (slice C1) ───────────────────────
    # Webhook/syslog/SMTP destinations are validated at subscribe AND delivery
    # time. Link-local (cloud metadata), unspecified, multicast and reserved
    # addresses are ALWAYS refused. Loopback and private (RFC1918 / ULA)
    # addresses are refused too unless this is true — a SOC subscribing an
    # on-prem Splunk/Elastic on 10.x must opt in explicitly, because a
    # subscription pointed at an internal service is an SSRF/exfil primitive.
    webhook_allow_private_destinations: bool = False
    # Upper bound on events waiting for webhook delivery (global queue AND each
    # subscription's own queue). When full, the oldest lowest-severity event is
    # dropped first and the drop is counted — an unbounded queue behind a dead
    # endpoint is a slow memory leak.
    webhook_queue_max: int = 10000
    # Per-(subscription, event_type) cap on CRITICAL notifications per minute
    # for the human channels. CRITICAL is exempt from the per-source-IP
    # coalescing, but spoofed-source UDP floods rotate source_ip, so without a
    # cap one flood turns the exemption into an unbounded stream.
    notify_critical_per_minute: int = 30
    # Comma-separated IPs/CIDRs that `blocklist_push_*` must never push (your
    # own gateway, monitoring, office egress). Link-local/private/loopback and
    # non-global addresses are never pushed regardless.
    blocklist_allowlist: str = ""
    # Extra Host header names the operations console answers to, comma-
    # separated, in addition to loopback and `console_host`. Anything else gets
    # 421, which stops a DNS-rebinding page reading the console from a browser.
    console_allowed_hosts: str = ""

    # Logging
    log_level: str = "INFO"
    # `text` (human-readable) or `json` (one JSON object per line — pipes
    # cleanly into Loki / Splunk / Cloudwatch Logs Insights).
    log_format: str = "text"

    @field_validator("mcp_transport")
    @classmethod
    def validate_mcp_transport(cls, v: str) -> str:
        valid = {"stdio", "http", "sse", "streamable-http", "none"}
        lower = v.lower()
        if lower not in valid:
            raise ValueError(f"mcp_transport must be one of {valid}")
        return lower

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper

    @field_validator("database_url", mode="after")
    @classmethod
    def _resolve_sqlite_path(cls, v: str) -> str:
        # SQLite + relative path = resolved against cwd, which breaks when the
        # server is launched outside the repo (e.g. Claude Desktop spawns from
        # C:\WINDOWS\system32). Anchor relative SQLite paths to the project
        # root so a `./foo.db` in .env still lands in the repo.
        if not v.startswith("sqlite"):
            return v
        scheme, sep, path = v.partition(":///")
        if not sep or not path or ":memory:" in path:
            return v
        if Path(path).is_absolute() or (len(path) >= 2 and path[1] == ":"):
            return v
        return f"{scheme}:///{(_PROJECT_ROOT / path).as_posix()}"

    @field_validator(
        "geoip_db_path", "geoip_asn_db_path", "mitre_data_path", "reports_dir", mode="after"
    )
    @classmethod
    def _anchor_to_project_root(cls, v: Path) -> Path:
        return v if v.is_absolute() else _PROJECT_ROOT / v


_settings: Settings | None = None


def warn_on_world_readable_env(env_path: Path | None = None) -> str | None:
    """Warn if the `.env` file is readable by anyone but its owner.

    It holds the MCP bearer token, VirusTotal and AbuseIPDB keys, and the
    webhook HMAC secrets. The default umask on most systems produces 0644, so
    a file created by an ordinary `cp .env.example .env` is world-readable —
    on a shared or multi-tenant host that hands the control-plane token to any
    local account. The control plane can deploy honeypots and read every
    captured credential, so this is not a theoretical exposure.

    Returns the warning text (for tests) or None when the mode is fine.
    """
    path = env_path or (_PROJECT_ROOT / ".env")
    try:
        if not path.is_file():
            return None
        mode = path.stat().st_mode
    except OSError:
        return None

    # Anything set in the group or other triads.
    if not mode & 0o077:
        return None
    message = (
        f"{path} is mode {oct(mode & 0o777)} — readable beyond its owner. It holds the "
        "MCP auth token and API keys. Run: chmod 600 " + str(path)
    )
    log.warning("%s", message)
    return message


def get_settings() -> Settings:
    """Process-wide settings singleton.

    Configuration comes from environment variables and `.env` only. A
    `config/settings.yaml` overlay used to be loaded here alongside them, but
    nothing ever read from it — the accessor was defined and never called — so
    editing that file silently changed nothing while the docs presented it as a
    config source. It has been removed rather than wired up: pydantic-settings
    already covers every value, and one authoritative mechanism beats two where
    one is a decoy.
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
