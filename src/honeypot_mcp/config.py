from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root: src/honeypot_mcp/config.py → parents[2]. Resolves so defaults
# work no matter what cwd the server was launched from (e.g. Claude Desktop
# launches MCP servers from C:\WINDOWS\system32, where relative paths fail).
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


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
    metrics_host: str = "0.0.0.0"
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
