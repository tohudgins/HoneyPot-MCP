from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
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

    # MITRE ATT&CK data path
    mitre_data_path: Path = _PROJECT_ROOT / "config" / "mitre_attack.json"

    # Logging
    log_level: str = "INFO"
    # `text` (human-readable) or `json` (one JSON object per line — pipes
    # cleanly into Loki / Splunk / Cloudwatch Logs Insights).
    log_format: str = "text"

    # YAML config overlay (loaded separately)
    _yaml_config: dict[str, Any] = {}

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

    @field_validator("geoip_db_path", "geoip_asn_db_path", "mitre_data_path", mode="after")
    @classmethod
    def _anchor_to_project_root(cls, v: Path) -> Path:
        return v if v.is_absolute() else _PROJECT_ROOT / v

    @classmethod
    def load(cls, yaml_path: Path | None = None) -> Settings:
        instance = cls()
        if yaml_path and yaml_path.exists():
            with yaml_path.open() as f:
                instance._yaml_config = yaml.safe_load(f) or {}
        return instance

    def get_yaml(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._yaml_config
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
        return node


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings.load(_PROJECT_ROOT / "config" / "settings.yaml")
    return _settings
