from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./honeypot_mcp.db"

    # Threat intel API keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""

    # GeoIP
    geoip_db_path: Path = Path("./config/GeoLite2-City.mmdb")

    # Canary callback server
    canary_callback_host: str = "0.0.0.0"
    canary_callback_port: int = 8888
    canary_public_url: str = "http://localhost:8888"

    # Docker
    docker_socket: str = Field(default="", description="Docker socket URI")

    # Honeypot default ports
    default_ssh_port: int = 2222
    default_http_port: int = 8080
    default_ftp_port: int = 2121
    default_smtp_port: int = 2525
    default_dns_port: int = 5353

    # MITRE ATT&CK data path
    mitre_data_path: Path = Path("./config/mitre_attack.json")

    # Logging
    log_level: str = "INFO"

    # YAML config overlay (loaded separately)
    _yaml_config: dict[str, Any] = {}

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper

    @classmethod
    def load(cls, yaml_path: Path | None = None) -> "Settings":
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
        _settings = Settings.load(Path("config/settings.yaml"))
    return _settings
