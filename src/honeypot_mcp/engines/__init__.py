"""Engine registry — maps HoneypotType to its engine instance."""

from __future__ import annotations

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.models import HoneypotType

_engines: dict[HoneypotType, HoneypotEngine] = {}


def get_engine(hp_type: HoneypotType) -> HoneypotEngine:
    if hp_type not in _engines:
        if hp_type == HoneypotType.SSH:
            from honeypot_mcp.engines.ssh import SSHEngine

            _engines[hp_type] = SSHEngine()
        elif hp_type == HoneypotType.HTTP:
            from honeypot_mcp.engines.http import HTTPEngine

            _engines[hp_type] = HTTPEngine()
        elif hp_type == HoneypotType.SMTP:
            from honeypot_mcp.engines.smtp import SMTPEngine

            _engines[hp_type] = SMTPEngine()
        elif hp_type == HoneypotType.FTP:
            from honeypot_mcp.engines.ftp import FTPEngine

            _engines[hp_type] = FTPEngine()
        elif hp_type == HoneypotType.DNS:
            from honeypot_mcp.engines.dns import DNSEngine

            _engines[hp_type] = DNSEngine()
        elif hp_type == HoneypotType.RDP:
            from honeypot_mcp.engines.rdp import RDPEngine

            _engines[hp_type] = RDPEngine()
        else:
            raise ValueError(f"No engine registered for type: {hp_type}")
    return _engines[hp_type]


def list_engine_types() -> list[str]:
    return [t.value for t in HoneypotType]
