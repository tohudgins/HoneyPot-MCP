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
        elif hp_type == HoneypotType.VNC:
            from honeypot_mcp.engines.vnc import VNCEngine

            _engines[hp_type] = VNCEngine()
        elif hp_type == HoneypotType.REDIS:
            from honeypot_mcp.engines.redis import RedisEngine

            _engines[hp_type] = RedisEngine()
        elif hp_type == HoneypotType.MYSQL:
            from honeypot_mcp.engines.mysql import MySQLEngine

            _engines[hp_type] = MySQLEngine()
        elif hp_type == HoneypotType.ELASTICSEARCH:
            from honeypot_mcp.engines.elasticsearch import ElasticsearchEngine

            _engines[hp_type] = ElasticsearchEngine()
        elif hp_type == HoneypotType.SMB:
            from honeypot_mcp.engines.smb import SMBEngine

            _engines[hp_type] = SMBEngine()
        elif hp_type == HoneypotType.POSTGRESQL:
            from honeypot_mcp.engines.postgresql import PostgreSQLEngine

            _engines[hp_type] = PostgreSQLEngine()
        elif hp_type == HoneypotType.MONGODB:
            from honeypot_mcp.engines.mongodb import MongoDBEngine

            _engines[hp_type] = MongoDBEngine()
        elif hp_type == HoneypotType.MSSQL:
            from honeypot_mcp.engines.mssql import MSSQLEngine

            _engines[hp_type] = MSSQLEngine()
        elif hp_type == HoneypotType.TELNET:
            from honeypot_mcp.engines.telnet import TelnetEngine

            _engines[hp_type] = TelnetEngine()
        elif hp_type == HoneypotType.MEMCACHED:
            from honeypot_mcp.engines.memcached import MemcachedEngine

            _engines[hp_type] = MemcachedEngine()
        elif hp_type == HoneypotType.SNMP:
            from honeypot_mcp.engines.snmp import SNMPEngine

            _engines[hp_type] = SNMPEngine()
        elif hp_type == HoneypotType.LDAP:
            from honeypot_mcp.engines.ldap import LDAPEngine

            _engines[hp_type] = LDAPEngine()
        elif hp_type == HoneypotType.DOCKER_API:
            from honeypot_mcp.engines.docker_api import DockerAPIEngine

            _engines[hp_type] = DockerAPIEngine()
        else:
            raise ValueError(f"No engine registered for type: {hp_type}")
    return _engines[hp_type]


def list_engine_types() -> list[str]:
    return [t.value for t in HoneypotType]
