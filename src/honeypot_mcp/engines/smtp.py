"""SMTP honeypot engine — lightweight asyncio SMTP server."""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


class _SMTPProtocol(asyncio.Protocol):
    """Minimal SMTP banner-and-capture protocol."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None, banner: str) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._banner = banner
        self._transport: asyncio.Transport | None = None
        self._buf = b""
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._lines: list[str] = []

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        transport.write(f"{self._banner}\r\n".encode())
        asyncio.create_task(self._record_event("smtp_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            decoded = line.decode("utf-8", errors="replace").strip()
            self._lines.append(decoded)
            self._dispatch(decoded)

    def _dispatch(self, line: str) -> None:
        upper = line.upper()
        if upper.startswith("EHLO") or upper.startswith("HELO"):
            self._transport.write(b"250-localhost Hello\r\n250 OK\r\n")
        elif upper.startswith("AUTH"):
            self._transport.write(b"334 VXNlcm5hbWU6\r\n")  # "Username:" base64
            asyncio.create_task(self._record_event(
                "smtp_auth_attempt", AlertSeverity.HIGH, {"command": line}
            ))
        elif upper.startswith("MAIL FROM"):
            self._transport.write(b"250 OK\r\n")
            asyncio.create_task(self._record_event(
                "smtp_mail_from", AlertSeverity.MEDIUM, {"command": line}
            ))
        elif upper.startswith("RCPT TO"):
            self._transport.write(b"250 OK\r\n")
            asyncio.create_task(self._record_event(
                "smtp_rcpt_to", AlertSeverity.MEDIUM, {"command": line}
            ))
        elif upper == "DATA":
            self._transport.write(b"354 Start mail input\r\n")
        elif upper == "QUIT":
            self._transport.write(b"221 Bye\r\n")
            if self._transport:
                self._transport.close()
        else:
            self._transport.write(b"500 Unknown command\r\n")

    async def _record_event(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        async with get_session() as session:
            await queries.create_alert(
                session,
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
            from honeypot_mcp.storage.models import AttackerEvent
            session.add(AttackerEvent(ip=src_ip, event_type=event_type, extra=payload))

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class SMTPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, tuple[asyncio.AbstractServer, str]] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        banner = config.get("fake_banner", "220 mail.example.com ESMTP Postfix")

        # Look up DB id
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _SMTPProtocol(name, hp_id, banner),
            host="0.0.0.0",
            port=port,
        )
        container_id = f"smtp-{secrets.token_hex(8)}"
        self._servers[container_id] = (server, name)
        log.info("SMTP honeypot '%s' listening on port %d", name, port)
        return container_id

    async def stop(self, container_id: str, remove: bool = False) -> None:
        entry = self._servers.pop(container_id, None)
        if entry:
            server, _ = entry
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_smtp"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["SMTP honeypot is in-process — events are stored directly in the database."]
