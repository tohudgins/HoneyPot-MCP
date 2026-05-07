"""FTP honeypot engine — minimal asyncio FTP server."""

from __future__ import annotations

import asyncio
import base64
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


class _FTPProtocol(asyncio.Protocol):
    """Minimal FTP server that captures login attempts."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None, banner: str) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._banner = banner
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._pending_user: str | None = None
        self._buf = b""

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        transport.write(f"220 {self._banner}\r\n".encode())
        asyncio.create_task(self._record("ftp_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            cmd = line.decode("utf-8", errors="replace").strip()
            self._handle_command(cmd)

    def _handle_command(self, cmd: str) -> None:
        parts = cmd.split(" ", 1)
        verb = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if verb == "USER":
            self._pending_user = arg
            self._transport.write(b"331 Password required\r\n")
        elif verb == "PASS":
            asyncio.create_task(self._record(
                "ftp_login_attempt", AlertSeverity.HIGH,
                {"username": self._pending_user, "password": arg}
            ))
            self._transport.write(b"530 Login incorrect\r\n")
            self._pending_user = None
        elif verb == "QUIT":
            self._transport.write(b"221 Goodbye\r\n")
            self._transport.close()
        elif verb == "SYST":
            self._transport.write(b"215 UNIX Type: L8\r\n")
        elif verb == "FEAT":
            self._transport.write(b"211-Features:\r\n PASV\r\n211 End\r\n")
        else:
            self._transport.write(b"502 Command not implemented\r\n")
            asyncio.create_task(self._record(
                "ftp_command", AlertSeverity.LOW, {"command": cmd}
            ))

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        await submit_event(PendingEvent(
            honeypot_id=self._hp_id,
            source_ip=src_ip,
            source_port=src_port,
            event_type=event_type,
            payload=payload,
            severity=severity,
        ))

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class FTPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        banner = config.get("fake_banner", "ProFTPD 1.3.5 Server (Debian) ready")

        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _FTPProtocol(name, hp_id, banner),
            host="0.0.0.0",
            port=port,
        )
        cid = f"ftp-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("FTP honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_ftp"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["FTP honeypot is in-process — events are stored directly in the database."]
