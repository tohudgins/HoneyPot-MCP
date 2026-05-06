"""DNS honeypot engine — logs all DNS queries for C2 callback detection."""

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


class _DNSProtocol(asyncio.DatagramProtocol):
    """UDP DNS server that logs every query and returns NXDOMAIN."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr
        try:
            import dnslib
            request = dnslib.DNSRecord.parse(data)
            qname = str(request.q.qname)
            qtype = dnslib.QTYPE[request.q.qtype]
        except Exception:
            qname = data[:64].hex()
            qtype = "UNKNOWN"

        asyncio.create_task(self._record(src_ip, src_port, qname, qtype))

        # Return NXDOMAIN for all queries
        try:
            import dnslib
            request = dnslib.DNSRecord.parse(data)
            reply = request.reply()
            reply.header.rcode = dnslib.RCODE.NXDOMAIN
            if self._transport:
                self._transport.sendto(reply.pack(), addr)
        except Exception:
            pass

    async def _record(self, src_ip: str, src_port: int, qname: str, qtype: str) -> None:
        # Check if this is a canary token DNS callback
        severity = AlertSeverity.LOW
        event_type = "dns_query"
        payload: dict = {"qname": qname, "qtype": qtype}

        # Canary token DNS callbacks often contain UUID-like subdomains
        if any(len(part) == 32 or len(part) == 36 for part in qname.split(".")):
            severity = AlertSeverity.HIGH
            event_type = "dns_canary_callback"
            # Try to match to a known honeytoken
            async with get_session() as session:
                from sqlalchemy import select
                from honeypot_mcp.storage.models import Honeytoken, HoneytokenType, HoneytokenStatus
                result = await session.execute(
                    select(Honeytoken).where(
                        Honeytoken.type == HoneytokenType.FILE,
                        Honeytoken.status == HoneytokenStatus.ACTIVE,
                    )
                )
                for token in result.scalars().all():
                    if token.token_value in qname or qname.startswith(token.token_value[:16]):
                        await queries.mark_honeytoken_triggered(
                            session, token.id,
                            {"trigger_ip": src_ip, "dns_query": qname}
                        )
                        severity = AlertSeverity.CRITICAL
                        payload["matched_token_id"] = token.id

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

    def error_received(self, exc: Exception) -> None:
        log.debug("DNS honeypot error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class DNSEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._transports: dict[str, asyncio.DatagramTransport] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(name, hp_id),
            local_addr=("0.0.0.0", port),
        )
        cid = f"dns-{secrets.token_hex(8)}"
        self._transports[cid] = transport  # type: ignore[assignment]
        log.info("DNS honeypot '%s' listening on UDP port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        transport = self._transports.pop(container_id, None)
        if transport:
            transport.close()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._transports, "type": "asyncio_udp_dns"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["DNS honeypot is in-process — events are stored directly in the database."]
