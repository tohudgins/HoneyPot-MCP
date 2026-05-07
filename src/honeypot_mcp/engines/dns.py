"""DNS honeypot engine — logs all DNS queries for C2 callback detection."""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
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
        severity = AlertSeverity.LOW
        event_type = "dns_query"
        payload: dict = {"qname": qname, "qtype": qtype}
        matched_token_id: int | None = None

        # File honeytokens use a 32-char UUID hex as a subdomain label.
        # Match against `token_meta.token_uid` (what file_token.py actually stores)
        # rather than the brittle `token_value in qname` heuristic.
        labels = [p for p in qname.split(".") if len(p) == 32]
        if labels:
            severity = AlertSeverity.HIGH
            event_type = "dns_canary_callback"
            async with get_session() as session:
                from sqlalchemy import select
                from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType
                result = await session.execute(
                    select(Honeytoken).where(
                        Honeytoken.type == HoneytokenType.FILE,
                        Honeytoken.status == HoneytokenStatus.ACTIVE,
                    )
                )
                for token in result.scalars().all():
                    meta = token.token_meta or {}
                    uid = meta.get("token_uid", "")
                    if uid and uid in labels:
                        await queries.mark_honeytoken_triggered(
                            session, token.id,
                            {"trigger_ip": src_ip, "dns_query": qname}
                        )
                        severity = AlertSeverity.CRITICAL
                        matched_token_id = token.id
                        payload["matched_token_id"] = token.id
                        break

        await submit_event(PendingEvent(
            honeypot_id=self._hp_id,
            source_ip=src_ip,
            source_port=src_port,
            event_type=event_type,
            payload=payload,
            severity=severity,
            honeytoken_id=matched_token_id,
        ))

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

    async def health_check(self, container_id: str, port: int) -> dict[str, Any]:
        """DNS is UDP — TCP probe doesn't work. Send a real DNS query and wait
        for any response."""
        transport = self._transports.get(container_id)
        if transport is None:
            return {"alive": False, "detail": "Transport not registered", "method": "internal"}
        if transport.is_closing():
            return {"alive": False, "detail": "Transport is closing", "method": "internal"}

        # Quick UDP roundtrip: any reply (even NXDOMAIN) means the server is up.
        try:
            import dnslib
        except ImportError:
            return {"alive": True, "detail": "Transport active (dnslib missing for probe)", "method": "internal"}

        class _Probe(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.received = asyncio.Event()

            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                self.received.set()

        loop = asyncio.get_event_loop()
        proto = _Probe()
        probe_transport = None
        try:
            probe_transport, _ = await loop.create_datagram_endpoint(
                lambda: proto, remote_addr=("127.0.0.1", port)
            )
            probe_transport.sendto(dnslib.DNSRecord.question("health.probe").pack())
            try:
                await asyncio.wait_for(proto.received.wait(), timeout=2.0)
                return {"alive": True, "detail": "DNS server answered probe", "method": "udp_dns"}
            except asyncio.TimeoutError:
                return {"alive": False, "detail": "DNS probe timed out", "method": "udp_dns"}
        except Exception as e:
            return {"alive": False, "detail": f"DNS probe error: {e}", "method": "udp_dns"}
        finally:
            if probe_transport is not None:
                probe_transport.close()

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["DNS honeypot is in-process — events are stored directly in the database."]
