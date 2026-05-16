"""DNS honeypot engine — logs all DNS queries for C2 callback detection.

Returns realistic answers for A / AAAA / MX / NS / TXT / SOA so that a
recon-style scanner sees believable data for arbitrary subdomains of any
zone (which is what a wildcard / catch-all real DNS server does), rather
than uniform NXDOMAIN that signals "honeypot or misconfigured zone" on
the first probe.

Unknown types and parse failures still fall through to NXDOMAIN.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
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
        request = None
        try:
            import dnslib

            request = dnslib.DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")
            qtype = dnslib.QTYPE[request.q.qtype]
        except Exception:
            qname = data[:64].hex()
            qtype = "UNKNOWN"

        asyncio.create_task(self._record(src_ip, src_port, qname, qtype))

        # Return a believable response for common query types — uniform
        # NXDOMAIN against any A query is itself a fingerprint (real
        # nameservers answer A queries for most domains). Unknown types and
        # parse failures still get NXDOMAIN.
        if request is None or self._transport is None:
            return
        try:
            import dnslib

            reply = _build_realistic_reply(request, qname, qtype)
            self._transport.sendto(reply.pack(), addr)
        except Exception:
            # On any synthesis error, fall back to NXDOMAIN.
            try:
                fallback = request.reply()
                fallback.header.rcode = dnslib.RCODE.NXDOMAIN
                self._transport.sendto(fallback.pack(), addr)
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
                            session, token.id, {"trigger_ip": src_ip, "dns_query": qname}
                        )
                        severity = AlertSeverity.CRITICAL
                        matched_token_id = token.id
                        payload["matched_token_id"] = token.id
                        break

        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
                honeytoken_id=matched_token_id,
            )
        )

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
            return {
                "alive": True,
                "detail": "Transport active (dnslib missing for probe)",
                "method": "internal",
            }

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
            except TimeoutError:
                return {"alive": False, "detail": "DNS probe timed out", "method": "udp_dns"}
        except Exception as e:
            return {"alive": False, "detail": f"DNS probe error: {e}", "method": "udp_dns"}
        finally:
            if probe_transport is not None:
                probe_transport.close()

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["DNS honeypot is in-process — events are stored directly in the database."]


# ── Response synthesis ──────────────────────────────────────────────────


def _deterministic_ip(qname: str) -> str:
    """Derive a deterministic public-looking IPv4 from the query name so
    repeat queries for the same name return the same answer (real DNS
    caches expect this). Uses SHA256 of the qname mapped into a /16 that
    isn't a known reserved range.

    Avoids 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
    192.168.0.0/16, 0.0.0.0, 255.255.255.255 — any of those is itself a
    fingerprint of a fake answer.
    """
    digest = hashlib.sha256(qname.encode("utf-8")).digest()
    # Pick a public-ish first octet from a curated set known to be globally
    # routable (and not assigned to a major CDN whose presence would look odd).
    first_octet_pool = (23, 51, 76, 91, 104, 138, 162, 178, 195, 203)
    a = first_octet_pool[digest[0] % len(first_octet_pool)]
    b = digest[1]
    c = digest[2]
    d = (digest[3] % 254) + 1  # avoid .0 and .255
    return f"{a}.{b}.{c}.{d}"


def _deterministic_ipv6(qname: str) -> str:
    digest = hashlib.sha256(qname.encode("utf-8")).digest()
    groups = [int.from_bytes(digest[i : i + 2], "big") for i in range(0, 16, 2)]
    # 2001:db8::/32 is documentation; use a more believable 2a00::/16 range
    # that maps to public IPv6 space. Override the first group so it doesn't
    # look like documentation/example space.
    groups[0] = 0x2A00 | (groups[0] & 0x00FF)
    return ":".join(f"{g:x}" for g in groups)


def _build_realistic_reply(request, qname: str, qtype: str):  # type: ignore[no-untyped-def]
    """Synthesize a believable DNS response for common query types.

    Returns a `dnslib.DNSRecord` ready to `.pack()`. Falls back to NXDOMAIN
    for types we don't model.
    """
    import dnslib

    reply = request.reply()
    qn = dnslib.DNSLabel(qname or "localhost")

    if qtype == "A":
        ip = _deterministic_ip(qname)
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.A, rdata=dnslib.A(ip), ttl=300))
        return reply

    if qtype == "AAAA":
        ip6 = _deterministic_ipv6(qname)
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.AAAA, rdata=dnslib.AAAA(ip6), ttl=300))
        return reply

    if qtype == "MX":
        # Two MX answers — primary at 10, backup at 20. Real mail-bearing
        # domains almost always have at least one MX; absence is a tell.
        domain = qname or "example.com"
        primary = f"mx1.{domain}"
        backup = f"mx2.{domain}"
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.MX, rdata=dnslib.MX(primary, 10), ttl=600))
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.MX, rdata=dnslib.MX(backup, 20), ttl=600))
        return reply

    if qtype == "NS":
        domain = qname or "example.com"
        for i in range(1, 3):
            reply.add_answer(
                dnslib.RR(
                    qn,
                    dnslib.QTYPE.NS,
                    rdata=dnslib.NS(f"ns{i}.{domain}"),
                    ttl=3600,
                )
            )
        return reply

    if qtype == "TXT":
        # Plausible SPF record — common on most real mail-bearing domains.
        spf = '"v=spf1 ip4:0.0.0.0/0 ~all"'
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.TXT, rdata=dnslib.TXT(spf), ttl=300))
        return reply

    if qtype == "SOA":
        domain = qname or "example.com"
        soa = dnslib.SOA(
            mname=f"ns1.{domain}",
            rname=f"hostmaster.{domain}",
            times=(2024010101, 7200, 3600, 1209600, 3600),
        )
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.SOA, rdata=soa, ttl=3600))
        return reply

    # CNAME / PTR / SRV / etc. — fall through to NXDOMAIN. Real servers
    # also legitimately NXDOMAIN for SRV / PTR on most names, so this is
    # not as obvious a tell as A-NXDOMAIN.
    reply.header.rcode = dnslib.RCODE.NXDOMAIN
    return reply
