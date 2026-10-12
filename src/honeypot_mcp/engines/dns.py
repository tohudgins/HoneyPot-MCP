"""DNS honeypot engine — logs all DNS queries for C2 callback detection.

Returns realistic answers for A / AAAA / MX / NS / TXT / SOA so that a
recon-style scanner sees believable data for arbitrary subdomains of any
zone (which is what a wildcard / catch-all real DNS server does), rather
than uniform NXDOMAIN that signals "honeypot or misconfigured zone" on
the first probe.

Beyond logging, each query is classified (`_classify_dns_query`) for the
recon/exfil shapes that make a DNS honeypot worth deploying:
* `dns_zone_transfer` (HIGH) — AXFR/IXFR full-zone dump attempts.
* `dns_version_probe` (MEDIUM) — CHAOS-class `version.bind` / `id.server`
  server fingerprinting.
* `dns_any_query` (MEDIUM) — ANY queries (amplification reflectors, recon).
* `dns_tunneling_suspected` (HIGH) — unusually long / high-entropy labels,
  the signature of base32/base64/hex-encoded data exfil over DNS.
A file-token canary hit still overrides these with CRITICAL.

Unknown types and parse failures still fall through to NXDOMAIN.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
from typing import Any

import dnslib

from honeypot_mcp import self_probe
from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import (
    ConnectionLimiter,
    UdpReplyLimiter,
    limited_handler,
    shutdown_server,
)
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# Classic DNS-over-UDP message limit (RFC 1035 §4.2.1). Queries are a few dozen
# bytes even with an EDNS OPT record; anything larger is not a query.
_MAX_QUERY_BYTES = 512
# A synthesized answer may be at most this many times the query's size. Real
# answers are necessarily somewhat larger than the question (an A record adds
# 16 bytes), so the strict "never larger" rule of SNMP/SIP would leave plain
# `dig` lookups unanswered; this keeps the factor small while staying
# believable. Answers are dropped from the end until the reply fits.
_MAX_REPLY_FACTOR = 2


def _is_plain_query(data: bytes) -> bool:
    """Cheap header gate, run before dnslib parses anything.

    Only a standard query with exactly one question is answered: QR=1 is a
    response (answering it lets two reflectors ping-pong forever), a non-zero
    opcode is NOTIFY/UPDATE/IQUERY, and qdcount != 1 is never sent by a
    resolver.
    """
    if len(data) < 12 or len(data) > _MAX_QUERY_BYTES:
        return False
    flags = data[2]
    qr = flags >> 7
    opcode = (flags >> 3) & 0x0F
    qdcount = int.from_bytes(data[4:6], "big")
    return qr == 0 and opcode == 0 and qdcount == 1


def _looks_like_tunneling(qname: str) -> bool:
    """Heuristic for DNS tunneling / exfiltration: encoded data chunked into
    labels produces unusually long, high-entropy labels (base32/base64/hex).
    Normal domain labels are short dictionary-ish words. Thresholds are
    conservative so ordinary FQDNs and the 32-char file-token label don't trip."""
    if len(qname) >= 100:
        return True
    # A label near the 63-char ceiling is an encoded data chunk, not a word.
    return any(len(label) >= 45 for label in qname.split("."))


def _classify_dns_query(qname: str, qtype: str, qclass: str) -> tuple[str, AlertSeverity]:
    """Beyond a plain lookup, recognise the recon/exfil query shapes that make
    a DNS honeypot worth deploying."""
    low = qname.lower()
    if qtype in ("AXFR", "IXFR"):
        # Full-zone dump attempt — a real misconfig leaks every record.
        return "dns_zone_transfer", AlertSeverity.HIGH
    if qclass == "CH" or low in ("version.bind", "version.server", "hostname.bind", "id.server"):
        # CHAOS-class server fingerprinting.
        return "dns_version_probe", AlertSeverity.MEDIUM
    if qtype == "ANY":
        # Amplification-DDoS reflectors and recon tools favour ANY.
        return "dns_any_query", AlertSeverity.MEDIUM
    if _looks_like_tunneling(qname):
        return "dns_tunneling_suspected", AlertSeverity.HIGH
    return "dns_query", AlertSeverity.LOW


def _parse_query(data: bytes) -> tuple[Any, str, str, str]:
    """(request, qname, qtype, qclass) for a plain single-question query, else
    (None, hex of the first bytes, "UNKNOWN", "IN"): recorded the way an unparseable packet always
    was, never parsed or answered."""
    if _is_plain_query(data):
        try:
            import dnslib

            request = dnslib.DNSRecord.parse(data)
            qclass = "IN"
            with contextlib.suppress(Exception):
                qclass = dnslib.CLASS[request.q.qclass]
            return request, str(request.q.qname).rstrip("."), dnslib.QTYPE[request.q.qtype], qclass
        except Exception:
            pass
    return None, data[:64].hex(), "UNKNOWN", "IN"


class _DNSProtocol(asyncio.DatagramProtocol):
    """UDP DNS server that logs every query and returns NXDOMAIN."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.DatagramTransport | None = None
        self._reply_limiter = UdpReplyLimiter()

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore[override]
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr
        request, qname, qtype, qclass = _parse_query(data)

        spawn(self._record(src_ip, src_port, qname, qtype, qclass), name="dns-record")

        # Return a believable response for common query types — uniform
        # NXDOMAIN against any A query is itself a fingerprint (real
        # nameservers answer A queries for most domains). Unknown types and
        # parse failures still get NXDOMAIN.
        if request is None or self._transport is None:
            return
        if not self._reply_limiter.allow(src_ip):
            return
        limit = len(data) * _MAX_REPLY_FACTOR
        try:
            import dnslib

            reply = _build_realistic_reply(request, qname, qtype)
            packed = reply.pack()
            while len(packed) > limit and reply.rr:
                reply.rr.pop()
                packed = reply.pack()
        except Exception:
            # On any synthesis error, fall back to NXDOMAIN.
            try:
                fallback = request.reply()
                fallback.header.rcode = dnslib.RCODE.NXDOMAIN
                packed = fallback.pack()
            except Exception:
                return
        if len(packed) > limit:
            return
        with contextlib.suppress(Exception):
            self._transport.sendto(packed, addr)

    async def _record(
        self, src_ip: str, src_port: int, qname: str, qtype: str, qclass: str = "IN"
    ) -> None:
        # Classify recon/exfil shape first (version probe, ANY, zone transfer,
        # tunneling). A canary-token match below overrides with CRITICAL.
        event_type, severity = _classify_dns_query(qname, qtype, qclass)
        payload: dict = {"qname": qname, "qtype": qtype, "qclass": qclass}
        matched_token_id: int | None = None

        # File honeytokens use a 32-char UUID hex as a subdomain label.
        # Match against `token_meta.token_uid` (what file_token.py actually stores)
        # rather than the brittle `token_value in qname` heuristic. Matching
        # goes through token_matchers' TTL-cached index rather than a fresh
        # DB query + full table scan on every packet — this is the ingest
        # hot path, and a DNS-tunneling burst is exactly the traffic that
        # would turn an uncached per-query lookup into a DB bottleneck.
        labels = [p for p in qname.split(".") if len(p) == 32]
        if labels:
            severity = AlertSeverity.HIGH
            event_type = "dns_canary_callback"
            from honeypot_mcp.token_matchers import match_file_uid

            token_id = await match_file_uid(labels)
            if token_id is not None:
                async with get_session() as session:
                    await queries.mark_honeytoken_triggered(
                        session, token_id, {"trigger_ip": src_ip, "dns_query": qname}
                    )
                severity = AlertSeverity.CRITICAL
                matched_token_id = token_id
                payload["matched_token_id"] = token_id

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


_MAX_TCP_QUERIES = 8  # per connection: a resolver reuses one for a few, a scanner for more
_TCP_READ_TIMEOUT = 8.0
_MAX_TCP_MESSAGE = 4096  # queries are tens of bytes; the 2-byte length allows 65,535
_BIND_VERSION = "9.18.12-0ubuntu0.22.04.3-Ubuntu"  # bind9 on Ubuntu 22.04, as the host's kernel
_SERVER_ID = "ns1"


async def _serve_tcp(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, recorder: _DNSProtocol
) -> None:
    """DNS over TCP (RFC 1035 §4.2.2: each message has a 2-byte length prefix).

    Zone transfers are TCP-only, so with UDP alone the `dns_zone_transfer` detection could only fire
    on a rare UDP attempt, a real transfer got "connection refused" and left no trace, and a
    nameserver with TCP/53 closed is itself a tell. Queries are answered as over UDP; AXFR/IXFR is
    recorded and REFUSED."""
    peer = writer.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = peer[0], peer[1]
    for _ in range(_MAX_TCP_QUERIES):
        try:
            header = await asyncio.wait_for(reader.readexactly(2), _TCP_READ_TIMEOUT)
            size = int.from_bytes(header, "big")
            if not 12 <= size <= _MAX_TCP_MESSAGE:
                return
            data = await asyncio.wait_for(reader.readexactly(size), _TCP_READ_TIMEOUT)
        except (asyncio.IncompleteReadError, TimeoutError, ConnectionError):
            return
        request, qname, qtype, qclass = _parse_query(data)
        await recorder._record(src_ip, src_port, qname, qtype, qclass)
        if request is None:
            return
        try:
            packed = _build_realistic_reply(request, qname, qtype).pack()
        except Exception:
            return
        writer.write(len(packed).to_bytes(2, "big") + packed)
        await writer.drain()


class DNSEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._transports: dict[str, asyncio.DatagramTransport] = {}
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

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
        recorder = _DNSProtocol(name, hp_id)

        async def _tcp(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await _serve_tcp(reader, writer, recorder)
            except Exception as e:
                log.debug("DNS TCP handler error: %s", e)
            finally:
                writer.close()

        try:
            server = await asyncio.start_server(
                limited_handler(_tcp, self._limiter), host="0.0.0.0", port=port
            )
        except OSError:
            transport.close()  # no half-started sensor: UDP without TCP is itself a tell
            raise
        cid = f"dns-{secrets.token_hex(8)}"
        self._transports[cid] = transport  # type: ignore[assignment]
        self._servers[cid] = server
        log.info("DNS honeypot '%s' listening on UDP and TCP port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        transport = self._transports.pop(container_id, None)
        if transport:
            transport.close()
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._transports, "type": "asyncio_udp_tcp_dns"}

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
            # Same reason as the TCP probe in `engines/base.py`: the server
            # logs this query as attacker traffic unless we claim it.
            self_probe.register(probe_transport.get_extra_info("sockname"))
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


class _HINFO(dnslib.RD):
    """HINFO rdata (RFC 1035 §3.3.2): dnslib ships no class for it. Two length-prefixed strings."""

    attrs = ("cpu", "os")

    def __init__(self, cpu: bytes, os: bytes) -> None:
        self.cpu, self.os = cpu, os

    def pack(self, buffer: Any) -> None:
        for field in (self.cpu, self.os):
            buffer.append(bytes([len(field)]) + field)


def _build_realistic_reply(request, qname: str, qtype: str):  # type: ignore[no-untyped-def]
    """Synthesize a believable DNS response for common query types.

    Returns a `dnslib.DNSRecord` ready to `.pack()`. Falls back to NXDOMAIN
    for types we don't model.
    """
    import dnslib

    reply = request.reply()
    qn = dnslib.DNSLabel(qname or "localhost")
    # A recursive resolver: not authoritative for what it answers, recursion available. dnslib
    # echoes the request's AD bit and defaults aa=1, so a plain `dig` saw `aa ra ad` together, which
    # no real server sends (AD means DNSSEC-validated, and nothing here validates anything).
    reply.header.aa = 0
    reply.header.ra = 1
    reply.header.ad = 0

    if qtype in ("AXFR", "IXFR"):
        # What a hardened server says. The attempt itself is the finding and is recorded.
        reply.header.rcode = dnslib.RCODE.REFUSED
        return reply

    if request.q.qclass == dnslib.CLASS.CH:
        # CHAOS class is server fingerprinting. A real BIND answers with its version string (the
        # TXT branch below used to answer these with an SPF record), and refuses anything else.
        name = qname.lower()
        if qtype == "TXT" and name in ("version.bind", "version.server"):
            text = _BIND_VERSION
        elif qtype == "TXT" and name in ("hostname.bind", "id.server"):
            text = _SERVER_ID
        else:
            reply.header.rcode = dnslib.RCODE.REFUSED
            return reply
        reply.add_answer(
            dnslib.RR(qn, dnslib.QTYPE.TXT, rclass=dnslib.CLASS.CH, rdata=dnslib.TXT(text), ttl=0)
        )
        return reply

    if qtype == "ANY":
        # RFC 8482: a minimal HINFO. NXDOMAIN here contradicted the A answer for the same name, and a
        # full ANY response is an amplification vector.
        reply.add_answer(dnslib.RR(qn, dnslib.QTYPE.HINFO, rdata=_HINFO(b"RFC8482", b""), ttl=3600))
        return reply
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
        # A plausible SPF record. (`ip4:0.0.0.0/0` passes the whole internet, which no real domain
        # publishes.)
        spf = "v=spf1 include:_spf.google.com ~all"
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
