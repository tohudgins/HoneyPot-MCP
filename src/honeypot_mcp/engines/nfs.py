"""NFS honeypot engine — tcp/2049, exported filesystem enumeration.

An NFS export reachable from the internet hands over files to anyone who can
reach the port. The classic misconfiguration is an export shared to `*` with
`no_root_squash`, which means a remote client can not only read the share but
write to it as root — so an exposed NFS server is both a data breach and,
frequently, a path to code execution via a planted cron job or SSH key.

The reconnaissance is a single command. `showmount -e <host>` calls the MOUNT
protocol's EXPORT procedure and returns every share and who it is exported to.
That one exchange tells an attacker whether the host is worth attacking, so it
is recorded as enumeration with the exact export list disclosed — including
which ones are shared to `*`, since that is the detail that decides their next
move.

The export list is built to look like a host worth mounting, and to be honest
about severity: an actual MNT call for a share is treated as an attempted mount
rather than a probe, because the next packet after a successful mount is a
file read.

Implemented: ONC RPC over TCP with record marking, enough XDR to decode a call
and encode a reply, and the procedures a scanner actually uses — portmapper
NULL/GETPORT/DUMP, MOUNT NULL/MNT/EXPORT/DUMP, and NFS NULL. Not implemented:
NFS file operations. Nothing is served and no filesystem exists.

Wire format: RFC 5531 (ONC RPC), RFC 1813 appendix I (MOUNT v3), RFC 1833
(portmapper / rpcbind).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines._bounds import write_backlogged
from honeypot_mcp.engines._tasks import spawn
from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.engines.conn_limit import ConnectionLimiter, limited_factory, shutdown_server
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# RPC program numbers.
PROG_PORTMAP = 100000
PROG_NFS = 100003
PROG_MOUNT = 100005

_PROGRAM_NAMES = {PROG_PORTMAP: "portmapper", PROG_NFS: "nfs", PROG_MOUNT: "mountd"}

# MOUNT procedures (RFC 1813).
MOUNT_NULL, MOUNT_MNT, MOUNT_DUMP, MOUNT_UMNT, MOUNT_UMNTALL, MOUNT_EXPORT = 0, 1, 2, 3, 4, 5
# Portmapper procedures (RFC 1833).
PMAP_NULL, PMAP_SET, PMAP_UNSET, PMAP_GETPORT, PMAP_DUMP = 0, 1, 2, 3, 4

MSG_CALL, MSG_REPLY = 0, 1
REPLY_ACCEPTED = 0
ACCEPT_SUCCESS, ACCEPT_PROG_UNAVAIL, ACCEPT_PROG_MISMATCH, ACCEPT_PROC_UNAVAIL = 0, 1, 2, 3
_PORTMAP_VERSIONS = (2, 3, 4)

_NFS_PORT = 2049
_MAX_RECORD = 256 * 1024
_MAX_RECORDS_PER_CONN = 256
_MAX_INVALID_PROBES = 5
_MAX_WRITE_BUFFER = 256 * 1024

# The fiction. A host with a root export shared to the world is exactly what
# scanners hunt for, and `*` is the detail that makes it worth their time.
_EXPORTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/srv/backups", ("*",)),
    ("/var/nfs/shared", ("*",)),
    ("/home", ("10.0.0.0/8",)),
    ("/srv/vmware", ("192.168.1.0/24",)),
)


# ── Minimal XDR ─────────────────────────────────────────────────────────────


def xdr_string(value: str | bytes) -> bytes:
    """XDR opaque/string: length, bytes, then padding to a 4-byte boundary."""
    raw = value.encode() if isinstance(value, str) else value
    padding = (4 - len(raw) % 4) % 4
    return struct.pack(">I", len(raw)) + raw + b"\x00" * padding


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def parse_rpc_call(body: bytes) -> dict[str, Any] | None:
    """Decode an RPC call header. None if it is not a well-formed v2 call."""
    try:
        if len(body) < 24:
            return None
        xid, msg_type, rpc_version, program, version, procedure = struct.unpack(
            ">IIIIII", body[:24]
        )
        if msg_type != MSG_CALL or rpc_version != 2:
            return None
        pos = 24
        # Skip credential and verifier: flavour, length, then that many bytes.
        for _ in range(2):
            if pos + 8 > len(body):
                return None
            _flavour, length = struct.unpack(">II", body[pos : pos + 8])
            pos += 8 + length + ((4 - length % 4) % 4)
        return {
            "xid": xid,
            "program": program,
            "version": version,
            "procedure": procedure,
            "program_name": _PROGRAM_NAMES.get(program, str(program)),
            "args": body[pos:],
        }
    except (struct.error, IndexError):
        return None


def build_reply(xid: int, results: bytes = b"", accept_stat: int = ACCEPT_SUCCESS) -> bytes:
    """An accepted RPC reply with a null verifier."""
    return (
        _u32(xid)
        + _u32(MSG_REPLY)
        + _u32(REPLY_ACCEPTED)
        + _u32(0)  # verifier flavour: AUTH_NULL
        + _u32(0)  # verifier length
        + _u32(accept_stat)
        + results
    )


def build_export_list() -> bytes:
    """MOUNT EXPORT result: a linked list of (dirpath, groups).

    Each node is a `value_follows` boolean then the payload, terminated by a
    zero. Getting the terminator wrong makes `showmount` hang, which is a
    louder tell than not answering at all.
    """
    out = b""
    for path, groups in _EXPORTS:
        out += _u32(1) + xdr_string(path)
        for group in groups:
            out += _u32(1) + xdr_string(group)
        out += _u32(0)  # end of this export's group list
    out += _u32(0)  # end of the export list
    return out


def build_mount_reply(accepted: bool) -> bytes:
    """MOUNT MNT result: status, and on success a file handle plus auth list."""
    if not accepted:
        return _u32(13)  # MNT3ERR_ACCES
    return _u32(0) + xdr_string(secrets.token_bytes(32)) + _u32(1) + _u32(1)  # AUTH_UNIX


def framed(payload: bytes) -> bytes:
    """RPC record marking: a 4-byte header with the last-fragment bit set."""
    return struct.pack(">I", 0x80000000 | len(payload)) + payload


class _NFSProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, hp_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = hp_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = bytearray()
        self._records = 0
        self._invalid = 0
        self._pending: list[tuple[str, AlertSeverity, dict]] = []

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        spawn(self._record("nfs_connection", AlertSeverity.LOW, {}), name="nfs-event")

    def _send(self, payload: bytes) -> None:
        if self._transport is not None and not self._transport.is_closing():
            self._transport.write(framed(payload))

    def _close(self) -> None:
        self._buf.clear()
        if self._transport is not None and not self._transport.is_closing():
            self._transport.close()

    def _emit(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        self._pending.append((event_type, severity, payload))

    async def _flush_events(self, events: list[tuple[str, AlertSeverity, dict]]) -> None:
        for event_type, severity, payload in events:
            await self._record(event_type, severity, payload)

    def data_received(self, data: bytes) -> None:
        t = self._transport
        if t is None or t.is_closing():
            return
        self._buf += data
        buf = self._buf
        pos = 0
        try:
            # Records are handled inline — one background task per *batch* of
            # events, never one per record — and the per-connection record and
            # invalid-probe counts bound how much work a single peer can queue.
            while len(buf) - pos >= 4 and not t.is_closing():
                if write_backlogged(t, _MAX_WRITE_BUFFER):
                    self._close()  # peer is not reading its replies
                    break
                (marker,) = struct.unpack_from(">I", buf, pos)
                length = marker & 0x7FFFFFFF
                if length > _MAX_RECORD:
                    self._close()
                    break
                if len(buf) - pos < 4 + length:
                    break
                record = bytes(buf[pos + 4 : pos + 4 + length])
                pos += 4 + length
                self._records += 1
                if self._records > _MAX_RECORDS_PER_CONN:
                    self._close()
                    break
                if length == 0 or parse_rpc_call(record) is None:
                    self._invalid += 1
                    if self._invalid > _MAX_INVALID_PROBES:
                        self._close()
                        break
                self._dispatch(record)
        except Exception:
            log.exception("nfs protocol error")
            self._close()
        del buf[:pos]
        if self._pending:
            events, self._pending = self._pending, []
            spawn(self._flush_events(events), name="nfs-event")

    def _local_ip(self) -> str:
        """The address the client reached us on, for universal addresses (`h1.h2.h3.h4.p1.p2`)."""
        name = self._transport.get_extra_info("sockname") if self._transport else None
        host = name[0] if name else "0.0.0.0"
        return host if host.count(".") == 3 else "0.0.0.0"

    def _universal_address(self, port: int) -> str:
        return f"{self._local_ip()}.{port >> 8}.{port & 0xFF}"

    def _dispatch(self, record: bytes) -> None:
        call = parse_rpc_call(record)
        if call is None:
            self._emit(
                "nfs_invalid_probe",
                AlertSeverity.LOW,
                {"bytes": len(record), "head_hex": record[:32].hex()},
            )
            return

        program, procedure, xid = call["program"], call["procedure"], call["xid"]

        if program == PROG_MOUNT:
            if procedure == MOUNT_EXPORT:
                # `showmount -e`. One call, and the attacker knows everything.
                world_readable = [p for p, groups in _EXPORTS if "*" in groups]
                self._send(build_reply(xid, build_export_list()))
                self._emit(
                    "nfs_export_enumeration",
                    AlertSeverity.HIGH,
                    {
                        "exports_disclosed": [p for p, _g in _EXPORTS],
                        "world_readable": world_readable,
                        "note": "showmount -e equivalent — full share list disclosed",
                    },
                )
                return
            if procedure == MOUNT_MNT:
                path = _read_xdr_string(call["args"])
                exported_to_world = any(p == path and "*" in g for p, g in _EXPORTS)
                self._send(build_reply(xid, build_mount_reply(exported_to_world)))
                self._emit(
                    "nfs_mount_attempt",
                    AlertSeverity.CRITICAL if exported_to_world else AlertSeverity.HIGH,
                    {
                        "path": path[:200],
                        "granted": exported_to_world,
                        "note": (
                            "mounted a world-exported share — the next call reads files"
                            if exported_to_world
                            else "attempted mount of a restricted share"
                        ),
                    },
                )
                return
            if procedure in (MOUNT_NULL, MOUNT_DUMP):
                self._send(build_reply(xid, b"" if procedure == MOUNT_NULL else _u32(0)))
                self._emit(
                    "nfs_mount_probe",
                    AlertSeverity.MEDIUM,
                    {"procedure": "NULL" if procedure == MOUNT_NULL else "DUMP"},
                )
                return
            self._send(build_reply(xid, b"", ACCEPT_PROC_UNAVAIL))
            return

        if program == PROG_PORTMAP:
            version = call["version"]
            if version not in _PORTMAP_VERSIONS:
                # rpcbind speaks v2, v3 and v4. Anything else gets the mismatch a real one sends,
                # with the supported range, which is how a client learns to fall back.
                self._send(
                    build_reply(
                        xid,
                        _u32(min(_PORTMAP_VERSIONS)) + _u32(max(_PORTMAP_VERSIONS)),
                        ACCEPT_PROG_MISMATCH,
                    )
                )
                return
            # v2 asks for a port (GETPORT, procedure 3) and lists with ints (DUMP, 4). v3 and v4 ask
            # for a universal address string (GETADDR, procedure 3) and list `rpcb` entries. nmap's
            # RPC library and libtirpc (Linux `showmount`) ask for v3/v4 first, and a v2-shaped
            # answer to those is unparseable: `rpcinfo` scripts failed with "data string too short".
            if procedure == PMAP_GETPORT:
                # Always point at 2049: this honeypot is one port, and a portmapper that advertises
                # services on ports nothing is listening on is trivially detectable.
                if version == 2:
                    results = _u32(_NFS_PORT)
                else:
                    results = xdr_string(self._universal_address(_NFS_PORT))
                self._send(build_reply(xid, results))
                self._emit(
                    "nfs_portmap_query",
                    AlertSeverity.MEDIUM,
                    {"requested_program": _decode_getport(call["args"])},
                )
                return
            if procedure == PMAP_DUMP:
                dump = _build_portmap_dump() if version == 2 else _build_rpcb_dump(self._local_ip())
                self._send(build_reply(xid, dump))
                self._emit(
                    "nfs_portmap_dump",
                    AlertSeverity.MEDIUM,
                    {"note": "rpcinfo -p equivalent — RPC service inventory disclosed"},
                )
                return
            self._send(build_reply(xid, b""))
            self._emit("nfs_portmap_probe", AlertSeverity.LOW, {"procedure": procedure})
            return

        if program == PROG_NFS:
            self._send(build_reply(xid, _u32(0)))
            self._emit(
                "nfs_request",
                AlertSeverity.MEDIUM,
                {"procedure": procedure, "version": call["version"]},
            )
            return

        self._send(build_reply(xid, b"", ACCEPT_PROG_UNAVAIL))
        self._emit(
            "nfs_unknown_program",
            AlertSeverity.LOW,
            {"program": program, "procedure": procedure},
        )

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        self._buf.clear()


def _read_xdr_string(data: bytes) -> str:
    try:
        (length,) = struct.unpack(">I", data[:4])
        return data[4 : 4 + min(length, 2048)].decode("utf-8", errors="replace")
    except (struct.error, IndexError):
        return ""


def _decode_getport(args: bytes) -> str:
    try:
        program, version, _protocol, _port = struct.unpack(">IIII", args[:16])
        return f"{_PROGRAM_NAMES.get(program, program)} v{version}"
    except struct.error:
        return "unknown"


def _build_portmap_dump() -> bytes:
    """`rpcinfo -p` output: the RPC services this host claims to run."""
    entries = (
        (PROG_PORTMAP, 2, 6, 111),
        (PROG_PORTMAP, 3, 6, 111),
        (PROG_PORTMAP, 4, 6, 111),
        (PROG_NFS, 3, 6, _NFS_PORT),
        (PROG_NFS, 4, 6, _NFS_PORT),
        (PROG_MOUNT, 3, 6, _NFS_PORT),
    )
    out = b""
    for program, version, protocol, port in entries:
        out += _u32(1) + _u32(program) + _u32(version) + _u32(protocol) + _u32(port)
    return out + _u32(0)


def _build_rpcb_dump(ip: str) -> bytes:
    """Portmapper v3/v4 DUMP: a list of `rpcb` entries (program, version, netid, universal address,
    owner). The v2 list is ints; this one is strings, which is what nmap's RPC library parses."""

    def uaddr(port: int) -> str:
        return f"{ip}.{port >> 8}.{port & 0xFF}"

    entries = (
        *((PROG_PORTMAP, v, uaddr(111)) for v in _PORTMAP_VERSIONS),
        (PROG_NFS, 3, uaddr(_NFS_PORT)),
        (PROG_NFS, 4, uaddr(_NFS_PORT)),
        (PROG_MOUNT, 3, uaddr(_NFS_PORT)),
    )
    out = b""
    for program, version, addr in entries:
        out += _u32(1) + _u32(program) + _u32(version) + xdr_string("tcp") + xdr_string(addr)
        out += xdr_string("superuser")
    return out + _u32(0)


class NFSEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._limiter = ConnectionLimiter(get_settings().max_connections_per_ip)

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            limited_factory(lambda: _NFSProtocol(name, hp_id), self._limiter),
            host="0.0.0.0",
            port=port,
        )
        cid = f"nfs-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("NFS honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            await shutdown_server(server, self._limiter)

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_nfs"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["NFS honeypot is in-process — events are stored directly in the database."]
