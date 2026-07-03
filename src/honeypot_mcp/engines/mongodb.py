"""MongoDB honeypot engine — wire-protocol capture of unauth attacks.

Exposed unauthenticated MongoDB (27017) drove one of the largest data-ransom
waves on record: scanners connect, `listDatabases`, then drop every database
and leave a ransom document telling the victim to pay for "recovery". The
high-value signal is the command sequence and the ransom note itself.

This engine speaks enough of the MongoDB wire protocol to look like an open
instance: it answers `isMaster`/`hello`/`ping`/`buildInfo` believably so the
tool proceeds, decodes the BSON command documents the attacker sends, and
captures them — flagging destructive/ransom behaviour (`dropDatabase`,
`insert` of a ransom note) as high severity.

It is NOT a real datastore — no data is persisted and nothing is actually
dropped. We reply `ok:1` to keep the attacker engaged so their full intent
(including the ransom note text and payment address) lands in the alert.

Wire reference:
* OP_MSG (2013) and legacy OP_QUERY (2004)
  https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import struct
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

_OP_REPLY = 1
_OP_QUERY = 2004
_OP_MSG = 2013

_DESTRUCTIVE = {"dropdatabase", "drop", "delete"}
_RANSOM_HINTS = ("bitcoin", "btc", "recover", "ransom", "payment", "wallet", "email us", "restore")


# ── Minimal BSON ────────────────────────────────────────────────────────────


def _bson_encode(doc: dict[str, Any]) -> bytes:
    """Encode a dict as a BSON document. Supports the subset the honeypot
    replies use: str, bool, int, float, list[dict], dict."""
    out = b""
    for key, value in doc.items():
        name = key.encode() + b"\x00"
        if isinstance(value, bool):
            out += b"\x08" + name + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            out += b"\x12" + name + struct.pack("<q", value)
        elif isinstance(value, float):
            out += b"\x01" + name + struct.pack("<d", value)
        elif isinstance(value, str):
            sb = value.encode() + b"\x00"
            out += b"\x02" + name + struct.pack("<i", len(sb)) + sb
        elif isinstance(value, dict):
            out += b"\x03" + name + _bson_encode(value)
        elif isinstance(value, list):
            arr = {str(i): v for i, v in enumerate(value)}
            out += b"\x04" + name + _bson_encode(arr)
    body = out + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _bson_first_key(data: bytes) -> str:
    """Return the first element name of a BSON document — for command docs this
    is the command name (e.g. 'isMaster', 'listDatabases', 'insert')."""
    try:
        if len(data) < 5:
            return ""
        pos = 4  # skip int32 length
        _type = data[pos]
        pos += 1
        end = data.find(b"\x00", pos)
        return data[pos:end].decode("utf-8", errors="replace") if end != -1 else ""
    except Exception:
        return ""


def _bson_collect_strings(data: bytes, limit: int = 40) -> list[str]:
    """Best-effort recursive pull of string values from a BSON doc — captures
    ransom-note text, target db names, filter values. Bounded, never raises."""
    found: list[str] = []

    def _walk(buf: bytes) -> None:
        if len(buf) < 5 or len(found) >= limit:
            return
        pos = 4
        while pos < len(buf) - 1 and len(found) < limit:
            etype = buf[pos]
            pos += 1
            name_end = buf.find(b"\x00", pos)
            if name_end == -1:
                return
            pos = name_end + 1
            if etype == 0x02:  # string
                if pos + 4 > len(buf):
                    return
                slen = struct.unpack("<i", buf[pos : pos + 4])[0]
                pos += 4
                val = buf[pos : pos + max(0, slen - 1)]
                found.append(val.decode("utf-8", errors="replace"))
                pos += slen
            elif etype in (0x03, 0x04):  # embedded doc / array
                if pos + 4 > len(buf):
                    return
                dlen = struct.unpack("<i", buf[pos : pos + 4])[0]
                _walk(buf[pos : pos + dlen])
                pos += dlen
            elif etype in (0x01, 0x12):  # double / int64
                pos += 8
            elif etype == 0x10:  # int32
                pos += 4
            elif etype == 0x08:  # bool
                pos += 1
            elif etype == 0x00:
                return
            else:
                return  # unknown type — stop rather than misparse

    import contextlib

    with contextlib.suppress(Exception):
        _walk(data)
    return found


def _extract_command(payload: bytes, opcode: int) -> tuple[str, bytes]:
    """Return (command_name, command_bson) from an OP_MSG or OP_QUERY body."""
    if opcode == _OP_MSG:
        # uint32 flagBits, then sections. Kind 0 = a single body document.
        if len(payload) < 5:
            return "", b""
        pos = 4
        kind = payload[pos]
        pos += 1
        if kind == 0:
            doc = payload[pos:]
            return _bson_first_key(doc), doc
        return "", b""
    if opcode == _OP_QUERY:
        # int32 flags, cstring fullCollectionName, int32 skip, int32 return, doc
        try:
            pos = 4
            coll_end = payload.find(b"\x00", pos)
            pos = coll_end + 1 + 8  # skip collection + skip/return int32s
            doc = payload[pos:]
            return _bson_first_key(doc), doc
        except Exception:
            return "", b""
    return "", b""


# ── Reply builders ──────────────────────────────────────────────────────────


def _ismaster_reply() -> dict[str, Any]:
    return {
        "ismaster": True,
        "maxBsonObjectSize": 16777216,
        "maxMessageSizeBytes": 48000000,
        "maxWriteBatchSize": 100000,
        "localTime": 0,
        "maxWireVersion": 8,
        "minWireVersion": 0,
        "readOnly": False,
        "ok": 1.0,
    }


def _build_reply(command: str, request_id: int, response_to: int, opcode: int) -> bytes:
    cmd = command.lower()
    if cmd in ("ismaster", "hello"):
        body = _ismaster_reply()
    elif cmd == "buildinfo":
        body = {"version": "5.0.14", "gitVersion": "1b3b0073a0b436a8a502b612e", "ok": 1.0}
    elif cmd == "listdatabases":
        body = {
            "databases": [
                {"name": "admin", "sizeOnDisk": 40960.0, "empty": False},
                {"name": "config", "sizeOnDisk": 61440.0, "empty": False},
                {"name": "local", "sizeOnDisk": 73728.0, "empty": False},
                {"name": "users", "sizeOnDisk": 2097152.0, "empty": False},
            ],
            "totalSize": 2273280.0,
            "ok": 1.0,
        }
    else:
        body = {"ok": 1.0}

    doc = _bson_encode(body)
    if opcode == _OP_MSG:
        payload = struct.pack("<I", 0) + b"\x00" + doc  # flagBits + section kind 0
        return _frame(payload, request_id, response_to, _OP_MSG)
    # OP_REPLY for legacy OP_QUERY.
    reply = struct.pack("<iqii", 0, 0, 0, 1) + doc  # flags, cursorID, from, count
    return _frame(reply, request_id, response_to, _OP_REPLY)


def _frame(payload: bytes, request_id: int, response_to: int, opcode: int) -> bytes:
    length = 16 + len(payload)
    return struct.pack("<iiii", length, request_id, response_to, opcode) + payload


class _MongoProtocol(asyncio.Protocol):
    def __init__(self, honeypot_id: int | None) -> None:
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        self._reqcounter = 0

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("mongodb_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= 16:
            length = struct.unpack("<i", self._buf[:4])[0]
            if length < 16 or length > 48_000_000:
                self._buf = b""
                return
            if len(self._buf) < length:
                return
            msg = self._buf[:length]
            self._buf = self._buf[length:]
            self._handle_message(msg)

    def _handle_message(self, msg: bytes) -> None:
        t = self._transport
        if t is None:
            return
        request_id, _response_to, opcode = struct.unpack("<iii", msg[4:16])
        command, doc = _extract_command(msg[16:], opcode)
        if command:
            cmd_lower = command.lower()
            strings = _bson_collect_strings(doc)
            severity = AlertSeverity.MEDIUM
            event_type = "mongodb_command"
            joined = " ".join(strings).lower()
            if cmd_lower in _DESTRUCTIVE:
                severity = AlertSeverity.HIGH
                event_type = "mongodb_destructive"
            if any(h in joined for h in _RANSOM_HINTS) or any(
                h in cmd_lower for h in _RANSOM_HINTS
            ):
                severity = AlertSeverity.CRITICAL
                event_type = "mongodb_ransom_note"
            asyncio.create_task(
                self._record(
                    event_type,
                    severity,
                    {"command": command, "strings": strings[:20]},
                )
            )

        self._reqcounter += 1
        with __import__("contextlib").suppress(Exception):
            t.write(_build_reply(command, self._reqcounter, request_id, opcode))

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class MongoDBEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(lambda: _MongoProtocol(hp_id), host="0.0.0.0", port=port)
        cid = f"mongodb-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("MongoDB honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_mongodb"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["MongoDB honeypot is in-process — events are stored directly in the database."]
