"""Regression tests for defects an independent review of the audit remediation
found — each one reproduced against the code before it was fixed, and each test
below fails if its fix is reverted."""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import os
import socket
import time
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match, token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    token_matchers.invalidate_cache()
    await init_db()
    yield
    await asyncio.sleep(0.1)
    credential_match.invalidate_cache()
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _register(name: str, type_name: str) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        session.add(Honeypot(name=name, type=HoneypotType(type_name), port=port))
        await session.flush()
    return port


# ── Redis: a pipelined flood must not hold the shared event loop ────────────


async def test_redis_command_flood_does_not_stall_the_event_loop():
    from honeypot_mcp.engines.redis import RedisEngine

    port = await _register("redis-flood", "redis")
    engine = RedisEngine()
    cid = await engine.start("redis-flood", port, {})
    stalls: list[float] = []

    async def heartbeat() -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(0.01)
            now = time.monotonic()
            stalls.append(now - last)
            last = now

    hb = asyncio.create_task(heartbeat())
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"A\r\n" * 340_000)  # ~1 MiB of one-token commands
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        await asyncio.sleep(1.0)
        # It took ~20 s before the per-read / per-connection command cap.
        assert max(stalls) < 1.0, f"event loop stalled for {max(stalls):.2f}s"
        writer.close()
    finally:
        hb.cancel()
        await engine.stop(cid)


# ── stop() must not hang on a connected idle client ─────────────────────────

_STOP_CASES = [
    ("redis", "RedisEngine", "redis"),
    ("mongodb", "MongoDBEngine", "mongodb"),
    ("postgresql", "PostgreSQLEngine", "postgresql"),
    ("nfs", "NFSEngine", "nfs"),
    ("mssql", "MSSQLEngine", "mssql"),
    ("mysql", "MySQLEngine", "mysql"),
    ("ldap", "LDAPEngine", "ldap"),
    ("memcached", "MemcachedEngine", "memcached"),
    ("vnc", "VNCEngine", "vnc"),
    ("smb", "SMBEngine", "smb"),
]


@pytest.mark.parametrize("module,cls,type_name", _STOP_CASES)
async def test_stop_returns_promptly_with_an_idle_client_attached(module, cls, type_name):
    engine = getattr(importlib.import_module(f"honeypot_mcp.engines.{module}"), cls)()
    port = await _register(f"{module}-stop", type_name)
    cid = await engine.start(f"{module}-stop", port, {})
    _reader, writer = await asyncio.open_connection("127.0.0.1", port)
    await asyncio.sleep(0.1)
    try:
        # On Python >= 3.12.1 an unbounded wait_closed() blocks on the live client.
        await asyncio.wait_for(engine.stop(cid), timeout=3.0)
    finally:
        writer.close()


# ── SMTP: a peer that never reads must be dropped, not buffered for 15 min ──


async def test_smtp_drops_a_peer_that_pipelines_commands_but_never_reads():
    from honeypot_mcp.engines.smtp import SMTPEngine

    port = await _register("smtp-noread", "smtp")
    engine = SMTPEngine()
    cid = await engine.start("smtp-noread", port, {"smtp_hostname": "mail.test.local"})
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
    try:
        sock.connect(("127.0.0.1", port))
        sock.setblocking(False)
        dropped = False
        for _ in range(300):
            try:
                sock.send(b"EHLO x\r\n" * 400)
            except BlockingIOError:
                pass
            except (BrokenPipeError, ConnectionResetError):
                dropped = True
                break
            await asyncio.sleep(0.01)
        assert dropped, "the server kept queueing replies for a peer that never reads"
        buffered = [t.get_write_buffer_size() for t in engine._limiter._transports]
        assert all(size < 2 * 1024 * 1024 for size in buffered)
    finally:
        sock.close()
        await engine.stop(cid)


# ── Honeytoken matching must see the payload before the clamp drops keys ────


async def test_planted_credential_inside_an_oversized_form_still_trips_the_token():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import (
        AlertSeverity,
        Honeytoken,
        HoneytokenStatus,
        HoneytokenType,
    )

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType.CREDENTIAL,
            label="oversized-form",
            token_value="cred:oversized",
            status=HoneytokenStatus.ACTIVE,
            token_meta={
                "service": "http",
                "credentials": [{"username": "svc-backup", "password": "Zx9!kLm2#qq"}],
            },
        )
        session.add(token)
        await session.flush()
        token_id = token.id

    # 62 padded fields push post_data far over the per-event budget, which makes
    # the clamp drop the whole key — credentials and all.
    post_data = {f"f{i}": "x" * 4000 for i in range(62)}
    post_data.update({"username": "svc-backup", "password": "Zx9!kLm2#qq"})
    event = PendingEvent(
        honeypot_id=None,
        source_ip="203.0.113.9",
        event_type="http_login_attempt",
        payload={"post_data": post_data, "path": "/login"},
        severity=AlertSeverity.MEDIUM,
    )
    await event_buffer.submit_event(event)

    assert event.honeytoken_id == token_id
    assert event.severity is AlertSeverity.CRITICAL
    assert event.event_type.startswith("honeytoken_triggered_credential_via_")
    assert event.payload.get("payload_truncated") is True  # …and it is still clamped


async def test_form_summary_keeps_credential_fields_behind_any_amount_of_junk():
    from honeypot_mcp.engines.http import _Scan, _summarise_form

    form = {f"junk{i}": "y" * 4000 for i in range(200)}
    form["Username"] = "root"
    form["password"] = "hunter2"
    out, overflow = _summarise_form(form, _Scan())
    assert overflow is True
    assert out["Username"] == "root" and out["password"] == "hunter2"
    assert sum(len(v) for v in out.values() if isinstance(v, str)) < 40_000


# ── Canary: random ids must not starve the global ceiling real hits need ────


async def test_flood_of_unknown_canary_ids_does_not_suppress_a_real_trigger(monkeypatch, tmp_path):
    from urllib.parse import urlparse

    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp import canary
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    monkeypatch.chdir(tmp_path)
    canary.invalidate_token_index()
    canary._rate_state.clear()
    canary._global_hits.clear()
    monkeypatch.setattr(canary, "_GLOBAL_RATE_MAX_PER_WINDOW", 5)
    monkeypatch.setattr(canary, "_RATE_MAX_PER_WINDOW", 10_000)

    delivered: list[Any] = []

    async def _spy(events: list[Any]) -> None:
        delivered.extend(events)

    buffer = event_buffer.get_buffer()
    buffer.set_on_flush(_spy)
    await buffer.start()
    token = await honeytoken_create(type="canary_url", label="starvation")
    path = urlparse(token["token_value"]).path

    client = TestClient(TestServer(canary.build_app()))
    await client.start_server()
    try:
        for i in range(60):
            resp = await client.get(f"/t/not-a-real-id-{i}")
            assert resp.status == 200
        resp = await client.get(path)
        assert resp.status == 200
        for _ in range(60):
            if delivered:
                break
            await asyncio.sleep(0.05)
        assert delivered, "a real canary hit was dropped after a flood of unknown ids"
        assert delivered[0].honeytoken_id == token["id"]
    finally:
        await client.close()
        await buffer.stop()
        canary.invalidate_token_index()
        # Module-level limiter state outlives the test; 60+ hits from 127.0.0.1
        # would rate-limit every later canary test in the process.
        canary._rate_state.clear()
        canary._global_hits.clear()


# ── Rotation starts the new secret with a clean history ─────────────────────


async def test_rotated_token_does_not_inherit_the_old_trigger_history():
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_rotate

    created = await honeytoken_create(type="canary_url", label="rotate-me")
    async with get_session() as session:
        await queries.mark_honeytoken_triggered(session, created["id"], {"trigger_ip": "1.2.3.4"})
    rotated = await honeytoken_rotate(created["id"])
    assert "error" not in rotated
    new_id = rotated["new_token"]["id"]
    from honeypot_mcp.storage.models import Honeytoken

    async with get_session() as session:
        fresh = await session.get(Honeytoken, new_id)
    assert fresh is not None and "triggers" not in (fresh.token_meta or {})


# ── IMAP / POP3: queued lines survive the half-close that ends a flood ──────


@pytest.mark.parametrize("module", ["imap", "pop3"])
async def test_reply_after_close_after_error_is_dropped_not_raised(module):
    mod = importlib.import_module(f"honeypot_mcp.engines.{module}")
    proto_cls = next(
        v for k, v in vars(mod).items() if k.endswith("Protocol") and k.startswith("_")
    )

    class _HalfClosed:
        def is_closing(self) -> bool:
            return False

        def write(self, data: bytes) -> None:
            raise RuntimeError("Cannot call write() after write_eof()")

    proto = proto_cls("hp", None)
    proto._transport = _HalfClosed()
    proto._send("* OK still here" if module == "imap" else "+OK still here")  # must not raise


# ── UDP: ordinary clients get real answers, still bounded ───────────────────


async def test_snmp_ordinary_get_receives_a_real_varbind_not_toobig():
    from honeypot_mcp.engines import snmp

    request_bytes = snmp.build_get_request("1.3.6.1.2.1.1.1.0")
    request = snmp.parse_snmp(request_bytes)
    assert request is not None
    reply = snmp.build_bounded_response(request, len(request_bytes) * snmp._UDP_REPLY_FACTOR)
    assert reply == snmp.build_response(request), "an ordinary snmpget must not come back tooBig"
    assert len(reply) <= len(request_bytes) * snmp._UDP_REPLY_FACTOR


async def test_snmp_getbulk_style_amplifiers_are_cut_back_to_the_bound():
    from honeypot_mcp.engines import snmp

    request_bytes = snmp.build_get_request("1.3.6.1.2.1.1.1.0")
    request = snmp.parse_snmp(request_bytes)
    assert request is not None
    request["oids"] = ["1.3.6.1.2.1.1.1.0"] * 8  # eight varbinds would triple the reply
    limit = len(request_bytes) * snmp._UDP_REPLY_FACTOR
    reply = snmp.build_bounded_response(request, limit)
    assert reply is not None and len(reply) <= limit


async def test_short_sip_register_still_receives_its_digest_challenge():
    from honeypot_mcp.engines.sip import _UDP_REPLY_FACTOR, SIPEngine

    port = await _register("sip-short", "sip")
    engine = SIPEngine()
    cid = await engine.start("sip-short", port, {})
    request = (
        b"REGISTER sip:x SIP/2.0\r\nVia: SIP/2.0/UDP a\r\nFrom: <sip:1@x>\r\n"
        b"To: <sip:1@x>\r\nCall-ID: 1\r\nCSeq: 1 REGISTER\r\n\r\n"
    )
    loop = asyncio.get_running_loop()
    got: asyncio.Future[bytes] = loop.create_future()

    class _Client(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            if not got.done():
                got.set_result(data)

    transport, _ = await loop.create_datagram_endpoint(_Client, remote_addr=("127.0.0.1", port))
    try:
        transport.sendto(request)
        reply = await asyncio.wait_for(got, timeout=2.0)
    finally:
        transport.close()
        await engine.stop(cid)
    # A 401 with no nonce cannot be answered, so it would capture nothing.
    assert b"nonce=" in reply and b"401" in reply.split(b"\r\n")[0]
    assert len(reply) <= len(request) * _UDP_REPLY_FACTOR
