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
from pathlib import Path
from typing import Any

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


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

    port = free_port()
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


# ── Malformed HTTP must not write a traceback per request ───────────────────


async def test_malformed_http_does_not_flood_the_log_with_tracebacks(caplog):
    import logging

    from aiohttp import web

    from honeypot_mcp.http_identity import identity_runner

    async def ok(_request: web.Request) -> web.Response:
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/", ok)
    runner = identity_runner(app, "nginx")
    await runner.setup()
    port = free_port()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    try:
        with caplog.at_level(logging.DEBUG, logger="aiohttp.server"):
            for payload in (
                b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\n\r\n",  # LineTooLong
                b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 64,  # TLS on HTTP
                b"G\x00T / HTTP/1.1\r\n\r\n",  # bad method
            ):
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(payload)
                with contextlib.suppress(ConnectionError):
                    await writer.drain()
                with contextlib.suppress(ConnectionError, TimeoutError):
                    await asyncio.wait_for(reader.read(1024), timeout=2.0)
                writer.close()
        flood = [r for r in caplog.records if r.name == "aiohttp.server" and r.exc_info]
        assert not flood, f"{len(flood)} traceback record(s) logged for attacker input"
    finally:
        await runner.cleanup()


# ── Cowrie log ingestion must survive pause, Docker errors and respawns ─────


class _FakeContainer:
    def __init__(self, statuses: list[str], lines: list[str], labels: dict | None = None):
        self._statuses = statuses
        self._lines = lines
        self.labels = labels or {}
        self.calls: list[str] = []
        self.since_seen: list[Any] = []
        self.id = "c" * 64
        self.attrs = {"Config": {"Env": []}}

    @property
    def status(self) -> str:
        return self._statuses.pop(0) if len(self._statuses) > 1 else self._statuses[0]

    def logs(self, since=None, timestamps=False):  # noqa: ARG002
        self.since_seen.append(since)
        out, self._lines = "\n".join(self._lines).encode(), []
        return out

    def pause(self):
        self.calls.append("pause")

    def unpause(self):
        self.calls.append("unpause")

    def start(self):
        self.calls.append("start")


def _cowrie_login_line(ip: str = "198.51.100.7") -> str:
    import json

    return json.dumps(
        {
            "eventid": "cowrie.login.failed",
            "src_ip": ip,
            "src_port": 4444,
            "username": "root",
            "password": "toor",
            "session": "s1",
        }
    )


def _engine_with(monkeypatch, container_for_get):
    import docker.errors

    from honeypot_mcp.engines import ssh

    class _Containers:
        def get(self, cid):
            return container_for_get(cid)

    class _Client:
        containers = _Containers()

    monkeypatch.setattr("docker.from_env", lambda: _Client())
    engine = ssh.SSHEngine()

    real_sleep = asyncio.sleep  # `ssh.asyncio` is this very module: capture before patching

    async def _fast_sleep(_s):
        await real_sleep(0)

    monkeypatch.setattr(ssh.asyncio, "sleep", _fast_sleep)
    return engine, ssh, docker.errors


async def test_ingestion_waits_through_a_paused_container_instead_of_quitting(monkeypatch):
    seen: list[Any] = []
    box = _FakeContainer(["paused", "paused", "paused", "running"], [_cowrie_login_line()])
    gone = {"after": 0}

    def get(_cid):
        gone["after"] += 1
        if gone["after"] > 8:
            raise docker_errors.NotFound("gone")
        return box

    engine, ssh, docker_errors = _engine_with(monkeypatch, get)

    async def capture(event):
        seen.append(event)

    monkeypatch.setattr(ssh, "submit_event", capture)
    await asyncio.wait_for(engine._ingest_logs("cw", "c" * 64), timeout=5)
    # Before the fix `_ingest_logs` returned at the first non-"running" status.
    assert [e.event_type for e in seen] == ["ssh_login_failed"]


async def test_ingestion_survives_a_docker_error_and_keeps_its_cursor(monkeypatch):
    box = _FakeContainer(["running"], [_cowrie_login_line()])
    calls = {"n": 0}

    def get(_cid):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("socket-proxy hiccup")  # not NotFound
        if calls["n"] > 6:
            raise docker_errors.NotFound("gone")
        return box

    engine, ssh, docker_errors = _engine_with(monkeypatch, get)
    seen: list[Any] = []

    async def capture(event):
        seen.append(event)

    monkeypatch.setattr(ssh, "submit_event", capture)
    await asyncio.wait_for(engine._ingest_logs("cw", "c" * 64), timeout=5)
    assert len(seen) == 1
    assert engine._ingest_cursor["c" * 64] is not None


async def test_a_respawned_ingestion_task_resumes_from_the_saved_cursor(monkeypatch):
    from datetime import UTC, datetime, timedelta

    box = _FakeContainer(["running"], [])
    calls = {"n": 0}

    def get(_cid):
        calls["n"] += 1
        if calls["n"] > 3:
            raise docker_errors.NotFound("gone")
        return box

    engine, _ssh, docker_errors = _engine_with(monkeypatch, get)
    saved = datetime.now(UTC) - timedelta(minutes=5)  # the gap a crash would have skipped
    engine._ingest_cursor["c" * 64] = saved
    await asyncio.wait_for(engine._ingest_logs("cw", "c" * 64), timeout=5)
    assert box.since_seen[0] == saved, "a respawn must not restart from 'two seconds ago'"


async def test_resume_restarts_ingestion_and_reattach_unpauses_instead_of_starting(monkeypatch):
    box = _FakeContainer(["paused"], [], labels={"honeypot-name": "cw-paused"})
    engine, _ssh, _errors = _engine_with(monkeypatch, lambda _cid: box)
    spawned: list[tuple[str, str]] = []
    monkeypatch.setattr(engine, "_spawn_ingest_task", lambda name, cid: spawned.append((name, cid)))

    await engine.resume("c" * 64)
    assert box.calls == ["unpause"]
    assert spawned == [("cw-paused", "c" * 64)], "ingestion was not restarted on resume"

    box.calls.clear()
    spawned.clear()
    await engine.reattach("cw-paused", 2222, {}, "c" * 64)
    assert box.calls == ["unpause"], "`start` on a paused container is an error"
    assert spawned == [("cw-paused", "c" * 64)]


async def test_reattach_warns_about_a_container_created_before_the_egress_control(
    monkeypatch, caplog
):
    import logging

    box = _FakeContainer(["running"], [])  # Env has no COWRIE_HONEYPOT_OUT_ADDR
    engine, _ssh, _errors = _engine_with(monkeypatch, lambda _cid: box)
    monkeypatch.setattr(engine, "_spawn_ingest_task", lambda *_a: None)
    with caplog.at_level(logging.WARNING, logger="honeypot_mcp.engines.ssh"):
        await engine.reattach("cw-old", 2222, {}, "c" * 64)
    assert any("OUT_ADDR" in r.getMessage() for r in caplog.records)


# ═══ Second independent review ═══════════════════════════════════════════════


async def _alerts_for(ips: list[str], count: int = 10) -> None:
    from datetime import UTC, datetime

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for ip in ips:
            for _ in range(count):
                session.add(
                    Alert(
                        timestamp=datetime.now(UTC),
                        source_ip=ip,
                        event_type="ssh_login_failed",
                        severity=AlertSeverity.MEDIUM,
                        payload={},
                    )
                )


async def _audit(tool: str) -> list[Any]:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    async with get_session() as session:
        return list(
            (await session.execute(select(AuditLog).where(AuditLog.tool == tool))).scalars()
        )


# ── Packaging: an installed package must not anchor its data to site-packages ──


def test_project_root_falls_back_to_cwd_when_installed_not_checked_out(tmp_path):
    from honeypot_mcp.config import _find_project_root

    checkout = tmp_path / "checkout"
    (checkout / "src" / "honeypot_mcp").mkdir(parents=True)
    (checkout / "pyproject.toml").write_text("[project]\n")
    config_file = checkout / "src" / "honeypot_mcp" / "config.py"
    assert _find_project_root(config_file, tmp_path / "elsewhere") == checkout.resolve()

    # `lib/python3.12/site-packages/honeypot_mcp/config.py`: parents[2] is `lib/python3.12`.
    installed = tmp_path / "venv" / "lib" / "python3.12" / "site-packages" / "honeypot_mcp"
    installed.mkdir(parents=True)
    cwd = tmp_path / "app"
    assert _find_project_root(installed / "config.py", cwd) == cwd


# ── IP / name validation ────────────────────────────────────────────────────


@pytest.mark.parametrize("bad", ["2001:db8::1%..", "fe80::1%x?k=1", "fe80::1%eth0"])
async def test_validate_ip_rejects_zone_ids(bad):
    from honeypot_mcp.tools._format import validate_ip

    assert validate_ip(bad) is not None
    assert validate_ip("2001:db8::1") is None and validate_ip("203.0.113.9") is None


async def test_virustotal_lookup_refuses_a_zone_id_instead_of_building_a_url(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.intel.virustotal import lookup_virustotal

    monkeypatch.setattr(get_settings(), "virustotal_api_key", "k" * 32)
    result = await lookup_virustotal("fe80::1%x?k=1")
    assert result["available"] is False and "scoped" in result["note"]


@pytest.mark.parametrize("name", ["good-name\n", "good-name\r\n"])
async def test_trailing_newline_does_not_pass_name_validation(name):
    from honeypot_mcp.tools._format import validate_honeypot_name

    assert validate_honeypot_name(name) is not None
    assert validate_honeypot_name("good-name") is None


# ── pcap extracts: exclusive and private ────────────────────────────────────


async def test_pcap_merge_never_overwrites_and_writes_owner_only(tmp_path):
    import stat
    import struct

    from honeypot_mcp.pcap import merge_pcaps

    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    src = tmp_path / "in.pcap"
    src.write_bytes(header)
    out = tmp_path / "out.pcap"
    merge_pcaps([src], out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600

    out.write_bytes(b"precious evidence")
    with pytest.raises(FileExistsError):
        merge_pcaps([src], out)
    assert out.read_bytes() == b"precious evidence"


# ── Removing a honeypot must not load every alert it captured ───────────────


async def test_honeypot_stop_remove_does_not_load_the_alert_history():
    from sqlalchemy import event, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_stop

    async with get_session() as session:
        hp = Honeypot(
            name="big-history",
            type=HoneypotType.HTTP,
            port=1,
            status=HoneypotStatus.RUNNING,
            container_id=None,
        )
        session.add(hp)
        await session.flush()
        hp_id = hp.id
        for i in range(300):
            session.add(
                Alert(
                    honeypot_id=hp_id,
                    source_ip="203.0.113.5",
                    event_type=f"e{i}",
                    severity="low",
                    payload={},
                )
            )

    loaded = {"n": 0}

    def _count(_target, _context):
        loaded["n"] += 1

    event.listen(Alert, "load", _count)
    try:
        result = await honeypot_stop(name="big-history", remove=True)
    finally:
        event.remove(Alert, "load", _count)
    assert "error" not in result, result
    assert loaded["n"] == 0, f"{loaded['n']} Alert rows were loaded into memory"

    async with get_session() as session:
        assert await session.get(Honeypot, hp_id) is None
        orphaned = (
            (await session.execute(select(Alert).where(Alert.source_ip == "203.0.113.5")))
            .scalars()
            .all()
        )
    assert len(orphaned) == 300 and all(a.honeypot_id is None for a in orphaned)


# ── Deployment plans ────────────────────────────────────────────────────────


async def test_failed_first_sensor_under_stop_on_error_creates_no_tokens():
    from sqlalchemy import func, select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken
    from honeypot_mcp.tools.deception import deception_deploy_plan

    result = await deception_deploy_plan(
        sensors=[{"type": "not-a-real-type", "name": "x"}],
        tokens=[{"type": "canary_url", "label": "should-not-exist"}],
        stop_on_error=True,
    )
    assert result.get("failures") or result.get("failed") or "error" in str(result).lower()
    async with get_session() as session:
        count = (await session.execute(select(func.count()).select_from(Honeytoken))).scalar_one()
    assert count == 0, "tokens were created for a plan whose first sensor failed"
    rows = await _audit("deception_deploy_plan")
    assert rows and rows[-1].outcome == "error"


async def test_deploy_validates_config_like_configure_does():
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    smuggled = await honeypot_deploy(type="ftp", config={"fake_banner": "x\r\n230 logged in"})
    assert "error" in smuggled
    unknown = await honeypot_deploy(type="ftp", config={"not_a_key": 1})
    assert "error" in unknown and "not_a_key" in unknown["error"]


# ── Audit log integrity ─────────────────────────────────────────────────────


async def test_audit_rows_use_one_outcome_vocabulary_and_clip_long_targets():
    from honeypot_mcp.tools._audit import record_action

    await record_action("t-vocab", "ok one", outcome="success", target="x" * 500)
    await record_action("t-vocab", "refused one", outcome="refused")
    await record_action("t-vocab", "fine", outcome="ok")
    rows = await _audit("t-vocab")
    assert sorted(r.outcome for r in rows) == ["error", "error", "ok"]
    assert all(len(r.target or "") <= 128 for r in rows)
    assert len(rows) == 3, "an over-long target must not drop the audit row"


async def test_triage_is_attributed_to_the_caller_not_to_a_name_they_supply(monkeypatch):
    from sqlalchemy import select

    from honeypot_mcp import rbac
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert
    from honeypot_mcp.tools.alerts import alerts_acknowledge

    await _alerts_for(["203.0.113.77"], count=2)
    monkeypatch.setattr(rbac, "current_actor", lambda: "alice (operator)")
    # there is no `analyst` argument to supply: the attribution can only be the caller's
    import inspect

    assert "analyst" not in inspect.signature(alerts_acknowledge).parameters
    result = await alerts_acknowledge(source_ip="203.0.113.77")
    assert "error" not in result, result
    async with get_session() as session:
        alerts = (
            (await session.execute(select(Alert).where(Alert.source_ip == "203.0.113.77")))
            .scalars()
            .all()
        )
    assert alerts and all(a.triaged_by == "alice (operator)" for a in alerts)


# ── Blocklists ──────────────────────────────────────────────────────────────


async def test_exports_honour_the_never_block_allowlist(monkeypatch, tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.analysis import export_indicators

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path, raising=False)
    monkeypatch.setattr(get_settings(), "blocklist_allowlist", "8.8.4.4")
    await _alerts_for(["8.8.4.4", "9.9.9.9"], count=10)
    result = await export_indicators(hours=24, min_hits=5)
    text = Path(result["path"]).read_text()
    assert "9.9.9.9" in text and "8.8.4.4" not in text


async def test_exports_refuse_a_malformed_allowlist_instead_of_ignoring_it(monkeypatch, tmp_path):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.analysis import export_indicators

    monkeypatch.setattr(get_settings(), "reports_dir", tmp_path, raising=False)
    monkeypatch.setattr(get_settings(), "blocklist_allowlist", "not-an-ip")
    await _alerts_for(["9.9.9.9"], count=10)
    assert "error" in await export_indicators(hours=24, min_hits=5)


# ── Collector mode ignores control-plane token config ───────────────────────


async def test_collector_mode_does_not_crash_on_a_malformed_auth_token_setting(monkeypatch):
    from honeypot_mcp import server
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "mcp_transport", "none")
    monkeypatch.setattr(settings, "mcp_auth_tokens", "garbage-without-a-role")
    assert server._build_auth() is None


# ── Transient database errors must not cost events ──────────────────────────


async def test_a_transient_database_error_is_retried_not_treated_as_a_refused_event(monkeypatch):
    """An OperationalError is a locked file / dropped connection / deadlock: the
    database did not reject the data. The old flusher retried immediately and then
    dropped each event as 'refused', losing events nothing was wrong with."""
    from sqlalchemy.exc import OperationalError

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    buf = event_buffer.get_buffer()
    real_write = buf._write
    failures = {"left": 4}

    async def flaky(events):
        if failures["left"] > 0:
            failures["left"] -= 1
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        return await real_write(events)

    monkeypatch.setattr(buf, "_write", flaky)
    events = [
        PendingEvent(
            honeypot_id=None,
            source_ip="203.0.113.50",
            event_type=f"transient_{i}",
            payload={},
            severity=AlertSeverity.LOW,
        )
        for i in range(3)
    ]
    written = await buf._flush(events)
    assert [e.event_type for e in written] == ["transient_0", "transient_1", "transient_2"]
    assert failures["left"] == 0


async def test_a_permanent_database_error_still_costs_only_the_poison_event(monkeypatch):
    from sqlalchemy.exc import IntegrityError

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.event_buffer import PendingEvent
    from honeypot_mcp.storage.models import AlertSeverity

    buf = event_buffer.get_buffer()
    real_write = buf._write

    async def picky(events):
        if any(e.event_type == "poison" for e in events):
            raise IntegrityError("INSERT", {}, Exception("constraint failed"))
        return await real_write(events)

    monkeypatch.setattr(buf, "_write", picky)

    def ev(name: str):
        return PendingEvent(
            honeypot_id=None,
            source_ip="203.0.113.51",
            event_type=name,
            payload={},
            severity=AlertSeverity.LOW,
        )

    start = time.monotonic()
    written = await buf._flush([ev("a"), ev("poison"), ev("b")])
    assert [e.event_type for e in written] == ["a", "b"]
    assert time.monotonic() - start < 1.0, "a permanent error must not be backed off"


# ── Data directories follow settings, not the directory the server was started in ──


async def test_certificate_and_generated_keys_do_not_depend_on_the_launch_directory(
    tmp_path, monkeypatch
):
    """A scanner pinning a honeypot's certificate must see the same one however the
    server was started. `tls/` and `reports/generated/` used to be relative to the
    working directory, so each launch directory got its own certificate and its own
    copy of generated honeytoken private keys."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.engines.tls import ensure_cert
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    settings = get_settings()
    monkeypatch.setattr(settings, "tls_dir", tmp_path / "data" / "tls")
    monkeypatch.setattr(settings, "reports_dir", tmp_path / "data" / "reports")

    first_dir = tmp_path / "launched-here"
    second_dir = tmp_path / "launched-there"
    first_dir.mkdir()
    second_dir.mkdir()

    monkeypatch.chdir(first_dir)
    cert_a, key_a = ensure_cert("pinned-sensor")
    monkeypatch.chdir(second_dir)
    cert_b, key_b = ensure_cert("pinned-sensor")

    assert cert_a == cert_b and key_a == key_b, "a second launch directory minted a new certificate"
    assert cert_a.is_relative_to(tmp_path / "data" / "tls")
    assert not (first_dir / "tls").exists() and not (second_dir / "tls").exists()

    token = await honeytoken_create(type="ssh_key", label="launch-dir")
    assert "error" not in token, token
    private_keys = list((tmp_path / "data" / "reports" / "generated").glob("id_rsa_*"))
    assert len(private_keys) == 1
    assert not (second_dir / "reports").exists()


# ── Packet capture ring files are private ───────────────────────────────────


async def test_capture_ring_is_owner_only_even_under_a_permissive_umask(tmp_path, monkeypatch):
    """tcpdump creates ring files with the umask it inherits — 0644 under the usual
    022 — and they hold raw attacker sessions. The capture directory is private and
    the child runs under umask 077, whatever the server's own umask is."""
    import os
    import stat

    from honeypot_mcp import pcap
    from honeypot_mcp.config import get_settings

    fake = tmp_path / "bin" / "tcpdump"
    fake.parent.mkdir()
    # Creates its -w file the way tcpdump does (inheriting the umask), then waits.
    fake.write_text(
        '#!/bin/sh\nwhile [ "$1" != "-w" ]; do shift; done\n'
        'out="$2"; : > "${out}0"\nexec sleep 30\n'
    )
    fake.chmod(0o755)
    monkeypatch.setattr(pcap, "probe_capability", lambda: pcap.Capability(True, "", str(fake)))
    ring = tmp_path / "ring"
    monkeypatch.setattr(get_settings(), "pcap_dir", ring)

    previous = os.umask(0o022)  # the permissive umask a default service inherits
    capture = pcap.PcapCapture()
    try:
        result = await capture.start([(2222, "tcp")])
        assert result["started"] is True, result
        await asyncio.sleep(0.3)
        files = list(ring.glob("honeypot.pcap*"))
        assert files, "the fake tcpdump never created its output"
        assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
        assert stat.S_IMODE(ring.stat().st_mode) == 0o700
    finally:
        await capture.stop()
        os.umask(previous)


def test_a_root_started_capture_drops_to_a_user_that_owns_the_directory(tmp_path, monkeypatch):
    """Started as root, tcpdump drops privileges after opening the interface and then
    writes as that user — so the private directory has to belong to it, or the capture
    dies at its first rotation."""
    import os
    import pwd
    from types import SimpleNamespace

    from honeypot_mcp import pcap

    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda name: (
            SimpleNamespace(pw_uid=777, pw_gid=778)
            if name == "tcpdump"
            else (_ for _ in ()).throw(KeyError(name))
        ),
    )
    assert pcap.capture_drop_args(tmp_path) == ["-Z", "tcpdump"]
    assert chowned == [(str(tmp_path), 777, 778)]

    # No such user on this host: fall through to the next candidate, then to nothing.
    monkeypatch.setattr(
        pwd,
        "getpwnam",
        lambda name: (
            SimpleNamespace(pw_uid=65534, pw_gid=65534)
            if name == "nobody"
            else (_ for _ in ()).throw(KeyError(name))
        ),
    )
    assert pcap.capture_drop_args(tmp_path) == ["-Z", "nobody"]
    monkeypatch.setattr(pwd, "getpwnam", lambda name: (_ for _ in ()).throw(KeyError(name)))
    assert pcap.capture_drop_args(tmp_path) == []


def test_a_capture_started_without_root_needs_no_privilege_drop(tmp_path, monkeypatch):
    import os

    from honeypot_mcp import pcap

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert pcap.capture_drop_args(tmp_path) == []
