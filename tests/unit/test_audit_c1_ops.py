"""Regression tests for audit slice C1, findings 10-12: the operational
surfaces (metrics, console, Markdown reports, packet-capture extracts)."""

from __future__ import annotations

import asyncio
import os
import socket
import struct
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.console import server as console_server
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    console_server._overview_cache.clear()
    await init_db()
    yield
    await close_db()
    console_server._overview_cache.clear()
    event_buffer.reset_for_tests()


async def _seed(ip="203.0.113.5", n=1, severity="low", country="Neverland", minutes_ago=5):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    payload: dict = {"username": "admin"}
    if country:
        payload["enrichment"] = {"geoip": {"country": country}}
    async with get_session() as session:
        for i in range(n):
            session.add(
                Alert(
                    source_ip=ip,
                    event_type="http_probe",
                    payload=payload,
                    severity=AlertSeverity(severity),
                    timestamp=datetime.now(UTC) - timedelta(minutes=minutes_ago, seconds=i),
                )
            )


# ── Finding 10: metrics ─────────────────────────────────────────────────────


async def _metrics_client():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.metrics import build_app

    client = TestClient(TestServer(build_app()))
    await client.start_server()
    return client


async def test_readyz_does_not_leak_exception_detail():
    from sqlalchemy import text

    from honeypot_mcp.storage.database import get_session

    client = await _metrics_client()
    try:
        async with get_session() as session:
            await session.execute(text("DROP TABLE honeypots"))
        response = await client.get("/readyz")
        assert response.status == 503
        body = await response.json()
        assert body["checks"]["database"] == "unavailable"
        raw = await response.text()
        assert "honeypots" not in raw and "OperationalError" not in raw
    finally:
        await client.close()


async def test_metrics_error_is_generic(monkeypatch):
    from honeypot_mcp import metrics

    async def boom() -> str:
        raise RuntimeError("postgresql://admin:hunter2@db/secret")

    monkeypatch.setattr(metrics, "_gather_metrics", boom)
    client = await _metrics_client()
    try:
        body = await (await client.get("/metrics")).text()
    finally:
        await client.close()
    assert body.startswith("# metrics_error")
    assert "hunter2" not in body and "RuntimeError" not in body


async def test_metrics_do_not_export_suppression_rule_labels():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import SuppressionRule

    async with get_session() as session:
        rule = SuppressionRule(
            label="partner-pentest-10.20.30.0",
            ip_pattern="10.20.30.0/24",
            action="drop",
            suppressed_count=7,
        )
        session.add(rule)
        await session.flush()
        rule_id = rule.id

    client = await _metrics_client()
    try:
        body = await (await client.get("/metrics")).text()
    finally:
        await client.close()
    assert "partner-pentest" not in body
    assert f'honeypot_suppression_drops_total{{rule_id="{rule_id}"}} 7' in body


async def test_metrics_server_warns_when_bound_off_loopback(caplog):
    from honeypot_mcp.metrics import start_metrics_server

    caplog.set_level("WARNING", logger="honeypot_mcp.metrics")
    runner = await start_metrics_server("0.0.0.0", 0)
    try:
        assert any("non-loopback" in r.getMessage() for r in caplog.records)
    finally:
        if runner is not None:
            await runner.cleanup()

    caplog.clear()
    runner = await start_metrics_server("127.0.0.1", 0)
    try:
        assert not any("non-loopback" in r.getMessage() for r in caplog.records)
    finally:
        if runner is not None:
            await runner.cleanup()


def _bound_port(runner) -> int:
    site = next(iter(runner.sites))
    return site._server.sockets[0].getsockname()[1]


async def test_metrics_protocol_errors_do_not_reveal_aiohttp():
    """A malformed request is answered before routing; that reply must not
    carry aiohttp's default `Server` banner."""
    from honeypot_mcp.metrics import start_metrics_server

    runner = await start_metrics_server("127.0.0.1", 0)
    assert runner is not None
    try:
        port = _bound_port(runner)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=5
        )
        writer.write(b"\x16\x03\x01 garbage not http\r\n\r\n")
        await writer.drain()
        head = await asyncio.wait_for(reader.read(4096), timeout=5)
        writer.close()
    finally:
        await runner.cleanup()
    text = head.decode("latin-1").lower()
    assert "aiohttp" not in text and "python" not in text


# ── Finding 10: console ─────────────────────────────────────────────────────


async def _console_client():
    from aiohttp.test_utils import TestClient, TestServer

    from honeypot_mcp.console import build_console_app

    client = TestClient(TestServer(build_console_app()))
    await client.start_server()
    return client


async def test_console_rejects_unknown_host_names(monkeypatch):
    """DNS rebinding: a hostile page whose name now resolves to loopback still
    sends its own name in Host."""
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "console_allowed_hosts", "soc-wall.internal")
    client = await _console_client()
    try:
        evil = await client.get("/api/overview", headers={"Host": "attacker.example"})
        assert evil.status == 421
        evil_index = await client.get("/", headers={"Host": "rebind.attacker.example:8090"})
        assert evil_index.status == 421

        for host in ("127.0.0.1:8090", "localhost:8090", "[::1]:8090", "soc-wall.internal"):
            ok = await client.get("/api/overview", headers={"Host": host})
            assert ok.status == 200, host
    finally:
        await client.close()


async def test_console_feed_is_limited_but_stats_count_everything():
    from honeypot_mcp.console.server import _FEED_ROWS, _overview

    await _seed(ip="203.0.113.5", n=_FEED_ROWS + 25, severity="low", country="Neverland")
    await _seed(ip="198.51.100.9", n=3, severity="critical", country="Atlantis")
    await _seed(ip="192.0.2.77", n=2, severity="high", country=None)

    data = await _overview(24)
    assert len(data["feed"]) == _FEED_ROWS
    assert data["stats"]["events"] == _FEED_ROWS + 30
    assert data["stats"]["unique_ips"] == 3
    assert data["stats"]["critical"] == 3 and data["stats"]["high"] == 2
    assert data["stats"]["untriaged"] == _FEED_ROWS + 30
    points = data["series"]["points"]
    assert sum(p["routine"] for p in points) == _FEED_ROWS + 25
    assert sum(p["serious"] for p in points) == 5
    assert data["top_countries"] == [
        {"country": "Neverland", "hits": _FEED_ROWS + 25},
        {"country": "Atlantis", "hits": 3},
    ]
    attackers = {a["ip"]: a for a in data["top_attackers"]}
    assert attackers["203.0.113.5"]["country"] == "Neverland"
    assert attackers["198.51.100.9"]["country"] == "Atlantis"
    assert attackers["192.0.2.77"]["country"] is None
    assert data["top_attackers"][0]["ip"] == "203.0.113.5"


async def test_console_overview_is_cached_briefly():
    client = await _console_client()
    try:
        first = await (await client.get("/api/overview?hours=24")).json()
        await _seed(n=4)
        second = await (await client.get("/api/overview?hours=24")).json()
    finally:
        await client.close()
    assert second["generated_at"] == first["generated_at"]
    assert second["stats"]["events"] == first["stats"]["events"] == 0


async def test_console_warns_when_bound_off_loopback(caplog):
    from honeypot_mcp.console import start_console_server

    caplog.set_level("WARNING", logger="honeypot_mcp.console.server")
    runner = await start_console_server("0.0.0.0", 0)
    try:
        assert any("non-loopback" in r.getMessage() for r in caplog.records)
    finally:
        if runner is not None:
            await runner.cleanup()


# ── Finding 11: Markdown report escaping ────────────────────────────────────


def test_md_cell_neutralises_markdown_and_html():
    from honeypot_mcp.analysis.reporter import _md_cell

    out = _md_cell("<script>x</script> [click](http://evil) ![i](http://e/p.png) `c` **b** _e_")
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "[click](" not in out and "\\[click\\]" in out
    assert "![" not in out.replace("\\!\\[", "")
    assert "`c`" not in out and "\\`c\\`" in out
    assert "**b**" not in out and "\\*\\*b\\*\\*" in out
    assert "\\_e\\_" in out
    # Intraword underscores are not emphasis in CommonMark and stay readable.
    assert _md_cell("ssh_login_failed") == "ssh_login_failed"
    assert _md_cell("a|b\nc") == "a\\|b c"


async def test_markdown_report_cannot_inject_links_or_html():
    from honeypot_mcp.analysis.reporter import generate
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    alert = Alert(
        id=1,
        honeypot_id=None,
        source_ip="1.2.3.4",
        event_type="[pay here](http://evil.example)<img src=x onerror=alert(1)>",
        payload={},
        severity=AlertSeverity.HIGH,
        timestamp=datetime.now(UTC),
        acknowledged=False,
    )
    md = await generate(
        title="Weekly", alerts=[alert], stats={}, target_ip="1.2.3.4`) evil", format="markdown"
    )
    assert "[pay here](http://evil.example)" not in md
    assert "<img" not in md
    assert "`1.2.3.4') evil`" in md


# ── Finding 12: concurrent pcap extracts ────────────────────────────────────


def _pcap_bytes(src: str) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20,
        0,
        0,
        64,
        6,
        0,
        socket.inet_aton(src),
        socket.inet_aton("198.51.100.1"),
    )
    frame = b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x08\x00" + ip
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    return header + struct.pack("<IIII", 1780000000, 0, len(frame), len(frame)) + frame


async def test_concurrent_extracts_do_not_delete_each_others_parts(tmp_path, monkeypatch):
    """Two extracts used to share `.extract-<pid>`: whichever finished first
    removed the directory the other was still writing parts into."""
    from honeypot_mcp import pcap
    from honeypot_mcp.config import get_settings

    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    (pcap_dir / "honeypot.pcap0").write_bytes(_pcap_bytes("203.0.113.10"))
    reports = tmp_path / "reports"
    reports.mkdir()

    # A stand-in tcpdump: copies the ring file to the part, slowly for one IP,
    # so the fast extract always finishes while the slow one is mid-flight.
    fake = tmp_path / "fake-tcpdump"
    fake.write_text(
        '#!/bin/sh\ncase "$6" in *203.0.113.99*) sleep 1 ;; *) sleep 0.1 ;; esac\ncp "$2" "$4"\n'
    )
    fake.chmod(0o755)

    settings = get_settings()
    monkeypatch.setattr(settings, "reports_dir", reports)
    monkeypatch.setattr(pcap, "probe_capability", lambda: pcap.Capability(True, "ok", str(fake)))
    monkeypatch.setattr(pcap.PcapCapture, "files", lambda self: [pcap_dir / "honeypot.pcap0"])

    capture = pcap.PcapCapture()
    fast, slow = await asyncio.wait_for(
        asyncio.gather(
            capture.extract("203.0.113.10", "fast.pcap"),
            capture.extract("203.0.113.99", "slow.pcap"),
        ),
        timeout=15,
    )
    assert "error" not in fast and "error" not in slow, (fast, slow)
    assert fast["packets"] == 1
    assert slow["packets"] == 1
    assert not [p for p in reports.iterdir() if p.name.startswith(".extract-")]


async def test_extract_write_failure_is_an_error_not_an_exception(tmp_path, monkeypatch):
    from honeypot_mcp import pcap
    from honeypot_mcp.config import get_settings

    pcap_dir = tmp_path / "pcap"
    pcap_dir.mkdir()
    (pcap_dir / "honeypot.pcap0").write_bytes(_pcap_bytes("203.0.113.10"))
    reports = tmp_path / "reports"
    reports.mkdir()
    fake = tmp_path / "fake-tcpdump"
    fake.write_text('#!/bin/sh\ncp "$2" "$4"\n')
    fake.chmod(0o755)

    def full_disk(_pieces, _dest):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(get_settings(), "reports_dir", reports)
    monkeypatch.setattr(pcap, "probe_capability", lambda: pcap.Capability(True, "ok", str(fake)))
    monkeypatch.setattr(pcap.PcapCapture, "files", lambda self: [pcap_dir / "honeypot.pcap0"])
    monkeypatch.setattr(pcap, "merge_pcaps", full_disk)

    result = await asyncio.wait_for(
        pcap.PcapCapture().extract("203.0.113.10", "x.pcap"), timeout=10
    )
    assert "error" in result and "No space" in result["error"]
    assert not (reports / "x.pcap").exists()
    assert not [p for p in reports.iterdir() if p.name.startswith(".extract-")]
