"""Which sources a blocklist may contain: never one that was seen only on spoofable UDP sensors."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _sensors(*types: str) -> dict[str, int]:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    ids: dict[str, int] = {}
    async with get_session() as session:
        for n, hp_type in enumerate(types):
            hp = Honeypot(
                name=f"hp-{hp_type}",
                type=HoneypotType(hp_type),
                port=2000 + n,
                status=HoneypotStatus.RUNNING,
                config={},
            )
            session.add(hp)
            await session.flush()
            ids[hp_type] = hp.id
    return ids


async def _hit(ip: str, honeypot_id: int, count: int = 6) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for _ in range(count):
            session.add(
                Alert(
                    source_ip=ip,
                    event_type="probe",
                    severity=AlertSeverity.MEDIUM,
                    timestamp=datetime.now(UTC),
                    payload={},
                    honeypot_id=honeypot_id,
                )
            )


async def test_a_source_seen_only_on_spoofable_sensors_is_not_a_blocklist_entry():
    """UDP reflection traffic carries whatever source its sender chose; blocking it punishes the victim.
    DNS now also listens on TCP (zone transfers), which must not make it look non-spoofable."""
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session

    sensor = await _sensors("dns", "snmp", "ssh")
    await _hit("91.121.7.1", sensor["dns"])  # DNS only: spoofable
    await _hit("91.121.7.2", sensor["snmp"])  # SNMP only: spoofable
    await _hit("91.121.7.3", sensor["ssh"])  # a TCP sensor: it completed a handshake
    await _hit("91.121.7.4", sensor["dns"])  # DNS and SSH: it also did something real
    await _hit("91.121.7.4", sensor["ssh"])

    async with get_session() as session:
        rows = await queries.get_top_offenders(
            session, 24, 5, global_only=True, exclude_udp_only=True
        )

    assert {ip for ip, _ in rows} == {"91.121.7.3", "91.121.7.4"}


def test_spoofability_is_about_the_traffic_not_the_transports_served():
    from honeypot_mcp.deception.capabilities import source_is_spoofable, transport_for

    assert transport_for("dns") == "both"
    assert source_is_spoofable("dns") and source_is_spoofable("snmp")
    assert not source_is_spoofable("ssh") and not source_is_spoofable("sip")
    assert not source_is_spoofable("no-such-engine")
