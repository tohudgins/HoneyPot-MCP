"""Tests for the SOC platform tools — exports, retention.

Format-stability tests: any downstream tool consuming `export_blocklist` or
`export_stix` should not break if we tweak the implementation.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db
    await init_db()
    yield
    await close_db()


async def _seed_alerts(ip: str, count: int, hours_ago: int = 1):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    async with get_session() as session:
        for _ in range(count):
            session.add(Alert(
                honeypot_id=None,
                source_ip=ip,
                source_port=None,
                event_type="ssh_login_failed",
                payload={},
                severity=AlertSeverity.HIGH,
                timestamp=ts,
            ))


@pytest.mark.asyncio
async def test_export_blocklist_plain_format():
    from honeypot_mcp.tools.analysis import export_blocklist

    await _seed_alerts("8.8.8.8", count=10)
    await _seed_alerts("9.9.9.9", count=2)  # Below threshold

    out = await export_blocklist(format="plain", hours=24, min_hits=5)
    assert "8.8.8.8" in out
    assert "9.9.9.9" not in out


@pytest.mark.asyncio
async def test_export_blocklist_iptables_format():
    from honeypot_mcp.tools.analysis import export_blocklist

    await _seed_alerts("1.2.3.4", count=10)
    out = await export_blocklist(format="iptables", hours=24, min_hits=5)
    assert "iptables -A INPUT -s 1.2.3.4 -j DROP" in out


@pytest.mark.asyncio
async def test_export_stix_emits_valid_bundle():
    from honeypot_mcp.tools.analysis import export_stix

    await _seed_alerts("4.4.4.4", count=3)
    raw = await export_stix(hours=24, min_hits=1)
    bundle = json.loads(raw)

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) >= 1
    indicator = bundle["objects"][0]
    assert indicator["type"] == "indicator"
    assert indicator["spec_version"] == "2.1"
    assert "ipv4-addr:value = '4.4.4.4'" in indicator["pattern"]
    assert "malicious-activity" in indicator["labels"]


@pytest.mark.asyncio
async def test_alerts_prune_deletes_old():
    from honeypot_mcp.tools.alerts import alerts_prune

    await _seed_alerts("old-1.1.1.1", count=2, hours_ago=24 * 100)  # 100 days old
    await _seed_alerts("new-2.2.2.2", count=2, hours_ago=1)         # fresh

    result = await alerts_prune(older_than_days=90)
    assert result["alerts_deleted"] == 2
    assert "cutoff" in result


@pytest.mark.asyncio
async def test_alerts_prune_rejects_zero():
    from honeypot_mcp.tools.alerts import alerts_prune

    result = await alerts_prune(older_than_days=0)
    assert "error" in result
