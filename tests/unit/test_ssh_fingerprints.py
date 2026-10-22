"""SSH client fingerprints: capture them, then cluster attackers by them.

Cowrie computes a HASSH for every connection (an MD5 over the client's key-exchange
offer). The same tool or botnet binary yields the same HASSH from every address it
runs on, which is how scattered sources are recognised as one campaign. The ingester
used to drop `cowrie.client.kex` because the event id was unmapped. The sample line
below is the shape a live Cowrie 3.0.15 emitted.
"""

import json
import os
from collections import deque
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

KEX_LINE = {
    "eventid": "cowrie.client.kex",
    "hassh": "2da464e4fd41314056df309d246a983a",
    "hasshAlgorithms": "curve25519-sha256;aes128-ctr;hmac-sha2-256;none",
    "kexAlgs": ["curve25519-sha256", "diffie-hellman-group14-sha256"] + ["x"] * 80,
    "keyAlgs": ["ssh-ed25519", "rsa-sha2-512"],
    "encCS": ["aes128-ctr", "aes256-ctr"],
    "macCS": ["hmac-sha2-256"],
    "compCS": ["none"],
    "langCS": [""],
    "src_ip": "203.0.113.50",
    "src_port": 40000,
    "session": "abc123",
    "protocol": "ssh",
    "sensor": "web-prod-01",
    "timestamp": "2026-10-04T12:00:00.000000Z",
}


@pytest.fixture
def submitted(monkeypatch):
    events = []

    async def _capture(event):
        events.append(event)

    monkeypatch.setattr("honeypot_mcp.engines.ssh.submit_event", _capture)
    return events


async def _feed(entry: dict) -> None:
    from honeypot_mcp.engines.ssh import SSHEngine

    await SSHEngine()._handle_line(json.dumps(entry), 1, set(), deque(maxlen=8))


async def test_the_key_exchange_fingerprint_is_recorded_not_discarded(submitted):
    await _feed(KEX_LINE)
    assert [e.event_type for e in submitted] == ["ssh_client_kex"]
    payload = submitted[0].payload
    assert payload["hassh"] == "2da464e4fd41314056df309d246a983a"
    assert payload["session"] == "abc123"
    assert len(payload["kexAlgs"]) <= 40, "an algorithm list must not be stored unbounded"
    assert "langCS" not in payload


async def test_data_pushed_through_the_ssh_proxy_is_recorded_and_bounded(submitted):
    await _feed(
        {
            "eventid": "cowrie.direct-tcpip.data",
            "src_ip": "203.0.113.50",
            "session": "abc123",
            "dst_ip": "203.0.113.9",
            "dst_port": 80,
            "data": "GET /spam HTTP/1.1\r\n" + "A" * 10_000,
        }
    )
    event = submitted[0]
    assert event.event_type == "ssh_port_forward_data"
    assert event.severity.value == "high"
    assert len(event.payload["data"]) == 2048
    assert event.payload["data_bytes"] > 10_000 and event.payload["data_truncated"] is True


async def test_an_offered_public_key_is_recorded(submitted):
    await _feed(
        {
            "eventid": "cowrie.client.fingerprint",
            "src_ip": "203.0.113.50",
            "session": "abc123",
            "username": "root",
            "fingerprint": "ab:cd:ef",
        }
    )
    assert submitted[0].event_type == "ssh_pubkey_attempt"


# ── Clustering ──────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _kex(
    ip: str, hassh: str, session: str, *, hours_ago: float = 1.0, version: str | None = None
):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    when = datetime.now(UTC) - timedelta(hours=hours_ago)
    async with get_session() as s:
        s.add(
            Alert(
                source_ip=ip,
                event_type="ssh_client_kex",
                severity=AlertSeverity.LOW,
                timestamp=when,
                payload={
                    "hassh": hassh,
                    "session": session,
                    "kexAlgs": ["curve25519-sha256", "a", "b", "c"],
                },
            )
        )
        if version:
            s.add(
                Alert(
                    source_ip=ip,
                    event_type="ssh_client_version",
                    severity=AlertSeverity.LOW,
                    timestamp=when,
                    payload={"version": version, "session": session},
                )
            )


async def test_scattered_addresses_sharing_a_fingerprint_become_one_cluster():
    from honeypot_mcp.tools.analysis import cluster_ssh_clients, fingerprint_clusters

    for i in range(6):  # one botnet binary, six addresses
        await _kex(f"198.51.100.{i + 1}", "botnet-hassh", f"s{i}", version="SSH-2.0-Go")
    await _kex(
        "198.51.100.99", "botnet-hassh", "s99", version="SSH-2.0-Go"
    )  # same IP/other session
    await _kex("203.0.113.7", "openssh-hassh", "t1", version="SSH-2.0-OpenSSH_9.6")  # a one-off

    out = await cluster_ssh_clients(168, 2, 100)
    assert out["fingerprints_seen"] == 2
    assert out["clusters_matching"] == 1, "the lone OpenSSH client is below min_sources=2"
    cluster = out["clusters"][0]
    assert cluster["hassh"] == "botnet-hassh"
    assert cluster["distinct_ips"] == 7 and cluster["sessions"] == 7
    assert cluster["client_banners"] == [{"banner": "SSH-2.0-Go", "sessions": 7}]
    assert (
        len(cluster["example_ips"]) <= 10 and cluster["kex_offer_start"][0] == "curve25519-sha256"
    )

    # The tool trims the same cluster for an agent: fewer examples, no key-exchange offer.
    shown = (await fingerprint_clusters())["clusters"][0]
    assert shown["hassh"] == "botnet-hassh" and shown["distinct_ips"] == 7
    assert len(shown["example_ips"]) == 5 and "kex_offer_start" not in shown


async def test_min_sources_one_includes_every_fingerprint_largest_first():
    from honeypot_mcp.tools.analysis import fingerprint_clusters

    for i in range(3):
        await _kex(f"198.51.100.{i + 1}", "big", f"b{i}")
    await _kex("203.0.113.7", "small", "c1")
    out = await fingerprint_clusters(min_sources=1)
    assert [c["hassh"] for c in out["clusters"]] == ["big", "small"]


async def test_activity_outside_the_window_is_ignored():
    from honeypot_mcp.tools.analysis import fingerprint_clusters

    await _kex("198.51.100.1", "old", "o1", hours_ago=24 * 30)
    await _kex("198.51.100.2", "old", "o2", hours_ago=24 * 30)
    out = await fingerprint_clusters(hours=24)
    assert out["fingerprints_seen"] == 0 and "No SSH key-exchange" in out["note"]


async def test_hitting_the_scan_cap_is_reported_not_hidden(monkeypatch):
    from honeypot_mcp.tools import analysis

    monkeypatch.setattr(analysis, "_CLUSTER_SCAN_CAP", 3)
    for i in range(5):
        await _kex(f"198.51.100.{i + 1}", "h", f"s{i}")
    out = await analysis.fingerprint_clusters()
    assert out["truncated"] is True and "cap" in out["note"]
