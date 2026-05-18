"""Elasticsearch honeypot tests.

Verifies the realistic cluster-banner endpoints respond with believable
JSON, and that data-access paths (`*_search`, `_bulk`, `_mget`) escalate
severity to HIGH.
"""

import asyncio
import os
import socket

import httpx
import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
async def es_server():
    from honeypot_mcp.engines.elasticsearch import ElasticsearchEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="es-test", type=HoneypotType.ELASTICSEARCH, port=port)
        session.add(hp)
        await session.flush()

    engine = ElasticsearchEngine()
    cid = await engine.start("es-test", port, {})
    try:
        yield port
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_root_returns_realistic_cluster_banner(es_server):
    """GET / must return the cluster banner JSON with version + tagline.
    Real Elasticsearch always emits these and a scanner pinning the
    response for fingerprinting will reject anything else."""
    port = es_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/")
    assert r.status_code == 200
    body = r.json()
    assert body["tagline"] == "You Know, for Search"
    assert body["version"]["number"].startswith("8.")
    assert body["cluster_name"]
    assert body["cluster_uuid"]


@pytest.mark.asyncio
async def test_cluster_health_returns_green(es_server):
    port = es_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/_cluster/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "green"
    assert body["number_of_nodes"] >= 1


@pytest.mark.asyncio
async def test_search_path_escalates_to_high_severity(es_server):
    """A POST to `/<index>/_search` is the canonical data-exfil shape."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = es_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"http://127.0.0.1:{port}/users/_search",
                json={"query": {"match_all": {}}, "size": 1000},
            )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "elasticsearch_data_access")
        )
        events = list(result.scalars().all())

    assert len(events) == 1
    assert events[0].severity.value == "high"
    body_preview = events[0].payload.get("body_preview", "")
    assert "match_all" in body_preview


@pytest.mark.asyncio
async def test_unknown_index_returns_404_json(es_server):
    """A bare GET to an unknown index path must return JSON
    `index_not_found_exception` — real Elasticsearch never serves
    HTML 404s and an HTML response is itself a fingerprint."""
    port = es_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/missing-index")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["error"]["type"] == "index_not_found_exception"
    assert body["status"] == 404
