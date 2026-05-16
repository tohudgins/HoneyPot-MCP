"""Tests for the HTTP API attack-surface endpoints.

Verifies /.well-known/openid-configuration, /swagger.json, and /graphql
return believable responses that capture scanner traffic.
"""

import asyncio
import json
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
    await asyncio.sleep(0.1)
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
async def http_server():
    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="http-api-test", type=HoneypotType.HTTP, port=port)
        session.add(hp)
        await session.flush()

    engine = HTTPEngine()
    cid = await engine.start("http-api-test", port, {"persona": "nginx_stable"})
    try:
        yield port
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_openid_configuration_serves_valid_json(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/.well-known/openid-configuration")
    assert r.status_code == 200
    data = r.json()
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data
    # Plausible scope list
    assert "openid" in data["scopes_supported"]


@pytest.mark.asyncio
async def test_swagger_json_serves_openapi_spec(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/swagger.json")
    assert r.status_code == 200
    spec = r.json()
    assert spec["openapi"].startswith("3.")
    assert "paths" in spec
    # Should advertise some endpoints
    assert len(spec["paths"]) > 0


@pytest.mark.asyncio
async def test_graphql_introspection_returns_schema(http_server):
    """Standard `IntrospectionQuery` POST returns a believable __schema."""
    port = http_server
    body = {"query": "query IntrospectionQuery { __schema { queryType { name } } }"}
    async with httpx.AsyncClient() as client:
        r = await client.post(f"http://127.0.0.1:{port}/graphql", json=body)
    assert r.status_code == 200
    data = r.json()
    assert "data" in data
    assert "__schema" in data["data"]


@pytest.mark.asyncio
async def test_graphql_non_introspection_post_logged_as_high(http_server):
    """A POST that's NOT introspection = trying to actually query/mutate.
    Higher signal. Logged at HIGH severity."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"http://127.0.0.1:{port}/graphql",
                json={"query": "{ users { id email role } }"},
            )
        await asyncio.sleep(1.1)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "http_api_probe"))
        alerts = list(result.scalars().all())

    assert len(alerts) >= 1
    high = [a for a in alerts if a.severity == AlertSeverity.HIGH]
    assert high, "expected at least one HIGH-severity api_probe alert"


@pytest.mark.asyncio
async def test_graphql_unit_helpers_return_valid_json():
    """Direct unit test of the introspection/error body builders — runs
    without a server so we don't need to mock the request lifecycle."""
    from honeypot_mcp.engines.http_endpoints import (
        get_graphql_error,
        get_graphql_introspection,
    )

    schema = json.loads(get_graphql_introspection())
    assert "data" in schema and "__schema" in schema["data"]

    err = json.loads(get_graphql_error())
    assert "errors" in err
