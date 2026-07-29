"""Tests for the live operations console.

The console is the only part of the system anyone can reach with a browser, so
two properties matter beyond "it renders": it must never accept a state change
(the control plane is MCP, and this page has no authentication), and it must
degrade to something readable when there is nothing to show.
"""

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


async def _seed(ip="203.0.113.5", n=1, severity="low", event_type="http_probe", hours_ago=0.1):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for _ in range(n):
            session.add(
                Alert(
                    source_ip=ip,
                    event_type=event_type,
                    payload={
                        "username": "admin",
                        "password": "changeme",
                        "headers": {"X-Big": "A" * 5000},
                        "enrichment": {"geoip": {"country": "Neverland"}},
                    },
                    severity=AlertSeverity(severity),
                    timestamp=datetime.now(UTC) - timedelta(hours=hours_ago),
                )
            )


@pytest.mark.asyncio
async def test_console_is_read_only():
    """No authentication guards this page, so it must expose no way to change
    anything — deploying and stopping honeypots stays on the MCP control plane."""
    from honeypot_mcp.console import build_console_app

    app = build_console_app()
    methods = {m for route in app.router.routes() for m in [route.method]}
    assert methods <= {"GET", "HEAD"}, f"console exposes non-read methods: {methods}"


@pytest.mark.asyncio
async def test_overview_reports_the_shape_the_page_expects():
    from honeypot_mcp.console.server import _overview

    await _seed(n=3, severity="critical")
    await _seed(ip="198.51.100.2", n=2, severity="low")

    data = await _overview(24)
    assert set(data) >= {"stats", "series", "top_attackers", "top_countries", "honeypots", "feed"}
    assert data["stats"]["events"] == 5
    assert data["stats"]["unique_ips"] == 2
    assert data["stats"]["critical"] == 3
    assert data["stats"]["untriaged"] == 5
    assert data["top_countries"][0]["country"] == "Neverland"
    assert data["series"]["points"], "series must always carry buckets to plot"


@pytest.mark.asyncio
async def test_feed_carries_a_digest_not_the_raw_payload():
    """The console polls every 5 seconds; shipping full captures would move
    megabytes a minute and tell the viewer nothing extra."""
    from honeypot_mcp.console.server import _overview

    await _seed(n=1, severity="high")
    entry = (await _overview(24))["feed"][0]

    assert entry["digest"]["username"] == "admin"
    assert "headers" not in entry["digest"]
    assert "payload" not in entry


@pytest.mark.asyncio
async def test_empty_database_still_produces_a_renderable_payload():
    """A fresh install opens the console before anything has been deployed."""
    from honeypot_mcp.console.server import _overview

    data = await _overview(24)
    assert data["stats"]["events"] == 0
    assert data["feed"] == []
    assert data["honeypots"] == []
    assert data["series"]["points"], "an empty window still needs an axis"


@pytest.mark.asyncio
async def test_time_window_filters_and_buckets_scale():
    from honeypot_mcp.console.server import _overview

    await _seed(n=2, hours_ago=0.2)
    await _seed(n=5, hours_ago=100)

    assert (await _overview(1))["stats"]["events"] == 2
    assert (await _overview(168))["stats"]["events"] == 7

    # Buckets stay in a plottable range regardless of window length.
    for hours in (1, 6, 24, 168):
        points = (await _overview(hours))["series"]["points"]
        assert 5 <= len(points) <= 60, f"{hours}h produced {len(points)} buckets"


@pytest.mark.asyncio
async def test_series_splits_routine_from_serious():
    """Two series, not four: the split that drives a decision is 'noise or
    something I act on'. Four severity bands cannot be reliably told apart as
    adjacent stacked marks."""
    from honeypot_mcp.console.server import _overview

    await _seed(n=4, severity="low")
    await _seed(n=3, severity="critical")
    await _seed(n=2, severity="high")

    points = (await _overview(24))["series"]["points"]
    assert sum(p["routine"] for p in points) == 4
    assert sum(p["serious"] for p in points) == 5


@pytest.mark.asyncio
async def test_index_serves_the_page():
    from honeypot_mcp.console.server import _handle_index

    response = await _handle_index(None)
    assert response.status == 200
    assert response.content_type == "text/html"
    assert "HoneyPot MCP" in response.text


@pytest.mark.asyncio
async def test_console_never_leaks_the_python_stack():
    """Same rule as the honeypots: no response advertises the implementation."""
    from aiohttp import web

    from honeypot_mcp.console.server import build_console_app

    app = build_console_app()
    middleware = app.middlewares[0]

    async def handler(_request):
        return web.Response(text="x")

    response = await middleware(None, handler)
    assert "aiohttp" not in response.headers.get("Server", "").lower()
