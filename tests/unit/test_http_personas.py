"""Tests for HTTP fingerprint resistance.

Verifies the persona module produces internally-consistent specs, that
different deploys can pick different personas, and end-to-end that a real
HTTP engine actually serves the chosen persona's Server header and 404 page.
"""

import os
from collections import Counter

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


# ── Persona module ────────────────────────────────────────────────────────────


def test_all_personas_have_required_fields():
    from honeypot_mcp.engines.http_personas import all_persona_ids, get_persona

    for pid in all_persona_ids():
        p = get_persona(pid)
        assert p.id == pid
        assert p.server_header
        assert p.cookie_name
        assert p.not_found_template
        assert p.jitter_ms_max >= p.jitter_ms_min >= 0


def test_get_persona_falls_back_for_unknown_id():
    from honeypot_mcp.engines.http_personas import get_persona

    # An old config row with a since-removed persona id shouldn't crash.
    p = get_persona("definitely_not_real")
    assert p.id == "apache_ubuntu"


def test_pick_random_persona_id_distributes():
    """Sample 100 picks; we ship 5 personas, so the chance of fewer than 2
    distinct over 100 trials is essentially zero. Catches a regression where
    pick_random_persona_id returns a constant."""
    from honeypot_mcp.engines.http_personas import all_persona_ids, pick_random_persona_id

    picks = Counter(pick_random_persona_id() for _ in range(100))
    assert len(picks) >= 2
    # All picks must be valid ids.
    valid = set(all_persona_ids())
    assert set(picks.keys()).issubset(valid)


def test_nginx_persona_does_not_advertise_php():
    """An Nginx persona claiming X-Powered-By: PHP would be the kind of
    inconsistent fingerprint a sophisticated attacker pivots on."""
    from honeypot_mcp.engines.http_personas import get_persona

    nginx = get_persona("nginx_stable")
    assert nginx.x_powered_by is None


def test_render_not_found_embeds_persona_identity():
    from honeypot_mcp.engines.http_personas import get_persona

    apache = get_persona("apache_ubuntu")
    body = apache.render_not_found("victim.local")
    assert "Apache/2.4.41" in body
    assert "victim.local" in body
    assert "<address>" in body  # Apache 404 specific marker

    nginx = get_persona("nginx_stable")
    body = nginx.render_not_found("victim.local")
    assert "nginx/1.18.0" in body
    assert "<center>" in body  # Nginx 404 specific marker


# ── End-to-end engine integration ─────────────────────────────────────────────


async def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _register_honeypot(name: str, port: int, persona_id: str | None = None) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    config = {"persona": persona_id} if persona_id else {}
    async with get_session() as session:
        hp = Honeypot(
            name=name,
            type=HoneypotType.HTTP,
            port=port,
            status=HoneypotStatus.RUNNING,
            config=config,
        )
        session.add(hp)
        await session.flush()
        return hp.id


@pytest.mark.asyncio
async def test_engine_serves_pinned_persona_headers():
    """If the config has a persona, start() must use it (no random pick).
    The Server header on a real request matches that persona."""
    import httpx

    from honeypot_mcp.engines.http import HTTPEngine

    port = await _free_port()
    await _register_honeypot("nginx-test", port, persona_id="nginx_stable")

    engine = HTTPEngine()
    container_id = await engine.start("nginx-test", port, {"persona": "nginx_stable"})
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://127.0.0.1:{port}/admin")
        assert resp.headers.get("Server") == "nginx/1.18.0"
        # Nginx persona must NOT advertise PHP.
        assert "X-Powered-By" not in resp.headers
    finally:
        await engine.stop(container_id)


@pytest.mark.asyncio
async def test_engine_persists_persona_when_unset():
    """If config has no persona, start() picks one and writes it back to the
    Honeypot row so subsequent restarts reuse it (stability across reboots)."""
    from sqlalchemy import select

    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot

    port = await _free_port()
    await _register_honeypot("auto-test", port)  # config={} — no persona pinned

    engine = HTTPEngine()
    container_id = await engine.start("auto-test", port, {})
    try:
        async with get_session() as session:
            result = await session.execute(select(Honeypot).where(Honeypot.name == "auto-test"))
            hp = result.scalar_one()
        assert "persona" in (hp.config or {})
        assert hp.config["persona"]  # non-empty string
    finally:
        await engine.stop(container_id)


@pytest.mark.asyncio
async def test_engine_serves_persona_specific_404():
    """Unknown path → persona's 404 (not the old 'generic_login' fallback)."""
    import httpx

    from honeypot_mcp.engines.http import HTTPEngine

    port = await _free_port()
    await _register_honeypot("404-test", port, persona_id="apache_ubuntu")

    engine = HTTPEngine()
    container_id = await engine.start("404-test", port, {"persona": "apache_ubuntu"})
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://127.0.0.1:{port}/this-does-not-exist")
        assert resp.status_code == 404
        # Apache-style 404 marker
        assert "<address>" in resp.text
        assert "Apache/2.4.41" in resp.text
        assert resp.headers.get("Server") == "Apache/2.4.41 (Ubuntu)"
    finally:
        await engine.stop(container_id)
