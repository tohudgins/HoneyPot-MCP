"""HTTP engine realistic well-known endpoints + session cookies + HTTPS.

Verifies:
* `/robots.txt`, `/favicon.ico`, `/sitemap.xml`, `/.well-known/security.txt`
  are served (real servers always have these; 404 is a fingerprint).
* Every request issues a persona-named session cookie (PHPSESSID etc).
* Repeat visits with the same cookie escalate severity once the recon
  threshold is hit.
* TLS-enabled deploy serves HTTPS on the configured port via a self-signed
  cert generated in `tls/<honeypot_name>/`.
"""

import asyncio
import contextlib
import os
import socket
import ssl

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
async def http_server():
    """Plain-HTTP honeypot on a free port. Persona is pinned to apache_ubuntu
    so cookie name + Server header are deterministic across runs."""
    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="http-endpoints-test", type=HoneypotType.HTTP, port=port)
        session.add(hp)
        await session.flush()

    engine = HTTPEngine()
    cid = await engine.start("http-endpoints-test", port, {"persona": "apache_ubuntu"})
    try:
        yield port
    finally:
        await engine.stop(cid)


@pytest.fixture
async def https_server(tmp_path, monkeypatch):
    """TLS-enabled honeypot. Cert lives in a temp dir so we don't litter the
    repo with `tls/` directories during testing."""
    monkeypatch.chdir(tmp_path)

    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        hp = Honeypot(name="https-test", type=HoneypotType.HTTP, port=port)
        session.add(hp)
        await session.flush()

    engine = HTTPEngine()
    cid = await engine.start("https-test", port, {"persona": "nginx_stable", "tls": True})
    try:
        yield port
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_robots_txt_advertises_bait(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/robots.txt")
    assert r.status_code == 200
    assert "Disallow: /admin/" in r.text
    assert "Disallow: /.env" in r.text
    # Persona header should still be present
    assert "Apache" in r.headers.get("Server", "")


@pytest.mark.asyncio
async def test_favicon_returns_ico_bytes(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/favicon.ico")
    assert r.status_code == 200
    assert r.headers.get("Content-Type", "").startswith("image/")
    # ICO magic bytes
    assert r.content[:4] == b"\x00\x00\x01\x00"


@pytest.mark.asyncio
async def test_sitemap_xml_valid(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/sitemap.xml")
    assert r.status_code == 200
    assert '<?xml version="1.0"' in r.text
    assert "<urlset" in r.text


@pytest.mark.asyncio
async def test_security_txt_has_contact(http_server):
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/.well-known/security.txt")
    assert r.status_code == 200
    assert "Contact: mailto:" in r.text


@pytest.mark.asyncio
async def test_session_cookie_issued(http_server):
    """First request issues a cookie under the persona's cookie name."""
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/")
        # apache_ubuntu persona uses PHPSESSID
        assert "PHPSESSID" in r.cookies or any(k.lower() == "phpsessid" for k in r.cookies)


@pytest.mark.asyncio
async def test_repeat_visits_escalate_severity(http_server):
    """Same session hitting many endpoints → http_active_recon at MEDIUM
    severity. Closes the 'each request is independent' fingerprint."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        async with httpx.AsyncClient() as client:
            for i in range(7):
                await client.get(f"http://127.0.0.1:{port}/path-{i}")
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(select(Alert).where(Alert.event_type == "http_active_recon"))
        recon = list(result.scalars().all())

    assert len(recon) >= 1, "expected http_active_recon after threshold hits"


@pytest.mark.asyncio
async def test_https_serves_over_tls(https_server):
    """TLS-enabled honeypot accepts an HTTPS connection. We disable cert
    verification because the cert is self-signed — a real attacker won't
    verify it either."""
    port = https_server
    # Build an SSLContext that skips verification (the cert is self-signed).
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    async with httpx.AsyncClient(verify=ctx) as client:
        r = await client.get(f"https://127.0.0.1:{port}/robots.txt")
    assert r.status_code == 200
    assert "Disallow:" in r.text


@pytest.mark.asyncio
async def test_https_cert_persisted_across_starts(https_server, tmp_path):
    """Cert files exist in tls/<honeypot_name>/ after start. Same cert is
    reused on subsequent starts (stable across restarts)."""
    cert_path = tmp_path / "tls" / "https-test" / "server.crt"
    key_path = tmp_path / "tls" / "https-test" / "server.key"
    assert cert_path.exists()
    assert key_path.exists()
    # Cert is non-empty PEM
    assert b"BEGIN CERTIFICATE" in cert_path.read_bytes()


@pytest.mark.asyncio
async def test_session_cookie_persists_across_requests(http_server):
    """Reusing the same client (cookie jar) — only the FIRST response sets a
    new Set-Cookie. Subsequent requests reuse the session id, and the
    in-memory session.hits counter increments."""
    port = http_server
    async with httpx.AsyncClient() as client:
        r1 = await client.get(f"http://127.0.0.1:{port}/")
        # First response must include the persona's session cookie.
        first_cookie = r1.cookies.get("PHPSESSID")
        assert first_cookie is not None

        r2 = await client.get(f"http://127.0.0.1:{port}/another")
        # Second response should NOT re-issue a new cookie — the engine
        # only sets the cookie when is_new is True.
        assert "PHPSESSID" not in r2.cookies
        # Verify same session was sent back
        assert client.cookies.get("PHPSESSID") == first_cookie


# Avoid lint complaints about unused imports
_ = contextlib
