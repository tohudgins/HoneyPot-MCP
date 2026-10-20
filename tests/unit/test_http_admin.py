"""The HTTP honeypot's authenticated admin console.

`POST /login` used to answer 401 to everything, so a credential-spraying bot (which
only moves on after a success) never showed us what it does with a foothold. A
narrow set of credentials now logs in: a planted honeytoken, or the one weak pair
this honeypot derives from its name.
"""

import asyncio
import os
import re

import httpx
import pytest
from sqlalchemy.exc import OperationalError

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

NAME = "http-admin-test"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    credential_match.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


async def _start(config: dict | None = None) -> tuple[int, object, str]:
    from honeypot_mcp.engines.http import HTTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(Honeypot(name=NAME, type=HoneypotType.HTTP, port=port))
        await session.flush()
    engine = HTTPEngine()
    cid = await engine.start(NAME, port, {"persona": "apache_ubuntu", **(config or {})})
    return port, engine, cid


async def _alerts(event_type: str) -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    for _ in range(40):
        try:
            async with get_session() as session:
                rows = (
                    (await session.execute(select(Alert).where(Alert.event_type == event_type)))
                    .scalars()
                    .all()
                )
        except OperationalError:
            await asyncio.sleep(0.1)  # in-memory SQLite: a read can land mid-commit
            continue
        if rows:
            return list(rows)
        await asyncio.sleep(0.1)
    return []


def _derived() -> tuple[str, str]:
    from honeypot_mcp.engines.http_admin import derive_login

    return derive_login(NAME)


async def test_the_derived_pair_logs_in_and_other_credentials_do_not():
    port, engine, cid = await _start()
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            bad = await c.post(f"{base}/login", data={"username": user, "password": "nope"})
            assert bad.status_code == 401
            denied = await c.get(f"{base}/dashboard")
            assert denied.status_code == 302 and denied.headers["location"] == "/login"

            ok = await c.post(f"{base}/login", data={"username": user, "password": password})
            assert ok.status_code == 302 and ok.headers["location"] == "/dashboard"
            home = await c.get(f"{base}/dashboard")
            assert home.status_code == 200 and "Dashboard" in home.text
            assert f"Signed in as {user}" in home.text
    finally:
        await engine.stop(cid)


async def test_a_successful_login_and_the_visitors_next_requests_are_recorded():
    port, engine, cid = await _start()
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient() as c:
            await c.post(f"{base}/login", data={"username": user, "password": password})
            await c.get(f"{base}/admin/users")
    finally:
        await engine.stop(cid)
    success = await _alerts("http_login_success")
    assert success and success[0].payload["username"] == user
    assert success[0].payload["planted_credential"] is False
    follow_up = await _alerts("http_authenticated_request")
    assert follow_up and follow_up[0].payload["authenticated_as"] == user
    assert follow_up[0].severity.value == "high"


async def test_backup_size_on_the_page_is_the_length_of_the_download():
    port, engine, cid = await _start()
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient() as c:
            await c.post(f"{base}/login", data={"username": user, "password": password})
            page = (await c.get(f"{base}/admin/backup")).text
            listed = {
                name: int(size.replace(",", ""))
                for name, size in re.findall(
                    r'href="/admin/backup/([^"]+)">[^<]+</a></td><td>([\d,]+) bytes', page
                )
            }
            assert set(listed) == {"db_dump.sql.gz", "site_backup.tar.gz"}
            for name, size in listed.items():
                got = await c.get(f"{base}/admin/backup/{name}")
                assert got.status_code == 200 and len(got.content) == size, name
            missing = await c.get(f"{base}/admin/backup/nope.zip")
            assert missing.status_code == 404
    finally:
        await engine.stop(cid)


async def test_an_upload_after_login_is_captured_as_an_authenticated_request():
    port, engine, cid = await _start()
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient() as c:
            await c.post(f"{base}/login", data={"username": user, "password": password})
            r = await c.post(
                f"{base}/admin/upload",
                files={"file": ("shell.php", b"<?php system($_GET['c']); ?>", "application/x-php")},
            )
            assert r.status_code == 200 and "uploaded successfully" in r.text
    finally:
        await engine.stop(cid)
    events = await _alerts("http_exploit_attempt") or await _alerts("http_authenticated_request")
    assert events
    assert any(e.payload.get("authenticated_as") == user for e in events)


async def test_logout_ends_the_session():
    port, engine, cid = await _start()
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            await c.post(f"{base}/login", data={"username": user, "password": password})
            assert (await c.get(f"{base}/dashboard")).status_code == 200
            out = await c.get(f"{base}/logout")
            assert out.status_code == 302 and out.headers["location"] == "/login"
            assert (await c.get(f"{base}/dashboard")).status_code == 302
    finally:
        await engine.stop(cid)


async def test_an_empty_accepted_logins_list_turns_the_area_off():
    port, engine, cid = await _start({"accepted_logins": []})
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            r = await c.post(f"{base}/login", data={"username": user, "password": password})
            assert r.status_code == 401
            assert (await c.get(f"{base}/dashboard")).status_code == 404
    finally:
        await engine.stop(cid)


async def test_configured_logins_replace_the_derived_pair():
    port, engine, cid = await _start({"accepted_logins": ["root:Sup3rSecret"]})
    base = f"http://127.0.0.1:{port}"
    user, password = _derived()
    try:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            derived = await c.post(f"{base}/login", data={"username": user, "password": password})
            assert derived.status_code == 401
            ok = await c.post(f"{base}/login", data={"username": "ROOT", "password": "Sup3rSecret"})
            assert ok.status_code == 302  # usernames are case-insensitive, passwords are not
            wrong = await c.post(
                f"{base}/login", data={"username": "root", "password": "supersecret"}
            )
            assert wrong.status_code == 401
    finally:
        await engine.stop(cid)


async def test_a_planted_honeytoken_credential_logs_in_and_is_flagged():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label="http-planted",
                token_value="cred:http-planted",
                status=HoneytokenStatus.ACTIVE,
                token_meta={
                    "service": "http",
                    "credentials": [{"username": "svc-portal", "password": "Zx9!kLm2#qq"}],
                },
            )
        )
    port, engine, cid = await _start({"accepted_logins": []})  # no weak pair at all
    base = f"http://127.0.0.1:{port}"
    try:
        async with httpx.AsyncClient(follow_redirects=False) as c:
            r = await c.post(
                f"{base}/login", data={"username": "svc-portal", "password": "Zx9!kLm2#qq"}
            )
            assert r.status_code == 302, "a planted credential should be let in to see what happens"
            assert (await c.get(f"{base}/dashboard")).status_code == 200
    finally:
        await engine.stop(cid)
    success = await _alerts("http_login_success")
    assert success and success[0].payload["planted_credential"] is True
    assert await _alerts("honeytoken_triggered_credential_via_http_credential_submit")


async def test_the_derived_pair_is_stable_per_honeypot_and_drawn_from_the_weak_pool():
    from honeypot_mcp.engines.http_admin import _WEAK_PASSWORDS, _WEAK_USERS, derive_login

    assert derive_login("a") == derive_login("a")
    user, password = derive_login("a")
    assert user in _WEAK_USERS and password in _WEAK_PASSWORDS
    assert len({derive_login(f"sensor-{i}") for i in range(40)}) > 3  # sensors differ
