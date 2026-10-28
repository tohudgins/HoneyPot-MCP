"""The single-use sign-in link that opens Grafana without anyone handling the password."""

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import httpx  # noqa: E402
import pytest  # noqa: E402

from honeypot_mcp import grafana_signin  # noqa: E402
from honeypot_mcp.config import get_settings  # noqa: E402
from honeypot_mcp.tools import _open  # noqa: E402
from honeypot_mcp.tools import grafana as grafana_tools  # noqa: E402


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import _window

    event_buffer.reset_for_tests()
    _window.reset_for_tests()
    await init_db()
    yield
    await close_db()
    _window.reset_for_tests()
    event_buffer.reset_for_tests()


class FakeGrafana:
    """Answers POST /login the way Grafana does: JSON in, a session cookie out (or 401)."""

    def __init__(self, accept: bool = True):
        self.accept, self.logins, self.server, self.port = accept, [], None, 0

    async def _handle(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        length = int(
            next(
                (
                    ln.split(b":")[1]
                    for ln in head.split(b"\r\n")
                    if ln.lower().startswith(b"content-length")
                ),
                b"0",
            )
        )
        body = await reader.readexactly(length) if length else b""
        self.logins.append((head.split(b" ")[0], json.loads(body or b"{}")))
        if self.accept:
            reply = b"HTTP/1.1 200 OK\r\nSet-Cookie: grafana_session=abc123; Path=/; HttpOnly\r\nContent-Length: 2\r\n\r\n{}"
        else:
            reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\n{}"
        writer.write(reply)
        await writer.drain()
        writer.close()

    async def __aenter__(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc):
        self.server.close()


async def _get(url: str, **kw) -> httpx.Response:
    async with httpx.AsyncClient(follow_redirects=False, timeout=5) as client:
        return await client.get(url, **kw)


async def test_the_link_signs_in_once_and_then_is_dead():
    async with FakeGrafana() as fake:
        dest = f"http://127.0.0.1:{fake.port}/d/honeypot-overview?orgId=1"
        link = await grafana_signin.mint(fake.port, "admin", "s3cret-pw", dest)

        first = await _get(link)
        assert first.status_code == 302 and first.headers["location"] == dest
        assert "grafana_session=abc123" in first.headers["set-cookie"]
        # the server logged in with the password itself; the link and the redirect never carry it
        assert fake.logins == [(b"POST", {"user": "admin", "password": "s3cret-pw"})]
        assert "s3cret-pw" not in link + first.headers["location"]

        await asyncio.sleep(0.1)
        with pytest.raises(httpx.ConnectError):
            await _get(link)


async def test_a_wrong_path_or_a_rebinding_host_gets_nothing_and_does_not_burn_the_link():
    async with FakeGrafana() as fake:
        link = await grafana_signin.mint(fake.port, "admin", "pw", "http://127.0.0.1:1/")
        origin, token = link.rsplit("/", 1)

        assert (await _get(f"{origin}/not-the-token")).status_code == 404
        assert (await _get(link, headers={"Host": "attacker.example"})).status_code == 404
        assert fake.logins == []  # nothing logged in for either

        assert (await _get(link)).status_code == 302  # the real link still works


async def test_a_refused_login_is_reported_and_sets_no_cookie():
    async with FakeGrafana(accept=False) as fake:
        link = await grafana_signin.mint(fake.port, "admin", "wrong", "http://127.0.0.1:1/")
        resp = await _get(link)
        assert resp.status_code == 502 and "set-cookie" not in resp.headers
        assert b"new link" in resp.content


async def test_an_unused_link_expires(monkeypatch):
    monkeypatch.setattr(grafana_signin, "LIFETIME_SECONDS", 0.2)
    async with FakeGrafana() as fake:
        link = await grafana_signin.mint(fake.port, "admin", "pw", "http://127.0.0.1:1/")
        await asyncio.sleep(0.5)
        with pytest.raises(httpx.ConnectError):
            await _get(link)


# ── what the tool does with the link ──────────────────────────────────────────


@pytest.fixture
def running_result():
    return {
        "running": True,
        "port": 3001,
        "dashboard_urls": {"Overview": "http://127.0.0.1:3001/d/honeypot-overview"},
        "read_password_with": "cat /x/admin_password",
        "password_file": "/x/admin_password",
        "datasource_ok": True,
        "dashboards": ["Overview"],
    }


@pytest.fixture
def minted(monkeypatch, tmp_path):
    """A password file, a recorded mint call and a recorded browser open."""
    (tmp_path / "admin_password").write_text("pw\n")
    monkeypatch.setattr(get_settings(), "grafana_dir", tmp_path)
    calls = {"mint": [], "open": []}

    async def fake_mint(port, user, password, destination):
        calls["mint"].append((port, user, password, destination))
        return "http://127.0.0.1:50000/tok"

    async def fake_open(url):
        calls["open"].append(url)
        return True

    monkeypatch.setattr(grafana_tools.grafana_signin, "mint", fake_mint)
    monkeypatch.setattr(grafana_tools, "open_page", fake_open)
    return calls


async def test_start_opens_the_signed_in_page_and_every_link_carries_the_data_range(
    running_result, minted, monkeypatch
):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    from honeypot_mcp.tools import _window

    _window.reset_for_tests()
    newest = datetime(2026, 10, 16, 14, 42, tzinfo=UTC)
    async with get_session() as session:
        for hours in (100, 0):  # in arrival order: the event buffer keeps rows chronological
            session.add(
                Alert(
                    source_ip="203.0.113.5",
                    event_type="x",
                    severity=AlertSeverity.LOW,
                    timestamp=newest - timedelta(hours=hours),
                    payload={},
                )
            )

    await grafana_tools._add_links(running_result, open_now=True)

    assert running_result["signed_in_url"] == "http://127.0.0.1:50000/tok"
    assert running_result["opened_in_browser"] is True and minted["open"] == [
        "http://127.0.0.1:50000/tok"
    ]
    assert "read_password_with" not in running_result  # nobody is told to go read a file
    assert "password_file" not in running_result and "cat " not in str(running_result)
    # a frozen run opens on the days the data covers, not on "the last 6 hours" (empty)
    # the oldest hour (rollups are hourly), whatever order the rows were inserted in
    start_ms = int((newest - timedelta(hours=100)).replace(minute=0).timestamp() * 1000)
    end_ms = int(newest.timestamp() * 1000)
    assert running_result["dashboard_urls"]["Overview"].endswith(
        f"?orgId=1&from={start_ms}&to={end_ms}&timezone=utc"
    )
    assert minted["mint"][0][:3] == (3001, "admin", "pw")


async def test_status_returns_a_link_but_does_not_open_a_browser(
    running_result, minted, monkeypatch
):
    monkeypatch.setattr(get_settings(), "analysis_mode", False)

    await grafana_tools._add_links(running_result, open_now=False)

    assert running_result["signed_in_url"] and running_result["opened_in_browser"] is False
    assert minted["open"] == []
    # a live server opens on the last day, ending now
    assert "&timezone=utc" in running_result["dashboard_urls"]["Overview"]


async def test_without_a_password_file_the_plain_urls_and_password_file_are_kept(
    running_result, tmp_path, monkeypatch
):
    monkeypatch.setattr(get_settings(), "grafana_dir", tmp_path)  # no admin_password in it

    await grafana_tools._add_links(running_result, open_now=True)

    assert "signed_in_url" not in running_result
    assert running_result["read_password_with"] == "cat /x/admin_password"
    assert (
        running_result["password_file"] == "/x/admin_password"
    )  # no link: the file is the only way in


def test_the_headline_says_what_the_person_can_do_now():
    opened = grafana_tools._headline(
        {
            "running": True,
            "dashboards": ["a", "b"],
            "opened_in_browser": True,
            "datasource_ok": True,
        }
    )
    link = grafana_tools._headline(
        {"running": True, "dashboards": ["a"], "signed_in_url": "u", "datasource_ok": False}
    )

    assert "open in your browser" in opened and "reads data fine" in opened
    assert "signed_in_url" in link and "panels will be empty" in link
    assert grafana_tools._headline({"running": False}) == "Grafana is not running."


# ── opening a page ────────────────────────────────────────────────────────────


async def test_a_page_opens_only_on_the_persons_own_machine(monkeypatch):
    opened = []
    monkeypatch.setattr(_open.webbrowser, "open", lambda url, new=0: opened.append(url) or True)
    settings = get_settings()

    for transport, flag, expect in (
        ("stdio", True, True),
        ("http", True, False),
        ("stdio", False, False),
    ):
        monkeypatch.setattr(settings, "mcp_transport", transport)
        monkeypatch.setattr(settings, "open_in_browser", flag)
        opened.clear()
        assert await _open.open_page("http://127.0.0.1:1/") is expect
        assert bool(opened) is expect

    monkeypatch.setattr(settings, "mcp_transport", "stdio")
    monkeypatch.setattr(settings, "open_in_browser", True)
    monkeypatch.setattr(
        _open.webbrowser,
        "open",
        lambda url, new=0: (_ for _ in ()).throw(RuntimeError("no display")),
    )
    assert await _open.open_page("http://127.0.0.1:1/") is False  # a headless host never raises
