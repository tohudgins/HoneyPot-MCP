"""File tokens must embed a URL the canary server actually answers on.

This pins the fix for a bug that made every PDF and DOCX token silently
inert. The old code built the embedded URL by stripping the scheme AND the
port off `CANARY_PUBLIC_URL` and prefixing a per-token subdomain:

    http://<token_uid>.canary.<host>/t/<token_uid>.png

That required a wildcard `*.canary.<domain>` DNS record nobody is told to
create, and it pointed at port 80 while the canary server listens on
`canary_callback_port` (default 8888). Tokens generated fine, planted fine,
and could never fire. Nothing in the suite noticed, because every other test
asserted on the *file structure* rather than on where the URL pointed.

So the assertions here are deliberately about reachability, not structure:
the embedded URL must be exactly `<canary_public_url>/t/<uid>.png`, and the
route it names must be one the canary server serves. `test_pdf_token_uri.py`
still covers the PDF trigger constructs themselves.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _reset_settings() -> None:
    """Drop the settings singleton so the next read picks up patched env.

    `get_settings` caches in a module global rather than via `lru_cache`, so
    there is no `cache_clear` to call.
    """
    from honeypot_mcp import config

    config._settings = None


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()


@pytest.fixture
def canary_url(monkeypatch, tmp_path):
    """Point the canary at a non-default host AND port.

    The port matters: the old bug was invisible whenever the public URL
    happened to carry no port, so a realistic value here is what makes the
    regression detectable.
    """
    monkeypatch.setenv("CANARY_PUBLIC_URL", "https://canary.example.com:8443")
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    _reset_settings()
    yield "https://canary.example.com:8443"
    monkeypatch.undo()
    _reset_settings()


async def _generate(file_type: str, tmp_path: Path) -> tuple[str, dict, Path]:
    from honeypot_mcp.tokens.file_token import FileTokenProvider

    uid, meta = await FileTokenProvider().create(
        {"file_type": file_type, "output_dir": str(tmp_path)}
    )
    return uid, meta, Path(meta["file_path"])


@pytest.mark.parametrize("file_type", ["pdf", "docx"])
async def test_embedded_url_is_the_canary_public_url(file_type, canary_url, tmp_path):
    """The URL baked into the file is one the canary server answers on."""
    uid, meta, path = await _generate(file_type, tmp_path)

    assert meta["tracking_url"] == f"{canary_url}/t/{uid}.png"

    blob = path.read_bytes()
    if file_type == "docx":
        with zipfile.ZipFile(path) as zf:
            blob = zf.read("word/_rels/document.xml.rels")

    assert meta["tracking_url"].encode() in blob, (
        f"{file_type} does not embed the tracking URL; the token cannot fire"
    )


@pytest.mark.parametrize("file_type", ["pdf", "docx"])
async def test_no_wildcard_dns_subdomain_is_embedded(file_type, canary_url, tmp_path):
    """The unreachable `<uid>.canary.<host>` form must never reach a file.

    `dns_canary` survives in metadata as an optional extra for operators who
    do run a wildcard record, but embedding it is what broke tokens before.
    """
    uid, meta, path = await _generate(file_type, tmp_path)

    blob = path.read_bytes()
    if file_type == "docx":
        with zipfile.ZipFile(path) as zf:
            blob = b"".join(zf.read(n) for n in zf.namelist())

    assert f"{uid}.canary.".encode() not in blob
    # The port must survive: stripping it is what aimed the old URL at :80.
    assert b":8443" in blob


@pytest.mark.parametrize("file_type", ["pdf", "docx"])
async def test_fetching_the_embedded_url_triggers_the_token(file_type, tmp_path, monkeypatch):
    """End-to-end: the URL in the file, fetched, fires the alert.

    This is the assertion the old suite was missing. Every other file-token
    test inspected document structure, so a URL pointing into the void passed
    them all. Here the canary server is started for real, the embedded URL is
    fetched verbatim, and the token must come back TRIGGERED.
    """
    from urllib.parse import urlparse

    from aiohttp.test_utils import TestClient, TestServer
    from sqlalchemy import select

    from honeypot_mcp.canary import build_app
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, Honeytoken, HoneytokenStatus
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    server = TestServer(build_app())
    client = TestClient(server)
    await client.start_server()
    try:
        # Point CANARY_PUBLIC_URL at the server that is actually listening,
        # so the token is generated exactly as it would be in the field.
        monkeypatch.setenv("CANARY_PUBLIC_URL", f"http://127.0.0.1:{server.port}")
        monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
        _reset_settings()

        created = await honeytoken_create(
            type="file",
            label=f"q3-financials.{file_type}",
            metadata={"file_type": file_type, "output_dir": str(tmp_path)},
        )
        tracking_url = created["metadata"]["tracking_url"]
        assert tracking_url.startswith(f"http://127.0.0.1:{server.port}/t/")

        resp = await client.get(urlparse(tracking_url).path)
        assert resp.status == 200
        assert resp.content_type == "image/png"

        async with get_session() as session:
            token = (
                await session.execute(select(Honeytoken).where(Honeytoken.id == created["id"]))
            ).scalar_one()
            assert token.status is HoneytokenStatus.TRIGGERED

            alerts = (await session.execute(select(Alert))).scalars().all()
            assert any(a.event_type == "honeytoken_triggered_file" for a in alerts)
    finally:
        await client.close()
        monkeypatch.undo()
        _reset_settings()
