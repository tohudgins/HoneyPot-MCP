"""PDF file-token /URI action test.

Verifies that the PDF generated for a FILE-type honeytoken contains both
trigger paths:

1. An `/OpenAction` URI dict on the document catalog (fires on document
   open in Acrobat / Foxit / desktop readers, subject to "Trust this URL?"
   prompts).
2. The canary URL string itself somewhere in the PDF bytes (the
   `linkAbsolute` click annotation, the safety-net path for readers that
   ignore `/OpenAction`).

We can't assert Acrobat-level behaviour from CI, but the presence of both
trigger constructs in the raw bytes is the next-best verification — they're
exactly what makes the difference between "PDF opens" and "canary fires".
"""

from __future__ import annotations

import os
from pathlib import Path

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


@pytest.mark.asyncio
async def test_pdf_token_contains_open_action_uri(tmp_path, monkeypatch):
    """The reportlab-backed PDF path must inject `/OpenAction` URI into the
    catalog AND embed the canary URL inline.

    We chdir to tmp_path so the FileTokenProvider's `reports/generated`
    output directory lands inside the temp tree and gets cleaned up
    automatically — without this the test litters the repo with PDFs.
    """
    monkeypatch.chdir(tmp_path)

    from honeypot_mcp.tokens.file_token import FileTokenProvider

    provider = FileTokenProvider()
    token_uid, meta = await provider.create({"file_type": "pdf"})

    pdf_path = Path(meta["file_path"])
    # The provider may use a path relative to cwd; resolve it.
    if not pdf_path.is_absolute():
        pdf_path = tmp_path / pdf_path
    assert pdf_path.exists(), f"expected PDF at {pdf_path}"
    pdf_bytes = pdf_path.read_bytes()

    # Sanity: it really is a PDF
    assert pdf_bytes.startswith(b"%PDF-")

    # Primary trigger: /OpenAction URI dict on the catalog. This is what
    # fires in Acrobat on document open (subject to Trust-this-URL prompt).
    assert b"/OpenAction" in pdf_bytes, "PDF missing /OpenAction — won't fire on open"
    assert b"/URI" in pdf_bytes, "PDF missing /URI action type"

    # The canary URL itself must be in the bytes — both the OpenAction and
    # the linkAbsolute click annotation point at it.
    canary_url = f"http://{meta['dns_canary']}/t/{token_uid}.png"
    assert canary_url.encode() in pdf_bytes, f"PDF doesn't reference the canary URL {canary_url!r}"


@pytest.mark.asyncio
async def test_pdf_manual_fallback_includes_uri_action(tmp_path):
    """If reportlab is unavailable the manual-PDF fallback must still embed
    the `/URI` action. Otherwise reportlab-less deployments ship inert
    tokens — exactly the gap this fix closes.

    We exercise the fallback directly because the import-failure path is
    hard to trigger from the test without rewriting the production import.
    """
    from honeypot_mcp.tokens.file_token import _write_minimal_pdf_with_uri_action

    target = tmp_path / "fallback.pdf"
    url = "http://test.canary.example/t/deadbeef.png"
    _write_minimal_pdf_with_uri_action(str(target), "Sensitive Report", url)

    pdf_bytes = target.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"/OpenAction" in pdf_bytes
    assert b"/URI" in pdf_bytes
    assert url.encode() in pdf_bytes
    # Xref table must point at a valid trailer so the PDF is well-formed.
    assert b"startxref" in pdf_bytes
    assert b"%%EOF" in pdf_bytes
