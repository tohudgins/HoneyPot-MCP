"""The SMTP honeypot's command rules, driven by the standard library's `smtplib`.

Real Postfix refuses MAIL/RCPT/DATA out of sequence, says 550 5.1.1 for a mailbox
it does not have, and answers VRFY per mailbox. The old engine accepted every
RCPT (so a directory-harvest run learned nothing and moved on) and answered every
VRFY with the same 252 — a reply that is itself the tell.
"""

import asyncio
import os
import smtplib
import socket

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
async def smtp_port(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp.engines.smtp import SMTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        session.add(Honeypot(name="smtp-pf", type=HoneypotType.SMTP, port=port))
        await session.flush()
    engine = SMTPEngine()
    cid = await engine.start("smtp-pf", port, {"smtp_hostname": "mail.corp.local"})
    yield port
    await engine.stop(cid)


async def _run(fn, *args):
    return await asyncio.to_thread(fn, *args)


def _client(port: int) -> smtplib.SMTP:
    c = smtplib.SMTP("127.0.0.1", port, timeout=5)
    c.ehlo("scanner.example")
    return c


async def test_commands_out_of_sequence_get_postfixs_503(smtp_port):
    def run() -> dict:
        c = _client(smtp_port)
        out = {
            "rcpt_first": c.docmd("RCPT TO:<info@corp.local>"),
            "data_first": c.docmd("DATA"),
        }
        c.docmd("MAIL FROM:<a@evil.example>")
        out["nested"] = c.docmd("MAIL FROM:<b@evil.example>")
        out["data_no_rcpt"] = c.docmd("DATA")
        c.quit()
        return out

    r = await _run(run)
    assert r["rcpt_first"][0] == 503 and b"need MAIL command" in r["rcpt_first"][1]
    assert r["data_first"][0] == 503
    assert r["nested"][0] == 503 and b"nested MAIL command" in r["nested"][1]
    assert r["data_no_rcpt"][0] == 554 and b"no valid recipients" in r["data_no_rcpt"][1]


async def test_unknown_local_mailbox_is_550_and_a_known_one_is_accepted(smtp_port):
    def run() -> dict:
        c = _client(smtp_port)
        c.docmd("MAIL FROM:<a@evil.example>")
        out = {
            "known": c.docmd("RCPT TO:<postmaster@corp.local>"),
            "unknown": c.docmd("RCPT TO:<zz-not-a-user@corp.local>"),
            "external": c.docmd("RCPT TO:<victim@other.example>"),
            "unqualified": c.docmd("RCPT TO:<someone>"),
        }
        c.quit()
        return out

    r = await _run(run)
    assert r["known"][0] == 250
    assert r["unknown"][0] == 550 and b"User unknown in local recipient table" in r["unknown"][1]
    assert r["external"][0] == 250  # the open-relay behaviour this honeypot exists to observe
    assert r["unqualified"][0] == 504


async def test_vrfy_distinguishes_real_mailboxes_from_missing_ones(smtp_port):
    def run() -> dict:
        c = _client(smtp_port)
        out = {
            "root": c.docmd("VRFY root"),
            "missing": c.docmd("VRFY zz-not-a-user"),
            "empty": c.docmd("VRFY"),
            "relay": c.docmd("VRFY someone@other.example"),
        }
        c.quit()
        return out

    r = await _run(run)
    assert r["root"][0] == 252 and b"root@mail.corp.local" in r["root"][1]
    assert r["missing"][0] == 550 and b"5.1.1" in r["missing"][1]
    assert r["empty"][0] == 501
    assert r["relay"][0] == 554 and b"Relay access denied" in r["relay"][1]


async def test_a_full_message_goes_through_and_rset_clears_the_envelope(smtp_port):
    def run() -> dict:
        c = _client(smtp_port)
        out = {}
        out["mail"] = c.docmd("MAIL FROM:<a@evil.example>")
        c.docmd("RCPT TO:<info@corp.local>")
        out["rset"] = c.docmd("RSET")
        out["rcpt_after_rset"] = c.docmd("RCPT TO:<info@corp.local>")  # 503: envelope cleared
        c.docmd("MAIL FROM:<a@evil.example>")
        c.docmd("RCPT TO:<info@corp.local>")
        out["data"] = c.docmd("DATA")  # 354: the server now expects the body
        c.send("Subject: hi\r\n\r\nbody\r\n.\r\n")
        out["queued"] = c.getreply()
        out["next_rcpt"] = c.docmd("RCPT TO:<info@corp.local>")  # transaction ended: 503
        c.quit()
        return out

    r = await _run(run)
    assert r["mail"][0] == 250 and r["rset"][0] == 250
    assert r["rcpt_after_rset"][0] == 503
    assert r["data"][0] == 354
    assert r["queued"][0] == 250 and b"queued as" in r["queued"][1]
    assert r["next_rcpt"][0] == 503


async def test_ehlo_greeting_matches_postfix_and_etrn_is_refused(smtp_port):
    def run() -> tuple:
        c = smtplib.SMTP("127.0.0.1", smtp_port, timeout=5)
        code, msg = c.ehlo("scanner.example")
        etrn = c.docmd("ETRN corp.local")
        bad_helo = c.docmd("EHLO")
        c.quit()
        return code, msg, etrn, bad_helo

    code, msg, etrn, bad_helo = await _run(run)
    assert code == 250
    assert msg.decode().splitlines()[0] == "mail.corp.local"  # Postfix: bare hostname, no "Hello"
    assert etrn[0] == 459
    assert bad_helo[0] == 501
