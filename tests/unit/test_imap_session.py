"""The IMAP honeypot's mailbox, driven by stdlib `imaplib` and by `curl`.

Until now IMAP rejected every login, so everything past authentication was fiction. Now the
same credentials that open the POP3 mailbox (a planted honeytoken credential, or the one weak
pair derived from the honeypot's name) open the same read-only maildrop, and a client sees a
real mailbox: SELECT, SEARCH, FETCH of envelopes, structures and bodies, flags that last for
the session only. imaplib and curl are independent parsers of the protocol: if a literal's
length or a BODYSTRUCTURE parenthesis is off by one, they fail where a hand-written assertion
would not.
"""

from __future__ import annotations

import asyncio
import email
import imaplib
import os
import shutil
import smtplib
import socket
import subprocess
from email.message import EmailMessage

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

HOST = "mail.corp.local"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import credential_match, token_matchers
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
    event_buffer.reset_for_tests()
    credential_match.invalidate_cache()
    token_matchers.invalidate_cache()
    await close_db()


@pytest.fixture(autouse=True)
def fresh_maildrop(monkeypatch):
    from honeypot_mcp.engines import imap, maildrop, pop3, smtp

    drop = maildrop.Maildrop()
    for module in (maildrop, smtp, pop3, imap):
        monkeypatch.setattr(module, "MAILDROP", drop)
    monkeypatch.setattr(imap, "_AUTH_FAIL_DELAY", 0.05)
    return drop


@pytest.fixture
async def mail(tmp_path, monkeypatch):
    """SMTP and IMAP honeypots side by side; yields (smtp_port, imap_port)."""
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp.engines.imap import IMAPEngine
    from honeypot_mcp.engines.smtp import SMTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    smtp_port, imap_port = _free_port(), _free_port()
    async with get_session() as session:
        session.add(Honeypot(name="smtp-i", type=HoneypotType.SMTP, port=smtp_port))
        session.add(Honeypot(name="imap-i", type=HoneypotType.IMAP, port=imap_port))
        await session.flush()
    smtp_engine, imap_engine = SMTPEngine(), IMAPEngine()
    s_id = await smtp_engine.start("smtp-i", smtp_port, {"smtp_hostname": HOST})
    i_id = await imap_engine.start("imap-i", imap_port, {})
    yield smtp_port, imap_port
    await smtp_engine.stop(s_id)
    await imap_engine.stop(i_id)


def _weak() -> tuple[str, str]:
    from honeypot_mcp.engines.http_admin import derive_login

    return derive_login("imap-i")


def _login(port: int, user: str, password: str) -> imaplib.IMAP4:
    client = imaplib.IMAP4("127.0.0.1", port, timeout=15)
    client.login(user, password)
    return client


def _send(port: int, rcpt: str, subject: str, body: str = "hello") -> None:
    message = EmailMessage()
    message["From"], message["To"], message["Subject"] = "a@elsewhere.example.org", rcpt, subject
    message.set_content(body)
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as client:
        client.ehlo("scanner.example.net")
        client.send_message(message)


async def _drain() -> None:
    """Wait until the event buffer has written everything submitted so far. The test database
    is one shared in-memory SQLite connection, so a SELECT issued while the flusher commits
    raises `cannot commit transaction - SQL statements in progress`; the flusher retries for
    ~1.5 s and then drops the batch, which looked like a lost event."""
    from honeypot_mcp.storage import event_buffer

    buffer = event_buffer.get_buffer()
    for _ in range(200):
        if buffer.qsize() == 0:
            break
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.3)  # the batch just taken off the queue is still being written


async def _events(event_type: str, wait: float = 8.0) -> list:
    from sqlalchemy import select
    from sqlalchemy.exc import OperationalError

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    await _drain()  # query only once the flusher is idle: see _drain
    deadline = asyncio.get_event_loop().time() + wait
    while True:
        try:
            async with get_session() as session:
                rows = (await session.execute(select(Alert))).scalars().all()
        except OperationalError:  # the flusher is mid-commit on the shared in-memory database
            rows = []
        found = [a for a in rows if a.event_type == event_type]
        if found or asyncio.get_event_loop().time() > deadline:
            return found
        await asyncio.sleep(0.2)


async def test_the_weak_pair_opens_a_real_mailbox(mail):
    _, port = mail
    user, password = _weak()

    def session() -> dict:
        client = _login(port, user, password)
        out: dict = {}
        out["list"] = client.list()[1]
        status, data = client.select("INBOX")
        out["select"] = (status, int(data[0]))
        out["status"] = client.status("INBOX", "(MESSAGES UIDNEXT UIDVALIDITY UNSEEN)")[1]
        out["search"] = client.search(None, "ALL")[1][0].split()
        out["meta"] = client.fetch("1", "(FLAGS UID RFC822.SIZE INTERNALDATE ENVELOPE)")[1]
        out["structure"] = client.fetch("1", "(BODYSTRUCTURE)")[1]
        out["header"] = client.fetch("1", "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")[1]
        full = client.fetch("1", "(RFC822)")[1]
        out["rfc822"] = full[0][1]
        out["after"] = client.fetch("1", "(FLAGS)")[1]
        client.logout()
        return out

    got = await asyncio.to_thread(session)
    assert got["select"][0] == "OK" and got["select"][1] >= 2
    assert any(b'"INBOX"' in line for line in got["list"])
    assert any(b'"Sent"' in line and b"\\Sent" in line for line in got["list"])
    assert b"MESSAGES" in got["status"][0] and b"UIDVALIDITY" in got["status"][0]
    assert len(got["search"]) == got["select"][1]
    assert b"ENVELOPE" in got["meta"][0] and b"RFC822.SIZE" in got["meta"][0]
    assert b'"TEXT" "PLAIN"' in got["structure"][0]
    assert b"Subject:" in got["header"][0][1]
    parsed = email.message_from_bytes(got["rfc822"])
    assert parsed["Subject"] and parsed.get_payload().strip()
    assert b"\\Seen" in got["after"][0]  # a seed message is already read


async def test_mail_the_smtp_honeypot_accepted_is_readable_and_new(mail):
    smtp_port, imap_port = mail
    user, password = _weak()
    await asyncio.to_thread(_send, smtp_port, f"{user}@corp.local", "needle-4471", "find me")

    def session() -> dict:
        client = _login(imap_port, user, password)
        client.select("INBOX")
        hits = client.search(None, "SUBJECT", '"needle-4471"')[1][0].split()
        unseen = client.search(None, "UNSEEN")[1][0].split()
        number = hits[0].decode()
        uid_hits = client.uid("SEARCH", None, "SUBJECT", '"needle-4471"')[1][0].split()
        body = client.uid("FETCH", uid_hits[0].decode(), "(BODY.PEEK[TEXT])")[1][0][1]
        flags_after = client.fetch(number, "(FLAGS)")[1]
        client.logout()
        return {"hits": hits, "unseen": unseen, "body": body, "flags": flags_after}

    got = await asyncio.to_thread(session)
    assert len(got["hits"]) == 1
    assert got["hits"][0] in got["unseen"]  # delivered after the mailbox existed: unread
    assert b"find me" in got["body"]
    assert b"\\Seen" not in got["flags"][0]  # BODY.PEEK must not mark it read


async def test_a_body_fetch_marks_read_for_this_session_only(mail):
    smtp_port, imap_port = mail
    user, password = _weak()
    await asyncio.to_thread(_send, smtp_port, f"{user}@corp.local", "flag-test")

    def first() -> bytes:
        client = _login(imap_port, user, password)
        client.select("INBOX")
        number = client.search(None, "SUBJECT", "flag-test")[1][0].split()[0].decode()
        client.fetch(number, "(RFC822)")  # not PEEK
        flags = client.fetch(number, "(FLAGS)")[1][0]
        client.store(number, "+FLAGS", "(\\Flagged)")
        client.logout()
        return flags

    def second() -> bytes:
        client = _login(imap_port, user, password)
        client.select("INBOX")
        number = client.search(None, "SUBJECT", "flag-test")[1][0].split()[0].decode()
        flags = client.fetch(number, "(FLAGS)")[1][0]
        client.logout()
        return flags

    assert b"\\Seen" in await asyncio.to_thread(first)
    later = await asyncio.to_thread(second)
    assert (
        b"\\Seen" not in later and b"\\Flagged" not in later
    )  # one visitor cannot mark mail for the next


async def test_expunge_and_close_never_delete_from_the_shared_maildrop(mail):
    _, port = mail
    user, password = _weak()

    def delete_everything() -> tuple[int, int, int]:
        client = _login(port, user, password)
        count = int(client.select("INBOX")[1][0])
        client.store("1:*", "+FLAGS", "(\\Deleted)")
        expunged = [e for e in client.expunge()[1] if e]
        client.noop()
        left = int(client.select("INBOX")[1][0])  # this session's view is now empty
        client.logout()
        return count, len(expunged), left

    def count_again() -> int:
        client = _login(port, user, password)
        n = int(client.select("INBOX")[1][0])
        client.logout()
        return n

    original, removed, left = await asyncio.to_thread(delete_everything)
    assert removed == original and left == 0  # gone for this visitor...
    assert await asyncio.to_thread(count_again) == original  # ...but not for the next


async def test_examine_is_read_only(mail):
    _, port = mail
    user, password = _weak()

    def attempt():
        client = _login(port, user, password)
        status, _ = client.select("INBOX", readonly=True)
        result = client.store("1", "+FLAGS", "(\\Deleted)")
        client.logout()
        return status, result

    status, result = await asyncio.to_thread(attempt)
    assert status == "OK" and result[0] == "NO"


async def test_wrong_passwords_and_unknown_folders_are_refused(mail):
    _, port = mail
    user, password = _weak()
    with pytest.raises(imaplib.IMAP4.error):
        await asyncio.to_thread(_login, port, user, password + "x")
    with pytest.raises(imaplib.IMAP4.error):
        await asyncio.to_thread(_login, port, "root", "toor")

    def folders():
        client = _login(port, user, password)
        missing = client.select("NoSuchFolder")
        sent = client.select("Sent")
        append = client.append("NoSuchFolder", None, None, b"Subject: x\r\n\r\nx")
        create = client.create("Bad/../Name")
        client.logout()
        return missing, sent, append, create

    missing, sent, append, create = await asyncio.to_thread(folders)
    assert missing[0] == "NO" and sent[0] == "OK" and int(sent[1][0]) >= 1  # seeded, not empty
    assert append[0] == "NO" and create[0] == "NO"


async def test_authenticate_plain_and_login_mechanisms_both_log_in(mail):
    _, port = mail
    user, password = _weak()

    def plain() -> str:
        client = imaplib.IMAP4("127.0.0.1", port, timeout=15)
        status, _ = client.authenticate(
            "PLAIN", lambda _challenge: f"\0{user}\0{password}".encode()
        )
        client.logout()
        return status

    def login_mech() -> str:
        client = imaplib.IMAP4("127.0.0.1", port, timeout=15)
        replies = iter([user.encode(), password.encode()])
        status, _ = client.authenticate("LOGIN", lambda _challenge: next(replies))
        client.logout()
        return status

    assert await asyncio.to_thread(plain) == "OK"
    assert await asyncio.to_thread(login_mech) == "OK"


async def test_a_planted_credential_logs_in_and_trips_its_token(mail):
    _, port = mail
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_credentials

    created = await honeytoken_generate_credentials("planted-imap", count=1, service="imap")
    pair = created["metadata"]["credentials"][0]
    client = await asyncio.to_thread(_login, port, pair["username"], pair["password"])
    await asyncio.to_thread(client.logout)
    [login] = await _events("imap_login_success")
    assert login.payload["planted_credential"] is True
    tripped = await _events("honeytoken_triggered_credential_via_imap_login_attempt")
    assert tripped and tripped[0].severity.value == "critical"


async def test_a_canary_string_as_the_password_is_not_a_login(mail):
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    canary = "canary-0123456789abcdef@corp.local"
    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.DB_ROW, label="c", token_value=canary,
                status=HoneytokenStatus.ACTIVE, token_meta={"canary_email": canary},
            )
        )  # fmt: skip
    token_matchers.invalidate_cache()
    _, port = mail
    with pytest.raises(imaplib.IMAP4.error):
        await asyncio.to_thread(_login, port, "root", canary)


async def test_a_login_sent_as_literals_is_understood(mail):
    """The capability list says LITERAL+, so a client may send the password as a literal
    (non-synchronising, so its bytes follow immediately). Advertising it and mishandling it
    would be a tell."""
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(f"a1 LOGIN {user} {{{len(password)}+}}\r\n{password}\r\n".encode())
        await writer.drain()
        reply = (await asyncio.wait_for(reader.readline(), 10)).decode()
        assert reply.startswith("a1 OK"), reply
    finally:
        writer.close()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        # A synchronising literal: the server asks for the bytes, and the rest of the
        # command follows them on the same line.
        writer.write(f"a2 LOGIN {{{len(user)}}}\r\n".encode())
        await writer.drain()
        assert (await asyncio.wait_for(reader.readline(), 10)).startswith(b"+ ")
        writer.write(f"{user} {password}\r\n".encode())
        await writer.drain()
        assert (await asyncio.wait_for(reader.readline(), 10)).decode().startswith("a2 OK")
    finally:
        writer.close()


async def test_idle_waits_for_done(mail):
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        for line in (f"a LOGIN {user} {password}", "b SELECT INBOX"):
            writer.write(line.encode() + b"\r\n")
            await writer.drain()
            while not (await asyncio.wait_for(reader.readline(), 10)).startswith(
                (b"a OK", b"b OK")
            ):
                pass
        writer.write(b"c IDLE\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.readline(), 10)).startswith(b"+ idling")
        writer.write(b"DONE\r\n")
        await writer.drain()
        assert (await asyncio.wait_for(reader.readline(), 10)).startswith(b"c OK")
    finally:
        writer.close()


async def test_malformed_commands_get_bad_not_silence_or_a_crash(mail):
    _, port = mail
    user, password = _weak()

    # imaplib raises on BAD; collect which ones raised
    def run() -> list[str]:
        client = _login(port, user, password)
        client.select("INBOX")
        outcomes = []
        for call in (
            lambda: client.fetch("1", "(BOGUSITEM)"),
            lambda: client.search(None, "NOSUCHKEY"),
            lambda: client.fetch("a:b", "(FLAGS)"),
            lambda: client.store("1", "BOGUS", "(x)"),
            lambda: client.fetch("99", "(FLAGS)"),
        ):
            try:
                outcomes.append(call()[0])
            except imaplib.IMAP4.error:
                outcomes.append("BAD")
        client.logout()
        return outcomes

    assert await asyncio.to_thread(run) == ["BAD", "BAD", "BAD", "BAD", "OK"]


async def test_commands_before_selecting_or_logging_in_are_refused(mail):
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(b"a SELECT INBOX\r\n")
        await writer.drain()
        assert b"NO" in await asyncio.wait_for(reader.readline(), 10)  # not authenticated
        writer.write(f"b LOGIN {user} {password}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), 10)
        writer.write(b"c FETCH 1 (FLAGS)\r\n")  # logged in, nothing selected
        await writer.drain()
        assert b"BAD" in await asyncio.wait_for(reader.readline(), 10)
    finally:
        writer.close()


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
async def test_curl_can_list_and_read_a_message(mail):
    """curl is a third, independent IMAP client with its own strict response parser."""
    _, port = mail
    user, password = _weak()
    base = f"imap://127.0.0.1:{port}"

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["curl", "-sS", "--max-time", "20", "-u", f"{user}:{password}", *args],
            capture_output=True, timeout=40,
        )  # fmt: skip

    listing = await asyncio.to_thread(run, f"{base}/")
    assert listing.returncode == 0 and b"INBOX" in listing.stdout, listing.stderr
    message = await asyncio.to_thread(run, f"{base}/INBOX;UID=1")
    assert message.returncode == 0, message.stderr
    assert email.message_from_bytes(message.stdout)["Subject"]
    search = await asyncio.to_thread(run, f"{base}/INBOX", "-X", "SEARCH ALL")
    assert search.returncode == 0 and b"SEARCH" in search.stdout


async def test_a_peer_that_never_reads_cannot_make_the_server_buffer_without_bound():
    from honeypot_mcp.engines.imap import _IMAPProtocol

    class StuckPeer:
        aborted = False

        def get_write_buffer_size(self) -> int:
            return 10 * 1024 * 1024

        def is_closing(self) -> bool:
            return False

        def abort(self) -> None:
            self.aborted = True

        def write(self, data: bytes) -> None:
            raise AssertionError("wrote to a peer that is 10 MB behind")

    protocol = _IMAPProtocol("i", None)
    protocol._transport = StuckPeer()  # type: ignore[assignment]
    protocol._send_bytes(b"* 1 FETCH (RFC822 {5}\r\nhello)\r\n")
    assert protocol._transport.aborted  # type: ignore[union-attr]


async def test_fetch_events_are_recorded_and_capped(mail, monkeypatch):
    smtp_port, port = mail
    user, password = _weak()
    from honeypot_mcp.engines import imap

    monkeypatch.setattr(imap, "_MAX_FETCH_EVENTS", 2)

    def read_all() -> None:
        client = _login(port, user, password)
        client.select("INBOX")
        for n in range(1, 4):
            client.fetch(str(n), "(RFC822)")
        client.fetch("1", "(BODY.PEEK[HEADER])")  # headers alone are not "reading the mail"
        client.logout()

    await asyncio.to_thread(read_all)
    events = await _events("imap_message_fetched")
    await asyncio.sleep(0.5)
    events = await _events("imap_message_fetched")
    assert len(events) == 2 and events[0].payload["subject"]


# ── hardening found in review ────────────────────────────────────────────────


def _deliver(raw: bytes, mailbox: str = "poison") -> None:
    from honeypot_mcp.engines import maildrop

    maildrop.MAILDROP.deliver(mailbox, raw, domain="corp.local")


def _login_as(port: int, mailbox: str) -> imaplib.IMAP4:
    client = imaplib.IMAP4("127.0.0.1", port, timeout=20)
    client.login(*_open_account(mailbox))
    return client


def _open_account(mailbox: str) -> tuple[str, str]:
    """The weak pair for this honeypot, with the mailbox it opens: derived users map to
    mailboxes by name, so use the derived user's own mailbox."""
    return _weak()


async def test_a_non_ascii_attachment_name_does_not_break_bodystructure(mail):
    """RFC 2231 parameters come back from the parser as (charset, language, value) tuples; the
    formatter did `ord()` on them and the command never got a reply, hanging the client."""
    _, port = mail
    user, password = _weak()
    _deliver(
        b"From: a@x.example\r\nSubject: cv\r\nMIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
        b"--B\r\nContent-Type: application/pdf; name*=UTF-8''r%C3%A9sum%C3%A9.pdf\r\n"
        b"Content-Disposition: attachment; filename*0*=UTF-8''r%C3%A9; filename*1*=sum%C3%A9.pdf\r\n\r\nPDF\r\n--B--\r\n",
        mailbox=user,
    )

    def run() -> bytes:
        client = _login(port, user, password)
        client.select("INBOX")
        data = client.fetch("*", "(BODYSTRUCTURE)")[1]
        client.logout()
        return b" ".join(x if isinstance(x, bytes) else b"".join(x) for x in data)

    structure = await asyncio.wait_for(asyncio.to_thread(run), 20)
    assert "résumé.pdf".encode() in structure or b"r\xc3\xa9sum\xc3\xa9.pdf" in structure


@pytest.mark.parametrize(
    "poison",
    [
        pytest.param(
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
            + b"--b\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" * 1500,
            id="nested-multipart",
        ),
        pytest.param(
            b"Content-Type: message/rfc822\r\n\r\n" * 1000 + b"Subject: x\r\n\r\nbody",
            id="nested-message",
        ),
        pytest.param(
            b"From: a@x.example\r\nTo: " + b"a:" * 30000 + b"\r\n\r\nbody", id="address-groups"
        ),
    ],
)
async def test_one_hostile_message_cannot_break_fetch_for_the_mailbox(mail, poison):
    """The SMTP honeypot delivers up to 128 KB of attacker content to any mailbox. Parsing it
    overflowed the stack and the command got no reply, so FETCH 1:* failed for every visitor."""
    _, port = mail
    user, password = _weak()
    _deliver(poison[:120_000], mailbox=user)

    def run() -> list[str]:
        client = _login(port, user, password)
        client.select("INBOX")
        outcomes = []
        for items in (
            "(ENVELOPE)",
            "(BODYSTRUCTURE)",
            "(BODY.PEEK[1])",
            "(BODY.PEEK[HEADER])",
            "(FLAGS)",
        ):
            outcomes.append(client.fetch("1:*", items)[0])  # a hang would raise on the timeout
        outcomes.append(client.search(None, "FROM", "a")[0])
        outcomes.append(client.search(None, "BODY", "body")[0])
        client.logout()
        return outcomes

    assert set(await asyncio.wait_for(asyncio.to_thread(run), 60)) == {"OK"}


async def test_fetch_item_count_is_capped(mail):
    """A 32 KB line named thousands of RFC822 items; each was built before anything was sent
    (1.6 GB resident from one command)."""
    _, port = mail
    user, password = _weak()

    def run() -> tuple[str, str]:
        client = _login(port, user, password)
        client.select("INBOX")
        ok = client.fetch("1", "(" + " ".join(["FLAGS"] * 16) + ")")[0]
        try:
            client.fetch("1", "(" + " ".join(["RFC822"] * 17) + ")")
            bad = "OK"
        except imaplib.IMAP4.error:
            bad = "BAD"
        client.logout()
        return ok, bad

    assert await asyncio.to_thread(run) == ("OK", "BAD")


def test_list_patterns_are_matched_without_fnmatch_and_its_process_wide_cache():
    import fnmatch

    from honeypot_mcp.engines.imap import _wild_match

    before = fnmatch._compile_pattern.cache_info().currsize
    for n in range(300):
        assert _wild_match(f"{'x' * 100}{n}*", "INBOX") is False
    assert fnmatch._compile_pattern.cache_info().currsize == before
    assert _wild_match("*", "INBOX") and _wild_match("%", "Sent") and _wild_match("in*", "INBOX")
    assert (
        _wild_match("S%", "Sent") and _wild_match("*box", "INBOX") and _wild_match("I*B*X", "INBOX")
    )
    assert (
        not _wild_match("In", "INBOX")
        and not _wild_match("Sent?", "Sent")
        and not _wild_match("", "INBOX")
    )
    assert not _wild_match("*" * 200, "INBOX")  # over the length cap


async def test_keywords_per_message_are_bounded(mail):
    _, port = mail
    user, password = _weak()

    def run() -> list[str]:
        client = _login(port, user, password)
        client.select("INBOX")
        results = []
        many = " ".join(f"k{n}" for n in range(40))
        results.append(client.store("1", "+FLAGS.SILENT", f"({many})")[0])
        results.append(client.store("1", "+FLAGS.SILENT", f"({'x' * 100})")[0])
        results.append(client.store("1", "+FLAGS.SILENT", "(ok1 ok2)")[0])
        client.logout()
        return results

    assert await asyncio.to_thread(run) == ["NO", "NO", "OK"]


async def test_absurd_numbers_get_an_answer_not_silence(mail):
    """`int()` refuses more than 4300 digits; the exception killed the command with no reply."""
    _, port = mail
    user, password = _weak()
    huge = "9" * 5000
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        for line in (f"a LOGIN {user} {password}", "b SELECT INBOX"):
            writer.write(line.encode() + b"\r\n")
            await writer.drain()
            while not (await asyncio.wait_for(reader.readline(), 10)).startswith(
                (b"a OK", b"b OK")
            ):
                pass
        for n, command in enumerate(
            (f"FETCH {huge} FLAGS", f"UID FETCH {huge} FLAGS", "FETCH 1 BODY[1" + huge + "]",
             f"FETCH 1 BODY[]<{huge}>", "SEARCH " + "NOT " * 5000 + "ALL", "SEARCH " + "(" * 5000 + "ALL" + ")" * 5000)
        ):  # fmt: skip
            tag = f"t{n}"
            writer.write(f"{tag} {command}\r\n".encode())
            await writer.drain()
            reply = b""
            while not reply.startswith(tag.encode()):
                reply = await asyncio.wait_for(reader.readline(), 10)
            assert reply.startswith(
                (f"{tag} BAD".encode(), f"{tag} OK".encode(), f"{tag} NO".encode())
            ), (command[:30], reply)
    finally:
        writer.close()


async def test_a_login_with_two_literals_works(mail):
    _, port = mail
    user, password = _weak()
    for plus in ("", "+"):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await reader.readline()
            writer.write(f"a LOGIN {{{len(user)}{plus}}}\r\n".encode())
            await writer.drain()
            if not plus:
                assert (await asyncio.wait_for(reader.readline(), 10)).startswith(b"+ ")
            writer.write(f"{user} {{{len(password)}{plus}}}\r\n".encode())
            await writer.drain()
            if not plus:
                assert (await asyncio.wait_for(reader.readline(), 10)).startswith(b"+ ")
            writer.write(password.encode() + b"\r\n")
            await writer.drain()
            reply = (await asyncio.wait_for(reader.readline(), 10)).decode()
            assert reply.startswith("a OK"), (plus, reply)
        finally:
            writer.close()


async def test_a_multi_line_append_is_not_mistaken_for_a_flood(mail):
    """Literal bytes were counted as command lines, so any APPEND of an ordinary message was
    answered `* BYE Too fast` and the client was disconnected."""
    _, port = mail
    user, password = _weak()
    message = b"Subject: saved\r\n\r\n" + b"line\r\n" * 60

    def run() -> tuple[str, str]:
        client = _login(port, user, password)
        result = client.append("Sent", None, None, message)
        after = client.noop()[0]  # the connection is still usable
        client.logout()
        return result[0], after

    assert await asyncio.to_thread(run) == ("OK", "OK")


async def test_a_slow_but_honest_reader_receives_the_whole_mailbox(mail):
    """A 512 KB write-backlog limit aborted FETCH 1:* mid-response for a client that was merely
    slower than the loop; backpressure now waits for it instead."""
    _, port = mail
    user, password = _weak()
    for n in range(8):
        _deliver(b"Subject: big%d\r\n\r\n" % n + b"A" * 119_000, mailbox=user)

    reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=2**16)
    sock = writer.get_extra_info("socket")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
    try:
        await reader.readline()
        for line in (f"a LOGIN {user} {password}", "b SELECT INBOX"):
            writer.write(line.encode() + b"\r\n")
            await writer.drain()
            while not (await asyncio.wait_for(reader.readline(), 10)).startswith(
                (b"a OK", b"b OK")
            ):
                pass
        writer.write(b"c FETCH 1:* (BODY.PEEK[])\r\n")
        await writer.drain()
        received = 0
        tail = b""
        deadline = asyncio.get_event_loop().time() + 90
        while b"c OK" not in tail and asyncio.get_event_loop().time() < deadline:
            chunk = await asyncio.wait_for(reader.read(4096), 30)
            if not chunk:
                break
            received += len(chunk)
            tail = (tail + chunk)[-64:]
            await asyncio.sleep(0.001)  # a reader slower than the server
        assert b"c OK" in tail, f"response cut off after {received} bytes"
        assert received > 8 * 119_000
    finally:
        writer.close()


def test_a_tag_cannot_carry_line_breaks_into_a_reply():
    from honeypot_mcp.engines.imap import _tag_of

    assert _tag_of("a\rinjected * BYE NOOP") == "ainjected"
    assert _tag_of("*") == "*" and _tag_of("") == "*" and _tag_of("t1 NOOP") == "t1"
    assert len(_tag_of("x" * 500)) == 32


async def test_uid_expunge_is_not_a_command_here(mail):
    _, port = mail
    user, password = _weak()

    def run() -> str:
        client = _login(port, user, password)
        client.select("INBOX")
        try:
            client.uid("EXPUNGE", "1")
            return "OK"
        except imaplib.IMAP4.error:
            return "BAD"
        finally:
            client.logout()

    assert await asyncio.to_thread(run) == "BAD"  # UIDPLUS is not advertised


# ── folders, APPEND and COPY (session only) ──────────────────────────────────


async def test_the_other_folders_hold_ordinary_mail_that_never_changes(mail):
    """An empty Sent folder is a mailbox nobody has used; a visitor who checks notices."""
    _, port = mail
    user, password = _weak()

    def run() -> dict:
        client = _login(port, user, password)
        counts = {
            name: int(client.select(name)[1][0]) for name in ("Sent", "Drafts", "Trash", "Junk")
        }
        client.select("Sent")
        subjects = [
            m[1]
            for m in client.fetch("1:*", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")[1]
            if isinstance(m, tuple)
        ]
        first_date = client.fetch("1", "(INTERNALDATE)")[1][0]
        client.logout()
        return {"counts": counts, "subjects": subjects, "date": first_date}

    first, second = await asyncio.to_thread(run), await asyncio.to_thread(run)
    assert all(n >= 1 for n in first["counts"].values()) and first["counts"]["Sent"] >= 2
    assert first["subjects"] == second["subjects"] and first["date"] == second["date"]


async def test_a_visitor_can_create_fill_and_read_back_a_folder_but_only_for_this_connection(mail):
    _, port = mail
    user, password = _weak()
    draft = b"From: a@corp.local\r\nTo: b@corp.local\r\nSubject: wire transfer details\r\n\r\nline one\r\nline two\r\n"

    def first() -> dict:
        client = _login(port, user, password)
        out = {"create": client.create("Projects")[0]}
        out["dup"] = client.create("Projects")[0]
        out["bad"] = client.create("../etc")[0]
        out["list"] = [x.decode() for x in client.list()[1]]
        out["append"] = client.append("Projects", "(\\Seen)", None, draft)[0]
        out["select"] = client.select("Projects")[1][0]
        out["body"] = client.fetch("1", "(BODY.PEEK[TEXT])")[1][0][1]
        out["flags"] = client.fetch("1", "(FLAGS)")[1][0]
        out["missing"] = client.append("NoSuchFolder", None, None, draft)[0]
        client.logout()
        return out

    def second() -> list:
        client = _login(port, user, password)
        listing = [x.decode() for x in client.list()[1]]
        if client.select("Projects")[0] == "OK":
            listing.append("SELECTED")
        client.logout()
        return listing

    got = await asyncio.to_thread(first)
    assert (got["create"], got["dup"], got["bad"]) == ("OK", "NO", "NO")
    assert any('"Projects"' in line for line in got["list"]) and got["append"] == "OK"
    assert got["select"] == b"1" and got["body"] == b"line one\r\nline two\r\n"
    assert b"\\Seen" in got["flags"] and got["missing"] == "NO"
    other = await asyncio.to_thread(second)
    assert not any("Projects" in line for line in other) and "SELECTED" not in other
    [event] = await _events("imap_append")
    assert (
        event.payload["subject"] == "wire transfer details"
        and event.payload["folder"] == "Projects"
    )


async def test_append_to_the_inbox_and_copy_work_and_new_mail_still_arrives(mail):
    smtp_port, port = mail
    user, password = _weak()

    def run() -> dict:
        client = _login(port, user, password)
        before = int(client.select("INBOX")[1][0])
        client.append("INBOX", None, None, b"Subject: self-note\r\n\r\nremember\r\n")
        after_append = int(client.select("INBOX")[1][0])
        copy = client.copy("1", "Trash")
        trash = int(client.select("Trash")[1][0])
        missing = client.copy("1", "Nowhere")[0]
        client.logout()
        return {
            "before": before,
            "after": after_append,
            "copy": copy[0],
            "trash": trash,
            "missing": missing,
        }

    got = await asyncio.to_thread(run)
    assert got["after"] == got["before"] + 1 and got["copy"] == "OK" and got["trash"] >= 2
    assert got["missing"] == "NO"

    # mail the SMTP honeypot accepts after the visitor appended to the inbox still shows up
    def watch() -> tuple[int, int]:
        client = _login(port, user, password)
        client.select("INBOX")
        client.append("INBOX", None, None, b"Subject: mine\r\n\r\nx\r\n")
        count = int(client.select("INBOX")[1][0])
        _send(smtp_port, f"{user}@corp.local", "arrives-after-append")
        client.noop()
        found = len(client.search(None, "SUBJECT", "arrives-after-append")[1][0].split())
        client.logout()
        return count, found

    count, found = await asyncio.to_thread(watch)
    assert found == 1


async def test_system_folders_cannot_be_deleted_or_renamed_but_the_visitors_own_can(mail):
    _, port = mail
    user, password = _weak()

    def run() -> list[str]:
        client = _login(port, user, password)
        outcomes = [
            client.delete("Sent")[0],
            client.delete("INBOX")[0],
            client.rename("Sent", "Old")[0],
        ]
        client.create("Scratch")
        client.append("Scratch", None, None, b"Subject: s\r\n\r\nx\r\n")
        outcomes.append(client.rename("Scratch", "Renamed")[0])
        outcomes.append(str(int(client.select("Renamed")[1][0])))  # the message moved with it
        outcomes.append(client.delete("Renamed")[0])
        outcomes.append("still-there" if client.select("Renamed")[0] == "OK" else "gone")
        client.logout()
        return outcomes

    assert await asyncio.to_thread(run) == ["NO", "NO", "NO", "OK", "1", "OK", "gone"]


async def test_what_one_connection_adds_is_bounded(mail):
    _, port = mail
    user, password = _weak()

    def run() -> dict:
        client = _login(port, user, password)
        out = {"folders": [client.create(f"F{n}")[0] for n in range(12)].count("OK")}
        big = b"Subject: big\r\n\r\n" + b"A" * 100_000
        out["big"] = client.append("INBOX", None, None, big)[0]
        results = [client.append("INBOX", None, None, big)[0] for _ in range(6)]
        out["over"] = results.count("NO")
        small = [client.append("Sent", None, None, b"Subject: s\r\n\r\nx")[0] for _ in range(60)]
        out["small_ok"] = small.count("OK")
        client.logout()
        return out

    got = await asyncio.to_thread(run)
    assert got["folders"] == 8  # the cap, not twelve
    assert got["big"] == "OK" and got["over"] >= 1  # 512 KB per connection
    assert got["small_ok"] < 60


async def test_an_append_larger_than_the_cap_is_refused_like_any_oversized_literal(mail):
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(f"a LOGIN {user} {password}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), 10)
        writer.write(f"b APPEND INBOX {{{200 * 1024}+}}\r\n".encode())
        await writer.drain()
        reply = (await asyncio.wait_for(reader.readline(), 10)).decode()
        assert reply.startswith("b NO [TOOBIG]"), reply
    finally:
        writer.close()


async def test_new_folders_survive_status_list_and_uid_copy(mail):
    _, port = mail
    user, password = _weak()

    def run() -> list[str]:
        client = _login(port, user, password)
        client.create("Archive")
        status = client.status("Archive", "(MESSAGES UIDNEXT UIDVALIDITY)")[1][0].decode()
        client.select("INBOX")
        uid_copy = client.uid("COPY", "1:*", "Archive")[0]
        count = client.status("Archive", "(MESSAGES)")[1][0].decode()
        client.logout()
        return [status, uid_copy, count]

    status, uid_copy, count = await asyncio.to_thread(run)
    assert "MESSAGES 0" in status and "UIDNEXT 1" in status and uid_copy == "OK"
    assert "MESSAGES 0" not in count


async def test_parentheses_in_an_appended_message_are_not_read_as_its_flags(mail):
    """The flags group was searched for in the whole command line, which by then contained the
    message itself, so "call me (asap)" in a body became the flag `asap`."""
    _, port = mail
    user, password = _weak()

    def run() -> tuple[bytes, bytes]:
        client = _login(port, user, password)
        client.create("P")
        client.append("P", None, None, b"Subject: s\r\n\r\ncall me (asap) or (never)\r\n")
        client.append("P", "(\\Seen)", None, b"Subject: t\r\n\r\nwith real flags (ignored)\r\n")
        client.select("P")
        first = client.fetch("1", "(FLAGS)")[1][0]
        second = client.fetch("2", "(FLAGS)")[1][0]
        client.logout()
        return first, second

    first, second = await asyncio.to_thread(run)
    assert b"asap" not in first and b"never" not in first
    assert b"\\Seen" in second and b"ignored" not in second


async def test_uids_in_a_session_folder_are_never_reused_and_deleting_it_returns_its_budget(mail):
    """A client that cached "UID 2" must never see a different message under it after an
    EXPUNGE; and deleting a folder must free what it used so the byte budget cannot desync."""
    _, port = mail
    user, password = _weak()
    big = b"Subject: b\r\n\r\n" + b"B" * 100_000

    def run() -> dict:
        client = _login(port, user, password)
        client.create("U")
        for n in range(3):
            client.append("U", None, None, b"Subject: m%d\r\n\r\nx" % n)
        client.select("U")
        client.store("3", "+FLAGS", "(\\Deleted)")
        client.expunge()
        client.append("U", None, None, b"Subject: again\r\n\r\nx")
        uids = [int(x.split(b"UID ")[1].split(b")")[0]) for x in (client.fetch("1:*", "(UID)")[1])]
        out = {"uids": uids}
        # budget: fill, delete the folder, and the space comes back
        client.create("V")
        fills = [client.append("V", None, None, big)[0] for _ in range(6)]
        out["filled"] = fills.count("OK")
        client.delete("V")
        out["after_delete"] = client.append("U", None, None, big)[0]
        client.logout()
        return out

    got = await asyncio.to_thread(run)
    assert got["uids"] == [1, 2, 4]  # the expunged UID 3 is not handed out again
    assert 1 <= got["filled"] < 6  # the 512 KB budget ended it
    assert got["after_delete"] == "OK"  # and deleting V gave the bytes back


# ── second review ─────────────────────────────────────────────────────────────


async def test_inbox_uids_stay_ascending_and_uidnext_rises_when_mail_arrives_after_an_append(mail):
    """Appended inbox mail was numbered from 1,000,000 while later real mail got small numbers:
    UIDs went 1 2 3 1000001 4, and UIDNEXT never rose when new mail arrived, so a client polling
    STATUS UIDNEXT never saw it."""
    smtp_port, port = mail
    user, password = _weak()

    def run() -> dict:
        client = _login(port, user, password)
        client.select("INBOX")
        client.append("INBOX", None, None, b"Subject: mine\r\n\r\nx\r\n")
        before = client.status("INBOX", "(UIDNEXT)")[1][0]
        _send(smtp_port, f"{user}@corp.local", "later-arrival")
        client.noop()
        after = client.status("INBOX", "(UIDNEXT MESSAGES)")[1][0]
        uids = [int(x.split(b"UID ")[1].split(b")")[0]) for x in client.fetch("1:*", "(UID)")[1]]
        client.select("INBOX")  # a fresh view must give the same order
        again = [int(x.split(b"UID ")[1].split(b")")[0]) for x in client.fetch("1:*", "(UID)")[1]]
        client.logout()
        return {"before": before, "after": after, "uids": uids, "again": again}

    got = await asyncio.to_thread(run)
    assert got["uids"] == sorted(got["uids"]) and got["uids"] == got["again"]
    assert max(got["uids"]) < 1000  # no jump into a separate range
    next_before = int(got["before"].split(b"UIDNEXT ")[1].rstrip(b")"))
    next_after = int(got["after"].split(b"UIDNEXT ")[1].split()[0].rstrip(b")"))
    assert next_after > next_before  # new mail raised it


async def test_recreating_a_folder_announces_a_new_uidvalidity(mail):
    """UIDs restart at 1 for a recreated folder; RFC 3501 requires UIDVALIDITY to change then,
    or a client keeps its cached UID 1 and shows the wrong message."""
    _, port = mail
    user, password = _weak()

    def run() -> list[bytes]:
        client = _login(port, user, password)
        client.create("Foo")
        first = client.status("Foo", "(UIDVALIDITY)")[1][0]
        client.delete("Foo")
        client.create("Foo")
        second = client.status("Foo", "(UIDVALIDITY)")[1][0]
        client.rename("Foo", "Bar")
        client.create("Foo")
        third = client.status("Foo", "(UIDVALIDITY)")[1][0]
        client.logout()
        return [first, second, third]

    first, second, third = await asyncio.to_thread(run)
    assert len({first, second, third}) == 3


async def test_an_append_with_no_literal_does_not_reuse_an_earlier_one(mail):
    """`_last_literal` outlived the command that produced it, so a bare APPEND stored the bytes
    of an unrelated earlier literal (a LOGIN or SELECT argument) and answered OK."""
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(f"a LOGIN {user} {password}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), 10)
        writer.write(b"b SELECT {5+}\r\nINBOX\r\n")
        await writer.drain()
        while not (await asyncio.wait_for(reader.readline(), 10)).startswith(b"b "):
            pass
        writer.write(b"c APPEND Sent\r\n")
        await writer.drain()
        reply = (await asyncio.wait_for(reader.readline(), 10)).decode()
        assert reply.startswith("c BAD"), reply
    finally:
        writer.close()


async def test_copy_is_all_or_nothing_and_flags_must_be_plain_atoms(mail):
    _, port = mail
    user, password = _weak()

    def run() -> dict:
        client = _login(port, user, password)
        client.create("Dest")
        for _ in range(48):
            client.append("Dest", None, None, b"Subject: s\r\n\r\nx")  # 48 of the 50 messages
        client.select("INBOX")
        total = int(client.status("Dest", "(MESSAGES)")[1][0].split(b"MESSAGES ")[1].rstrip(b")"))
        result = client.copy("1:*", "Dest")[0]  # three messages, room for two
        after = int(client.status("Dest", "(MESSAGES)")[1][0].split(b"MESSAGES ")[1].rstrip(b")"))
        bad_append = []
        for flags in ("(\\Recent)", "(\\Bogus)", '(fo"o)', "(a%b)"):
            try:
                bad_append.append(client.append("Dest", flags, None, b"Subject: x\r\n\r\nx")[0])
            except imaplib.IMAP4.error:
                bad_append.append("BAD")
        try:
            client.store("1", "+FLAGS", "(\\Recent)")
            store = "OK"
        except imaplib.IMAP4.error:
            store = "BAD"
        client.logout()
        return {"total": total, "copy": result, "after": after, "bad": bad_append, "store": store}

    got = await asyncio.to_thread(run)
    assert got["copy"] == "NO" and got["after"] == got["total"]  # nothing half-copied
    assert got["bad"] == ["BAD"] * 4 and got["store"] == "BAD"


async def test_only_an_authenticated_append_may_send_a_message_sized_literal(mail):
    """The 128 KB literal allowance was granted to any line containing the word APPEND, including
    a LOGIN, and each continuation could repeat it."""
    _, port = mail
    user, password = _weak()
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(b"a LOGIN APPEND {131072+}\r\n")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(200), 5)
        assert b"TOOBIG" in reply, reply  # refused outright, not read to the end
    finally:
        writer.close()


async def test_a_connection_has_a_total_output_allowance(mail):
    _, port = mail
    user, password = _weak()
    from honeypot_mcp.engines import imap

    for n in range(6):
        _deliver(b"Subject: big%d\r\n\r\n" % n + b"A" * 119_000, mailbox=user)
    imap_limit = imap._MAX_CONNECTION_OUTPUT
    imap._MAX_CONNECTION_OUTPUT = 1_000_000
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(f"a LOGIN {user} {password}\r\nb SELECT INBOX\r\n".encode())
        await writer.drain()
        writer.write(b"c FETCH 1:* (BODY.PEEK[])\r\nd FETCH 1:* (BODY.PEEK[])\r\n")
        await writer.drain()
        received = 0
        try:
            while chunk := await asyncio.wait_for(reader.read(65536), 10):
                received += len(chunk)
        except (TimeoutError, ConnectionError):
            pass
        writer.close()
        assert received < 3_000_000  # cut off near the allowance, not 2 x the mailbox
    finally:
        imap._MAX_CONNECTION_OUTPUT = imap_limit
