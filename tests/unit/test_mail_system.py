"""Mail that goes in one honeypot comes out of another, and nothing leaves the host.

The SMTP honeypot used to acknowledge a message and forget it: no queue, no bounce, nothing a
person watching for a delivery notice would ever see. Now a completed message is analysed
(attachments hashed, links listed), routed per recipient, and stored where the POP3 honeypot
serves it — which a client only reaches with a planted honeytoken credential or the one weak
pair the honeypot derives from its name. These tests drive real `smtplib`/`poplib` clients.
"""

import asyncio
import email
import os
import poplib
import smtplib
import socket
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
    from honeypot_mcp import token_matchers
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
    token_matchers.invalidate_cache()
    await close_db()


@pytest.fixture(autouse=True)
def fresh_maildrop(monkeypatch):
    from honeypot_mcp.engines import maildrop, pop3, smtp

    drop = maildrop.Maildrop()
    monkeypatch.setattr(maildrop, "MAILDROP", drop)
    monkeypatch.setattr(smtp, "MAILDROP", drop)
    monkeypatch.setattr(pop3, "MAILDROP", drop)
    monkeypatch.setattr(smtp, "_DSN_DELAY", (0.0, 0.05))
    return drop


@pytest.fixture
async def mail(tmp_path, monkeypatch):
    """An SMTP honeypot and a POP3 honeypot side by side."""
    monkeypatch.chdir(tmp_path)
    from honeypot_mcp.engines.pop3 import POP3Engine
    from honeypot_mcp.engines.smtp import SMTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    smtp_port, pop_port = _free_port(), _free_port()
    async with get_session() as session:
        session.add(Honeypot(name="smtp-m", type=HoneypotType.SMTP, port=smtp_port))
        session.add(Honeypot(name="pop3-m", type=HoneypotType.POP3, port=pop_port))
        await session.flush()
    smtp_engine, pop_engine = SMTPEngine(), POP3Engine()
    s_id = await smtp_engine.start("smtp-m", smtp_port, {"smtp_hostname": HOST})
    p_id = await pop_engine.start("pop3-m", pop_port, {})
    yield smtp_port, pop_port
    await smtp_engine.stop(s_id)
    await pop_engine.stop(p_id)


def _weak_login() -> tuple[str, str]:
    from honeypot_mcp.engines.http_admin import derive_login

    return derive_login("pop3-m")


def _send(port: int, sender: str, rcpts: list[str], message: EmailMessage) -> None:
    with smtplib.SMTP("127.0.0.1", port, timeout=10) as client:
        client.ehlo("scanner.example.net")
        client.send_message(message, from_addr=sender, to_addrs=rcpts)


def _pop(port: int, user: str, password: str) -> poplib.POP3:
    client = poplib.POP3("127.0.0.1", port, timeout=10)
    client.user(user)
    client.pass_(password)
    return client


def _msg(
    subject: str, body: str = "hello", sender: str = "a@elsewhere.example.org"
) -> EmailMessage:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "postmaster@corp.local", subject
    m.set_content(body)
    return m


async def _events(event_type: str) -> list:
    from sqlalchemy import select

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    for _ in range(200):  # wait for the flusher to go idle before querying the shared database
        if event_buffer.get_buffer().qsize() == 0:
            break
        await asyncio.sleep(0.05)
    await asyncio.sleep(0.4)
    async with get_session() as session:
        rows = (await session.execute(select(Alert))).scalars().all()
    return [a for a in rows if a.event_type == event_type]


# ── message analysis ─────────────────────────────────────────────────────────


async def test_analysis_hashes_attachments_lists_links_and_flags_a_spoofed_sender():
    import hashlib

    from honeypot_mcp.engines.mail_message import analyse

    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "CEO <ceo@corp.local>", "x@corp.local", "Invoice"
    m.set_content("Pay here: https://evil.example/pay?id=1")
    payload = b"MZ\x90\x00 fake executable"
    m.add_attachment(
        payload, maintype="application", subtype="octet-stream", filename="invoice.exe"
    )
    info = analyse(m.as_bytes(), envelope_from="attacker@bad.example")
    assert info["subject"] == "Invoice" and info["envelope_mismatch"] is True
    assert info["urls"] == ["https://evil.example/pay?id=1"]
    [att] = info["attachments"]
    assert att["sha256"] == hashlib.sha256(payload).hexdigest()
    assert att["executable"] is True and info["executable_attachment"] is True


async def test_a_hostile_message_cannot_break_or_stall_analysis():
    from honeypot_mcp.engines.mail_message import MAX_PARSE_BYTES, analyse

    nested = (
        b"Content-Type: multipart/mixed; boundary=b\r\n\r\n"
        + b"--b\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" * 3000
    )
    assert analyse(nested)["parsed"] in (True, False)  # returned, did not raise
    assert analyse(b"\x00\xff" * 100)["parsed"] in (True, False)
    big = analyse(b"Subject: x\r\n\r\n" + b"A" * (MAX_PARSE_BYTES * 3))
    assert big["truncated_for_analysis"] is True


async def test_a_delivery_notice_is_a_valid_rfc3464_report():
    from honeypot_mcp.engines.mail_message import build_dsn

    raw = build_dsn(
        hostname=HOST, queue_id="4F2A1B3C9D", sender="admin@corp.local",
        failed=[("x@nowhere.invalid", "Host or domain name not found")],
        original_headers="From: admin@corp.local\r\nTo: x@nowhere.invalid\r\nSubject: hi",
    )  # fmt: skip
    msg = email.message_from_bytes(raw)
    assert msg.get_content_type() == "multipart/report"
    assert msg.get_param("report-type") == "delivery-status"
    kinds = [p.get_content_type() for p in msg.get_payload()]
    assert kinds == ["text/plain", "message/delivery-status", "text/rfc822-headers"]
    status = msg.get_payload()[1].as_string()
    assert "Final-Recipient: rfc822; x@nowhere.invalid" in status and "Action: failed" in status
    assert msg["Subject"] == "Undelivered Mail Returned to Sender"


# ── the queue: SMTP in, POP3 out ─────────────────────────────────────────────


async def test_mail_to_a_local_mailbox_can_be_read_back_over_pop3(mail):
    smtp_port, pop_port = mail
    user, password = _weak_login()
    await asyncio.to_thread(
        _send, smtp_port, "a@elsewhere.example.org", [f"{user}@corp.local"], _msg("probe-7731")
    )
    user, password = _weak_login()
    client = await asyncio.to_thread(_pop, pop_port, user, password)
    try:
        count, _ = await asyncio.to_thread(client.stat)
        assert count >= 3  # the seeded inbox plus what we sent
        # Find it among the messages.
        found = ""
        for number in range(1, count + 1):
            _, lines, _ = await asyncio.to_thread(client.retr, number)
            text = b"\n".join(lines).decode()
            if "probe-7731" in text:
                found = text
        assert "Received: from scanner.example.net" in found and "(Postfix) with ESMTP id" in found
    finally:
        client.close()


async def test_pop3_refuses_a_wrong_password_and_a_spray_does_not_get_in(mail):
    _, pop_port = mail
    user, password = _weak_login()
    with pytest.raises(poplib.error_proto):
        await asyncio.to_thread(_pop, pop_port, user, password + "x")
    with pytest.raises(poplib.error_proto):
        await asyncio.to_thread(_pop, pop_port, "root", "toor")


async def test_pop3_dele_is_acknowledged_but_never_removes_mail(mail):
    _, pop_port = mail
    user, password = _weak_login()
    first = await asyncio.to_thread(_pop, pop_port, user, password)
    before, _ = await asyncio.to_thread(first.stat)
    await asyncio.to_thread(first.dele, 1)
    after, _ = await asyncio.to_thread(first.stat)
    assert after == before - 1  # this session sees it gone
    await asyncio.to_thread(first.quit)  # blocking client: never on the loop thread
    second = await asyncio.to_thread(_pop, pop_port, user, password)
    try:
        again, _ = await asyncio.to_thread(second.stat)
        assert again == before  # but an intruder cannot empty the decoy
    finally:
        second.close()


async def test_a_message_to_an_unresolvable_domain_bounces_to_a_local_sender(mail, fresh_maildrop):
    smtp_port, _ = mail
    m = _msg("will-bounce", sender="admin@corp.local")
    m.replace_header("To", "victim@nowhere.invalid")
    await asyncio.to_thread(_send, smtp_port, "admin@corp.local", ["victim@nowhere.invalid"], m)
    for _ in range(40):
        await asyncio.sleep(0.1)
        notices = [
            x for x in fresh_maildrop.messages("admin") if b"Undelivered Mail Returned" in x.raw
        ]
        if notices:
            break
    assert notices, "the sender never received a delivery-failure notice"
    assert b"Host or domain name not found" in notices[0].raw
    [event] = await _events("smtp_message_received")
    assert event.payload["delivery"]["bounced"] == 1
    assert event.payload["delivery"]["dsn"] == "delivered to mailbox admin"


async def test_a_bounce_owed_to_an_external_sender_is_suppressed_not_sent(
    mail, fresh_maildrop, monkeypatch
):
    """Backscatter: the sender address of a spammer's message is usually someone else's.
    The honeypot never opens an outbound connection, and says so in the record."""
    smtp_port, _ = mail
    real_connect = socket.socket.connect

    def loopback_only(self, address):
        assert address[0] in ("127.0.0.1", "::1"), f"outbound connection to {address}"
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", loopback_only)
    m = _msg("spoofed", sender="victim@bank.example.com")
    m.replace_header("To", "x@nowhere.invalid")
    await asyncio.to_thread(_send, smtp_port, "victim@bank.example.com", ["x@nowhere.invalid"], m)
    await asyncio.sleep(0.5)
    assert all(b"Undelivered" not in x.raw for x in fresh_maildrop.messages("victim"))
    [event] = await _events("smtp_message_received")
    assert event.payload["delivery"]["dsn"].startswith("suppressed")


async def test_an_executable_attachment_is_critical_and_hashed_in_the_event(mail):
    smtp_port, _ = mail
    m = _msg("invoice")
    m.add_attachment(
        b"MZ payload", maintype="application", subtype="octet-stream", filename="pay.scr"
    )
    await asyncio.to_thread(
        _send, smtp_port, "a@elsewhere.example.org", ["postmaster@corp.local"], m
    )
    [event] = await _events("smtp_message_received")
    assert event.severity.value == "critical"
    assert event.payload["attachments"][0]["filename"] == "pay.scr"
    assert len(event.payload["attachments"][0]["sha256"]) == 64
    assert event.payload["delivery"]["delivered_local"] == 1


async def test_a_planted_pop3_credential_logs_in_and_trips_its_honeytoken(mail):
    _, pop_port = mail
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_credentials

    created = await honeytoken_generate_credentials("planted-mail", count=1, service="pop3")
    pair = created["metadata"]["credentials"][0]
    client = await asyncio.to_thread(_pop, pop_port, pair["username"], pair["password"])
    try:
        assert (await asyncio.to_thread(client.stat))[0] >= 1
    finally:
        client.close()
    [login] = await _events("pop3_login_success")
    assert login.payload["planted_credential"] is True
    [tripped] = await _events("honeytoken_triggered_credential_via_pop3_login_attempt")
    assert tripped.severity.value == "critical"


async def test_a_canary_email_as_the_pop3_password_is_not_a_login(mail):
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    canary = "canary-0123456789abcdef@corp.local"
    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.DB_ROW,
                label="canary",
                token_value=canary,
                status=HoneytokenStatus.ACTIVE,
                token_meta={"canary_email": canary},
            )
        )
    token_matchers.invalidate_cache()
    _, pop_port = mail
    with pytest.raises(poplib.error_proto):
        await asyncio.to_thread(_pop, pop_port, "root", canary)


# ── hardening found in review ────────────────────────────────────────────────


async def test_a_control_character_in_an_address_cannot_write_into_the_bounce(mail):
    """A lone CR in MAIL FROM reached the generated delivery notice unescaped, so a sender
    could inject its own Subject and body into a message the honeypot itself authored."""
    smtp_port, _ = mail

    def attempt() -> tuple[bytes, bytes]:
        with socket.create_connection(("127.0.0.1", smtp_port), timeout=10) as s:
            s.recv(256)
            s.sendall(b"EHLO x\r\n")
            s.recv(2048)
            s.sendall(b"MAIL FROM:<admin@corp.local\rSubject: URGENT reset your password>\r\n")
            first = s.recv(256)
            s.sendall(b"RCPT TO:<a@b.example\rBcc: x@y>\r\n")
            return first, s.recv(256)

    mail_from_reply, _ = await asyncio.to_thread(attempt)
    assert mail_from_reply.startswith(b"501 ")

    from honeypot_mcp.engines.mail_message import build_dsn

    notice = build_dsn(
        hostname=HOST, queue_id="AB12", sender="a@corp.local\rSubject: injected",
        failed=[("x@nowhere.invalid\r\nBcc: evil", "not found\rX: y")],
        original_headers="From: a\rSubject: injected2\nTo: b",
    )  # fmt: skip
    parsed = email.message_from_bytes(notice)
    assert parsed["Subject"] == "Undelivered Mail Returned to Sender"
    assert parsed.get_all("Subject") == ["Undelivered Mail Returned to Sender"]
    assert parsed["Bcc"] is None


async def test_a_binary_attachment_is_hashed_as_sent_not_as_decoded_text(mail):
    """DATA was decoded as UTF-8 with replacement and re-encoded, so every non-UTF-8 byte
    became U+FFFD: the reported size and SHA-256 were of a different file, which is what an
    analyst would look up."""
    import hashlib

    smtp_port, _ = mail
    payload = bytes(range(128, 256)) * 2 + b"\xff\xfe\x00\x80"
    m = _msg("binary")
    m.add_attachment(payload, maintype="application", subtype="octet-stream", filename="blob.bin")
    await asyncio.to_thread(
        _send, smtp_port, "a@elsewhere.example.org", ["postmaster@corp.local"], m
    )
    [event] = await _events("smtp_message_received")
    attachment = event.payload["attachments"][0]
    assert attachment["sha256"] == hashlib.sha256(payload).hexdigest()
    assert attachment["size"] == len(payload)


async def test_executable_attachments_are_found_however_the_name_hides_it():
    from email.message import EmailMessage

    from honeypot_mcp.engines.mail_message import analyse

    for name in ("a.exe.", "x.EXE;", "report.pdf.exe", "inv\u202egpj.exe", "run.scr ", "m.docm"):
        m = EmailMessage()
        m["From"], m["To"], m["Subject"] = "a@b.example", "c@d.example", "x"
        m.set_content("hi")
        m.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename=name)
        assert analyse(m.as_bytes())["executable_attachment"] is True, name

    # The executable is the twelfth attachment: only ten are listed, all are checked.
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@b.example", "c@d.example", "x"
    m.set_content("hi")
    for i in range(11):
        m.add_attachment(
            f"d{i}".encode(), maintype="application", subtype="pdf", filename=f"{i}.pdf"
        )
    m.add_attachment(b"MZ", maintype="application", subtype="octet-stream", filename="z.exe")
    info = analyse(m.as_bytes())
    assert len(info["attachments"]) == 10 and info["executable_attachment"] is True

    benign = EmailMessage()
    benign["From"], benign["To"], benign["Subject"] = "a@b.example", "c@d.example", "x"
    benign.set_content("hi")
    benign.add_attachment(b"x", maintype="application", subtype="pdf", filename="exe.pdf")
    assert analyse(benign.as_bytes())["executable_attachment"] is False


async def test_deeply_nested_mime_is_refused_before_it_can_stall_the_server():
    """A 250 KB message of nested multiparts took 3.4 s to parse, on the event loop."""
    import time

    from honeypot_mcp.engines.mail_message import analyse

    nested = b"Content-Type: multipart/mixed; boundary=b\r\nSubject: bomb\r\n\r\n"
    nested += b"--b\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" * 5000
    started = time.monotonic()
    info = analyse(nested)
    assert time.monotonic() - started < 0.5
    assert info["mime_too_complex"] is True and info["subject"] == "bomb"


async def test_pop3_stops_queueing_replies_for_a_peer_that_never_reads():
    from honeypot_mcp.engines.pop3 import _POP3Protocol

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

    protocol = _POP3Protocol("p", None)
    protocol._transport = StuckPeer()  # type: ignore[assignment]
    protocol._send("+OK something")
    assert protocol._transport.aborted  # type: ignore[union-attr]


async def test_pop3_message_numbers_are_plain_ascii_digits(mail):
    _, pop_port = mail
    user, password = _weak_login()
    client = await asyncio.to_thread(_pop, pop_port, user, password)
    try:
        for odd in ("+1", "1_0", "\u0663", "1.0", "-1"):
            with pytest.raises(poplib.error_proto):
                await asyncio.to_thread(client._shortcmd, f"RETR {odd}")
        await asyncio.to_thread(client._shortcmd, "RETR 1")  # the plain form still works
    finally:
        client.close()


# ── POP3 AUTH (SASL) ─────────────────────────────────────────────────────────


class _Raw:
    """A bare POP3 conversation, line by line."""

    def __init__(self, reader, writer) -> None:
        self.reader, self.writer = reader, writer

    @classmethod
    async def open(cls, port: int) -> "_Raw":
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        raw = cls(reader, writer)
        await raw.line()  # greeting
        return raw

    async def line(self) -> str:
        return (await asyncio.wait_for(self.reader.readline(), 10)).decode().rstrip("\r\n")

    async def say(self, text: str) -> str:
        self.writer.write(text.encode() + b"\r\n")
        await self.writer.drain()
        return await self.line()

    def close(self) -> None:
        self.writer.close()


def _b64(text: str) -> str:
    import base64

    return base64.b64encode(text.encode()).decode()


async def test_pop3_auth_plain_with_an_initial_response_logs_in(mail):
    _, pop_port = mail
    user, password = _weak_login()
    raw = await _Raw.open(pop_port)
    try:
        reply = await raw.say(f"AUTH PLAIN {_b64(chr(0) + user + chr(0) + password)}")
        assert reply.startswith("+OK")
        assert (await raw.say("STAT")).startswith("+OK")
    finally:
        raw.close()


async def test_pop3_auth_plain_and_login_work_step_by_step(mail):
    _, pop_port = mail
    user, password = _weak_login()
    raw = await _Raw.open(pop_port)
    try:
        assert await raw.say("AUTH PLAIN") == "+ "
        assert (await raw.say(_b64(f"\0{user}\0{password}"))).startswith("+OK")
    finally:
        raw.close()
    raw = await _Raw.open(pop_port)
    try:
        assert await raw.say("AUTH LOGIN") == f"+ {_b64('Username:')}"
        assert await raw.say(_b64(user)) == f"+ {_b64('Password:')}"
        assert (await raw.say(_b64(password))).startswith("+OK")
    finally:
        raw.close()


async def test_pop3_auth_refuses_wrong_passwords_and_records_the_attempt(mail):
    _, pop_port = mail
    user, password = _weak_login()
    raw = await _Raw.open(pop_port)
    try:
        reply = await raw.say(f"AUTH PLAIN {_b64(f'{chr(0)}{user}{chr(0)}{password}x')}")
        assert reply.startswith("-ERR")
        assert (await raw.say("AUTH LOGIN")).startswith("+ ")
        await raw.say(_b64(user))
        assert (await raw.say(_b64("wrong"))).startswith("-ERR")
        assert (await raw.say("AUTH CRAM-MD5")).startswith("-ERR Unsupported")
        assert (await raw.say("AUTH LOGIN")).startswith("+ ")
        assert (await raw.say("*")).startswith("-ERR Authentication cancelled")
    finally:
        raw.close()
    attempts = await _events("pop3_login_attempt")
    assert {a.payload["method"] for a in attempts} >= {"AUTH PLAIN", "AUTH LOGIN"}
    assert all(a.payload["password"] != password for a in attempts)  # decoded, not the blob


async def test_a_planted_credential_sent_over_auth_login_trips_its_token(mail):
    """AUTH LOGIN was never decoded, so a planted credential sent that way was neither
    matched nor let in."""
    _, pop_port = mail
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_credentials

    created = await honeytoken_generate_credentials("sasl", count=1, service="pop3")
    pair = created["metadata"]["credentials"][0]
    raw = await _Raw.open(pop_port)
    try:
        await raw.say("AUTH LOGIN")
        await raw.say(_b64(pair["username"]))
        assert (await raw.say(_b64(pair["password"]))).startswith("+OK")
    finally:
        raw.close()
    tripped = await _events("honeytoken_triggered_credential_via_pop3_login_attempt")
    assert tripped and tripped[0].severity.value == "critical"


async def test_auth_is_refused_once_logged_in_and_the_next_command_still_works(mail):
    """AUTH was reachable in the transaction state: it swallowed the next command as a
    credential and could swap the session to another mailbox (a free guess per command)."""
    _, pop_port = mail
    user, password = _weak_login()
    raw = await _Raw.open(pop_port)
    try:
        assert (await raw.say(f"USER {user}")).startswith("+OK")
        assert (await raw.say(f"PASS {password}")).startswith("+OK")
        assert (await raw.say("AUTH PLAIN")).startswith("-ERR Command not permitted")
        assert (await raw.say("AUTH LOGIN")).startswith("-ERR Command not permitted")
        assert (await raw.say("STAT")).startswith("+OK")  # not eaten as a credential
        assert (await raw.say("RETR " + "9" * 5000)).startswith("-ERR")  # and no 4300-digit crash
    finally:
        raw.close()
