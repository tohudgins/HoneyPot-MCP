"""Reading and writing mail for the SMTP and POP3 honeypots.

Two jobs, both pure functions so they can be tested without a socket:

* `analyse` turns the bytes a client sent after `DATA` into what an analyst wants to know:
  who it claims to be from, what it links to, and every attachment hashed (an attachment's
  SHA-256 is what gets looked up on VirusTotal; the bytes themselves are never stored).
* `build_dsn` writes the delivery-failure notice a real MTA sends when it cannot deliver
  (RFC 3464 multipart/report), and `build_received` the trace header a real MTA prepends.

Everything here handles hostile input: a message is attacker-authored, so parsing is bounded,
nesting bombs are caught, and nothing the message says is trusted for a decision beyond
labelling it.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import unicodedata
from datetime import UTC, datetime
from email.utils import format_datetime, parseaddr
from typing import Any

# Bytes of a message that are kept and parsed. Beyond this the message is still accepted and
# counted, but analysis covers only the head and says so.
MAX_PARSE_BYTES = 256 * 1024
_MAX_URLS = 10
_MAX_ATTACHMENTS = 10
# A message with more MIME containers than this is not parsed as a tree: nesting depth is what
# makes the standard parser expensive (a 250 KB message of nested multiparts took 3+ seconds).
_MAX_MULTIPARTS = 40
_MAX_PARTS_WALKED = 200
_MAX_FIELD = 200

_URL_RE = re.compile(r"""https?://[^\s<>"')\]]{4,300}""", re.I)

# Extensions that make an attachment a payload rather than a document.
EXECUTABLE_EXTENSIONS = frozenset(
    {
        ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf",
        ".ps1", ".hta", ".jar", ".msi", ".dll", ".lnk", ".iso", ".img", ".docm", ".xlsm",
        ".pptm", ".one",
    }
)  # fmt: skip

# RFC 6761 names that can never resolve; mail to them is a permanent failure.
UNDELIVERABLE_TLDS = frozenset({"invalid", "test", "localhost", "example"})


def _clip(value: object, limit: int = _MAX_FIELD) -> str:
    return str(value or "")[:limit].replace("\r", " ").replace("\n", " ")


def _is_executable_name(name: str) -> bool:
    """Whether an attachment name ends in an executable extension once the tricks that hide
    it are undone: trailing dots, spaces and semicolons, case, and invisible or bidirectional
    control characters (`invoice.exe` written with a right-to-left override)."""
    cleaned = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf"))
    cleaned = cleaned.strip().rstrip(". ;").lower()
    return "." in cleaned and "." + cleaned.rsplit(".", 1)[-1] in EXECUTABLE_EXTENSIONS


def analyse(raw: bytes, *, envelope_from: str = "") -> dict[str, Any]:
    """Summarise a message. Never raises: a message that cannot be parsed is reported as such."""
    truncated = len(raw) > MAX_PARSE_BYTES
    head = raw[:MAX_PARSE_BYTES]
    info: dict[str, Any] = {"parsed": False, "truncated_for_analysis": truncated}
    too_complex = head.lower().count(b"multipart/") > _MAX_MULTIPARTS
    try:
        if too_complex:
            msg = email.message_from_bytes(
                head.split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0] + b"\n\n",
                policy=email.policy.compat32,
            )
            info["mime_too_complex"] = True
        else:
            msg = email.message_from_bytes(head, policy=email.policy.compat32)
    except Exception:  # deep nesting, pathological encodings
        info["parse_error"] = True
        return info
    info["parsed"] = True

    from_header = _clip(msg.get("From"))
    info.update(
        from_header=from_header,
        to_header=_clip(msg.get("To")),
        subject=_clip(msg.get("Subject")),
        message_id=_clip(msg.get("Message-ID"), 128),
        x_mailer=_clip(msg.get("X-Mailer") or msg.get("User-Agent"), 128),
        reply_to=_clip(msg.get("Reply-To")),
    )
    # A From: that disagrees with the envelope sender is how most phishing and spoofing looks.
    header_addr = parseaddr(from_header)[1].lower()
    envelope = envelope_from.lower()
    info["envelope_mismatch"] = bool(header_addr and envelope and header_addr != envelope)

    urls: list[str] = []
    attachments: list[dict[str, Any]] = []
    any_executable = False
    try:
        for walked, part in enumerate(msg.walk()):
            if walked >= _MAX_PARTS_WALKED:
                info["parts_truncated"] = True
                break
            if part.is_multipart():
                continue
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            content_type = part.get_content_type()
            if filename or (payload and not content_type.startswith("text/")):
                if isinstance(payload, bytes):
                    # Every attachment is checked; only the first few are listed.
                    executable = _is_executable_name(str(filename or ""))
                    any_executable = any_executable or executable
                    if len(attachments) < _MAX_ATTACHMENTS:
                        attachments.append(
                            {
                                "filename": _clip(filename or "(unnamed)", 128),
                                "content_type": content_type,
                                "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                                "executable": executable,
                            }
                        )
            elif content_type.startswith("text/") and isinstance(payload, bytes):
                for url in _URL_RE.findall(payload[:65536].decode("utf-8", errors="replace")):
                    if url not in urls and len(urls) < _MAX_URLS:
                        urls.append(url)
    except Exception:
        info["walk_error"] = True
    info["urls"] = urls
    info["attachments"] = attachments
    info["executable_attachment"] = any_executable
    return info


def _line(value: object, limit: int = 320) -> str:
    """One header-safe line: control characters (CR and LF above all) removed."""
    return "".join(c for c in str(value) if c >= " " and c != "\x7f")[:limit]


def is_undeliverable_domain(domain: str) -> bool:
    """True for a destination that can never resolve (so the MTA would bounce it)."""
    return domain.rsplit(".", 1)[-1].lower() in UNDELIVERABLE_TLDS if domain else False


def build_received(*, hostname: str, client_ip: str, helo: str, queue_id: str, rcpt: str) -> str:
    """The `Received:` header Postfix prepends to a message it accepts."""
    when = format_datetime(datetime.now(UTC))
    return (
        f"Received: from {_clip(helo, 80) or 'unknown'} ([{client_ip}])\r\n"
        f"\tby {hostname} (Postfix) with ESMTP id {queue_id}\r\n"
        f"\tfor <{_clip(rcpt, 120)}>; {when}\r\n"
    )


def build_dsn(
    *,
    hostname: str,
    queue_id: str,
    sender: str,
    failed: list[tuple[str, str]],
    original_headers: str,
) -> bytes:
    """A permanent-failure notice in the shape Postfix sends (RFC 3464 multipart/report).

    `failed` is `[(recipient, diagnostic)]`. Only the original *headers* are returned, as
    Postfix does by default (`bounce_size_limit`), so a bounce is never a way to read a
    large message back."""
    # Everything interpolated below is attacker-influenced (envelope addresses, the original
    # headers): stripped of line breaks so none of it can add headers or end the MIME parts.
    hostname, queue_id, sender = _line(hostname), _line(queue_id, 32), _line(sender)
    failed = [(_line(rcpt), _line(diagnostic, 400)) for rcpt, diagnostic in failed]
    original_headers = "\n".join(_line(h, 998) for h in original_headers.splitlines()[:200])
    boundary = f"{queue_id}.{abs(hash((queue_id, sender))) % 10**10}/{hostname}"
    now = format_datetime(datetime.now(UTC))
    human = "\n".join(f"<{rcpt}>: {diagnostic}" for rcpt, diagnostic in failed)
    per_recipient = "".join(
        f"\nFinal-Recipient: rfc822; {rcpt}\nOriginal-Recipient: rfc822;{rcpt}\n"
        f"Action: failed\nStatus: 5.1.2\nDiagnostic-Code: X-Postfix; {diagnostic}\n"
        for rcpt, diagnostic in failed
    )
    body = (
        f"From: MAILER-DAEMON@{hostname} (Mail Delivery System)\r\n"
        f"To: {sender}\r\n"
        "Subject: Undelivered Mail Returned to Sender\r\n"
        f"Date: {now}\r\n"
        f"Message-Id: <{queue_id}-dsn@{hostname}>\r\n"
        "Auto-Submitted: auto-replied\r\n"
        "MIME-Version: 1.0\r\n"
        f'Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary="{boundary}"\r\n'
        "\r\n"
        "This is a MIME-encapsulated message.\r\n"
        f"\r\n--{boundary}\r\n"
        "Content-Description: Notification\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "\r\n"
        f"This is the mail system at host {hostname}.\r\n\r\n"
        "I'm sorry to have to inform you that your message could not\r\n"
        "be delivered to one or more recipients. It's attached below.\r\n\r\n"
        "For further assistance, please send mail to postmaster.\r\n\r\n"
        "If you do so, please include this problem report. You can\r\n"
        "delete your own text from the attached returned message.\r\n\r\n"
        f"{human}\r\n"
        f"\r\n--{boundary}\r\n"
        "Content-Description: Delivery report\r\n"
        "Content-Type: message/delivery-status\r\n"
        "\r\n"
        f"Reporting-MTA: dns; {hostname}\r\n"
        f"X-Postfix-Queue-ID: {queue_id}\r\n"
        f"X-Postfix-Sender: rfc822; {sender}\r\n"
        f"Arrival-Date: {now}\r\n"
        f"{per_recipient}"
        f"\r\n--{boundary}\r\n"
        "Content-Description: Undelivered Message Headers\r\n"
        "Content-Type: text/rfc822-headers\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        f"{original_headers.rstrip()}\r\n"
        f"\r\n--{boundary}--\r\n"
    )
    return body.replace("\n", "\r\n").replace("\r\r\n", "\r\n").encode("utf-8", errors="replace")


def header_block(raw: bytes) -> str:
    """The header section of a message (everything before the first blank line)."""
    text = raw[:MAX_PARSE_BYTES].decode("utf-8", errors="replace")
    for separator in ("\r\n\r\n", "\n\n"):
        head, found, _ = text.partition(separator)
        if found:
            return head
    return text[:4096]
