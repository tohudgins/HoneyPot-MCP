"""The mailboxes behind the SMTP and POP3 honeypots.

Mail the SMTP engine accepts for a local mailbox lands here, as does the delivery-failure
notice a real MTA would send a local sender, and the POP3 engine serves it back to a client
that gets in. That closes the loop an attacker can actually observe: send a message to
`postmaster@host`, then log in and find it; mail something undeliverable from `admin@host`,
then find the bounce.

Bounded on every axis, because everything here is written by strangers: messages per
mailbox, bytes per mailbox, bytes per message, and mailboxes held. Oldest mail goes first.
Nothing is persisted: it is a decoy, and restarting the process resets it, like a rebuilt VM.

A fresh mailbox is not empty. An inbox with nothing in it is itself a tell, so each starts
with a few ordinary internal messages, derived from the mailbox name so the same mailbox
always holds the same mail. They contain no credentials and name no real organisation.
"""

from __future__ import annotations

import hashlib
import random
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

_MAX_MESSAGES = 50
_MAX_MAILBOX_BYTES = 1024 * 1024
_MAX_MESSAGE_BYTES = 128 * 1024
_MAX_MAILBOXES = 64


@dataclass(frozen=True)
class StoredMessage:
    uid: str
    raw: bytes

    @property
    def size(self) -> int:
        return len(self.raw)


_SEEDS = (
    (
        "Weekly backup report",
        "Backup job completed.\r\n\r\nHosts: 14 ok, 0 failed\r\nDuration: 02:41\r\nNext run: Sunday 01:00\r\n",
    ),
    (
        "Scheduled maintenance window",
        "The patching window for the Linux estate is Saturday 22:00-02:00.\r\n"
        "Expect brief restarts on the application tier. No action needed.\r\n",
    ),
    (
        "Re: Q3 vendor invoices",
        "Thanks, I've approved the three outstanding invoices. The remaining one is waiting\r\n"
        "on a purchase order from procurement.\r\n",
    ),
    (
        "Mailbox quota notice",
        "Your mailbox is at 71% of its quota. Old messages can be archived from the web client.\r\n",
    ),
)


def _seed_messages(mailbox: str, domain: str) -> list[StoredMessage]:
    seed = int.from_bytes(hashlib.sha256(f"mail:{mailbox}".encode()).digest()[:8], "big")
    rng = random.Random(seed)
    picks = rng.sample(range(len(_SEEDS)), k=rng.randint(2, 3))
    now = datetime.now(UTC)
    out: list[StoredMessage] = []
    for n, index in enumerate(sorted(picks)):
        subject, body = _SEEDS[index]
        when = now - timedelta(days=rng.randint(1, 20) + n, hours=rng.randint(0, 23))
        sender = rng.choice(("it-ops", "noreply", "facilities", "finance"))
        raw = (
            f"From: {sender}@{domain}\r\nTo: {mailbox}@{domain}\r\nSubject: {subject}\r\n"
            f"Date: {format_datetime(when)}\r\n"
            f"Message-ID: <seed{seed % 10**6}{n}@{domain}>\r\n"
            "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\n"
            f"{body}"
        ).encode()
        out.append(StoredMessage(uid=f"seed{seed % 10**6}{n}", raw=raw))
    return out


class Maildrop:
    def __init__(self) -> None:
        self._boxes: OrderedDict[str, list[StoredMessage]] = OrderedDict()
        self._counter = 0

    @staticmethod
    def _key(mailbox: str) -> str:
        return mailbox.split("@", 1)[0].strip().lower()[:64]

    def _box(self, mailbox: str, domain: str) -> list[StoredMessage]:
        key = self._key(mailbox)
        box = self._boxes.get(key)
        if box is None:
            box = _seed_messages(key, domain)
            self._boxes[key] = box
            while len(self._boxes) > _MAX_MAILBOXES:
                self._boxes.popitem(last=False)
        else:
            self._boxes.move_to_end(key)
        return box

    def deliver(self, mailbox: str, raw: bytes, *, domain: str = "localhost") -> StoredMessage:
        box = self._box(mailbox, domain)
        self._counter += 1
        message = StoredMessage(uid=f"m{self._counter}", raw=raw[:_MAX_MESSAGE_BYTES])
        box.append(message)
        total = sum(m.size for m in box)
        while len(box) > _MAX_MESSAGES or (total > _MAX_MAILBOX_BYTES and len(box) > 1):
            total -= box.pop(0).size
        return message

    def messages(self, mailbox: str, domain: str = "localhost") -> list[StoredMessage]:
        return list(self._box(mailbox, domain))


# One store per process: an estate has one mail domain, and the SMTP honeypot that accepts a
# message and the POP3 honeypot that serves it are separate engines with separate names.
MAILDROP = Maildrop()
