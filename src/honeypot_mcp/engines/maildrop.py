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
import time
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
    # Increases with every message ever delivered to the mailbox and is never reused, so it
    # is what IMAP exposes as UID: a client that cached "UID 7" still means the same message
    # after older mail has been evicted from the bounded mailbox.
    number: int = 0

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
    """A new mailbox's starting mail, numbered 1..n."""
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
        out.append(StoredMessage(uid=f"seed{seed % 10**6}{n}", raw=raw, number=n + 1))
    return out


# Ordinary mail for the folders besides the inbox: (subject, body). A mailbox with an empty Sent
# folder is one nobody has ever used, which a visitor who checks notices.
_FOLDER_SEEDS: dict[str, tuple[tuple[str, str], ...]] = {
    "Sent": (
        (
            "Re: Weekly backup report",
            "Thanks, looks fine. Please keep the Sunday window as is.\r\n",
        ),
        (
            "Q3 vendor invoices",
            "Attached is the list for approval. Let me know if anything looks off.\r\n",
        ),
        ("Patching window", "Confirming Saturday 22:00-02:00 for the Linux estate.\r\n"),
    ),
    "Drafts": (
        ("Notes for Monday", "- review the open tickets\r\n- follow up with procurement\r\n"),
    ),
    "Trash": (
        ("Your mailbox quota", "Your mailbox is at 94% of its quota.\r\n"),
        ("Lunch on Friday?", "Are we still on for noon?\r\n"),
    ),
    "Junk": (("You have been selected", "Click here to claim your reward.\r\n"),),
}


def _seed_folder(mailbox: str, folder: str, domain: str) -> list[StoredMessage]:
    """Starting mail for a non-inbox folder, derived from the mailbox so it never changes."""
    seeds = _FOLDER_SEEDS.get(folder, ())
    seed = int.from_bytes(hashlib.sha256(f"folder:{mailbox}:{folder}".encode()).digest()[:8], "big")
    rng = random.Random(seed)
    now = datetime.now(UTC)
    out = []
    for n, (subject, body) in enumerate(seeds, start=1):
        when = now - timedelta(days=rng.randint(1, 25) + n, hours=rng.randint(0, 23))
        sender, recipient = (
            (f"{mailbox}@{domain}", rng.choice(("it-ops", "finance", "facilities")) + f"@{domain}")
            if folder in ("Sent", "Drafts")
            else (rng.choice(("noreply", "alerts", "promo")) + f"@{domain}", f"{mailbox}@{domain}")
        )
        raw = (
            f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nDate: {format_datetime(when)}\r\n"
            f"Message-ID: <{folder.lower()}{seed % 10**6}{n}@{domain}>\r\nMIME-Version: 1.0\r\n"
            f"Content-Type: text/plain; charset=us-ascii\r\n\r\n{body}"
        ).encode()
        out.append(StoredMessage(uid=f"seed{folder.lower()}{n}", raw=raw, number=n))
    return out


class Maildrop:
    def __init__(self) -> None:
        self._boxes: OrderedDict[str, list[StoredMessage]] = OrderedDict()
        self._counter = 0
        self._next_number: dict[str, int] = {}
        self._validity: dict[str, int] = {}
        self._generation = 0
        self._folders: dict[tuple[str, str], list[StoredMessage]] = {}

    @staticmethod
    def _key(mailbox: str) -> str:
        return mailbox.split("@", 1)[0].strip().lower()[:64]

    def _box(self, mailbox: str, domain: str) -> list[StoredMessage]:
        key = self._key(mailbox)
        box = self._boxes.get(key)
        if box is None:
            box = _seed_messages(key, domain)
            self._boxes[key] = box
            self._next_number[key] = len(box) + 1
            # A mailbox that is evicted and later recreated restarts its numbering, which
            # IMAP requires to be announced as a new UIDVALIDITY.
            self._generation += 1
            self._validity[key] = int(time.time()) + self._generation
            while len(self._boxes) > _MAX_MAILBOXES:
                evicted, _ = self._boxes.popitem(last=False)
                self._next_number.pop(evicted, None)
                self._validity.pop(evicted, None)
                for folder_key in [k for k in self._folders if k[0] == evicted]:
                    del self._folders[folder_key]
        else:
            self._boxes.move_to_end(key)
        return box

    def deliver(self, mailbox: str, raw: bytes, *, domain: str = "localhost") -> StoredMessage:
        box = self._box(mailbox, domain)
        self._counter += 1
        key = self._key(mailbox)
        number = self._next_number.get(key, len(box) + 1)
        self._next_number[key] = number + 1
        message = StoredMessage(
            uid=f"m{self._counter}", raw=raw[:_MAX_MESSAGE_BYTES], number=number
        )
        box.append(message)
        total = sum(m.size for m in box)
        while len(box) > _MAX_MESSAGES or (total > _MAX_MAILBOX_BYTES and len(box) > 1):
            total -= box.pop(0).size
        return message

    def folder(self, mailbox: str, folder: str, domain: str = "localhost") -> list[StoredMessage]:
        """The shared, read-only messages of a folder other than the inbox."""
        self._box(mailbox, domain)
        key = (self._key(mailbox), folder)
        if key not in self._folders:
            self._folders[key] = _seed_folder(key[0], folder, domain)
        return list(self._folders[key])

    def reserve_number(self, mailbox: str, domain: str = "localhost") -> int:
        """Take the next UID for a message that is not stored here (one a visitor appended), so
        the shared numbering never hands out the same number to mail delivered later."""
        self._box(mailbox, domain)
        key = self._key(mailbox)
        number = self._next_number[key]
        self._next_number[key] = number + 1
        return number

    def validity(self, mailbox: str, domain: str = "localhost") -> int:
        self._box(mailbox, domain)
        return self._validity[self._key(mailbox)]

    def next_number(self, mailbox: str, domain: str = "localhost") -> int:
        self._box(mailbox, domain)
        return self._next_number[self._key(mailbox)]

    def messages(self, mailbox: str, domain: str = "localhost") -> list[StoredMessage]:
        return list(self._box(mailbox, domain))


# One store per process: an estate has one mail domain, and the SMTP honeypot that accepts a
# message and the POP3 honeypot that serves it are separate engines with separate names.
MAILDROP = Maildrop()
