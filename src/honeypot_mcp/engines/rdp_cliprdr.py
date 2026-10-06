"""The RDP clipboard channel (MS-RDPECLIP), server side, for the honeypot's session.

Why it matters: the clipboard is how an intruder moves text into a remote desktop. They paste
the command they were going to type, a download URL, a credential they just cracked. Keystrokes
record what is typed; this records what is pasted.

The conversation is the standard one. The server announces itself (capabilities, then Monitor
Ready); whenever the client's clipboard changes it sends a Format List; the server accepts it
and asks for the text; the client answers with the text.

By default nothing is offered in the other direction and a request for the server's clipboard is
answered with a failure. An operator may configure `clipboard_text`: a short string the server
then announces as its own clipboard, and serves when the client pastes it. A clipboard that is
never empty is what a used machine has, and what a visitor takes from it is recorded.

Pure: `ClipboardChannel` takes channel payloads in and returns payloads to send, so it is tested
without a socket. Framing (`CHANNEL_PDU_HEADER`, chunking at 1600 bytes) lives here too.
"""

from __future__ import annotations

import struct

# Message types and flags (MS-RDPECLIP 2.2.1).
CB_MONITOR_READY = 0x0001
CB_FORMAT_LIST = 0x0002
CB_FORMAT_LIST_RESPONSE = 0x0003
CB_FORMAT_DATA_REQUEST = 0x0004
CB_FORMAT_DATA_RESPONSE = 0x0005
CB_TEMP_DIRECTORY = 0x0006
CB_CLIP_CAPS = 0x0007
CB_RESPONSE_OK = 0x0001
CB_RESPONSE_FAIL = 0x0002

CF_TEXT = 1
CF_OEMTEXT = 7
CF_UNICODETEXT = 13

# CHANNEL_PDU_HEADER flags (MS-RDPBCGR 2.2.6.1.1).
_FLAG_FIRST, _FLAG_LAST, _FLAG_SHOW_PROTOCOL = 0x01, 0x02, 0x10
CHUNK_SIZE = 1600

MAX_MESSAGE = 256 * 1024  # largest single clipboard message accepted
MAX_TEXTS = 20  # clipboard contents recorded per session
MAX_TEXT_CHARS = 4000
MAX_OFFER_CHARS = 500
_SHORT_FORMAT_ENTRY = 36  # formatId(4) + a 32-byte name

_TEXT_FORMATS = (CF_UNICODETEXT, CF_TEXT, CF_OEMTEXT)


def _pdu(msg_type: int, flags: int = 0, data: bytes = b"") -> bytes:
    return struct.pack("<HHI", msg_type, flags, len(data)) + data


def wrap_channel_pdu(message: bytes) -> list[bytes]:
    """Split a clipboard message into static-channel chunks, each with its header."""
    chunks = [message[i : i + CHUNK_SIZE] for i in range(0, max(len(message), 1), CHUNK_SIZE)]
    out = []
    for index, chunk in enumerate(chunks):
        flags = _FLAG_SHOW_PROTOCOL
        if index == 0:
            flags |= _FLAG_FIRST
        if index == len(chunks) - 1:
            flags |= _FLAG_LAST
        out.append(struct.pack("<II", len(message), flags) + chunk)
    return out


class ClipboardChannel:
    """One session's clipboard conversation."""

    def __init__(self, offer: str | None = None) -> None:
        self.offer = _printable(offer)[:MAX_OFFER_CHARS] if offer else None
        self.offer_reads = 0
        # Announced once the client has finished its own initial exchange. Real clients (and
        # aardwolf) ignore anything but a Format List Response until then, as the protocol says.
        self._offer_pending = bool(self.offer)
        self.texts: list[str] = []
        self.formats_seen: set[int] = set()
        self.offered_lists = 0
        self._buffer = b""
        self._expected = 0
        self._pending_format: int | None = None

    # ── what the server sends first ──────────────────────────────────────────

    def opening(self) -> list[bytes]:
        """Capabilities then Monitor Ready. General flags are 0, so format names stay in the
        short fixed-size form this side parses."""
        caps = struct.pack("<HHHHII", 1, 0, 1, 12, 2, 0)  # one set: general, version 2, flags 0
        return [_pdu(CB_CLIP_CAPS, 0, caps), _pdu(CB_MONITOR_READY)]

    def _offer_list(self) -> bytes:
        """The server's own clipboard, as a Format List: Unicode text, no format name."""
        return _pdu(CB_FORMAT_LIST, 0, struct.pack("<I", CF_UNICODETEXT) + bytes(32))

    # ── what the client sends ────────────────────────────────────────────────

    def feed(self, chunk: bytes) -> list[bytes]:
        """One channel chunk from the client; returns complete messages to send back (each
        still to be passed through `wrap_channel_pdu`)."""
        if len(chunk) < 8:
            return []
        total, flags = struct.unpack_from("<II", chunk, 0)
        body = chunk[8:]
        if flags & _FLAG_FIRST:
            if total > MAX_MESSAGE:
                self._abandon()
                return []
            self._buffer, self._expected = b"", total
        elif not self._expected:
            return []  # a continuation with no beginning
        self._buffer += body
        if len(self._buffer) > self._expected:
            self._abandon()
            return []
        if not flags & _FLAG_LAST:
            return []
        message, self._buffer, self._expected = self._buffer, b"", 0
        return self._message(message)

    def _abandon(self) -> None:
        """Drop a message that cannot be accepted (too large, or longer than it said). The
        request it answered is dead too: leaving it pending would blind every later paste."""
        self._buffer, self._expected = b"", 0
        self._pending_format = None

    def _message(self, message: bytes) -> list[bytes]:
        if len(message) < 8:
            return []
        msg_type, msg_flags, data_len = struct.unpack_from("<HHI", message, 0)
        data = message[8 : 8 + data_len]
        if len(data) < data_len:
            return []
        if msg_type == CB_FORMAT_LIST:
            return self._format_list(data)
        if msg_type == CB_FORMAT_DATA_RESPONSE:
            self._data_response(msg_flags, data)
            # The server's own Format List claims clipboard ownership, which would cancel a
            # request still in flight; so it follows the answer to ours, not the request.
            return [self._take_offer()] if self._offer_pending else []

        if msg_type == CB_FORMAT_DATA_REQUEST:
            wanted = struct.unpack_from("<I", data, 0)[0] if len(data) >= 4 else 0
            if self.offer and wanted in (CF_UNICODETEXT, CF_TEXT):
                self.offer_reads += 1
                text = self.offer.encode(
                    "utf-16-le" if wanted == CF_UNICODETEXT else "cp1252", errors="replace"
                )
                text += b"\x00\x00" if wanted == CF_UNICODETEXT else b"\x00"
                return [_pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text)]
            return [_pdu(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL)]
        return []  # capabilities, temporary directory, file contents, locks: not served

    def _format_list(self, data: bytes) -> list[bytes]:
        self.offered_lists += 1
        ids = [
            struct.unpack_from("<I", data, at)[0]
            for at in range(0, len(data) - _SHORT_FORMAT_ENTRY + 1, _SHORT_FORMAT_ENTRY)
        ]
        self.formats_seen.update(ids)
        replies = [_pdu(CB_FORMAT_LIST_RESPONSE, CB_RESPONSE_OK)]
        wanted = next((f for f in _TEXT_FORMATS if f in ids), None)
        # A new Format List means the clipboard changed again: whatever was being waited for is
        # stale, so it is replaced rather than blocking the new paste.
        self._pending_format = None
        if wanted is not None and len(self.texts) < MAX_TEXTS:
            self._pending_format = wanted
            replies.append(_pdu(CB_FORMAT_DATA_REQUEST, 0, struct.pack("<I", wanted)))
        if self._offer_pending and self._pending_format is None:
            replies.append(self._take_offer())  # nothing outstanding to cancel
        return replies

    def _take_offer(self) -> bytes:
        self._offer_pending = False
        return self._offer_list()

    def _data_response(self, flags: int, data: bytes) -> None:
        format_id, self._pending_format = self._pending_format, None
        if format_id is None or not flags & CB_RESPONSE_OK or len(self.texts) >= MAX_TEXTS:
            return
        if format_id == CF_UNICODETEXT:
            text = data.decode("utf-16-le", errors="replace")
        else:
            text = data.decode("cp1252", errors="replace")
        text = text.split("\x00", 1)[0]  # the text is NUL-terminated
        if text:
            self.texts.append(_printable(text)[:MAX_TEXT_CHARS])

    def take_new_text(self, already: int) -> list[str]:
        """Texts recorded after the first `already` ones (so callers can report each once)."""
        return self.texts[already:]


def _printable(text: str) -> str:
    """Keep line breaks and tabs, replace other control characters: pasted text is an
    attacker's, and ends up in events and reports."""
    return "".join(c if c.isprintable() or c in "\r\n\t" else "?" for c in text)
