"""Pure IMAP helpers: sequence sets, FETCH items, ENVELOPE, BODYSTRUCTURE, SEARCH.

No sockets and no HoneyPot-MCP imports, so every function is tested directly and the
protocol class in `imap.py` stays thin. Written against RFC 3501.

Two rules run through all of it:

* A message is whatever a stranger sent. Parsing is bounded (`_PARSE_LIMIT`), nothing here
  trusts a header for anything but display, and a part that cannot be found yields an empty
  result rather than an exception.
* `BODY[...]` sections are the message's bytes as stored, *not* decoded: `BODY[1]` of a
  quoted-printable part is the quoted-printable text. Decoding would corrupt an attachment
  that a client then re-decodes itself.
"""

from __future__ import annotations

import email
import email.message
import email.policy
import email.utils
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from email.utils import getaddresses, parsedate_to_datetime

# Most bytes of a message that are parsed. The maildrop already caps a message at 128 KB.
_PARSE_LIMIT = 512 * 1024
_MAX_PART_DEPTH = 12
# A message with more MIME containers or nested messages than this is not parsed as a tree:
# the standard parser recurses per level and a 128 KB message can nest ~1500 deep, which
# overflows the stack (and takes seconds before it does).
_MAX_CONTAINERS = 40
# Longest run of digits accepted as a number. `int()` refuses more than 4300, and nothing here
# needs more than a 32-bit value.
_MAX_DIGITS = 10
_MAX_SEARCH_DEPTH = 32
_MAX_ADDRESS_HEADER = 4096


# ── Sequence sets ────────────────────────────────────────────────────────────


def _number(text: str) -> int | None:
    """A plain ASCII decimal of sensible length, else None."""
    if text.isascii() and text.isdigit() and len(text) <= _MAX_DIGITS:
        return int(text)
    return None


def parse_seqset(text: str, largest: int) -> list[int]:
    """Expand an IMAP sequence set against `largest` (what `*` stands for).

    `3`, `2:5`, `1,4,7:9`, `5:*`, `*`. A reversed range means the same as the forward one,
    and anything outside `1..largest` is dropped. Invalid tokens are ignored; an empty or
    wholly invalid set yields nothing (the caller answers BAD)."""
    numbers: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            low_text, _, high_text = part.partition(":")
            low = largest if low_text == "*" else _number(low_text)
            high = largest if high_text == "*" else _number(high_text)
            if low is None or high is None:
                continue
            if low > high:
                low, high = high, low
            numbers.update(range(max(1, low), min(largest, high) + 1))
        elif part == "*":
            if largest >= 1:
                numbers.add(largest)
        elif (n := _number(part)) is not None and 1 <= n <= largest:
            numbers.add(n)
    return sorted(numbers)


def valid_seqset(text: str) -> bool:
    """Whether `text` is syntactically a sequence set (so BAD can be told from "no match")."""
    one = r"(?:\d{1,10}|\*)"
    return bool(re.fullmatch(rf"{one}(?::{one})?(?:,{one}(?::{one})?)*", text))


def uid_set_to_seqnums(text: str, uids: list[int]) -> list[int]:
    """Sequence numbers (1-based) of the messages whose UID is in the UID set `text`.
    `uids` is the UID of each message in sequence order."""
    largest = max(uids, default=0)
    wanted = set(parse_seqset(text, largest))
    return [i + 1 for i, uid in enumerate(uids) if uid in wanted]


# ── FETCH item tokenizer ─────────────────────────────────────────────────────

_MACROS = {
    "ALL": ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"],
    "FAST": ["FLAGS", "INTERNALDATE", "RFC822.SIZE"],
    "FULL": ["FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"],
}


def tokenize_fetch_items(text: str) -> list[str]:
    """Split FETCH data items, keeping `BODY[HEADER.FIELDS (From To)]` as one token.

    Accepts `FLAGS`, `(FLAGS UID)`, and the macros ALL/FAST/FULL (expanded). Returns the
    items upper-cased only where the grammar is case-insensitive; section contents keep
    their case (header field names are matched case-insensitively later)."""
    text = text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1].strip()
    tokens: list[str] = []
    current: list[str] = []
    square = round_ = 0
    for char in text:
        if char == "[":
            square += 1
        elif char == "]":
            square = max(0, square - 1)
        elif char == "(":
            round_ += 1
        elif char == ")":
            round_ = max(0, round_ - 1)
        if char == " " and square == 0 and round_ == 0:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        tokens.append("".join(current))
    expanded: list[str] = []
    for token in tokens:
        macro = _MACROS.get(token.upper())
        expanded.extend(macro if macro else [token])
    return expanded


_BODY_ITEM = re.compile(
    r"(BODY(?:\.PEEK)?)\[([^\]]{0,200})\](?:<(\d{1,10})(?:\.(\d{1,10}))?>)?\Z", re.I
)


def parse_body_item(item: str) -> tuple[bool, str, tuple[int, int | None] | None] | None:
    """`BODY[section]<offset.count>` -> (peek, section, partial), or None if not one."""
    match = _BODY_ITEM.match(item)
    if not match:
        return None
    partial = None
    if match.group(3) is not None:
        partial = (int(match.group(3)), int(match.group(4)) if match.group(4) else None)
    return match.group(1).upper().endswith(".PEEK"), match.group(2).strip(), partial


# ── Strings ──────────────────────────────────────────────────────────────────


def imap_string(value: str | None) -> str:
    """A quoted string, a literal when it cannot be quoted, or NIL.

    A literal's length is that of the UTF-8 encoding, because responses are encoded as a
    whole before being written."""
    if value is None:
        return "NIL"
    if any(ord(c) > 126 or ord(c) < 32 for c in value) or len(value) > 900:
        return f"{{{len(value.encode('utf-8', errors='replace'))}}}\r\n{value}"
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _raw_header(msg: email.message.Message, name: str) -> str | None:
    """A header exactly as sent (encoded-words intact), folded onto one line."""
    value = msg.get(name)
    if value is None:
        return None
    return re.sub(r"\s*\r?\n\s*", " ", str(value)).strip()


# ── ENVELOPE ─────────────────────────────────────────────────────────────────


def _too_nested(raw: bytes) -> bool:
    lowered = raw[:_PARSE_LIMIT].lower()
    return (
        lowered.count(b"boundary") > _MAX_CONTAINERS or lowered.count(b"message/") > _MAX_CONTAINERS
    )


def _parse(raw: bytes) -> email.message.Message:
    """Parse a message, never raising. One nested beyond `_MAX_CONTAINERS` is read as its
    headers plus an opaque body (the tree is the expensive, recursive part); one the parser
    still chokes on becomes an empty message."""
    try:
        if _too_nested(raw):
            header, body = _split(raw)
            message = email.message_from_bytes(header, policy=email.policy.compat32)
            for name in ("Content-Type", "Content-Transfer-Encoding"):
                del message[name]
            message.set_payload(body.decode("latin-1"))
            return message
        return email.message_from_bytes(raw[:_PARSE_LIMIT], policy=email.policy.compat32)
    except Exception:
        return email.message.Message()


def _addresses(msg: email.message.Message, name: str) -> str | None:
    values = msg.get_all(name)
    if not values:
        return None
    entries = []
    try:
        # Bounded, and guarded: the address parser recurses on group syntax (`a:a:a:...`).
        parsed = getaddresses([str(v)[:_MAX_ADDRESS_HEADER] for v in values])
    except Exception:
        return None
    for display, address in parsed:
        if not address:
            continue
        local, _, host = address.rpartition("@") if "@" in address else (address, "", "")
        entries.append(
            f"({imap_string(display or None)} NIL {imap_string(local)} {imap_string(host or None)})"
        )
    return "(" + "".join(entries) + ")" if entries else None


def build_envelope(raw: bytes) -> str:
    """The ENVELOPE structure for a message (RFC 3501 §7.4.2). Never raises: a message the
    parser cannot handle yields an envelope of NILs, so one hostile message cannot break a
    FETCH for the whole mailbox."""
    try:
        return _envelope(_parse(raw))
    except Exception:
        return "(" + " ".join(["NIL"] * 10) + ")"


def _envelope(msg: email.message.Message) -> str:
    sender = _addresses(msg, "From")
    fields = [
        imap_string(_raw_header(msg, "Date")),
        imap_string(_raw_header(msg, "Subject")),
        sender or "NIL",
        _addresses(msg, "Sender") or sender or "NIL",
        _addresses(msg, "Reply-To") or sender or "NIL",
        _addresses(msg, "To") or "NIL",
        _addresses(msg, "Cc") or "NIL",
        _addresses(msg, "Bcc") or "NIL",
        imap_string(_raw_header(msg, "In-Reply-To")),
        imap_string(_raw_header(msg, "Message-ID")),
    ]
    return "(" + " ".join(fields) + ")"


# ── Bytes of a message and of its parts ──────────────────────────────────────


def _split(raw: bytes) -> tuple[bytes, bytes]:
    """(header block including the blank line, body)."""
    for separator in (b"\r\n\r\n", b"\n\n"):
        at = raw.find(separator)
        if at >= 0:
            return raw[: at + len(separator)], raw[at + len(separator) :]
    return raw + b"\r\n\r\n", b""


# compat32 with CRLF line endings: IMAP sizes and literals count the bytes a client receives,
# and the generator's default is bare LF, which made every octet count short by one per line.
_WIRE = email.policy.compat32.clone(linesep="\r\n")


def _flatten(part: email.message.Message) -> bytes:
    """A part as bytes, headers and all, without re-wrapping its header lines."""
    try:
        return part.as_bytes(policy=_WIRE)
    except Exception:
        return b""


def _body_of(part: email.message.Message) -> bytes:
    """The part's body exactly as encoded in the message (not transfer-decoded)."""
    return _split(_flatten(part))[1]


def _children(part: email.message.Message) -> list[email.message.Message]:
    payload = part.get_payload()
    return (
        [p for p in payload if isinstance(p, email.message.Message)]
        if isinstance(payload, list)
        else []
    )


def _is_container(part: email.message.Message) -> bool:
    """A real multipart (not message/*, whose payload is also a list in this parser)."""
    return part.get_content_maintype() == "multipart" and part.is_multipart()


# ── BODYSTRUCTURE ────────────────────────────────────────────────────────────


def _param_text(value: object) -> str:
    """A parameter value as text. RFC 2231 parameters (`filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`)
    come back from the parser as (charset, language, value) tuples."""
    if isinstance(value, tuple):
        try:
            return str(email.utils.collapse_rfc2231_value(value))
        except Exception:
            return str(value[-1]) if value else ""
    return str(value)


def _params(pairs: Sequence[tuple[str, object]] | None) -> str:
    items = [(k, _param_text(v)) for k, v in (pairs or []) if k]
    if not items:
        return "NIL"
    return "(" + " ".join(f"{imap_string(k.upper())} {imap_string(v)}" for k, v in items) + ")"


def _content_params(part: email.message.Message) -> str:
    return _params((part.get_params() or [])[1:])  # [0] is the type itself


def _disposition(part: email.message.Message) -> str:
    value = part.get("Content-Disposition")
    if not value:
        return "NIL"
    kind = str(value).split(";", 1)[0].strip().lower()
    pairs = (part.get_params(header="content-disposition") or [])[1:]
    return f"({imap_string(kind.upper())} {_params(pairs)})"


def build_bodystructure(raw: bytes, *, extended: bool = True) -> str:
    """BODYSTRUCTURE (extended) or BODY (basic) for a message. Never raises: a message that
    cannot be described is reported as one plain-text part of its real size."""
    try:
        return _structure(_parse(raw), extended=extended, depth=0)
    except Exception:
        body = _split(raw)[1]
        lines = body.count(b"\n")
        tail = " NIL NIL NIL NIL" if extended else ""
        return f'("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "7BIT" {len(body)} {lines}{tail})'


def _structure(part: email.message.Message, *, extended: bool, depth: int) -> str:
    if depth > _MAX_PART_DEPTH:
        return '("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)'
    if _is_container(part):
        subs = "".join(_structure(c, extended=extended, depth=depth + 1) for c in _children(part))
        out = f"{subs} {imap_string(part.get_content_subtype().upper())}"
        if extended:
            out += f" {_content_params(part)} {_disposition(part)} NIL NIL"
        return f"({out})"

    maintype = part.get_content_maintype().upper()
    subtype = part.get_content_subtype().upper()
    body = _body_of(part)
    encoding = str(part.get("Content-Transfer-Encoding") or "7BIT").strip().upper()
    core = (
        f"{imap_string(maintype)} {imap_string(subtype)} {_content_params(part)} "
        f"{imap_string(_raw_header(part, 'Content-ID'))} "
        f"{imap_string(_raw_header(part, 'Content-Description'))} "
        f"{imap_string(encoding)} {len(body)}"
    )
    lines = body.count(b"\n")
    if maintype == "TEXT":
        core += f" {lines}"
    elif maintype == "MESSAGE" and subtype == "RFC822":
        inner = _children(part)
        if inner:
            core += (
                f" {_envelope(inner[0])} "
                f"{_structure(inner[0], extended=extended, depth=depth + 1)} {lines}"
            )
    if extended:
        core += f" NIL {_disposition(part)} NIL NIL"  # md5, disposition, language, location
    return f"({core})"


# ── FETCH: sections ──────────────────────────────────────────────────────────


def _field_block(header: bytes, names: set[str], *, exclude: bool) -> bytes:
    """The header lines whose field is (or, with `exclude`, is not) in `names`."""
    out: list[bytes] = []
    keep = False
    for line in header.splitlines(keepends=True):
        if line.strip(b"\r\n") == b"":
            break
        if line[:1] in (b" ", b"\t"):
            if keep:
                out.append(line)
            continue
        field = line.split(b":", 1)[0].decode("latin-1").strip().upper()
        keep = (field in names) != exclude
        if keep:
            out.append(line)
    out.append(b"\r\n")
    return b"".join(out)


def _find_part(msg: email.message.Message, numbers: list[int]) -> email.message.Message | None:
    current = msg
    for n in numbers:
        if _is_container(current):
            kids = _children(current)
        elif current.get_content_type() == "message/rfc822" and _children(current):
            inner = _children(current)[0]
            kids = _children(inner) if _is_container(inner) else [inner]
        else:
            kids = [current]  # a leaf: part "1" is the leaf itself
        if not 1 <= n <= len(kids):
            return None
        current = kids[n - 1]
    return current


_SECTION = re.compile(
    r"((?:\d{1,6}\.){0,12}\d{1,6})?(?:\.?([A-Za-z.]{1,24})(?:\s*\(([^)]{0,500})\))?)?\Z"
)


def fetch_section(raw: bytes, section: str, partial: tuple[int, int | None] | None = None) -> bytes:
    """The bytes of `BODY[section]`: "", HEADER, TEXT, HEADER.FIELDS (..), HEADER.FIELDS.NOT (..),
    a part number such as 2.1, or a part number with .MIME / .HEADER / .TEXT."""
    section = section.strip()
    match = _SECTION.match(section)
    numbers: list[int] = []
    keyword, fields = "", ""
    if match:
        numbers = [int(n) for n in match.group(1).split(".")] if match.group(1) else []
        keyword = (match.group(2) or "").upper()
        fields = match.group(3) or ""
    elif section:
        return b""

    if numbers:
        try:
            return _numbered_section(raw, numbers, keyword, fields, partial)
        except Exception:
            return b""
    header, body = _split(raw)
    return _slice(_flat_section(raw, header, body, keyword, fields), partial)


def _slice(data: bytes, partial: tuple[int, int | None] | None) -> bytes:
    if partial is None:
        return data
    offset, count = partial
    return data[offset:] if count is None else data[offset : offset + count]


def _flat_section(raw: bytes, header: bytes, body: bytes, keyword: str, fields: str) -> bytes:
    if keyword == "HEADER":
        return header
    if keyword == "TEXT":
        return body
    if keyword.startswith("HEADER.FIELDS"):
        names = {f.upper() for f in fields.split()}
        return _field_block(header, names, exclude=keyword.endswith(".NOT"))
    return raw if not keyword else b""


def _numbered_section(
    raw: bytes,
    numbers: list[int],
    keyword: str,
    fields: str,
    partial: tuple[int, int | None] | None,
) -> bytes:
    """A section of a numbered MIME part. Raises on a message the parser cannot handle (the
    caller turns that into an empty section)."""
    part = _find_part(_parse(raw), numbers)
    if part is None:
        return b""
    unit = _flatten(part)
    is_message = part.get_content_type() == "message/rfc822" and bool(_children(part))
    inner = _flatten(_children(part)[0]) if is_message else unit
    header, body = _split(unit)
    if keyword == "MIME":
        data = header
    elif keyword == "HEADER":
        data = _split(inner)[0]
    elif keyword == "TEXT":
        data = _split(inner)[1]
    elif keyword.startswith("HEADER.FIELDS"):
        names = {f.upper() for f in fields.split()}
        data = _field_block(_split(inner)[0], names, exclude=keyword.endswith(".NOT"))
    elif not keyword:
        data = _split(inner)[1] if is_message else body
    else:
        data = b""
    return _slice(data, partial)


# ── INTERNALDATE ─────────────────────────────────────────────────────────────


def _message_datetime(raw: bytes) -> datetime:
    try:
        value = _parse(raw[:8192]).get("Date")
        if value:
            parsed = parsedate_to_datetime(str(value))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except Exception:
        pass
    return datetime.now(UTC)


def internaldate(raw: bytes) -> str:
    """INTERNALDATE: `05-Oct-2026 12:34:56 +0000`."""
    return _message_datetime(raw).strftime("%d-%b-%Y %H:%M:%S %z")


# ── SEARCH ───────────────────────────────────────────────────────────────────

_FLAG_KEYS = {
    "SEEN": ("\\Seen", True), "UNSEEN": ("\\Seen", False),
    "ANSWERED": ("\\Answered", True), "UNANSWERED": ("\\Answered", False),
    "FLAGGED": ("\\Flagged", True), "UNFLAGGED": ("\\Flagged", False),
    "DELETED": ("\\Deleted", True), "UNDELETED": ("\\Deleted", False),
    "DRAFT": ("\\Draft", True), "UNDRAFT": ("\\Draft", False),
    "RECENT": ("\\Recent", True), "OLD": ("\\Recent", False),
}  # fmt: skip
_HEADER_KEYS = {"SUBJECT": "subject", "FROM": "from", "TO": "to", "CC": "cc", "BCC": "bcc"}
_DATE_KEYS = {"SINCE", "BEFORE", "ON", "SENTSINCE", "SENTBEFORE", "SENTON"}


def tokenize_search(text: str) -> list[str]:
    """Split SEARCH criteria on spaces, honouring quotes; `(` and `)` are their own tokens."""
    tokens: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif quoted:
            current.append(char)
        elif char in "()":
            if current:
                tokens.append("".join(current))
                current = []
            tokens.append(char)
        elif char == " ":
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens


class SearchError(ValueError):
    """The criteria are not valid IMAP SEARCH syntax (the client is told BAD)."""


class _Message:
    """What one search evaluation needs, parsed once."""

    def __init__(
        self, raw: bytes, seq: int, uid: int, flags: set[str], count: int, largest_uid: int
    ):
        self.raw, self.seq, self.uid, self.flags = raw, seq, uid, flags
        self.count, self.largest_uid = count, largest_uid
        self._parsed: email.message.Message | None = None

    @property
    def parsed(self) -> email.message.Message:
        if self._parsed is None:
            self._parsed = _parse(self.raw)
        return self._parsed

    def body_text(self) -> str:
        return _split(self.raw)[1].decode("utf-8", errors="replace")


def _term(tokens: list[str], pos: int, msg: _Message, depth: int = 0) -> tuple[bool, int]:
    """Evaluate one search key starting at `pos`; returns (matches, next position)."""
    if depth > _MAX_SEARCH_DEPTH:
        raise SearchError("criteria nested too deeply")
    if pos >= len(tokens):
        raise SearchError("missing search key")
    token = tokens[pos]
    key = token.upper()
    pos += 1

    def argument() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise SearchError(f"{key} needs an argument")
        pos += 1
        return tokens[pos - 1]

    if token == "(":
        result = True
        while pos < len(tokens) and tokens[pos] != ")":
            matched, pos = _term(tokens, pos, msg, depth + 1)
            result = result and matched
        if pos >= len(tokens):
            raise SearchError("unbalanced parenthesis")
        return result, pos + 1
    if key == "ALL":
        return True, pos
    if key in _FLAG_KEYS:
        flag, wanted = _FLAG_KEYS[key]
        return (flag in msg.flags) == wanted, pos
    if key == "NEW":
        return "\\Recent" in msg.flags and "\\Seen" not in msg.flags, pos
    if key in ("KEYWORD", "UNKEYWORD"):
        flag = argument()
        return (flag.lower() in {f.lower() for f in msg.flags}) == (key == "KEYWORD"), pos
    if key == "NOT":
        matched, pos = _term(tokens, pos, msg, depth + 1)
        return not matched, pos
    if key == "OR":
        left, pos = _term(tokens, pos, msg, depth + 1)
        right, pos = _term(tokens, pos, msg, depth + 1)
        return left or right, pos
    if key in _HEADER_KEYS:
        needle = argument().lower()
        return needle in str(msg.parsed.get(_HEADER_KEYS[key], "")).lower(), pos
    if key == "HEADER":
        name, needle = argument(), argument().lower()
        values = msg.parsed.get_all(name) or []
        return (any(needle in str(v).lower() for v in values) if needle else bool(values)), pos
    if key == "BODY":
        return argument().lower() in msg.body_text().lower(), pos
    if key == "TEXT":
        return argument().lower() in msg.raw.decode("utf-8", errors="replace").lower(), pos
    if key in ("SMALLER", "LARGER"):
        limit = argument()
        if not limit.isdigit():
            raise SearchError(f"{key} needs a number")
        return (len(msg.raw) < int(limit)) if key == "SMALLER" else (len(msg.raw) > int(limit)), pos
    if key == "UID":
        spec = argument()
        if not valid_seqset(spec):
            raise SearchError("bad UID set")
        return msg.uid in parse_seqset(spec, msg.largest_uid), pos
    if key in _DATE_KEYS:
        text = argument()
        try:
            day = datetime.strptime(text, "%d-%b-%Y").date()
        except ValueError as e:
            raise SearchError("bad date") from e
        when = _message_datetime(msg.raw).date()
        kind = key.removeprefix("SENT")
        return {"SINCE": when >= day, "BEFORE": when < day, "ON": when == day}[kind], pos
    if valid_seqset(token):  # a bare set of message sequence numbers
        return msg.seq in parse_seqset(token, msg.count), pos
    raise SearchError(f"unknown search key {token[:24]!r}")


def matches_search(
    raw: bytes,
    seq: int,
    uid: int,
    flags: set[str],
    criteria: list[str],
    *,
    count: int,
    largest_uid: int,
) -> bool:
    """Whether a message satisfies every criterion (they are ANDed). Raises `SearchError`."""
    msg = _Message(raw, seq, uid, flags, count, largest_uid)
    pos, result = 0, True
    while pos < len(criteria):
        matched, pos = _term(criteria, pos, msg)
        result = result and matched
    return result


def validate_search(criteria: list[str]) -> None:
    """Raise `SearchError` if `criteria` is not valid SEARCH syntax, even when the mailbox is
    empty and nothing would otherwise be evaluated."""
    if not criteria:
        raise SearchError("SEARCH needs at least one criterion")
    matches_search(b"Subject: x\r\n\r\n", 1, 1, set(), criteria, count=1, largest_uid=1)
