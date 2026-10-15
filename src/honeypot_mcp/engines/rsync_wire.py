"""rsync wire format for the honeypot's file listing: the server (sender) side
of protocol 30/31, plus the decoy trees it lists.

A real `rsync rsync://host/module/` does not stop at `@RSYNCD: OK`: the client
sends its server-side argument vector, then waits for the daemon's setup bytes
and the file list. Without them the client hangs, which tells the operator of
the scanner that nothing real is on the other end. This module produces those
bytes.

What is sent, in order (rsync 3.x, no incremental recursion):

1. compat flags (one byte) and the 4-byte checksum seed, in the clear;
2. everything after that is wrapped in multiplexed `MSG_DATA` frames
   (4-byte little-endian header `(7 + tag) << 24 | length`);
3. the file list: one entry per file (xmit flags, name, size as a "varlong",
   mtime, mode, optional uid/gid), a zero byte to end it, then the (empty)
   uid and gid name tables when the client asked to preserve owner/group.

Nothing here touches the filesystem: the trees are generated in memory, so no
argument the client sends can reach a path.

Protocol 29 and older (openrsync, rsync 2.x) encode the list differently and
are not served; the caller closes those sessions.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# ── constants (from rsync's rsync.h / flist.c) ──────────────────────────────

MPLEX_BASE = 7
MSG_DATA = 0
MSG_ERROR_XFER = 1

CF_SYMLINK_TIMES = 1 << 1
CF_SAFE_FLIST = 1 << 3
# Incremental recursion is deliberately not offered: the client then expects the
# whole list up front, which is one flat sequence rather than a stream of
# per-directory lists.
COMPAT_FLAGS = CF_SYMLINK_TIMES | CF_SAFE_FLIST

XMIT_TOP_DIR = 1 << 0
XMIT_SAME_MODE = 1 << 1
XMIT_EXTENDED_FLAGS = 1 << 2
XMIT_SAME_UID = 1 << 3
XMIT_SAME_GID = 1 << 4
XMIT_SAME_NAME = 1 << 5
XMIT_LONG_NAME = 1 << 6
XMIT_SAME_TIME = 1 << 7
XMIT_NO_CONTENT_DIR = 1 << 8

S_IFDIR = 0o040000
S_IFREG = 0o100000

# One MSG_DATA frame carries at most this many payload bytes.
_FRAME_BYTES = 16384
# Entries sent per session; the decoy trees are far smaller, so this only
# bounds repeated path arguments.
MAX_LISTED = 2000
# Option letters / long options that change the per-entry wire format in ways
# this encoder does not produce (ACLs, xattrs, atimes, crtimes, checksums).
_UNSUPPORTED_SHORT = set("AXUNc")
_UNSUPPORTED_LONG = (
    "--acls",
    "--xattrs",
    "--atimes",
    "--crtimes",
    "--checksum",
    "--files-from",
    "--iconv",
)


# ── encoding primitives ─────────────────────────────────────────────────────


def encode_varnum(x: int, min_bytes: int, max_bytes: int) -> bytes:
    """rsync's `write_varint` (min 1, max 4) / `write_varlong` (min n, max 8).

    The first byte carries a unary length prefix in its high bits followed by
    the top bits of the value; the remaining bytes are the low bytes, little
    endian.
    """
    if x < 0 or x >= 1 << (8 * max_bytes):
        raise ValueError("value out of range")
    b = bytearray(1 + max_bytes)
    b[1:] = x.to_bytes(max_bytes, "little")
    cnt = max_bytes
    while cnt > min_bytes and b[cnt] == 0:
        cnt -= 1
    bit = 1 << (7 - cnt + min_bytes)
    if b[cnt] >= bit:
        cnt += 1
        b[0] = ~(bit - 1) & 0xFF
    elif cnt > min_bytes:
        b[0] = b[cnt] | (~(bit * 2 - 1) & 0xFF)
    else:
        b[0] = b[cnt]
    return bytes(b[:cnt])


def encode_varint(x: int) -> bytes:
    return encode_varnum(x, 1, 4)


def encode_varlong(x: int, min_bytes: int) -> bytes:
    return encode_varnum(x, min_bytes, 8)


def mplex(payload: bytes, tag: int = MSG_DATA) -> bytes:
    """Wrap `payload` in multiplexed frames (empty payload -> no frames)."""
    out = bytearray()
    for i in range(0, len(payload), _FRAME_BYTES):
        chunk = payload[i : i + _FRAME_BYTES]
        out += struct.pack("<I", ((MPLEX_BASE + tag) << 24) | len(chunk))
        out += chunk
    return bytes(out)


# ── decoy trees ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Node:
    name: str
    mode: int  # full st_mode, file type included
    size: int
    mtime: int
    uid: int = 0
    gid: int = 0
    children: tuple[Node, ...] = ()

    @property
    def is_dir(self) -> bool:
        return self.mode & 0o170000 == S_IFDIR

    def child(self, name: str) -> Node | None:
        for c in self.children:
            if c.name == name:
                return c
        return None


def _h(seed: str, label: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}|{label}".encode()).digest()[:8], "big")


def _between(seed: str, label: str, lo: int, hi: int) -> int:
    return lo + _h(seed, label) % (hi - lo + 1)


def _file(name: str, size: int, mtime: int, *, mode: int = 0o644, uid: int = 0, gid: int = 0):
    return Node(name, S_IFREG | mode, size, mtime, uid, gid)


def _dir(name: str, mtime: int, children: list[Node], *, uid: int = 0, gid: int = 0, mode=0o755):
    return Node(
        name, S_IFDIR | mode, 4096, mtime, uid, gid, tuple(sorted(children, key=lambda n: n.name))
    )


class _Clock:
    """Dates for the decoy: the last full day is yesterday, so no file is ever
    dated in the future whatever the hour."""

    def __init__(self, now: float) -> None:
        self.today = datetime.fromtimestamp(now, UTC).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

    def day(self, n: int) -> datetime:
        return self.today - timedelta(days=n)

    def ymd(self, n: int) -> str:
        return self.day(n).strftime("%Y%m%d")

    def at(self, n: int, hour: int, minute: int = 0, second: int = 0) -> int:
        d = self.day(n) + timedelta(hours=hour, minutes=minute, seconds=second)
        return int(d.timestamp())


def _backups(seed: str, c: _Clock) -> Node:
    web: list[Node] = []
    for n in range(1, 4):
        ymd = c.ymd(n)
        t = c.at(n, 1, _between(seed, f"b{n}", 5, 40))
        web.append(_file(f"etc-{ymd}.tar.gz", _between(seed, f"etc{n}", 1_800_000, 3_900_000), t))
        web.append(
            _file(
                f"home-{ymd}.tar.gz", _between(seed, f"home{n}", 180_000_000, 900_000_000), t + 90
            )
        )
        web.append(
            _file(
                f"www-{ymd}.tar.gz", _between(seed, f"www{n}", 400_000_000, 2_100_000_000), t + 240
            )
        )
    weekly: list[Node] = []
    back = back_days(c)
    for w in range(1, 4):
        # Sundays: step back to the most recent Sunday, then by weeks.
        n = back + 7 * (w - 1)
        weekly.append(
            _file(
                f"full-{c.ymd(n)}.tar.zst",
                _between(seed, f"wk{w}", 2_000_000_000, 6_400_000_000),
                c.at(n, 3, _between(seed, f"wt{w}", 0, 50)),
                mode=0o640,
            )
        )
    return _dir(
        "",
        c.at(1, 3, 12),
        [
            _dir("web01", c.at(1, 1, 50), web),
            _dir("weekly", c.at(back, 4, 20), weekly),
            _file("backup.log", _between(seed, "log", 9_000, 90_000), c.at(1, 3, 12), uid=0),
        ],
    )


def back_days(c: _Clock) -> int:
    return (c.today.weekday() + 1) % 7 or 7


def _db_dumps(seed: str, c: _Clock) -> Node:
    dumps: list[Node] = []
    for n in range(1, 8):
        base = _between(seed, "dbsize", 180_000_000, 260_000_000)
        grow = _between(seed, f"g{n}", 0, 4_000_000)
        t = c.at(n, 2, 10, _between(seed, f"ds{n}", 0, 59))
        dumps.append(
            _file(
                f"appdb-{c.ymd(n)}.sql.gz", base - n * 350_000 + grow, t, mode=0o600, uid=26, gid=26
            )
        )
        dumps.append(
            _file(
                f"globals-{c.ymd(n)}.sql.gz",
                _between(seed, f"gl{n}", 2_400, 6_900),
                t - 11,
                mode=0o600,
                uid=26,
                gid=26,
            )
        )
    monthly = []
    for k in range(3):
        month = c.today.month - k
        year = c.today.year + (month - 1) // 12
        first = c.today.replace(year=year, month=(month - 1) % 12 + 1, day=1)
        if first >= c.today:
            continue  # this month's first-of-month dump is not due until tonight
        monthly.append(
            _file(
                f"appdb-{first.strftime('%Y%m%d')}.sql.gz",
                _between(seed, f"m{k}", 170_000_000, 250_000_000),
                int(first.timestamp()) + 2 * 3600 + 600,
                mode=0o600,
                uid=26,
                gid=26,
            )
        )
    return _dir(
        "",
        c.at(1, 2, 12),
        [
            *dumps,
            _dir("monthly", c.at(1, 2, 14), monthly, uid=26, gid=26),
            _file(
                "pg_dump.log",
                _between(seed, "pglog", 3_000, 40_000),
                c.at(1, 2, 12),
                uid=26,
                gid=26,
            ),
            _file("README", 214, c.at(120, 11, 5)),
        ],
        uid=26,
        gid=26,
    )


def _public(seed: str, c: _Clock) -> Node:
    pub = [
        _file("CHECKSUMS.sha256", _between(seed, "cs", 400, 900), c.at(9, 8, 30)),
        _file("release-notes.txt", _between(seed, "rn", 3_000, 9_000), c.at(9, 8, 29)),
        _dir(
            "tools",
            c.at(40, 14, 2),
            [
                _file(
                    "cli-tools-2.4.1.tar.gz",
                    _between(seed, "cli", 2_000_000, 6_000_000),
                    c.at(40, 14, 1),
                )
            ],
        ),
    ]
    return _dir(
        "",
        c.at(9, 8, 31),
        [
            _file("README.txt", _between(seed, "readme", 400, 1_200), c.at(75, 10, 15)),
            _dir("pub", c.at(9, 8, 31), pub),
        ],
    )


_BUILDERS = {"backups": _backups, "db-dumps": _db_dumps, "public": _public}


def decoy_tree(module: str, honeypot_name: str, now: float) -> Node | None:
    """The tree listed for an open `module`, stable per `honeypot_name` for the
    whole of a UTC day (dates are relative to `now`, so the newest backup is
    always last night's, but nothing varies between connections)."""
    build = _BUILDERS.get(module)
    if build is None:
        return None
    return build(f"{honeypot_name}:{module}", _Clock(now))


# ── client arguments ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ServerArgs:
    sender: bool = False
    recursive: bool = False
    dirs: bool = False
    owner: bool = False
    group: bool = False
    numeric_ids: bool = False
    unsupported: str | None = None


def parse_server_args(argv: list[str]) -> ServerArgs:
    """Interpret the option words the client sends to its remote server
    (`--server --sender -vlogDtpre.iLsfxCIvu . module/`): which way data flows
    and the few options that change how a file-list entry is encoded."""
    sender = recursive = dirs = owner = group = numeric = False
    unsupported: str | None = None
    for a in argv:
        if a == ".":
            break
        if a.startswith("--"):
            word = a.split("=", 1)[0]
            if word == "--sender":
                sender = True
            elif word in ("--recursive",):
                recursive = True
            elif word in ("--no-recursive", "--no-r"):
                recursive = False
            elif word == "--dirs":
                dirs = True
            elif word in ("--no-dirs", "--no-d"):
                dirs = False
            elif word == "--numeric-ids":
                numeric = True
            elif word == "--owner":
                owner = True
            elif word == "--group":
                group = True
            elif word == "--no-owner":
                owner = False
            elif word == "--no-group":
                group = False
            elif word in _UNSUPPORTED_LONG:
                unsupported = unsupported or word
            continue
        if a.startswith("-") and len(a) > 1:
            # Short cluster; `e<info>` (client capability string) ends it.
            for ch in a[1:]:
                if ch == "e":
                    break
                if ch == "r":
                    recursive = True
                elif ch == "d":
                    dirs = True
                elif ch == "o":
                    owner = True
                elif ch == "g":
                    group = True
                elif ch == "a":
                    recursive = owner = group = True
                elif ch in _UNSUPPORTED_SHORT:
                    unsupported = unsupported or f"-{ch}"
    return ServerArgs(sender, recursive, dirs, owner, group, numeric, unsupported)


# ── file list ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ListEntry:
    name: str
    node: Node
    top: bool  # a top-level directory argument (XMIT_TOP_DIR)
    content: bool  # directory whose contents are sent too


def resolve_request(
    root: Node, request: str, module: str, args: ServerArgs
) -> list[ListEntry] | None:
    """The entries the sender produces for one path argument, or None when it
    does not exist. `request` is `module/path[/]` as sent (the daemon strips the
    module name; a trailing slash or a bare module means "the contents")."""
    path = request
    if path == module:
        path = ""
    elif path.startswith(module + "/"):
        path = path[len(module) + 1 :]
    contents = path == "" or path.endswith("/") or path.endswith("/.") or path == "."
    parts = [p for p in path.split("/") if p and p != "."]
    node = root
    for p in parts:
        nxt = node.child(p) if node.is_dir else None
        if nxt is None:
            return None
        node = nxt

    out: list[ListEntry] = []
    if not node.is_dir:
        return [ListEntry(parts[-1] if parts else node.name, node, False, False)]
    if not (args.recursive or args.dirs):
        return out  # a real sender skips directories here and says so on stderr

    def walk(n: Node, prefix: str) -> None:
        for c in n.children:
            nm = prefix + c.name
            if c.is_dir:
                out.append(ListEntry(nm, c, False, args.recursive))
                if args.recursive:
                    walk(c, nm + "/")
            else:
                out.append(ListEntry(nm, c, False, False))

    if contents:
        out.append(ListEntry(".", node, True, True))
        walk(node, "")
    else:
        out.append(ListEntry(parts[-1], node, True, args.recursive))
        if args.recursive:
            walk(node, parts[-1] + "/")
    return out


class _EntryWriter:
    """Delta state the format keeps between entries (same mode / time / owner /
    name prefix as the previous entry cost one flag bit instead of bytes)."""

    def __init__(self, args: ServerArgs) -> None:
        self._args = args
        self._mode: int | None = None
        self._time: int | None = None
        self._uid: int | None = None
        self._gid: int | None = None
        self._last = b""

    def encode(self, e: ListEntry) -> bytes:
        n = e.node
        if n.is_dir:
            x = (XMIT_TOP_DIR if e.top else 0) if e.content else XMIT_NO_CONTENT_DIR
        else:
            x = 0
        if n.mode == self._mode:
            x |= XMIT_SAME_MODE
        self._mode = n.mode
        send_uid = self._args.owner and n.uid != self._uid
        send_gid = self._args.group and n.gid != self._gid
        if self._args.owner and not send_uid:
            x |= XMIT_SAME_UID
        if self._args.group and not send_gid:
            x |= XMIT_SAME_GID
        if self._args.owner:
            self._uid = n.uid
        if self._args.group:
            self._gid = n.gid
        if n.mtime == self._time:
            x |= XMIT_SAME_TIME
        self._time = n.mtime

        name = e.name.encode("utf-8")
        l1 = 0
        while l1 < min(len(self._last), len(name), 255) and self._last[l1] == name[l1]:
            l1 += 1
        l2 = len(name) - l1
        self._last = name
        if l1:
            x |= XMIT_SAME_NAME
        if l2 > 255:
            x |= XMIT_LONG_NAME
        # A zero flag byte ends the list, so a non-directory with no flag set
        # carries the (meaningless for files) TOP_DIR bit, as rsync does.
        if x == 0 and not n.is_dir:
            x = XMIT_TOP_DIR

        out = bytearray()
        if x & 0xFF00 or x == 0:
            x |= XMIT_EXTENDED_FLAGS
            out += struct.pack("<H", x)
        else:
            out.append(x)
        if x & XMIT_SAME_NAME:
            out.append(l1)
        out += encode_varint(l2) if x & XMIT_LONG_NAME else bytes([l2])
        out += name[l1:]
        out += encode_varlong(n.size, 3)
        if not x & XMIT_SAME_TIME:
            out += encode_varlong(n.mtime, 4)
        if not x & XMIT_SAME_MODE:
            out += struct.pack("<I", n.mode)
        if send_uid:
            out += encode_varint(n.uid)
        if send_gid:
            out += encode_varint(n.gid)
        return bytes(out)


def encode_session(
    entries: list[ListEntry],
    args: ServerArgs,
    seed: int,
    errors: list[str] | None = None,
) -> bytes:
    """Everything the server sends after reading the client's arguments:
    compat flags, checksum seed, then the multiplexed file list. `errors` are
    messages for paths that do not exist (sent as `MSG_ERROR_XFER`, which the
    client prints and turns into exit code 23, like a real sender)."""
    head = bytes([COMPAT_FLAGS]) + struct.pack("<I", seed & 0xFFFFFFFF)
    w = _EntryWriter(args)
    body = bytearray()
    for e in entries[:MAX_LISTED]:
        body += w.encode(e)
    body.append(0)  # end of file list
    if not args.numeric_ids:
        # uid and gid name tables, both empty (varint 0 terminates each).
        if args.owner:
            body.append(0)
        if args.group:
            body.append(0)
    framed = b"".join(mplex(m.encode("utf-8", "replace"), MSG_ERROR_XFER) for m in errors or ())
    return head + framed + mplex(bytes(body))


# ── the client's side of the session after the list ─────────────────────────

NDX_DONE = 0
# rsync 3.x sends this many end-of-phase markers on a clean list-only run;
# the last is answered and the exchange is over.
FINAL_DONE_COUNT = 5
_MAX_FILTER_BYTES = 8192


class ClientStream:
    """Reads what the client sends once the list is out: its filter rules, then
    a run of end-of-phase markers (`NDX_DONE`, one 0 byte each). Any other index
    is a request for file data, which this server never serves.

    Input is demultiplexed (only `MSG_DATA` frames carry the stream; other
    frames are control messages and are skipped). `feed` returns the bytes to
    send back; `requested_data` turns True on the first real file request."""

    def __init__(self, stats: bytes = b"") -> None:
        self.stats = stats
        self._raw = bytearray()
        self._stream = bytearray()
        self._filters_done = False
        self._skip = 0
        self.done_count = 0
        self.requested_data = False
        self.bad = False

    @property
    def finished(self) -> bool:
        """Nothing more to say: the exchange is complete, or the client wants
        file data (or sent something unparseable), which is refused by hanging
        up now rather than leaving it waiting."""
        return self.bad or self.requested_data or self.done_count >= FINAL_DONE_COUNT

    def feed(self, data: bytes) -> list[bytes]:
        self._raw += data
        if len(self._raw) > 4 * _MAX_FILTER_BYTES:
            self.bad = True
            return []
        while len(self._raw) >= 4:
            (hdr,) = struct.unpack_from("<I", self._raw)
            tag, ln = (hdr >> 24) - MPLEX_BASE, hdr & 0xFFFFFF
            if tag < 0 or ln > _MAX_FILTER_BYTES:
                self.bad = True
                return []
            if len(self._raw) < 4 + ln:
                break
            if tag == MSG_DATA:
                self._stream += self._raw[4 : 4 + ln]
            del self._raw[: 4 + ln]
        return self._consume()

    def _consume(self) -> list[bytes]:
        replies: list[bytes] = []
        s = self._stream
        while not self._filters_done:
            if self._skip:
                n = min(self._skip, len(s))
                del s[:n]
                self._skip -= n
                if self._skip:
                    return replies
            if len(s) < 4:
                return replies
            (ln,) = struct.unpack_from("<i", s)
            del s[:4]
            if ln == 0:
                self._filters_done = True
            elif ln < 0 or ln > _MAX_FILTER_BYTES:
                self.bad = True
                return replies
            else:
                self._skip = ln
        while s:
            if s[0] != NDX_DONE:
                self.requested_data = True
                s.clear()
                break
            del s[0]
            self.done_count += 1
            replies.append(mplex(bytes([NDX_DONE])))
            if self.done_count == 3:
                replies.append(mplex(self.stats))
        return replies


def encode_stats(total_read: int, total_written: int, total_size: int) -> bytes:
    """The sender's end-of-transfer statistics (protocol 29+): bytes read,
    bytes written, total file size, then list build and transfer times."""
    return b"".join(encode_varlong(v, 3) for v in (total_read, total_written, total_size, 0, 0))
