"""rsync honeypot: the server side of a file LISTING.

A real `rsync rsync://host/module/` sends its argument words after
`@RSYNCD: OK` and then waits for the daemon's setup bytes and file list; a
daemon that goes quiet at that point is visibly not a daemon. These tests pin
the bytes against a decoder written here *from rsync's own reader functions*
(`read_varint`/`read_varlong`/`recv_file_entry`), never from the encoder, so a
mistake shared by both sides cannot pass. The same wire was also checked
against real rsync 3.1.3 and 3.5.0 clients (see the engine docstring).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
import time

import pytest

from tests._ports import free_port

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp.engines import rsync_wire as wire  # noqa: E402

# ── independent decoder (mirrors rsync's io.c / flist.c readers) ─────────────

_EXTRA = [0] * 32 + [1] * 16 + [2] * 8 + [3] * 4 + [4] * 2 + [5, 6]


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, n: int) -> bytes:
        assert self.pos + n <= len(self.data), "decoder ran past the end"
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def byte(self) -> int:
        return self.read(1)[0]

    def eof(self) -> bool:
        return self.pos >= len(self.data)


def _read_varlong(r: _Reader, min_bytes: int) -> int:
    b2 = r.read(min_bytes)
    u = bytearray(9)
    u[0 : min_bytes - 1] = b2[1:]
    extra = _EXTRA[b2[0] // 4]
    if extra:
        bit = 1 << (8 - extra)
        u[min_bytes - 1 : min_bytes - 1 + extra] = r.read(extra)
        u[min_bytes + extra - 1] = b2[0] & (bit - 1)
    else:
        u[min_bytes - 1] = b2[0]
    return int.from_bytes(u[:8], "little")


def _demux(data: bytes) -> tuple[bytes, list[tuple[int, bytes]]]:
    """Split multiplexed frames: (MSG_DATA payload, [(tag, payload) others])."""
    r = _Reader(data)
    stream = b""
    others: list[tuple[int, bytes]] = []
    while not r.eof():
        (hdr,) = struct.unpack("<I", r.read(4))
        tag, ln = (hdr >> 24) - 7, hdr & 0xFFFFFF
        assert tag >= 0
        payload = r.read(ln)
        if tag == 0:
            stream += payload
        else:
            others.append((tag, payload))
    return stream, others


def _decode_flist(
    stream: bytes, *, owner: bool, group: bool, numeric: bool = False, strict: bool = True
):
    r = _Reader(stream)
    mode = mtime = uid = gid = 0
    last = b""
    entries = []
    while True:
        flags = r.byte()
        if flags == 0:
            break
        if flags & 0x04:  # XMIT_EXTENDED_FLAGS
            flags |= r.byte() << 8
        l1 = r.byte() if flags & 0x20 else 0
        l2 = _read_varlong(r, 1) if flags & 0x40 else r.byte()
        name = last[:l1] + r.read(l2)
        last = name
        size = _read_varlong(r, 3)
        if not flags & 0x80:
            mtime = _read_varlong(r, 4)
        if not flags & 0x02:
            (mode,) = struct.unpack("<I", r.read(4))
        if owner and not flags & 0x08:
            uid = _read_varlong(r, 1)
        if group and not flags & 0x10:
            gid = _read_varlong(r, 1)
        entries.append(
            {
                "name": name.decode(),
                "size": size,
                "mtime": mtime,
                "mode": mode,
                "uid": uid,
                "gid": gid,
                "flags": flags,
            }
        )
    if not numeric:
        for present in (owner, group):
            if present:
                assert _read_varlong(r, 1) == 0  # empty id-name table
    if strict:
        assert r.eof(), "trailing bytes after the file list"
    return entries


def _split_session(blob: bytes) -> tuple[int, int, bytes]:
    """compat flags, checksum seed, multiplexed remainder."""
    return blob[0], struct.unpack("<I", blob[1:5])[0], blob[5:]


# ── primitives ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value",
    [0, 1, 127, 128, 255, 256, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 2**31 - 1, 2**32 - 1],
)
def test_varint_round_trips_through_rsyncs_reader(value):
    assert _read_varlong(_Reader(wire.encode_varint(value)), 1) == value


@pytest.mark.parametrize("min_bytes", [3, 4])
@pytest.mark.parametrize(
    "value",
    [
        0,
        1,
        4096,
        2**16,
        2**23 - 1,
        2**24,
        2**31,
        2**32 + 7,
        5_256_400_396,
        1_790_000_000,
        2**48,
        2**56 - 1,
    ],
)
def test_varlong_round_trips_through_rsyncs_reader(value, min_bytes):
    assert _read_varlong(_Reader(wire.encode_varlong(value, min_bytes)), min_bytes) == value


def test_varint_known_vectors():
    # Values worked out by hand from rsync's `write_varint`: the first byte is
    # a unary length prefix followed by the top bits.
    assert wire.encode_varint(0) == b"\x00"
    assert wire.encode_varint(127) == b"\x7f"
    assert wire.encode_varint(128) == b"\x80\x80"
    assert wire.encode_varint(255) == b"\x80\xff"
    assert wire.encode_varlong(4096, 3) == b"\x00\x00\x10"


def test_varnum_rejects_what_it_cannot_encode():
    with pytest.raises(ValueError):
        wire.encode_varint(-1)
    with pytest.raises(ValueError):
        wire.encode_varint(2**32)


def test_mplex_header_is_little_endian_tag_plus_seven_and_length():
    assert wire.mplex(b"abc") == struct.pack("<I", (7 << 24) | 3) + b"abc"
    assert wire.mplex(b"x", wire.MSG_ERROR_XFER) == struct.pack("<I", (8 << 24) | 1) + b"x"
    assert wire.mplex(b"") == b""
    big = wire.mplex(b"a" * 40000)
    stream, _ = _demux(big)
    assert stream == b"a" * 40000  # chunked, but reassembles


# ── decoy trees ──────────────────────────────────────────────────────────────

NOW = 1_792_000_000.0  # a fixed instant: trees are a function of (name, day)


def _walk(node, prefix=""):
    for c in node.children:
        yield prefix + c.name, c
        if c.is_dir:
            yield from _walk(c, prefix + c.name + "/")


def test_decoy_tree_is_deterministic_per_name_and_differs_between_names():
    a1 = wire.decoy_tree("db-dumps", "hp-a", NOW)
    a2 = wire.decoy_tree("db-dumps", "hp-a", NOW + 3600)  # same UTC day
    b = wire.decoy_tree("db-dumps", "hp-b", NOW)
    assert a1 == a2
    assert [n.size for _, n in _walk(a1)] != [n.size for _, n in _walk(b)]
    assert [p for p, _ in _walk(a1)] == [p for p, _ in _walk(b)]  # same shape


def test_decoy_names_match_the_module_description():
    dumps = dict(_walk(wire.decoy_tree("db-dumps", "hp", NOW)))
    sql = [p for p, n in dumps.items() if not n.is_dir and "appdb-" in p]
    assert sql and all(p.endswith(".sql.gz") for p in sql)
    assert "README" in dumps and "monthly" in dumps and dumps["monthly"].is_dir
    backups = dict(_walk(wire.decoy_tree("backups", "hp", NOW)))
    assert any(p.endswith(".tar.gz") for p in backups)
    assert wire.decoy_tree("etc", "hp", NOW) is None  # protected modules are never listed


def test_decoy_dates_in_names_agree_with_mtimes_and_none_is_in_the_future():
    for module in ("backups", "db-dumps", "public"):
        tree = wire.decoy_tree(module, "hp", NOW)
        for path, node in _walk(tree):
            assert node.mtime < NOW, path
            stem = path.rsplit("/", 1)[-1]
            for token in stem.replace(".", "-").split("-"):
                if len(token) == 8 and token.isdigit() and token.startswith("20"):
                    stamp = time.strftime("%Y%m%d", time.gmtime(node.mtime))
                    assert stamp == token or stem.startswith("appdb-" + token[:6]), path


def test_the_newest_dump_is_always_last_nights():
    tree = wire.decoy_tree("db-dumps", "hp", NOW)
    names = sorted(c.name for c in tree.children if c.name.startswith("appdb-"))
    yesterday = time.strftime("%Y%m%d", time.gmtime(NOW - 86400))
    assert names[-1] == f"appdb-{yesterday}.sql.gz"


# ── arguments ────────────────────────────────────────────────────────────────


def test_parse_args_of_a_listing_and_a_recursive_pull():
    listing = wire.parse_server_args(["--server", "--sender", "-de.LsfxCIvu", ".", "mod/"])
    assert listing.sender and listing.dirs and not listing.recursive and not listing.owner
    pull = wire.parse_server_args(["--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "mod/"])
    assert pull.sender and pull.recursive and pull.owner and pull.group and not pull.dirs


def test_the_capability_string_after_e_is_not_read_as_options():
    # `.iLsfxCIvu` contains 'i', 'L', 's', 'x', 'C', 'I', 'v', 'u' — and the
    # unsupported-option letters 'X' / 'c' would be false positives if read.
    a = wire.parse_server_args(["--server", "--sender", "-re.iLsfxCIvuXcAUN", ".", "m/"])
    assert a.recursive and a.unsupported is None


def test_options_that_change_the_entry_format_are_flagged_unsupported():
    for argv in (
        ["--server", "--sender", "-Xre.x", ".", "m/"],
        ["--server", "--sender", "-rc", ".", "m/"],
        ["--server", "--sender", "--acls", ".", "m/"],
        ["--server", "--sender", "--checksum", ".", "m/"],
    ):
        assert wire.parse_server_args(argv).unsupported, argv


def test_a_missing_sender_flag_means_an_upload():
    assert not wire.parse_server_args(["--server", "-vlogDtpre.i", ".", "mod/"]).sender


def test_option_words_after_the_dummy_dot_are_paths_not_options():
    a = wire.parse_server_args(["--server", "--sender", "-d", ".", "mod/-r", "mod/--acls"])
    assert not a.recursive and a.unsupported is None


# ── file list ────────────────────────────────────────────────────────────────


def _session(module, request, argv, *, name="hp", now=NOW):
    args = wire.parse_server_args(argv)
    tree = wire.decoy_tree(module, name, now)
    entries = wire.resolve_request(tree, request, module, args)
    assert entries is not None
    blob = wire.encode_session(entries, args, 0x01020304)
    return tree, args, entries, blob


_LIST = ["--server", "--sender", "-de.LsfxCIvu", ".", "x"]
_PULL = ["--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "x"]


def test_session_header_is_compat_flags_then_the_checksum_seed():
    _, _, _, blob = _session("db-dumps", "db-dumps/", _LIST)
    flags, seed, rest = _split_session(blob)
    assert flags == wire.COMPAT_FLAGS
    assert not flags & 0x01  # incremental recursion is not offered
    assert seed == 0x01020304
    assert blob[1:5] == b"\x04\x03\x02\x01"
    assert rest and (struct.unpack("<I", rest[:4])[0] >> 24) == 7  # MSG_DATA


def test_listing_decodes_to_the_tree_with_names_sizes_times_and_modes():
    tree, args, entries, blob = _session("db-dumps", "db-dumps/", _LIST)
    stream, others = _demux(_split_session(blob)[2])
    assert not others
    got = _decode_flist(stream, owner=False, group=False)
    assert got[0]["name"] == "." and got[0]["mode"] & 0o170000 == 0o040000
    by_name = {e["name"]: e for e in got}
    for child in tree.children:  # non-recursive: top level only
        e = by_name[child.name]
        assert (e["size"], e["mtime"], e["mode"]) == (child.size, child.mtime, child.mode)
    assert not any("/" in e["name"] for e in got)
    assert len(got) == len(tree.children) + 1


def test_non_recursive_listing_marks_subdirectories_as_having_no_content():
    _, _, _, blob = _session("db-dumps", "db-dumps/", _LIST)
    got = _decode_flist(_demux(_split_session(blob)[2])[0], owner=False, group=False)
    monthly = next(e for e in got if e["name"] == "monthly")
    assert monthly["flags"] & wire.XMIT_NO_CONTENT_DIR
    dot = got[0]
    assert dot["flags"] & wire.XMIT_TOP_DIR and not dot["flags"] & wire.XMIT_NO_CONTENT_DIR


def test_recursive_pull_lists_every_descendant_with_owner_and_group():
    tree, args, entries, blob = _session("db-dumps", "db-dumps/", _PULL)
    got = _decode_flist(_demux(_split_session(blob)[2])[0], owner=True, group=True)
    expected = {p: n for p, n in _walk(tree)}
    assert {e["name"] for e in got} == {".", *expected}
    for e in got:
        if e["name"] == ".":
            continue
        n = expected[e["name"]]
        assert (e["size"], e["mtime"], e["mode"], e["uid"], e["gid"]) == (
            n.size,
            n.mtime,
            n.mode,
            n.uid,
            n.gid,
        )
    assert any(e["uid"] == 26 for e in got) and any(e["uid"] == 0 for e in got)


def test_numeric_ids_omits_the_id_name_tables():
    argv = _PULL[:-2] + ["--numeric-ids", ".", "x"]
    tree, args, entries, blob = _session("backups", "backups/", argv)
    assert args.numeric_ids
    got = _decode_flist(_demux(_split_session(blob)[2])[0], owner=True, group=True, numeric=True)
    assert len(got) == len(entries)


def test_subdirectory_and_file_requests_resolve_like_a_real_sender():
    _, _, entries, _ = _session("public", "public/pub/", _LIST)
    assert [e.name for e in entries][0] == "."
    assert "tools" in [e.name for e in entries]
    _, _, entries, _ = _session("public", "public/pub", _LIST)  # no slash: the dir itself
    assert [e.name for e in entries] == ["pub"] and not entries[0].content
    _, _, entries, _ = _session("public", "public/README.txt", _LIST)
    assert [e.name for e in entries] == ["README.txt"]
    assert not entries[0].top and not entries[0].content and not entries[0].node.is_dir
    _, _, entries, _ = _session("public", "public/pub/", _PULL)
    assert "tools/cli-tools-2.4.1.tar.gz" in [e.name for e in entries]


def test_missing_paths_and_traversal_resolve_to_nothing():
    args = wire.parse_server_args(_LIST)
    tree = wire.decoy_tree("public", "hp", NOW)
    assert wire.resolve_request(tree, "public/nope/", "public", args) is None
    assert wire.resolve_request(tree, "public/../etc/passwd", "public", args) is None
    assert wire.resolve_request(tree, "public/README.txt/x", "public", args) is None


def test_errors_are_sent_as_error_frames_before_the_list():
    args = wire.parse_server_args(_LIST)
    blob = wire.encode_session([], args, 1, ["rsync: [sender] link_stat failed\n"])
    _, _, rest = _split_session(blob)
    stream, others = _demux(rest)
    assert others == [(wire.MSG_ERROR_XFER, b"rsync: [sender] link_stat failed\n")]
    assert _decode_flist(stream, owner=False, group=False) == []


def test_long_names_and_shared_prefixes_round_trip():
    node = wire.Node("x", wire.S_IFREG | 0o644, 1, 100)
    long_a = "a" * 300
    entries = [
        wire.ListEntry(long_a + "1", node, False, False),
        wire.ListEntry(long_a + "2", node, False, False),
        wire.ListEntry("b", node, False, False),
    ]
    args = wire.parse_server_args(_LIST)
    blob = wire.encode_session(entries, args, 0)
    got = _decode_flist(_demux(_split_session(blob)[2])[0], owner=False, group=False)
    assert [e["name"] for e in got] == [long_a + "1", long_a + "2", "b"]


def test_a_non_directory_never_starts_with_a_zero_flag_byte():
    # A zero byte ends the list; the encoder must never emit one mid-list.
    node = wire.Node("x", wire.S_IFREG | 0o644, 5, 100)
    entries = [wire.ListEntry(f"f{i}", node, False, False) for i in range(5)]
    args = wire.parse_server_args(_LIST)
    got = _decode_flist(
        _demux(_split_session(wire.encode_session(entries, args, 0))[2])[0],
        owner=False,
        group=False,
    )
    assert len(got) == 5


def test_entry_count_is_bounded():
    node = wire.Node("x", wire.S_IFREG | 0o644, 5, 100)
    entries = [wire.ListEntry(f"f{i}", node, False, False) for i in range(wire.MAX_LISTED + 50)]
    args = wire.parse_server_args(_LIST)
    got = _decode_flist(
        _demux(_split_session(wire.encode_session(entries, args, 0))[2])[0],
        owner=False,
        group=False,
    )
    assert len(got) == wire.MAX_LISTED


# ── the client's side after the list ─────────────────────────────────────────


def _client_frames(*payloads: bytes) -> bytes:
    return b"".join(wire.mplex(p) for p in payloads)


def test_client_stream_answers_each_end_of_phase_and_adds_stats_on_the_third():
    cs = wire.ClientStream(stats=b"STATS")
    out = cs.feed(_client_frames(b"\x00\x00\x00\x00"))  # empty filter list
    assert out == [] and not cs.finished
    done = wire.mplex(b"\x00")
    assert cs.feed(wire.mplex(b"\x00")) == [done]
    assert cs.feed(wire.mplex(b"\x00")) == [done]
    assert cs.feed(wire.mplex(b"\x00")) == [done, wire.mplex(b"STATS")]
    assert not cs.finished
    assert cs.feed(wire.mplex(b"\x00")) == [done]
    assert not cs.finished
    assert cs.feed(wire.mplex(b"\x00")) == [done]
    assert cs.finished


def test_client_stream_skips_filter_rules_and_split_frames():
    cs = wire.ClientStream()
    rule = b"- *.log"
    data = _client_frames(struct.pack("<i", len(rule)) + rule + b"\x00\x00\x00\x00", b"\x00")
    replies = []
    for i in range(0, len(data), 3):  # arbitrary TCP segmentation
        replies += cs.feed(data[i : i + 3])
    assert replies == [wire.mplex(b"\x00")]


def test_client_stream_refuses_a_file_request_and_garbage():
    cs = wire.ClientStream()
    cs.feed(_client_frames(b"\x00\x00\x00\x00", b"\x03\x00\x60"))
    assert cs.requested_data and cs.finished
    bad = wire.ClientStream()
    bad.feed(b"\xff\xff\xff\xff")
    assert bad.bad and bad.finished
    huge = wire.ClientStream()
    huge.feed(b"\x00" * 200000)
    assert huge.bad


# ── the engine, over a socket ────────────────────────────────────────────────


@pytest.fixture
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


async def _start(name: str):
    from honeypot_mcp.engines.rsync import RsyncEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    port = free_port()
    async with get_session() as session:
        session.add(
            Honeypot(
                name=name,
                type=HoneypotType.RSYNC,
                port=port,
                status=HoneypotStatus.RUNNING,
                config={},
            )
        )
    engine = RsyncEngine()
    cid = await engine.start(name, port, {})
    return engine, cid, port


async def _alerts(event_type: str) -> list:
    from sqlalchemy import select
    from sqlalchemy.exc import OperationalError

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    for _ in range(80):
        try:
            async with get_session() as session:
                rows = [
                    a
                    for a in (await session.execute(select(Alert))).scalars().all()
                    if a.event_type == event_type
                ]
        except OperationalError:
            # The in-memory test database is ONE connection shared with the event flusher; a commit
            # that lands while the flusher is mid-statement fails ("SQL statements in progress") and
            # succeeds on the next poll. Production uses a pooled file database.
            await asyncio.sleep(0.05)
            continue
        if rows:
            return rows
        await asyncio.sleep(0.05)
    return []


def _nul(*words: str) -> bytes:
    return b"".join(w.encode() + b"\0" for w in words) + b"\0"


async def _read_all(reader: asyncio.StreamReader, timeout: float = 3.0) -> bytes:
    """Everything until the server hangs up. A server that leaves the
    connection open raises TimeoutError — that is the "client hangs" bug."""
    return await asyncio.wait_for(reader.read(), timeout=timeout)


async def _open_module(port: int, module: str, greeting: bytes = b"@RSYNCD: 32.0 md5 md4\n"):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    assert (await reader.readline()).startswith(b"@RSYNCD: 31")
    writer.write(greeting + module.encode() + b"\n")
    await writer.drain()
    assert await reader.readline() == b"@RSYNCD: OK\n"
    return reader, writer


@pytest.mark.asyncio
async def test_listing_session_end_to_end_like_rsync_3(setup_db):
    """The exact exchange a real client performs: args, filter list, then the
    end-of-phase markers. Ends with the server hanging up on its own."""
    engine, cid, port = await _start("rsync-list-1")
    try:
        reader, writer = await _open_module(port, "db-dumps")
        writer.write(_nul("--server", "--sender", "-de.LsfxCIvu", ".", "db-dumps/"))
        writer.write(wire.mplex(b"\x00\x00\x00\x00"))
        await writer.drain()
        flags_seed = await asyncio.wait_for(reader.readexactly(5), 3)
        assert flags_seed[0] == wire.COMPAT_FLAGS
        # Read the multiplexed list incrementally until the terminating zero.
        buf = b""
        while True:
            hdr = await asyncio.wait_for(reader.readexactly(4), 2)
            ln = struct.unpack("<I", hdr)[0] & 0xFFFFFF
            buf += hdr + await asyncio.wait_for(reader.readexactly(ln), 2)
            stream, _ = _demux(buf)
            with contextlib.suppress(AssertionError):
                entries = _decode_flist(stream, owner=False, group=False)
                break
        names = [e["name"] for e in entries]
        assert names[0] == "."
        assert any(n.startswith("appdb-") and n.endswith(".sql.gz") for n in names)
        # Phase markers: each is answered; after the fifth the server is done.
        for _ in range(5):
            writer.write(wire.mplex(b"\x00"))
            await writer.drain()
        rest = await _read_all(reader)
        _, others = _demux(rest)
        assert not others
        writer.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_everything_arriving_in_one_segment_still_lists(setup_db):
    engine, cid, port = await _start("rsync-list-2")
    try:
        reader, writer = await _open_module(port, "public")
        writer.write(
            _nul("--server", "--sender", "-de.LsfxCIvu", ".", "public/")
            + wire.mplex(b"\x00\x00\x00\x00")
            + wire.mplex(b"\x00") * 5
        )
        await writer.drain()
        data = await _read_all(reader)
        _, _, rest = _split_session(data)
        stream, _ = _demux(rest)
        # The list, then 5 NDX_DONE echoes and the stats; decode the list part.
        names = [e["name"] for e in _decode_flist(stream, owner=False, group=False, strict=False)]
        assert names[0] == "." and "README.txt" in names
        writer.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_event_payload_carries_files_listed_and_no_new_event_types(setup_db):
    engine, cid, port = await _start("rsync-list-3")
    try:
        reader, writer = await _open_module(port, "backups")
        writer.write(_nul("--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "backups/"))
        writer.write(wire.mplex(b"\x00\x00\x00\x00") + wire.mplex(b"\x00") * 5)
        await writer.drain()
        data = await _read_all(reader)
        writer.close()
        expected = len(
            wire.resolve_request(
                wire.decoy_tree("backups", "rsync-list-3", time.time()),
                "backups/",
                "backups",
                wire.parse_server_args(["--sender", "-rogd", "."]),
            )
        )
        assert data

        anonymous = await _alerts("rsync_anonymous_access")
        assert anonymous and anonymous[0].severity.value == "critical"
        requests = await _alerts("rsync_file_request")
        assert requests and requests[0].payload["path"] == "backups/"
        assert requests[0].payload["files_listed"] == expected > 5
        assert requests[0].severity.value == "critical"
        options = await _alerts("rsync_transfer_options")
        assert {o.payload["options"] for o in options} >= {"--server", "--sender", "."}
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_missing_path_reports_the_error_and_exits_cleanly(setup_db):
    engine, cid, port = await _start("rsync-list-4")
    try:
        reader, writer = await _open_module(port, "public")
        writer.write(_nul("--server", "--sender", "-de.LsfxCIvu", ".", "public/nope/"))
        writer.write(wire.mplex(b"\x00\x00\x00\x00") + wire.mplex(b"\x00") * 5)
        await writer.drain()
        data = await _read_all(reader)
        writer.close()
        _, others = _demux(_split_session(data)[2][: _first_end(data)])
        assert others and b"link_stat" in others[0][1] and b"No such file" in others[0][1]
        requests = await _alerts("rsync_file_request")
        assert requests[0].payload["files_listed"] == 0
    finally:
        await engine.stop(cid)


def _first_end(data: bytes) -> int:
    """Length of the error frame + data frame holding the (empty) list."""
    pos = 5
    for _ in range(2):
        (hdr,) = struct.unpack_from("<I", data, pos)
        pos += 4 + (hdr & 0xFFFFFF)
    return pos - 5


@pytest.mark.asyncio
async def test_a_file_pull_fails_promptly_instead_of_hanging(setup_db):
    """`rsync -av rsync://host/module/ dest` gets past the list, asks for a
    file, and is hung up on well inside the drain window."""
    engine, cid, port = await _start("rsync-list-5")
    try:
        reader, writer = await _open_module(port, "public")
        writer.write(_nul("--server", "--sender", "-vlogDtpre.iLsfxCIvu", ".", "public/"))
        writer.write(wire.mplex(b"\x00\x00\x00\x00"))
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(5), 3)
        await asyncio.sleep(0.1)
        writer.write(wire.mplex(b"\x03\x00\x60"))  # an ndx + iflags: a file request
        await writer.drain()
        started = time.monotonic()
        await _read_all(reader, timeout=2.5)
        assert time.monotonic() - started < 1.5
        writer.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_an_upload_or_unsupported_option_is_recorded_and_closed_not_left_hanging(setup_db):
    engine, cid, port = await _start("rsync-list-6")
    try:
        for argv in (
            ("--server", "-vlogDtpre.iLsfxCIvu", ".", "public/"),  # no --sender: an upload
            ("--server", "--sender", "-Xre.iLsfx", ".", "public/"),  # xattrs: not encodable
        ):
            reader, writer = await _open_module(port, "public")
            writer.write(_nul(*argv))
            await writer.drain()
            data = await _read_all(reader, timeout=2.0)
            assert data == b""  # nothing that is not the real protocol
            writer.close()
        assert await _alerts("rsync_file_request")
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_protocol_29_client_is_closed_not_hung(setup_db):
    """openrsync / rsync 2.x speak protocol 29 (newline arguments, a different
    list encoding). They are not served, but they must not wait forever."""
    engine, cid, port = await _start("rsync-list-7")
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readline()
        writer.write(b"@RSYNCD: 29\npublic\n")
        await writer.drain()
        assert await reader.readline() == b"@RSYNCD: OK\n"
        writer.write(b"--server\n--sender\n-vlogDtpre.iLsfx\n.\npublic/\n\n")
        await writer.drain()
        assert await _read_all(reader, timeout=2.0) == b""
        requests = await _alerts("rsync_file_request")
        assert requests and requests[0].payload["files_listed"] == 0
        writer.close()
    finally:
        await engine.stop(cid)


@pytest.mark.asyncio
async def test_argument_phase_is_bounded(setup_db):
    engine, cid, port = await _start("rsync-list-8")
    try:
        # One endless word.
        reader, writer = await _open_module(port, "public")
        writer.write(b"A" * 40000)
        await writer.drain()
        data = await _read_all(reader, timeout=2.0)
        assert b"@ERROR" in data
        writer.close()
        # Far too many words, each below the per-word cap.
        reader, writer = await _open_module(port, "public")
        writer.write(b"-x\0" * 500)
        await writer.drain()
        data = await _read_all(reader, timeout=2.0)
        assert b"@ERROR" in data
        writer.close()
    finally:
        await engine.stop(cid)
