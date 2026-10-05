"""An RDP session for the honeypot: what happens after a login is accepted.

Until now the RDP honeypot ended at authentication. A credential-spraying tool is satisfied
by that, but it means every attacker who gets in is told, a moment later, that nothing is
there. This module is the part after: the MCS connection, the capability exchange, a desktop
on screen, and a record of what the visitor does with it.

What a visitor gets is deliberately small and honest about what it is: a static Windows-style
desktop (wallpaper, two icons, a taskbar), and their keystrokes and clicks are recorded.
Nothing executes, nothing opens, nothing can be reached from it. That is enough to learn what
an intruder does first (types a command, opens the Start menu, looks for a browser) which is
the information a live session exists to produce.

Protocol (MS-RDPBCGR), enhanced security only (the TLS tunnel is already up):

    Connect Initial / Response   channels and desktop size are negotiated
    Erect Domain, Attach User, Channel Join
    Client Info                  username, domain and, without NLA, the plaintext password
    License                      "valid client", skipping licensing
    Demand / Confirm Active      capabilities
    Synchronize, Control, Font   the finalisation handshake
    Bitmap updates               the desktop, uncompressed, in horizontal bands
    Input events                 scancodes, unicode, mouse, recorded until the session ends

Everything is read from an untrusted peer: every length is checked against the buffer, every
read has a timeout, and a session is bounded by time, events and bytes.
"""

from __future__ import annotations

import asyncio
import struct
import time
from collections.abc import Awaitable, Callable
from typing import Any

from honeypot_mcp.engines.rdp_cliprdr import ClipboardChannel, wrap_channel_pdu

SERVER_USER = 1002
IO_CHANNEL = 1003
CLIENT_USER = 1007  # what Windows hands the first client of a session with few channels

SESSION_SECONDS = 120.0
IDLE_SECONDS = 45.0
MAX_EVENTS = 4000
MAX_INPUT_BYTES = 1024 * 1024
# The desktop is ~2 MB and a client can ask for it again, so output is capped per session:
# without it a few KB of Refresh Rect PDUs bought gigabytes of replies.
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_REFRESHES = 3
MAX_TYPED = 2000
MAX_CLICKS = 50
MAX_STATIC_CHANNELS = 31
_READ_TIMEOUT = 20.0
SHARE_ID = 0x000103EA

_SEC_INFO_PKT = 0x0040
_SEC_LICENSE_PKT = 0x0080

# Share control PDU types (low nibble of pduType).
_PDU_DEMAND_ACTIVE = 1
_PDU_CONFIRM_ACTIVE = 3
_PDU_DEACTIVATE = 6
_PDU_DATA = 7
# Data PDU types (pduType2).
_DATA_UPDATE = 0x02
_DATA_CONTROL = 0x14
_DATA_INPUT = 0x1C
_DATA_SYNCHRONIZE = 0x1F
_DATA_REFRESH_RECT = 0x21
_DATA_SHUTDOWN_REQUEST = 0x24
_DATA_SHUTDOWN_DENIED = 0x25
_DATA_FONT_LIST = 0x27
_DATA_FONT_MAP = 0x28
_DATA_SET_ERROR_INFO = 0x2F


# ── Wire helpers ────────────────────────────────────────────────────────────


def per_length(n: int) -> bytes:
    return bytes([n]) if n < 0x80 else struct.pack(">H", 0x8000 | n)


def ber_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    return b"\x81" + bytes([n]) if n < 0x100 else b"\x82" + struct.pack(">H", n)


def frame(mcs: bytes) -> bytes:
    """TPKT + X.224 data TPDU around an MCS PDU."""
    body = b"\x02\xf0\x80" + mcs
    return struct.pack(">BBH", 3, 0, len(body) + 4) + body


async def read_frame(reader: asyncio.StreamReader, timeout: float) -> tuple[str, bytes]:
    """One PDU from the client: ("slow", body-after-TPKT) or ("fast", body-after-header).
    Raises ValueError for a malformed length."""
    head = await asyncio.wait_for(reader.readexactly(2), timeout)
    if head[0] == 3:
        rest = await asyncio.wait_for(reader.readexactly(2), timeout)
        length = struct.unpack(">H", rest)[0]
        if length < 7:
            raise ValueError("TPKT too short")
        return "slow", await asyncio.wait_for(reader.readexactly(length - 4), timeout)
    if head[1] & 0x80:
        extra = await asyncio.wait_for(reader.readexactly(1), timeout)
        length, header = ((head[1] & 0x7F) << 8) | extra[0], 3
    else:
        length, header = head[1], 2
    if length < header:
        raise ValueError("fast-path too short")
    return "fast", await asyncio.wait_for(reader.readexactly(length - header), timeout)


def send_data_indication(channel: int, data: bytes) -> bytes:
    """MCS Send Data Indication from the server user."""
    mcs = (
        b"\x68"
        + struct.pack(">HH", SERVER_USER - 1001, channel)
        + b"\x70"
        + per_length(len(data))
        + data
    )
    return frame(mcs)


def parse_send_data_request(mcs: bytes) -> tuple[int, bytes] | None:
    """(channel, data) of an MCS Send Data Request, or None if it is not one."""
    if len(mcs) < 8 or mcs[0] >> 2 != 25:
        return None
    channel = struct.unpack_from(">H", mcs, 3)[0]
    length_byte = mcs[6]
    if length_byte & 0x80:
        length, offset = ((length_byte & 0x7F) << 8) | mcs[7], 8
    else:
        length, offset = length_byte, 7
    return channel, mcs[offset : offset + length]


# ── Connect Initial / Response ──────────────────────────────────────────────


def parse_client_blocks(connect_initial: bytes) -> dict[str, Any]:
    """Desktop size and requested static channels from the client's GCC user data.
    Returns defaults for anything missing; never raises."""
    out: dict[str, Any] = {"width": 1024, "height": 768, "channels": []}
    at = connect_initial.find(b"Duca")
    if at < 0:
        return out
    pos = at + 4
    if pos >= len(connect_initial):
        return out
    pos += 2 if connect_initial[pos] & 0x80 else 1  # PER length of the block run
    while pos + 4 <= len(connect_initial):
        block_type, block_len = struct.unpack_from("<HH", connect_initial, pos)
        if block_len < 4 or pos + block_len > len(connect_initial):
            break
        body = connect_initial[pos + 4 : pos + block_len]
        if block_type == 0xC001 and len(body) >= 8:  # CS_CORE
            out["width"], out["height"] = struct.unpack_from("<HH", body, 4)
        elif block_type == 0xC003 and len(body) >= 4 and not out["channels"]:  # CS_NET, first only
            count = min(struct.unpack_from("<I", body, 0)[0], MAX_STATIC_CHANNELS)
            for i in range(count):
                entry = body[4 + i * 12 : 4 + i * 12 + 8]
                if len(entry) == 8:
                    # The whole 8-byte field: truncating to 7 characters made `cliprdrX` look
                    # like `cliprdr`.
                    out["channels"].append(entry.rstrip(b"\x00").decode("ascii", "replace"))
        pos += block_len
    return out


def build_connect_response(channel_count: int, selected_protocol: int) -> bytes:
    """MCS Connect Response carrying the GCC Conference Create Response (T.125 / T.124)."""
    sc_core = struct.pack("<HHII", 0x0C01, 12, 0x00080004, selected_protocol)
    sc_security = struct.pack("<HHII", 0x0C02, 12, 0, 0)  # no encryption: TLS carries it
    ids = b"".join(struct.pack("<H", IO_CHANNEL + 1 + i) for i in range(channel_count))
    pad = b"\x00\x00" if channel_count % 2 else b""
    sc_net = (
        struct.pack("<HHHH", 0x0C03, 8 + len(ids) + len(pad), IO_CHANNEL, channel_count) + ids + pad
    )
    # Windows and FreeRDP send core, net, security. Security last matters: some clients
    # read it as the long form even when it is the short one and would swallow the next block.
    blocks = sc_core + sc_net + sc_security
    gcc = b"\x14\x76\x0a\x01\x01\x00\x01\xc0\x00McDn" + per_length(len(blocks)) + blocks
    connect_data = b"\x00\x05\x00\x14\x7c\x00\x01" + per_length(len(gcc)) + gcc
    domain = (
        b"\x30\x1a\x02\x01\x22\x02\x01\x03\x02\x01\x00\x02\x01\x01\x02\x01\x00"
        b"\x02\x01\x01\x02\x03\x00\xff\xf8\x02\x01\x02"
    )
    body = (
        b"\x0a\x01\x00\x02\x01\x00"
        + domain
        + b"\x04"
        + ber_length(len(connect_data))
        + connect_data
    )
    return frame(b"\x7f\x66" + ber_length(len(body)) + body)


# ── Share headers and the capability exchange ───────────────────────────────


def share_control(pdu_type: int, payload: bytes) -> bytes:
    return struct.pack("<HHH", len(payload) + 6, pdu_type | 0x10, SERVER_USER) + payload


def share_data(data_type: int, payload: bytes) -> bytes:
    header = struct.pack("<IBBHBBH", SHARE_ID, 0, 1, len(payload) + 4, data_type, 0, 0)
    return share_control(_PDU_DATA, header + payload)


def _cap(cap_type: int, body: bytes) -> bytes:
    return struct.pack("<HH", cap_type, len(body) + 4) + body


def demand_active(width: int, height: int) -> bytes:
    """Demand Active PDU. Advertises no drawing orders and no fast-path input, so a client
    answers with plain bitmap updates and slow-path input, the two cases handled here."""
    general = _cap(1, struct.pack("<HHHHHHHHHBB", 1, 3, 0x0200, 0, 0, 0x0400, 0, 0, 0, 0, 0))
    bitmap = _cap(2, struct.pack("<HHHHHHHHHBBHH", 16, 1, 1, 1, width, height, 0, 0, 1, 0, 0, 1, 0))
    order = _cap(
        3,
        bytes(16)
        + struct.pack("<IHHHHHH", 0, 1, 20, 0, 1, 0, 0x0022)
        + bytes(32)
        + struct.pack("<HHIIHHHH", 0, 0, 0, 480 * 480, 0, 0, 0, 0),
    )
    pointer = _cap(8, struct.pack("<HH", 1, 20))  # colour pointers on, 20 cached
    inp = _cap(0x0D, struct.pack("<HHIIII", 0x0001 | 0x0004 | 0x0010, 0, 0, 0, 0, 0) + bytes(64))
    virtual = _cap(0x14, struct.pack("<I", 0))
    share = _cap(9, struct.pack("<HH", SERVER_USER, 0))
    font = _cap(0x0E, struct.pack("<HH", 1, 0))
    caps = [general, bitmap, order, pointer, inp, virtual, share, font]
    combined = b"".join(caps)
    body = (
        struct.pack("<IHH", SHARE_ID, 4, len(combined) + 4)
        + b"RDP\x00"
        + struct.pack("<HH", len(caps), 0)
        + combined
        + struct.pack("<I", 0)
    )
    return share_control(_PDU_DEMAND_ACTIVE, body)


def confirmed_bits_per_pixel(confirm_active: bytes, default: int = 16) -> int:
    """Colour depth the client chose, from the bitmap capability in its Confirm Active."""
    # shareId(4) sourceLen(2) combinedLen(2) source... numCaps(2) pad(2) capabilitySets...
    try:
        source_len = struct.unpack_from("<H", confirm_active, 4)[0]
        pos = 8 + source_len
        count = struct.unpack_from("<H", confirm_active, pos)[0]
        pos += 4
        for _ in range(min(count, 64)):
            cap_type, cap_len = struct.unpack_from("<HH", confirm_active, pos)
            if cap_len < 4:
                break
            if cap_type == 2 and cap_len >= 6:  # bitmap capability
                bpp = struct.unpack_from("<H", confirm_active, pos + 4)[0]
                return bpp if bpp in (15, 16, 24, 32) else default
            pos += cap_len
    except struct.error:
        pass
    return default


# ── Client Info ─────────────────────────────────────────────────────────────


def parse_client_info(data: bytes) -> dict[str, Any] | None:
    """TS_INFO_PACKET behind a security header carrying SEC_INFO_PKT. Without NLA the
    password arrives here in the clear, inside the TLS tunnel."""
    if len(data) < 4 + 18:
        return None
    flags = struct.unpack_from("<H", data, 0)[0]
    if not flags & _SEC_INFO_PKT:
        return None
    code_page, info_flags, cb_domain, cb_user, cb_password, cb_shell, cb_dir = struct.unpack_from(
        "<IIHHHHH", data, 4
    )
    pos = 4 + 18
    out: dict[str, Any] = {"code_page": code_page, "info_flags": info_flags}
    for name, size in (
        ("domain", cb_domain),
        ("username", cb_user),
        ("password", cb_password),
        ("alternate_shell", cb_shell),
        ("working_dir", cb_dir),
    ):
        if size > 512 or pos + size > len(data):
            return out
        out[name] = data[pos : pos + size].decode("utf-16-le", errors="replace")[:128]
        pos += size + 2  # each string is followed by a 2-byte terminator
    return out


# ── The desktop ─────────────────────────────────────────────────────────────

_PIXEL_FORMATS = {15, 16, 24, 32}


def _pixel(rgb: tuple[int, int, int], bpp: int) -> bytes:
    r, g, b = rgb
    if bpp == 16:
        return struct.pack("<H", ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3))
    if bpp == 15:
        return struct.pack("<H", ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3))
    if bpp == 24:
        return bytes((b, g, r))
    return bytes((b, g, r, 0))


def render_desktop(width: int, height: int, bpp: int) -> list[bytes]:
    """Top-down pixel rows of the decoy desktop, built from horizontal runs so a 1024x768
    frame costs a few thousand byte joins rather than 786,432 pixel packs."""
    taskbar = 40
    taskbar_colour, start_colour, tray_colour = (28, 28, 32), (0, 120, 215), (40, 40, 46)
    icon_columns = 24
    icon_tops = (24, 112)
    rows: list[bytes] = []
    for y in range(height):
        if y >= height - taskbar:
            if y > height - taskbar + 3:
                runs = [
                    (0, 52, start_colour),
                    (52, width - 120, taskbar_colour),
                    (width - 120, width, tray_colour),
                ]
            else:
                runs = [(0, width, taskbar_colour)]
        else:
            shade = max(0, 150 - (y * 90) // max(1, height))
            background = (8, shade // 2 + 20, shade + 40)
            runs = [(0, width, background)]
            for top in icon_tops:
                if top <= y < top + 48:
                    glyph = (235, 235, 240) if y < top + 36 else (90, 110, 150)
                    runs = [
                        (0, icon_columns, background),
                        (icon_columns, icon_columns + 48, glyph),
                        (icon_columns + 48, width, background),
                    ]
                    break
        rows.append(
            b"".join(_pixel(colour, bpp) * max(0, end - start) for start, end, colour in runs)
        )
    return rows


def bitmap_updates(rows: list[bytes], width: int, bpp: int) -> list[bytes]:
    """Slow-path bitmap Update PDUs covering the whole desktop in full-width bands."""
    bytes_per_pixel = (bpp + 7) // 8
    per_band = max(1, 7600 // max(1, width * bytes_per_pixel))
    out: list[bytes] = []
    for top in range(0, len(rows), per_band):
        band = rows[top : top + per_band]
        bottom = top + len(band) - 1
        data = b"".join(reversed(band))  # bitmaps are stored bottom-up
        rect = struct.pack(
            "<HHHHHHHHH", 0, top, width - 1, bottom, width, len(band), bpp, 0, len(data)
        )
        out.append(share_data(_DATA_UPDATE, struct.pack("<HH", 1, 1) + rect + data))
    return out


# ── Input ───────────────────────────────────────────────────────────────────

# Set-1 scancodes on a US keyboard: unshifted, shifted.
_KEYS: dict[int, tuple[str, str]] = {
    0x02: ("1", "!"), 0x03: ("2", "@"), 0x04: ("3", "#"), 0x05: ("4", "$"), 0x06: ("5", "%"),
    0x07: ("6", "^"), 0x08: ("7", "&"), 0x09: ("8", "*"), 0x0A: ("9", "("), 0x0B: ("0", ")"),
    0x0C: ("-", "_"), 0x0D: ("=", "+"), 0x10: ("q", "Q"), 0x11: ("w", "W"), 0x12: ("e", "E"),
    0x13: ("r", "R"), 0x14: ("t", "T"), 0x15: ("y", "Y"), 0x16: ("u", "U"), 0x17: ("i", "I"),
    0x18: ("o", "O"), 0x19: ("p", "P"), 0x1A: ("[", "{"), 0x1B: ("]", "}"), 0x1E: ("a", "A"),
    0x1F: ("s", "S"), 0x20: ("d", "D"), 0x21: ("f", "F"), 0x22: ("g", "G"), 0x23: ("h", "H"),
    0x24: ("j", "J"), 0x25: ("k", "K"), 0x26: ("l", "L"), 0x27: (";", ":"), 0x28: ("'", '"'),
    0x29: ("`", "~"), 0x2B: ("\\", "|"), 0x2C: ("z", "Z"), 0x2D: ("x", "X"), 0x2E: ("c", "C"),
    0x2F: ("v", "V"), 0x30: ("b", "B"), 0x31: ("n", "N"), 0x32: ("m", "M"), 0x33: (",", "<"),
    0x34: (".", ">"), 0x35: ("/", "?"), 0x39: (" ", " "), 0x1C: ("\n", "\n"), 0x0F: ("\t", "\t"),
}  # fmt: skip
_BACKSPACE, _LSHIFT, _RSHIFT, _CAPS, _LWIN = 0x0E, 0x2A, 0x36, 0x3A, 0x5B
# Navigation keys arrive as extended scancodes; they are noted, not typed.
_EXTENDED_KEYS = {
    0x48: "up", 0x50: "down", 0x4B: "left", 0x4D: "right", 0x53: "delete",
    0x47: "home", 0x4F: "end", 0x49: "page_up", 0x51: "page_down", 0x52: "insert",
}  # fmt: skip


class InputRecorder:
    """Turns keyboard and mouse events into a bounded transcript of what was done."""

    def __init__(self) -> None:
        self.typed: list[str] = []
        self.keys = 0
        self.clicks: list[tuple[int, int]] = []
        self.moves = 0
        self.special: set[str] = set()
        self._shift = False
        self._caps = False

    def on_scancode(self, flags: int, code: int) -> None:
        released = bool(flags & 0x8000)
        extended = bool(flags & 0x0100)
        if extended and code in (_LSHIFT, _RSHIFT):
            return  # the fake-shift half of an extended key pair (Print Screen, arrows)
        if code in (_LSHIFT, _RSHIFT):
            self._shift = not released
            return
        if released:
            return
        self.keys += 1
        if code == _LWIN:
            self.special.add("windows_key")
            return
        if code == _CAPS:
            self._caps = not self._caps
            return
        if code == _BACKSPACE:
            if self.typed:
                self.typed.pop()
            return
        if extended and code in _EXTENDED_KEYS:
            self.special.add(_EXTENDED_KEYS[code])
            return
        entry = _KEYS.get(code)
        if entry is None or len(self.typed) >= MAX_TYPED:
            return
        upper = self._shift ^ self._caps if entry[0].isalpha() else self._shift
        self.typed.append(entry[1] if upper else entry[0])

    def on_unicode(self, flags: int, code: int) -> None:
        if flags & 0x8000:
            return
        self.keys += 1
        if len(self.typed) < MAX_TYPED and 0 < code < 0x110000:
            self.typed.append(chr(code) if chr(code).isprintable() or code in (9, 10, 13) else "?")

    def on_mouse(self, flags: int, x: int, y: int) -> None:
        if flags & 0x0800:
            self.moves += 1
        if flags & 0x8000 and flags & 0x7000 and len(self.clicks) < MAX_CLICKS:
            self.clicks.append((x, y))

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "typed": "".join(self.typed),
            "key_events": self.keys,
            "mouse_moves": self.moves,
            "clicks": [list(c) for c in self.clicks],
        }
        if self.special:
            out["special_keys"] = sorted(self.special)
        return out


def parse_slow_path_input(payload: bytes, recorder: InputRecorder) -> int:
    """Feed an Input Data PDU's events to `recorder`. Returns the number of events."""
    if len(payload) < 4:
        return 0
    count = min(struct.unpack_from("<H", payload, 0)[0], 256)
    pos, seen = 4, 0
    for _ in range(count):
        if pos + 12 > len(payload):
            break
        _time, kind, a, b, c = struct.unpack_from("<IHHHH", payload, pos)
        if kind == 0x0004:
            recorder.on_scancode(a, b)
        elif kind == 0x0005:
            recorder.on_unicode(a, b)
        elif kind in (0x8001, 0x8002):
            recorder.on_mouse(a, b, c)
        pos += 12
        seen += 1
    return seen


# ── The session ─────────────────────────────────────────────────────────────

LoginDecision = Callable[[dict[str, Any]], Awaitable[bool]]


async def run_session(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    connect_initial: bytes,
    selected_protocol: int,
    decide_login: LoginDecision | None,
    on_active: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    on_clipboard: Callable[[list[str]], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Serve one session from the client's Connect Initial to its end.

    `decide_login(client_info)` is asked once, when the Client Info arrives, and returns
    whether to let this visitor in; None means authentication already happened (NLA).
    Returns what happened: stage reached, client info, duration and the input transcript."""
    started = time.monotonic()
    blocks = parse_client_blocks(connect_initial)
    width = max(320, min(blocks["width"], 1024)) // 4 * 4
    height = max(240, min(blocks["height"], 768))
    channels: list[str] = blocks["channels"]
    # The client's own MCS user channel. Static channels take the ids after the I/O channel
    # (1004, 1005, ...); a user id equal to one of them would send that channel's traffic to the
    # client instead. Windows allocates the user id after the channels for the same reason.
    client_user = max(CLIENT_USER, IO_CHANNEL + 1 + len(channels))
    result: dict[str, Any] = {
        "stage": "connect",
        "desktop": f"{width}x{height}",
        "static_channels": channels,
    }
    recorder = InputRecorder()
    # The clipboard channel, if the client asked for it: static channels are numbered in the
    # order they were requested, starting after the I/O channel (see build_connect_response).
    clip_id = next(
        (IO_CHANNEL + 1 + i for i, name in enumerate(channels) if name.lower() == "cliprdr"), None
    )
    clipboard = ClipboardChannel() if clip_id is not None else None
    clipboard_reported = 0

    def send_clipboard(messages: list[bytes]) -> None:
        assert clip_id is not None
        for message in messages:
            for chunk in wrap_channel_pdu(message):
                send(send_data_indication(clip_id, chunk))

    bpp = 16
    stage = "mcs"
    input_bytes = 0
    events = 0
    last_input = started

    sent = 0
    refreshes = 0
    desktop: list[bytes] | None = None

    def send(data: bytes) -> None:
        nonlocal sent
        sent += len(data)
        if not writer.is_closing():
            writer.write(data)

    def desktop_updates() -> list[bytes]:
        """The desktop as ready-to-send frames, rendered once per session."""
        nonlocal desktop
        if desktop is None:
            rows = render_desktop(width, height, bpp)
            desktop = [
                send_data_indication(IO_CHANNEL, u) for u in bitmap_updates(rows, width, bpp)
            ]
        return desktop

    send(build_connect_response(len(channels), selected_protocol))
    try:
        await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
        while True:
            now = time.monotonic()
            if now - started > SESSION_SECONDS or now - last_input > IDLE_SECONDS:
                result["ended_by"] = "time limit"
                break
            if events > MAX_EVENTS or input_bytes > MAX_INPUT_BYTES or sent > MAX_OUTPUT_BYTES:
                result["ended_by"] = "volume limit"
                break
            kind, body = await read_frame(reader, _READ_TIMEOUT)
            input_bytes += len(body)
            if kind == "fast":
                continue  # fast-path input is never negotiated; tolerate and ignore
            if body[:3] != b"\x02\xf0\x80":
                result["ended_by"] = "x224 disconnect"
                break
            mcs = body[3:]
            if not mcs:
                continue
            pdu = mcs[0] >> 2
            if pdu == 8:  # Disconnect Provider Ultimatum
                result["ended_by"] = "client disconnect"
                break
            if pdu == 10:  # Attach User Request
                send(frame(b"\x2e\x00" + struct.pack(">H", client_user - 1001)))
            elif pdu == 14 and len(mcs) >= 5:  # Channel Join Request
                requested = struct.unpack_from(">H", mcs, 3)[0]
                send(
                    frame(
                        b"\x3e\x00"
                        + struct.pack(">H", client_user - 1001)
                        + struct.pack(">H", requested)
                        + struct.pack(">H", requested)
                    )
                )
            elif pdu == 25:
                parsed = parse_send_data_request(mcs)
                if parsed is None:
                    continue
                channel, data = parsed
                if channel != IO_CHANNEL:
                    if clipboard is not None and channel == clip_id and stage == "active":
                        events += 1
                        last_input = time.monotonic()
                        send_clipboard(clipboard.feed(data))
                        fresh = clipboard.take_new_text(clipboard_reported)
                        if fresh:
                            clipboard_reported += len(fresh)
                            if on_clipboard is not None:
                                await on_clipboard(fresh)
                    continue  # any other static virtual channel: not served
                events += 1
                last_input = time.monotonic()
                if stage == "mcs":
                    info = parse_client_info(data)
                    if info is None:
                        continue
                    result["client_info"] = info
                    result["stage"] = "client_info"
                    if decide_login is not None and not await decide_login(info):
                        result["ended_by"] = "login refused"
                        break
                    send(
                        send_data_indication(
                            IO_CHANNEL,
                            struct.pack("<HH", _SEC_LICENSE_PKT, 0)
                            + struct.pack("<BBHIIHH", 0xFF, 0x03, 16, 7, 2, 4, 0),
                        )
                    )
                    send(send_data_indication(IO_CHANNEL, demand_active(width, height)))
                    stage = "confirm"
                    continue
                if len(data) < 6:
                    continue
                total, pdu_type, _source = struct.unpack_from("<HHH", data, 0)
                ptype = pdu_type & 0x0F
                if ptype == _PDU_CONFIRM_ACTIVE:
                    bpp = confirmed_bits_per_pixel(data[6:])
                    result["color_depth"] = bpp
                    stage = "finalize"
                    # Windows follows a Confirm Active with its own Synchronize and
                    # Control(Cooperate), unprompted, and clients wait for them.
                    send(
                        send_data_indication(
                            IO_CHANNEL,
                            share_data(_DATA_SYNCHRONIZE, struct.pack("<HH", 1, client_user)),
                        )
                    )
                    send(
                        send_data_indication(
                            IO_CHANNEL,
                            share_data(_DATA_CONTROL, struct.pack("<HHI", 4, 0, 0)),
                        )
                    )
                elif ptype == _PDU_DATA and len(data) >= 18:
                    data_type = data[14]
                    payload = data[18:]
                    if data_type == _DATA_CONTROL and len(payload) >= 2:
                        if struct.unpack_from("<H", payload, 0)[0] == 1:  # request control
                            reply = struct.pack("<HHI", 2, client_user, 0x03EA)  # granted
                            send(send_data_indication(IO_CHANNEL, share_data(_DATA_CONTROL, reply)))
                    elif data_type == _DATA_FONT_LIST and stage == "finalize":
                        send(
                            send_data_indication(
                                IO_CHANNEL,
                                share_data(_DATA_FONT_MAP, struct.pack("<HHHH", 0, 0, 3, 4)),
                            )
                        )
                        for frame_bytes in desktop_updates():
                            send(frame_bytes)
                            await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
                        stage = "active"
                        result["stage"] = "active"
                        if on_active is not None:
                            await on_active(dict(result))
                        if clipboard is not None:
                            send_clipboard(clipboard.opening())
                    elif data_type == _DATA_INPUT and stage == "active":
                        events += parse_slow_path_input(payload, recorder)
                    elif data_type == _DATA_SHUTDOWN_REQUEST:
                        send(
                            send_data_indication(IO_CHANNEL, share_data(_DATA_SHUTDOWN_DENIED, b""))
                        )
                    elif (
                        data_type == _DATA_REFRESH_RECT
                        and stage == "active"
                        and refreshes < MAX_REFRESHES
                    ):
                        refreshes += 1
                        for frame_bytes in desktop_updates():
                            send(frame_bytes)
                            await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
            await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
            await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
    except (asyncio.IncompleteReadError, ConnectionError, OSError):
        result.setdefault("ended_by", "connection closed")
    except TimeoutError:
        result.setdefault("ended_by", "timeout")
    except ValueError:
        result.setdefault("ended_by", "malformed pdu")
    result.setdefault("ended_by", "ended")
    result["duration_seconds"] = round(time.monotonic() - started, 1)
    result.update(recorder.summary())
    if clipboard is not None and (clipboard.texts or clipboard.formats_seen):
        result["clipboard"] = clipboard.texts
        result["clipboard_formats"] = sorted(clipboard.formats_seen)[:32]
    return result
