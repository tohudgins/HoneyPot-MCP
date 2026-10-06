"""The RDP honeypot's desktop: a framebuffer, and a small Windows-like shell around it.

A visitor who gets a session sees a desktop with two icons and a taskbar. Double-click the
`cmd` icon, open the Start menu, or press Win+R and type `cmd` or `powershell`, and a console
window opens in which `rdp_shell.Shell` answers what they type. Everything is drawn here, into
an in-memory framebuffer, and sent as bitmap updates: nothing is executed and nothing is
displayed that this module did not paint.

Three parts:

* `Screen`: rows of pixel bytes in the format the client negotiated, with `fill` and `text`
  (8x16 Spleen glyphs, cached per colour pair so a line of text is sixteen slice assignments).
* `Desktop`: the scene (background, icons, taskbar, Start menu, windows) and the input state
  machine (clicks, double-clicks, typed characters, Esc, Win, Win+R).
* `commit()`: repaint the scene, then find what changed against the previous frame and return
  only that rectangle, so a keystroke costs a 16-pixel-high strip rather than the screen.

Pure and synchronous, so it is unit-tested without a client.
"""

from __future__ import annotations

import textwrap
import time
from dataclasses import dataclass, field

from honeypot_mcp.engines.rdp_font import GLYPH_HEIGHT, GLYPH_WIDTH, GLYPHS, glyph
from honeypot_mcp.engines.rdp_shell import Identity, Shell

Rect = tuple[int, int, int, int]  # x0, y0, x1, y1 (exclusive), multiples of 8 horizontally
RGB = tuple[int, int, int]

TASKBAR_H = 40
MAX_INPUT_CHARS = 500
MAX_SCROLLBACK = 300
DOUBLE_CLICK_SECONDS = 0.8
MAX_COMMANDS = 100
_CHUNK_BYTES = 16_000

_WHITE: RGB = (235, 235, 240)
_BLACK: RGB = (12, 12, 12)
_GREY: RGB = (204, 204, 204)
_ACCENT: RGB = (0, 120, 215)
_TASKBAR: RGB = (28, 28, 32)
_TRAY: RGB = (40, 40, 46)
_PS_BG: RGB = (1, 36, 86)
_PS_FG: RGB = (238, 237, 240)
_FRAME: RGB = (100, 100, 110)
_MENU: RGB = (36, 36, 42)
_BUTTON: RGB = (225, 225, 225)

_KNOWN_PROGRAMS = {
    "notepad", "calc", "mspaint", "regedit", "taskmgr", "mstsc", "explorer", "control", "mmc", "services.msc",
    "eventvwr", "compmgmt.msc", "devmgmt.msc", "diskmgmt.msc", "lusrmgr.msc", "gpedit.msc", "wmic", "msconfig",
    "cleanmgr", "perfmon", "resmon", "winver", "snippingtool", "wordpad", "write", "osk", "magnify", "narrator",
    "dxdiag", "msinfo32", "appwiz.cpl", "ncpa.cpl", "sysdm.cpl", "inetcpl.cpl", "firewall.cpl", "powercfg.cpl",
    "cmd", "powershell", "pwsh", "wt", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "msiexec",
}  # fmt: skip


def pixel(rgb: RGB, bpp: int) -> bytes:
    """One pixel in the client's colour depth (RGB565, RGB555, BGR24, BGRA32)."""
    r, g, b = rgb
    if bpp == 16:
        value = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
        return bytes((value & 0xFF, value >> 8))
    if bpp == 15:
        value = ((r >> 3) << 10) | ((g >> 3) << 5) | (b >> 3)
        return bytes((value & 0xFF, value >> 8))
    if bpp == 24:
        return bytes((b, g, r))
    return bytes((b, g, r, 0))


class Screen:
    """Rows of pixels, with rectangle fill and bitmap-font text."""

    def __init__(self, width: int, height: int, bpp: int) -> None:
        self.width, self.height, self.bpp = width, height, bpp
        self.bytes_pp = (bpp + 7) // 8
        self.rows: list[bytearray] = [bytearray(width * self.bytes_pp) for _ in range(height)]
        self._glyphs: dict[tuple[str, RGB, RGB], tuple[bytes, ...]] = {}
        self._pixels: dict[RGB, bytes] = {}

    def _px(self, colour: RGB) -> bytes:
        if colour not in self._pixels:
            self._pixels[colour] = pixel(colour, self.bpp)
        return self._pixels[colour]

    def fill(self, x0: int, y0: int, x1: int, y1: int, colour: RGB) -> None:
        x0, x1 = max(0, x0), min(self.width, x1)
        y0, y1 = max(0, y0), min(self.height, y1)
        if x0 >= x1 or y0 >= y1:
            return
        run = self._px(colour) * (x1 - x0)
        a, b = x0 * self.bytes_pp, x1 * self.bytes_pp
        for y in range(y0, y1):
            self.rows[y][a:b] = run

    def _cell(self, char: str, fg: RGB, bg: RGB) -> tuple[bytes, ...]:
        # Keyed by the glyph that is drawn, not the character asked for: every character the font
        # lacks draws the same block, and a visitor can type 85,000 distinct ones.
        key = (char if ord(char) in GLYPHS else "\u2591", fg, bg)
        cached = self._glyphs.get(key)
        if cached is None:
            on, off = self._px(fg), self._px(bg)
            cached = tuple(
                b"".join(on if row & (0x80 >> bit) else off for bit in range(GLYPH_WIDTH))
                for row in glyph(char)
            )
            self._glyphs[key] = cached
        return cached

    def text(self, x: int, y: int, text: str, fg: RGB, bg: RGB) -> None:
        """Draw `text` with its top-left at (x, y), clipped to the screen."""
        if y < 0 or y + GLYPH_HEIGHT > self.height or not text:
            return
        if x < 0:  # drop the characters that start left of the screen
            skip = (-x + GLYPH_WIDTH - 1) // GLYPH_WIDTH
            text, x = text[skip:], x + skip * GLYPH_WIDTH
        text = text[: max(0, (self.width - x) // GLYPH_WIDTH)]
        if not text:
            return
        cells = [self._cell(ch, fg, bg) for ch in text]
        a, b = x * self.bytes_pp, (x + len(text) * GLYPH_WIDTH) * self.bytes_pp
        for line in range(GLYPH_HEIGHT):
            self.rows[y + line][a:b] = b"".join(cell[line] for cell in cells)


@dataclass
class _Icon:
    label: str
    x: int
    y: int
    action: str


@dataclass
class _Window:
    kind: str  # "terminal" | "run" | "message"
    title: str
    x: int
    y: int
    w: int
    h: int
    lines: list[str] = field(default_factory=list)


@dataclass
class Command:
    shell: str  # "cmd" | "powershell" | "run"
    text: str


def _wrap(text: str, cols: int) -> list[str]:
    if cols <= 0:
        return [""]
    return [text[i : i + cols] for i in range(0, max(len(text), 1), cols)] or [""]


class Desktop:
    def __init__(self, width: int, height: int, bpp: int, identity: Identity) -> None:
        self.screen = Screen(width, height, bpp)
        self.identity = identity
        self.width, self.height = width, height
        self.icons = [_Icon("Recycle Bin", 24, 24, "recycle"), _Icon("cmd", 24, 112, "terminal")]
        self.selected: int | None = None
        self._last_click: tuple[int, float] | None = None
        self.start_open = False
        self.terminal: _Window | None = None
        self.shell: Shell | None = None
        self._scrollback: list[str] = []
        self._input = ""
        self.run: _Window | None = None
        self._run_text = ""
        self.message: _Window | None = None
        self.commands: list[Command] = []
        self.commands_run = 0
        self._pending: list[Command] = []
        self.repaints = 0
        self.disconnect = False  # the visitor shut the machine down or logged off
        self._background = self._paint_background()
        self._frame: list[bytes] | None = None

    # ── geometry ─────────────────────────────────────────────────────────────

    def _terminal_geometry(self) -> tuple[int, int, int, int, int, int]:
        cols = max(20, min(80, (self.width - 64) // GLYPH_WIDTH))
        rows = max(6, min(25, (self.height - TASKBAR_H - 100) // GLYPH_HEIGHT))
        w, h = cols * GLYPH_WIDTH + 16, rows * GLYPH_HEIGHT + 32
        x = max(0, (self.width - w) // 2) // 8 * 8
        y = max(0, (self.height - TASKBAR_H - h) // 2)
        return x, y, w, h, cols, rows

    # ── painting ─────────────────────────────────────────────────────────────

    def _paint_background(self) -> list[bytes]:
        screen = Screen(self.width, self.height, self.screen.bpp)
        for y in range(self.height):
            shade = max(0, 150 - (y * 90) // max(1, self.height))
            screen.fill(0, y, self.width, y + 1, (8, shade // 2 + 20, shade + 40))
        return [bytes(r) for r in screen.rows]

    def _paint_scene(self) -> None:
        s = self.screen
        for y in range(self.height):
            s.rows[y][:] = self._background[y]
        for index, icon in enumerate(self.icons):
            s.fill(icon.x, icon.y, icon.x + 48, icon.y + 36, _WHITE)
            s.fill(icon.x, icon.y + 36, icon.x + 48, icon.y + 48, (90, 110, 150))
            label_x = max(0, icon.x + 24 - len(icon.label) * GLYPH_WIDTH // 2)
            highlighted = self.selected == index
            s.text(
                label_x,
                icon.y + 52,
                icon.label,
                (255, 255, 255),
                _ACCENT if highlighted else (10, 40, 80),
            )
        self._paint_taskbar()
        if self.start_open:
            self._paint_start_menu()
        for window in (self.terminal, self.message, self.run):
            if window is not None:
                self._paint_window(window)

    def _paint_taskbar(self) -> None:
        s, top = self.screen, self.height - TASKBAR_H
        s.fill(0, top, self.width, self.height, _TASKBAR)
        s.fill(0, top + 4, 52, self.height, _ACCENT)
        s.text(6, top + 4 + (TASKBAR_H - 4 - GLYPH_HEIGHT) // 2, "Start", (255, 255, 255), _ACCENT)
        if self.terminal is not None:
            s.fill(60, top + 6, 230, self.height - 2, _TRAY)
            label = (
                "Windows PowerShell"
                if self.shell is not None and self.shell.kind == "powershell"
                else "Command Prompt"
            )
            s.text(68, top + 4 + (TASKBAR_H - 4 - GLYPH_HEIGHT) // 2, label, _GREY, _TRAY)
        s.fill(self.width - 120, top + 4, self.width, self.height, _TRAY)
        s.text(
            self.width - 96,
            top + 4 + (TASKBAR_H - 4 - GLYPH_HEIGHT) // 2,
            time.strftime("%I:%M %p"),
            _GREY,
            _TRAY,
        )

    _MENU_ITEMS = ("Command Prompt", "Windows PowerShell", "Run", "Shut down")

    def _menu_rect(self) -> Rect:
        height = len(self._MENU_ITEMS) * 28 + 8
        return 0, self.height - TASKBAR_H - height, 232, self.height - TASKBAR_H

    def _paint_start_menu(self) -> None:
        x0, y0, x1, y1 = self._menu_rect()
        self.screen.fill(x0, y0, x1, y1, _MENU)
        for i, label in enumerate(self._MENU_ITEMS):
            self.screen.text(x0 + 16, y0 + 4 + i * 28 + 6, label, (240, 240, 240), _MENU)

    def _paint_window(self, w: _Window) -> None:
        s = self.screen
        s.fill(w.x - 1, w.y - 1, w.x + w.w + 1, w.y + w.h + 1, _FRAME)
        s.fill(w.x, w.y, w.x + w.w, w.y + 24, (255, 255, 255))
        s.text(w.x + 6, w.y + 4, w.title[: (w.w - 48) // GLYPH_WIDTH], (0, 0, 0), (255, 255, 255))
        s.fill(w.x + w.w - 40, w.y, w.x + w.w, w.y + 24, (232, 17, 35))
        s.text(w.x + w.w - 28, w.y + 4, "X", (255, 255, 255), (232, 17, 35))
        if w.kind == "terminal":
            self._paint_terminal(w)
        elif w.kind == "run":
            self._paint_run(w)
        else:
            self._paint_message(w)

    def _terminal_colours(self) -> tuple[RGB, RGB]:
        return (
            (_PS_FG, _PS_BG) if self.shell and self.shell.kind == "powershell" else (_GREY, _BLACK)
        )

    def _visible_terminal_lines(self, cols: int, rows: int) -> list[str]:
        assert self.shell is not None
        current = _wrap(self.shell.prompt() + self._input, cols)
        lines = self._scrollback + current
        return lines[-rows:]

    def _paint_terminal(self, w: _Window) -> None:
        _, _, _, _, cols, rows = self._terminal_geometry()
        fg, bg = self._terminal_colours()
        body_y = w.y + 24
        self.screen.fill(w.x, body_y, w.x + w.w, w.y + w.h, bg)
        visible = self._visible_terminal_lines(cols, rows)
        for i, line in enumerate(visible):
            self.screen.text(w.x + 8, body_y + 4 + i * GLYPH_HEIGHT, line, fg, bg)
        # the cursor: an underscore at the end of the input
        last = visible[-1] if visible else ""
        self.screen.text(
            w.x + 8 + len(last) * GLYPH_WIDTH,
            body_y + 4 + (len(visible) - 1) * GLYPH_HEIGHT,
            "_",
            fg,
            bg,
        )

    def _paint_run(self, w: _Window) -> None:
        s = self.screen
        grey, black = (240, 240, 240), (0, 0, 0)
        s.fill(w.x, w.y + 24, w.x + w.w, w.y + w.h, grey)
        for i, line in enumerate(w.lines):  # the caption, wrapped to the dialog
            s.text(w.x + 12, w.y + 34 + i * GLYPH_HEIGHT, line, black, grey)
        open_y = w.y + 34 + len(w.lines) * GLYPH_HEIGHT + 12
        s.text(w.x + 12, open_y + 4, "Open:", black, grey)
        s.fill(w.x + 72, open_y, w.x + w.w - 16, open_y + 24, (255, 255, 255))
        shown = self._run_text[-max(1, (w.w - 96) // GLYPH_WIDTH - 1) :]
        s.text(w.x + 76, open_y + 4, shown + "_", black, (255, 255, 255))
        for label, bx in (("OK", w.w - 220), ("Cancel", w.w - 140)):
            if bx < 0:
                continue
            s.fill(w.x + bx, w.y + w.h - 40, w.x + bx + 68, w.y + w.h - 12, _BUTTON)
            s.text(w.x + bx + 34 - len(label) * 4, w.y + w.h - 34, label, black, _BUTTON)

    def _paint_message(self, w: _Window) -> None:
        s = self.screen
        s.fill(w.x, w.y + 24, w.x + w.w, w.y + w.h, (240, 240, 240))
        for i, line in enumerate(w.lines[:4]):
            s.text(w.x + 16, w.y + 40 + i * 18, line, (0, 0, 0), (240, 240, 240))
        s.fill(w.x + w.w - 92, w.y + w.h - 40, w.x + w.w - 24, w.y + w.h - 12, _BUTTON)
        s.text(w.x + w.w - 74, w.y + w.h - 34, "OK", (0, 0, 0), _BUTTON)

    # ── committing a frame ───────────────────────────────────────────────────

    def commit(self) -> Rect | None:
        """Repaint, and return the rectangle that differs from the last committed frame
        (the whole screen the first time)."""
        self._paint_scene()
        self.repaints += 1
        rows = [bytes(r) for r in self.screen.rows]
        previous, self._frame = self._frame, rows
        if previous is None:
            return 0, 0, self.width, self.height
        bp = self.screen.bytes_pp
        top = bottom = None
        left, right = len(rows[0]), 0
        for y, (old, new) in enumerate(zip(previous, rows, strict=True)):
            if old == new:
                continue
            diff = int.from_bytes(old, "big") ^ int.from_bytes(new, "big")
            size = len(new)
            # Big-endian: the most significant set bit is the FIRST differing byte, the least
            # significant set bit the last.
            first = size - 1 - ((diff.bit_length() - 1) // 8)
            last = size - 1 - (((diff & -diff).bit_length() - 1) // 8)
            left, right = min(left, first), max(right, last)
            top = y if top is None else top
            bottom = y
        if top is None or bottom is None:
            return None
        x0 = (left // bp) // 8 * 8
        x1 = min(self.width, ((right // bp) // 8 + 1) * 8)
        return x0, top, x1, bottom + 1

    def chunks(self, rect: Rect) -> list[tuple[int, int, int, int, bytes]]:
        """The pixels of `rect` as bitmap-update pieces: (x0, y0, x1, y1, data), each small
        enough for one PDU, rows stored bottom-up as the protocol wants."""
        x0, y0, x1, y1 = rect
        bp = self.screen.bytes_pp
        row_bytes = (x1 - x0) * bp
        per = max(1, _CHUNK_BYTES // row_bytes)
        out = []
        frame = self._frame or []
        for top in range(y0, y1, per):
            bottom = min(y1, top + per)
            data = b"".join(frame[y][x0 * bp : x1 * bp] for y in range(bottom - 1, top - 1, -1))
            out.append((x0, top, x1, bottom, data))
        return out

    # ── input ────────────────────────────────────────────────────────────────

    def apply(self, actions: list[tuple], now: float | None = None) -> Rect | None:
        """Process input actions in order and return the changed rectangle, if any.

        Actions: ("char", c), ("special", "esc" | "win" | "win+r"), ("click", x, y, button)."""
        now = time.monotonic() if now is None else now
        for action in actions:
            kind = action[0]
            if kind == "char":
                self._on_char(action[1])
            elif kind == "special":
                self._on_special(action[1])
            elif kind == "click" and action[3] == 1:
                self._on_click(action[1], action[2], now)
        return self.commit()

    def drain_commands(self) -> list[Command]:
        out, self._pending = self._pending, []
        return out

    def _record(self, shell: str, text: str) -> None:
        command = Command(shell, text[:500])
        self._pending.append(command)
        if len(self.commands) < MAX_COMMANDS:
            self.commands.append(command)

    def _on_char(self, char: str) -> None:
        if self.message is not None:
            if char in "\n\r":
                self.message = None
            return
        if self.run is not None:
            if char in "\n\r":
                self._submit_run()
            elif char == "\b":
                self._run_text = self._run_text[:-1]
            elif char.isprintable() and len(self._run_text) < 200:
                self._run_text += char
            return
        if self.terminal is None or self.shell is None:
            return
        if char in "\n\r":
            self._submit_terminal()
        elif char == "\b":
            self._input = self._input[:-1]
        elif char.isprintable() and len(self._input) < MAX_INPUT_CHARS:
            self._input += char

    def _on_special(self, name: str) -> None:
        if self.message is not None and name != "esc":
            return  # a message box is modal: Start and Run wait behind it
        if name == "ctrl+c":
            if self.terminal is not None and self.shell is not None and self.run is None:
                cols = self._terminal_geometry()[4]
                self._scrollback.extend(_wrap(self.shell.prompt() + self._input + "^C", cols))
                self._input = ""
                del self._scrollback[:-MAX_SCROLLBACK]
            return
        if name == "esc":
            if self.message is not None:
                self.message = None
            elif self.run is not None:
                self.run, self._run_text = None, ""
            else:
                self.start_open = False
        elif name == "win":
            self.start_open = not self.start_open
        elif name == "win+r":
            self.start_open = False
            self._open_run()

    def _open_run(self) -> None:
        if self.message is not None:
            return  # a message box is modal
        w = max(160, min(420, self.width - 16)) // 8 * 8
        caption = textwrap.wrap(
            "Type the name of a program, folder, document, or Internet resource, and Windows "
            "will open it for you.",
            max(8, (w - 24) // GLYPH_WIDTH),
        )[:5]
        h = len(caption) * GLYPH_HEIGHT + 130
        self.run = _Window("run", "Run", 8, max(0, self.height - TASKBAR_H - h - 8), w, h, caption)
        self._run_text = ""

    def _open_terminal(self, kind: str = "cmd") -> None:
        x, y, w, h, cols, _rows = self._terminal_geometry()
        self.start_open = False
        if self.terminal is None:
            self.shell = Shell(self.identity, kind)
            self._scrollback = []
            for line in self.shell.banner():
                self._scrollback.extend(_wrap(line, cols))
            self._input = ""
        elif self.shell is not None and kind == "powershell" and self.shell.kind != "powershell":
            self.shell.execute("powershell")
        self.terminal = _Window("terminal", self._terminal_title(), x, y, w, h)

    def _terminal_title(self) -> str:
        if self.shell and self.shell.kind == "powershell":
            return "Windows PowerShell"
        return "C:\\Windows\\system32\\cmd.exe"

    def _submit_terminal(self) -> None:
        assert self.shell is not None and self.terminal is not None
        _, _, _, _, cols, _ = self._terminal_geometry()
        line = self._input
        self._input = ""
        self._scrollback.extend(_wrap(self.shell.prompt() + line, cols))
        if line.strip():
            self._record(self.shell.kind, line)
            self.commands_run += 1
        result = self.shell.execute(line)
        if result.clear:
            self._scrollback = []
        if result.disconnect:
            self.disconnect = True
        if result.exit:
            self.terminal, self.shell, self._scrollback = None, None, []
            return
        for out in result.lines:
            self._scrollback.extend(_wrap(out, cols))
        del self._scrollback[:-MAX_SCROLLBACK]
        self.terminal.title = self._terminal_title()

    def _submit_run(self) -> None:
        text = self._run_text.strip()
        self.run, self._run_text = None, ""
        if not text:
            return
        self._record("run", text)
        self.commands_run += 1
        words = text.split(None, 1)
        program = words[0].lower().removesuffix(".exe")
        if program in ("cmd", "powershell", "pwsh") and len(words) == 1:
            self._open_terminal("powershell" if program != "cmd" else "cmd")
        elif program in ("shutdown", "logoff"):
            if Shell(self.identity).execute(text).disconnect:
                self.disconnect = True
        elif program in _KNOWN_PROGRAMS or "\\" in text or "/" in text:
            return  # something real Windows would open; there is no window for it here
        else:
            shown = text[:40]
            self._message(
                shown,
                [
                    f"Windows cannot find '{shown}'. Make sure you typed the name correctly, and then try again."
                ],
            )

    def _message(self, title: str, lines: list[str]) -> None:
        w = max(160, min(400, self.width - 16)) // 8 * 8
        wrapped = [
            piece
            for line in lines
            for piece in textwrap.wrap(line, max(8, (w - 32) // GLYPH_WIDTH)) or [""]
        ][:6]
        h = max(130, 24 + 16 + len(wrapped) * 18 + 56)
        self.message = _Window(
            "message",
            title,
            max(0, (self.width - w) // 2) // 8 * 8,
            max(0, (self.height - TASKBAR_H - h) // 2),
            w,
            h,
            wrapped,
        )

    def _on_click(self, x: int, y: int, now: float) -> None:
        if self.message is not None:
            m = self.message
            if _inside(
                x, y, m.x + m.w - 92, m.y + m.h - 40, m.x + m.w - 24, m.y + m.h - 12
            ) or _inside(x, y, m.x + m.w - 40, m.y, m.x + m.w, m.y + 24):
                self.message = None
            return
        if self.run is not None:
            r = self.run
            if _inside(x, y, r.x + r.w - 40, r.y, r.x + r.w, r.y + 24) or _inside(
                x, y, r.x + r.w - 140, r.y + r.h - 40, r.x + r.w - 72, r.y + r.h - 12
            ):
                self.run, self._run_text = None, ""
            elif _inside(x, y, r.x + r.w - 220, r.y + r.h - 40, r.x + r.w - 152, r.y + r.h - 12):
                self._submit_run()
            return
        top = self.height - TASKBAR_H
        if self.start_open:
            x0, y0, x1, y1 = self._menu_rect()
            if _inside(x, y, x0, y0, x1, y1):
                item = (y - y0 - 4) // 28
                self.start_open = False
                if item == 0:
                    self._open_terminal("cmd")
                elif item == 1:
                    self._open_terminal("powershell")
                elif item == 2:
                    self._open_run()
                return
            self.start_open = False
            if _inside(x, y, 0, top, 52, self.height):
                return  # the click that closes the menu
        if _inside(x, y, 0, top, 52, self.height):
            self.start_open = not self.start_open
            return
        if self.terminal is not None:
            t = self.terminal
            if _inside(x, y, t.x + t.w - 40, t.y, t.x + t.w, t.y + 24):
                self.terminal, self.shell, self._scrollback = None, None, []
                return
        for index, icon in enumerate(self.icons):
            if _inside(x, y, icon.x, icon.y, icon.x + 48, icon.y + 72):
                again = (
                    self._last_click is not None
                    and self._last_click[0] == index
                    and now - self._last_click[1] <= DOUBLE_CLICK_SECONDS
                )
                self.selected = index
                self._last_click = (index, now)
                if again:
                    self._last_click = None
                    if icon.action == "terminal":
                        self._open_terminal("cmd")
                    else:
                        self._message("Recycle Bin", ["This folder is empty."])
                return
        self.selected = None
        self._last_click = None


def _inside(x: int, y: int, x0: int, y0: int, x1: int, y1: int) -> bool:
    return x0 <= x < x1 and y0 <= y < y1
