"""A fake Windows command line for the RDP honeypot's desktop: `cmd.exe` and PowerShell.

Nothing here executes anything. It is a table of plausible answers over a tiny virtual
filesystem, so a visitor who opens a terminal sees a machine that behaves like Windows and keeps
typing, and what they type is the intelligence. Three rules shape it:

* **No network, ever.** `ping`, `nslookup`, `curl`, `certutil`, `Invoke-WebRequest` and friends
  never touch a socket. Downloads fail the way they fail on a server with no route out (a name
  that does not resolve), which also records the URL they tried.
* **Honest about limits.** A process the visitor tries to kill, or a protected path they try to
  delete, is refused the way Windows refuses it; nothing claims a change it did not make except
  the session-local ones below (a file they `echo` into, a user they `net user /add`), which
  they can read back, because a visitor who writes a file and cannot find it leaves at once.
* **Deterministic.** Everything that looks like state (process ids, addresses, dates) derives
  from the honeypot's identity, so two visits to the same honeypot agree.

Pure and synchronous: `Shell.execute(line)` returns what to print.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

MAX_OUTPUT_LINES = 200
MAX_LINE_CHARS = 240
MAX_FILES = 20
MAX_FILE_BYTES = 2048
MAX_USERS = 8

_URL = re.compile(r"""(?:https?|ftp)://[^\s"'<>)]{3,300}""", re.I)
_DOWNLOADERS = re.compile(
    r"\b(curl|wget|certutil|bitsadmin|invoke-webrequest|iwr|invoke-restmethod|irm|"
    r"downloadstring|downloadfile|start-bitstransfer|net\.webclient)\b",
    re.I,
)


@dataclass
class Result:
    lines: list[str] = field(default_factory=list)
    clear: bool = False
    exit: bool = False
    disconnect: bool = False  # the session itself ends (shutdown, logoff)


@dataclass(frozen=True)
class Identity:
    computer: str
    domain: str
    user: str
    build: tuple[int, int, int] = (10, 0, 17763)
    peer_ip: str = "0.0.0.0"


def _h(*parts: str) -> int:
    return int.from_bytes(hashlib.sha256(":".join(parts).encode()).digest()[:8], "big")


def extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(_URL.findall(text)))[:5]


# Commands that only show or manage something: a URL or a tool name among their arguments is
# data, not an attempt to fetch it (`echo curl`, `dir C:\\wget`, `net user irm /add`).
_DISPLAY_WORDS = frozenset(
    [
        "echo",
        "type",
        "dir",
        "net",
        "ls",
        "gci",
        "cat",
        "gc",
        "write-host",
        "write-output",
        "findstr",
        "find",
        "set",
        "cd",
        "chdir",
        "md",
        "mkdir",
        "del",
        "erase",
        "copy",
        "ren",
        "rename",
        "move",
        "rd",
        "rmdir",
        "ver",
        "hostname",
        "whoami",
        "tasklist",
        "taskkill",
        "get-childitem",
        "get-content",
        "select-string",
        "sc",
        "reg",
        "assoc",
        "title",
        "cls",
        "where",
    ]
)
_DOWNLOAD_WORDS = frozenset(
    [
        "curl",
        "wget",
        "certutil",
        "bitsadmin",
        "invoke-webrequest",
        "iwr",
        "invoke-restmethod",
        "irm",
        "start-bitstransfer",
        "iex",
        "invoke-expression",
    ]
)


def _first_word(text: str) -> str:
    match = re.match(r"\s*\(?\s*([A-Za-z0-9_$.-]+)", text)
    return match[1].lower().removesuffix(".exe") if match else ""


def looks_like_download(text: str) -> bool:
    """Whether a command line is an attempt to fetch something. Decided by what is being run,
    not by substring: the severity of the alert depends on it."""
    word = _first_word(text)
    if word in _DISPLAY_WORDS:
        return False
    return word in _DOWNLOAD_WORDS or bool(_DOWNLOADERS.search(text) or _URL.search(text))


def _args(rest: str) -> list[str]:
    """Arguments split like cmd.exe: whitespace separates, quotes group (and are dropped)."""
    return [t.strip('"') for t in re.findall(r'"[^"]*"|\S+', rest)]


def _us_datetime(when: datetime) -> str:
    """`3/19/2019, 4:03:11 AM` without strftime's platform-specific `%-m` extension."""
    hour = when.hour % 12 or 12
    return f"{when.month}/{when.day}/{when.year}, {hour}:{when:%M:%S} {'AM' if when.hour < 12 else 'PM'}"


_PRODUCTS = {
    14393: ("Windows Server 2016 Standard", "(c) 2016 Microsoft Corporation. All rights reserved."),
    17763: ("Windows Server 2019 Standard", "(c) 2018 Microsoft Corporation. All rights reserved."),
    20348: ("Windows Server 2022 Standard", "(c) Microsoft Corporation. All rights reserved."),
}
_RESERVED_DEVICES = frozenset(
    [
        "con",
        "prn",
        "aux",
        "nul",
        *[f"com{n}" for n in range(1, 10)],
        *[f"lpt{n}" for n in range(1, 10)],
    ]
)


# ── virtual filesystem ───────────────────────────────────────────────────────


@dataclass
class Entry:
    name: str
    is_dir: bool = False
    size: int = 0
    when: datetime = field(default_factory=lambda: datetime(2019, 3, 19, 4, 3))


def _norm(path: str) -> str:
    path = path.replace("/", "\\")
    drive, _, rest = path.partition(":")
    parts: list[str] = []
    for piece in rest.split("\\"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return f"{drive.upper()}:\\" + "\\".join(parts)


class FileSystem:
    def __init__(self, identity: Identity) -> None:
        self.user = identity.user
        seed = _h("fs", identity.computer)
        base = datetime.now(UTC).replace(second=0, microsecond=0, tzinfo=None)
        self.dirs: dict[str, list[Entry]] = {}
        self.files: dict[str, str] = {}
        old = datetime(2019, 3, 19, 4, 3)

        def dated(offset_days: int, minute: int = 0) -> datetime:
            return base - timedelta(days=offset_days + seed % 5, minutes=minute)

        home = f"C:\\Users\\{identity.user}"
        self.dirs = {
            "C:\\": [
                Entry("PerfLogs", True, when=old),
                Entry("Program Files", True, when=old),
                Entry("Program Files (x86)", True, when=old),
                Entry("Users", True, when=dated(30)),
                Entry("Windows", True, when=dated(2)),
            ],
            "C:\\Users": [
                Entry(identity.user, True, when=dated(30)),
                Entry("Public", True, when=old),
            ],
            home: [
                Entry(n, True, when=dated(20 + i))
                for i, n in enumerate(("Desktop", "Documents", "Downloads", "Music", "Pictures"))
            ],
            f"{home}\\Desktop": [Entry("desktop.ini", False, 282, dated(20))],
            f"{home}\\Documents": [],
            f"{home}\\Downloads": [],
            f"{home}\\Music": [],
            f"{home}\\Pictures": [],
            "C:\\Users\\Public": [
                Entry("Documents", True, when=old),
                Entry("Downloads", True, when=old),
            ],
            "C:\\Windows": [
                Entry("System32", True, when=dated(2)),
                Entry("Temp", True, when=dated(0)),
                Entry("explorer.exe", False, 4_460_544, old),
                Entry("notepad.exe", False, 250_880, old),
                Entry("win.ini", False, 92, old),
            ],
            "C:\\Windows\\Temp": [],
            "C:\\Windows\\System32": [
                Entry("cmd.exe", False, 302_592, old),
                Entry("drivers", True, when=old),
                Entry("ipconfig.exe", False, 36_864, old),
                Entry("whoami.exe", False, 65_536, old),
            ],
            "C:\\Windows\\System32\\drivers": [Entry("etc", True, when=old)],
            "C:\\Windows\\System32\\drivers\\etc": [Entry("hosts", False, 824, old)],
            "C:\\Program Files": [
                Entry("Common Files", True, when=old),
                Entry("Windows Defender", True, when=old),
                Entry("Windows NT", True, when=old),
            ],
            "C:\\Program Files (x86)": [Entry("Common Files", True, when=old)],
            "C:\\PerfLogs": [],
        }
        self.files = {
            "C:\\Windows\\win.ini": "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1",
            "C:\\Windows\\System32\\drivers\\etc\\hosts": (
                "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
                "#\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost"
            ),
        }
        self._overlay_dirs: set[str] = set()
        self.created: dict[str, str] = {}

    # lookups
    def exists_dir(self, path: str) -> bool:
        key = _norm(path)
        return any(key.lower() == d.lower() for d in (*self.dirs, *self._overlay_dirs))

    def _key(self, path: str) -> str:
        key = _norm(path)
        for d in (*self.dirs, *self._overlay_dirs):
            if d.lower() == key.lower():
                return d
        return key

    def listing(self, path: str) -> list[Entry] | None:
        if not self.exists_dir(path):
            return None
        key = self._key(path)
        entries = list(self.dirs.get(key, []))
        parent = key.rstrip("\\")
        for created in self._overlay_dirs:
            if created.rsplit("\\", 1)[0].rstrip("\\").lower() == parent.lower() and created != key:
                entries.append(
                    Entry(
                        created.rsplit("\\", 1)[1],
                        True,
                        when=datetime.now(UTC).replace(tzinfo=None),
                    )
                )
        for fpath, content in self.created.items():
            if fpath.rsplit("\\", 1)[0].rstrip("\\").lower() == parent.lower():
                entries.append(
                    Entry(
                        fpath.rsplit("\\", 1)[1],
                        False,
                        len(content.encode()),
                        datetime.now(UTC).replace(tzinfo=None),
                    )
                )
        return sorted(entries, key=lambda e: (not e.is_dir, e.name.lower()))

    def read(self, path: str) -> str | None:
        key = _norm(path)
        for table in (self.created, self.files):
            for name, content in table.items():
                if name.lower() == key.lower():
                    return content
        return None

    def write(self, path: str, content: str, *, append: bool = False) -> str | None:
        """Create or extend a session file. Returns an error message or None."""
        key = _norm(path)
        folder, _, leaf = key.rpartition("\\")
        folder = folder or "C:"
        leaf = leaf.rstrip(". ")  # Windows ignores trailing dots and spaces in names
        if not leaf:  # a drive root, or only dots: not a file
            return "Access is denied."
        if leaf.split(".")[0].lower() in _RESERVED_DEVICES:
            return None  # `> nul`: a device, not a file; the data goes nowhere
        key = f"{folder}\\{leaf}" if not folder.endswith("\\") else f"{folder}{leaf}"
        if not self.exists_dir(folder + "\\"):
            return "The system cannot find the path specified."
        if self.exists_dir(key):
            return "Access is denied."
        if folder.lower().startswith("c:\\windows\\system32"):
            return "Access is denied."
        existing = next((k for k in self.created if k.lower() == key.lower()), None)
        key = existing or key
        if existing is None and len(self.created) >= MAX_FILES:
            return "There is not enough space on the disk."
        previous = self.created.get(key, "") if append else ""
        self.created[key] = (previous + content)[:MAX_FILE_BYTES]
        return None

    def remove_dir(self, path: str) -> str | None:
        key = self._key(path)
        if key in self._overlay_dirs:
            self._overlay_dirs.discard(key)
            for name in [n for n in self.created if n.rsplit("\\", 1)[0].lower() == key.lower()]:
                del self.created[name]
            return None
        if self.exists_dir(key):
            return "Access is denied."
        return "The system cannot find the file specified."

    def move(self, source: str, target: str) -> str | None:
        """Rename or move a session file. Shipped files are not the visitor's to move."""
        key = next((k for k in self.created if k.lower() == _norm(source).lower()), None)
        if key is None:
            if self.read(source) is not None or self.exists_dir(source):
                return "Access is denied."
            return "The system cannot find the file specified."
        content = self.created[key]
        error = self.write(target, content)
        if error is None:
            del self.created[key]
        return error

    def make_dir(self, path: str) -> str | None:
        key = _norm(path)
        if self.exists_dir(key):
            return "A subdirectory or file " + key.rsplit("\\", 1)[-1] + " already exists."
        parent = key.rsplit("\\", 1)[0] or "C:\\"
        if not self.exists_dir(parent):
            return "The system cannot find the path specified."
        if len(self._overlay_dirs) >= MAX_FILES:
            return "There is not enough space on the disk."
        self._overlay_dirs.add(key)
        return None

    def delete(self, path: str) -> str | None:
        key = _norm(path)
        for name in list(self.created):
            if name.lower() == key.lower():
                del self.created[name]
                return None
        if self.read(key) is not None or self.exists_dir(key):
            return "Access is denied."
        return f"Could Not Find {key}"


# ── shell ────────────────────────────────────────────────────────────────────

_PROCESSES = (
    ("System Idle Process", 0, "Services", 0, "8 K"), ("System", 4, "Services", 0, "144 K"),
    ("smss.exe", 332, "Services", 0, "1,188 K"), ("csrss.exe", 424, "Services", 0, "4,524 K"),
    ("wininit.exe", 500, "Services", 0, "4,996 K"), ("csrss.exe", 508, "Console", 1, "4,064 K"),
    ("winlogon.exe", 568, "Console", 1, "9,128 K"), ("services.exe", 640, "Services", 0, "8,164 K"),
    ("lsass.exe", 652, "Services", 0, "15,632 K"), ("svchost.exe", 780, "Services", 0, "24,420 K"),
    ("dwm.exe", 912, "Console", 1, "35,644 K"), ("svchost.exe", 988, "Services", 0, "17,312 K"),
    ("spoolsv.exe", 1624, "Services", 0, "10,872 K"), ("MsMpEng.exe", 2144, "Services", 0, "142,008 K"),
    ("sihost.exe", 3108, "Console", 1, "19,744 K"), ("explorer.exe", 3844, "Console", 1, "58,216 K"),
    ("RuntimeBroker.exe", 4216, "Console", 1, "14,332 K"), ("rdpclip.exe", 4560, "RDP-Tcp#0", 2, "7,856 K"),
    ("cmd.exe", 5012, "RDP-Tcp#0", 2, "4,320 K"), ("conhost.exe", 5020, "RDP-Tcp#0", 2, "11,416 K"),
    ("tasklist.exe", 5340, "RDP-Tcp#0", 2, "8,092 K"),
)  # fmt: skip
_PROTECTED = {
    "msmpeng.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "system",
    "wininit.exe",
}

_KNOWN_QUIET = {
    "attrib", "chkdsk", "cipher", "color", "compact", "driverquery", "fc", "findstr", "icacls", "label",
    "mode", "more", "openfiles", "pause", "path", "pushd", "popd", "sort", "start", "time", "title",
    "tree", "vol", "where", "xcopy", "robocopy", "wevtutil", "gpupdate", "klist", "nbtstat", "pathping",
    "takeown", "tzutil", "mstsc", "mshta", "rundll32", "regsvr32", "cscript", "wscript", "msiexec",
    "bcdedit", "vssadmin", "wbadmin", "cmdkey", "fsutil", "gpresult", "prompt", "tskill", "mountvol",
    "subst", "diskpart", "dism", "sfc", "fltmc", "setx", "ftype", "pnputil", "typeperf", "auditpol",
    "net1", "logman", "manage-bde", "reagentc", "cacls", "msg", "mklink", "expand", "makecab",
    "eventcreate", "forfiles", "runas", "explorer", "notepad", "calc", "mspaint", "taskmgr",
}  # fmt: skip


class Shell:
    def __init__(self, identity: Identity, kind: str = "cmd") -> None:
        self.id = identity
        self.kind = kind  # "cmd" | "powershell"
        self.fs = FileSystem(identity)
        self.cwd = f"C:\\Users\\{identity.user}"
        self.users = ["Administrator", "DefaultAccount", "Guest", "WDAGUtilityAccount"]
        if identity.user not in self.users:
            self.users.insert(1, identity.user)
        self._seed = _h("shell", identity.computer)
        self._nested = False  # PowerShell entered from cmd (exit returns), not opened directly
        self._cmd_depth = 0  # `cmd` run inside cmd: exit returns to the outer one

    # ── presentation ─────────────────────────────────────────────────────────

    def _product(self) -> tuple[str, str]:
        """(product name, copyright line) matching the Windows build the honeypot reports over
        NLA and to nmap, so the console never disagrees with them."""
        return _PRODUCTS.get(self.id.build[2], _PRODUCTS[17763])

    def prompt(self) -> str:
        return f"PS {self.cwd}> " if self.kind == "powershell" else f"{self.cwd}>"

    def banner(self) -> list[str]:
        major, minor, build = self.id.build
        if self.kind == "powershell":
            return [
                "Windows PowerShell",
                "Copyright (C) Microsoft Corporation. All rights reserved.",
                "",
                "Try the new cross-platform PowerShell https://aka.ms/pscore6",
                "",
            ]
        return [
            f"Microsoft Windows [Version {major}.{minor}.{build}.{self._seed % 3000 + 100}]",
            self._product()[1],
            "",
        ]

    def _ip(self, host: int = 0) -> str:
        return f"10.{self._seed % 200 + 10}.{(self._seed >> 8) % 250 + 1}.{(self._seed >> 16) % 200 + 20 + host}"

    # ── execution ────────────────────────────────────────────────────────────

    def execute(self, line: str) -> Result:
        line = line.strip()[:1000]
        if not line:
            return Result()
        result = self._run(line)
        result.lines = [ln[:MAX_LINE_CHARS] for ln in result.lines[:MAX_OUTPUT_LINES]]
        return result

    def _run(self, line: str) -> Result:
        # Redirection of `echo` to a file is the one write the visitor can read back.
        redirect = re.match(
            r"^(?P<cmd>echo\b.*?)(?P<gap>\s*)(?P<op>>>|>)\s*(?P<path>[^<>|]+?)\s*$", line, re.I
        )
        if redirect:
            inner = self._run(redirect["cmd"])
            # cmd.exe keeps the space before the `>` and ends the line with CRLF.
            body = "\r\n".join(inner.lines) + redirect["gap"][:1] + "\r\n"
            error = self.fs.write(
                self._abs(redirect["path"].strip('"')), body, append=redirect["op"] == ">>"
            )
            return Result([error] if error else [])

        # The command word runs up to the first character that cannot be part of a name, so
        # `cd..`, `cd\\`, `dir/w`, `ipconfig/all` and `echo.` work as they do in cmd.exe.
        match = re.match(r"([A-Za-z0-9_$-]+)(?:\.(?:exe|com)(?![A-Za-z0-9]))?", line)
        if match:
            word, tail = match[1], line[match.end() :]
        else:
            word, _, tail = line.partition(" ")
        name = word.lower()
        rest = tail.strip()
        if name == "echo" and tail.startswith("."):
            return Result([tail[1:].strip()])  # `echo.` prints a blank line
        if re.fullmatch(r"[A-Za-z]:\\?", line.strip()):  # `d:` changes drive
            return self._c_cd(line.strip().rstrip("\\") + "\\")
        if self.kind == "powershell":
            out = self._powershell(name, rest, line)
            if out is not None:
                return out
        if name in ("powershell", "pwsh") and rest:
            return self._c_powershell(rest)  # runs the command in PowerShell, whose errors differ
        if looks_like_download(line):
            return self._download(name, rest, line)
        handler = getattr(self, f"_c_{name.replace('-', '_')}", None)
        if handler is not None:
            return handler(rest)
        if name in _KNOWN_QUIET:
            return Result()
        if self.kind == "powershell":
            return Result(
                [
                    f"{word} : The term '{word}' is not recognized as the name of a cmdlet, function, script file, or operable program. "
                    "Check the spelling of the name, or if a path was included, verify that the path is correct and try again.",
                    "At line:1 char:1",
                    f"+ {line[:60]}",
                    "+ " + "~" * min(len(word), 60),
                    f"    + CategoryInfo          : ObjectNotFound: ({word}:String) [], CommandNotFoundException",
                    "    + FullyQualifiedErrorId : CommandNotFoundException",
                    "",
                ]
            )
        return Result(
            [
                f"'{word}' is not recognized as an internal or external command,",
                "operable program or batch file.",
                "",
            ]
        )

    def _abs(self, path: str) -> str:
        path = path.strip().strip('"')
        if len(path) >= 2 and path[1] == ":":
            return _norm(path)
        if path.startswith(("\\", "/")):  # rooted: the root of the current drive
            return _norm("C:" + path)
        return _norm(f"{self.cwd}\\{path}")

    # ── downloads: refused the way a machine with no route out refuses ───────

    def _download(self, name: str, rest: str, line: str) -> Result:
        """This machine has no route out: a name does not resolve, an address does not answer."""
        urls = extract_urls(line)
        target = re.sub(r"^\w+://", "", urls[0]).split("/")[0] if urls else "host"
        host, _, port = target.partition(":")
        port = port or ("443" if urls and urls[0].lower().startswith("https") else "80")
        is_ip = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is not None
        if self.kind == "powershell":
            reason = (
                "Unable to connect to the remote server"
                if is_ip
                else f"The remote name could not be resolved: '{host}'"
            )
            return Result(
                [
                    f"{name} : {reason}",
                    "At line:1 char:1",
                    f"+ {line[:60]}",
                    "+ " + "~" * min(len(line), 60),
                    "    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException",
                    "    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand",
                    "",
                ]
            )
        if name == "curl":
            if is_ip:
                return Result(
                    [
                        f"curl: (28) Failed to connect to {host} port {port} after 21045 ms: Timed out"
                    ]
                )
            return Result([f"curl: (6) Could not resolve host: {host}"])
        if name == "certutil":
            code = (
                "0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)"
                if is_ip
                else "0x80072ee7 (WinHttp: 12007 ERROR_WINHTTP_NAME_NOT_RESOLVED)"
            )
            return Result(["****  Online  ****", f"CertUtil: -URLCache command FAILED: {code}",
                           "CertUtil: The operation timed out" if is_ip else "CertUtil: The server name or address could not be resolved"])  # fmt: skip
        if name == "bitsadmin":
            return Result(
                [
                    "BITSADMIN version 3.0",
                    "BITS 7.8.",
                    "",
                    "Unable to complete transfer - 0x80072ee2"
                    if is_ip
                    else "Unable to complete transfer - 0x80072ee7",
                    "",
                ]
            )
        return Result([f"{name}: unable to {'connect to' if is_ip else 'resolve'} '{host}'"])

    # ── cmd.exe commands ─────────────────────────────────────────────────────

    def _c_help(self, _: str) -> Result:
        return Result(
            ["For more information on a specific command, type HELP command-name",
             "ASSOC          Displays or modifies file extension associations.",
             "CD             Displays the name of or changes the current directory.",
             "CLS            Clears the screen.", "COPY           Copies one or more files to another location.",
             "DATE           Displays or sets the date.", "DEL            Deletes one or more files.",
             "DIR            Displays a list of files and subdirectories in a directory.",
             "ECHO           Displays messages, or turns command echoing on or off.",
             "EXIT           Quits the CMD.EXE program (command interpreter).",
             "HOSTNAME       Prints the name of the current host.",
             "IPCONFIG       Displays IP configuration.", "MKDIR          Creates a directory.",
             "NET            Manages users, groups and shares.", "TASKLIST       Lists running processes.",
             "TYPE           Displays the contents of a text file.", "VER            Displays the Windows version.",
             "WHOAMI         Displays user, group and privilege information.", ""]
        )  # fmt: skip

    def _c_cls(self, _: str) -> Result:
        return Result(clear=True)

    def _c_exit(self, _: str) -> Result:
        if self._cmd_depth:
            self._cmd_depth -= 1
            return Result()
        if self.kind == "powershell" and self._nested:
            self.kind, self._nested = "cmd", False
            return Result()
        return Result(exit=True)

    def _c_cmd(self, rest: str) -> Result:
        """`cmd` starts a nested interpreter; `cmd /c text` runs `text` and returns."""
        match = re.search(r"(?i)(?:^|\s)/[ck]\s+(.*)$", rest)
        if match:
            command = match[1].strip()
            if len(command) >= 2 and command[0] == command[-1] == '"':
                command = command[1:-1]
            result = self._run(command) if command else Result()
            result.exit = result.clear = False  # the child ended; this window did not
            return result
        self._cmd_depth += 1
        return Result(self.banner() if self.kind == "cmd" else [])

    def _c_echo(self, rest: str) -> Result:
        if rest.lower() in ("on", "off"):
            return Result()
        return Result([rest.strip('"') if rest else "ECHO is on."])

    def _c_ver(self, _: str) -> Result:
        major, minor, build = self.id.build
        return Result(
            ["", f"Microsoft Windows [Version {major}.{minor}.{build}.{self._seed % 3000 + 100}]"]
        )

    def _c_hostname(self, _: str) -> Result:
        return Result([self.id.computer])

    def _c_whoami(self, rest: str) -> Result:
        who = f"{self.id.domain.lower()}\\{self.id.user.lower()}"
        flag = rest.lower()
        if flag in ("", "/user"):
            if not flag:
                return Result([who])
            return Result(["", "USER INFORMATION", "----------------", "", "User Name".ljust(25) + "SID",
                           "=" * 24 + " " + "=" * 45, who.ljust(25) + f"S-1-5-21-{self._seed % 10**9}-{self._seed % 10**8}-{self._seed % 10**7}-500"])  # fmt: skip
        if flag == "/priv":
            rows = [("SeIncreaseQuotaPrivilege", "Adjust memory quotas for a process", "Disabled"),
                    ("SeSecurityPrivilege", "Manage auditing and security log", "Disabled"),
                    ("SeTakeOwnershipPrivilege", "Take ownership of files or other objects", "Disabled"),
                    ("SeLoadDriverPrivilege", "Load and unload device drivers", "Disabled"),
                    ("SeDebugPrivilege", "Debug programs", "Enabled"),
                    ("SeImpersonatePrivilege", "Impersonate a client after authentication", "Enabled"),
                    ("SeChangeNotifyPrivilege", "Bypass traverse checking", "Enabled")]  # fmt: skip
            return Result(["", "PRIVILEGES INFORMATION", "----------------------", "",
                           "Privilege Name".ljust(32) + "Description".ljust(45) + "State",
                           "=" * 31 + " " + "=" * 44 + " " + "=" * 8,
                           *[a.ljust(32) + b.ljust(45) + c for a, b, c in rows]])  # fmt: skip
        if flag in ("/groups", "/all"):
            groups = [("Everyone", "Well-known group", "S-1-1-0"), ("BUILTIN\\Administrators", "Alias", "S-1-5-32-544"),
                      ("BUILTIN\\Remote Desktop Users", "Alias", "S-1-5-32-555"), ("NT AUTHORITY\\INTERACTIVE", "Well-known group", "S-1-5-4"),
                      ("NT AUTHORITY\\Authenticated Users", "Well-known group", "S-1-5-11")]  # fmt: skip
            out = ["", "GROUP INFORMATION", "-----------------", "", "Group Name".ljust(40) + "Type".ljust(20) + "SID",
                   "=" * 39 + " " + "=" * 19 + " " + "=" * 12,
                   *[a.ljust(40) + b.ljust(20) + c for a, b, c in groups]]  # fmt: skip
            return Result(out)
        return Result(
            ["ERROR: Invalid argument/option - '" + rest[:20] + "'.", 'Type "WHOAMI /?" for usage.']
        )

    def _c_ipconfig(self, rest: str) -> Result:
        full = "/all" in rest.lower()
        out = ["", "Windows IP Configuration", ""]
        if full:
            out += [f"   Host Name . . . . . . . . . . . . : {self.id.computer}",
                    f"   Primary Dns Suffix  . . . . . . . : {self.id.domain.lower()}.local",
                    "   Node Type . . . . . . . . . . . . : Hybrid", "   IP Routing Enabled. . . . . . . . : No", ""]  # fmt: skip
        out += ["Ethernet adapter Ethernet0:", "",
                f"   Connection-specific DNS Suffix  . : {self.id.domain.lower()}.local"]  # fmt: skip
        if full:
            mac = "00-0C-29-" + "-".join(f"{(self._seed >> (8 * i)) & 0xFF:02X}" for i in range(3))
            out += ["   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection",
                    f"   Physical Address. . . . . . . . . : {mac}", "   DHCP Enabled. . . . . . . . . . . : No"]  # fmt: skip
        out += [f"   IPv4 Address. . . . . . . . . . . : {self._ip()}", "   Subnet Mask . . . . . . . . . . . : 255.255.255.0",
                f"   Default Gateway . . . . . . . . . : {self._ip(-19)}", ""]  # fmt: skip
        return Result(out)

    def _c_systeminfo(self, _: str) -> Result:
        major, minor, build = self.id.build
        boot = datetime.now(UTC) - timedelta(days=self._seed % 40 + 3, hours=self._seed % 20)
        rows = [("Host Name", self.id.computer), ("OS Name", "Microsoft " + self._product()[0]),
                ("OS Version", f"{major}.{minor}.{build} N/A Build {build}"), ("OS Manufacturer", "Microsoft Corporation"),
                ("OS Configuration", "Member Server"), ("OS Build Type", "Multiprocessor Free"),
                ("Registered Owner", "Windows User"), ("Product ID", f"00429-70000-00000-AA{self._seed % 900 + 100}"),
                ("Original Install Date", "3/19/2019, 4:03:11 AM"), ("System Boot Time", _us_datetime(boot)),
                ("System Manufacturer", "VMware, Inc."), ("System Model", "VMware7,1"), ("System Type", "x64-based PC"),
                ("Processor(s)", "2 Processor(s) Installed."), ("BIOS Version", "VMware, Inc. VMW71.00V.16221537.B64.2005150253, 5/15/2020"),
                ("Windows Directory", "C:\\Windows"), ("System Directory", "C:\\Windows\\system32"),
                ("Total Physical Memory", "8,191 MB"), ("Available Physical Memory", f"{self._seed % 3000 + 3000:,} MB"),
                ("Domain", f"{self.id.domain.lower()}.local"), ("Logon Server", f"\\\\{self.id.computer}"),
                ("Hotfix(s)", "4 Hotfix(s) Installed."), ("Network Card(s)", "1 NIC(s) Installed.")]  # fmt: skip
        return Result([f"{k}:".ljust(27) + v for k, v in rows])

    def _c_net(self, rest: str) -> Result:
        words = rest.split()
        sub = words[0].lower() if words else ""
        if sub in ("user", "users"):
            if len(words) >= 3 and "/add" in rest.lower():
                new = words[1]
                if (
                    re.fullmatch(r"[\w.-]{1,20}", new)
                    and len(self.users) < MAX_USERS
                    and new not in self.users
                ):
                    self.users.append(new)
                return Result(["The command completed successfully.", ""])
            if len(words) >= 2 and not words[1].startswith("/"):
                if words[1].lower() not in (u.lower() for u in self.users):
                    return Result(
                        [
                            "The user name could not be found.",
                            "",
                            "More help is available by typing NET HELPMSG 2221.",
                            "",
                        ]
                    )
                return Result(["User name".ljust(30) + words[1], "Full Name".ljust(30), "Comment".ljust(30),
                               "Account active".ljust(30) + "Yes", "Password last set".ljust(30) + "3/19/2019 4:09:27 AM",
                               "Password expires".ljust(30) + "Never", "Local Group Memberships".ljust(30) + "*Administrators",
                               "Global Group memberships".ljust(30) + "*None", "The command completed successfully.", ""])  # fmt: skip
            width = 25
            rows = [u.ljust(width) for u in self.users]
            body = [" ".join(rows[i : i + 3]) for i in range(0, len(rows), 3)]
            return Result(["", f"User accounts for \\\\{self.id.computer}", "", "-" * 75, *body,
                           "The command completed successfully.", ""])  # fmt: skip
        if sub == "localgroup":
            group = " ".join(words[1:]).lower()
            if group.startswith("administrators"):
                if "/add" in group:
                    return Result(["The command completed successfully.", ""])
                return Result(["Alias name     Administrators", "Comment        Administrators have complete and unrestricted access to the computer/domain",
                               "", "Members", "", "-" * 79, "Administrator", f"{self.id.domain}\\Domain Admins", self.id.user if self.id.user != "Administrator" else "",
                               "The command completed successfully.", ""])  # fmt: skip
            return Result(["", f"Aliases for \\\\{self.id.computer}", "", "-" * 75, "*Access Control Assistance Operators", "*Administrators",
                           "*Remote Desktop Users", "*Users", "The command completed successfully.", ""])  # fmt: skip
        if sub == "view":
            return Result(["There are no entries in the list.", ""])
        if sub == "share":
            return Result(["Share name   Resource                        Remark", "", "-" * 78, "C$           C:\\                             Default share",
                           "IPC$                                        Remote IPC", "ADMIN$       C:\\Windows                     Remote Admin",
                           "The command completed successfully.", ""])  # fmt: skip
        if sub in ("stop", "start") and len(words) > 1:
            return Result(["System error 5 has occurred.", "", "Access is denied.", ""])
        return Result(["The syntax of this command is:", "", "NET", "    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |",
                       "      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |", "      STATISTICS | STOP | TIME | USE | USER | VIEW ]", ""])  # fmt: skip

    def _c_tasklist(self, _: str) -> Result:
        head = [
            "",
            "Image Name".ljust(26) + "PID Session Name".ljust(20) + "Session#    Mem Usage",
            "=" * 25 + " ======== ================ =========== ============",
        ]
        rows = [f"{n:<26}{pid:>8} {s:<16} {sn:>11} {m:>12}" for n, pid, s, sn, m in _PROCESSES]
        return Result(head + rows)

    def _c_taskkill(self, rest: str) -> Result:
        match = re.search(r"/im\s+(\S+)", rest, re.I)
        pid = re.search(r"/pid\s+(\d+)", rest, re.I)
        for n, p, *_ in _PROCESSES:
            if (match and match[1].lower() == n.lower()) or (pid and int(pid[1]) == p):
                if n.lower() in _PROTECTED:
                    return Result(
                        [
                            f'ERROR: The process "{n}" with PID {p} could not be terminated.',
                            "Reason: Access is denied.",
                        ]
                    )
                return Result([f'SUCCESS: The process "{n}" with PID {p} has been terminated.'])
        target = match[1] if match else (pid[1] if pid else "")
        return Result(
            [
                f'ERROR: The process "{target}" not found.'
                if target
                else 'ERROR: Invalid syntax. Type "TASKKILL /?" for usage.'
            ]
        )

    def _c_netstat(self, _: str) -> Result:
        ip = self._ip()
        listening = [
            ("0.0.0.0:135", 780),
            ("0.0.0.0:445", 4),
            ("0.0.0.0:3389", 988),
            ("0.0.0.0:5985", 4),
            ("0.0.0.0:49664", 500),
        ]
        rows = [f"  TCP    {a:<23}{'0.0.0.0:0':<23}{'LISTENING':<16}{p}" for a, p in listening]
        rows.append(
            f"  TCP    {ip + ':3389':<23}{self.id.peer_ip + ':51873':<23}{'ESTABLISHED':<16}988"
        )
        return Result(
            [
                "",
                "Active Connections",
                "",
                "  Proto  Local Address          Foreign Address        State           PID",
                *rows,
                "",
            ]
        )

    def _c_query(self, rest: str) -> Result:
        if rest.lower().startswith("user"):
            return self._c_quser("")
        return Result(["Invalid parameter(s)"])

    def _c_quser(self, _: str) -> Result:
        now = datetime.now(UTC)
        when = f"{now.month}/{now.day}/{now.year} {now.hour % 12 or 12}:{now:%M} {'AM' if now.hour < 12 else 'PM'}"
        return Result([" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME",
                       f">{self.id.user.lower():<21} rdp-tcp#0           2  Active          .  {when}"])  # fmt: skip

    def _c_arp(self, _: str) -> Result:
        return Result(["", f"Interface: {self._ip()} --- 0x5", "  Internet Address      Physical Address      Type",
                       f"  {self._ip(-19)}".ljust(24) + "00-50-56-a3-1c-02     dynamic", "  224.0.0.22".ljust(24) + "01-00-5e-00-00-16     static", ""])  # fmt: skip

    def _c_sc(self, rest: str) -> Result:
        if rest.lower().startswith("query"):
            return Result(["", "SERVICE_NAME: Dnscache", "DISPLAY_NAME: DNS Client", "        TYPE               : 20  WIN32_SHARE_PROCESS",
                           "        STATE              : 4  RUNNING", "", "SERVICE_NAME: Spooler", "DISPLAY_NAME: Print Spooler",
                           "        STATE              : 4  RUNNING", ""])  # fmt: skip
        return Result(["[SC] OpenService FAILED 5:", "", "Access is denied.", ""])

    def _c_reg(self, _: str) -> Result:
        return Result(["ERROR: The system was unable to find the specified registry key or value."])

    def _c_schtasks(self, _: str) -> Result:
        return Result(
            ["INFO: There are no scheduled tasks presently available at your access level."]
        )

    def _c_wmic(self, rest: str) -> Result:
        low = rest.lower()
        if "os get caption" in low:
            return Result(["Caption", "Microsoft " + self._product()[0], ""])
        if "cpu get name" in low:
            return Result(["Name", "Intel(R) Xeon(R) Silver 4214 CPU @ 2.20GHz", ""])
        return Result(["Invalid GET Expression."])

    def _c_nslookup(self, rest: str) -> Result:
        target = rest.split()[0] if rest.split() else ""
        return Result(["Server:  UnKnown", f"Address:  {self._ip(-19)}", "", "DNS request timed out.", "    timeout was 2 seconds.",
                       "*** Request to UnKnown timed-out" if target else ""])  # fmt: skip

    def _c_tracert(self, rest: str) -> Result:
        host = rest.split()[-1] if rest.split() else ""
        return Result(["", f"Tracing route to {host} over a maximum of 30 hops", "", "  1     *        *        *     Request timed out.",
                       "  2     *        *        *     Request timed out.", "", "Trace complete."])  # fmt: skip

    def _c_ping(self, rest: str) -> Result:
        """No packet is ever sent. This machine answers for itself (localhost, 127.x, its own
        name and address, which every Windows host does) and has no route to anywhere else: a
        name does not resolve and an address does not answer. Answering for outside addresses
        would be a lie the visitor can check against `curl`, which fails the same way."""
        targets = [w for w in rest.split() if not w.startswith(("-", "/"))]
        host = targets[-1] if targets else ""
        if not host:
            return Result(["", "Usage: ping [-t] [-a] [-n count] [-l size] target_name", ""])
        lowered = host.lower()
        own = self._ip()
        if lowered == "localhost" or lowered == self.id.computer.lower():
            shown, reply = (
                (f"{self.id.computer} [::1]", "::1")
                if lowered == "localhost"
                else (f"{self.id.computer} [{own}]", own)
            )
            return self._ping_replies(shown, reply, host)
        if re.fullmatch(r"127(\.\d{1,3}){3}", host) or host == own:
            return self._ping_replies(host, host, host)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) is None:
            return Result(
                [
                    "",
                    f"Ping request could not find host {host[:60]}. Please check the name and try again.",
                ]
            )
        return Result(["", f"Pinging {host} with 32 bytes of data:", *["Request timed out."] * 4, "",
                       f"Ping statistics for {host}:", "    Packets: Sent = 4, Received = 0, Lost = 4 (100% loss),"])  # fmt: skip

    @staticmethod
    def _ping_replies(shown: str, reply: str, stats_host: str) -> Result:
        return Result(["", f"Pinging {shown} with 32 bytes of data:",
                       *[f"Reply from {reply}: " + ("time<1ms" if ":" in reply else "bytes=32 time<1ms TTL=128") for _ in range(4)],
                       "", f"Ping statistics for {reply}:", "    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),",
                       "Approximate round trip times in milli-seconds:", "    Minimum = 0ms, Maximum = 0ms, Average = 0ms"])  # fmt: skip

    def _c_rmdir(self, rest: str) -> Result:
        targets = [a for a in _args(rest) if not a.startswith("/")]
        error = (
            self.fs.remove_dir(self._abs(targets[0]))
            if targets
            else "The syntax of the command is incorrect."
        )
        return Result([error] if error else [])

    _c_rd = _c_rmdir

    def _c_ren(self, rest: str) -> Result:
        parts = [a for a in _args(rest) if not a.startswith("/")]
        if len(parts) < 2:
            return Result(["The syntax of the command is incorrect."])
        target = (
            parts[1]
            if ("\\" in parts[1] or ":" in parts[1])
            else f"{self._abs(parts[0]).rsplit(chr(92), 1)[0]}\\{parts[1]}"
        )
        error = self.fs.move(self._abs(parts[0]), target)
        return Result([error] if error else [])

    _c_rename = _c_ren

    def _c_move(self, rest: str) -> Result:
        parts = [a for a in _args(rest) if not a.startswith("/")]
        if len(parts) < 2:
            return Result(["The syntax of the command is incorrect."])
        error = self.fs.move(self._abs(parts[0]), self._abs(parts[1]))
        return Result([error] if error else ["        1 file(s) moved."])

    def _c_assoc(self, rest: str) -> Result:
        table = {
            ".txt": "txtfile",
            ".exe": "exefile",
            ".bat": "batfile",
            ".cmd": "cmdfile",
            ".ps1": "Microsoft.PowerShellScript.1",
            ".log": "txtfile",
            ".dll": "dllfile",
        }
        if not rest:
            return Result([f"{k}={v}" for k, v in sorted(table.items())])
        key = rest.split("=")[0].lower()
        return Result(
            [f"{key}={table[key]}"]
            if key in table
            else [f"File association not found for extension {key}"]
        )

    def _c_find(self, rest: str) -> Result:
        args = _args(rest)
        flags = {a.lower() for a in args if a.startswith("/")}
        words = [a for a in args if not a.startswith("/")]
        if not words:
            return Result(["FIND: Parameter format not correct"])
        needle, files = words[0], words[1:]
        out: list[str] = []
        for name in files:
            content = self.fs.read(self._abs(name))
            if content is None:
                out.append(f"File not found - {name.upper()}")
                continue
            out += ["", f"---------- {name.upper()}"]
            out += [
                ln
                for ln in content.split("\r\n")
                if (needle.lower() in ln.lower() if "/i" in flags else needle in ln)
            ]
        return Result(out)

    def _c_findstr(self, rest: str) -> Result:
        words = [a for a in _args(rest) if not a.startswith("/")]
        if len(words) < 2:
            return Result()
        out = []
        for name in words[1:]:
            content = self.fs.read(self._abs(name))
            if content is None:
                out.append(f"FINDSTR: Cannot open {name}")
            else:
                out += [ln for ln in content.split("\r\n") if words[0].lower() in ln.lower()]
        return Result(out)

    def _c_shutdown(self, rest: str) -> Result:
        flags = rest.lower().split()
        if any(f in ("/l",) for f in flags) or any(f in ("/r", "/s", "/p", "/h") for f in flags):
            return Result(disconnect=True)  # the machine goes away and takes the session with it
        if "/a" in flags:
            return Result(
                ["Unable to abort the system shutdown because no shutdown was in progress.(1116)"]
            )
        return Result(
            [
                "Usage: shutdown [/i | /l | /s | /sg | /r | /g | /a | /p | /h | /e | /o] [/hybrid] [/soft] [/fw] [/f]",
                '    [/m \\\\computer][/t xxx][/d [p|u:]xx:yy [/c "comment"]]',
            ]
        )

    def _c_logoff(self, _: str) -> Result:
        return Result(disconnect=True)

    def _c_route(self, rest: str) -> Result:
        if rest.lower().startswith("print"):
            gw = self._ip(-19)
            return Result(["=" * 75, "Interface List", "  5...00 0c 29 aa bb cc ......Intel(R) 82574L Gigabit Network Connection", "  1...........................Software Loopback Interface 1", "=" * 75, "",
                           "IPv4 Route Table", "=" * 75, "Active Routes:", "Network Destination        Netmask          Gateway       Interface  Metric",
                           f"          0.0.0.0          0.0.0.0{gw:>16}{self._ip():>16}     281", "        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331", "=" * 75])  # fmt: skip
        return Result()

    def _c_getmac(self, _: str) -> Result:
        mac = "00-0C-29-" + "-".join(f"{(self._seed >> (8 * i)) & 0xFF:02X}" for i in range(3))
        return Result(
            [
                "",
                "Physical Address    Transport Name",
                "=================== ==========================================================",
                f"{mac}   \\Device\\Tcpip_{{{self._seed % 10**8:08X}-0000-4000-8000-000C29AABBCC}}",
            ]
        )

    def _c_netsh(self, rest: str) -> Result:
        low = rest.lower()
        if "advfirewall" in low and any(w in low for w in ("set", "add", "delete")):
            return Result(["Ok.", ""])
        if "advfirewall" in low and "show" in low:
            return Result(
                [
                    "",
                    "Domain Profile Settings:",
                    "-" * 55,
                    "State                                 ON",
                    "Firewall Policy                       BlockInbound,AllowOutbound",
                    "",
                ]
            )
        return Result()

    def _c_cd(self, rest: str) -> Result:
        rest = rest.strip()
        if not rest or rest == "/d":
            return Result([self.cwd])
        target = rest[3:].strip() if rest.lower().startswith("/d ") else rest
        path = self._abs(target)
        if self.fs.exists_dir(path):
            self.cwd = self.fs._key(path)
            return Result()
        return Result(["The system cannot find the path specified."])

    _c_chdir = _c_cd

    def _c_dir(self, rest: str) -> Result:
        args = [a for a in _args(rest) if not a.startswith("/")]
        path = self._abs(args[0]) if args else self.cwd
        entries = self.fs.listing(path)
        if entries is None:
            return Result([" Volume in drive C has no label.", f" Volume Serial Number is {self._seed % 0xFFFF:04X}-{(self._seed >> 16) % 0xFFFF:04X}",
                           "", f" Directory of {_norm(path)}", "", "File Not Found"])  # fmt: skip
        stamp = datetime(2019, 3, 19, 4, 3)
        dots = (
            [Entry(".", True, when=stamp), Entry("..", True, when=stamp)]
            if len(_norm(path)) > 3
            else []
        )
        rows = [
            f"{e.when.strftime('%m/%d/%Y  %I:%M %p')}"
            + (f"{'    <DIR>':<18} " if e.is_dir else f"{format(e.size, ','):>18} ")
            + e.name
            for e in (*dots, *entries)
        ]
        files = [e for e in entries if not e.is_dir]
        dirs = [e for e in entries if e.is_dir] + dots
        free = 40_000_000_000 + self._seed % 9_000_000_000
        return Result([" Volume in drive C has no label.", f" Volume Serial Number is {self._seed % 0xFFFF:04X}-{(self._seed >> 16) % 0xFFFF:04X}",
                       "", f" Directory of {_norm(path).rstrip(chr(92)) if len(_norm(path)) > 3 else _norm(path)}", "", *rows,
                       f"{len(files):>16} File(s) {sum(e.size for e in files):>14,} bytes", f"{len(dirs):>16} Dir(s)  {free:>14,} bytes free"])  # fmt: skip

    def _c_type(self, rest: str) -> Result:
        content = self.fs.read(self._abs(rest)) if rest else None
        if content is None:
            return Result(
                ["The system cannot find the file specified."]
                if rest
                else ["The syntax of the command is incorrect."]
            )
        lines = content.split("\r\n")
        if lines and lines[-1] == "":
            lines.pop()  # the file's final line break ends its last line; it is not a blank line
        return Result(lines)

    def _c_mkdir(self, rest: str) -> Result:
        error = (
            self.fs.make_dir(self._abs(rest)) if rest else "The syntax of the command is incorrect."
        )
        return Result([error] if error else [])

    _c_md = _c_mkdir

    def _c_del(self, rest: str) -> Result:
        targets = [a for a in _args(rest) if not a.startswith("/")]
        if not targets:
            return Result(["The syntax of the command is incorrect."])
        error = self.fs.delete(self._abs(targets[0]))
        return Result([error] if error else [])

    _c_erase = _c_del

    def _c_copy(self, rest: str) -> Result:
        parts = [a for a in _args(rest) if not a.startswith("/")]
        if len(parts) < 2:
            return Result(["The syntax of the command is incorrect."])
        content = self.fs.read(self._abs(parts[0]))
        if content is None:
            return Result(["The system cannot find the file specified."])
        error = self.fs.write(self._abs(parts[1]), content)
        return Result([error] if error else ["        1 file(s) copied."])

    def _c_set(self, rest: str) -> Result:
        if rest:
            return Result()
        return Result([f"COMPUTERNAME={self.id.computer}", f"USERDOMAIN={self.id.domain}", f"USERNAME={self.id.user}",
                       f"USERPROFILE=C:\\Users\\{self.id.user}", "OS=Windows_NT", "SystemRoot=C:\\Windows",
                       "PROCESSOR_ARCHITECTURE=AMD64", "TEMP=C:\\Users\\" + self.id.user + "\\AppData\\Local\\Temp"])  # fmt: skip

    _PS_VALUE_FLAGS = frozenset(
        [
            "-w",
            "-windowstyle",
            "-ep",
            "-executionpolicy",
            "-version",
            "-v",
            "-inputformat",
            "-outputformat",
            "-psconsolefile",
            "-configurationname",
            "-workingdirectory",
            "-wd",
        ]
    )

    def _c_powershell(self, rest: str) -> Result:
        if rest:
            command, silent = self._ps_command(rest)
            if silent or not command:
                return Result()  # -EncodedCommand / -File: runs something we cannot show
            previous, self.kind = self.kind, "powershell"
            try:
                result = self._run(command)
            finally:
                self.kind = previous
            result.exit = result.clear = False  # the child ended; this window did not
            return result
        self.kind, self._nested = "powershell", True
        return Result(self.banner())

    def _ps_command(self, rest: str) -> tuple[str, bool]:
        """(command text, runs-something-unseen) from powershell's own command line: flags
        that take a value consume it, `-Command` takes everything after it."""
        tokens = [(m[0], m.start()) for m in re.finditer(r'"[^"]*"|\S+', rest)]
        i = 0
        while i < len(tokens):
            token = tokens[i][0].lower()
            if token in ("-c", "-command", "-cmd"):
                command = rest[tokens[i + 1][1] :].strip() if i + 1 < len(tokens) else ""
                if len(command) >= 2 and command[0] == command[-1] == '"':
                    command = command[1:-1]
                return command, False
            if token in ("-e", "-ec", "-enc", "-encodedcommand", "-f", "-file"):
                return "", True
            if token in self._PS_VALUE_FLAGS:
                i += 2
            elif token.startswith("-"):
                i += 1
            else:
                return rest[tokens[i][1] :].strip(), False
        return "", False

    _c_pwsh = _c_powershell

    def _c_date(self, _: str) -> Result:
        return Result(
            [
                f"The current date is: {datetime.now(UTC).strftime('%a %m/%d/%Y')}",
                "Enter the new date: (mm-dd-yy)",
            ]
        )

    # ── PowerShell-only forms ────────────────────────────────────────────────

    def _powershell(self, name: str, rest: str, line: str) -> Result | None:
        if name in ("get-location", "pwd", "gl"):
            return Result(["", "Path", "----", self.cwd, ""])
        if name in ("set-location", "sl"):
            return self._c_cd(rest)
        if name in ("get-childitem", "gci", "ls", "dir"):
            return self._ps_listing(rest)
        if name in ("get-process", "ps", "gps"):
            rows = []
            for n, pid, _session, si, mem in _PROCESSES[2:]:
                ws = n_mem(mem)
                handles = _h("handles", n, str(pid)) % 900 + 90
                rows.append(
                    f"{handles:>7} {_h('npm', n) % 18 + 4:>6} {ws * 3 // 5:>8} {ws:>10} {pid:>6} {si:>3} {n.removesuffix('.exe')}"
                )
            return Result(
                [
                    "",
                    "Handles  NPM(K)    PM(K)      WS(K)     Id  SI ProcessName",
                    "-------  ------    -----      -----     --  -- -----------",
                    *rows,
                    "",
                ]
            )
        if name in ("get-date",):
            return Result(["", datetime.now(UTC).strftime("%A, %B %d, %Y %I:%M:%S %p"), ""])
        if name == "get-localuser":
            return Result(["", "Name                Enabled Description", "----                ------- -----------",
                           *[f"{u:<20}{'True' if u != 'Guest' else 'False':<8}" for u in self.users], ""])  # fmt: skip
        if name == "get-content" or name in ("cat", "gc"):
            return self._c_type(rest)
        if name == "$psversiontable" or line.lower().startswith("$psversiontable"):
            return Result(["", "Name                           Value", "----                           -----", f"PSVersion                      5.1.{self.id.build[2]}.{self._seed % 4000 + 1000}",
                           "PSEdition                      Desktop", f"BuildVersion                   10.0.{self.id.build[2]}.{self._seed % 4000 + 1000}", "CLRVersion                     4.0.30319.42000", ""])  # fmt: skip
        if name in ("get-service", "gsv"):
            return Result(["", "Status   Name               DisplayName", "------   ----               -----------",
                           "Running  Dnscache           DNS Client", "Running  EventLog           Windows Event Log", "Running  Spooler            Print Spooler", ""])  # fmt: skip
        if name in ("get-hotfix",):
            return Result(["", "Source        Description      HotFixID      InstalledBy          InstalledOn", "------        -----------      --------      -----------          -----------",
                           f"{self.id.computer:<14}Security Update  KB5034127     NT AUTHORITY\\SYSTEM  1/12/2024 12:00:00 AM", ""])  # fmt: skip
        if name == "write-host" or name == "write-output":
            return Result([rest.strip("\"'")])
        if name in ("clear-host", "clear", "cls"):
            return Result(clear=True)
        return None

    def _ps_listing(self, rest: str) -> Result:
        named = [a for a in _args(rest) if not a.startswith("-")]
        path = self._abs(named[0]) if named else self.cwd
        entries = self.fs.listing(path)
        if entries is None:
            return Result(
                [
                    f"Get-ChildItem : Cannot find path '{path}' because it does not exist.",
                    "At line:1 char:1",
                    "+ Get-ChildItem",
                    "+ ~~~~~~~~~~~~~~",
                    "",
                ]
            )
        rows = [
            f"{'d-----' if e.is_dir else '-a----'}  {e.when.strftime('%m/%d/%Y  %I:%M %p')}  {'' if e.is_dir else e.size:>10} {e.name}"
            for e in entries
        ]
        return Result(["", f"    Directory: {_norm(path).rstrip(chr(92)) if len(_norm(path)) > 3 else _norm(path)}", "", "Mode                LastWriteTime         Length Name",
                       "----                -------------         ------ ----", *rows, ""])  # fmt: skip


def n_mem(text: str) -> int:
    digits = re.sub(r"[^\d]", "", text)
    return int(digits) if digits else 0
