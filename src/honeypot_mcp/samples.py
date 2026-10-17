"""Captured malware samples: a confined quarantine, YARA, and collection from Cowrie containers.

The honeypots capture files (wget/curl/tftp downloads, scp uploads, shell redirections) and
Cowrie keeps them, plus TTY recordings, in a tmpfs inside the container. `scripts/fetch_backup.sh
--samples` pulls them into a mode-000 quarantine directory; before this module nothing in the MCP
could read that directory. `scan()` hashes, types and runs YARA over what is in it, and `collect()`
fills it from running Cowrie containers.

Everything here follows from one fact: the files are live malware and the paths come from a model
that reads attacker-authored text.

* **Nothing is executed, ever.** Files are read into memory as bytes and handed to YARA as data.
  No scratch copy is written, so no second copy of malware exists on disk.
* **Confined.** `resolve_in_root` rejects `..`, absolute paths outside the quarantine, and any
  symlink component (a symlink that stays inside is refused too: a quarantine has no use for one).
  Directory walks never follow a link and only open regular files under a size cap.
* **Mode-000 files are read as their owner.** A file with no permission bits cannot be opened even
  by its owner, so `read_sample` grants the owner read for the instant it takes to open the file,
  puts the original mode back through the open descriptor (`fchmod`, not a path) and then reads
  through that descriptor; a `finally` restores it if the open itself fails. The content and the
  mode are unchanged afterwards (only ctime moves). A file owned by someone else is skipped, with
  that reason, rather than changed.
* **What is returned is a description, not the sample.** Hashes, sizes, a magic-byte type, YARA rule
  hits with rule-defined string identifiers and offsets, and at most one clipped (64 characters),
  printable-only excerpt per matched string.
* **A container is untrusted input.** `collect()` streams the tar `Container.get_archive` returns
  (what `docker cp` does) under byte and member caps, extracts nothing with `tarfile`, accepts
  only regular files directly inside `downloads/` or `tty/`, and writes each file itself, mode
  000, never over an existing one.

YARA comes from `yara-python` when it imports, otherwise from `yara-x` (the Rust implementation,
which ships abi3 wheels for every supported Python). Without either, every function degrades to
`{"available": False, "note": ...}`.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import importlib.metadata
import os
import queue
import re
import secrets
import stat
import struct
import tarfile
import threading
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from honeypot_mcp.config import get_settings
from honeypot_mcp.engines.cowrie_limits import COWRIE_STATE_DIRS
from honeypot_mcp.secure_io import ensure_private_dir, write_private_file

# ── Constants ───────────────────────────────────────────────────────────────

SEVERITIES = ("info", "low", "medium", "high")
_SEVERITY_RANK = {"unrated": -1, "info": 0, "low": 1, "medium": 2, "high": 3}

# Files `fetch_backup.sh` and `collect()` keep in the quarantine root that are not samples.
METADATA_FILES = frozenset({"README.txt", "SHA256SUMS"})
README_TEXT = (
    "LIVE MALWARE captured by the honeypots. Never execute, open or upload these files from a "
    "machine you care about. Files are named by SHA-256; see SHA256SUMS.\n"
)
PARTIAL_PREFIX = ".collect-"  # a file being written by `collect()`; never a sample

_MAX_WALK_DEPTH = 6
_WALK_COUNT_CEILING = 200_000  # stop *counting* files past this; nobody scans that many
_SCAN_TIMEOUT_SECONDS = 30
_ENTROPY_WINDOW = 1 << 20
_EXCERPT_CHARS = 64
_MAX_STRINGS_PER_RULE = 10
_MAX_OFFSETS = 5
_USER_RULE_MAX_BYTES = 1 << 20

COLLECT_CATEGORIES = ("downloads", "tty")
_CONTAINER_LABEL = ("honeypot-mcp", "true")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_MEMBER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SampleError(Exception):
    """A request that cannot be served; `message` is safe to show the caller."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def as_result(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.message}
        if self.hint:
            out["hint"] = self.hint
        return out


class SampleAccessError(SampleError):
    """A path that must not be read."""


class SkipFile(Exception):
    """A file that is reported as skipped (with `reason`) instead of scanned."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ── YARA engine ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleIssue:
    """A rule file that did not compile (or could not be read), named with its line."""

    file: str
    line: int | None
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "message": self.message}


@dataclass(frozen=True)
class RawMatch:
    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]
    # (identifier, ((offset, length), ...))
    strings: tuple[tuple[str, tuple[tuple[int, int], ...]], ...]


class ScanTimeout(Exception):
    pass


class _YaraPython:
    name = "yara-python"

    def __init__(self, module: Any) -> None:
        self.mod = module

    @property
    def version(self) -> str:
        return str(getattr(self.mod, "YARA_VERSION", "") or getattr(self.mod, "__version__", ""))

    def check(self, source: str) -> tuple[int | None, str] | None:
        try:
            self.mod.compile(source=source, includes=False)
        except self.mod.Error as exc:
            text = str(exc)
            match = re.match(r"line (\d+): (.*)", text, re.S)
            return (int(match.group(1)), match.group(2)) if match else (None, text)
        return None

    def compile(self, units: Sequence[tuple[str, str]]) -> Any:
        return self.mod.compile(sources=dict(units), includes=False)

    def scan(self, compiled: Any, data: bytes, timeout: int) -> list[RawMatch]:
        try:
            matches = compiled.match(data=data, timeout=timeout)
        except self.mod.TimeoutError:
            raise ScanTimeout from None
        out: list[RawMatch] = []
        for m in matches:
            strings = tuple(
                (s.identifier, tuple((i.offset, i.matched_length) for i in s.instances))
                for s in m.strings
            )
            out.append(RawMatch(m.rule, m.namespace, tuple(m.tags), dict(m.meta), strings))
        return out


class _YaraX:
    name = "yara-x"

    def __init__(self, module: Any) -> None:
        self.mod = module

    @property
    def version(self) -> str:
        with contextlib.suppress(importlib.metadata.PackageNotFoundError):
            return importlib.metadata.version("yara-x")
        return ""

    def _compiler(self) -> Any:
        compiler = self.mod.Compiler()
        compiler.enable_includes(False)
        return compiler

    def check(self, source: str) -> tuple[int | None, str] | None:
        compiler = self._compiler()
        try:
            compiler.add_source(source)
        except self.mod.CompileError as exc:
            errors = compiler.errors()
            if errors:
                first = errors[0]
                return first.get("line"), str(first.get("title") or first.get("text"))
            return None, str(exc).splitlines()[0]
        return None

    def compile(self, units: Sequence[tuple[str, str]]) -> Any:
        compiler = self._compiler()
        for label, source in units:
            compiler.new_namespace(label)
            compiler.add_source(source, origin=label)
        return compiler.build()

    def scan(self, compiled: Any, data: bytes, timeout: int) -> list[RawMatch]:
        scanner = self.mod.Scanner(compiled)
        scanner.set_timeout(timeout)
        try:
            results = scanner.scan(data)
        except self.mod.TimeoutError:
            raise ScanTimeout from None
        out: list[RawMatch] = []
        for rule in results.matching_rules:
            strings = tuple(
                (p.identifier, tuple((m.offset, m.length) for m in p.matches))
                for p in rule.patterns
                if p.matches
            )
            out.append(
                RawMatch(
                    rule.identifier, rule.namespace, tuple(rule.tags), dict(rule.metadata), strings
                )
            )
        return out


_BACKENDS: tuple[tuple[str, Any], ...] = (("yara", _YaraPython), ("yara_x", _YaraX))
_NOT_AVAILABLE_NOTE = (
    "No YARA engine is installed. Install the forensics extra "
    '(pip install "honeypot-mcp[forensics]"): it provides yara-python on Python 3.11-3.13 '
    "and yara-x (which has wheels for every supported Python) on 3.14."
)


def load_backend() -> Any | None:
    """The first YARA engine that imports, or None. Looked up on every call so that installing
    one while the server runs takes effect, and so a test can hide one with `sys.modules`."""
    for module_name, cls in _BACKENDS:
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        probe = "Compiler" if module_name == "yara_x" else "compile"
        if hasattr(module, probe):
            return cls(module)
    return None


def availability() -> dict[str, Any]:
    backend = load_backend()
    if backend is None:
        return {"available": False, "note": _NOT_AVAILABLE_NOTE}
    return {"available": True, "engine": backend.name, "engine_version": backend.version}


@dataclass
class RuleFile:
    name: str  # `iot_botnets` for a bundled file, `my_rules.yar` for a user file
    origin: str  # "bundled" | "user"
    label: str  # the YARA namespace and the name shown in errors
    source: str

    @property
    def rule_count(self) -> int:
        return len(re.findall(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", self.source, re.M))


@dataclass
class RuleSet:
    backend: Any
    compiled: Any | None
    loaded: list[RuleFile] = field(default_factory=list)
    issues: list[RuleIssue] = field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return sum(f.rule_count for f in self.loaded)

    def describe(self) -> dict[str, Any]:
        return {
            "engine": self.backend.name,
            "bundled": [f.name for f in self.loaded if f.origin == "bundled"],
            "user": [f.name for f in self.loaded if f.origin == "user"],
            "rules": self.rule_count,
            "errors": [i.as_dict() for i in self.issues],
        }


def _bundled_rule_files() -> list[RuleFile]:
    directory = resources.files("honeypot_mcp") / "yara_rules"
    files = []
    for entry in sorted(directory.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".yar") and entry.is_file():
            files.append(
                RuleFile(
                    name=entry.name[: -len(".yar")],
                    origin="bundled",
                    label=f"bundled:{entry.name}",
                    source=entry.read_text(encoding="utf-8"),
                )
            )
    return files


def _user_rule_files() -> tuple[list[RuleFile], list[RuleIssue]]:
    """`*.yar`/`*.yara` files directly inside `yara_rules_dir`. The directory is created owner-only
    on first use. Links, non-regular files and oversized files are reported, not read."""
    directory = get_settings().yara_rules_dir
    try:
        ensure_private_dir(directory)
        entries = sorted(os.scandir(directory), key=lambda e: e.name)
    except OSError as exc:
        return [], [RuleIssue("yara_rules_dir", None, f"cannot read the rules directory: {exc}")]
    files: list[RuleFile] = []
    issues: list[RuleIssue] = []
    for entry in entries:
        if not entry.name.endswith((".yar", ".yara")) or entry.name.startswith("."):
            continue
        label = f"user:{entry.name}"
        try:
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                issues.append(RuleIssue(label, None, "not a regular file (links are not followed)"))
                continue
            if info.st_size > _USER_RULE_MAX_BYTES:
                issues.append(RuleIssue(label, None, "rule file is over 1 MB; not loaded"))
                continue
            text = Path(entry.path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            issues.append(RuleIssue(label, None, f"cannot read the file: {exc}"))
            continue
        files.append(RuleFile(entry.name, "user", label, text))
    return files, issues


_RULE_CACHE: dict[tuple[Any, ...], RuleSet] = {}
_RULE_CACHE_LOCK = threading.Lock()
_RULE_CACHE_MAX = 8


def parse_selection(rules: str | Sequence[str] | None) -> tuple[str, ...]:
    if rules is None:
        return ()
    items = rules.split(",") if isinstance(rules, str) else list(rules)
    return tuple(sorted({p.strip() for p in items if p and p.strip()}))


def load_rules(rules: str | Sequence[str] | None = None) -> RuleSet:
    """Compile the bundled rules plus the user's, once, and reuse the result.

    A rule file that does not compile is recorded as an issue (file, line, message) and left out;
    the others still load, so one bad user file never disables detection. `rules` narrows the set
    to named files (bundled stem such as `miners`, or a user file name). Raises `SampleError` when
    no YARA engine is installed or a name matches nothing."""
    backend = load_backend()
    if backend is None:
        raise SampleError(_NOT_AVAILABLE_NOTE)
    selection = parse_selection(rules)
    user, issues = _user_rule_files()
    candidates = _bundled_rule_files() + user
    if selection:
        wanted = []
        for want in selection:
            hit = [f for f in candidates if want in (f.name, f.name.rsplit(".", 1)[0], f.label)]
            if not hit:
                names = ", ".join(sorted({f.name for f in candidates}))
                raise SampleError(
                    f"No rule file is named {want!r}.", f"Available rule files: {names}."
                )
            wanted.extend(hit)
        candidates = list({f.label: f for f in wanted}.values())
        issues = [i for i in issues if any(i.file == f.label for f in candidates)]
    fingerprint = tuple(
        (f.label, hashlib.sha256(f.source.encode()).hexdigest()) for f in candidates
    )
    key = (backend.name, selection, fingerprint, tuple((i.file, i.line, i.message) for i in issues))
    with _RULE_CACHE_LOCK:
        cached = _RULE_CACHE.get(key)
        if cached is not None:
            return cached
        good: list[RuleFile] = []
        for rule_file in candidates:
            problem = backend.check(rule_file.source)
            if problem is None:
                good.append(rule_file)
            else:
                issues.append(RuleIssue(rule_file.label, problem[0], problem[1]))
        compiled = backend.compile([(f.label, f.source) for f in good]) if good else None
        ruleset = RuleSet(backend, compiled, good, issues)
        if len(_RULE_CACHE) >= _RULE_CACHE_MAX:
            _RULE_CACHE.pop(next(iter(_RULE_CACHE)))
        _RULE_CACHE[key] = ruleset
        return ruleset


def _printable(data: bytes, limit: int = _EXCERPT_CHARS) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def evaluate(ruleset: RuleSet, data: bytes) -> list[dict[str, Any]]:
    """YARA hits for `data`, as plain dicts. Raises `ScanTimeout`."""
    if ruleset.compiled is None:
        return []
    hits = []
    for m in ruleset.backend.scan(ruleset.compiled, data, _SCAN_TIMEOUT_SECONDS):
        severity = str(m.meta.get("severity", "")).lower()
        strings = []
        for identifier, instances in sorted(m.strings)[:_MAX_STRINGS_PER_RULE]:
            first_offset, first_length = instances[0]
            strings.append(
                {
                    "id": identifier,
                    "count": len(instances),
                    "offsets": [o for o, _ in instances[:_MAX_OFFSETS]],
                    "excerpt": _printable(data[first_offset : first_offset + first_length]),
                }
            )
        hits.append(
            {
                "rule": m.rule,
                "source": m.namespace,
                "severity": severity if severity in SEVERITIES else "unrated",
                "family": str(m.meta["family"]) if m.meta.get("family") else None,
                "description": str(m.meta.get("description", ""))[:300] or None,
                "tags": list(m.tags),
                "strings": strings,
            }
        )
    hits.sort(key=lambda h: (-_SEVERITY_RANK[h["severity"]], h["rule"]))
    return hits


# ── Type, entropy ───────────────────────────────────────────────────────────

_ELF_MACHINES = {
    2: "sparc", 3: "x86", 4: "m68k", 8: "mips", 10: "mips", 18: "sparc", 20: "ppc", 21: "ppc64",
    22: "s390", 40: "arm", 42: "superh", 43: "sparc64", 45: "arc", 62: "x86-64", 83: "avr",
    94: "xtensa", 164: "hexagon", 183: "aarch64", 243: "riscv",
}  # fmt: skip
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object/PIE", 4: "core"}
_ARCHIVE_MAGIC: tuple[tuple[bytes, int, str], ...] = (
    (b"\x1f\x8b", 0, "gzip"),
    (b"BZh", 0, "bzip2"),
    (b"\xfd7zXZ\x00", 0, "xz"),
    (b"PK\x03\x04", 0, "zip"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7z"),
    (b"Rar!\x1a\x07", 0, "rar"),
    (b"\x28\xb5\x2f\xfd", 0, "zstd"),
    (b"ustar", 257, "tar"),
    (b"070701", 0, "cpio"),
)
_MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
}  # fmt: skip


def _elf_info(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"kind": "elf"}
    if len(data) < 20 or data[4] not in (1, 2) or data[5] not in (1, 2):
        info["description"] = "ELF (truncated or malformed header)"
        return info
    bits = 32 if data[4] == 1 else 64
    order = "<" if data[5] == 1 else ">"
    e_type, machine = struct.unpack_from(order + "HH", data, 16)
    arch = _ELF_MACHINES.get(machine, f"machine-{machine}")
    info.update(
        bits=bits,
        endian="little" if data[5] == 1 else "big",
        arch=arch,
        elf_type=_ELF_TYPES.get(e_type, f"type-{e_type}"),
    )
    linking = "unknown"
    try:
        if bits == 32 and len(data) >= 46:
            (phoff,) = struct.unpack_from(order + "I", data, 28)
            phentsize, phnum = struct.unpack_from(order + "HH", data, 42)
        elif bits == 64 and len(data) >= 58:
            (phoff,) = struct.unpack_from(order + "Q", data, 32)
            phentsize, phnum = struct.unpack_from(order + "HH", data, 54)
        else:
            phoff = phentsize = phnum = 0
        if phnum and phentsize >= 4:
            linking = "static"
            for index in range(min(phnum, 64)):
                at = phoff + index * phentsize
                if at + 4 > len(data):
                    linking = "unknown"
                    break
                if struct.unpack_from(order + "I", data, at)[0] == 3:  # PT_INTERP
                    linking = "dynamic"
                    break
    except struct.error:
        linking = "unknown"
    info["linking"] = linking
    endian = f", {info['endian']}-endian" if arch in ("mips", "ppc", "sparc") else ""
    info["description"] = (
        f"ELF {bits}-bit {info['elf_type']}, {arch}{endian}, "
        f"{linking + 'ally linked' if linking == 'static' else linking + ' linking'}"
    )
    return info


def _looks_like_text(data: bytes) -> bool:
    head = data[:8192]
    if b"\x00" in head:
        return False
    for trim in range(4):  # a multi-byte character may be cut at the end of the window
        try:
            text = head[: len(head) - trim].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        return False
    controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\x1b\x0c")
    return controls <= max(1, len(text) // 50)


def _is_cowrie_tty(data: bytes) -> bool:
    """Cowrie's tty recordings are UML-style records `<iLiiLL` (op, tty, length, direction, sec,
    usec); the first is an OPEN (op 1) stamped with the session start."""
    if len(data) < 24:
        return False
    op, _tty, length, _direction, sec, usec = struct.unpack_from("<iLiiLL", data, 0)
    return (
        op in (1, 2, 3, 4)
        and 0 <= length <= 1 << 20
        and 946684800 <= sec <= 4102444800
        and usec < 1_000_000
    )


def detect_type(data: bytes) -> dict[str, Any]:
    """What the leading bytes say the file is: `kind` plus a one-line `description`."""
    if not data:
        return {"kind": "empty", "description": "empty file"}
    if data[:4] == b"\x7fELF":
        return _elf_info(data)
    if data[:2] == b"MZ" and len(data) >= 64:
        (lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if data[lfanew : lfanew + 4] == b"PE\x00\x00":
            return {"kind": "pe", "description": "PE executable (Windows)"}
    if data[:4] in _MACHO_MAGIC:
        return {"kind": "macho", "description": "Mach-O executable"}
    for magic, offset, name in _ARCHIVE_MAGIC:
        if data[offset : offset + len(magic)] == magic:
            return {"kind": "archive", "format": name, "description": f"{name} archive/compressed"}
    if data[:2] == b"#!":
        line = data[2:130].split(b"\n", 1)[0].strip()
        interpreter = _printable(line, 80)
        return {
            "kind": "script",
            "interpreter": interpreter,
            "description": f"script, interpreter {interpreter}",
        }
    if _is_cowrie_tty(data):
        return {"kind": "tty_recording", "description": "Cowrie TTY session recording"}
    if _looks_like_text(data):
        return {"kind": "text", "description": "text"}
    return {"kind": "data", "description": "unrecognised binary data"}


def entropy_info(data: bytes) -> dict[str, Any]:
    """Shannon entropy of the first MiB, in bits per byte, with a coarse bucket: low (padding,
    repetition), medium (text, code), high (compiled code, mixed data) and packed_or_encrypted
    (compressed, packed or encrypted content looks like this)."""
    window = data[:_ENTROPY_WINDOW]
    if not window:
        return {"bits_per_byte": 0.0, "bucket": "low", "window_bytes": 0}
    import math

    total = len(window)
    counts = Counter(window)
    bits = -sum((c / total) * math.log2(c / total) for c in counts.values())
    bucket = (
        "low"
        if bits < 3.5
        else "medium"
        if bits < 6.0
        else "high"
        if bits < 7.2
        else "packed_or_encrypted"
    )
    return {"bits_per_byte": round(bits, 3), "bucket": bucket, "window_bytes": total}


# ── Confined access ─────────────────────────────────────────────────────────


def quarantine_root() -> Path:
    """The resolved quarantine directory, created owner-only if it does not exist."""
    root = get_settings().samples_dir
    try:
        ensure_private_dir(root)
        return root.resolve()
    except OSError as exc:
        raise SampleError(f"The samples directory is not usable: {exc.strerror or exc}.") from None


def resolve_in_root(path: str | None, root: Path) -> tuple[Path, os.stat_result]:
    """Resolve a file or directory name to a path inside `root`, or raise `SampleAccessError`.

    The twin of `pcap_analysis.open_capture`, for a tree. `..` is rejected outright (even where
    it would stay inside), an absolute path must already lie inside the quarantine, and every
    component below the root is checked with `lstat`: a symlink anywhere on the path is refused,
    so nothing can lead out of the directory."""
    if path is None or not str(path).strip():
        return root, os.lstat(root)
    text = str(path).strip()
    if "\x00" in text:
        raise SampleAccessError("path contains a NUL byte")
    candidate = Path(text)
    if ".." in candidate.parts:
        raise SampleAccessError("'..' is not allowed in a sample path; name a file or directory")
    if candidate.is_absolute():
        for base in (root, get_settings().samples_dir):
            try:
                relative = candidate.relative_to(base)
                break
            except ValueError:
                continue
        else:
            raise SampleAccessError(
                "refusing to read outside the samples directory; pass a name relative to it",
                "sample_collect fills the samples directory; its result names what it holds.",
            )
    else:
        relative = candidate
    current = root
    info = os.lstat(root)
    for part in relative.parts:
        if part in ("", "."):
            continue
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            raise SampleAccessError(
                f"{text!r} was not found in the samples directory",
                "sample_scan with no path scans everything there.",
            ) from None
        except OSError as exc:
            raise SampleAccessError(f"cannot inspect {text!r}: {exc.strerror}") from None
        if stat.S_ISLNK(info.st_mode):
            raise SampleAccessError("symbolic links are not followed inside the samples directory")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise SampleAccessError("not a regular file or directory")
    return current, info


@dataclass
class WalkResult:
    files: list[Path] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    not_scanned: int = 0  # regular files past the per-call cap


def walk_files(top: Path, root: Path, max_files: int) -> WalkResult:
    """Regular files under `top`, sorted, never following a link. Links, devices, FIFOs and
    sockets are returned as skipped entries. The quarantine's own metadata files and in-progress
    `collect()` files are not samples and are left out silently."""
    result = WalkResult()
    seen = 0
    stack: list[tuple[Path, int]] = [(top, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            result.skipped.append(
                {
                    "path": _rel(directory, root),
                    "reason": "unreadable directory",
                    "detail": exc.strerror or "",
                }
            )
            continue
        subdirs: list[Path] = []
        for entry in entries:
            path = Path(entry.path)
            if directory == root and entry.name in METADATA_FILES:
                continue
            if entry.name.startswith(PARTIAL_PREFIX):
                continue
            try:
                if entry.is_symlink():
                    result.skipped.append({"path": _rel(path, root), "reason": "symlink"})
                elif entry.is_dir(follow_symlinks=False):
                    if depth >= _MAX_WALK_DEPTH:
                        result.skipped.append({"path": _rel(path, root), "reason": "too deep"})
                    else:
                        subdirs.append(path)
                elif entry.is_file(follow_symlinks=False):
                    seen += 1
                    if len(result.files) < max_files:
                        result.files.append(path)
                    else:
                        result.not_scanned += 1
                    if seen >= _WALK_COUNT_CEILING:
                        return result
                else:
                    result.skipped.append({"path": _rel(path, root), "reason": "special file"})
            except OSError:
                result.skipped.append({"path": _rel(path, root), "reason": "unreadable"})
        stack.extend((d, depth + 1) for d in reversed(subdirs))
    result.files.sort()
    return result


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix() or "."
    except ValueError:
        return path.name


_O_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_CLOEXEC", 0)
)


def read_sample(path: Path, max_bytes: int) -> tuple[bytes, str]:
    """`(content, sha256 hex)` of one regular file. Raises `SkipFile` with the reason.

    A file with no permission bits is opened by granting its owner read, then putting the exact
    original mode back through the descriptor right after the open (the window is the time of one
    `open`); a `finally` restores it if the open fails. The file is never written. The descriptor,
    not the path, is checked to be the same regular file that was inspected, so a swap between
    the check and the open is caught."""
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise SkipFile("unreadable", exc.strerror or "") from None
    if stat.S_ISLNK(before.st_mode):
        raise SkipFile("symlink")
    if not stat.S_ISREG(before.st_mode):
        raise SkipFile("special file")
    if before.st_size > max_bytes:
        raise SkipFile("over the size cap", f"{before.st_size} bytes > {max_bytes}")
    original_mode = stat.S_IMODE(before.st_mode)
    owner_ok = getattr(os, "geteuid", lambda: before.st_uid)() == before.st_uid
    granted = False
    try:
        try:
            fd = os.open(path, _O_FLAGS)
        except PermissionError:
            if not owner_ok:
                raise SkipFile("not readable and not owned by this user") from None
            # Never follows a symlink: a path swapped for a link after the `lstat` above would
            # otherwise have its *target* made owner-readable (the fchmod below restores only the
            # mode of the file this was meant to be). Linux raises NotImplementedError for a link
            # and leaves the target alone; macOS changes the link itself.
            try:
                os.chmod(path, 0o400, follow_symlinks=False)
            except NotImplementedError:
                raise SkipFile("symlink") from None
            granted = True
            fd = os.open(path, _O_FLAGS)
    except SkipFile:
        raise
    except OSError as exc:
        if granted:
            with contextlib.suppress(OSError, NotImplementedError):
                os.chmod(path, original_mode, follow_symlinks=False)
        raise SkipFile("unreadable", exc.strerror or "") from None
    try:
        if granted:
            os.fchmod(fd, original_mode)
            granted = False
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(
            after.st_mode
        ):
            raise SkipFile("changed while being read")
        digest = hashlib.sha256()
        chunks = bytearray()
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            digest.update(block)
            chunks += block
            if len(chunks) > max_bytes:
                raise SkipFile("over the size cap", f"grew past {max_bytes} bytes while reading")
        return bytes(chunks), digest.hexdigest()
    except OSError as exc:
        raise SkipFile("unreadable", exc.strerror or "") from None
    finally:
        if granted:
            with contextlib.suppress(OSError):
                os.fchmod(fd, original_mode)
        os.close(fd)


# ── Scanning ────────────────────────────────────────────────────────────────


@dataclass
class ScanReport:
    root_label: str
    records: list[dict[str, Any]]
    skipped: list[dict[str, str]]
    not_scanned: int
    max_files: int
    max_bytes: int
    ruleset: RuleSet
    seconds: float


def scan_records(path: str | None, rules: str | Sequence[str] | None) -> ScanReport:
    """Hash, type and (when an engine is installed) match everything at `path` inside the
    quarantine. Pure and synchronous: call it in a thread. Raises `SampleError`."""
    started = time.monotonic()
    settings = get_settings()
    root = quarantine_root()
    ruleset = load_rules(rules)
    target, info = resolve_in_root(path, root)
    max_bytes = settings.sample_max_mb * 1024 * 1024
    max_files = settings.sample_scan_max_files
    walked = (
        WalkResult(files=[target])
        if stat.S_ISREG(info.st_mode)
        else walk_files(target, root, max_files)
    )
    records: list[dict[str, Any]] = []
    skipped = list(walked.skipped)
    for file_path in walked.files:
        rel = _rel(file_path, root)
        try:
            data, sha256 = read_sample(file_path, max_bytes)
        except SkipFile as skip:
            skipped.append({"path": rel, "reason": skip.reason, "detail": skip.detail})
            continue
        record: dict[str, Any] = {
            "path": rel,
            "sha256": sha256,
            "size": len(data),
            "type": detect_type(data),
            "entropy": entropy_info(data),
            "hits": [],
        }
        try:
            record["hits"] = evaluate(ruleset, data)
        except ScanTimeout:
            record["scan_error"] = f"rule scan timed out after {_SCAN_TIMEOUT_SECONDS}s"
        except Exception as exc:  # a malformed sample must not end the whole scan
            record["scan_error"] = f"rule scan failed ({type(exc).__name__})"
        records.append(record)
    return ScanReport(
        root_label=root.name,
        records=records,
        skipped=skipped,
        not_scanned=walked.not_scanned,
        max_files=max_files,
        max_bytes=max_bytes,
        ruleset=ruleset,
        seconds=round(time.monotonic() - started, 3),
    )


def _top_severity(record: dict[str, Any]) -> str | None:
    hits = record["hits"]
    return hits[0]["severity"] if hits else None


def compact_record(record: dict[str, Any], *, strings: int = 3) -> dict[str, Any]:
    """A per-file entry for the response: same facts, fewer matched strings per rule."""
    out = {k: v for k, v in record.items() if k != "hits"}
    out["hits"] = [{**h, "strings": h["strings"][:strings]} for h in record["hits"]]
    return out


def digest(
    records: list[dict[str, Any]],
    skipped: list[dict[str, str]],
    *,
    top: int,
    not_scanned: int = 0,
    max_files: int | None = None,
) -> dict[str, Any]:
    """The scan reduced to what a reader acts on: counts, hits by rule/family/severity, the files
    that matter most, duplicates, and everything that could not be scanned and why."""
    by_type = Counter(r["type"]["kind"] for r in records)
    by_arch = Counter(r["type"].get("arch", "?") for r in records if r["type"]["kind"] == "elf")
    with_hits = [r for r in records if r["hits"]]
    sev_files = Counter(_top_severity(r) for r in with_hits)
    rule_files: dict[tuple[str, str, str | None], set[str]] = {}
    family_files: dict[str, set[str]] = {}
    for r in with_hits:
        for h in r["hits"]:
            rule_files.setdefault((h["rule"], h["severity"], h["family"]), set()).add(r["sha256"])
            if h["family"]:
                family_files.setdefault(h["family"], set()).add(r["sha256"])
    by_hash: dict[str, list[str]] = {}
    for r in records:
        by_hash.setdefault(r["sha256"], []).append(r["path"])
    duplicates: list[dict[str, Any]] = sorted(
        (
            {"sha256": sha, "copies": len(paths), "paths": paths[:5]}
            for sha, paths in by_hash.items()
            if len(paths) > 1
        ),
        key=lambda d: (-int(d["copies"]), str(d["sha256"])),
    )
    ranked = sorted(
        with_hits,
        key=lambda r: (-_SEVERITY_RANK[r["hits"][0]["severity"]], -len(r["hits"]), r["path"]),
    )
    no_hit = [r for r in records if not r["hits"]]
    unknown = [r for r in records if r["type"]["kind"] == "data"]
    reasons = Counter(s["reason"] for s in skipped)
    out: dict[str, Any] = {
        "files_scanned": len(records),
        "distinct_hashes": len(by_hash),
        "bytes_scanned": sum(r["size"] for r in records),
        "files_skipped": {
            "count": len(skipped),
            "by_reason": dict(reasons),
            "examples": skipped[:10],
        },
        "by_type": dict(by_type),
        "elf_architectures": dict(by_arch),
        "files_with_hits": len(with_hits),
        "files_with_hits_by_type": dict(Counter(r["type"]["kind"] for r in with_hits)),
        "files_without_hits": len(no_hit),
        "unknown_type_files": len(unknown),
        "hits_by_severity": {s: sev_files.get(s, 0) for s in (*reversed(SEVERITIES), "unrated")},
        "hits_by_family": {
            fam: len(shas) for fam, shas in sorted(family_files.items(), key=lambda kv: -len(kv[1]))
        },
        "hits_by_rule": [
            {"rule": rule, "severity": sev, "family": fam, "files": len(shas)}
            for (rule, sev, fam), shas in sorted(
                rule_files.items(),
                key=lambda kv: (-_SEVERITY_RANK[kv[0][1]], -len(kv[1]), kv[0][0]),
            )
        ],
        "duplicates": {"groups": len(duplicates), "examples": duplicates[:10]},
        "top_files": [compact_record(r) for r in ranked[:top]],
        "no_hit_examples": [
            {"path": r["path"], "sha256": r["sha256"], "type": r["type"]["kind"], "size": r["size"]}
            for r in no_hit[: min(top, 10)]
        ],
        "scan_errors": [
            {"path": r["path"], "error": r["scan_error"]} for r in records if r.get("scan_error")
        ][:10],
    }
    if not_scanned:
        out["truncated"] = {
            "files_not_scanned": not_scanned,
            "note": (
                f"The directory holds more than the per-call limit of {max_files} files; "
                f"{not_scanned} were not opened. Scan a sub-directory, or raise "
                "SAMPLE_SCAN_MAX_FILES."
            ),
        }
    return out


# ── Collection from Cowrie containers ───────────────────────────────────────


def _docker_client() -> Any:
    import docker

    settings = get_settings()
    try:
        client = (
            docker.DockerClient(base_url=settings.docker_socket)  # type: ignore[attr-defined]
            if settings.docker_socket
            else docker.from_env()  # type: ignore[attr-defined]
        )
        client.ping()
    except Exception as exc:
        raise SampleError(
            f"Docker is not available ({type(exc).__name__}: {str(exc)[:200]}).",
            "Cowrie (the SSH and Telnet honeypots) runs in Docker. Start Docker and make sure "
            "this user can reach its socket (DOCKER_HOST or DOCKER_SOCKET).",
        ) from None
    return client


class _CapExceeded(Exception):
    pass


class _DeadlineExceeded(Exception):
    pass


_MAX_READ = (
    4 << 20
)  # the most one `_ByteStream.read` returns; a caller asking for more gets a short read
_READ_CHUNK = 1 << 20  # how a member's content is pulled out of the tar: never in one allocation
_MAX_EXTENDED_HEADER = 64 * 1024  # a GNU long name or PAX record that is longer is not a file name
_EXTENDED_HEADER_TYPES = frozenset(
    {
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.XHDTYPE,
        tarfile.XGLTYPE,
        tarfile.SOLARIS_XHDTYPE,
    }
)


class _BoundedTarInfo(tarfile.TarInfo):
    """`tarfile` reads a GNU long-name or PAX header *whatever size the archive declares*, copying it
    several times (measured: a 40 MB long name peaked at ~180 MB over baseline, so the 512 MB
    per-call cap meant ~2.5 GB), and expands a GNU sparse map into tuples at ~5x the archive's bytes.
    Docker's archives have neither, so both are refused before any of it is read."""

    def _proc_member(self, tarfile_: tarfile.TarFile) -> Any:  # type: ignore[override]
        if self.type in _EXTENDED_HEADER_TYPES and self.size > _MAX_EXTENDED_HEADER:
            raise tarfile.ReadError("oversized extended header")
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise tarfile.ReadError("GNU sparse member")
        return super()._proc_member(tarfile_)  # type: ignore[misc]


class _ByteStream:
    """A file-like over the chunks `Container.get_archive` yields, bounded in bytes and in time, so a
    container that streams without end, or that stalls, is cut off instead of filling memory or
    holding the collection lock.

    The chunks are pulled by a helper thread: the Docker SDK turns the socket timeout off for the
    stream, so a peer that goes quiet blocks the read for ever, and only a wait that is not itself
    the read can give up on it. An abandoned thread ends when the connection does (it is a daemon
    thread and holds at most two chunks)."""

    _END = object()

    def __init__(self, chunks: Iterator[bytes], limit: int, deadline: float | None = None) -> None:
        self._chunks = iter(chunks)
        self._buffer = bytearray()
        self._limit = limit
        self._deadline = deadline
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=2)
        self._stopped = threading.Event()
        self._pump_thread: threading.Thread | None = None
        self._eof = False
        self.received = 0

    def _pump(self) -> None:
        item: Any
        try:
            for chunk in self._chunks:
                item = chunk
                while not self._stopped.is_set():
                    try:
                        self._queue.put(item, timeout=0.5)
                        break
                    except queue.Full:
                        continue
                if self._stopped.is_set():
                    return
            item = self._END
        except BaseException as exc:  # handed to the reader, which raises it
            item = exc
        while not self._stopped.is_set():
            try:
                self._queue.put(item, timeout=0.5)
                return
            except queue.Full:
                continue

    def close(self) -> None:
        """Stop the helper thread. It exits within a moment unless it is blocked inside the peer's
        socket, in which case it is left to end with the connection."""
        self._stopped.set()
        thread = self._pump_thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)

    def _next_chunk(self) -> bytes | None:
        if self._eof:
            return None
        if self._pump_thread is None:
            self._pump_thread = threading.Thread(
                target=self._pump, name="sample-collect-pump", daemon=True
            )
            self._pump_thread.start()
        while True:
            wait = 1.0
            if self._deadline is not None:
                wait = min(wait, self._deadline - time.monotonic())
                if wait <= 0:
                    raise _DeadlineExceeded
            try:
                item = self._queue.get(timeout=wait)
            except queue.Empty:
                continue
            if item is self._END:
                self._eof = True
                return None
            if isinstance(item, BaseException):
                self._eof = True
                raise item
            return item  # type: ignore[no-any-return]

    def _fill(self, want: int) -> None:
        while len(self._buffer) < want:
            chunk = self._next_chunk()
            if chunk is None:
                return
            self.received += len(chunk)
            if self.received > self._limit:
                raise _CapExceeded
            self._buffer += chunk

    def read(self, size: int = -1) -> bytes:
        """Up to `size` bytes, never more than `_MAX_READ`, and as soon as any are available: a
        short read is how a file-like says "call again", `tarfile` does, and waiting for a full
        `size` would hold back a complete member until the peer sent a block's worth more. Reading
        the whole stream in one call is not offered."""
        size = _MAX_READ if size < 0 else min(size, _MAX_READ)
        if not self._buffer:
            self._fill(1)
        count = min(size, len(self._buffer))
        with memoryview(self._buffer) as view:
            taken = bytes(view[:count])
        del self._buffer[:count]
        return taken


@dataclass
class _Totals:
    files: int = 0
    nbytes: int = 0


@dataclass
class _Collected:
    container: str
    honeypot: str
    new: list[dict[str, Any]] = field(default_factory=list)
    duplicates: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    truncated: str | None = None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "container": self.container,
            "honeypot": self.honeypot,
            "new_files": len(self.new),
            "new_bytes": sum(f["size"] for f in self.new),
            "downloads_new": sum(1 for f in self.new if f["category"] == "downloads"),
            "tty_new": sum(1 for f in self.new if f["category"] == "tty"),
            "duplicates_skipped": self.duplicates,
            "skipped": dict(self.skipped),
            "new": self.new[:25],
        }
        if len(self.new) > 25:
            out["new_listing_truncated"] = len(self.new) - 25
        if self.truncated:
            out["truncated"] = self.truncated
        if self.error:
            out["error"] = self.error
        return out


_COLLECT_LOCK = threading.Lock()


def _read_sums(path: Path) -> dict[str, str]:
    """`{relative path: sha256}` from an existing SHA256SUMS; {} when absent or unreadable."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            return {}
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    sums: dict[str, str] = {}
    for line in text.splitlines():
        digest_part, _, name = line.partition("  ")
        if re.fullmatch(r"[0-9a-f]{64}", digest_part) and name:
            sums[name] = digest_part
    return sums


def _make_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise SampleError(f"{path.name!r} in the samples directory is not a directory")


def _store(directory: Path, name: str, data: bytes | bytearray) -> bool:
    """Write `data` as `directory/name`, mode 000, and never over an existing file. True when the
    file is new. Written to a private temp file and linked into place, so a reader never sees a
    half-written sample and an existing one can never be replaced."""
    tmp = directory / f"{PARTIAL_PREFIX}{secrets.token_hex(6)}.part"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fchmod(fh.fileno(), 0)
        final = directory / name
        try:
            os.link(tmp, final)
        except FileExistsError:
            return False
        except OSError:  # a filesystem without hard links
            if final.exists() or final.is_symlink():
                return False
            os.rename(tmp, final)
        return True
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)


def _safe_member(name: str) -> tuple[str, str] | None:
    """`(category, file name)` for a member that is `downloads/<file>` or `tty/<file>`, else None."""
    if "\\" in name or "\x00" in name or name.startswith("/"):
        return None
    parts = name.split("/")
    if len(parts) != 2 or parts[0] not in COLLECT_CATEGORIES or not _SAFE_MEMBER.match(parts[1]):
        return None
    return parts[0], parts[1]


def _ingest_tar(
    stream: _ByteStream,
    expected: str,
    honeypot_dir: Path,
    root: Path,
    sums: dict[str, str],
    result: _Collected,
    totals: _Totals,
    max_files: int,
    max_total: int,
    max_file: int,
) -> bool:
    """Walk the tar as it streams in and store acceptable members; False when a per-call limit
    stopped it. Nothing is extracted by `tarfile`: only regular files are read, by declared size,
    into memory, and written by `_store`. `expected` is the directory that was asked for."""
    category_dir: Path | None = None
    with tarfile.open(fileobj=stream, mode="r|", tarinfo=_BoundedTarInfo) as tar:  # type: ignore[call-overload]
        for member in tar:
            if member.isdir():
                continue
            parsed = _safe_member(member.name)
            if not member.isreg() or member.issparse():
                result.skipped["not a regular file (link, device, FIFO or sparse)"] += 1
                continue
            if parsed is None or parsed[0] != expected:
                result.skipped["unexpected path"] += 1
                continue
            category, base = parsed
            if member.size > max_file:
                result.skipped[f"over the {max_file // (1024 * 1024)} MB size cap"] += 1
                continue
            if totals.files >= max_files or totals.nbytes + member.size > max_total:
                result.truncated = (
                    "Stopped at the per-call limit "
                    f"({max_files} files / {max_total // (1024 * 1024)} MB); run sample_collect "
                    "again to take the next batch, or raise SAMPLE_COLLECT_MAX_FILES / "
                    "SAMPLE_COLLECT_MAX_TOTAL_MB."
                )
                return False
            handle = tar.extractfile(member)
            # Pulled in pieces into one buffer (hashed as it goes): `handle.read(member.size)` made
            # tarfile build the member several times over (a 40 MB file peaked ~180 MB above baseline).
            data = bytearray()
            digest = hashlib.sha256()
            if handle is not None:
                while len(data) < member.size:
                    piece = handle.read(min(_READ_CHUNK, member.size - len(data)))
                    if not piece:
                        break
                    data += piece
                    digest.update(piece)
            if len(data) != member.size:
                result.skipped["truncated member"] += 1
                continue
            totals.files += 1
            totals.nbytes += len(data)
            sha256 = digest.hexdigest()
            if category_dir is None:
                _make_dir(honeypot_dir)
                category_dir = honeypot_dir / category
                _make_dir(category_dir)
            prefix = category_dir.relative_to(root).as_posix()
            if category == "downloads":
                name = sha256  # content-addressed: the DB's shasum field joins on it
            else:
                # tty recordings keep Cowrie's own name (the `ttylog` field of its events names
                # it). A different content under a name that is already taken is a fuller copy
                # of a session that was still open; keep both rather than overwrite.
                name = base
                if (category_dir / name).exists() and sums.get(f"{prefix}/{name}") != sha256:
                    name = f"{base}.{sha256[:12]}"
            rel = f"{prefix}/{name}"
            if sums.get(rel) == sha256 or not _store(category_dir, name, data):
                result.duplicates += 1
                continue
            sums[rel] = sha256
            result.new.append(
                {"path": rel, "sha256": sha256, "size": len(data), "category": category}
            )
    return True


_GUARD_HINT = (
    "Docker (or the honeypot Docker guard in front of it) refused to copy files out of the "
    "container. The guard must allow GET on /containers/<id>/archive for the Cowrie "
    "downloads and tty directories; update the host's honeypot-mcp so its guard does."
)


_DEADLINE_NOTE = (
    "Stopped at the time limit (SAMPLE_COLLECT_DEADLINE_SECONDS); what arrived before that was "
    "kept. Run sample_collect again to continue."
)


def _collect_container(
    client: Any,
    container: Any,
    root: Path,
    sums: dict[str, str],
    deadline: float | None = None,
) -> _Collected:
    """Copy `downloads/` and `tty/` out of one container with `Container.get_archive` (what
    `docker cp` does). Files in a tmpfs mount are invisible to it; Cowrie's state directory is
    on the image's anonymous volume, which it does see."""
    import docker.errors

    settings = get_settings()
    name = str(container.name)
    result = _Collected(name, str((container.labels or {}).get("honeypot-name") or name))
    max_file = settings.sample_max_mb * 1024 * 1024
    max_total = settings.sample_collect_max_total_mb * 1024 * 1024
    honeypot_dir = root / name
    totals = _Totals()
    found = False
    try:
        for state_dir in COWRIE_STATE_DIRS:
            for category in COLLECT_CATEGORIES:
                try:
                    if deadline is not None and time.monotonic() >= deadline:
                        result.truncated = _DEADLINE_NOTE
                        return result
                    chunks, _stat = container.get_archive(f"{state_dir}/{category}")
                except docker.errors.NotFound:
                    continue
                found = True
                stream = _ByteStream(chunks, max_total + (8 << 20), deadline)
                try:
                    complete = _ingest_tar(
                        stream, category, honeypot_dir, root, sums, result, totals,
                        settings.sample_collect_max_files, max_total, max_file,
                    )  # fmt: skip
                except _CapExceeded:
                    result.truncated = (
                        "The container sent more than the per-call byte limit "
                        f"({settings.sample_collect_max_total_mb} MB); what arrived before that "
                        "was kept."
                    )
                    complete = False
                except _DeadlineExceeded:
                    result.truncated = _DEADLINE_NOTE
                    complete = False
                except tarfile.TarError as exc:
                    result.skipped[f"unreadable archive ({type(exc).__name__})"] += 1
                    complete = True
                finally:
                    stream.close()
                    close = getattr(chunks, "close", None)
                    if close is not None:
                        with contextlib.suppress(Exception):
                            close()
                if not complete:
                    return result
        if not found:
            result.error = (
                "Cowrie's data directory was not found in this container (not a Cowrie sensor?)"
            )
    except SampleError as exc:
        result.error = exc.message
    except docker.errors.APIError as exc:
        refused = getattr(exc, "status_code", None) == 403
        result.error = _GUARD_HINT if refused else f"Docker error: {str(exc)[:200]}"
    except Exception as exc:
        result.error = (
            f"could not collect from this container ({type(exc).__name__}: {str(exc)[:160]})"
        )
    return result


def collect(honeypot: str | None = None) -> dict[str, Any]:
    """Copy captured files out of the running Cowrie containers into the quarantine. Synchronous
    (Docker's SDK blocks): call it in a thread. Returns the result dict; raises `SampleError`."""
    settings = get_settings()
    if settings.analysis_mode:
        raise SampleError(
            "This server is in analysis mode (ANALYSIS_MODE=true): it reads a copy of captured "
            "data and runs no sensors, so there are no honeypot containers to collect from.",
            "Run sample_collect from the server that runs on the sensor host, or fetch a backup "
            "with scripts/fetch_backup.sh --samples and copy its samples-QUARANTINE directory "
            "into the samples directory.",
        )
    if honeypot is not None and not _SAFE_NAME.match(honeypot):
        raise SampleError(
            f"{honeypot!r} is not a valid honeypot name.", "Use a name from honeypot_list."
        )
    client = _docker_client()
    key, value = _CONTAINER_LABEL
    running = list(client.containers.list(filters={"label": f"{key}={value}", "status": "running"}))
    if honeypot is not None:
        running = [
            c
            for c in running
            if honeypot
            in (
                (c.labels or {}).get("honeypot-name"),
                c.name,
                str(c.name).removeprefix("honeypot-"),
            )
        ]
    if not running:
        raise SampleError(
            (
                f"No running honeypot container matches {honeypot!r}."
                if honeypot
                else "No running honeypot container was found."
            ),
            "Only the SSH and Telnet honeypots run in a container (Cowrie) and have files to "
            "collect; every other sensor runs inside this server. Check honeypot_list for a "
            "running ssh or telnet sensor.",
        )
    unsafe = [
        str(c.name) for c in running if not _SAFE_NAME.match(str(c.name)) or ".." in str(c.name)
    ]
    if unsafe:
        raise SampleError(f"Refusing a container with an unusual name: {unsafe[0][:60]!r}.")
    with _COLLECT_LOCK:
        root = quarantine_root()
        sums_path = root / "SHA256SUMS"
        sums = _read_sums(sums_path)
        before = dict(sums)
        # One clock for the whole call (every container shares it); it starts once the lock is held.
        deadline = time.monotonic() + settings.sample_collect_deadline_seconds
        results = [_collect_container(client, c, root, sums, deadline) for c in running]
        new_lines = {p: h for p, h in sums.items() if before.get(p) != h}
        notes: list[str] = []
        if new_lines:
            lines = "".join(f"{h}  {p}\n" for p, h in sorted(sums.items()))
            try:
                write_private_file(sums_path, lines)
            except OSError as exc:
                notes.append(f"SHA256SUMS could not be written ({exc.strerror}); files were kept.")
        readme = root / "README.txt"
        if not readme.exists() and not readme.is_symlink():
            with contextlib.suppress(OSError):
                write_private_file(readme, README_TEXT)
    new_total = sum(len(r.new) for r in results)
    ok = [r for r in results if not r.error]
    return {
        "collected": bool(ok),
        "new_files": new_total,
        "new_bytes": sum(f["size"] for r in results for f in r.new),
        "duplicates_skipped": sum(r.duplicates for r in results),
        "containers_checked": len(results),
        "honeypots": [r.as_dict() for r in results],
        "quarantine": str(root),
        "notes": notes,
        "next_step": (
            "Run sample_scan (path = a container directory name from this result, or none for "
            "everything) to hash, type and YARA-scan what was collected."
            if new_total
            else "Nothing new: every file in the containers is already in the quarantine."
        ),
    }
