"""Fingerprint hardening for Cowrie, loaded *inside the Cowrie container* as `sitecustomize`.

Cowrie is Twisted conch behind a faithful shell, and two of its network-visible defaults are
fingerprints that no `cowrie.cfg` option reaches:

* **Telnet opens with `IAC DO NAWS` and then `login: `.** nmap ships a rule for exactly that
  (`softmatch telnet m|^\\xff\\xfd\\x1f(?!\\xff)| p/Cowrie Honeypot telnetd/`), so `nmap -sV` names
  the product on the first probe. A Linux `telnetd` instead opens with
  `IAC DO TTYPE, DO TSPEED, DO XDISPLOC, DO NEW-ENVIRON`, then `\\r\\n<issue>\\r\\n<host> login: `.
* **The SSH algorithm lists are Twisted's, not the claimed OpenSSH's.** The banner says
  `OpenSSH_9.2p1` while the offer includes `3des-cbc`, `cast128-cbc`, `hmac-md5`,
  `diffie-hellman-group14-sha1` and a bare `ssh-rsa` host key, none of which OpenSSH 9.2 offers by
  default, and `ssh-audit` reports the contradiction. Ciphers, MACs and compression are plain
  `[ssh]` options (set by the engine through `COWRIE_SSH_*`); the key-exchange and host-key lists
  are not options at all.

The module is mounted into the container (`PYTHONPATH=/cowrie/persona/patch:...`), so Python
imports it at start-up, before Cowrie. It must not import Cowrie itself (nothing is on the path
yet and Cowrie reads its configuration at import): it installs an import hook that patches
`cowrie.ssh.factory` and `cowrie.telnet.userauth` the moment each is first imported. Driven by
environment variables the engine sets from the persona:

    HONEYPOT_SSH_KEX        comma list; offered key exchanges, in order (only those Twisted has)
    HONEYPOT_SSH_HOSTKEYS   comma list; offered host-key algorithms, in order (only those with a key)
    HONEYPOT_TELNET_ISSUE   the distro name a telnetd prints before the login prompt
    HONEYPOT_JANITOR_INTERVAL  seconds between artifact clean-ups (default 300; 0 turns it off)
    HONEYPOT_MAX_TTY        session recordings to keep, newest first (default 5000; -1 keeps all)

It also fixes two shell tells: `head -2` (legacy `-N`, which Cowrie rejects) and `uptime` /
`/proc/uptime` (which count from container start and so read minutes after every restart; they
report a per-hostname boot offset of several days plus real elapsed time).

Nothing runs when it is imported under any other name, so the host process and the tests can
import it to exercise the patch functions.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.abc
import importlib.util
import os
import posixpath
import sys
import threading
import time
from types import ModuleType
from typing import Any

# Option bytes Twisted does not name. A Linux telnetd asks for the terminal type, speed and
# display and for the environment, in that order, before it prints anything.
_TTYPE = b"\x18"
_TSPEED = b"\x20"
_XDISPLOC = b"\x23"
_NEW_ENVIRON = b"\x27"

# The key format a host-key signature algorithm is made with. OpenSSH signs with an `ssh-rsa`
# key using rsa-sha2-256/512, which Twisted supports; only the *offer* needs naming.
_KEY_FORMAT = {b"rsa-sha2-256": b"ssh-rsa", b"rsa-sha2-512": b"ssh-rsa"}


def _csv(name: str) -> list[bytes]:
    return [item.strip().encode() for item in os.environ.get(name, "").split(",") if item.strip()]


# ── SSH ──────────────────────────────────────────────────────────────────────────────────────


def restrict_ssh_offer(
    transport: Any, key_exchanges: list[bytes], host_keys: list[bytes], have_keys: set[bytes]
) -> None:
    """Narrow a freshly built SSH transport's algorithm offer to what the persona's OpenSSH
    would send, keeping the persona's order. Names this Twisted does not implement, and host-key
    algorithms the sensor has no key for, are skipped rather than offered and failed.
    """
    if key_exchanges:
        kept = [k for k in key_exchanges if k in transport.supportedKeyExchanges]
        if kept:
            transport.supportedKeyExchanges = kept
    if host_keys:
        kept = [k for k in host_keys if _KEY_FORMAT.get(k, k) in have_keys]
        if kept:
            transport.supportedPublicKeys = kept


def patch_ssh_factory(module: ModuleType) -> None:
    start_janitor()
    factory_cls = module.CowrieSSHFactory
    original = factory_cls.buildProtocol
    key_exchanges, host_keys = _csv("HONEYPOT_SSH_KEX"), _csv("HONEYPOT_SSH_HOSTKEYS")

    def buildProtocol(self: Any, addr: Any) -> Any:  # noqa: N802 (Twisted's name)
        transport = original(self, addr)
        restrict_ssh_offer(transport, key_exchanges, host_keys, set(self.privateKeys))
        return transport

    factory_cls.buildProtocol = buildProtocol


# ── Telnet ───────────────────────────────────────────────────────────────────────────────────


def telnet_greeting(issue: str, hostname: str) -> bytes:
    """What a telnetd writes before it reads anything: a blank line, the issue, then the
    `<host> login: ` prompt. `\\n` here becomes Cowrie's `\\r\\r\\n` (its transport strips one `\\r`)."""
    text = f"\n{issue}\n" if issue else "\n"
    return (
        text.encode("utf-8", "replace").replace(b"\n", b"\r\r\n") + f"{hostname} login: ".encode()
    )


def patch_telnet_userauth(module: ModuleType) -> None:
    start_janitor()
    proto = module.HoneyPotTelnetAuthProtocol
    issue = os.environ.get("HONEYPOT_TELNET_ISSUE", "").strip()

    def connectionMade(self: Any) -> None:  # noqa: N802 (Twisted's name)
        self.transport.negotiationMap[module.NAWS] = self.telnet_NAWS
        self.transport.negotiationMap[module.NEW_ENVIRON] = self.telnet_NEW_ENVIRON
        for option in (_TTYPE, _TSPEED, _XDISPLOC, module.NEW_ENVIRON):
            # A client that refuses (WONT) errbacks the deferred; that is the normal answer.
            self.transport.doChain(option).addErrback(lambda _failure: None)

        self.environ_received = {}
        self.windowSize = [40, 80]
        hostname = module.CowrieConfig.get("honeypot", "hostname", fallback="localhost")
        # An operator-supplied issue.net, if the factory loaded a non-empty one, wins over the
        # persona's distro line.
        banner = getattr(self.factory, "banner", b"").decode("utf-8", "replace").strip()
        self.transport.write(telnet_greeting(banner or issue, hostname))

    proto.connectionMade = connectionMade


# ── Artifact janitor ─────────────────────────────────────────────────────────────────────────
#
# Cowrie keeps session recordings (`tty/`) and download records (`downloads/`) under
# `var/lib/cowrie`, which the container mounts as tmpfs. Two properties of that are fatal under a
# botnet. The memory cgroup counts every file's inode and dentry on top of the tmpfs `size=` cap
# (which does not limit the *number* of files), and with egress closed every failed `wget`/`curl`
# leaves a 0-byte `tmp…`/`redir_…` file that nothing ever removes. On the live VPS that was
# 43,591 empty files plus 10,654 recordings (~85 MB against a 64 MB tmpfs): ~80 MiB of a 256 MiB
# limit, the telnet container OOM-killed 246 times in 20 hours, and the directory full, so new
# recordings and real downloads were failing to write. The cleanup runs here, inside the container,
# because the host's Docker guard deliberately refuses `exec`.

_DATA_ROOTS = ("/cowrie/cowrie-git/var/lib/cowrie", "/cowrie/var/lib/cowrie")
_MIN_AGE_SECONDS = 300
_janitor_started = False


def prune_artifacts(
    roots: tuple[str, ...], keep_tty: int, min_age: float = _MIN_AGE_SECONDS
) -> dict[str, int] | None:
    """Delete 0-byte download leftovers older than `min_age` seconds and all but the newest
    `keep_tty` recordings. Never follows or removes through a symlink (file names are
    attacker-influenced). A negative `keep_tty` keeps every recording. None if there is no data
    directory (so "looked in the wrong place" is distinguishable from "nothing to do")."""
    root = next((r for r in roots if os.path.isdir(r)), None)
    if root is None:
        return None
    now = time.time()
    result = {"empty_downloads": 0, "tty_pruned": 0, "tty_kept": 0}

    def entries(path: str) -> list[tuple[str, os.stat_result]]:
        found: list[tuple[str, os.stat_result]] = []
        try:
            with os.scandir(path) as it:
                for entry in it:
                    try:
                        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                            continue
                        found.append((entry.path, entry.stat(follow_symlinks=False)))
                    except OSError:
                        continue
        except OSError:
            pass
        return found

    for path, st in entries(os.path.join(root, "downloads")):
        if st.st_size == 0 and now - st.st_mtime > min_age:
            try:
                os.unlink(path)
                result["empty_downloads"] += 1
            except OSError:
                pass

    recordings = sorted(entries(os.path.join(root, "tty")), key=lambda item: item[1].st_mtime)
    if keep_tty >= 0 and len(recordings) > keep_tty:
        for path, _ in recordings[: len(recordings) - keep_tty]:
            try:
                os.unlink(path)
                result["tty_pruned"] += 1
            except OSError:
                pass
    result["tty_kept"] = len(recordings) - result["tty_pruned"]
    return result


def _janitor_loop(interval: float, keep_tty: int) -> None:
    # First pass soon after start (a restarted container can already be near its limit), then on
    # the interval. Any failure is swallowed: housekeeping must never take the honeypot down.
    time.sleep(min(60.0, interval))
    while True:
        with contextlib.suppress(Exception):
            prune_artifacts(_DATA_ROOTS, keep_tty)
        time.sleep(interval)


def start_janitor() -> None:
    """Start the cleanup thread once, in a process that is actually running Cowrie (called when a
    patched Cowrie module is imported, so `docker exec python3 -c` never gets one)."""
    global _janitor_started
    if _janitor_started:
        return
    _janitor_started = True
    try:
        interval = float(os.environ.get("HONEYPOT_JANITOR_INTERVAL", "300"))
        keep_tty = int(os.environ.get("HONEYPOT_MAX_TTY", "5000"))
    except ValueError:
        return
    if interval <= 0:
        return
    threading.Thread(
        target=_janitor_loop, args=(interval, keep_tty), name="artifact-janitor", daemon=True
    ).start()


# ── head -N ──────────────────────────────────────────────────────────────────────────────────


def normalise_head_args(args: list[str]) -> list[str]:
    """Rewrite the legacy `head -2 file` form to `head -n 2 file`. coreutils still accepts it
    (scripts and muscle memory use it constantly); Cowrie's getopt only knows `-n`/`-c`, so it
    answered "invalid option -- '2'" — a one-command tell. Stops at `--`; leaves everything else
    untouched."""
    out: list[str] = []
    for i, arg in enumerate(args):
        if arg == "--":
            out.extend(args[i:])
            break
        if len(arg) > 1 and arg[0] == "-" and arg[1:].isdigit() and arg.isascii():
            out.extend(["-n", arg[1:]])
        else:
            out.append(arg)
    return out


def patch_commands_fs(module: ModuleType) -> None:
    """`head -2` and `tail -3` (the legacy `-N` form) are accepted by coreutils; Cowrie rejects both."""
    for name in ("Command_head", "Command_tail"):
        command = getattr(module, name, None)
        if command is None:
            continue

        def wrap(original: Any) -> Any:
            def start(self: Any) -> Any:
                self.args = normalise_head_args(list(self.args))
                return original(self)

            return start

        command.start = wrap(command.start)


# ── uptime ───────────────────────────────────────────────────────────────────────────────────

_PROCESS_START = time.time()
_MIN_BOOT_DAYS = 3
_BOOT_SPREAD_DAYS = 24  # 3 .. 27 days of uptime before this container started


def boot_offset_seconds(hostname: str) -> int:
    """How long the emulated host had been up before this process started: deterministic per
    hostname (so a restart does not change the story), several days to about four weeks.
    Cowrie counts from container start, so `uptime` read "11 min" after every restart."""
    digest = hashlib.sha256(f"boot:{hostname}".encode()).digest()
    return int.from_bytes(digest[:8], "big") % (_BOOT_SPREAD_DAYS * 86400) + _MIN_BOOT_DAYS * 86400


def uptime_seconds(hostname: str, now: float | None = None, start: float | None = None) -> float:
    """Boot offset plus the real time this process has been running."""
    now = time.time() if now is None else now
    start = _PROCESS_START if start is None else start
    return boot_offset_seconds(hostname) + max(0.0, now - start)


def proc_uptime_text(up: float) -> bytes:
    """`/proc/uptime`: seconds up and seconds idle summed over cores (a lightly loaded box is
    ~95% idle; two cores, like the persona's cpuinfo)."""
    return f"{up:.2f} {up * 2 * 0.95:.2f}\n".encode()


def _hostname() -> str:
    return os.environ.get("COWRIE_HONEYPOT_HOSTNAME") or os.environ.get("COWRIE_HOSTNAME") or "host"


def patch_shell_protocol(module: ModuleType) -> None:
    protocol = getattr(module, "HoneyPotBaseProtocol", None)
    if protocol is None:
        return

    def uptime(self: Any) -> float:
        return uptime_seconds(_hostname())

    protocol.uptime = uptime


def patch_shell_fs(module: ModuleType) -> None:
    filesystem = getattr(module, "HoneyPotFilesystem", None)
    if filesystem is None:
        return
    original = filesystem.file_contents

    def file_contents(self: Any, target: str) -> bytes:
        data = original(self, target)
        try:
            path = self.resolve_path(target, posixpath.dirname(target))
        except Exception:
            return data
        if path == "/proc/uptime":
            return proc_uptime_text(uptime_seconds(_hostname()))
        return data

    filesystem.file_contents = file_contents


# ── import hook ──────────────────────────────────────────────────────────────────────────────

_PATCHES = {
    "cowrie.ssh.factory": patch_ssh_factory,
    "cowrie.telnet.userauth": patch_telnet_userauth,
    "cowrie.commands.fs": patch_commands_fs,
    "cowrie.shell.protocol": patch_shell_protocol,
    "cowrie.shell.fs": patch_shell_fs,
}


class _PatchFinder(importlib.abc.MetaPathFinder):
    """Patch a target module right after it executes, whatever imports it first."""

    def __init__(self) -> None:
        self._resolving: set[str] = set()

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        patch = _PATCHES.get(fullname)
        if patch is None or fullname in self._resolving:
            return None
        self._resolving.add(fullname)
        try:
            spec = importlib.util.find_spec(fullname)
        finally:
            self._resolving.discard(fullname)
        if spec is None or spec.loader is None:
            return None
        execute = spec.loader.exec_module

        def exec_module(module: ModuleType) -> None:
            execute(module)
            patch(module)

        spec.loader.exec_module = exec_module  # type: ignore[method-assign]
        return spec


def install() -> None:
    sys.meta_path.insert(0, _PatchFinder())


if __name__ == "sitecustomize":  # imported by Python's `site` at start-up inside the container
    install()
