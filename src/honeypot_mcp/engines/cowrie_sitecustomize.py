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

Nothing runs when it is imported under any other name, so the host process and the tests can
import it to exercise the patch functions.
"""

from __future__ import annotations

import importlib.abc
import importlib.util
import os
import sys
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


# ── import hook ──────────────────────────────────────────────────────────────────────────────

_PATCHES = {
    "cowrie.ssh.factory": patch_ssh_factory,
    "cowrie.telnet.userauth": patch_telnet_userauth,
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
