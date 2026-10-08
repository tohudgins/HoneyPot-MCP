"""Cowrie's two network-visible defaults that no `cowrie.cfg` option reaches.

`nmap -sV` names a telnet service that opens `IAC DO NAWS` + `login:` "Cowrie Honeypot telnetd",
and Twisted's SSH offer (3des-cbc, cast128-cbc, hmac-md5, group14-sha1, a bare ssh-rsa host key)
contradicts the OpenSSH banner. The persona supplies what a real host of that persona sends and
`engines/cowrie_sitecustomize.py`, mounted into the container, applies it.
"""

from __future__ import annotations

import io
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

from honeypot_mcp.engines import cowrie_sitecustomize as patch
from honeypot_mcp.engines.ssh_personas import (
    _PERSONAS,
    cowrie_env_vars,
    hostkey_algorithms,
    telnet_issue,
)

# Names OpenSSH stopped offering by default long before 8.0, which Twisted's defaults still do.
_NOT_OFFERED_BY_OPENSSH_8_PLUS = {
    "3des-cbc",
    "blowfish-cbc",
    "cast128-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "hmac-md5",
    "hmac-sha2-384",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "zlib",
}


@pytest.mark.parametrize("persona", list(_PERSONAS.values()), ids=list(_PERSONAS))
def test_every_persona_offers_only_algorithms_its_openssh_sends(persona):
    env = cowrie_env_vars(persona, "host")
    offered = set()
    for key in (
        "COWRIE_SSH_CIPHERS",
        "COWRIE_SSH_MACS",
        "COWRIE_SSH_COMPRESSION",
        "HONEYPOT_SSH_KEX",
    ):
        offered |= set(env[key].split(","))
    assert not offered & _NOT_OFFERED_BY_OPENSSH_8_PLUS
    assert env["COWRIE_SSH_COMPRESSION"] == "none,zlib@openssh.com"
    assert env["PYTHONPATH"].split(":")[0] == "/cowrie/persona/patch"
    assert env["PYTHONPATH"].endswith("/cowrie/cowrie-git/src"), "the image's own path stays"


@pytest.mark.parametrize(
    ("persona_id", "has_ssh_rsa"),
    [("ubuntu_22_04", False), ("debian_12", False), ("ubuntu_20_04", True), ("rhel_8", True)],
)
def test_ssh_rsa_is_a_default_host_key_algorithm_only_before_openssh_8_8(persona_id, has_ssh_rsa):
    algorithms = hostkey_algorithms(_PERSONAS[persona_id]).split(",")
    assert ("ssh-rsa" in algorithms) is has_ssh_rsa
    assert algorithms[:2] == ["rsa-sha2-512", "rsa-sha2-256"], "OpenSSH's own order"


def test_the_telnet_issue_is_the_release_without_its_codename():
    assert telnet_issue(_PERSONAS["debian_12"]) == "Debian GNU/Linux 12"
    assert telnet_issue(_PERSONAS["ubuntu_22_04"]) == "Ubuntu 22.04.3 LTS"
    assert telnet_issue(_PERSONAS["rhel_8"]) == "Red Hat Enterprise Linux 8.8"


# ── the patch functions ──────────────────────────────────────────────────────────────────────


class _Transport:
    supportedKeyExchanges = [  # noqa: N815
        b"curve25519-sha256",
        b"curve25519-sha256@libssh.org",
        b"ecdh-sha2-nistp256",
        b"diffie-hellman-group14-sha1",
    ]
    supportedPublicKeys = [b"ssh-rsa", b"ecdsa-sha2-nistp256", b"ssh-ed25519"]  # noqa: N815


def test_the_offer_is_narrowed_to_the_persona_in_the_persona_order():
    transport = _Transport()
    patch.restrict_ssh_offer(
        transport,
        key_exchanges=[
            b"curve25519-sha256",
            b"sntrup761x25519-sha512@openssh.com",
            b"ecdh-sha2-nistp256",
        ],
        host_keys=[b"rsa-sha2-512", b"rsa-sha2-256", b"ecdsa-sha2-nistp256", b"ssh-ed25519"],
        have_keys={b"ssh-rsa", b"ecdsa-sha2-nistp256", b"ssh-ed25519"},
    )
    # sntrup is not implemented by Twisted and is skipped, not offered and then failed.
    assert transport.supportedKeyExchanges == [b"curve25519-sha256", b"ecdh-sha2-nistp256"]
    assert transport.supportedPublicKeys[:2] == [b"rsa-sha2-512", b"rsa-sha2-256"]
    assert b"ssh-rsa" not in transport.supportedPublicKeys


def test_a_host_key_the_sensor_has_no_key_for_is_never_offered():
    transport = _Transport()
    patch.restrict_ssh_offer(
        transport,
        key_exchanges=[],
        host_keys=[b"rsa-sha2-512", b"ecdsa-sha2-nistp256", b"ssh-ed25519"],
        have_keys={b"ssh-ed25519"},  # no RSA and no ECDSA key on disk
    )
    assert transport.supportedPublicKeys == [b"ssh-ed25519"]


def test_an_offer_that_would_be_empty_leaves_twisteds_defaults():
    transport = _Transport()
    patch.restrict_ssh_offer(transport, [b"nonexistent"], [b"rsa-sha2-512"], have_keys=set())
    assert transport.supportedKeyExchanges == _Transport.supportedKeyExchanges
    assert transport.supportedPublicKeys == _Transport.supportedPublicKeys


def test_the_telnet_greeting_is_a_blank_line_the_issue_and_a_host_login_prompt():
    assert patch.telnet_greeting("Ubuntu 22.04.3 LTS", "web-prod-01") == (
        b"\r\r\nUbuntu 22.04.3 LTS\r\r\nweb-prod-01 login: "
    )
    assert patch.telnet_greeting("", "h") == b"\r\r\nh login: "


class _FakeTransport:
    def __init__(self):
        self.negotiationMap = {}  # noqa: N815
        self.sent_options: list[bytes] = []
        self.written = b""

    def doChain(self, option):  # noqa: N802
        self.sent_options.append(option)

        class _Deferred:
            def addErrback(self, _fn):  # noqa: N802
                return self

        return _Deferred()

    def write(self, data):
        self.written += data


def _fake_userauth_module(banner: bytes = b""):
    class HoneyPotTelnetAuthProtocol:
        def __init__(self):
            self.transport = _FakeTransport()
            self.factory = type("Factory", (), {"banner": banner})()

        def telnet_NAWS(self, data):  # noqa: N802
            pass

        def telnet_NEW_ENVIRON(self, data):  # noqa: N802
            pass

    module = type(sys)("cowrie.telnet.userauth")
    module.HoneyPotTelnetAuthProtocol = HoneyPotTelnetAuthProtocol
    module.NAWS = b"\x1f"
    module.NEW_ENVIRON = b"\x27"
    module.CowrieConfig = type("Cfg", (), {"get": staticmethod(lambda *a, **k: "srv-internal")})()
    return module


def test_telnet_opens_like_a_linux_telnetd_not_with_do_naws(monkeypatch):
    """The first bytes are what nmap's `softmatch ... \\xff\\xfd\\x1f` names Cowrie from."""
    monkeypatch.setenv("HONEYPOT_TELNET_ISSUE", "Debian GNU/Linux 12")
    module = _fake_userauth_module()
    patch.patch_telnet_userauth(module)
    proto = module.HoneyPotTelnetAuthProtocol()
    proto.connectionMade()

    assert proto.transport.sent_options == [b"\x18", b"\x20", b"\x23", b"\x27"]
    assert b"\x1f" not in proto.transport.sent_options, "no DO NAWS"
    assert proto.transport.written == b"\r\r\nDebian GNU/Linux 12\r\r\nsrv-internal login: "
    # Cowrie's own handlers stay registered: NAWS if the client volunteers it, NEW-ENVIRON for
    # the environment capture.
    assert set(proto.transport.negotiationMap) == {b"\x1f", b"\x27"}
    assert proto.windowSize == [40, 80] and proto.environ_received == {}


def test_an_operator_issue_net_replaces_the_personas_distro_line(monkeypatch):
    monkeypatch.setenv("HONEYPOT_TELNET_ISSUE", "Debian GNU/Linux 12")
    module = _fake_userauth_module(banner=b"Authorised use only\n")
    patch.patch_telnet_userauth(module)
    proto = module.HoneyPotTelnetAuthProtocol()
    proto.connectionMade()
    assert proto.transport.written == b"\r\r\nAuthorised use only\r\r\nsrv-internal login: "


def test_the_import_hook_patches_a_module_exactly_when_it_is_first_imported(tmp_path, monkeypatch):
    """Nothing about Cowrie can be imported when Python starts, so the patch rides an import
    hook; it must patch the target after it executes and leave every other module alone."""
    pkg = tmp_path / "fakecowrie"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "target.py").write_text("VALUE = 'original'\n")
    (pkg / "other.py").write_text("VALUE = 'original'\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(
        patch, "_PATCHES", {"fakecowrie.target": lambda m: setattr(m, "VALUE", "patched")}
    )
    finder = patch._PatchFinder()
    monkeypatch.setattr(sys, "meta_path", [finder, *sys.meta_path])
    for name in ("fakecowrie", "fakecowrie.target", "fakecowrie.other"):
        monkeypatch.delitem(sys.modules, name, raising=False)

    import fakecowrie.other
    import fakecowrie.target

    assert fakecowrie.target.VALUE == "patched"
    assert fakecowrie.other.VALUE == "original"


def test_importing_the_module_normally_installs_nothing():
    """The host process imports this file (the engine reads it to ship it): it must not hook
    the host interpreter's imports."""
    assert not any(isinstance(f, patch._PatchFinder) for f in sys.meta_path)
    assert patch.__name__ != "sitecustomize"


# ── delivery ─────────────────────────────────────────────────────────────────────────────────


def test_the_patch_travels_with_the_persona_filesystem_and_is_importable_from_the_archive():
    from honeypot_mcp.engines.cowrie_fs import persona_tar
    from honeypot_mcp.engines.ssh import _sitecustomize_source

    source = _sitecustomize_source()
    with tarfile.open(fileobj=io.BytesIO(persona_tar(b"pickle", source))) as tar:
        members = {m.name: m for m in tar.getmembers()}
        assert {"fs.pickle", "patch", "patch/sitecustomize.py"} <= set(members)
        assert members["patch"].isdir() and members["patch"].mode == 0o755
        assert tar.extractfile("patch/sitecustomize.py").read() == source
    assert source == Path(patch.__file__).read_bytes()
    # Without a patch the archive is the old one.
    with tarfile.open(fileobj=io.BytesIO(persona_tar(b"pickle"))) as tar:
        assert tar.getnames() == ["fs.pickle"]


def test_sitecustomize_runs_its_installer_only_under_that_name(tmp_path):
    """Python imports `sitecustomize` by that name at start-up; run the real file the way it
    will be run and check the hook is registered (and not under another module name)."""
    source = Path(patch.__file__).read_text()
    probe = tmp_path / "probe"
    probe.mkdir()
    (probe / "sitecustomize.py").write_text(source)
    (probe / "check.py").write_text(
        textwrap.dedent(
            """
            import sys
            print(any(type(f).__name__ == "_PatchFinder" for f in sys.meta_path))
            """
        )
    )
    import os
    import subprocess

    env = {**os.environ, "PYTHONPATH": str(probe)}
    out = subprocess.run(
        [sys.executable, str(probe / "check.py")],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.stdout.strip() == "True", out.stderr


def test_compose_sensor_carries_the_same_algorithm_environment_as_the_engine():
    """docker-compose.yml spells the values out (it cannot import Python); they must equal what
    `cowrie_env_vars` gives the persona the stack claims, or the stack and an SDK deploy of the
    same persona would present different servers."""
    import yaml

    compose = yaml.safe_load(
        (Path(__file__).parents[2] / "docker" / "docker-compose.yml").read_text()
    )
    init = compose["services"]["cowrie-persona-init"]
    env = dict(item.split("=", 1) for item in compose["services"]["cowrie-ssh"]["environment"])
    expected = cowrie_env_vars(_PERSONAS[init["environment"]["PERSONA"]], "ubuntu-server")
    for key in (
        "COWRIE_SSH_CIPHERS",
        "COWRIE_SSH_MACS",
        "COWRIE_SSH_COMPRESSION",
        "HONEYPOT_SSH_KEX",
        "HONEYPOT_SSH_HOSTKEYS",
        "HONEYPOT_TELNET_ISSUE",
        "PYTHONPATH",
    ):
        assert env[key] == expected[key], key
    assert (
        "../src/honeypot_mcp/engines/cowrie_sitecustomize.py:/hp-src/cowrie_sitecustomize.py:ro"
        in init["volumes"]
    )
