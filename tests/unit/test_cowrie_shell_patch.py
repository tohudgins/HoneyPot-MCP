"""Shell-level realism: legacy `head -N`, a believable uptime, and the tracked bait credential."""

from __future__ import annotations

import pickle
import types

import pytest

from honeypot_mcp.engines import cowrie_fs as cf
from honeypot_mcp.engines import cowrie_sitecustomize as patch
from honeypot_mcp.engines.ssh_personas import _PERSONAS


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["-2", "/etc/passwd"], ["-n", "2", "/etc/passwd"]),
        (["-n", "2", "f"], ["-n", "2", "f"]),
        (["-c", "5", "-3"], ["-c", "5", "-n", "3"]),
        (["--", "-2"], ["--", "-2"]),
        (["-", "-x", "-2x"], ["-", "-x", "-2x"]),
        ([], []),
    ],
)
def test_normalise_head_args(args, expected):
    assert patch.normalise_head_args(args) == expected


def test_patched_head_start_sees_normalised_args():
    seen: list[list[str]] = []

    class Command_head:
        def start(self):
            seen.append(list(self.args))

    module = types.ModuleType("cowrie.commands.fs")
    module.Command_head = Command_head  # type: ignore[attr-defined]
    patch.patch_commands_fs(module)
    cmd = Command_head()
    cmd.args = ["-2", "x"]
    cmd.start()
    assert seen == [["-n", "2", "x"]]


def test_patched_head_and_tail_each_keep_their_own_start():
    """`tail -3` was rejected exactly like `head -2`; and wrapping both in one loop must not make
    one command call the other's original (the classic late-binding closure mistake)."""
    calls: list[tuple[str, list[str]]] = []

    class Command_head:
        def start(self):
            calls.append(("head", list(self.args)))

    class Command_tail:
        def start(self):
            calls.append(("tail", list(self.args)))

    module = types.ModuleType("cowrie.commands.fs")
    module.Command_head = Command_head  # type: ignore[attr-defined]
    module.Command_tail = Command_tail  # type: ignore[attr-defined]
    patch.patch_commands_fs(module)
    for cls, args in ((Command_head, ["-2", "a"]), (Command_tail, ["-3", "b"])):
        cmd = cls()
        cmd.args = args
        cmd.start()
    assert calls == [("head", ["-n", "2", "a"]), ("tail", ["-n", "3", "b"])]


def test_boot_offset_is_stable_per_host_and_several_days():
    offsets = {patch.boot_offset_seconds(f"host-{i}") for i in range(200)}
    assert len(offsets) > 100, "hosts must not all share one uptime"
    assert min(offsets) >= 3 * 86400 and max(offsets) < 27 * 86400
    assert patch.boot_offset_seconds("web-01") == patch.boot_offset_seconds("web-01")


def test_uptime_is_offset_plus_real_elapsed_time():
    base = patch.boot_offset_seconds("web-01")
    assert patch.uptime_seconds("web-01", now=1100.0, start=1000.0) == base + 100.0
    assert patch.uptime_seconds("web-01", now=900.0, start=1000.0) == base  # clock step back


def test_proc_uptime_has_the_two_field_format():
    text = patch.proc_uptime_text(1234567.891).decode()
    up, idle = text.split()
    assert text.endswith("\n") and up == "1234567.89"
    assert 0 < float(idle) < 2 * float(up)


def test_shell_protocol_patch_replaces_uptime(monkeypatch):
    monkeypatch.setenv("COWRIE_HONEYPOT_HOSTNAME", "web-01")

    class HoneyPotBaseProtocol:
        def uptime(self):
            return 5.0  # container start: seconds

    module = types.ModuleType("cowrie.shell.protocol")
    module.HoneyPotBaseProtocol = HoneyPotBaseProtocol  # type: ignore[attr-defined]
    patch.patch_shell_protocol(module)
    assert HoneyPotBaseProtocol().uptime() >= patch.boot_offset_seconds("web-01")


def test_shell_fs_patch_serves_proc_uptime_only(monkeypatch):
    monkeypatch.setenv("COWRIE_HONEYPOT_HOSTNAME", "web-01")

    class HoneyPotFilesystem:
        def resolve_path(self, target, cwd):
            return target

        def file_contents(self, target):
            return b""  # Cowrie serves /proc/uptime as an empty file

    module = types.ModuleType("cowrie.shell.fs")
    module.HoneyPotFilesystem = HoneyPotFilesystem  # type: ignore[attr-defined]
    patch.patch_shell_fs(module)
    fs = HoneyPotFilesystem()
    assert float(fs.file_contents("/proc/uptime").split()[0]) >= patch.boot_offset_seconds("web-01")
    assert fs.file_contents("/proc/meminfo") == b""


def test_patches_are_registered_for_the_cowrie_modules():
    assert {"cowrie.commands.fs", "cowrie.shell.protocol", "cowrie.shell.fs"} <= set(patch._PATCHES)


# ── bait ────────────────────────────────────────────────────────────────────


def _base() -> bytes:
    return pickle.dumps(
        ["/", 1, 0, 0, 0, 0o40755, 0, [["etc", 1, 0, 0, 4096, 0o40755, 0, [], None, None]], None, None],
        protocol=4,
    )  # fmt: skip


def _build(credential=None, seed="seed", persona="debian_12"):
    p = _PERSONAS[persona]
    return cf.load_fs(cf.build_persona_fs(_base(), p, "web-01", seed, credential)), cf.username_for(
        p, seed
    )


@pytest.mark.parametrize("persona", list(_PERSONAS))
def test_tracked_credential_is_in_history_and_my_cnf(persona):
    pair = ("gitlab_f019", "26wJh#f$BgZiv56V")
    root, user = _build(pair, persona=persona)
    history = cf._read(root, f"/home/{user}/.bash_history")
    cnf = cf._read(root, f"/home/{user}/.my.cnf")
    assert "mysql -u gitlab_f019 '-p26wJh#f$BgZiv56V' -h db1.internal\n" in history
    assert history.endswith("cd ~\nexit\n")
    assert 'user=gitlab_f019\npassword="26wJh#f$BgZiv56V"\n' in cnf
    assert cf._walk(root, f"/home/{user}/.my.cnf")[cf.A_MODE] == 0o100600


def test_without_a_token_the_same_files_carry_a_stable_decoy():
    a, user = _build(None)
    b, _ = _build(None)
    decoy_user, decoy_pw = cf.bait_credential("seed")
    assert decoy_user in cf._read(a, f"/home/{user}/.my.cnf")
    assert cf._read(a, f"/home/{user}/.my.cnf") == cf._read(b, f"/home/{user}/.my.cnf")
    assert cf._read(a, f"/home/{user}/.bash_history") == cf._read(b, f"/home/{user}/.bash_history")
    assert decoy_pw in cf._read(a, f"/home/{user}/.bash_history")
    assert cf.bait_credential("other") != cf.bait_credential("seed")


def test_bait_is_deterministic_and_sizes_agree_with_content():
    pair = ("u", "p w")
    root1, user = _build(pair)
    root2, _ = _build(pair)
    assert cf.bait_files(user, "/h", pair) == cf.bait_files(user, "/h", pair)
    for path in (f"/home/{user}/.my.cnf", f"/home/{user}/.bash_history"):
        n1, n2 = cf._walk(root1, path), cf._walk(root2, path)
        assert n1[cf.A_CONTENTS] == n2[cf.A_CONTENTS]
        assert n1[cf.A_SIZE] == len(n1[cf.A_CONTENTS])
    assert "'-pp w'" in cf._read(root1, f"/home/{user}/.bash_history")


def test_a_different_token_changes_the_bait():
    a, user = _build(("u1", "p1"))
    b, _ = _build(("u2", "p2"))
    assert cf._read(a, f"/home/{user}/.my.cnf") != cf._read(b, f"/home/{user}/.my.cnf")


@pytest.mark.parametrize("persona", list(_PERSONAS))
def test_the_bait_is_also_in_roots_home_because_that_is_who_attackers_log_in_as(persona):
    """The first run had 105,066 successful logins as `root` and 70,460 as `admin`; the persona's own
    user (`appuser`, `deploy`...) never appears. Bait only under /home/<user> was never read by anyone."""
    pair = ("gitlab_f019", "26wJh#f$BgZiv56V")
    root, user = _build(pair, persona=persona)

    history = cf._read(root, "/root/.bash_history")
    cnf = cf._read(root, "/root/.my.cnf")
    assert "mysql -u gitlab_f019 '-p26wJh#f$BgZiv56V' -h db1.internal\n" in history
    assert 'user=gitlab_f019\npassword="26wJh#f$BgZiv56V"\n' in cnf
    node = cf._walk(root, "/root/.my.cnf")
    assert node[cf.A_MODE] == 0o100600 and node[cf.A_UID] == 0, "root's own, mode 600"
    assert node[cf.A_SIZE] == len(cnf.encode()), "ls -l and cat agree"
