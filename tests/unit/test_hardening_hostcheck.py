"""The host checks tell the operator what an attacker would meet before the application does.

Each parser is fed real kernel and sshd output; each judgement is built from the bad host it
exists for and the good host that must pass. A check that can only say "pass" is worse than none.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import threading
from pathlib import Path

import pytest

from honeypot_mcp.hardening import hostcheck as hc
from honeypot_mcp.preflight import FAIL, PASS, SKIP, WARN

# /proc/net/tcp, as the kernel writes it (header line, then one socket per line).
TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0100007F:1F41 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
   3: 0F02000A:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4 1 0 100 0 0 10 0
"""
TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0D3D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5 1 0 100 0 0 10 0
   1: 00000000000000000000000001000000:2382 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6 1 0 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:2383 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7 1 0 100 0 0 10 0
"""
UDP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000:00A1 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 8 2 0
   1: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   102        0 9 2 0
   2: 0A00020F:E4D2 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 10 2 0
"""
NET = {"tcp": TCP, "tcp6": TCP6, "udp": UDP, "udp6": ""}


def test_proc_net_is_parsed_for_listeners_only_and_addresses_are_decoded():
    assert hc.parse_proc_net(TCP, "tcp") == [
        ("0.0.0.0", 80, "tcp"),
        ("127.0.0.1", 8000, "tcp"),  # the ESTABLISHED line (state 01) is not a listener
        ("10.0.2.15", 22, "tcp"),
    ]
    assert hc.parse_proc_net(TCP6, "tcp") == [
        ("::", 3389, "tcp"),
        ("::1", 9090, "tcp"),
        ("::ffff:127.0.0.1", 9091, "tcp"),
    ]
    assert hc.parse_proc_net(UDP, "udp") == [("0.0.0.0", 161, "udp"), ("127.0.0.1", 53, "udp")]
    assert hc.parse_proc_net("header only\n", "tcp") == []
    assert hc.parse_proc_net("h\n garbage line\n   0: zz:zz x x 0A\n", "tcp") == []


def test_only_sockets_on_non_loopback_addresses_are_public():
    assert hc.public_listeners(NET) == {(80, "tcp"), (22, "tcp"), (3389, "tcp"), (161, "udp")}
    assert (9091, "tcp") not in hc.public_listeners(NET), "an IPv4-mapped loopback is loopback"


def test_an_unplanned_public_listener_fails_and_a_planned_estate_passes():
    expected = hc.expected_listeners([(80, "tcp"), (3389, "tcp"), (161, "udp")], admin_port=22)
    assert hc.check_public_listeners(expected, proc_net=NET).status == PASS

    # The same host with the metrics port bound to the world by a typo.
    leaky = {
        **NET,
        "tcp": TCP + "   9: 00000000:2382 00000000:0000 0A 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
    }
    result = hc.check_public_listeners(expected, proc_net=leaky)
    assert result.status == FAIL and "9090/tcp" in result.detail and "ss -tulnp" in result.fix

    # A planned TCP port does not excuse the same number over UDP.
    assert (
        hc.check_public_listeners({(80, "tcp"), (22, "tcp"), (3389, "tcp")}, proc_net=NET).status
        == FAIL
    )
    assert hc.check_public_listeners(expected, proc_net={}).status == SKIP


def test_expected_listeners_expand_both_and_add_the_admin_port():
    assert hc.expected_listeners([(5060, "both"), (80, "tcp"), (53, "udp")], 2200) == {
        (5060, "tcp"),
        (5060, "udp"),
        (80, "tcp"),
        (53, "udp"),
        (2200, "tcp"),
    }
    assert hc.expected_listeners([], None) == set()


# ── sshd ─────────────────────────────────────────────────────────────────────────────────────

HARD = """\
port 2200
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
allowusers deploy
x11forwarding no
allowagentforwarding no
allowtcpforwarding local
maxauthtries 3
"""


def test_a_hardened_sshd_passes():
    assert hc.judge_sshd(hc.parse_sshd_config(HARD), honeypot_ports=[22, 80, 3389]) == []
    assert hc.check_sshd([22, 80], text=HARD).status == PASS


@pytest.mark.parametrize(
    ("replace", "problem"),
    [
        ("passwordauthentication no", "password logins"),
        ("kbdinteractiveauthentication no", "keyboard-interactive"),
        ("permitrootlogin no", "root may log in"),
        ("pubkeyauthentication yes", "public-key login is disabled"),
        ("allowusers deploy", "AllowUsers is not set"),
        ("x11forwarding no", "X11"),
        ("allowagentforwarding no", "agent forwarding"),
        ("allowtcpforwarding local", "remote TCP forwarding"),
        ("maxauthtries 3", "MaxAuthTries is 6"),
        ("port 2200", "default port 22"),
    ],
)
def test_each_way_sshd_can_be_weak_is_named(replace, problem):
    weak = {
        "passwordauthentication no": "passwordauthentication yes",
        "kbdinteractiveauthentication no": "kbdinteractiveauthentication yes",
        "permitrootlogin no": "permitrootlogin yes",
        "pubkeyauthentication yes": "pubkeyauthentication no",
        "allowusers deploy": "",
        "x11forwarding no": "x11forwarding yes",
        "allowagentforwarding no": "allowagentforwarding yes",
        "allowtcpforwarding local": "allowtcpforwarding all",
        "maxauthtries 3": "maxauthtries 6",
        "port 2200": "port 22",
    }[replace]
    result = hc.check_sshd([80], text=HARD.replace(replace, weak))
    assert result.status == FAIL and problem in result.detail, result.detail


def test_sshd_on_a_honeypot_port_and_root_by_key_are_flagged():
    assert "listens on honeypot port(s) [2200]" in hc.check_sshd([2200], text=HARD).detail
    assert (
        "root may log in with a key"
        in hc.check_sshd(
            [80], text=HARD.replace("permitrootlogin no", "permitrootlogin prohibit-password")
        ).detail
    )


def test_sshd_config_is_parsed_case_insensitively_with_repeated_keys():
    cfg = hc.parse_sshd_config("Port 22\nPort 2200\nAllowUsers a b\n\n")
    assert cfg == {"port": ["22", "2200"], "allowusers": ["a b"]}


# ── firewall, docker access, guard ───────────────────────────────────────────────────────────


def test_the_firewall_must_be_loaded_with_a_default_drop_input_chain():
    loaded = "table inet hp_fw {\n\tchain input {\n\t\ttype filter hook input priority -10; policy drop;\n\t}\n}\n"
    assert hc.check_firewall(lambda cmd: (0, loaded)).status == PASS
    assert (
        hc.check_firewall(lambda cmd: (0, loaded.replace("policy drop", "policy accept"))).status
        == FAIL
    )
    assert hc.check_firewall(lambda cmd: (127, "")).status == WARN, "nft missing"
    absent = hc.check_firewall(lambda cmd: (1, ""))
    expected = FAIL if os.geteuid() == 0 else SKIP
    assert absent.status == expected, "unreadable without root is SKIP, never a silent pass"


UNIT = "Environment=DOCKER_HOST=unix:///run/honeypot-docker/docker.sock\n"


def test_the_service_in_the_docker_group_is_a_root_compromise_waiting_for_a_bug():
    result = hc.check_service_docker_access(docker_members=["deploy", "honeypot"], unit_text=UNIT)
    assert result.status == FAIL and "gpasswd -d honeypot docker" in result.fix
    assert (
        hc.check_service_docker_access(docker_members=["hp-guard"], unit_text=UNIT).status == PASS
    )
    assert hc.check_service_docker_access(docker_members=[], unit_text="").status == WARN
    assert (
        hc.check_service_docker_access(docker_members=[], unit_text="Environment=X=1").status
        == WARN
    )


def _serve_unix(handler):
    """(socket path, stop function): an asyncio unix server on its own thread, because the check
    under test uses blocking sockets and would deadlock a server sharing its thread."""
    directory = tempfile.mkdtemp(prefix="hpc-")
    path = os.path.join(directory, "g.sock")
    loop = asyncio.new_event_loop()
    started = threading.Event()
    done: dict[str, asyncio.Event] = {}

    async def main() -> None:
        done["stop"] = asyncio.Event()
        server = await asyncio.start_unix_server(handler, path=path)
        started.set()
        await done["stop"].wait()
        server.close()
        await server.wait_closed()

    thread = threading.Thread(target=lambda: loop.run_until_complete(main()), daemon=True)
    thread.start()
    assert started.wait(5)

    def stop() -> None:
        loop.call_soon_threadsafe(done["stop"].set)
        thread.join(5)

    return path, stop


def test_the_guard_check_tells_a_guard_from_a_bare_docker_socket():
    async def guardlike(reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        ok = head.startswith(b"GET /_ping")
        status = b"200 OK" if ok else b"403 Forbidden"
        writer.write(b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    async def baredocker(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    async def dead(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    for handler, expected in ((guardlike, PASS), (baredocker, FAIL), (dead, FAIL)):
        path, stop = _serve_unix(handler)
        try:
            assert hc.check_docker_guard(path, auto_user=False).status == expected, handler.__name__
        finally:
            stop()
    assert hc.check_docker_guard("/nonexistent/g.sock").status == SKIP


def test_as_root_the_guard_is_probed_as_the_service_user_because_it_serves_no_one_else(monkeypatch):
    """Run as root, the first version of this check was refused by the guard (which serves only the
    honeypot user) and reported a healthy guard as broken."""
    seen: list[list[str]] = []

    def fake_run(cmd):
        seen.append(cmd)
        return 0, "HTTP/1.1 200 OK\nHTTP/1.1 403 Forbidden\n"

    path, stop = _serve_unix(lambda r, w: None)
    try:
        monkeypatch.setattr(hc, "_run", fake_run)
        monkeypatch.setattr(hc.os, "geteuid", lambda: 0)
        assert hc.check_docker_guard(path).status == PASS
        assert seen[0][:4] == ["runuser", "-u", "honeypot", "--"]
        seen.clear()
        monkeypatch.setattr(hc.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(hc.os, "access", lambda *a: False)
        assert hc.check_docker_guard(path).status == SKIP, "an unrelated user cannot probe it"
        assert seen == []
        monkeypatch.setattr(hc, "_run", lambda cmd: (1, ""))
        monkeypatch.setattr(hc.os, "geteuid", lambda: 0)
        assert hc.check_docker_guard(path).status == FAIL
    finally:
        stop()


# ── kernel and updates ───────────────────────────────────────────────────────────────────────

GOOD_SYSCTL = {
    "net/ipv4/conf/all/rp_filter": "1",
    "net/ipv4/conf/all/accept_redirects": "0",
    "net/ipv4/conf/all/send_redirects": "0",
    "net/ipv4/conf/all/accept_source_route": "0",
    "net/ipv4/tcp_syncookies": "1",
    "kernel/kptr_restrict": "2",
    "kernel/dmesg_restrict": "1",
    "kernel/yama/ptrace_scope": "2",
    "kernel/unprivileged_bpf_disabled": "1",
}


def test_sysctl_judgement_names_each_weak_setting_and_accepts_stricter_ptrace():
    assert hc.check_sysctl(GOOD_SYSCTL.get).status == PASS
    weak = {**GOOD_SYSCTL, "net/ipv4/conf/all/accept_redirects": "1", "kernel/kptr_restrict": "0"}
    result = hc.check_sysctl(weak.get)
    assert result.status == WARN
    assert "accept_redirects=1" in result.detail and "kptr_restrict=0" in result.detail
    assert hc.check_sysctl(lambda key: None).status == SKIP, "not Linux"
    # A kernel without a key (an older or hardened one) is not a weakness.
    partial = {k: v for k, v in GOOD_SYSCTL.items() if k != "kernel/yama/ptrace_scope"}
    assert hc.check_sysctl(partial.get).status == PASS


def test_unattended_upgrades_must_be_on():
    assert hc.check_auto_updates('APT::Periodic::Unattended-Upgrade "1";\n').status == PASS
    assert hc.check_auto_updates('APT::Periodic::Unattended-Upgrade "0";\n').status == WARN
    assert hc.check_auto_updates("").status == WARN


def test_off_linux_the_host_checks_are_one_skip(monkeypatch):
    monkeypatch.setattr(hc.sys, "platform", "darwin")
    out = hc.host_checks([(80, "tcp")], 22, [80])
    assert [c.status for c in out] == [SKIP]


def test_the_preflight_cli_takes_listen_ports_and_can_skip_host_checks(capsys):
    from honeypot_mcp import preflight as pf

    code = pf.main(
        ["--no-host-checks", "--listen-ports", "8080,1110/udp", "--admin-port", "2200", "--json"]
    )
    names = {c["name"] for c in __import__("json").loads(capsys.readouterr().out)}
    assert "public listeners" not in names and "host hardening" not in names
    assert code in (0, 1)
    pf.main(["--listen-ports", "8080", "--admin-port", "2200", "--json"])
    out = {c["name"]: c for c in __import__("json").loads(capsys.readouterr().out)}
    assert ("host hardening" in out) or (
        "public listeners" in out
    )  # one SKIP off Linux, the checks on it
    assert Path(hc.__file__).exists()
