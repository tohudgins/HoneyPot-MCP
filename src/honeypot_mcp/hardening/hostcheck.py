"""Pre-flight checks for the *host* a honeypot runs on (Linux only).

`preflight.py` judges the application (token, bind addresses, disk, sensors). These judge what
an attacker meets before the application: what the machine listens on, whether the firewall is
loaded, whether the service can reach Docker as root, whether sshd is hardened. Each read is
done in a way that works without root where it can, and says so when it cannot, rather than
reporting a pass for something it could not look at.

Pure parsers (`parse_proc_net`, `parse_sshd_config`, ...) take text, so the logic is tested
without a Linux host.
"""

from __future__ import annotations

import contextlib
import grp
import ipaddress
import os
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

from honeypot_mcp.hardening.firewall import TABLE as FIREWALL_TABLE
from honeypot_mcp.preflight import FAIL, PASS, SKIP, WARN, Check

GUARD_SOCKET = "/run/honeypot-docker/docker.sock"
SERVICE_USER = "honeypot"
UNIT_PATH = Path("/etc/systemd/system/honeypot-mcp.service")

# Listening state in /proc/net/tcp*, and the unconnected state of a bound UDP socket.
_TCP_LISTEN, _UDP_BOUND = "0A", "07"


def _decode_address(hex_address: str) -> str:
    raw = bytes.fromhex(hex_address)
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw[::-1]))
    words = b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4))
    return str(ipaddress.IPv6Address(words))


def parse_proc_net(text: str, proto: str) -> list[tuple[str, int, str]]:
    """`(address, port, proto)` of every listening socket in a /proc/net/{tcp,tcp6,udp,udp6} dump."""
    wanted = _TCP_LISTEN if proto == "tcp" else _UDP_BOUND
    out: list[tuple[str, int, str]] = []
    for row in text.splitlines()[1:]:
        fields = row.split()
        if len(fields) < 4 or fields[3] != wanted:
            continue
        address, _, port = fields[1].rpartition(":")
        try:
            out.append((_decode_address(address), int(port, 16), proto))
        except ValueError:
            continue
    return out


def _is_loopback(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def public_listeners(proc_net: dict[str, str]) -> set[tuple[int, str]]:
    """`(port, proto)` of every socket that listens on a non-loopback address."""
    out: set[tuple[int, str]] = set()
    for name, text in proc_net.items():
        for address, port, proto in parse_proc_net(
            text, "tcp" if name.startswith("tcp") else "udp"
        ):
            if not _is_loopback(address):
                out.add((port, proto))
    return out


def _read_proc_net() -> dict[str, str]:
    out = {}
    for name in ("tcp", "tcp6", "udp", "udp6"):
        with contextlib.suppress(OSError):
            out[name] = Path(f"/proc/net/{name}").read_text()
    return out


def check_public_listeners(
    expected: Iterable[tuple[int, str]],
    *,
    proc_net: dict[str, str] | None = None,
) -> Check:
    """Anything listening on a public address that is not a planned honeypot or the admin port.

    This is the check that catches the things nobody planned: a metrics endpoint bound to the
    world by a typo, the canary callback server on 0.0.0.0, a database an installer started.
    """
    name = "public listeners"
    data = proc_net if proc_net is not None else _read_proc_net()
    if not data:
        return Check(name, SKIP, "cannot read /proc/net (not Linux)")
    allowed = set(expected)
    stray = sorted(public_listeners(data) - allowed)
    if not stray:
        return Check(name, PASS, f"only the {len(allowed)} planned ports listen publicly")
    shown = ", ".join(f"{port}/{proto}" for port, proto in stray[:12])
    return Check(
        name,
        FAIL,
        f"unplanned public listeners: {shown}" + (" ..." if len(stray) > 12 else ""),
        "Find the owner with `ss -tulnp | grep :PORT`; bind it to 127.0.0.1 or stop it. "
        "(The firewall also drops it, but a listener nobody planned is a configuration error.)",
    )


def check_firewall(run: Callable[[list[str]], tuple[int, str]] | None = None) -> Check:
    """The `inet hp_fw` table is loaded and its input chain defaults to drop."""
    name = "host firewall"
    runner = run or _run
    code, out = runner(["nft", "list", "table", "inet", FIREWALL_TABLE])
    if code == 127:
        return Check(name, WARN, "nft is not installed", "apt-get install nftables")
    if code != 0:
        if os.geteuid() != 0:
            return Check(name, SKIP, "cannot read the ruleset without root", "Run this as root.")
        return Check(
            name,
            FAIL,
            f"table inet {FIREWALL_TABLE} is not loaded",
            "deploy/harden-host.sh finalize ... (it loads and persists the ruleset)",
        )
    if "policy drop" not in out:
        return Check(
            name, FAIL, "the input chain does not default to drop", "Re-render and reload."
        )
    return Check(name, PASS, f"table inet {FIREWALL_TABLE} loaded, input policy drop")


def check_service_docker_access(
    *,
    docker_members: list[str] | None = None,
    unit_text: str | None = None,
) -> Check:
    """The honeypot service must not hold root-equivalent Docker access."""
    name = "service docker access"
    if docker_members is None:
        try:
            docker_members = list(grp.getgrnam("docker").gr_mem)
        except KeyError:
            docker_members = []
    if SERVICE_USER in docker_members:
        return Check(
            name,
            FAIL,
            f"{SERVICE_USER} is in the docker group: a bug in the service reaches Docker, which is root",
            f"gpasswd -d {SERVICE_USER} docker; use the Docker guard (deploy/honeypot-docker-guard.service)",
        )
    if unit_text is None:
        try:
            unit_text = UNIT_PATH.read_text()
        except OSError:
            return Check(name, SKIP, f"{UNIT_PATH} is not installed")
    if GUARD_SOCKET not in unit_text:
        return Check(
            name,
            WARN,
            "the service unit does not use the Docker guard socket",
            "Install deploy/honeypot-mcp.service (DOCKER_HOST points at the guard).",
        )
    return Check(name, PASS, f"{SERVICE_USER} is not in the docker group; the unit uses the guard")


# Run in a child process so it can run as the service user: the guard serves only that user, so
# probing it as root (what an operator running preflight is) would be refused, correctly.
_GUARD_PROBE = r"""
import socket, sys
def call(request):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(sys.argv[1])
        sock.sendall(request)
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
    return data.split(b"\r\n", 1)[0].decode()
print(call(b"GET /_ping HTTP/1.1\r\nHost: x\r\n\r\n"))
print(call(b"GET /info HTTP/1.1\r\nHost: x\r\n\r\n"))
"""


def check_docker_guard(
    socket_path: str = GUARD_SOCKET,
    *,
    as_user: str | None = None,
    auto_user: bool = True,
) -> Check:
    """The guard answers a ping and refuses a daemon-wide call: proves it is the guard, not a
    bare Docker socket, on the other end. As root (and `auto_user`) the probe runs as the service
    user, the only one the guard serves."""
    name = "docker guard"
    if not Path(socket_path).exists():
        return Check(name, SKIP, f"{socket_path} not present (guard not running)")
    if as_user is None and auto_user and os.geteuid() == 0:
        as_user = SERVICE_USER
    cmd = [sys.executable, "-c", _GUARD_PROBE, socket_path]
    if as_user:
        cmd = ["runuser", "-u", as_user, "--", *cmd]
    elif os.geteuid() != 0 and not os.access(socket_path, os.W_OK):
        return Check(name, SKIP, "the guard socket is only open to the service user: run as root")
    code, out = _run(cmd)
    answers = out.strip().splitlines()
    if code != 0 or len(answers) != 2:
        return Check(
            name,
            FAIL,
            "cannot talk to the guard as the service user",
            "systemctl status honeypot-docker-guard; journalctl -u honeypot-docker-guard",
        )
    ping, info = answers
    if not ping.startswith("HTTP/1.1 200"):
        return Check(
            name,
            FAIL,
            "the guard does not reach Docker",
            "systemctl status docker honeypot-docker-guard",
        )
    if not info.startswith("HTTP/1.1 403"):
        return Check(
            name,
            FAIL,
            "the socket answered a daemon-wide call: it is not a guard",
            "DOCKER_HOST must point at the guard socket, not /var/run/docker.sock",
        )
    return Check(name, PASS, "forwards the engine's calls, refuses everything else")


def parse_sshd_config(text: str) -> dict[str, list[str]]:
    """`sshd -T` output (lowercase `key value`) as {key: [values]}."""
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            out.setdefault(key.lower(), []).append(value.strip())
    return out


def judge_sshd(cfg: dict[str, list[str]], honeypot_ports: Iterable[int]) -> list[str]:
    """What is wrong with the effective sshd configuration, as short sentences."""
    problems: list[str] = []

    def one(key: str) -> str:
        return (cfg.get(key) or [""])[0].lower()

    if one("passwordauthentication") != "no":
        problems.append("password logins are enabled")
    if one("kbdinteractiveauthentication") not in ("no", ""):
        problems.append("keyboard-interactive logins are enabled")
    if one("permitrootlogin") not in ("no", "prohibit-password", "without-password"):
        problems.append("root may log in")
    if one("permitrootlogin") in ("prohibit-password", "without-password"):
        problems.append("root may log in with a key")
    if one("pubkeyauthentication") == "no":
        problems.append("public-key login is disabled")
    if not cfg.get("allowusers"):
        problems.append("AllowUsers is not set")
    if one("x11forwarding") == "yes":
        problems.append("X11 forwarding is enabled")
    if one("allowagentforwarding") == "yes":
        problems.append("agent forwarding is enabled")
    if one("allowtcpforwarding") in ("all", "remote", "yes") and one("allowtcpforwarding") != "yes":
        problems.append("remote TCP forwarding is enabled")
    if one("maxauthtries") and int(one("maxauthtries")) > 4:
        problems.append(f"MaxAuthTries is {one('maxauthtries')}")
    taken = set(honeypot_ports)
    clash = sorted(int(p) for p in cfg.get("port", []) if p.isdigit() and int(p) in taken)
    if clash:
        problems.append(f"sshd listens on honeypot port(s) {clash}")
    if "22" in cfg.get("port", []):
        problems.append("sshd is on the default port 22 (it is the port every scanner tries)")
    return problems


def check_sshd(honeypot_ports: Iterable[int], *, text: str | None = None) -> Check:
    name = "sshd hardening"
    if text is None:
        if os.geteuid() != 0:
            return Check(name, SKIP, "reading the effective sshd configuration needs root")
        code, text = _run(["sshd", "-T"])
        if code != 0:
            return Check(name, SKIP, "sshd -T failed (is openssh-server installed?)")
    problems = judge_sshd(parse_sshd_config(text), honeypot_ports)
    if not problems:
        return Check(name, PASS, "key-only, non-root, allow-listed user, tunnel forwarding only")
    return Check(
        name,
        FAIL,
        "; ".join(problems),
        "deploy/harden-host.sh prepare writes /etc/ssh/sshd_config.d/10-honeypot-host.conf",
    )


# Values the host-hardening script sets and a scan would otherwise read as a weak host.
_SYSCTLS = {
    "net/ipv4/conf/all/rp_filter": ("1", "reverse-path filtering"),
    "net/ipv4/conf/all/accept_redirects": ("0", "ICMP redirects ignored"),
    "net/ipv4/conf/all/send_redirects": ("0", "ICMP redirects not sent"),
    "net/ipv4/conf/all/accept_source_route": ("0", "source routing refused"),
    "net/ipv4/tcp_syncookies": ("1", "SYN cookies"),
    "kernel/kptr_restrict": ("2", "kernel pointers hidden"),
    "kernel/dmesg_restrict": ("1", "dmesg restricted"),
    "kernel/yama/ptrace_scope": ("1", "ptrace restricted"),
    "kernel/unprivileged_bpf_disabled": ("1", "unprivileged bpf disabled"),
}


def check_sysctl(read: Callable[[str], str | None] | None = None) -> Check:
    name = "kernel hardening"

    def default_read(key: str) -> str | None:
        try:
            return Path("/proc/sys", key).read_text().strip()
        except OSError:
            return None

    reader = read or default_read
    if reader("kernel/kptr_restrict") is None:
        return Check(name, SKIP, "cannot read /proc/sys (not Linux)")
    weak = []
    for key, (want, label) in _SYSCTLS.items():
        have = reader(key)
        if have is None:
            continue
        # ptrace_scope 2 and 3 are stricter than the 1 asked for; the rest are exact.
        ok = have == want or (key.endswith("ptrace_scope") and have in ("1", "2", "3"))
        ok = ok or (key.endswith("kptr_restrict") and have == "2")
        if not ok:
            weak.append(f"{label} ({key.replace('/', '.')}={have}, want {want})")
    if not weak:
        return Check(name, PASS, "sysctl hardening applied")
    return Check(
        name,
        WARN,
        "; ".join(weak[:6]),
        "deploy/harden-host.sh prepare writes /etc/sysctl.d/90-honeypot-host.conf",
    )


def check_auto_updates(text: str | None = None) -> Check:
    name = "security updates"
    if text is None:
        try:
            text = Path("/etc/apt/apt.conf.d/20auto-upgrades").read_text()
        except OSError:
            return Check(
                name,
                WARN,
                "unattended-upgrades is not configured",
                "apt-get install unattended-upgrades",
            )
    if 'Unattended-Upgrade "1"' in text:
        return Check(name, PASS, "unattended security upgrades are enabled")
    return Check(
        name,
        WARN,
        "unattended security upgrades are off",
        "dpkg-reconfigure -plow unattended-upgrades",
    )


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""
    return proc.returncode, proc.stdout


def expected_listeners(
    listen_ports: Iterable[tuple[int, str]], admin_port: int | None
) -> set[tuple[int, str]]:
    """The `(port, proto)` pairs that may listen publicly: the planned honeypot ports (`both`
    means tcp and udp) and the admin SSH port."""
    out: set[tuple[int, str]] = set()
    for port, proto in listen_ports:
        if proto in ("tcp", "both"):
            out.add((port, "tcp"))
        if proto in ("udp", "both"):
            out.add((port, "udp"))
    if admin_port:
        out.add((admin_port, "tcp"))
    return out


def host_checks(
    listen_ports: list[tuple[int, str]], admin_port: int | None, honeypot_ports: Iterable[int]
) -> list[Check]:
    """Every host check, or one SKIP outside Linux."""
    if not sys.platform.startswith("linux"):
        return [Check("host hardening", SKIP, "host checks run on the Linux honeypot host only")]
    return [
        check_public_listeners(expected_listeners(listen_ports, admin_port)),
        check_firewall(),
        check_service_docker_access(),
        check_docker_guard(),
        check_sshd(honeypot_ports),
        check_sysctl(),
        check_auto_updates(),
    ]
