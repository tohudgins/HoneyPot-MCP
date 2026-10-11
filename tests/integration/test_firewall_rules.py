"""The honeypot host firewall, loaded into a real Linux kernel and probed with real packets.

`tests/unit/test_hardening_firewall.py` pins what the ruleset *text* must contain. Whether the
kernel accepts it (nft 1.0.2, the version Ubuntu 22.04 ships), whether the redirect works, whether
a listener nobody planned is really unreachable, and whether the service user really cannot
connect out can only be shown by sending packets. Two containers on a private network: a target
(NET_ADMIN, runs nftables and some listeners) and an attacker. Opt-in via `RUN_DOCKER_TESTS=1`;
needs a Linux Docker daemon (Docker Desktop's VM is one) and network access to build the image once.

Not covered here, and verified by hand on a real dockerd instead (docs/HARDENING.md): the rules on
Docker's own bridges (`docker0`, `br-*`) for container egress.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap
import uuid

import pytest

from honeypot_mcp.hardening.firewall import FirewallSpec, parse_ports, render

IMAGE = "hp-fw-it:1"
DOCKERFILE = textwrap.dedent(
    """\
    FROM ubuntu:22.04
    RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \\
        nftables netcat-openbsd python3 iproute2 util-linux >/dev/null \\
     && rm -rf /var/lib/apt/lists/* && useradd -r -s /usr/sbin/nologin honeypot
    """
)


def _docker_available() -> bool:
    return shutil.which("docker") is not None and (
        subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0
    )


skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs a Linux Docker daemon and RUN_DOCKER_TESTS=1",
)


def sh(*cmd: str, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check)


def _spec(**overrides) -> FirewallSpec:
    tcp, udp, redirects = parse_ports("3389,80>8080,110>1110")
    base = {"admin_port": 2200, "tcp_ports": tcp, "udp_ports": udp, "redirects": redirects}
    return FirewallSpec(**{**base, **overrides})


# Ports something listens on in the target: three honeypot engines, the admin sshd, and a spread of
# services that must NOT be reachable (control plane, metrics, canary, docker api, ssh).
_LISTENING = (8080, 3389, 1110, 2200, 8000, 18443, 19090, 18888, 2375, 22, 9999)
_LISTENER = textwrap.dedent(
    """\
    import socket, threading, time
    def serve(port):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port)); s.listen(128)
        while True:
            c, _ = s.accept(); c.sendall(b"PORT %d\\n" % port); c.close()
    for p in PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    time.sleep(3600)
    """
)


class Lab:
    def __init__(self) -> None:
        tag = uuid.uuid4().hex[:8]
        self.net, self.target, self.attacker = f"hpfw-{tag}", f"hpfw-t-{tag}", f"hpfw-a-{tag}"

    def start(self) -> None:
        if sh("docker", "image", "inspect", IMAGE, check=False).returncode != 0:
            subprocess.run(
                ["docker", "build", "-q", "-t", IMAGE, "-"],
                input=DOCKERFILE,
                text=True,
                check=True,
                capture_output=True,
                timeout=900,
            )
        sh("docker", "network", "create", self.net)
        sh("docker", "run", "-d", "--name", self.target, "--network", self.net,
           "--cap-add", "NET_ADMIN", IMAGE, "sleep", "3600")  # fmt: skip
        sh("docker", "run", "-d", "--name", self.attacker, "--network", self.net,
           "--cap-add", "NET_ADMIN", IMAGE, "sleep", "3600")  # fmt: skip
        self.target_ip = self._ip(self.target)
        self.attacker_ip = self._ip(self.attacker)
        script = f"PORTS = {_LISTENING!r}\n" + _LISTENER
        subprocess.run(["docker", "exec", "-i", self.target, "bash", "-c", "cat > /l.py"],
                       input=script, text=True, check=True, capture_output=True)  # fmt: skip
        sh("docker", "exec", "-d", self.target, "python3", "/l.py")
        # A listener on the attacker, for the service-user egress test.
        subprocess.run(["docker", "exec", "-i", self.attacker, "bash", "-c", "cat > /l.py"],
                       input="PORTS = (443, 22, 80)\n" + _LISTENER, text=True, check=True,
                       capture_output=True)  # fmt: skip
        sh("docker", "exec", "-d", self.attacker, "python3", "/l.py")

    def _ip(self, name: str) -> str:
        template = f'{{{{(index .NetworkSettings.Networks "{self.net}").IPAddress}}}}'
        return sh("docker", "inspect", "-f", template, name).stdout.strip()

    def load(self, spec: FirewallSpec) -> None:
        text = render(spec)
        subprocess.run(["docker", "exec", "-i", self.target, "bash", "-c", "cat > /hp.nft"],
                       input=text, text=True, check=True, capture_output=True)  # fmt: skip
        sh("docker", "exec", self.target, "nft", "-c", "-f", "/hp.nft")
        sh("docker", "exec", self.target, "nft", "-f", "/hp.nft")

    def probe(
        self,
        port: int,
        *,
        source: str | None = None,
        dest: str | None = None,
        as_user: str | None = None,
    ) -> bool:
        """True if a TCP connection from `source` (default: the attacker) to `dest`:port answers."""
        container = source or self.attacker
        address = dest or self.target_ip
        cmd = f"exec 3<>/dev/tcp/{address}/{port} && head -c 4 <&3"
        argv = ["docker", "exec", container]
        if as_user:
            argv += ["setpriv", f"--reuid={as_user}", f"--regid={as_user}", "--clear-groups"]
        argv += ["timeout", "3", "bash", "-c", cmd]
        return subprocess.run(argv, capture_output=True, timeout=30).returncode == 0

    def close(self) -> None:
        for name in (self.target, self.attacker):
            sh("docker", "rm", "-f", name, check=False)
        sh("docker", "network", "rm", self.net, check=False)


@pytest.fixture(scope="module")
def lab():
    laboratory = Lab()
    try:
        laboratory.start()
        yield laboratory
    finally:
        laboratory.close()


@skip_docker
def test_only_the_planned_ports_answer_even_though_other_services_are_listening(lab):
    """Nine things listen in the target; four are honeypot/admin ports. The rest (the control
    plane, metrics, the canary server, the Docker API, port 22, a stray service) are all up and
    must be unreachable: the firewall, not the services' bind addresses, is the second line."""
    lab.load(_spec())
    answers = {port: lab.probe(port) for port in (*_LISTENING, 80, 110)}
    reachable = {port for port, ok in answers.items() if ok}
    # 8080 and 1110 are listening too but exist only as the targets of 80 and 110: reachable through
    # the redirect, not directly (a port scan must not find a second POP3 beside the first).
    assert reachable == {3389, 2200, 80, 110}, answers


@skip_docker
def test_honeypot_ports_are_never_rate_limited_but_admin_ssh_is(lab):
    lab.load(_spec())
    honeypot = sum(lab.probe(80) for _ in range(25))
    assert honeypot == 25, "an attacker must be able to hammer a honeypot port"
    admin = [lab.probe(2200) for _ in range(14)]
    assert sum(admin) >= 5, "a normal login must always get through"
    assert not all(admin), "the per-source meter must cut off a sprayer on the admin port"


@skip_docker
def test_an_admin_allow_list_locks_everyone_else_out_and_lets_the_operator_in(lab):
    lab.load(_spec(admin_allow=(f"{lab.attacker_ip}/32",)))
    assert lab.probe(2200), "the operator's address is allowed"
    assert lab.probe(80), "honeypot ports ignore the allow-list"
    lab.load(_spec(admin_allow=("203.0.113.0/24",)))
    assert not lab.probe(2200), "everyone else is refused"
    assert lab.probe(80)


@skip_docker
def test_the_service_user_can_answer_and_open_https_but_cannot_scan_or_connect_out(lab):
    """A hijacked honeypot process runs as this user: it must not be able to attack anything."""
    lab.load(_spec())
    # (nothing here depends on DNS: the destinations are addresses)
    assert lab.probe(443, source=lab.target, dest=lab.attacker_ip, as_user="honeypot"), (
        "HTTPS allowed"
    )
    assert not lab.probe(22, source=lab.target, dest=lab.attacker_ip, as_user="honeypot")
    assert not lab.probe(80, source=lab.target, dest=lab.attacker_ip, as_user="honeypot")
    assert lab.probe(22, source=lab.target, dest=lab.attacker_ip), (
        "root and the admin are unrestricted"
    )


@skip_docker
def test_loading_is_repeatable_and_leaves_other_tables_alone(lab):
    sh("docker", "exec", lab.target, "nft", "add", "table", "inet", "someone_else")
    sh(
        "docker",
        "exec",
        lab.target,
        "nft",
        "add",
        "chain",
        "inet",
        "someone_else",
        "c",
        "{ type filter hook input priority 50; }",
    )
    for _ in range(3):
        lab.load(_spec())
    tables = sh("docker", "exec", lab.target, "nft", "list", "tables").stdout
    assert "inet hp_fw" in tables and "inet someone_else" in tables
    assert tables.count("inet hp_fw") == 1
    # The ruleset is still correct after being loaded three times over.
    assert lab.probe(80) and not lab.probe(8000)
