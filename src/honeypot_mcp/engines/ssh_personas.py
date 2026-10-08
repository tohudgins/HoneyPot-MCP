"""SSH personas for the Cowrie honeypot.

Default Cowrie always advertises the same `ubuntu-server` / generic kernel,
which is the first thing a curious attacker checks. A persona is a coherent
bundle of (hostname pool, kernel version + build string, OpenSSH banner,
distro identity) that makes a Cowrie deploy look like a specific real-world
server rather than the same default identity on every spin-up.

A persona is picked at deploy time and persisted in the honeypot's `config`
dict (alongside a randomly-chosen hostname from the persona's pool), so the
identity is stable across restarts but two SSH honeypots in one project
pick different personas.

The values are passed to Cowrie via `COWRIE_<SECTION>_<OPTION>` env vars
that override the baseline `cowrie.cfg`.

Add a persona by appending to `_PERSONAS`. Keep the bundle internally
consistent — a Debian persona shouldn't claim an Ubuntu kernel build string,
because mismatched fingerprint surfaces is itself a fingerprint.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class SSHPersona:
    id: str
    # Multiple plausible hostnames — engine picks one at deploy and pins it.
    hostname_pool: tuple[str, ...]
    kernel_version: str
    kernel_build_string: str
    hardware_platform: str
    operating_system: str
    distro_pretty_name: str
    # Real OpenSSH banner format: SSH-2.0-OpenSSH_<ver> <distro-build>.
    # Attackers absolutely fingerprint on this.
    ssh_version_string: str


_PERSONAS: dict[str, SSHPersona] = {
    "ubuntu_22_04": SSHPersona(
        id="ubuntu_22_04",
        hostname_pool=("web-prod-01", "api-gateway-02", "app-server-03", "ubuntu-srv"),
        kernel_version="5.15.0-91-generic",
        kernel_build_string="#91-Ubuntu SMP Mon Aug 14 12:51:52 UTC 2023",
        hardware_platform="x86_64",
        operating_system="GNU/Linux",
        distro_pretty_name="Ubuntu 22.04.3 LTS",
        ssh_version_string="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
    ),
    "ubuntu_20_04": SSHPersona(
        id="ubuntu_20_04",
        hostname_pool=("db-prod-01", "cache-redis-01", "worker-02", "backend-01"),
        kernel_version="5.4.0-150-generic",
        kernel_build_string="#167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023",
        hardware_platform="x86_64",
        operating_system="GNU/Linux",
        distro_pretty_name="Ubuntu 20.04.6 LTS",
        ssh_version_string="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9",
    ),
    "debian_12": SSHPersona(
        id="debian_12",
        hostname_pool=("srv-internal", "mail-relay-01", "git-server", "debian-srv"),
        kernel_version="6.1.0-13-amd64",
        kernel_build_string="#1 SMP PREEMPT_DYNAMIC Debian 6.1.55-1 (2023-09-29)",
        hardware_platform="x86_64",
        operating_system="GNU/Linux",
        distro_pretty_name="Debian GNU/Linux 12 (bookworm)",
        ssh_version_string="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
    ),
    "rhel_8": SSHPersona(
        id="rhel_8",
        hostname_pool=("rhel-prod-01", "oracle-app", "corp-finance-01", "redhat-srv"),
        kernel_version="4.18.0-477.27.1.el8_8.x86_64",
        kernel_build_string="#1 SMP Wed Sep 20 15:55:39 EDT 2023",
        hardware_platform="x86_64",
        operating_system="GNU/Linux",
        distro_pretty_name="Red Hat Enterprise Linux 8.8 (Ootpa)",
        ssh_version_string="SSH-2.0-OpenSSH_8.0",
    ),
}


def get_persona(persona_id: str | None) -> SSHPersona:
    if persona_id and persona_id in _PERSONAS:
        return _PERSONAS[persona_id]
    return _PERSONAS["ubuntu_22_04"]


def pick_random_persona_id() -> str:
    return secrets.choice(list(_PERSONAS.keys()))


def all_persona_ids() -> list[str]:
    return list(_PERSONAS.keys())


def pick_hostname(persona: SSHPersona) -> str:
    return secrets.choice(persona.hostname_pool)


# What the persona's OpenSSH offers, narrowed to what Twisted conch implements, in OpenSSH's own
# order. Twisted has no chacha20-poly1305, AES-GCM, `-etm` MACs or sntrup761, so the offer is a
# strict *subset* of the real one: every name here is one OpenSSH 8.0-9.2 sends by default, and
# nothing OpenSSH dropped (3des-cbc, cast128-cbc, hmac-md5, diffie-hellman-group14-sha1, a bare
# ssh-rsa host key on 8.8+) is, which is what made `ssh-audit` contradict the banner.
_CIPHERS = "aes128-ctr,aes192-ctr,aes256-ctr"
_MACS = "hmac-sha2-256,hmac-sha2-512,hmac-sha1"
_COMPRESSION = "none,zlib@openssh.com"
_KEX = (
    "curve25519-sha256,curve25519-sha256@libssh.org,"
    "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521"
)
_HOSTKEYS_8_8_PLUS = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
# Before 8.8 `ssh-rsa` (SHA-1) was still a default host-key algorithm.
_HOSTKEYS_BEFORE_8_8 = "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519"


def hostkey_algorithms(persona: SSHPersona) -> str:
    """The host-key signature algorithms the persona's OpenSSH offers (comma list)."""
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", persona.ssh_version_string)
    version = (int(match.group(1)), int(match.group(2))) if match else (9, 0)
    return _HOSTKEYS_8_8_PLUS if version >= (8, 8) else _HOSTKEYS_BEFORE_8_8


def telnet_issue(persona: SSHPersona) -> str:
    """What a telnetd prints before `login:`: the release as `/etc/issue.net` words it, without
    the parenthesised codename `os-release` adds ("Debian GNU/Linux 12", not "... (bookworm)")."""
    return re.sub(r"\s*\([^)]*\)\s*$", "", persona.distro_pretty_name)


def cowrie_env_vars(
    persona: SSHPersona, hostname: str, *, allow_egress: bool = False
) -> dict[str, str]:
    """Build the `COWRIE_*` environment dict that Cowrie reads at container
    start. Sets both `COWRIE_HOSTNAME` (legacy) and `COWRIE_HONEYPOT_HOSTNAME`
    (modern) for compatibility across Cowrie versions."""
    return {
        "COWRIE_HOSTNAME": hostname,
        "COWRIE_HONEYPOT_HOSTNAME": hostname,
        # Kernel / platform / OS identity live in Cowrie's [shell] section. They
        # were once set as COWRIE_HONEYPOT_* (the wrong section), which Cowrie
        # ignores, so `uname` kept reporting the image's own Debian kernel whatever
        # persona was chosen — verified against a live container.
        "COWRIE_SHELL_KERNEL_VERSION": persona.kernel_version,
        "COWRIE_SHELL_KERNEL_BUILD_STRING": persona.kernel_build_string,
        "COWRIE_SHELL_HARDWARE_PLATFORM": persona.hardware_platform,
        "COWRIE_SHELL_OPERATING_SYSTEM": persona.operating_system,
        "COWRIE_SSH_VERSION": persona.ssh_version_string,
        # ── Route Cowrie's JSON event stream to stdout ──────────────────
        # `SSHEngine._ingest_logs` reads `docker logs` and parses each line as
        # JSON. Cowrie's stdout is Twisted's *text* log, so without these the
        # parser rejects every line and the honeypot captures nothing while
        # looking perfectly healthy.
        #
        # `logtype` matters as much as the path. The image default is
        # `rotating`, which wraps the file in Twisted's LogFile — that seeks
        # on open and dies with EBADF/"Illegal seek" against a pipe, taking
        # the whole jsonlog plugin down with it. `plain` uses a bare
        # `open(path, "w")`, which a pipe accepts.
        "COWRIE_HONEYPOT_LOGTYPE": "plain",
        "COWRIE_OUTPUT_JSONLOG_ENABLED": "true",
        "COWRIE_OUTPUT_JSONLOG_LOGFILE": "/proc/self/fd/1",
        # Cowrie's wget/curl emulation really downloads (that is how it captures
        # malware), so an attacker chooses what this container fetches. Cap the
        # size of what it will keep; the default is 10 MiB.
        "COWRIE_HONEYPOT_DOWNLOAD_LIMIT_SIZE": "2097152",
        # Algorithm offer: ciphers, MACs and compression are `[ssh]` options; key exchange,
        # host keys and the telnet opening are not, so `engines/cowrie_sitecustomize.py`
        # (delivered into the container with the persona filesystem) reads the HONEYPOT_*
        # variables below. PYTHONPATH replaces the image's, so it names that directory first
        # and then the image's own `/cowrie/cowrie-git/src`.
        "COWRIE_SSH_CIPHERS": _CIPHERS,
        "COWRIE_SSH_MACS": _MACS,
        "COWRIE_SSH_COMPRESSION": _COMPRESSION,
        "HONEYPOT_SSH_KEX": _KEX,
        "HONEYPOT_SSH_HOSTKEYS": hostkey_algorithms(persona),
        "HONEYPOT_TELNET_ISSUE": telnet_issue(persona),
        "PYTHONPATH": "/cowrie/persona/patch:/cowrie/cowrie-git/src",
        **({} if allow_egress else {"COWRIE_HONEYPOT_OUT_ADDR": "127.0.0.1"}),
    }
