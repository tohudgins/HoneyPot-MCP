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


def cowrie_env_vars(persona: SSHPersona, hostname: str) -> dict[str, str]:
    """Build the `COWRIE_*` environment dict that Cowrie reads at container
    start. Sets both `COWRIE_HOSTNAME` (legacy) and `COWRIE_HONEYPOT_HOSTNAME`
    (modern) for compatibility across Cowrie versions."""
    return {
        "COWRIE_HOSTNAME": hostname,
        "COWRIE_HONEYPOT_HOSTNAME": hostname,
        "COWRIE_KERNEL_VERSION": persona.kernel_version,
        "COWRIE_HONEYPOT_KERNEL_VERSION": persona.kernel_version,
        "COWRIE_HONEYPOT_KERNEL_BUILD_STRING": persona.kernel_build_string,
        "COWRIE_HONEYPOT_HARDWARE_PLATFORM": persona.hardware_platform,
        "COWRIE_HONEYPOT_OPERATING_SYSTEM": persona.operating_system,
        "COWRIE_SSH_VERSION": persona.ssh_version_string,
    }
