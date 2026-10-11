"""What a Cowrie honeypot container is allowed to be.

One definition of the image, its resource ceiling and its writable paths, read by two parties
that must agree: the SSH engine (`engines/ssh.py`), which creates the container, and the Docker
guard (`hardening/docker_guard.py`), which refuses to create any container that does not match.
Kept free of imports so the guard, a small root-adjacent process, loads nothing else.
"""

from __future__ import annotations

# Pinned to an explicit release (3.0.15 is what `latest` and `3.0` resolved to
# when this was pinned). `:latest` meant every fresh host — and every
# `images.pull` after an upstream push — silently ran whatever was newest.
# Bump deliberately, together with a run of the Docker-gated capture test.
COWRIE_IMAGE = "cowrie/cowrie:3.0.15"

# Resource ceiling for the attacker-facing container. Cowrie is a Python
# emulator that an attacker drives interactively, so it must not be able to
# starve the host. Mirrors docker/docker-compose.yml's cowrie-ssh service.
COWRIE_MEM_LIMIT = "256m"
COWRIE_MEM_LIMIT_BYTES = 256 * 1024 * 1024
COWRIE_PIDS_LIMIT = 128
COWRIE_NANO_CPUS = 500_000_000  # 0.5 CPU
# Cowrie's JSON event stream goes to stdout, so the docker json-file log *is*
# the evidence channel; cap it or a long brute-force run fills the disk.
COWRIE_LOG_MAX_SIZE = "10m"
COWRIE_LOG_MAX_FILES = "3"
# Read-only root filesystem; the only writable paths are small tmpfs mounts.
# uid/gid 999 is the image's `cowrie` user. SDK-deployed honeypots are
# ephemeral, so samples and tty replays living in memory is acceptable here
# (the event stream, including each sample's hash, is already in the logs); the
# compose stack mounts a persistent volume for them instead.
COWRIE_TMPFS = {
    "/tmp": "rw,size=16m",
    "/cowrie/var/lib/cowrie": "rw,size=64m,uid=999,gid=999,mode=0755",
    "/cowrie/var/log/cowrie": "rw,size=32m,uid=999,gid=999,mode=0755",
}
# Ports Cowrie listens on inside the container, before any host publishing.
COWRIE_INTERNAL_PORT = 2222
COWRIE_TELNET_PORT = 2223
