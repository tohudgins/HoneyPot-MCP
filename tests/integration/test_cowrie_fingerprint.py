"""Does the real Cowrie container present the persona's SSH offer and a telnetd's opening?

`tests/unit/test_cowrie_fingerprint.py` proves the patch functions on fakes. Whether Python
inside the real image imports the delivered `sitecustomize` (PYTHONPATH, the anonymous volume,
the import hook against Cowrie's own modules) can only be seen by deploying the image and
reading the wire: the SSH KEXINIT a scanner reads and the first bytes a telnet client receives.
Opt-in via `RUN_DOCKER_TESTS=1`, like the other Docker-gated tests.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import tempfile
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.asyncio


def _docker_available() -> bool:
    try:
        import docker

        docker.from_env().ping()
        return True
    except Exception:
        return False


pytest.importorskip("docker", reason="docker SDK not installed")

skip_docker = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="needs Docker and RUN_DOCKER_TESTS=1 (pulls the Cowrie image)",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def _kexinit_lists(port: int) -> tuple[str, dict[str, list[str]]]:
    """(server banner, the server's KEXINIT name-lists) from a raw SSH connection."""
    names = (
        "kex",
        "host_key",
        "enc_c2s",
        "enc_s2c",
        "mac_c2s",
        "mac_s2c",
        "comp_c2s",
        "comp_s2c",
    )
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        banner = b""
        while not banner.endswith(b"\n"):
            banner += _read_exact(sock, 1)
        sock.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")
        length = struct.unpack(">I", _read_exact(sock, 4))[0]
        packet = _read_exact(sock, length)
    padding = packet[0]
    payload = packet[1 : length - padding]
    assert payload[0] == 20, "not a KEXINIT"
    pos = 1 + 16
    lists: dict[str, list[str]] = {}
    for name in names:
        (size,) = struct.unpack(">I", payload[pos : pos + 4])
        lists[name] = payload[pos + 4 : pos + 4 + size].decode().split(",")
        pos += 4 + size
    return banner.decode().strip(), lists


def _telnet_opening(port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.settimeout(4)
        data = b""
        try:
            while b"login: " not in data:
                chunk = sock.recv(512)
                if not chunk:
                    break
                data += chunk
        except TimeoutError:
            pass
    return data


async def _wait_for_port(port: int) -> None:
    for _ in range(60):
        await asyncio.sleep(1)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.settimeout(2)
                sock.recv(16)
            return
        except OSError:
            continue
    pytest.fail(f"nothing accepted on {port}")


@skip_docker
async def test_real_cowrie_presents_the_personas_ssh_offer_and_a_linux_telnetds_opening():
    from honeypot_mcp import config
    from honeypot_mcp.engines.ssh_personas import _PERSONAS, telnet_issue
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.honeypot import honeypot_deploy, honeypot_stop

    previous_url = os.environ.get("DATABASE_URL")
    db_dir = tempfile.mkdtemp(prefix="honeypot-fp-it-")
    await close_db()
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{Path(db_dir) / 'it.db'}"
    config._settings = None
    event_buffer.reset_for_tests()
    await init_db()
    await event_buffer.get_buffer().start()

    suffix = uuid.uuid4().hex[:8]
    ssh_name, telnet_name = f"it-fp-ssh-{suffix}", f"it-fp-telnet-{suffix}"
    ssh_port, telnet_port = _free_port(), _free_port()
    deployed: list[str] = []
    try:
        ssh = await honeypot_deploy(
            type="ssh", name=ssh_name, port=ssh_port, config={"ssh_persona": "debian_12"}
        )
        assert "error" not in ssh, ssh
        deployed.append(ssh_name)
        telnet = await honeypot_deploy(
            type="telnet", name=telnet_name, port=telnet_port, config={"ssh_persona": "debian_12"}
        )
        assert "error" not in telnet, telnet
        deployed.append(telnet_name)
        await _wait_for_port(ssh_port)
        await _wait_for_port(telnet_port)

        banner, lists = await asyncio.to_thread(_kexinit_lists, ssh_port)
        persona = _PERSONAS["debian_12"]
        assert banner == persona.ssh_version_string

        # Twisted's own offer, which contradicted the OpenSSH 9.2 banner, is gone.
        offered = {name for values in lists.values() for name in values}
        assert not offered & {
            "3des-cbc",
            "cast128-cbc",
            "aes256-cbc",
            "hmac-md5",
            "hmac-sha2-384",
            "diffie-hellman-group14-sha1",
            "ssh-rsa",
            "zlib",
        }, sorted(offered)
        assert lists["host_key"] == [
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519",
        ]
        assert lists["kex"][:2] == ["curve25519-sha256", "curve25519-sha256@libssh.org"]
        assert lists["enc_s2c"] == ["aes128-ctr", "aes192-ctr", "aes256-ctr"]
        assert lists["comp_s2c"] == ["none", "zlib@openssh.com"]

        opening = await asyncio.to_thread(_telnet_opening, telnet_port)
        # IAC DO TTYPE, TSPEED, XDISPLOC, NEW-ENVIRON, as a Linux telnetd sends; never DO NAWS.
        assert opening.startswith(b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"), opening[:16]
        assert not opening.startswith(b"\xff\xfd\x1f")
        assert telnet_issue(persona).encode() in opening
        assert opening.rstrip().endswith(b" login:")
    finally:
        for name in deployed:
            await honeypot_stop(name=name)
        await event_buffer.get_buffer().stop()
        await close_db()
        if previous_url is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = previous_url
        config._settings = None
        event_buffer.reset_for_tests()
