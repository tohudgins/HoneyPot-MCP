"""Tests for SSH persona module + engine integration.

Verifies the persona module produces internally-consistent specs, and that
SSHEngine.start() picks a persona, persists it to the Honeypot config, and
passes the right COWRIE_* env vars to the (mocked) Docker container.
"""

import os
from collections import Counter
from unittest.mock import AsyncMock, MagicMock

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


# ── Persona module ────────────────────────────────────────────────────────────


def test_all_personas_have_required_fields():
    from honeypot_mcp.engines.ssh_personas import all_persona_ids, get_persona

    for pid in all_persona_ids():
        p = get_persona(pid)
        assert p.id == pid
        assert p.hostname_pool, f"Persona {pid} has empty hostname_pool"
        assert p.kernel_version
        assert p.kernel_build_string
        assert p.ssh_version_string.startswith("SSH-2.0-OpenSSH_")
        assert p.distro_pretty_name


def test_get_persona_falls_back_for_unknown_id():
    from honeypot_mcp.engines.ssh_personas import get_persona

    p = get_persona("not_a_real_persona")
    assert p.id == "ubuntu_22_04"


def test_pick_random_persona_id_distributes():
    from honeypot_mcp.engines.ssh_personas import all_persona_ids, pick_random_persona_id

    picks = Counter(pick_random_persona_id() for _ in range(100))
    assert len(picks) >= 2  # not stuck on a constant
    assert set(picks.keys()).issubset(set(all_persona_ids()))


def test_pick_hostname_returns_member_of_pool():
    from honeypot_mcp.engines.ssh_personas import all_persona_ids, get_persona, pick_hostname

    for pid in all_persona_ids():
        p = get_persona(pid)
        for _ in range(20):
            chosen = pick_hostname(p)
            assert chosen in p.hostname_pool


def test_persona_distros_are_internally_consistent():
    """A Debian persona shouldn't claim an Ubuntu kernel build, and vice versa.
    Mismatched fingerprint surfaces are themselves a fingerprint."""
    from honeypot_mcp.engines.ssh_personas import get_persona

    debian = get_persona("debian_12")
    assert "Debian" in debian.kernel_build_string
    assert "Debian" in debian.distro_pretty_name
    assert "Debian" in debian.ssh_version_string

    ubuntu = get_persona("ubuntu_22_04")
    assert "Ubuntu" in ubuntu.kernel_build_string
    assert "Ubuntu" in ubuntu.distro_pretty_name
    assert "Ubuntu" in ubuntu.ssh_version_string


def test_cowrie_env_vars_includes_both_legacy_and_modern_keys():
    """Cowrie versions disagree on the env-var naming convention. We set both
    so the persona takes effect regardless of which version is pulled."""
    from honeypot_mcp.engines.ssh_personas import cowrie_env_vars, get_persona

    p = get_persona("ubuntu_22_04")
    env = cowrie_env_vars(p, "test-host")
    assert env["COWRIE_HOSTNAME"] == "test-host"
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == "test-host"
    assert env["COWRIE_HONEYPOT_KERNEL_VERSION"] == p.kernel_version
    assert env["COWRIE_SSH_VERSION"] == p.ssh_version_string


# ── Engine integration (Docker mocked) ────────────────────────────────────────


async def _seed_honeypot(name: str, port: int, config: dict | None = None) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        hp = Honeypot(
            name=name,
            type=HoneypotType.SSH,
            port=port,
            status=HoneypotStatus.STOPPED,
            config=config or {},
        )
        session.add(hp)
        await session.flush()
        return hp.id


def _mock_docker_client():
    """A docker client whose `containers.run` returns a fake container with
    a fixed id and remembers its kwargs for assertion."""
    fake_container = MagicMock()
    fake_container.id = "fake_container_abcdef"
    client = MagicMock()
    client.images.get = MagicMock()  # image found, no pull
    client.containers.run = MagicMock(return_value=fake_container)
    return client, fake_container


@pytest.mark.asyncio
async def test_ssh_start_picks_persona_and_persists_to_config():
    from sqlalchemy import select

    from honeypot_mcp.engines.ssh import SSHEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot

    await _seed_honeypot("auto-ssh", 2222, config={})

    engine = SSHEngine()
    engine._client, _ = _mock_docker_client()
    # _ingest_logs spawns a background task — replace with a no-op coroutine.
    engine._ingest_logs = AsyncMock(return_value=None)

    config: dict = {}
    cid = await engine.start("auto-ssh", 2222, config)
    assert cid == "fake_container_abcdef"
    assert "ssh_persona" in config
    assert "ssh_hostname" in config

    # Persisted to DB so a restart sees the same identity.
    async with get_session() as session:
        result = await session.execute(select(Honeypot).where(Honeypot.name == "auto-ssh"))
        hp = result.scalar_one()
    assert hp.config["ssh_persona"] == config["ssh_persona"]
    assert hp.config["ssh_hostname"] == config["ssh_hostname"]


@pytest.mark.asyncio
async def test_ssh_start_passes_persona_env_vars_to_docker():
    from honeypot_mcp.engines.ssh import SSHEngine
    from honeypot_mcp.engines.ssh_personas import get_persona

    await _seed_honeypot(
        "env-test", 2222, config={"ssh_persona": "debian_12", "ssh_hostname": "git-server"}
    )

    engine = SSHEngine()
    engine._client, _ = _mock_docker_client()
    engine._ingest_logs = AsyncMock(return_value=None)

    config = {"ssh_persona": "debian_12", "ssh_hostname": "git-server"}
    await engine.start("env-test", 2222, config)

    docker_kwargs = engine._client.containers.run.call_args.kwargs
    env = docker_kwargs["environment"]

    expected = get_persona("debian_12")
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == "git-server"
    assert env["COWRIE_HONEYPOT_KERNEL_VERSION"] == expected.kernel_version
    assert env["COWRIE_SSH_VERSION"] == expected.ssh_version_string
    # Container labelled with the persona for visibility.
    assert docker_kwargs["labels"]["honeypot-persona"] == "debian_12"


@pytest.mark.asyncio
async def test_ssh_start_respects_existing_persona():
    """If config already has a persona (from a previous deploy or user override),
    start() must NOT overwrite it."""
    from honeypot_mcp.engines.ssh import SSHEngine

    await _seed_honeypot(
        "pinned",
        2222,
        config={
            "ssh_persona": "rhel_8",
            "ssh_hostname": "oracle-app",
        },
    )

    engine = SSHEngine()
    engine._client, _ = _mock_docker_client()
    engine._ingest_logs = AsyncMock(return_value=None)

    config = {"ssh_persona": "rhel_8", "ssh_hostname": "oracle-app"}
    await engine.start("pinned", 2222, config)

    assert config["ssh_persona"] == "rhel_8"
    assert config["ssh_hostname"] == "oracle-app"
    docker_env = engine._client.containers.run.call_args.kwargs["environment"]
    assert docker_env["COWRIE_HONEYPOT_HOSTNAME"] == "oracle-app"


@pytest.mark.asyncio
async def test_ssh_start_user_override_wins():
    """Explicit `fake_hostname` / `fake_kernel` in config beat the persona —
    escape hatch for users who want a specific identity."""
    from honeypot_mcp.engines.ssh import SSHEngine

    await _seed_honeypot(
        "override",
        2222,
        config={
            "ssh_persona": "ubuntu_22_04",
            "ssh_hostname": "ubuntu-srv",
            "fake_hostname": "MY-CUSTOM-HOST",
            "fake_kernel": "9.9.9-custom",
        },
    )

    engine = SSHEngine()
    engine._client, _ = _mock_docker_client()
    engine._ingest_logs = AsyncMock(return_value=None)

    config = {
        "ssh_persona": "ubuntu_22_04",
        "ssh_hostname": "ubuntu-srv",
        "fake_hostname": "MY-CUSTOM-HOST",
        "fake_kernel": "9.9.9-custom",
    }
    await engine.start("override", 2222, config)

    env = engine._client.containers.run.call_args.kwargs["environment"]
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == "MY-CUSTOM-HOST"
    assert env["COWRIE_HONEYPOT_KERNEL_VERSION"] == "9.9.9-custom"
