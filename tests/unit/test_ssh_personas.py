"""Tests for SSH persona module + engine integration.

Verifies the persona module produces internally-consistent specs, and that
SSHEngine.start() picks a persona, persists it to the Honeypot config, and
passes the right COWRIE_* env vars to the (mocked) Docker container.
"""

import os
from collections import Counter
from unittest.mock import AsyncMock, MagicMock

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


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
    assert env["COWRIE_SHELL_KERNEL_VERSION"] == p.kernel_version
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
    """A docker client whose `containers.create` returns a fake container with a
    fixed id. The container serves a minimal valid filesystem pickle from
    `get_archive` and accepts `put_archive`, so the persona filesystem delivery
    runs for real; kwargs of the create call are kept for assertion."""
    import io
    import pickle
    import tarfile

    root = ["/", 1, 0, 0, 0, 0o40755, 0, [], None, None]
    payload = pickle.dumps(root, protocol=4)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("fs.pickle")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    fake_container = MagicMock()
    fake_container.id = "fake_container_abcdef"
    fake_container.get_archive = MagicMock(return_value=(iter([buf.getvalue()]), {}))
    fake_container.put_archive = MagicMock(return_value=True)
    client = MagicMock()
    client.images.get = MagicMock()  # image found, no pull
    client.containers.create = MagicMock(return_value=fake_container)
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

    docker_kwargs = engine._client.containers.create.call_args.kwargs
    env = docker_kwargs["environment"]

    expected = get_persona("debian_12")
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == "git-server"
    assert env["COWRIE_SHELL_KERNEL_VERSION"] == expected.kernel_version
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
    docker_env = engine._client.containers.create.call_args.kwargs["environment"]
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

    env = engine._client.containers.create.call_args.kwargs["environment"]
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == "MY-CUSTOM-HOST"
    assert env["COWRIE_SHELL_KERNEL_VERSION"] == "9.9.9-custom"


@pytest.mark.asyncio
async def test_ssh_start_delivers_the_persona_filesystem_before_starting():
    from honeypot_mcp.engines.cowrie_fs import PERSONA_DIR, PERSONA_PICKLE_PATH, load_fs
    from honeypot_mcp.engines.ssh import SSHEngine

    await _seed_honeypot("fs-ssh", 2222, config={})
    engine = SSHEngine()
    engine._client, container = _mock_docker_client()
    engine._ingest_logs = AsyncMock(return_value=None)

    await engine.start("fs-ssh", 2222, {})

    env = engine._client.containers.create.call_args.kwargs["environment"]
    assert env["COWRIE_SHELL_FILESYSTEM"] == PERSONA_PICKLE_PATH
    # The archive went in while the container was still stopped, and the pickle
    # inside it is the persona's: hostname and a persona account, no `phil`.
    assert container.put_archive.call_count == 1
    path, data = container.put_archive.call_args.args
    assert path == PERSONA_DIR  # into the volume mount point, not the read-only rootfs
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        built = tar.extractfile("fs.pickle").read()
    root = load_fs(built)
    from honeypot_mcp.engines import cowrie_fs as cf

    hostname = env["COWRIE_HONEYPOT_HOSTNAME"]
    assert cf._read(root, "/etc/hostname") == f"{hostname}\n"
    assert "phil" not in cf._read(root, "/etc/passwd")
    assert [c[0] for c in container.method_calls if c[0] in ("put_archive", "start")] == [
        "put_archive",
        "start",
    ]


@pytest.mark.asyncio
async def test_ssh_start_falls_back_to_the_default_filesystem_if_delivery_fails():
    from honeypot_mcp.engines.ssh import SSHEngine

    await _seed_honeypot("fallback-ssh", 2222, config={})
    engine = SSHEngine()
    client, container = _mock_docker_client()
    container.get_archive = MagicMock(side_effect=RuntimeError("proxy refused archive"))
    engine._client = client
    engine._ingest_logs = AsyncMock(return_value=None)

    cid = await engine.start("fallback-ssh", 2222, {})

    assert cid == "fake_container_abcdef"  # the deploy still succeeds
    calls = client.containers.create.call_args_list
    assert len(calls) == 2
    assert "COWRIE_SHELL_FILESYSTEM" in calls[0].kwargs["environment"]
    assert "COWRIE_SHELL_FILESYSTEM" not in calls[1].kwargs["environment"]
    container.remove.assert_called_once()
    container.start.assert_called_once()


@pytest.mark.parametrize("persona_id", ["ubuntu_22_04", "ubuntu_20_04", "debian_12", "rhel_8"])
def test_persona_filesystem_keeps_the_preauth_banner_empty(persona_id):
    """Cowrie sends /etc/issue.net as the SSH pre-auth banner whenever it is
    non-empty. Real sshd sends none by default, so a persona filesystem that fills
    the file makes every connection announce itself as a honeypot-flavoured Linux."""
    import pickle

    from honeypot_mcp.engines import cowrie_fs as cf
    from honeypot_mcp.engines.ssh_personas import _PERSONAS

    base = pickle.dumps(
        ["/", 1, 0, 0, 0, 0o40755, 0,
         [["etc", 1, 0, 0, 4096, 0o40755, 0,
           [["issue.net", 2, 0, 0, 0, 0o100644, 0, b"", None, None]], None, None]],
         None, None],
        protocol=4,
    )  # fmt: skip
    root = cf.load_fs(cf.build_persona_fs(base, _PERSONAS[persona_id], "web-01", "seed"))
    assert cf._read(root, "/etc/issue.net").strip() == ""


def test_compose_cowrie_service_matches_the_persona_it_claims():
    """docker-compose.yml carries the persona's identity as literal env values (it
    cannot import Python). They must equal the persona they name, and the init job
    must build the filesystem for that same persona and hostname — otherwise the
    compose sensor says one thing in `uname` and another in /etc."""
    from pathlib import Path

    import yaml

    from honeypot_mcp.engines.ssh_personas import _PERSONAS

    compose = yaml.safe_load(
        (Path(__file__).parents[2] / "docker" / "docker-compose.yml").read_text()
    )
    init = compose["services"]["cowrie-persona-init"]
    sensor = compose["services"]["cowrie-ssh"]
    env = dict(item.split("=", 1) for item in sensor["environment"])

    persona = _PERSONAS[init["environment"]["PERSONA"]]
    assert env["COWRIE_SHELL_KERNEL_VERSION"] == persona.kernel_version
    assert env["COWRIE_SHELL_KERNEL_BUILD_STRING"] == persona.kernel_build_string
    assert env["COWRIE_SHELL_HARDWARE_PLATFORM"] == persona.hardware_platform
    assert env["COWRIE_SHELL_OPERATING_SYSTEM"] == persona.operating_system
    assert env["COWRIE_SSH_VERSION"] == persona.ssh_version_string
    assert env["COWRIE_HONEYPOT_HOSTNAME"] == init["environment"]["COWRIE_HOSTNAME"]

    # The sensor waits for the filesystem to exist, and reads it from the volume
    # the init job writes.
    assert (
        sensor["depends_on"]["cowrie-persona-init"]["condition"] == "service_completed_successfully"
    )
    assert env["COWRIE_SHELL_FILESYSTEM"] == "/cowrie/persona/fs.pickle"
    assert "cowrie-persona:/cowrie/persona:ro" in sensor["volumes"]
    assert "cowrie-persona:/persona" in init["volumes"]
