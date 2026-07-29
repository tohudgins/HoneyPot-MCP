"""Honeypot containers started outside this process must still be ingested.

A Cowrie container only produces alerts if something tails its logs, and that
only happens for containers with a `Honeypot` row pointing at them. The compose
stack starts `cowrie-ssh` itself, so nothing was ever attached to it: following
the README — `docker compose up`, then `ssh -p 2222 localhost` — gave a full
interactive session, recorded it in Cowrie's own logs, and produced zero
alerts. `docker ps` and the port both looked healthy the whole time.

`adopt_labelled_containers()` closes that by claiming containers labelled
`honeypot-mcp=true` at startup. Docker is faked here so the logic is testable
without a daemon; `tests/integration/test_ssh_capture.py` covers the real path.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await close_db()
    event_buffer.reset_for_tests()


class _FakeContainer:
    def __init__(self, cid: str, name: str, host_port: int | None, labels: dict[str, str]):
        self.id = cid
        self.name = name
        self.labels = labels
        ports: dict[str, Any] = {}
        if host_port is not None:
            ports["2222/tcp"] = [{"HostIp": "0.0.0.0", "HostPort": str(host_port)}]
        self.attrs = {"NetworkSettings": {"Ports": ports}}


@pytest.fixture
def fake_docker(monkeypatch):
    """Install a fake docker module and record reattach calls."""
    import honeypot_mcp.reconcile as reconcile

    containers: list[_FakeContainer] = []
    reattached: list[tuple[str, int, str]] = []

    class _Containers:
        def list(self, filters=None):
            assert filters == {"label": "honeypot-mcp=true"}
            return list(containers)

    class _Client:
        containers = _Containers()

    fake_module = type("docker", (), {"from_env": staticmethod(lambda: _Client())})
    monkeypatch.setitem(__import__("sys").modules, "docker", fake_module)

    class _Engine:
        async def reattach(self, name, port, config, container_id):
            reattached.append((name, port, container_id))
            return container_id

    monkeypatch.setattr(reconcile, "get_engine", lambda _type: _Engine())
    return containers, reattached


async def test_unknown_container_is_registered_and_ingestion_attached(fake_docker):
    from sqlalchemy import select

    from honeypot_mcp.reconcile import adopt_labelled_containers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    containers, reattached = fake_docker
    containers.append(
        _FakeContainer(
            "abc123", "honeypot-ssh", 2222, {"honeypot-mcp": "true", "honeypot-name": "cowrie-ssh"}
        )
    )

    assert await adopt_labelled_containers() == ["cowrie-ssh"]
    assert reattached == [("cowrie-ssh", 2222, "abc123")]

    async with get_session() as session:
        rows = (await session.execute(select(Honeypot))).scalars().all()
    assert len(rows) == 1
    assert rows[0].name == "cowrie-ssh"
    assert rows[0].container_id == "abc123"
    assert rows[0].status is HoneypotStatus.RUNNING


async def test_orphaned_row_is_repointed_rather_than_duplicated(fake_docker):
    """The seeded `demo-ssh` row is the real case: right port, no container.

    Creating a second row would leave the original stuck in ERROR and put two
    honeypots on one port.
    """
    from sqlalchemy import select

    from honeypot_mcp.reconcile import adopt_labelled_containers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        session.add(
            Honeypot(
                name="demo-ssh",
                type=HoneypotType.SSH,
                port=2222,
                status=HoneypotStatus.ERROR,
                container_id=None,
                config={"ssh_persona": "ubuntu_22_04"},
            )
        )

    containers, reattached = fake_docker
    containers.append(
        _FakeContainer(
            "cid999", "honeypot-ssh", 2222, {"honeypot-mcp": "true", "honeypot-name": "cowrie-ssh"}
        )
    )

    await adopt_labelled_containers()

    async with get_session() as session:
        rows = (await session.execute(select(Honeypot))).scalars().all()
    assert len(rows) == 1, "adoption duplicated the honeypot instead of re-pointing it"
    assert rows[0].name == "demo-ssh"
    assert rows[0].container_id == "cid999"
    assert rows[0].status is HoneypotStatus.RUNNING
    # The existing persona must be carried into reattach, not reset.
    assert reattached == [("cowrie-ssh", 2222, "cid999")]


async def test_container_without_a_published_port_is_skipped(fake_docker):
    """Unpublished means unreachable — registering it would be a lie."""
    from honeypot_mcp.reconcile import adopt_labelled_containers

    containers, reattached = fake_docker
    containers.append(_FakeContainer("cid1", "internal", None, {"honeypot-mcp": "true"}))

    assert await adopt_labelled_containers() == []
    assert reattached == []


async def test_already_adopted_container_is_left_alone(fake_docker):
    """Adoption runs on every start; it must be idempotent."""
    from honeypot_mcp.reconcile import adopt_labelled_containers

    containers, reattached = fake_docker
    containers.append(
        _FakeContainer("same", "honeypot-ssh", 2222, {"honeypot-mcp": "true", "honeypot-name": "s"})
    )

    await adopt_labelled_containers()
    assert len(reattached) == 1
    assert await adopt_labelled_containers() == []
    assert len(reattached) == 1


async def test_a_row_stuck_in_error_is_re_adopted(fake_docker):
    """Matching container id alone must not short-circuit a broken row.

    The watchdog can mark a honeypot ERROR for a transient reason. If adoption
    skips on container id alone, the row keeps the right container, stays
    ERROR, and never recovers — which is exactly what happened to `demo-ssh`.
    """
    from sqlalchemy import select

    from honeypot_mcp.reconcile import adopt_labelled_containers
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus, HoneypotType

    async with get_session() as session:
        session.add(
            Honeypot(
                name="demo-ssh",
                type=HoneypotType.SSH,
                port=2222,
                status=HoneypotStatus.ERROR,
                container_id="same",
                config={},
            )
        )

    containers, reattached = fake_docker
    containers.append(
        _FakeContainer("same", "honeypot-ssh", 2222, {"honeypot-mcp": "true", "honeypot-name": "s"})
    )

    assert await adopt_labelled_containers() == ["s"]
    assert len(reattached) == 1

    async with get_session() as session:
        row = (await session.execute(select(Honeypot))).scalars().one()
    assert row.status is HoneypotStatus.RUNNING


async def test_docker_unavailable_is_not_an_error(monkeypatch):
    """Adoption is best-effort — a machine without Docker still starts."""
    import honeypot_mcp.reconcile as reconcile

    class _Boom:
        @staticmethod
        def from_env():
            raise RuntimeError("no docker socket")

    monkeypatch.setitem(__import__("sys").modules, "docker", _Boom)
    assert await reconcile.adopt_labelled_containers() == []
