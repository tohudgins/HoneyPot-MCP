"""Grafana on the server's own data: container lifecycle, the database view, the tools.

A fake Docker client stands in for the daemon so the arguments the module hands Docker can be
pinned (loopback-only port, read-only mounts that hold only the database, no password in any
result) and every failure path can be driven. What a fake cannot show — that a read-only mount of a
0600 WAL-mode file really opens inside a Grafana container — was run against the real daemon;
see the module docstring of `honeypot_mcp.grafana`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import errno
import json
import os
import socket
import sqlite3
import tomllib
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import docker.errors
import httpx
import pytest
import yaml

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

ROOT = Path(__file__).resolve().parents[2]

# A root-owned database is (deliberately) never hardlinked, so tests that need the live hardlink
# view cannot run as root; the root cases are covered explicitly with a patched uid.
not_root = pytest.mark.skipif(os.geteuid() == 0, reason="a root-owned database is snapshotted")


# ── a fake Docker daemon ─────────────────────────────────────────────────────────────────────


class FakeContainer:
    def __init__(self, client: FakeClient, spec: dict[str, Any]) -> None:
        self.client = client
        self.spec = spec
        self.name = spec["name"]
        self.id = f"c{next(client.ids):04d}"
        self.labels = dict(spec.get("labels", {}))
        self.status = "created"
        host, port = spec.get("ports", {}).get("3000/tcp", (None, None))
        self.attrs: dict[str, Any] = {
            "HostConfig": {"PortBindings": {"3000/tcp": [{"HostIp": host, "HostPort": str(port)}]}},
            "State": {"StartedAt": "2026-10-16T21:41:22.473062123Z"},
        }
        self.removed_with_volumes: bool | None = None

    def start(self) -> None:
        if self.client.fail_start:
            raise docker.errors.APIError(self.client.fail_start)
        self.status = "running"

    def stop(self, timeout: int = 10) -> None:
        self.status = "exited"

    def remove(self, force: bool = False, v: bool = False) -> None:
        self.removed_with_volumes = v
        self.client.store.remove(self)
        self.client.removed.append(self)

    def reload(self) -> None:
        pass

    def logs(self, tail: int = 20) -> bytes:
        return b"logger=server level=error msg=boom\n"


class FakeContainers:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def create(self, **spec: Any) -> FakeContainer:
        if self.client.fail_create:
            raise docker.errors.APIError(self.client.fail_create)
        c = FakeContainer(self.client, spec)
        self.client.created.append(c)
        self.client.store.append(c)
        return c

    def list(self, all: bool = False, filters: dict[str, str] | None = None) -> list[FakeContainer]:
        out = list(self.client.store)
        if filters and "label" in filters:
            key, _, value = filters["label"].partition("=")
            out = [c for c in out if c.labels.get(key) == value]
        return out

    def get(self, name: str) -> FakeContainer:
        for c in self.client.store:
            if c.name == name:
                return c
        raise docker.errors.NotFound(name)


class FakeImages:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def get(self, name: str) -> object:
        if not self.client.have_image:
            raise docker.errors.ImageNotFound(name)
        return object()

    def pull(self, repo: str, tag: str | None = None) -> None:
        if self.client.pull_error:
            raise self.client.pull_error
        self.client.pulled.append(f"{repo}:{tag}")
        self.client.have_image = True


class FakeNetwork:
    def __init__(self, client: FakeClient, name: str, internal: bool, labels: dict[str, str]):
        self.client = client
        self.name = name
        self.internal = internal
        self.attrs: dict[str, Any] = {"Labels": dict(labels)}
        self.connected: list[FakeContainer] = []

    def connect(self, container: FakeContainer, **kw: Any) -> None:
        self.connected.append(container)

    def remove(self) -> None:
        self.client.network_store.remove(self)
        self.client.networks_removed.append(self)


class FakeNetworks:
    def __init__(self, client: FakeClient) -> None:
        self.client = client

    def create(
        self, name: str, driver: str = "bridge", internal: bool = False, labels: Any = None
    ) -> FakeNetwork:
        net = FakeNetwork(self.client, name, internal, labels or {})
        self.client.network_store.append(net)
        self.client.networks_created.append(net)
        return net

    def list(
        self, names: list[str] | None = None, filters: dict[str, str] | None = None
    ) -> list[FakeNetwork]:
        out = list(self.client.network_store)
        if names:
            out = [n for n in out if n.name in names]
        if filters and "label" in filters:
            key, _, value = filters["label"].partition("=")
            out = [n for n in out if n.attrs["Labels"].get(key) == value]
        return out


class FakeClient:
    def __init__(self) -> None:
        import itertools

        self.ids = itertools.count(1)
        self.store: list[FakeContainer] = []
        self.created: list[FakeContainer] = []
        self.removed: list[FakeContainer] = []
        self.network_store: list[FakeNetwork] = []
        self.networks_created: list[FakeNetwork] = []
        self.networks_removed: list[FakeNetwork] = []
        self.pulled: list[str] = []
        self.have_image = True
        self.pull_error: Exception | None = None
        self.fail_create: str | None = None
        self.fail_start: str | None = None
        self.containers = FakeContainers(self)
        self.images = FakeImages(self)
        self.networks = FakeNetworks(self)

    def ping(self) -> bool:
        return True

    @property
    def grafana(self) -> FakeContainer:
        """The container that holds the database (the other one is the port forwarder)."""
        return next(
            c for c in self.created if c.labels.get("honeypot-mcp-grafana-role") == "grafana"
        )

    @property
    def proxy(self) -> FakeContainer:
        return next(c for c in self.created if c.labels.get("honeypot-mcp-grafana-role") == "proxy")


def _foreign(client: FakeClient, name: str, labels: dict[str, str] | None = None) -> FakeContainer:
    c = FakeContainer(client, {"name": name, "labels": labels or {}, "ports": {}})
    c.status = "running"
    client.store.append(c)
    return c


# ── fixtures ─────────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db

    event_buffer.reset_for_tests()
    await init_db()
    # A persistent database creates its engine on first use, not in init_db. Several tests then point
    # `database_url` at another database to exercise the tool, and an engine first created after that
    # would bind to the wrong one (and its audit write would hit a database with no tables).
    async with get_session():
        pass
    yield
    await asyncio.sleep(0.05)
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
def healthy_probe(monkeypatch):
    """A probe that reports Grafana healthy and the datasource answering."""
    from honeypot_mcp import grafana

    calls: list[tuple[int, str]] = []

    async def probe(port, password, alive, **kw):
        calls.append((port, password))
        return {
            "healthy": True,
            "datasource_ok": True,
            "tables": ["alert_rollups", "alerts"],
            "datasource_error": None,
            "container_exited": False,
        }

    monkeypatch.setattr(grafana, "_probe", probe)
    monkeypatch.setattr(grafana, "_port_free", lambda port: True)
    return calls


@pytest.fixture
def docker_client(monkeypatch):
    from honeypot_mcp import grafana

    client = FakeClient()
    monkeypatch.setattr(grafana, "_docker_client", lambda: client)

    def fake_install(plugins_dir: Path) -> None:
        """No download in unit tests: leave a plugin directory where the real one would be."""
        target = plugins_dir / grafana.SQLITE_PLUGIN
        target.mkdir(parents=True)
        (target / "plugin.json").write_text("{}")

    monkeypatch.setattr(grafana, "_install_plugin", fake_install)
    return client


def _make_db(path: Path, rows: int = 5) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, x TEXT)")
    conn.executemany("INSERT INTO alerts (x) VALUES (?)", [("a",)] * rows)
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    path.chmod(0o600)
    return path


@pytest.fixture
def database(tmp_path, monkeypatch, setup_db):
    """A real SQLite file in a directory that also holds things Grafana must never see."""
    from honeypot_mcp.config import get_settings

    data = tmp_path / "data"
    db = _make_db(data / "app.db")
    (data / ".env").write_text("MCP_AUTH_TOKEN=hunter2\n")
    (data / "tls").mkdir()
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{db}")
    return db


async def _audit_rows():
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AuditLog

    async with get_session() as session:
        return (await session.execute(select(AuditLog))).scalars().all()


# ── what Docker is asked to run ──────────────────────────────────────────────────────────────


async def test_port_is_published_on_loopback_only_by_the_forwarder(
    database, docker_client, healthy_probe
):
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=3300)

    assert "error" not in result, result
    # The container that holds the data publishes nothing; the forwarder publishes loopback only.
    assert "ports" not in docker_client.grafana.spec
    assert docker_client.proxy.spec["ports"] == {"3000/tcp": ("127.0.0.1", 3300)}
    assert result["url"] == "http://127.0.0.1:3300/"
    assert "0.0.0.0" not in json.dumps([c.spec for c in docker_client.created], default=str)


async def test_there_is_no_way_to_ask_for_another_bind_address():
    import inspect

    from honeypot_mcp.tools.grafana import grafana_start

    assert list(inspect.signature(grafana_start).parameters) == ["port"]


async def test_container_is_locked_down(database, docker_client, healthy_probe):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    spec = docker_client.grafana.spec
    env = spec["environment"]

    assert spec["image"] == "grafana/grafana:11.3.0"
    assert env["GF_AUTH_ANONYMOUS_ENABLED"] == "false"
    # Nothing is installed by Grafana, and no unsigned plugin is waved through.
    assert "GF_INSTALL_PLUGINS" not in env
    assert "GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS" not in env
    assert env["GF_PATHS_PLUGINS"] == "/mcp-plugins"
    assert spec["read_only"] is True
    assert spec["cap_drop"] == ["ALL"]
    assert spec["security_opt"] == ["no-new-privileges:true"]
    assert spec["labels"][grafana.LABEL_KEY] == grafana.LABEL_VALUE
    # Every host mount is read-only.
    assert spec["volumes"] and all(v["mode"] == "ro" for v in spec["volumes"].values())


async def test_the_container_with_the_data_has_no_route_out(database, docker_client, healthy_probe):
    """The finding: no `network_mode` meant the default bridge with full egress. Grafana is on an
    `internal` network (no gateway) and nothing else, and only the forwarder reaches an edge one."""
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=3300)

    internal = next(n for n in docker_client.networks_created if n.name == grafana.NETWORK_INTERNAL)
    edge = next(n for n in docker_client.networks_created if n.name == grafana.NETWORK_EDGE)
    assert internal.internal is True and edge.internal is False
    spec = docker_client.grafana.spec
    assert spec["network"] == grafana.NETWORK_INTERNAL
    assert "network_mode" not in spec
    assert "ports" not in spec
    assert "extra_hosts" not in spec and "dns" not in spec
    # The forwarder holds no data and no secret, and is the only thing on the edge network.
    proxy = docker_client.proxy.spec
    assert proxy["network"] == grafana.NETWORK_EDGE
    assert "volumes" not in proxy and "mounts" not in proxy and "environment" not in proxy
    assert proxy["user"] == "65534:65534"
    assert proxy["read_only"] is True and proxy["cap_drop"] == ["ALL"]
    assert docker_client.proxy in internal.connected  # reaches Grafana over the internal network
    assert docker_client.grafana not in internal.connected  # created on it, not connected later
    assert result["grafana_has_outbound_network"] is False
    assert any("no route out" in n and "forwarder" in n for n in result["notes"])
    # Both networks carry our label, so stop() can find them and nothing else.
    assert all(n.attrs["Labels"] == {"honeypot-mcp": "grafana"} for n in (internal, edge))


async def test_a_network_that_is_not_ours_is_never_touched(database, docker_client, healthy_probe):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    foreign = docker_client.networks.create(grafana.NETWORK_INTERNAL, internal=False, labels={})
    result = await grafana_start(port=3300)

    assert "was not created by this server" in result["error"]
    assert foreign in docker_client.network_store
    assert docker_client.networks_removed == []
    assert docker_client.created == []


async def test_the_plugin_is_never_installed_by_grafana_and_comes_from_a_ro_mount(
    database, docker_client, healthy_probe
):
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    spec = docker_client.grafana.spec
    plugins = next(Path(h) for h, v in spec["volumes"].items() if v["bind"] == "/mcp-plugins")

    assert spec["volumes"][str(plugins)]["mode"] == "ro"
    assert (plugins / "frser-sqlite-datasource" / "plugin.json").is_file()


@not_root
async def test_the_mount_holds_only_the_database(database, docker_client, healthy_probe):
    """The directory the database lives in also holds `.env` and `tls/`; neither may be mounted."""
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=3300)
    spec = docker_client.created[0].spec
    data_mount = next(h for h, v in spec["volumes"].items() if v["bind"] == "/mcp-data")

    assert Path(data_mount) != database.parent
    assert Path(data_mount).parent == get_settings().grafana_dir
    assert sorted(os.listdir(data_mount)) == [grafana.DB_FILENAME]
    assert result["db_mount"] == "hardlink"
    # Nothing else of the host is mounted either: the other three are the packaged config copies
    # and the unpacked plugin.
    others = {Path(h).name for h, v in spec["volumes"].items() if v["bind"] != "/mcp-data"}
    assert others == {"provisioning", "dashboards", "plugins"}


@not_root
async def test_hardlink_is_the_same_file_and_the_original_is_untouched(
    database, docker_client, healthy_probe
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    before = database.stat()
    await grafana_start(port=3300)
    spec = docker_client.created[0].spec
    mount = next(Path(h) for h, v in spec["volumes"].items() if v["bind"] == "/mcp-data")
    linked = mount / grafana.DB_FILENAME

    assert linked.stat().st_ino == database.stat().st_ino
    assert database.stat().st_nlink == 2
    # The permissions problem is solved on the container side, not by loosening the file.
    assert database.stat().st_mode == before.st_mode
    assert oct(database.stat().st_mode & 0o777) == "0o600"
    assert spec["user"] == f"{database.stat().st_uid}:0"
    assert oct(mount.stat().st_mode & 0o777) == "0o700"


@not_root
async def test_live_wal_sidecars_are_linked_and_not_immutable(
    database, docker_client, healthy_probe
):
    """A database a writer has open: its -wal/-shm come along, so the view stays live."""
    from honeypot_mcp.tools.grafana import grafana_start

    writer = sqlite3.connect(database)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO alerts (x) VALUES ('b')")
    writer.commit()
    try:
        assert database.with_name("app.db-shm").exists()
        result = await grafana_start(port=3300)
    finally:
        writer.close()

    spec = docker_client.created[0].spec
    mount = next(Path(h) for h, v in spec["volumes"].items() if v["bind"] == "/mcp-data")
    assert sorted(os.listdir(mount)) == [
        "honeypot_mcp.db",
        "honeypot_mcp.db-shm",
        "honeypot_mcp.db-wal",
    ]
    assert result["db_mount"] == "hardlink"
    cfg = next(Path(h) for h, v in spec["volumes"].items() if v["bind"].endswith("provisioning"))
    ds = yaml.safe_load((cfg / "datasources" / "datasources.yml").read_text())
    honeypot = next(d for d in ds["datasources"] if d["uid"] == "honeypot-db")
    assert "pathOptions" not in honeypot["jsonData"]


@not_root
async def test_wal_database_nobody_has_open_is_read_as_immutable(
    database, docker_client, healthy_probe
):
    """The read-only/WAL problem: a WAL file on a read-only mount cannot create its -shm, so it
    must be opened immutable — which is only correct because there is no log to ignore."""
    from honeypot_mcp.tools.grafana import grafana_start

    assert not database.with_name("app.db-shm").exists()
    result = await grafana_start(port=3300)

    spec = docker_client.created[0].spec
    cfg = next(Path(h) for h, v in spec["volumes"].items() if v["bind"].endswith("provisioning"))
    ds = yaml.safe_load((cfg / "datasources" / "datasources.yml").read_text())
    honeypot = next(d for d in ds["datasources"] if d["uid"] == "honeypot-db")
    assert honeypot["jsonData"]["pathPrefix"] == "file:"
    assert honeypot["jsonData"]["pathOptions"] == "mode=ro&immutable=1"
    assert honeypot["jsonData"]["path"] == "/mcp-data/honeypot_mcp.db"
    assert honeypot["isDefault"] is True
    assert any("immutable" in n for n in result["notes"])


# ── the secret ───────────────────────────────────────────────────────────────────────────────


async def test_password_is_in_a_private_file_and_nowhere_else(
    database, docker_client, healthy_probe
):
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=3300)
    password = docker_client.created[0].spec["environment"]["GF_SECURITY_ADMIN_PASSWORD"]
    pw_file = Path(result["password_file"])

    assert len(password) >= 24
    assert pw_file.read_text().strip() == password
    assert oct(pw_file.stat().st_mode & 0o777) == "0o600"
    assert oct(pw_file.parent.stat().st_mode & 0o777) == "0o700"
    assert healthy_probe == [(3300, password)]

    # Not in what the caller gets back, nor in what is recorded about the call.
    assert password not in json.dumps(result, default=str)
    rows = await _audit_rows()
    assert [r.tool for r in rows] == ["grafana_start"]
    blob = json.dumps(
        [rows[0].summary, rows[0].arguments, rows[0].error, rows[0].target], default=str
    )
    assert password not in blob
    assert rows[0].outcome == "ok"
    assert rows[0].arguments == {"port": 3300}


async def test_each_start_generates_a_new_password(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    await grafana_start(port=3300)
    first, second = (
        c.spec["environment"]["GF_SECURITY_ADMIN_PASSWORD"]
        for c in docker_client.created
        if c.labels.get("honeypot-mcp-grafana-role") == "grafana"
    )
    assert first != second


# ── refusals ─────────────────────────────────────────────────────────────────────────────────


async def test_refuses_a_non_sqlite_database_without_touching_docker(monkeypatch, setup_db):
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    def boom():
        raise AssertionError("Docker must not be consulted for a database Grafana cannot read")

    monkeypatch.setattr(grafana, "_docker_client", boom)
    monkeypatch.setattr(
        get_settings(), "database_url", "postgresql+asyncpg://user:pw@db.example/honeypot"
    )

    result = await grafana_start(port=3300)

    assert "SQLite" in result["error"] and "postgresql" in result["error"]
    assert "pw" not in json.dumps(result)  # the URL's credentials are never echoed
    assert result["hint"]
    rows = await _audit_rows()
    assert rows[0].outcome == "error"


async def test_refuses_an_in_memory_database(monkeypatch, setup_db):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    monkeypatch.setattr(get_settings(), "database_url", "sqlite+aiosqlite:///:memory:")
    result = await grafana_start(port=3300)
    assert "in-memory" in result["error"]


async def test_refuses_a_missing_database(tmp_path, monkeypatch, setup_db):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    gone = tmp_path / "nope" / "missing.db"
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{gone}")
    result = await grafana_start(port=3300)
    assert "does not exist" in result["error"]
    assert not (tmp_path / "grafana").exists()


async def test_refuses_a_file_that_is_not_sqlite(tmp_path, monkeypatch, setup_db):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    fake = tmp_path / "notes.db"
    fake.write_text("this is not a database at all, just a text file\n" * 10)
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{fake}")
    result = await grafana_start(port=3300)
    assert "not a SQLite database" in result["error"]


@pytest.mark.parametrize("bad", [0, -1, 65536, "3000", True])
async def test_refuses_a_bad_port(bad, database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=bad)
    assert "port must be" in result["error"]
    assert docker_client.created == []


# ── error mapping: every one is an actionable dict, not a traceback ─────────────────────────


async def test_docker_unavailable_is_a_clear_error(database, monkeypatch):
    from honeypot_mcp.tools.grafana import grafana_start

    def no_daemon(*a, **k):
        raise docker.errors.DockerException("Error while fetching server API version")

    monkeypatch.setattr(docker, "from_env", no_daemon)

    result = await grafana_start(port=3300)

    assert result["error"].startswith("Docker is not available")
    assert "Start Docker" in result["hint"]
    assert [r.outcome for r in await _audit_rows()] == ["error"]


async def test_offline_image_pull_is_a_clear_error_and_leaves_nothing(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp.tools.grafana import grafana_start

    docker_client.have_image = False
    docker_client.pull_error = docker.errors.APIError(
        "dial tcp: lookup registry-1.docker.io: no such host"
    )

    result = await grafana_start(port=3300)

    assert "Could not pull grafana/grafana:11.3.0" in result["error"]
    assert "docker pull grafana/grafana:11.3.0" in result["hint"]
    assert docker_client.created == []
    assert not (tmp_path / "grafana").exists()


async def test_first_start_pulls_the_image_and_says_so(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start

    docker_client.have_image = False
    result = await grafana_start(port=3300)

    assert docker_client.pulled == ["grafana/grafana:11.3.0"]
    assert any("Pulled" in n for n in result["notes"])


async def test_an_image_already_present_is_not_pulled(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    assert docker_client.pulled == []


async def test_busy_port_is_a_clear_error_before_anything_is_created(
    database, docker_client, healthy_probe, monkeypatch, tmp_path
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    monkeypatch.setattr(grafana, "_port_free", lambda port: False)

    result = await grafana_start(port=3300)

    assert "Port 3300 is already in use" in result["error"]
    assert "free port" in result["hint"]
    assert docker_client.created == []
    assert not (tmp_path / "grafana").exists()


async def test_port_race_reported_by_docker_is_mapped_too(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp.tools.grafana import grafana_start

    docker_client.fail_create = (
        "driver failed programming external connectivity: port is already allocated"
    )

    result = await grafana_start(port=3300)

    assert "Port 3300 is already in use" in result["error"]
    assert not (tmp_path / "grafana").exists()


async def test_docker_refusing_the_mount_points_at_file_sharing(
    database, docker_client, healthy_probe
):
    from honeypot_mcp.tools.grafana import grafana_start

    docker_client.fail_create = "mounts denied: The path /x is not shared from the host"
    result = await grafana_start(port=3300)
    assert "File sharing" in result["hint"]


async def test_a_container_that_is_not_ours_is_never_touched(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    squatter = _foreign(docker_client, grafana.CONTAINER_NAME)

    result = await grafana_start(port=3300)

    assert "not created by this server" in result["error"]
    assert docker_client.removed == []
    assert squatter in docker_client.store
    assert docker_client.created == []


async def test_grafana_that_never_becomes_healthy_is_removed_with_its_files(
    database, docker_client, monkeypatch, tmp_path
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    async def sick(port, password, alive, **kw):
        return {
            "healthy": False,
            "datasource_ok": False,
            "tables": [],
            "datasource_error": None,
            "container_exited": True,
        }

    monkeypatch.setattr(grafana, "_probe", sick)
    monkeypatch.setattr(grafana, "_port_free", lambda p: True)

    result = await grafana_start(port=3300)

    assert "exited during start-up" in result["error"]
    assert "level=error msg=boom" in result["error"]  # the log tail is shown
    assert docker_client.store == []
    assert not (tmp_path / "grafana").exists()


async def test_a_datasource_that_does_not_answer_is_reported_not_hidden(
    database, docker_client, monkeypatch
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    async def no_plugin(port, password, alive, **kw):
        return {
            "healthy": True,
            "datasource_ok": False,
            "tables": [],
            "datasource_error": "plugin_not_installed",
            "container_exited": False,
        }

    monkeypatch.setattr(grafana, "_probe", no_plugin)
    monkeypatch.setattr(grafana, "_port_free", lambda p: True)

    result = await grafana_start(port=3300)

    assert result["datasource_ok"] is False
    assert any("did not register it" in n for n in result["notes"])
    assert result["datasource_error"] == "plugin_not_installed"


async def test_an_unexpected_exception_becomes_an_error_dict(
    database, docker_client, healthy_probe, monkeypatch
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    def explode(client):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(grafana, "_ensure_image", explode)
    result = await grafana_start(port=3300)
    assert "RuntimeError" in result["error"] and "kaboom" in result["error"]


# ── result shape ─────────────────────────────────────────────────────────────────────────────


@not_root
async def test_result_carries_what_the_caller_needs(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start

    result = await grafana_start(port=3300)

    assert result["running"] is True
    assert result["username"] == "admin"
    assert result["datasource_ok"] is True
    assert result["db_mount"] == "hardlink"
    assert result["database"] == str(database.resolve())
    assert len(result["dashboards"]) == 5
    assert any("Overview" in d for d in result["dashboards"])
    assert result["dashboard_urls"][result["dashboards"][0]].startswith("http://127.0.0.1:3300/d/")
    assert result["needs_prometheus"] == []
    assert result["datasource_tables"] == ["alert_rollups", "alerts"]


async def test_dashboards_that_need_prometheus_are_reported(
    database, docker_client, healthy_probe, monkeypatch
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    shipped = grafana.list_dashboards()
    flagged = [
        grafana.Dashboard(shipped[0].file, shipped[0].title, shipped[0].uid, True),
        *shipped[1:],
    ]
    monkeypatch.setattr(grafana, "list_dashboards", lambda: flagged)

    result = await grafana_start(port=3300)

    assert result["needs_prometheus"] == [shipped[0].title]
    assert "no data" in result["needs_prometheus_note"]


def test_prometheus_detection_finds_nested_and_string_datasources():
    from honeypot_mcp.grafana import _uses_prometheus

    sql = {"datasource": {"type": "frser-sqlite-datasource", "uid": "honeypot-db"}}
    assert not _uses_prometheus({"panels": [sql, sql]})
    assert _uses_prometheus({"panels": [sql, {"targets": [{"datasource": {"uid": "prometheus"}}]}]})
    assert _uses_prometheus({"panels": [{"datasource": {"type": "prometheus", "uid": "x"}}]})
    assert _uses_prometheus({"panels": [{"datasource": "Prometheus"}]})


# ── analysis mode ────────────────────────────────────────────────────────────────────────────


async def test_works_in_analysis_mode_where_sensor_tools_are_blocked(
    database, docker_client, healthy_probe
):
    """ANALYSIS_MODE refuses deploy/stop; Grafana does not touch sensors and must still run."""
    from honeypot_mcp import instance_lock
    from honeypot_mcp.tools.grafana import grafana_start, grafana_status, grafana_stop
    from honeypot_mcp.tools.honeypot import honeypot_stop

    instance_lock.set_analysis_mode()
    try:
        assert "analysis mode" in (await honeypot_stop(name="x"))["error"]

        started = await grafana_start(port=3300)
        assert "error" not in started and started["datasource_ok"] is True
        assert (await grafana_status())["running"] is True
        assert (await grafana_stop())["stopped"] is True
    finally:
        instance_lock.set_ownership(True)


# ── stop ─────────────────────────────────────────────────────────────────────────────────────


async def test_stop_removes_only_the_labelled_container(database, docker_client, healthy_probe):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start, grafana_stop

    other_grafana = _foreign(docker_client, "someone-elses-grafana", {"app": "grafana"})
    lookalike = _foreign(docker_client, grafana.CONTAINER_NAME + "-2", {"honeypot-mcp": "true"})
    named_like_ours = _foreign(docker_client, grafana.CONTAINER_NAME)
    docker_client.store.remove(named_like_ours)  # the name is free for ours to take

    await grafana_start(port=3300)
    ours = list(docker_client.created)
    docker_client.store.append(named_like_ours)  # ...and now an unlabelled one has that name too

    result = await grafana_stop()

    assert result["stopped"] is True and result["removed_containers"] == 2
    assert result["removed_networks"] == 2
    assert docker_client.removed == ours
    assert all(c.removed_with_volumes is True for c in ours)  # Grafana's anonymous volumes go too
    assert set(docker_client.store) == {other_grafana, lookalike, named_like_ours}
    assert docker_client.network_store == []


async def test_stop_removes_the_private_directory_and_leaves_the_database(
    database, docker_client, healthy_probe
):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start, grafana_stop

    await grafana_start(port=3300)
    assert (get_settings().grafana_dir / "db").is_dir()

    result = await grafana_stop()

    assert result["removed_link_dir"] is True
    assert not get_settings().grafana_dir.exists()
    assert database.exists() and database.stat().st_nlink == 1
    assert sqlite3.connect(database).execute("SELECT count(*) FROM alerts").fetchone() == (5,)


async def test_stop_is_idempotent(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start, grafana_stop

    await grafana_start(port=3300)
    first = await grafana_stop()
    second = await grafana_stop()
    third = await grafana_stop()

    assert first["stopped"] is True
    for again in (second, third):
        assert "error" not in again
        assert again["stopped"] is False and again["removed_link_dir"] is False
        assert "Nothing to stop" in again["note"]
    assert docker_client.store == []


async def test_stop_with_nothing_started_changes_nothing(docker_client, tmp_path):
    from honeypot_mcp import grafana

    unrelated = _foreign(docker_client, "unrelated")
    result = await grafana.stop()
    assert result["stopped"] is False
    assert docker_client.removed == []
    assert unrelated in docker_client.store


async def test_stop_only_removes_what_it_created_under_grafana_dir(
    docker_client, tmp_path, monkeypatch
):
    """GRAFANA_DIR is user-chosen; a stray file the user keeps there must survive a stop, and
    only the exact names this module creates go (never a wildcard, never the directory's other
    contents)."""
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    base = get_settings().grafana_dir
    base.mkdir(parents=True)
    (base / grafana._MARKER).write_text("ours")
    (base / "db").mkdir()
    (base / "db" / "honeypot_mcp.db").write_bytes(b"x")
    (base / "plugins").mkdir()
    (base / "keep-me.txt").write_text("mine")
    (base / "keep-dir").mkdir()

    result = await grafana.stop()

    assert result["removed_link_dir"] is True
    assert (base / "keep-me.txt").read_text() == "mine"
    assert (base / "keep-dir").is_dir()
    assert not (base / "db").exists() and not (base / "plugins").exists()
    assert not (base / grafana._MARKER).exists()


async def test_stop_touches_nothing_in_a_directory_it_did_not_create(
    docker_client, tmp_path, monkeypatch
):
    """No marker, no deletion: a `config/` or `db/` that is the operator's own survives."""
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    base = get_settings().grafana_dir
    (base / "config").mkdir(parents=True)
    (base / "config" / "settings.env").write_text("precious")
    (base / "db").mkdir()
    (base / "admin_password").write_text("also theirs")

    result = await grafana.stop()

    assert result["removed_link_dir"] is False
    assert (base / "config" / "settings.env").read_text() == "precious"
    assert (base / "db").is_dir()
    assert (base / "admin_password").read_text() == "also theirs"


async def test_stop_reports_unreachable_docker_and_leaves_files(database, monkeypatch, tmp_path):
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_stop

    (get_settings().grafana_dir / "db").mkdir(parents=True)

    def no_daemon():
        raise grafana.GrafanaError("Docker is not available (x).", "Start Docker")

    monkeypatch.setattr(grafana, "_docker_client", no_daemon)
    result = await grafana_stop()
    assert result["error"].startswith("Docker is not available")
    assert (get_settings().grafana_dir / "db").exists()


async def test_starting_again_replaces_the_previous_instance(
    database, docker_client, healthy_probe, monkeypatch
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    first = docker_client.created[:2]
    # The port is busy only because of our own container: that must not block the restart.
    monkeypatch.setattr(grafana, "_port_free", lambda port: False)

    result = await grafana_start(port=3300)

    assert "error" not in result, result
    assert all(c in docker_client.removed for c in first)
    assert sorted(c.name for c in docker_client.store) == [
        grafana.CONTAINER_NAME,
        grafana.PROXY_NAME,
    ]
    assert len(docker_client.network_store) == 2  # the old pair was removed, a new pair created


# ── status ───────────────────────────────────────────────────────────────────────────────────


async def test_status_when_nothing_runs(docker_client):
    from honeypot_mcp.tools.grafana import grafana_status

    result = await grafana_status()
    assert result["running"] is False and "grafana_start" in result["note"]


@not_root
async def test_status_reports_what_it_serves_and_no_secrets(database, docker_client, healthy_probe):
    from honeypot_mcp.tools.grafana import grafana_start, grafana_status

    started = await grafana_start(port=3300)
    password = docker_client.created[0].spec["environment"]["GF_SECURITY_ADMIN_PASSWORD"]

    result = await grafana_status()

    assert result["running"] is True
    assert result["url"] == "http://127.0.0.1:3300/"
    assert result["database"] == str(database.resolve())
    assert result["db_mount"] == "hardlink"
    assert result["dashboards"] == started["dashboards"]
    assert result["uptime_seconds"] > 0
    assert password not in json.dumps(result)
    assert "password" not in json.dumps(result).lower()


async def test_status_with_docker_down_is_an_error_not_a_guess(monkeypatch):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_status

    def no_daemon():
        raise grafana.GrafanaError("Docker is not available (x).", "Start Docker")

    monkeypatch.setattr(grafana, "_docker_client", no_daemon)
    result = await grafana_status()
    assert result["running"] is None and "Docker is not available" in result["error"]


# ── the database view, without Docker ────────────────────────────────────────────────────────


def _src(db: Path):
    from honeypot_mcp import grafana

    return grafana.inspect_database(f"sqlite+aiosqlite:///{db}")


def _fresh_view(tmp_path: Path) -> Path:
    view = tmp_path / "view"
    view.mkdir(mode=0o700)
    return view


def test_a_failed_hardlink_falls_back_to_a_consistent_copy(tmp_path, monkeypatch):
    from honeypot_mcp import grafana

    db = _make_db(tmp_path / "src" / "app.db")
    writer = sqlite3.connect(db)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.executemany("INSERT INTO alerts (x) VALUES (?)", [("live",)] * 3)
    writer.commit()  # three rows exist only in the write-ahead log

    def refuse(*a, **k):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(os, "link", refuse)
    monkeypatch.setattr(grafana, "_reflink", lambda s, d: False)
    view_dir = _fresh_view(tmp_path)
    try:
        view = grafana.build_view(_src(db), view_dir, max_copy_mb=100)
    finally:
        writer.close()

    assert view.mount == "copy" and view.live is False
    assert "different filesystem" in view.notes[0]
    assert sorted(os.listdir(view_dir)) == ["honeypot_mcp.db"]
    copy = view_dir / "honeypot_mcp.db"
    assert oct(copy.stat().st_mode & 0o777) == "0o600"
    conn = sqlite3.connect(copy)
    assert conn.execute("SELECT count(*) FROM alerts").fetchone() == (8,)  # the log was folded in
    # Rewritten out of WAL mode, so a read-only mount can open it.
    assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    conn.close()


def test_a_snapshot_prefers_a_reflink_when_the_filesystem_can(tmp_path, monkeypatch):
    from honeypot_mcp import grafana

    db = _make_db(tmp_path / "src" / "app.db")

    def refuse(*a, **k):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    def fake_reflink(src, dst):
        dst.write_bytes(src.read_bytes())
        return True

    monkeypatch.setattr(os, "link", refuse)
    monkeypatch.setattr(grafana, "_reflink", fake_reflink)
    view_dir = _fresh_view(tmp_path)

    view = grafana.build_view(_src(db), view_dir, max_copy_mb=0)  # a plain copy is not allowed

    assert view.mount == "reflink"
    conn = sqlite3.connect(view_dir / "honeypot_mcp.db")
    assert conn.execute("SELECT count(*) FROM alerts").fetchone() == (5,)
    assert conn.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    conn.close()


def test_a_database_too_big_to_copy_is_refused_with_the_way_out(tmp_path, monkeypatch):
    from honeypot_mcp import grafana

    db = _make_db(tmp_path / "src" / "app.db", rows=5000)

    def refuse(*a, **k):
        raise OSError(errno.EXDEV, "Invalid cross-device link")

    monkeypatch.setattr(os, "link", refuse)
    monkeypatch.setattr(grafana, "_reflink", lambda s, d: False)
    big = dataclasses.replace(_src(db), size_bytes=3 * 1024 * 1024 * 1024)

    with pytest.raises(grafana.GrafanaError) as exc:
        grafana.build_view(big, _fresh_view(tmp_path), max_copy_mb=2048)

    assert "GRAFANA_MAX_COPY_MB" in exc.value.message
    assert "GRAFANA_DIR" in (exc.value.hint or "")


def test_wal_frames_without_a_shm_file_cannot_be_read_in_place_so_they_are_snapshotted(tmp_path):
    """Hardlinking just the .db would silently drop the recent alerts that are still in the log."""
    from honeypot_mcp import grafana

    live = _make_db(tmp_path / "live" / "app.db")
    writer = sqlite3.connect(live)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.executemany("INSERT INTO alerts (x) VALUES (?)", [("live",)] * 3)
    writer.commit()
    stranded = tmp_path / "stranded"
    stranded.mkdir()
    try:
        for suffix in ("", "-wal"):  # a copy of the files with the shared-memory file left behind
            (stranded / f"app.db{suffix}").write_bytes(
                (live.parent / f"app.db{suffix}").read_bytes()
            )
    finally:
        writer.close()
    src = _src(stranded / "app.db")
    assert src.wal_bytes > 0 and not src.shm_exists

    view_dir = _fresh_view(tmp_path)
    view = grafana.build_view(src, view_dir, max_copy_mb=100)

    assert view.mount in ("reflink", "copy")
    conn = sqlite3.connect(view_dir / "honeypot_mcp.db")
    assert conn.execute("SELECT count(*) FROM alerts").fetchone() == (8,)
    conn.close()


def test_a_link_failure_that_is_not_about_the_filesystem_is_not_papered_over(tmp_path, monkeypatch):
    from honeypot_mcp import grafana

    db = _make_db(tmp_path / "src" / "app.db")

    def disk_full(*a, **k):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(os, "link", disk_full)
    with pytest.raises(grafana.GrafanaError, match="Could not link"):
        grafana.build_view(_src(db), _fresh_view(tmp_path), max_copy_mb=100)


def test_database_url_forms(tmp_path):
    from honeypot_mcp.grafana import GrafanaError, database_path

    assert database_path("sqlite+aiosqlite:////var/lib/x/a.db") == Path("/var/lib/x/a.db")
    assert database_path("sqlite:///rel/a.db?mode=ro") == Path("rel/a.db")
    for bad in (
        "postgresql://u@h/d",
        "mysql+aiomysql://u@h/d",
        "sqlite+aiosqlite:///:memory:",
        "sqlite://",
    ):
        with pytest.raises(GrafanaError):
            database_path(bad)


# ── the real readiness probe, against a stand-in Grafana ─────────────────────────────────────


@pytest.fixture
async def fake_grafana():
    """A tiny HTTP server speaking just enough of Grafana's API to drive `_probe`."""
    from aiohttp import web

    state = SimpleNamespace(
        health_status=200,
        ds_payload={
            "results": {"A": {"frames": [{"data": {"values": [["alert_rollups", "alerts"]]}}]}}
        },
        ds_status=200,
        seen_auth=[],
    )

    async def health(request):
        return web.json_response({"database": "ok"}, status=state.health_status)

    async def query(request):
        state.seen_auth.append(request.headers.get("Authorization"))
        return web.json_response(state.ds_payload, status=state.ds_status)

    app = web.Application()
    app.router.add_get("/api/health", health)
    app.router.add_post("/api/ds/query", query)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    await web.TCPSite(runner, "127.0.0.1", port).start()
    state.port = port
    yield state
    await runner.cleanup()


async def test_probe_confirms_health_and_a_datasource_query(fake_grafana):
    from honeypot_mcp import grafana

    result = await grafana._probe(fake_grafana.port, "pw", lambda: True, health_timeout=5)

    assert result["healthy"] and result["datasource_ok"]
    assert result["tables"] == ["alert_rollups", "alerts"]
    assert fake_grafana.seen_auth[0].startswith("Basic ")


async def test_probe_reports_a_missing_plugin(fake_grafana):
    from honeypot_mcp import grafana

    fake_grafana.ds_status = 404
    fake_grafana.ds_payload = {
        "message": "Plugin not registered",
        "messageId": "plugin.notRegistered",
    }

    result = await grafana._probe(
        fake_grafana.port, "pw", lambda: True, health_timeout=5, datasource_timeout=0.5
    )

    assert result["healthy"] and not result["datasource_ok"]
    assert result["datasource_error"] == "plugin_not_installed"


async def test_probe_reports_a_datasource_error_from_the_plugin(fake_grafana):
    from honeypot_mcp import grafana

    fake_grafana.ds_payload = {"results": {"A": {"error": "unable to open database file (14)"}}}
    result = await grafana._probe(
        fake_grafana.port, "pw", lambda: True, health_timeout=5, datasource_timeout=0.5
    )
    assert not result["datasource_ok"]
    assert "unable to open database file" in result["datasource_error"]


async def test_probe_stops_waiting_when_the_container_has_exited(fake_grafana):
    from honeypot_mcp import grafana

    fake_grafana.health_status = 503
    result = await grafana._probe(fake_grafana.port, "pw", lambda: False, health_timeout=30)
    assert result["container_exited"] and not result["healthy"]


async def test_probe_gives_up_after_the_bound(fake_grafana):
    import time

    from honeypot_mcp import grafana

    fake_grafana.health_status = 503
    started = time.monotonic()
    result = await grafana._probe(fake_grafana.port, "pw", lambda: True, health_timeout=1.5)
    assert not result["healthy"] and not result["container_exited"]
    assert time.monotonic() - started < 6


def test_port_probe_sees_a_listener_and_a_free_port():
    from honeypot_mcp.grafana import _port_free

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        busy = listener.getsockname()[1]
        assert _port_free(busy) is False
    assert _port_free(busy) is True


# ── packaging ────────────────────────────────────────────────────────────────────────────────


def test_grafana_assets_ship_with_the_package():
    """Resolved through importlib.resources, like the presets and the console page: a wheel that
    omits them builds and imports fine and then `grafana_start` has nothing to provision."""
    from honeypot_mcp import grafana

    root = resources.files("honeypot_mcp") / "grafana_assets"
    assert (root / "provisioning" / "datasources" / "datasources.yml").is_file()
    assert (root / "provisioning" / "dashboards" / "dashboards.yml").is_file()
    dashboards = grafana.list_dashboards()
    assert [d.file for d in dashboards] == [
        "01-overview.json",
        "02-threat-map.json",
        "03-mitre-coverage.json",
        "04-query.json",
        "05-alerts.json",
    ]
    assert all(d.title and d.uid for d in dashboards)
    ds = yaml.safe_load((root / "provisioning" / "datasources" / "datasources.yml").read_text())
    assert {d["uid"] for d in ds["datasources"]} == {"prometheus", "honeypot-db"}


def test_materialised_config_is_a_faithful_copy_of_the_package(tmp_path):
    from honeypot_mcp import grafana

    grafana.materialise_assets(tmp_path / "cfg", immutable=False)

    packaged = resources.files("honeypot_mcp") / "grafana_assets" / "dashboards"
    for f in packaged.iterdir():
        copy = tmp_path / "cfg" / "dashboards" / f.name
        assert copy.read_bytes() == f.read_bytes()
        assert oct(copy.stat().st_mode & 0o777) == "0o644"
    provider = yaml.safe_load(
        (tmp_path / "cfg" / "provisioning" / "dashboards" / "dashboards.yml").read_text()
    )
    assert provider["providers"][0]["options"]["path"] == "/etc/grafana/dashboards"
    ds = yaml.safe_load(
        (tmp_path / "cfg" / "provisioning" / "datasources" / "datasources.yml").read_text()
    )
    by_uid = {d["uid"]: d for d in ds["datasources"]}
    assert by_uid["honeypot-db"]["isDefault"] is True
    assert by_uid["prometheus"]["isDefault"] is False


def test_wheel_config_declares_the_grafana_assets():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["hatch"]["build"][
        "targets"
    ]["wheel"]["artifacts"]
    assert "src/honeypot_mcp/grafana_assets/dashboards/*.json" in declared
    assert "src/honeypot_mcp/grafana_assets/provisioning/**/*.yml" in declared


def test_there_is_one_copy_of_the_assets_and_the_compose_files_mount_it():
    """The old `docker/grafana` copy must be gone, and both compose files must point at the
    package's directory (relative to `docker/`), which must exist."""
    assert not (ROOT / "docker" / "grafana").exists()
    for name in ("docker-compose.yml", "docker-compose.observability.yml"):
        compose = yaml.safe_load((ROOT / "docker" / name).read_text())
        mounts = [v for v in compose["services"]["grafana"]["volumes"] if ":/etc/grafana/" in v]
        assert len(mounts) == 2, name
        for mount in mounts:
            host = mount.split(":")[0]
            assert host.startswith("../src/honeypot_mcp/grafana_assets/"), (name, host)
            assert (ROOT / "docker" / host).is_dir(), (name, host)


def test_nothing_in_the_repo_still_points_at_the_old_location():
    needle = "docker/grafana"
    stale = []
    for base in ("scripts", "tests", "src", ".github", "docker", "deploy"):
        for path in (ROOT / base).rglob("*"):
            if (
                path.is_file()
                and path.suffix in {".py", ".sh", ".yml", ".yaml", ".toml", ".conf", ".json"}
                and path.name != "test_grafana.py"
                and "__pycache__" not in path.parts
                and needle in path.read_text(errors="ignore")
            ):
                stale.append(str(path.relative_to(ROOT)))
    assert stale == []


# ── classification ───────────────────────────────────────────────────────────────────────────


def test_tiers():
    from honeypot_mcp import rbac

    assert "grafana_status" in rbac.VIEWER_TOOLS
    assert {"grafana_start", "grafana_stop"} <= rbac.ADMIN_TOOLS
    assert not {"grafana_start", "grafana_stop"} & (rbac.OPERATOR_TOOLS | rbac.VIEWER_TOOLS)


async def test_start_and_stop_carry_an_admin_gate_and_status_does_not():
    from honeypot_mcp.server import mcp

    tools = {t.name: t for t in await mcp.list_tools()}
    assert tools["grafana_start"].auth is not None
    assert tools["grafana_stop"].auth is not None
    assert tools["grafana_status"].auth is None
    assert tools["grafana_status"].annotations.readOnlyHint is True
    assert tools["grafana_start"].annotations.openWorldHint is True
    # It removes the previous instance (containers, networks, private directory) before
    # recreating it, so a client must be told it is destructive, not merely additive.
    assert tools["grafana_start"].annotations.destructiveHint is True
    assert tools["grafana_start"].annotations.readOnlyHint is False


# ── the plugin: pinned, checksummed, unpacked as hostile ─────────────────────────────────────


def _plugin_zip(members: dict[str, bytes], *, symlink: tuple[str, str] | None = None) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o100755 if "gpx_" in name else 0o100644) << 16
            zf.writestr(info, data)
        if symlink:
            info = zipfile.ZipInfo(symlink[0])
            info.external_attr = 0o120777 << 16
            zf.writestr(info, symlink[1])
    return buf.getvalue()


_GOOD_MEMBERS = {
    "frser-sqlite-datasource/plugin.json": b'{"id": "frser-sqlite-datasource"}',
    "frser-sqlite-datasource/module.js": b"//",
    "frser-sqlite-datasource/gpx_sqlite-datasource_linux_amd64": b"\x7fELF-linux",
    "frser-sqlite-datasource/gpx_sqlite-datasource_darwin_arm64": b"MACH-O",
}


@pytest.fixture
def plugin_download(monkeypatch):
    """Serve `payload` as the plugin download, with the pinned checksum following it."""
    import hashlib

    from honeypot_mcp import grafana

    class Download:
        requested: list[str] = []

        def serve(self, payload: bytes, *, pin: bool = True) -> None:
            if pin:
                monkeypatch.setattr(
                    grafana, "SQLITE_PLUGIN_SHA256", hashlib.sha256(payload).hexdigest()
                )
            real = httpx.Client

            def handler(request: httpx.Request) -> httpx.Response:
                self.requested.append(str(request.url))
                return httpx.Response(200, content=payload)

            monkeypatch.setattr(
                grafana.httpx,
                "Client",
                lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
            )

    return Download()


def test_the_plugin_is_pinned_to_an_exact_version_and_a_checksum():
    import re

    from honeypot_mcp import grafana

    assert re.fullmatch(r"\d+\.\d+\.\d+", grafana.SQLITE_PLUGIN_VERSION)
    assert re.fullmatch(r"[0-9a-f]{64}", grafana.SQLITE_PLUGIN_SHA256)
    assert f"/versions/{grafana.SQLITE_PLUGIN_VERSION}/download" in grafana.SQLITE_PLUGIN_URL
    assert grafana.SQLITE_PLUGIN_URL.startswith("https://")


def test_a_verified_plugin_is_unpacked_whole_and_executable(tmp_path, plugin_download):
    from honeypot_mcp import grafana

    plugin_download.serve(_plugin_zip(_GOOD_MEMBERS))
    grafana._install_plugin(tmp_path / "plugins")

    root = tmp_path / "plugins" / "frser-sqlite-datasource"
    # Every file, other platforms' binaries included: Grafana checks the whole signed manifest.
    assert sorted(p.name for p in root.iterdir()) == sorted(n.split("/")[1] for n in _GOOD_MEMBERS)
    assert oct((root / "gpx_sqlite-datasource_linux_amd64").stat().st_mode & 0o777) == "0o755"
    assert oct((root / "plugin.json").stat().st_mode & 0o777) == "0o644"
    assert oct((tmp_path / "plugins").stat().st_mode & 0o777) == "0o755"
    assert plugin_download.requested[-1] == grafana.SQLITE_PLUGIN_URL
    # The downloaded archive lived in an unnamed temporary file: nothing else is left behind.
    assert [p.name for p in tmp_path.iterdir()] == ["plugins"]


def test_a_plugin_that_does_not_match_the_pinned_checksum_is_refused_and_not_unpacked(
    tmp_path, plugin_download
):
    """The finding: unpinned and unsigned. A different file at the same URL must fail closed."""
    from honeypot_mcp import grafana

    plugin_download.serve(_plugin_zip(_GOOD_MEMBERS), pin=False)
    with pytest.raises(grafana.GrafanaError) as exc:
        grafana._install_plugin(tmp_path / "plugins")

    assert "does not match the pinned checksum" in exc.value.message
    assert exc.value.hint and "SQLITE_PLUGIN_SHA256" in exc.value.hint
    assert list((tmp_path / "plugins").iterdir()) == []


@pytest.mark.parametrize(
    "members, symlink, why",
    [
        ({"frser-sqlite-datasource/../evil": b"x"}, None, "unexpected entry"),
        ({"other-plugin/plugin.json": b"x"}, None, "unexpected entry"),
        ({"/etc/cron.d/x": b"x"}, None, "unexpected entry"),
        ({"frser-sqlite-datasource\\..\\x": b"x"}, None, "unexpected entry"),
        ({}, ("frser-sqlite-datasource/link", "/etc/passwd"), "symlink"),
    ],
)
def test_a_hostile_archive_cannot_write_outside_or_plant_symlinks(
    tmp_path, plugin_download, members, symlink, why
):
    """Pinned and hashed, but unpacked as if it were not: defence in depth."""
    from honeypot_mcp import grafana

    plugin_download.serve(_plugin_zip(members, symlink=symlink))
    with pytest.raises(grafana.GrafanaError) as exc:
        grafana._install_plugin(tmp_path / "plugins")

    assert why in exc.value.message
    assert not (tmp_path / "evil").exists()
    assert not any(p.is_symlink() for p in (tmp_path / "plugins").rglob("*"))


def test_an_archive_that_unpacks_to_an_implausible_size_is_refused(
    tmp_path, plugin_download, monkeypatch
):
    from honeypot_mcp import grafana

    monkeypatch.setattr(grafana, "_PLUGIN_MAX_UNPACKED", 10)
    plugin_download.serve(_plugin_zip(_GOOD_MEMBERS))
    with pytest.raises(grafana.GrafanaError, match="implausible size"):
        grafana._install_plugin(tmp_path / "plugins")


def test_an_oversized_download_is_refused(tmp_path, plugin_download, monkeypatch):
    from honeypot_mcp import grafana

    monkeypatch.setattr(grafana, "_PLUGIN_MAX_DOWNLOAD", 10)
    plugin_download.serve(_plugin_zip(_GOOD_MEMBERS))
    with pytest.raises(grafana.GrafanaError, match="exceeded"):
        grafana._install_plugin(tmp_path / "plugins")


def test_an_offline_plugin_download_is_a_clear_error_with_the_way_out(tmp_path, monkeypatch):
    from honeypot_mcp import grafana

    def offline(**kw):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(grafana.httpx, "Client", offline)
    with pytest.raises(grafana.GrafanaError) as exc:
        grafana._install_plugin(tmp_path / "plugins")

    assert "Could not download" in exc.value.message and "ConnectError" in exc.value.message
    assert exc.value.hint and "internet access" in exc.value.hint


async def test_a_failed_plugin_install_leaves_no_containers_and_no_files(
    database, docker_client, healthy_probe, monkeypatch, tmp_path
):
    from honeypot_mcp import grafana
    from honeypot_mcp.tools.grafana import grafana_start

    def refuse(plugins_dir):
        raise grafana.GrafanaError("Could not download the SQLite datasource plugin", "retry")

    monkeypatch.setattr(grafana, "_install_plugin", refuse)
    result = await grafana_start(port=3300)

    assert "Could not download" in result["error"]
    assert docker_client.created == [] and docker_client.network_store == []
    assert not (tmp_path / "grafana").exists()


# ── GRAFANA_DIR must be dedicated ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "where",
    ["root", "parent_of_root", "config", "inside_config"],
)
async def test_a_grafana_dir_that_is_the_project_root_or_config_is_refused_untouched(
    where, database, docker_client, healthy_probe, tmp_path, monkeypatch
):
    """The finding: GRAFANA_DIR=<project root> chmod'ed it 0700 and rmtree'd the operator's
    `config/`. Refused before anything is created, removed or changed. (A stand-in project
    root: this test must never be able to hurt the real checkout.)"""
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    root = (tmp_path / "project").resolve()
    (root / "config").mkdir(parents=True)
    (root / "config" / "GeoLite2-City.mmdb").write_text("precious")
    monkeypatch.setattr(grafana, "_PROJECT_ROOT", root)
    chosen = {
        "root": root,
        "parent_of_root": root.parent,
        "config": root / "config",
        "inside_config": root / "config" / "grafana-work",
    }[where]
    root_mode = root.stat().st_mode
    chosen_mode = chosen.stat().st_mode if chosen.exists() else None
    get_settings().grafana_dir = chosen

    started = await grafana.start(3300)
    stopped = await grafana.stop()

    assert "GRAFANA_DIR" in started["error"]
    assert "project root" in started["error"] or "config/" in started["error"]
    assert "error" not in stopped and stopped["removed_link_dir"] is False
    assert docker_client.created == [] and docker_client.network_store == []
    assert (root / "config" / "GeoLite2-City.mmdb").read_text() == "precious"
    assert root.stat().st_mode == root_mode  # not chmod'ed 0700
    if chosen_mode is not None:
        assert chosen.stat().st_mode == chosen_mode
    assert not (chosen / grafana._MARKER).exists()


async def test_a_directory_with_other_things_in_it_is_refused_and_nothing_is_deleted(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    shared = tmp_path / "shared"
    (shared / "config").mkdir(parents=True)
    (shared / "config" / "mine.yaml").write_text("keep")
    (shared / "db").mkdir()
    (shared / "notes.txt").write_text("keep")
    get_settings().grafana_dir = shared
    before = oct(shared.stat().st_mode & 0o777)

    result = await grafana_start(port=3300)

    assert "not empty and was not created by grafana_start" in result["error"]
    assert "config" in result["error"] and "notes.txt" in result["error"]
    assert (shared / "config" / "mine.yaml").read_text() == "keep"
    assert (shared / "db").is_dir() and (shared / "notes.txt").read_text() == "keep"
    assert oct(shared.stat().st_mode & 0o777) == before  # not chmod'ed
    assert docker_client.created == []


async def test_a_refused_grafana_dir_does_not_take_down_the_running_instance(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    await grafana_start(port=3300)
    running = list(docker_client.store)
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "x").write_text("x")
    get_settings().grafana_dir = tmp_path / "other"

    result = await grafana_start(port=3300)

    assert "error" in result
    assert docker_client.store == running and docker_client.removed == []


async def test_an_empty_or_new_dedicated_directory_is_claimed_with_a_marker(
    database, docker_client, healthy_probe, tmp_path
):
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start, grafana_stop

    for name in ("fresh", "empty"):
        base = tmp_path / name
        if name == "empty":
            base.mkdir()
        get_settings().grafana_dir = base
        result = await grafana_start(port=3300)
        assert "error" not in result, result
        assert (base / grafana._MARKER).is_file()
        assert oct(base.stat().st_mode & 0o777) == "0o700"
        assert sorted(p.name for p in base.iterdir()) == sorted(
            [grafana._MARKER, "admin_password", "config", "db", "plugins"]
        )
        await grafana_stop()
        assert not base.exists()  # marker and contents gone, and the then-empty directory too


async def test_a_symlinked_grafana_dir_cannot_point_the_cleanup_at_the_project(
    database, docker_client, healthy_probe, tmp_path, monkeypatch
):
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    root = (tmp_path / "project").resolve()
    (root / "config").mkdir(parents=True)
    monkeypatch.setattr(grafana, "_PROJECT_ROOT", root)
    link = tmp_path / "innocent-looking"
    link.symlink_to(root, target_is_directory=True)
    get_settings().grafana_dir = link

    result = await grafana_start(port=3300)

    assert "project root" in result["error"]
    assert not (root / grafana._MARKER).exists()
    assert (root / "config").is_dir()


async def test_a_marker_that_is_a_symlink_does_not_make_a_directory_ours(tmp_path):
    from honeypot_mcp import grafana

    base = tmp_path / "d"
    base.mkdir()
    (base / "db").mkdir()
    real = tmp_path / "real-marker"
    real.write_text("x")
    (base / grafana._MARKER).symlink_to(real)

    assert grafana._cleanup_files(base) is False
    assert (base / "db").is_dir()


# ── never uid 0 ──────────────────────────────────────────────────────────────────────────────


def test_the_container_spec_refuses_uid_zero(tmp_path):
    from honeypot_mcp import grafana

    kw = dict(
        password="x" * 24,
        view_dir=tmp_path,
        config_dir=tmp_path,
        plugins_dir=tmp_path,
        db=tmp_path / "a.db",
    )
    with pytest.raises(grafana.GrafanaError, match="uid 0"):
        grafana._container_spec(db_uid=0, **kw)
    # An unknown owner falls back to Grafana's own uid, never to root.
    assert grafana._container_spec(db_uid=None, **kw)["user"] == "472:0"
    assert grafana._container_spec(db_uid=1000, **kw)["user"] == "1000:0"


@pytest.mark.parametrize(
    "server_uid, db_owner_uid",
    [(0, 0), (0, 1000), (1000, 0), (1000, 1000), (1000, 2000)],
)
async def test_grafana_never_runs_as_root_whoever_owns_what(
    server_uid, db_owner_uid, database, docker_client, healthy_probe, monkeypatch
):
    """The finding: the container ran as `<db owner>:0`, so a root server (or a root-owned
    database) put Grafana and a downloaded native binary at uid 0."""
    import dataclasses

    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    real_inspect = grafana.inspect_database
    monkeypatch.setattr(
        grafana,
        "inspect_database",
        lambda url: dataclasses.replace(real_inspect(url), uid=db_owner_uid),
    )
    monkeypatch.setattr(grafana, "_host_uid", lambda: server_uid)
    chowned: list[tuple[str, int, int]] = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))

    result = await grafana_start(port=3300)

    assert "error" not in result, result
    uid, _, gid = docker_client.grafana.spec["user"].partition(":")
    assert int(uid) != 0, docker_client.grafana.spec["user"]
    assert gid == "0"  # group 0 is what Grafana's own data directory is writable by
    if db_owner_uid == 0:
        # A root-owned file is never hardlinked (that would need a root container): a snapshot.
        assert result["db_mount"] in ("reflink", "copy")
        if server_uid == 0:
            assert int(uid) == 472
            # ... and a snapshot made by a root server is handed to that unprivileged uid.
            assert chowned and all(u == 472 and g == 0 for _, u, g in chowned)
            db = get_settings().grafana_dir / "db" / grafana.DB_FILENAME
            assert chowned[0][0] == str(db)
        else:
            assert int(uid) == server_uid
    else:
        assert result["db_mount"] == "hardlink"
        assert int(uid) == db_owner_uid
        assert chowned == []  # a live hardlink is the original inode: never chowned


async def test_a_snapshot_is_readable_by_the_container_user_not_just_the_owner(
    database, docker_client, healthy_probe, monkeypatch
):
    """Root server + root-owned DB: the container is 472, so the private directory it must
    traverse is opened up; the snapshot file itself stays 0600."""
    import dataclasses

    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools.grafana import grafana_start

    real_inspect = grafana.inspect_database
    monkeypatch.setattr(
        grafana, "inspect_database", lambda url: dataclasses.replace(real_inspect(url), uid=0)
    )
    monkeypatch.setattr(grafana, "_host_uid", lambda: 0)
    monkeypatch.setattr(os, "chown", lambda *a: None)

    result = await grafana_start(port=3300)

    assert "error" not in result, result
    view = get_settings().grafana_dir / "db"
    assert oct(view.stat().st_mode & 0o777) == "0o755"
    assert oct((view / grafana.DB_FILENAME).stat().st_mode & 0o777) == "0o600"
    assert os.listdir(view) == [grafana.DB_FILENAME]
