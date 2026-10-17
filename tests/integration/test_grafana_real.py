"""Does `grafana_start` really put a working Grafana on a database, through a real Docker daemon?

`tests/unit/test_grafana.py` pins the arguments handed to a fake Docker client. It cannot show
what only the daemon can: that a read-only bind mount of a 0600, WAL-mode SQLite file is readable
inside the container, that the SQLite plugin loads on a read-only root filesystem, and that
Grafana's own API returns the data. Those are the properties that failed first, and the ones a
fake agrees with by construction.

Opt-in (`RUN_DOCKER_TESTS=1`): it needs `grafana/grafana:11.3.0` (pulled on first use) and
internet access for the SQLite plugin, and takes about 30 seconds. Skips itself without Docker.
"""

from __future__ import annotations

import os
import socket
import sqlite3
from pathlib import Path

import httpx
import pytest


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
    reason="needs Docker and RUN_DOCKER_TESTS=1 (runs a Grafana container)",
)


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_wal_db(path: Path, rows: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, x TEXT)")
    conn.execute("CREATE TABLE alert_rollups (count INTEGER)")
    conn.executemany("INSERT INTO alerts (x) VALUES (?)", [("a",)] * rows)
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    path.chmod(0o600)


async def _grafana_count(port: int, password_file: str, sql: str) -> int:
    password = Path(password_file).read_text().strip()
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"uid": "honeypot-db", "type": "frser-sqlite-datasource"},
                "queryText": sql,
                "rawQueryText": sql,
                "queryType": "table",
                "timeColumns": [],
            }
        ],
        "from": "now-1h",
        "to": "now",
    }
    async with httpx.AsyncClient(timeout=30, trust_env=False) as http:
        health = await http.get(f"http://127.0.0.1:{port}/api/health")
        assert health.json()["database"] == "ok"
        # No anonymous access.
        assert (await http.get(f"http://127.0.0.1:{port}/api/search")).status_code == 401
        resp = await http.post(
            f"http://127.0.0.1:{port}/api/ds/query", json=body, auth=("admin", password)
        )
    return resp.json()["results"]["A"]["frames"][0]["data"]["values"][0][0]


@skip_docker
async def test_grafana_reads_a_0600_wal_database_through_a_read_only_hardlink(
    tmp_path, monkeypatch
):
    import docker
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    db = tmp_path / "data" / "honeypot_mcp.db"
    _make_wal_db(db, rows=7)
    (db.parent / ".env").write_text("MCP_AUTH_TOKEN=must-never-be-mounted\n")
    settings = get_settings()
    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db}")
    monkeypatch.setattr(settings, "grafana_dir", tmp_path / "grafana")
    port = _free_port()

    result = await grafana.start(port)
    try:
        assert "error" not in result, result
        assert result["db_mount"] == "hardlink"
        assert result["datasource_ok"] is True
        assert (
            await _grafana_count(port, result["password_file"], "select count(*) from alerts") == 7
        )

        # Only the database files are visible inside the container.
        client = docker.from_env()
        container = client.containers.get(grafana.CONTAINER_NAME)
        code, listing = container.exec_run(["ls", "-A", "/mcp-data"])
        assert code == 0 and listing.decode().split() == ["honeypot_mcp.db"]
        # The container with the data publishes nothing; the forwarder publishes loopback only.
        assert not container.attrs["HostConfig"]["PortBindings"]
        proxy = client.containers.get(grafana.PROXY_NAME)
        assert proxy.attrs["HostConfig"]["PortBindings"]["3000/tcp"][0]["HostIp"] == "127.0.0.1"
        # Never root, and the plugin was verified by Grafana's own signature check.
        code, ident = container.exec_run(["id", "-u"])
        assert code == 0 and ident.decode().strip() != "0"
        assert "Plugin registered" in container.logs().decode()
    finally:
        stopped = await grafana.stop()

    assert stopped["stopped"] is True and stopped["removed_containers"] == 2
    assert not (tmp_path / "grafana").exists()
    client = docker.from_env()
    assert client.containers.list(all=True, filters={"label": "honeypot-mcp=grafana"}) == []
    assert client.networks.list(filters={"label": "honeypot-mcp=grafana"}) == []
    assert db.exists()


@skip_docker
async def test_grafana_sees_a_live_writers_uncheckpointed_alerts(tmp_path, monkeypatch):
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    db = tmp_path / "data" / "honeypot_mcp.db"
    _make_wal_db(db, rows=5)
    writer = sqlite3.connect(db)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.executemany("INSERT INTO alerts (x) VALUES (?)", [("live",)] * 3)
    writer.commit()  # in the write-ahead log only
    settings = get_settings()
    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db}")
    monkeypatch.setattr(settings, "grafana_dir", tmp_path / "grafana")
    port = _free_port()

    result = await grafana.start(port)
    try:
        assert "error" not in result, result
        assert result["db_mount"] == "hardlink"
        assert (
            await _grafana_count(port, result["password_file"], "select count(*) from alerts") == 8
        )
    finally:
        writer.close()
        await grafana.stop()


@skip_docker
async def test_the_container_that_holds_the_data_has_no_route_out(tmp_path, monkeypatch):
    """The claim in the module docstring, on a real daemon: Grafana (with the whole database
    mounted) cannot reach the internet, a sibling container on Docker's default network, or
    anything else, while the dashboards still work through the loopback port."""
    import docker
    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    db = tmp_path / "data" / "honeypot_mcp.db"
    _make_wal_db(db, rows=4)
    settings = get_settings()
    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db}")
    monkeypatch.setattr(settings, "grafana_dir", tmp_path / "grafana")
    port = _free_port()
    client = docker.from_env()
    # A listener on the default bridge: reachable by its neighbours, which is what an SSRF from a
    # compromised Grafana would try to reach (another container, an internal service).
    victim = client.containers.run(
        grafana.GRAFANA_IMAGE,
        entrypoint=["busybox", "nc", "-ll", "-p", "8000", "-e", "echo", "secret"],
        detach=True,
        labels={"honeypot-mcp-test": "grafana-egress"},
    )
    neighbour = None
    result = await grafana.start(port)
    try:
        assert "error" not in result, result
        victim.reload()
        victim_ip = victim.attrs["NetworkSettings"]["Networks"]["bridge"]["IPAddress"]
        neighbour = client.containers.run(
            grafana.GRAFANA_IMAGE,
            entrypoint=["sleep", "120"],
            detach=True,
            labels={"honeypot-mcp-test": "grafana-egress"},
        )
        # Control: the listener IS reachable from another container on the default network.
        code, _ = neighbour.exec_run(["nc", "-w", "3", "-z", victim_ip, "8000"])
        assert code == 0, "the control listener must be reachable, or this test proves nothing"

        container = client.containers.get(grafana.CONTAINER_NAME)
        code, routes = container.exec_run(["sh", "-c", "ip route | grep -c '^default' || true"])
        assert routes.decode().strip() == "0"  # no default route at all
        for target in (f"{victim_ip} 8000", "1.1.1.1 53", "169.254.169.254 80"):
            code, out = container.exec_run(["sh", "-c", f"nc -w 3 -z {target}"])
            assert code != 0, f"Grafana reached {target}"
        code, _ = container.exec_run(["nslookup", "grafana.com"])
        assert code != 0  # no DNS either

        # ... and it is not a broken Grafana: the dashboards and the datasource answer.
        assert result["datasource_ok"] is True
        assert (
            await _grafana_count(port, result["password_file"], "select count(*) from alerts") == 4
        )
    finally:
        await grafana.stop()
        for c in (victim, neighbour):
            if c is not None:
                c.remove(force=True)


@skip_docker
async def test_grafana_readers_do_not_hold_up_the_writers_checkpoints(tmp_path, monkeypatch):
    """Backs the module docstring's WAL paragraph with a measurement: dashboards read the live
    hardlinked database continuously; the server's own checkpoints must still complete."""
    import asyncio
    import time

    from honeypot_mcp import grafana
    from honeypot_mcp.config import get_settings

    db = tmp_path / "data" / "honeypot_mcp.db"
    _make_wal_db(db, rows=3000)
    writer = sqlite3.connect(db, isolation_level=None)
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.execute("INSERT INTO alerts (x) VALUES ('live')")  # opens the -wal/-shm
    settings = get_settings()
    monkeypatch.setattr(settings, "database_url", f"sqlite+aiosqlite:///{db}")
    monkeypatch.setattr(settings, "grafana_dir", tmp_path / "grafana")
    port = _free_port()

    result = await grafana.start(port)
    try:
        assert "error" not in result, result
        assert result["db_mount"] == "hardlink"
        password = Path(result["password_file"]).read_text().strip()
        sql = "select count(*) from alerts a, alerts b where a.id + b.id > 3"  # ~1 s of reading
        body = {
            "queries": [
                {
                    "refId": "A",
                    "datasource": {"uid": "honeypot-db", "type": "frser-sqlite-datasource"},
                    "queryText": sql,
                    "rawQueryText": sql,
                    "queryType": "table",
                    "timeColumns": [],
                }
            ],
            "from": "now-1h",
            "to": "now",
        }
        stop = False
        done = 0

        async def hammer(http: httpx.AsyncClient) -> None:
            nonlocal done
            while not stop:
                await http.post(
                    f"http://127.0.0.1:{port}/api/ds/query", json=body, auth=("admin", password)
                )
                done += 1

        busy = []
        async with httpx.AsyncClient(timeout=60, trust_env=False) as http:
            workers = [asyncio.create_task(hammer(http)) for _ in range(4)]
            started = time.time()
            while time.time() - started < 8:
                writer.executemany("INSERT INTO alerts (x) VALUES (?)", [("w",)] * 50)
                await asyncio.sleep(0.3)
                busy.append(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0])
            stop = True
            await asyncio.gather(*workers)
        assert done >= 8, "the readers must actually have been busy"
        assert busy and not any(busy), f"a checkpoint was blocked by Grafana's readers: {busy}"
        assert (db.parent / (db.name + "-wal")).stat().st_size == 0
    finally:
        writer.close()
        await grafana.stop()
