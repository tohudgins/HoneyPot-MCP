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
        assert container.attrs["HostConfig"]["PortBindings"]["3000/tcp"][0]["HostIp"] == "127.0.0.1"
    finally:
        stopped = await grafana.stop()

    assert stopped["stopped"] is True
    assert not (tmp_path / "grafana").exists()
    client = docker.from_env()
    assert client.containers.list(all=True, filters={"label": "honeypot-mcp=grafana"}) == []
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
