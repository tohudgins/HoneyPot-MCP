"""Put the packaged Grafana dashboards on this server's own database, in one call.

`grafana_start` (tools/grafana.py) runs a pinned Grafana container, provisioned from the
dashboards shipped inside this package, against the SQLite file the server is configured to use.
It works the same on a live server and in ANALYSIS_MODE against a restored backup. This module is
the container and filesystem lifecycle; the MCP tools are thin wrappers that add the audit trail.

Design decisions, because each one is a way this goes wrong quietly:

**The assets come from the installed package.** `grafana_assets/` (provisioning + dashboards) is
read through `importlib.resources` and copied into a private working directory, so the same code
runs from a checkout and from a wheel. The compose files mount the same directory.

**Grafana can see the database files and nothing else.** The database holds secret tables
(honeytoken values, API-key digests, webhook secrets), so the container is given a directory that
this module creates and that contains only `honeypot_mcp.db` (and its `-wal`/`-shm` when it is in
use), mounted read-only. Mounting the directory the database happens to live in would hand over
whatever else is there (`.env`, `tls/`, reports). The container also has no anonymous access, a
generated admin password, a read-only root filesystem, every capability dropped, and a published
port bound to 127.0.0.1 only: there is deliberately no bind-address parameter.

**How the file gets into that directory** (`db_mount` in the result):

* `hardlink`, the default and the only one that is live. A hardlink is the same inode, so new
  alerts appear as the server writes them, nothing is duplicated (the real database this was built
  against is 12 GB), and no permission has to be changed on the original. It needs the working
  directory (`GRAFANA_DIR`) to be on the database's filesystem; the default, under the project
  root, is on the same one for the default database location.
* `reflink`, when a hardlink is impossible (another filesystem, `fs.protected_hardlinks`): a
  copy-on-write clone (APFS `clonefile`, Linux `FICLONE` on btrfs/XFS), instant and free, but a
  snapshot as of the start. Only used when the write-ahead log holds nothing, since a clone cannot
  carry frames the log has not checkpointed.
* `copy`, the last resort: a consistent copy made with SQLite's own backup API (it folds in the
  write-ahead log), refused above `GRAFANA_MAX_COPY_MB` or when the disk cannot hold it.

**Both snapshot kinds are rewritten to the rollback journal mode** so that a read-only mount can
open them. That is the read-only/WAL problem: a WAL database must create or write a shared-memory
`-shm` file to be read, and a read-only mount forbids it ("unable to open database file").
A hardlinked live database gets its existing `-wal` and `-shm` hardlinked beside it, which SQLite
can read without writing (verified against a running writer); a hardlinked WAL database with no
`-shm` (a backup nobody has open) is opened with SQLite's `immutable=1`, which is correct only
because there is no write-ahead log to ignore. A WAL database that has un-checkpointed frames but
no `-shm` cannot be read in place either way, so it takes the snapshot route.

**Permissions.** The database file is 0600 (`secure_io`), and a hardlink shares the original's
mode, so it cannot be loosened for Grafana's default uid 472 without loosening the original. The
container instead runs as the file's *owner* uid (group 0, which is what Grafana's data directory
is writable by). On Linux that makes the 0600 file readable; Docker Desktop for macOS presents
bind mounts to whichever uid asks, so the same setting is harmless there. Verified with the real
daemon on both a 0600 file and a WAL database.

**Nothing persists.** Grafana's own state lives on anonymous volumes removed with the container, so a stopped container leaves no
dashboards edited in the UI, no sessions and no downloaded plugin behind; the SQLite plugin
(`frser-sqlite-datasource`, an unsigned community plugin, allowed by name exactly as the compose
files do) is downloaded from grafana.com on every start. That and the image pull are the only
network actions, and both happen only inside `start()`.

Every failure a user can cause or fix (no Docker, offline, port busy, not SQLite, no such file)
comes back as `{"error": ..., "hint": ...}`, never a traceback.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import json
import logging
import os
import secrets
import shutil
import socket
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

import httpx
import yaml

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import get_settings
from honeypot_mcp.secure_io import ensure_private_dir, write_private_file

log = logging.getLogger(__name__)

GRAFANA_IMAGE = "grafana/grafana:11.3.0"
CONTAINER_NAME = "honeypot-mcp-grafana"
# The label is what identifies a container as ours. The name alone is not enough: someone else's
# container may already be called that, and it must never be stopped or removed by this module.
LABEL_KEY = "honeypot-mcp"
LABEL_VALUE = "grafana"
LABEL_DB = "honeypot-mcp-grafana-db"
LABEL_DB_MOUNT = "honeypot-mcp-grafana-db-mount"

SQLITE_PLUGIN = "frser-sqlite-datasource"
DATASOURCE_UID = "honeypot-db"
ADMIN_USER = "admin"

DB_FILENAME = "honeypot_mcp.db"
_CONTAINER_DATA_DIR = "/mcp-data"
_CONTAINER_DB_PATH = f"{_CONTAINER_DATA_DIR}/{DB_FILENAME}"
_HOME_DASHBOARD = "/etc/grafana/dashboards/01-overview.json"

# Names this module creates under `grafana_dir`, and the only things `stop()` ever removes there.
_VIEW_DIR = "db"
_CONFIG_DIR = "config"
_PASSWORD_FILE = "admin_password"

_SQLITE_MAGIC = b"SQLite format 3\x00"
HEALTH_TIMEOUT_SECONDS = 90.0
DATASOURCE_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 10
_MEM_LIMIT = "1g"
_PIDS_LIMIT = 512

_lock: LoopBound[asyncio.Lock] = LoopBound(asyncio.Lock)


class GrafanaError(Exception):
    """A failure with a message fit to show the user, and what to do about it."""

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": self.message}
        if self.hint:
            out["hint"] = self.hint
        return out


# ── packaged assets ─────────────────────────────────────────────────────────────────────────


def assets_root() -> Traversable:
    """The `grafana_assets` directory inside the installed package."""
    return resources.files("honeypot_mcp") / "grafana_assets"


def _dashboard_files() -> list[Traversable]:
    return sorted(
        (p for p in (assets_root() / "dashboards").iterdir() if p.name.endswith(".json")),
        key=lambda p: p.name,
    )


@dataclass(frozen=True)
class Dashboard:
    file: str
    title: str
    uid: str
    needs_prometheus: bool


def _uses_prometheus(node: Any) -> bool:
    if isinstance(node, dict):
        ds = node.get("datasource")
        if isinstance(ds, dict) and (
            ds.get("uid") == "prometheus" or str(ds.get("type", "")).lower() == "prometheus"
        ):
            return True
        if isinstance(ds, str) and ds.lower() == "prometheus":
            return True
        return any(_uses_prometheus(v) for v in node.values())
    if isinstance(node, list):
        return any(_uses_prometheus(v) for v in node)
    return False


def list_dashboards() -> list[Dashboard]:
    """The dashboards this package ships, read from the installed assets."""
    out: list[Dashboard] = []
    for f in _dashboard_files():
        doc = json.loads(f.read_text(encoding="utf-8"))
        out.append(
            Dashboard(
                file=f.name,
                title=str(doc.get("title") or f.name),
                uid=str(doc.get("uid") or ""),
                needs_prometheus=_uses_prometheus(doc),
            )
        )
    return out


def _copy_asset_tree(src: Traversable, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o755)
    for child in src.iterdir():
        target = dest / child.name
        if child.is_dir():
            _copy_asset_tree(child, target)
        else:
            target.write_bytes(child.read_bytes())
            os.chmod(target, 0o644)


def _datasources_yaml(*, immutable: bool) -> str:
    """The packaged datasource provisioning, adjusted for this run.

    The SQLite datasource becomes the default (the packaged file makes Prometheus the default,
    which in this mode points at a host that does not exist), and gets SQLite's `immutable`
    option when the view is a WAL database nobody has open (see the module docstring).
    """
    doc = yaml.safe_load(
        (assets_root() / "provisioning" / "datasources" / "datasources.yml").read_text("utf-8")
    )
    for ds in doc.get("datasources", []):
        if ds.get("uid") == DATASOURCE_UID:
            ds["isDefault"] = True
            ds.setdefault("jsonData", {})["path"] = _CONTAINER_DB_PATH
            if immutable:
                ds["jsonData"]["pathPrefix"] = "file:"
                ds["jsonData"]["pathOptions"] = "mode=ro&immutable=1"
        elif ds.get("uid") == "prometheus":
            ds["isDefault"] = False
    header = "# Generated by honeypot-mcp `grafana_start` from the packaged provisioning; not edited by hand.\n"
    return header + yaml.safe_dump(doc, sort_keys=False)


def materialise_assets(dest: Path, *, immutable: bool) -> None:
    """Write provisioning + dashboards from the package into `dest` (a fresh directory)."""
    root = assets_root()
    dest.mkdir(parents=True, exist_ok=True)
    os.chmod(dest, 0o755)
    _copy_asset_tree(root / "dashboards", dest / "dashboards")
    prov = dest / "provisioning"
    _copy_asset_tree(root / "provisioning", prov)
    ds_file = prov / "datasources" / "datasources.yml"
    ds_file.write_text(_datasources_yaml(immutable=immutable), encoding="utf-8")
    os.chmod(ds_file, 0o644)


# ── the database ────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DbSource:
    path: Path
    uid: int
    wal_mode: bool
    wal_bytes: int
    shm_exists: bool
    size_bytes: int


def database_path(database_url: str) -> Path:
    """The SQLite file `database_url` names, or `GrafanaError` for anything else."""
    scheme = database_url.split(":", 1)[0].lower()
    if not scheme.startswith("sqlite"):
        raise GrafanaError(
            f"Grafana can only be pointed at a SQLite database, and DATABASE_URL uses "
            f"'{scheme.split('+')[0] or 'an unrecognised scheme'}'.",
            "Run Grafana against a SQLite copy or backup of the data (database_backup), or "
            "point it at your PostgreSQL server with its own datasource.",
        )
    _, sep, rest = database_url.partition(":///")
    rest = rest.split("?", 1)[0]
    if not sep or not rest or ":memory:" in rest:
        raise GrafanaError(
            "DATABASE_URL is an in-memory SQLite database, which exists only inside this process "
            "and cannot be shared with a container.",
            "Set DATABASE_URL to a SQLite file.",
        )
    return Path(rest)


def inspect_database(database_url: str) -> DbSource:
    """Validate the configured database and describe what has to be exposed."""
    path = database_path(database_url)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise GrafanaError(
            f"The SQLite database does not exist: {path}",
            "Check DATABASE_URL, or start the server once so it creates the database.",
        ) from None
    if not resolved.is_file():
        raise GrafanaError(f"The database path is not a file: {path}")
    try:
        with resolved.open("rb") as fh:
            header = fh.read(100)
    except OSError as e:
        raise GrafanaError(
            f"Cannot read the database file ({e.strerror or e}): {path}",
            "Run the server as a user that can read it.",
        ) from None
    if not header.startswith(_SQLITE_MAGIC):
        raise GrafanaError(f"{path} is not a SQLite database (bad file header).")
    st = resolved.stat()
    wal = resolved.with_name(resolved.name + "-wal")
    shm = resolved.with_name(resolved.name + "-shm")
    return DbSource(
        path=resolved,
        uid=st.st_uid,
        wal_mode=len(header) >= 20 and header[18] == 2 and header[19] == 2,
        wal_bytes=wal.stat().st_size if wal.exists() else 0,
        shm_exists=shm.exists(),
        size_bytes=st.st_size,
    )


@dataclass
class DbView:
    mount: str  # hardlink | reflink | copy
    immutable: bool
    files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def live(self) -> bool:
        return self.mount == "hardlink"


# Hardlinking can fail for reasons of the filesystem or the platform, not of the request.
_LINK_REFUSED = {
    errno.EXDEV,
    errno.EPERM,
    errno.EACCES,
    errno.EMLINK,
    errno.ENOTSUP,
    errno.ENOSYS,
    errno.EOPNOTSUPP,
}


def _reflink(src: Path, dst: Path) -> bool:
    """Copy-on-write clone `src` to `dst` (which must not exist). False when it cannot be done."""
    try:
        if os.uname().sysname == "Darwin":
            libc = ctypes.CDLL("libSystem.B.dylib", use_errno=True)
            return libc.clonefile(os.fsencode(src), os.fsencode(dst), 0) == 0
        import fcntl

        with src.open("rb") as s, dst.open("xb") as d:
            try:
                fcntl.ioctl(d.fileno(), 0x40049409, s.fileno())  # FICLONE
                return True
            except OSError:
                pass
        dst.unlink()  # created by the open above and left empty
    except (OSError, AttributeError):
        pass
    return False


def _backup_copy(src: Path, dst: Path) -> None:
    """A transactionally consistent copy, write-ahead log included."""
    source = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(dst)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()


def _to_rollback_journal(db: Path) -> None:
    """Switch a snapshot out of WAL mode so a read-only mount can open it."""
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA journal_mode=DELETE").fetchone()
    finally:
        conn.close()
    for suffix in ("-wal", "-shm"):
        with contextlib.suppress(OSError):
            db.with_name(db.name + suffix).unlink()


def _is_wal(db: Path) -> bool:
    with db.open("rb") as fh:
        header = fh.read(20)
    return len(header) >= 20 and header[18] == 2 and header[19] == 2


def build_view(src: DbSource, view_dir: Path, *, max_copy_mb: int) -> DbView:
    """Fill `view_dir` with the database (and only it); see the module docstring.

    Raises `GrafanaError` when the file can be neither linked nor copied.
    """
    target = view_dir / DB_FILENAME
    # A log with frames in it but no shared-memory file cannot be read in place by a read-only
    # process, and ignoring the log would drop recent alerts silently. Snapshot instead.
    unreadable_in_place = src.wal_mode and src.wal_bytes > 0 and not src.shm_exists
    link_error: str | None = None
    if unreadable_in_place:
        link_error = "its write-ahead log has un-checkpointed frames and no -shm file"
    else:
        sidecars: list[Path] = []
        if src.wal_mode and src.shm_exists:
            sidecars = [
                p
                for p in (
                    src.path.with_name(src.path.name + "-wal"),
                    src.path.with_name(src.path.name + "-shm"),
                )
                if p.exists()
            ]
        linked: list[Path] = []
        try:
            os.link(src.path, target)
            linked.append(target)
            for side in sidecars:
                dest = view_dir / (DB_FILENAME + side.name[len(src.path.name) :])
                os.link(side, dest)
                linked.append(dest)
        except OSError as e:
            for p in linked:
                with contextlib.suppress(OSError):
                    p.unlink()
            if e.errno not in _LINK_REFUSED:
                raise GrafanaError(
                    f"Could not link the database into Grafana's private directory: {e}"
                ) from None
            link_error = (
                "it is on a different filesystem than GRAFANA_DIR"
                if e.errno == errno.EXDEV
                else (e.strerror or "the filesystem refused a hardlink")
            )
        else:
            immutable = src.wal_mode and not sidecars
            return DbView(
                mount="hardlink",
                immutable=immutable,
                files=[p.name for p in linked],
                notes=[
                    "The database is a write-ahead-log file that nothing has open, so Grafana "
                    "reads it as immutable: it will not see writes made after this start."
                    if immutable
                    else "Live view: Grafana reads the same file the server writes, so new "
                    "alerts appear as they are recorded."
                ],
            )

    # ── snapshot ─────────────────────────────────────────────────────────────────────────────
    note = f"Snapshot taken at start, not live (a hardlink was not possible: {link_error})."
    if src.wal_bytes == 0 and _reflink(src.path, target):
        view = DbView("reflink", False, [DB_FILENAME], [note + " It is a copy-on-write clone."])
    else:
        limit = max_copy_mb * 1024 * 1024
        need = src.size_bytes + src.wal_bytes
        if limit <= 0 or need > limit:
            raise GrafanaError(
                f"The database cannot be hardlinked ({link_error}) or cloned, and copying "
                f"{need // (1024 * 1024):,} MB exceeds GRAFANA_MAX_COPY_MB={max_copy_mb}.",
                "Point GRAFANA_DIR at a directory on the database's own filesystem so it can be "
                "hardlinked, or raise GRAFANA_MAX_COPY_MB.",
            )
        free = shutil.disk_usage(view_dir).free
        if free < need * 1.1:
            raise GrafanaError(
                f"Not enough free disk to snapshot the database ({need // (1024 * 1024):,} MB "
                f"needed, {free // (1024 * 1024):,} MB free).",
                "Point GRAFANA_DIR at a larger volume.",
            )
        try:
            _backup_copy(src.path, target)
        except sqlite3.Error as e:
            with contextlib.suppress(OSError):
                target.unlink()
            raise GrafanaError(f"Could not copy the database: {e}") from None
        view = DbView("copy", False, [DB_FILENAME], [note])
    os.chmod(target, 0o600)
    if _is_wal(target):
        try:
            _to_rollback_journal(target)
        except sqlite3.Error as e:
            raise GrafanaError(
                f"Could not prepare the database snapshot for Grafana: {e}"
            ) from None
    return view


# ── docker ──────────────────────────────────────────────────────────────────────────────────


def _docker_client() -> Any:
    """A connected Docker client, or `GrafanaError` saying how to get one."""
    import docker

    settings = get_settings()
    try:
        client = (
            docker.DockerClient(base_url=settings.docker_socket)  # type: ignore[attr-defined]
            if settings.docker_socket
            else docker.from_env()  # type: ignore[attr-defined]
        )
        client.ping()
    except Exception as e:
        raise GrafanaError(
            f"Docker is not available ({type(e).__name__}: {str(e)[:200]}).",
            "Start Docker (Docker Desktop, or the docker service) and make sure this user can "
            "reach its socket; DOCKER_HOST or DOCKER_SOCKET can point at a non-default one.",
        ) from None
    return client


def _ours(client: Any) -> list[Any]:
    return list(client.containers.list(all=True, filters={"label": f"{LABEL_KEY}={LABEL_VALUE}"}))


def _remove_container(container: Any) -> None:
    import docker.errors

    with contextlib.suppress(docker.errors.NotFound, docker.errors.APIError):
        container.stop(timeout=_STOP_TIMEOUT_SECONDS)
    with contextlib.suppress(docker.errors.NotFound):
        container.remove(force=True, v=True)


def _ensure_image(client: Any) -> bool:
    """True when the image had to be pulled (the one network action besides the plugin)."""
    import docker.errors

    repo, _, tag = GRAFANA_IMAGE.partition(":")
    try:
        client.images.get(GRAFANA_IMAGE)
        return False
    except docker.errors.ImageNotFound:
        pass
    try:
        client.images.pull(repo, tag=tag)
    except Exception as e:
        raise GrafanaError(
            f"Could not pull {GRAFANA_IMAGE} ({type(e).__name__}: {str(e)[:200]}). "
            "This usually means there is no internet access or the registry is unreachable.",
            f"Pull it once while online (`docker pull {GRAFANA_IMAGE}`) and call grafana_start "
            "again; it is not pulled again afterwards.",
        ) from None
    return True


def _port_free(port: int) -> bool:
    """False when something already accepts connections on 127.0.0.1:`port`.

    A connect, not a bind: a bind without SO_REUSEADDR fails on a port that merely has
    connections in TIME_WAIT (which the previous Grafana's health probe leaves behind), and with
    SO_REUSEADDR it succeeds beside a wildcard listener on some platforms. Docker's own
    "port is already allocated" error is the backstop (`_map_create_error`).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) != 0


def _published_port(container: Any) -> int | None:
    try:
        bindings = container.attrs["HostConfig"]["PortBindings"]["3000/tcp"]
        return int(bindings[0]["HostPort"])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def _host_uid() -> int | None:
    geteuid = getattr(os, "geteuid", None)
    return geteuid() if geteuid else None


def _container_spec(
    *, port: int, password: str, view_dir: Path, config_dir: Path, db_uid: int | None, db: Path
) -> dict[str, Any]:
    """Every argument of `containers.create`, in one place so a test can pin them."""
    import docker.types

    env = {
        "GF_SECURITY_ADMIN_USER": ADMIN_USER,
        "GF_SECURITY_ADMIN_PASSWORD": password,
        # The same switches as the compose files: no anonymous access, the SQLite plugin loaded by
        # name. Nothing else about the instance is open.
        "GF_AUTH_ANONYMOUS_ENABLED": "false",
        "GF_AUTH_DISABLE_LOGIN_FORM": "false",
        "GF_INSTALL_PLUGINS": SQLITE_PLUGIN,
        "GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS": SQLITE_PLUGIN,
        "GF_USERS_DEFAULT_THEME": "dark",
        "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH": _HOME_DASHBOARD,
        "GF_LOG_MODE": "console",
        # An analysis container has no business phoning home.
        "GF_ANALYTICS_REPORTING_ENABLED": "false",
        "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
        "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
        "GF_NEWS_NEWS_FEED_ENABLED": "false",
        "GF_SECURITY_DISABLE_GRAVATAR": "true",
    }
    spec: dict[str, Any] = {
        "image": GRAFANA_IMAGE,
        "name": CONTAINER_NAME,
        "environment": env,
        # Loopback only, by construction: there is no parameter that could widen this.
        "ports": {"3000/tcp": ("127.0.0.1", port)},
        "volumes": {
            str(view_dir): {"bind": _CONTAINER_DATA_DIR, "mode": "ro"},
            str(config_dir / "provisioning"): {"bind": "/etc/grafana/provisioning", "mode": "ro"},
            str(config_dir / "dashboards"): {"bind": "/etc/grafana/dashboards", "mode": "ro"},
        },
        "labels": {
            LABEL_KEY: LABEL_VALUE,
            LABEL_DB: str(db),
        },
        "read_only": True,
        # Grafana's own state (and the plugin it downloads, a few hundred MB unpacked) goes on
        # anonymous volumes: writable under a read-only root filesystem, executable (a tmpfs
        # is mounted noexec and would stop the native plugin binary), not charged to the
        # container's memory limit, and deleted with the container (`remove(v=True)`).
        "mounts": [
            docker.types.Mount(target="/var/lib/grafana", source=None, type="volume"),  # type: ignore[arg-type]
            docker.types.Mount(target="/tmp", source=None, type="volume"),  # type: ignore[arg-type]
        ],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": _MEM_LIMIT,
        "pids_limit": _PIDS_LIMIT,
    }
    if db_uid is not None:
        # See the module docstring: the owner of the (possibly 0600) file, group 0.
        spec["user"] = f"{db_uid}:0"
    return spec


def _map_create_error(exc: Exception, port: int) -> GrafanaError:
    text = str(exc)
    low = text.lower()
    if "port is already allocated" in low or "address already in use" in low or "bind for" in low:
        return GrafanaError(
            f"Port {port} is already in use on this machine.",
            "Pass a different, free port, e.g. grafana_start(port=3301).",
        )
    if "mounts denied" in low or "not shared from the host" in low or "not shared" in low:
        return GrafanaError(
            f"Docker is not allowed to mount the working directory ({text[:160]}).",
            "Share it in Docker Desktop (Settings > Resources > File sharing) or point "
            "GRAFANA_DIR at a shared path such as one under your home directory.",
        )
    return GrafanaError(f"Docker could not start Grafana: {text[:300]}")


# ── readiness ───────────────────────────────────────────────────────────────────────────────

_DATASOURCE_SQL = (
    "select name from sqlite_master where type = 'table' "
    "and name in ('alerts', 'alert_rollups') order by name"
)


async def _probe(
    port: int,
    password: str,
    alive: Any,
    *,
    health_timeout: float = HEALTH_TIMEOUT_SECONDS,
    datasource_timeout: float = DATASOURCE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Wait (bounded) for `/api/health`, then run a trivial query through the SQLite datasource.

    `alive` is a sync callable reporting whether the container is still running, so a crash
    ends the wait at once instead of after the full timeout.
    """
    base = f"http://127.0.0.1:{port}"
    result: dict[str, Any] = {
        "healthy": False,
        "datasource_ok": False,
        "tables": [],
        "datasource_error": None,
        "container_exited": False,
    }
    # trust_env=False: a proxy in the environment must not intercept a loopback request.
    async with httpx.AsyncClient(timeout=5.0, trust_env=False) as http:
        deadline = time.monotonic() + health_timeout
        while time.monotonic() < deadline:
            try:
                resp = await http.get(f"{base}/api/health")
                if resp.status_code == 200 and resp.json().get("database") == "ok":
                    result["healthy"] = True
                    break
            except (httpx.HTTPError, ValueError):
                pass
            if not await asyncio.to_thread(alive):
                result["container_exited"] = True
                return result
            await asyncio.sleep(1.0)
        if not result["healthy"]:
            return result

        body = {
            "queries": [
                {
                    "refId": "A",
                    "datasource": {"uid": DATASOURCE_UID, "type": SQLITE_PLUGIN},
                    "queryText": _DATASOURCE_SQL,
                    "rawQueryText": _DATASOURCE_SQL,
                    "queryType": "table",
                    "timeColumns": [],
                }
            ],
            "from": "now-1h",
            "to": "now",
        }
        deadline = time.monotonic() + datasource_timeout
        while True:
            error: str | None = None
            try:
                resp = await http.post(
                    f"{base}/api/ds/query", json=body, auth=(ADMIN_USER, password)
                )
                payload = resp.json()
                if resp.status_code == 401:
                    error = "Grafana rejected the generated admin credentials."
                elif payload.get("messageId") == "plugin.notRegistered":
                    error = "plugin_not_installed"
                else:
                    cell = payload.get("results", {}).get("A", {})
                    if cell.get("error"):
                        error = str(cell["error"])
                    else:
                        frames = cell.get("frames") or []
                        values = frames[0]["data"]["values"] if frames else [[]]
                        result["tables"] = list(values[0]) if values else []
                        result["datasource_ok"] = True
                        return result
            except (httpx.HTTPError, ValueError, KeyError, IndexError) as e:
                error = f"{type(e).__name__}: {e}"[:200]
            result["datasource_error"] = error
            if time.monotonic() >= deadline:
                return result
            await asyncio.sleep(2.0)


# ── lifecycle ───────────────────────────────────────────────────────────────────────────────


def _remove_tree(path: Path) -> bool:
    """Remove a directory this module created. Returns whether anything was there."""
    if path.is_symlink():
        path.unlink()
        return True
    if not path.exists():
        return False
    shutil.rmtree(path)
    return True


def _cleanup_files(base: Path) -> bool:
    removed = False
    for name in (_VIEW_DIR, _CONFIG_DIR):
        removed = _remove_tree(base / name) or removed
    pw = base / _PASSWORD_FILE
    if pw.is_file() or pw.is_symlink():
        pw.unlink()
        removed = True
    with contextlib.suppress(OSError):
        base.rmdir()  # only when nothing else lives there
    return removed


def _log_tail(container: Any, lines: int = 20) -> str:
    try:
        return container.logs(tail=lines).decode("utf-8", "replace")[-1500:]
    except Exception:
        return ""


def _prepare(
    src: DbSource, base: Path, password: str, max_copy_mb: int
) -> tuple[DbView, Path, Path, Path]:
    """Create the private working directory. Blocking: run it in a thread."""
    ensure_private_dir(base)
    os.chmod(base, 0o700)
    _cleanup_files(base)
    ensure_private_dir(base)
    me = _host_uid()
    view_dir = base / _VIEW_DIR
    # The directory is private to its owner. The one case it cannot be is a database owned by a
    # different user than the server (then the container runs as that user, and must traverse it);
    # the files inside keep their own permissions either way.
    view_dir.mkdir(mode=0o700)
    if me is not None and src.uid != me:
        os.chmod(view_dir, 0o755)
    view = build_view(src, view_dir, max_copy_mb=max_copy_mb)
    config_dir = base / _CONFIG_DIR
    materialise_assets(config_dir, immutable=view.immutable)
    password_file = base / _PASSWORD_FILE
    write_private_file(password_file, password + "\n")
    return view, view_dir, config_dir, password_file


def _dashboards_result(port: int) -> dict[str, Any]:
    dashboards = list_dashboards()
    base = f"http://127.0.0.1:{port}"
    return {
        "dashboards": [d.title for d in dashboards],
        "dashboard_urls": {d.title: f"{base}/d/{d.uid}" for d in dashboards if d.uid},
        "needs_prometheus": [d.title for d in dashboards if d.needs_prometheus],
    }


async def start(port: int = 3000) -> dict[str, Any]:
    """Run Grafana on the configured database. Returns a result dict; never raises."""
    async with _lock.get():
        try:
            return await _start(port)
        except GrafanaError as e:
            return e.as_dict()
        except Exception as e:
            log.exception("grafana_start failed unexpectedly")
            return {
                "error": f"Unexpected failure starting Grafana ({type(e).__name__}): {str(e)[:300]}"
            }


async def _start(port: int) -> dict[str, Any]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise GrafanaError(f"port must be an integer from 1 to 65535 (got {port!r}).")
    settings = get_settings()
    # The database comes first: refusing a non-SQLite URL needs no Docker at all.
    src = await asyncio.to_thread(inspect_database, settings.database_url)
    client = await asyncio.to_thread(_docker_client)

    previous = await asyncio.to_thread(_ours, client)
    # A restart is allowed to reuse its own port: it is freed when the old container goes.
    if port not in {_published_port(c) for c in previous} and not _port_free(port):
        raise GrafanaError(
            f"Port {port} is already in use on this machine.",
            "Pass a different, free port, e.g. grafana_start(port=3301).",
        )
    try:
        squatter = await asyncio.to_thread(client.containers.get, CONTAINER_NAME)
    except Exception:
        squatter = None
    if squatter is not None and all(squatter.id != c.id for c in previous):
        raise GrafanaError(
            f"A container named '{CONTAINER_NAME}' already exists and was not created by this "
            "server, so it will not be touched.",
            f"Remove or rename it (`docker rm -f {CONTAINER_NAME}`) and try again.",
        )

    pulled = await asyncio.to_thread(_ensure_image, client)
    for old in previous:
        await asyncio.to_thread(_remove_container, old)

    password = secrets.token_urlsafe(24)
    base = settings.grafana_dir
    try:
        view, view_dir, config_dir, password_file = await asyncio.to_thread(
            _prepare, src, base, password, settings.grafana_max_copy_mb
        )
    except OSError as e:
        await asyncio.to_thread(_cleanup_files, base)
        raise GrafanaError(f"Could not prepare Grafana's working directory {base}: {e}") from None
    except GrafanaError:
        await asyncio.to_thread(_cleanup_files, base)
        raise

    spec = _container_spec(
        port=port,
        password=password,
        view_dir=view_dir,
        config_dir=config_dir,
        db_uid=_host_uid() if not view.live else src.uid,
        db=src.path,
    )
    spec["labels"][LABEL_DB_MOUNT] = view.mount

    container = None
    try:
        try:
            container = await asyncio.to_thread(lambda: client.containers.create(**spec))
            await asyncio.to_thread(container.start)
        except Exception as e:
            raise _map_create_error(e, port) from None

        def alive() -> bool:
            container.reload()
            return container.status == "running"

        probe = await _probe(port, password, alive)
        if not probe["healthy"]:
            tail = await asyncio.to_thread(_log_tail, container)
            what = (
                "The Grafana container exited during start-up."
                if probe["container_exited"]
                else f"Grafana did not become healthy within {int(HEALTH_TIMEOUT_SECONDS)} s."
            )
            raise GrafanaError(
                what + (f" Last log lines:\n{tail}" if tail else ""),
                "The container has been removed. Retry, or pick another port if something else "
                "answered on this one.",
            )
    except BaseException:
        if container is not None:
            await asyncio.to_thread(_remove_container, container)
        await asyncio.to_thread(_cleanup_files, base)
        raise

    notes = list(view.notes)
    if pulled:
        notes.append(f"Pulled {GRAFANA_IMAGE} (first run).")
    result: dict[str, Any] = {
        "running": True,
        "url": f"http://127.0.0.1:{port}/",
        "port": port,
        "username": ADMIN_USER,
        "password_file": str(password_file),
        "db_mount": view.mount,
        "database": str(src.path),
        "datasource_ok": probe["datasource_ok"],
        "container": CONTAINER_NAME,
        "image": GRAFANA_IMAGE,
        **_dashboards_result(port),
    }
    if probe["datasource_ok"]:
        result["datasource_tables"] = probe["tables"]
        if "alerts" not in probe["tables"]:
            notes.append("The database has no `alerts` table: the dashboards will be empty.")
    else:
        err = probe["datasource_error"]
        if err == "plugin_not_installed":
            notes.append(
                f"The SQLite datasource plugin ({SQLITE_PLUGIN}) is not loaded, so every panel "
                "will error. It is downloaded from grafana.com when Grafana starts; check this "
                "machine's internet access and run grafana_stop then grafana_start."
            )
        else:
            notes.append(f"The SQLite datasource did not answer a test query: {err}")
        result["datasource_error"] = err
    result["notes"] = notes
    if result["needs_prometheus"]:
        result["needs_prometheus_note"] = (
            "These dashboards read Prometheus, which this mode does not run: their panels show "
            "no data."
        )
    result["read_password_with"] = f"cat {password_file}"
    return result


async def stop() -> dict[str, Any]:
    """Remove the container this module created and its private directory. Idempotent."""
    async with _lock.get():
        try:
            return await _stop()
        except GrafanaError as e:
            return e.as_dict()
        except Exception as e:
            log.exception("grafana_stop failed unexpectedly")
            return {
                "error": f"Unexpected failure stopping Grafana ({type(e).__name__}): {str(e)[:300]}"
            }


async def _stop() -> dict[str, Any]:
    client = await asyncio.to_thread(_docker_client)
    found = await asyncio.to_thread(_ours, client)  # label-scoped, never by name
    was_running = False
    for c in found:
        was_running = was_running or c.status == "running"
        await asyncio.to_thread(_remove_container, c)
    removed_dir = await asyncio.to_thread(_cleanup_files, get_settings().grafana_dir)
    return {
        "stopped": bool(found),
        "was_running": was_running,
        "removed_containers": len(found),
        "removed_link_dir": removed_dir,
        "note": (
            "Grafana stopped and its private files were removed."
            if found or removed_dir
            else "Nothing to stop: no Grafana started by this server was running."
        ),
    }


def _uptime(started_at: str | None) -> tuple[str | None, float | None]:
    if not started_at:
        return None, None
    head, _, tail = started_at.rstrip("Z").partition(".")
    try:
        when = datetime.fromisoformat(f"{head}.{tail[:6]}" if tail else head).replace(tzinfo=UTC)
    except ValueError:
        return started_at, None
    return when.isoformat(), max(0.0, (datetime.now(UTC) - when).total_seconds())


async def status() -> dict[str, Any]:
    """Whether the Grafana this server started is running, and what it serves. No secrets."""
    try:
        client = await asyncio.to_thread(_docker_client)
        found = await asyncio.to_thread(_ours, client)
    except GrafanaError as e:
        return {"running": None, **e.as_dict()}
    except Exception as e:
        return {
            "running": None,
            "error": f"Could not query Docker ({type(e).__name__}): {str(e)[:200]}",
        }
    if not found:
        return {
            "running": False,
            "note": "No Grafana started by this server. Call grafana_start to put the dashboards "
            "on the configured database.",
        }
    c = found[0]
    labels = c.labels or {}
    state = (c.attrs or {}).get("State", {})
    running = c.status == "running"
    port = _published_port(c)
    started_at, uptime = _uptime(state.get("StartedAt")) if running else (None, None)
    out: dict[str, Any] = {
        "running": running,
        "container": c.name,
        "container_status": c.status,
        "database": labels.get(LABEL_DB),
        "db_mount": labels.get(LABEL_DB_MOUNT),
        "started_at": started_at,
        "uptime_seconds": round(uptime, 1) if uptime is not None else None,
    }
    if port is not None:
        out["url"] = f"http://127.0.0.1:{port}/"
        out.update(_dashboards_result(port))
    if len(found) > 1:
        out["note"] = f"{len(found)} containers carry the Grafana label; grafana_stop removes all."
    elif not running:
        out["note"] = "The container exists but is not running; grafana_stop removes it."
    return out
