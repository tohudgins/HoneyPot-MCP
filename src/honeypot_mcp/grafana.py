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
generated admin password, a read-only root filesystem, every capability dropped, and the dashboards
are published on 127.0.0.1 only: there is deliberately no bind-address parameter.

**Grafana has no route out** (verified on a real daemon: no default route, DNS fails, connects to
a public address and to the host gateway are refused). Docker cannot publish a port from an
`internal` network, so there are two containers. `honeypot-mcp-grafana` holds the database and the
plugin and is attached to an `internal` network only. `honeypot-mcp-grafana-proxy` is a
byte-forwarder (busybox `nc` from the same image, user `nobody`, read-only root, every capability
dropped, no mounts, no secrets) on its own edge network that publishes 127.0.0.1:<port> and
relays to Grafana over the internal network. What is NOT blocked: the proxy container itself keeps
ordinary outbound access (it must, to publish a port), but it holds nothing and is isolated from
every other container; and Grafana can talk to the proxy over the internal network. A plugin or
a Grafana admin using SSRF/snapshot features therefore cannot reach the internet, the cloud
metadata endpoint or other containers from the container that has the data.

**The plugin is pinned, checksummed and signature-checked, and Grafana never downloads
anything.** The SQLite datasource (`frser-sqlite-datasource`, a community plugin) is fetched by
*this process* from grafana.com at the exact version in `SQLITE_PLUGIN_VERSION`, refused unless
the file's SHA-256 equals `SQLITE_PLUGIN_SHA256`, unpacked with path/symlink/size checks, and
mounted read-only. Grafana then verifies the package's own signature (the release is
community-signed), so `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` is deliberately NOT set: an
altered plugin directory is refused by Grafana instead of waved through. `GF_INSTALL_PLUGINS` is
not used. A new plugin release changes nothing until someone reviews it and edits those two
constants.

**The working directory is dedicated.** `GRAFANA_DIR` must be empty or already carry this
module's marker file; a directory with anything else in it, the project root (or any directory
containing it), `config/` and anything inside `config/` are refused, and `stop()` removes only
the exact names this module creates (`db`, `config`, `plugins`, `admin_password`, the marker) and
only when the marker is present.

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

**Permissions, and never uid 0.** The database file is 0600 (`secure_io`), and a hardlink shares
the original's mode, so it cannot be loosened for Grafana's default uid 472 without loosening the
original. The container instead runs as the file's *owner* uid (group 0, which is what Grafana's
data directory is writable by). On Linux that makes the 0600 file readable; Docker Desktop for
macOS presents bind mounts to whichever uid asks, so the same setting is harmless there. A
database owned by root is never hardlinked (that would need a root container): it takes the
snapshot route, the copy is created by this process and, when the server itself is root, handed
to uid 472. The container user is never 0; `_container_spec` refuses it.

**Nothing persists.** Grafana's own state lives on anonymous volumes removed with the container,
so a stopped container leaves no dashboards edited in the UI and no sessions behind, and `stop()`
removes the two containers, the two networks and the private directory (including the unpacked
plugin). Network actions, all inside `start()`: the image pull (first run only) and the plugin
download by this process.

**Write-ahead-log growth (measured, not a proven guarantee).** A live hardlinked database is
read through a read-only mount by an auto-refreshing dashboard, which could in principle keep a
reader open across the server's checkpoints and let the log grow. Measured on a real daemon
(tests/integration/test_grafana_real.py): with four concurrent ~1 s queries from Grafana running
throughout, every `wal_checkpoint(TRUNCATE)` issued by the writing connection completed with
`busy=0` and the log was reset each time, and Grafana saw every row written. So no mitigation is
built in; if a very long dashboard query on a huge database ever holds a reader open, the log
grows until it ends. A snapshot is a frozen file and has no log.

Every failure a user can cause or fix (no Docker, offline, port busy, not SQLite, no such file)
comes back as `{"error": ..., "hint": ...}`, never a traceback.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import hashlib
import json
import logging
import os
import secrets
import shutil
import socket
import sqlite3
import stat
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path, PurePosixPath
from typing import IO, Any

import httpx
import yaml

from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import _PROJECT_ROOT, get_settings
from honeypot_mcp.secure_io import ensure_private_dir, write_private_file

log = logging.getLogger(__name__)

GRAFANA_IMAGE = "grafana/grafana:11.3.0"
CONTAINER_NAME = "honeypot-mcp-grafana"
PROXY_NAME = "honeypot-mcp-grafana-proxy"
# Grafana (and the database) live on the internal network, which has no route out; the proxy
# publishes the loopback port from the edge network and reaches Grafana over the internal one.
NETWORK_INTERNAL = "honeypot-mcp-grafana-internal"
NETWORK_EDGE = "honeypot-mcp-grafana-edge"
# The label is what identifies a container or network as ours. The name alone is not enough:
# someone else's may already be called that, and it must never be stopped or removed by this module.
LABEL_KEY = "honeypot-mcp"
LABEL_VALUE = "grafana"
LABEL_DB = "honeypot-mcp-grafana-db"
LABEL_DB_MOUNT = "honeypot-mcp-grafana-db-mount"
LABEL_ROLE = "honeypot-mcp-grafana-role"
ROLE_GRAFANA = "grafana"
ROLE_PROXY = "proxy"

SQLITE_PLUGIN = "frser-sqlite-datasource"
# The one release this module will run, and the SHA-256 of the file grafana.com serves for it
# (the catalogue's own `packages.any.sha256`, re-verified by hand). Changing the version without
# the hash fails closed; so does a changed file at the same URL.
SQLITE_PLUGIN_VERSION = "4.0.6"
SQLITE_PLUGIN_SHA256 = "e5ce2354dd26ba9bea56b37f9ed4050cc917a46b858a0a191e1cafda382bf18a"
SQLITE_PLUGIN_URL = (
    f"https://grafana.com/api/plugins/{SQLITE_PLUGIN}/versions/{SQLITE_PLUGIN_VERSION}/download"
)
_PLUGIN_MAX_DOWNLOAD = 192 * 1024 * 1024
_PLUGIN_MAX_UNPACKED = 512 * 1024 * 1024
DATASOURCE_UID = "honeypot-db"
ADMIN_USER = "admin"

DB_FILENAME = "honeypot_mcp.db"
_CONTAINER_DATA_DIR = "/mcp-data"
_CONTAINER_DB_PATH = f"{_CONTAINER_DATA_DIR}/{DB_FILENAME}"
_CONTAINER_PLUGINS_DIR = "/mcp-plugins"
_HOME_DASHBOARD = "/etc/grafana/dashboards/01-overview.json"

# Names this module creates under `grafana_dir`, and the only things `stop()` ever removes there
# (and only when `_MARKER` is present: see `_claim_base`).
_VIEW_DIR = "db"
_CONFIG_DIR = "config"
_PLUGINS_DIR = "plugins"
_PASSWORD_FILE = "admin_password"
_MARKER = ".honeypot-mcp-grafana"
_OWNED_NAMES = (_VIEW_DIR, _CONFIG_DIR, _PLUGINS_DIR, _PASSWORD_FILE)

# Grafana's own uid in the image. The container never runs as 0.
_SAFE_UID = 472
_PROXY_UID = 65534  # nobody

_SQLITE_MAGIC = b"SQLite format 3\x00"
HEALTH_TIMEOUT_SECONDS = 90.0
DATASOURCE_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 10
_MEM_LIMIT = "1g"
_PIDS_LIMIT = 512
_PROXY_MEM_LIMIT = "64m"
_PROXY_PIDS_LIMIT = 256

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


# ── the datasource plugin ───────────────────────────────────────────────────────────────────


def _fetch_plugin_zip(fh: IO[bytes]) -> None:
    """Download the pinned release into `fh`, bounded. Integrity is checked by the caller."""
    timeout = httpx.Timeout(30.0, read=60.0)
    with (
        httpx.Client(timeout=timeout, follow_redirects=True) as http,
        http.stream("GET", SQLITE_PLUGIN_URL) as resp,
    ):
        resp.raise_for_status()
        size = 0
        for chunk in resp.iter_bytes(1 << 20):
            size += len(chunk)
            if size > _PLUGIN_MAX_DOWNLOAD:
                raise GrafanaError(
                    f"The plugin download exceeded {_PLUGIN_MAX_DOWNLOAD // (1024 * 1024)} MB; "
                    "refusing it."
                )
            fh.write(chunk)


def _sha256_of(fh: IO[bytes]) -> str:
    digest = hashlib.sha256()
    fh.seek(0)
    while chunk := fh.read(1 << 20):
        digest.update(chunk)
    return digest.hexdigest()


def _extract_plugin(fh: IO[bytes], dest: Path) -> None:
    """Unpack the verified zip into `dest`, treating it as hostile anyway: every entry must sit
    under `<plugin>/`, no `..`, no absolute or backslash paths, no symlinks, bounded size.

    Every file is unpacked, other platforms' binaries included: the package carries a signed
    MANIFEST over all of them, and Grafana refuses a plugin whose files do not match it
    ("modified signature"), which is also what makes the signature check a real second check."""
    prefix = f"{SQLITE_PLUGIN}/"
    try:
        zf = zipfile.ZipFile(fh)
    except zipfile.BadZipFile:
        raise GrafanaError("The downloaded plugin is not a valid zip file.") from None
    total = 0
    with zf:
        for info in zf.infolist():
            name = info.filename
            rel = PurePosixPath(name[len(prefix) :])
            if (
                not name.startswith(prefix)
                or "\\" in name
                or "\x00" in name
                or rel.is_absolute()
                or ".." in rel.parts
            ):
                raise GrafanaError(f"The plugin package has an unexpected entry: {name!r}.")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise GrafanaError(f"The plugin package contains a symlink: {name!r}.")
            target = dest.joinpath(*rel.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, 0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(target.parent, 0o755)
            with zf.open(info) as src, target.open("xb") as out:
                while chunk := src.read(1 << 20):
                    total += len(chunk)
                    if total > _PLUGIN_MAX_UNPACKED:
                        raise GrafanaError("The plugin package unpacks to an implausible size.")
                    out.write(chunk)
            os.chmod(target, 0o755 if rel.name.startswith("gpx_") else 0o644)
    if not (dest / "plugin.json").is_file() or not any(dest.glob("gpx_*_linux_*")):
        raise GrafanaError("The plugin package has no plugin.json or no Linux backend binary.")


def _install_plugin(plugins_dir: Path) -> None:
    """Download the pinned plugin, verify its SHA-256, unpack it into `plugins_dir`.

    Blocking; run it in a thread. Grafana itself never downloads anything.
    """
    plugins_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(plugins_dir, 0o755)
    # An unnamed temporary file inside the private working directory.
    with tempfile.TemporaryFile(dir=plugins_dir.parent) as fh:
        try:
            _fetch_plugin_zip(fh)
        except (httpx.HTTPError, OSError) as e:
            raise GrafanaError(
                f"Could not download the SQLite datasource plugin {SQLITE_PLUGIN} "
                f"{SQLITE_PLUGIN_VERSION} ({type(e).__name__}: {str(e)[:160]}).",
                "Grafana is not given a network, so this server downloads the plugin itself. "
                "Check this machine's internet access and call grafana_start again.",
            ) from None
        got = _sha256_of(fh)
        if got != SQLITE_PLUGIN_SHA256:
            raise GrafanaError(
                f"The downloaded plugin does not match the pinned checksum (got {got[:16]}…, "
                f"expected {SQLITE_PLUGIN_SHA256[:16]}…); it was discarded.",
                "Do not work around this: the file at the download URL changed. Review the new "
                "release and update SQLITE_PLUGIN_VERSION and SQLITE_PLUGIN_SHA256 together.",
            )
        fh.seek(0)
        _extract_plugin(fh, plugins_dir / SQLITE_PLUGIN)


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


def build_view(
    src: DbSource, view_dir: Path, *, max_copy_mb: int, allow_link: bool = True
) -> DbView:
    """Fill `view_dir` with the database (and only it); see the module docstring.

    Raises `GrafanaError` when the file can be neither linked nor copied.
    """
    target = view_dir / DB_FILENAME
    # A log with frames in it but no shared-memory file cannot be read in place by a read-only
    # process, and ignoring the log would drop recent alerts silently. Snapshot instead.
    unreadable_in_place = src.wal_mode and src.wal_bytes > 0 and not src.shm_exists
    link_error: str | None = None
    if not allow_link:
        link_error = "the database file is owned by root and Grafana never runs as root"
    elif unreadable_in_place:
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
    """True when the image had to be pulled (a network action, first run only)."""
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
    *,
    password: str,
    view_dir: Path,
    config_dir: Path,
    plugins_dir: Path,
    db_uid: int | None,
    db: Path,
) -> dict[str, Any]:
    """Every argument of `containers.create` for Grafana itself, in one place so a test can pin
    them. It publishes no port and sits on the internal network only: see `_proxy_spec`."""
    import docker.types

    if db_uid == 0:
        raise GrafanaError("Refusing to run Grafana as uid 0.")
    env = {
        "GF_SECURITY_ADMIN_USER": ADMIN_USER,
        "GF_SECURITY_ADMIN_PASSWORD": password,
        # No anonymous access. The SQLite plugin is installed by this process and verified by
        # Grafana's own signature check, so no unsigned-plugin allow-list is needed.
        "GF_AUTH_ANONYMOUS_ENABLED": "false",
        "GF_AUTH_DISABLE_LOGIN_FORM": "false",
        "GF_PATHS_PLUGINS": _CONTAINER_PLUGINS_DIR,
        "GF_PLUGINS_PLUGIN_ADMIN_ENABLED": "false",
        "GF_PLUGINS_PREINSTALL_DISABLED": "true",
        "GF_SNAPSHOTS_EXTERNAL_ENABLED": "false",
        "GF_USERS_DEFAULT_THEME": "dark",
        "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH": _HOME_DASHBOARD,
        "GF_LOG_MODE": "console",
        # An analysis container has no business phoning home (and cannot: it has no route out).
        "GF_ANALYTICS_REPORTING_ENABLED": "false",
        "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
        "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
        "GF_NEWS_NEWS_FEED_ENABLED": "false",
        "GF_SECURITY_DISABLE_GRAVATAR": "true",
    }
    return {
        "image": GRAFANA_IMAGE,
        "name": CONTAINER_NAME,
        "environment": env,
        # An `internal` network has no gateway: this container cannot reach the internet, the
        # host, the cloud metadata endpoint or any container outside the network.
        "network": NETWORK_INTERNAL,
        "volumes": {
            str(view_dir): {"bind": _CONTAINER_DATA_DIR, "mode": "ro"},
            str(plugins_dir): {"bind": _CONTAINER_PLUGINS_DIR, "mode": "ro"},
            str(config_dir / "provisioning"): {"bind": "/etc/grafana/provisioning", "mode": "ro"},
            str(config_dir / "dashboards"): {"bind": "/etc/grafana/dashboards", "mode": "ro"},
        },
        "labels": {
            LABEL_KEY: LABEL_VALUE,
            LABEL_ROLE: ROLE_GRAFANA,
            LABEL_DB: str(db),
        },
        "read_only": True,
        # Grafana's own state goes on anonymous volumes: writable under a read-only root
        # filesystem, not charged to the container's memory limit, and deleted with the
        # container (`remove(v=True)`).
        "mounts": [
            docker.types.Mount(target="/var/lib/grafana", source=None, type="volume"),  # type: ignore[arg-type]
            docker.types.Mount(target="/tmp", source=None, type="volume"),  # type: ignore[arg-type]
        ],
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": _MEM_LIMIT,
        "pids_limit": _PIDS_LIMIT,
        # The owner of the (possibly 0600) file, group 0; never root. See the module docstring.
        "user": f"{db_uid if db_uid else _SAFE_UID}:0",
    }


def _proxy_spec(*, port: int) -> dict[str, Any]:
    """The loopback-port forwarder. It holds no data and no secret: no mounts, no environment,
    nobody, read-only root, no capabilities. It exists because Docker cannot publish a port from an
    internal network, so the one container that publishes must not be the one with the database."""
    return {
        "image": GRAFANA_IMAGE,  # already present; busybox is in it
        "name": PROXY_NAME,
        "entrypoint": [
            "busybox",
            "nc",
            "-ll",
            "-p",
            "3000",
            "-e",
            "sh",
            "-c",
            f"exec nc {CONTAINER_NAME} 3000",
        ],
        # Loopback only, by construction: there is no parameter that could widen this.
        "ports": {"3000/tcp": ("127.0.0.1", port)},
        "network": NETWORK_EDGE,
        "labels": {LABEL_KEY: LABEL_VALUE, LABEL_ROLE: ROLE_PROXY},
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": _PROXY_MEM_LIMIT,
        "pids_limit": _PROXY_PIDS_LIMIT,
        "user": f"{_PROXY_UID}:{_PROXY_UID}",
    }


def _our_networks(client: Any) -> list[Any]:
    return list(client.networks.list(filters={"label": f"{LABEL_KEY}={LABEL_VALUE}"}))


def _remove_networks(client: Any) -> None:
    """Remove the networks this module created (by label), after their containers are gone."""
    import docker.errors

    for net in _our_networks(client):
        try:
            net.remove()
        except docker.errors.NotFound:
            pass
        except docker.errors.APIError as e:
            log.warning("could not remove Docker network %s: %s", net.name, e)


def _create_networks(client: Any) -> tuple[Any, Any]:
    """(internal, edge). A network of the same name that is not ours is never touched."""
    import docker.errors

    for name in (NETWORK_INTERNAL, NETWORK_EDGE):
        for net in client.networks.list(names=[name]):
            if (net.attrs.get("Labels") or {}).get(LABEL_KEY) != LABEL_VALUE:
                raise GrafanaError(
                    f"A Docker network named '{name}' already exists and was not created by this "
                    "server, so it will not be touched.",
                    f"Remove or rename it (`docker network rm {name}`) and try again.",
                )
    labels = {LABEL_KEY: LABEL_VALUE}
    try:
        internal = client.networks.create(
            NETWORK_INTERNAL, driver="bridge", internal=True, labels=labels
        )
        edge = client.networks.create(NETWORK_EDGE, driver="bridge", labels=labels)
    except docker.errors.APIError as e:
        raise GrafanaError(f"Docker could not create Grafana's networks: {str(e)[:300]}") from None
    return internal, edge


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
    """Remove a file or directory this module created. Returns whether anything was there."""
    if path.is_symlink() or path.is_file():
        path.unlink()
        return True
    if not path.exists():
        return False
    shutil.rmtree(path)
    return True


def _is_contained(outer: Path, inner: Path) -> bool:
    return inner == outer or outer in inner.parents


def _base_refusal(base: Path) -> str | None:
    """Why a (resolved) directory can never be the working directory, whatever it holds."""
    root = _PROJECT_ROOT.resolve()
    if _is_contained(base, root):
        return "is, or contains, the project root"
    if _is_contained(root / "config", base):
        return "is, or is inside, the project's config/ directory"
    return None


def _is_ours(base: Path) -> bool:
    marker = base / _MARKER
    return marker.is_file() and not marker.is_symlink()


def _validate_base(raw: Path) -> Path:
    """`raw` (`GRAFANA_DIR`) resolved, or `GrafanaError` if it cannot be the working directory.

    Every start and stop deletes things from it, so it must be dedicated: absent, empty, or
    already carrying `_MARKER`. Anything else (the project root, `config/`, a directory with the
    operator's files in it) is refused. Changes nothing.
    """
    base = raw.resolve()
    reason = _base_refusal(base)
    if reason:
        raise GrafanaError(
            f"GRAFANA_DIR ({raw}) {reason}, and Grafana's working files are deleted from it "
            "on every start and stop.",
            "Point GRAFANA_DIR at a dedicated directory that holds nothing else "
            "(the default is a 'grafana' directory under the project root).",
        )
    if base.exists() and not base.is_dir():
        raise GrafanaError(f"GRAFANA_DIR ({raw}) exists and is not a directory.")
    if base.is_dir() and not _is_ours(base):
        leftovers = sorted(os.listdir(base))
        if leftovers:
            shown = ", ".join(leftovers[:5]) + (", ..." if len(leftovers) > 5 else "")
            raise GrafanaError(
                f"GRAFANA_DIR ({raw}) is not empty and was not created by grafana_start "
                f"(it holds: {shown}), so nothing in it will be touched or removed.",
                "Point GRAFANA_DIR at an empty or new directory that is used for nothing else.",
            )
    return base


def _claim_base(raw: Path) -> Path:
    """Validate `raw`, make it private and mark it as this module's. Returns it resolved."""
    base = _validate_base(raw)
    ensure_private_dir(base)
    os.chmod(base, 0o700)
    write_private_file(
        base / _MARKER,
        "Working directory of honeypot-mcp grafana_start. Its db/, config/, plugins/ and "
        "admin_password are deleted by grafana_start and grafana_stop; keep nothing else here.\n",
    )
    return base


def _remove_owned(base: Path) -> bool:
    """Remove exactly the names this module creates under a directory it has claimed."""
    removed = False
    for name in _OWNED_NAMES:
        removed = _remove_tree(base / name) or removed
    return removed


def _cleanup_files(base: Path) -> bool:
    """Remove what `_prepare` created. A directory without the marker is never touched."""
    base = base.resolve()
    if _base_refusal(base) or not _is_ours(base):
        return False
    removed = _remove_owned(base)
    (base / _MARKER).unlink(missing_ok=True)
    with contextlib.suppress(OSError):
        base.rmdir()  # only when nothing else lives there
    return removed


def _log_tail(container: Any, lines: int = 20) -> str:
    try:
        return container.logs(tail=lines).decode("utf-8", "replace")[-1500:]
    except Exception:
        return ""


@dataclass
class Prepared:
    view: DbView
    view_dir: Path
    config_dir: Path
    plugins_dir: Path
    password_file: Path
    run_uid: int | None


def _run_uid(view: DbView, src: DbSource, me: int | None) -> int | None:
    """The uid Grafana runs as, never 0 (None: use the image's own 472).

    A live hardlink is the original inode, so only its owner (or root) can read a 0600 file: the
    container runs as the owner, and `allow_link` already refused a root-owned file. A snapshot
    was created by this process, so it belongs to `me`, or, when `me` is root, is handed to 472.
    """
    if view.live:
        return src.uid or None
    if me is None:
        return None
    return me or _SAFE_UID


def _prepare(src: DbSource, base: Path, password: str, max_copy_mb: int) -> Prepared:
    """Create the private working directory. Blocking: run it in a thread."""
    base = _claim_base(base)
    _remove_owned(base)
    me = _host_uid()
    view_dir = base / _VIEW_DIR
    view_dir.mkdir(mode=0o700)
    view = build_view(src, view_dir, max_copy_mb=max_copy_mb, allow_link=me is None or src.uid != 0)
    run_uid = _run_uid(view, src, me)
    # The directory is private to its owner. The one case it cannot be is a container user that is
    # not this process's user (a database owned by someone else, or a snapshot made by root): it
    # must traverse the directory. The files inside keep their own permissions either way.
    if run_uid is not None and run_uid != me:
        os.chmod(view_dir, 0o755)
        if not view.live:
            for name in view.files:
                os.chown(view_dir / name, run_uid, 0)
    config_dir = base / _CONFIG_DIR
    materialise_assets(config_dir, immutable=view.immutable)
    password_file = base / _PASSWORD_FILE
    write_private_file(password_file, password + "\n")
    return Prepared(
        view=view,
        view_dir=view_dir,
        config_dir=config_dir,
        plugins_dir=base / _PLUGINS_DIR,
        password_file=password_file,
        run_uid=run_uid,
    )


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
    # The database comes first: refusing a non-SQLite URL needs no Docker at all. So does an
    # unusable GRAFANA_DIR: nothing is removed or pulled for a start that cannot work.
    src = await asyncio.to_thread(inspect_database, settings.database_url)
    base = await asyncio.to_thread(_validate_base, settings.grafana_dir)
    client = await asyncio.to_thread(_docker_client)

    previous = await asyncio.to_thread(_ours, client)
    # A restart is allowed to reuse its own port: it is freed when the old container goes.
    if port not in {_published_port(c) for c in previous} and not _port_free(port):
        raise GrafanaError(
            f"Port {port} is already in use on this machine.",
            "Pass a different, free port, e.g. grafana_start(port=3301).",
        )
    for name in (CONTAINER_NAME, PROXY_NAME):
        try:
            squatter = await asyncio.to_thread(client.containers.get, name)
        except Exception:
            squatter = None
        if squatter is not None and all(squatter.id != c.id for c in previous):
            raise GrafanaError(
                f"A container named '{name}' already exists and was not created by this "
                "server, so it will not be touched.",
                f"Remove or rename it (`docker rm -f {name}`) and try again.",
            )

    pulled = await asyncio.to_thread(_ensure_image, client)
    for old in previous:
        await asyncio.to_thread(_remove_container, old)
    await asyncio.to_thread(_remove_networks, client)

    password = secrets.token_urlsafe(24)
    try:
        prep = await asyncio.to_thread(_prepare, src, base, password, settings.grafana_max_copy_mb)
        await asyncio.to_thread(_install_plugin, prep.plugins_dir)
    except OSError as e:
        await asyncio.to_thread(_cleanup_files, base)
        raise GrafanaError(f"Could not prepare Grafana's working directory {base}: {e}") from None
    except GrafanaError:
        await asyncio.to_thread(_cleanup_files, base)
        raise
    view = prep.view

    grafana_spec = _container_spec(
        password=password,
        view_dir=prep.view_dir,
        config_dir=prep.config_dir,
        plugins_dir=prep.plugins_dir,
        db_uid=prep.run_uid,
        db=src.path,
    )
    grafana_spec["labels"][LABEL_DB_MOUNT] = view.mount
    proxy_spec = _proxy_spec(port=port)

    created: list[Any] = []
    try:
        internal, _edge = await asyncio.to_thread(_create_networks, client)
        try:
            # Grafana first: the proxy forwards to it by name over the internal network.
            grafana = await asyncio.to_thread(lambda: client.containers.create(**grafana_spec))
            created.append(grafana)
            await asyncio.to_thread(grafana.start)
            proxy = await asyncio.to_thread(lambda: client.containers.create(**proxy_spec))
            created.append(proxy)
            await asyncio.to_thread(internal.connect, proxy)
            await asyncio.to_thread(proxy.start)
        except Exception as e:
            raise _map_create_error(e, port) from None

        def alive() -> bool:
            for c in created:
                c.reload()
            return all(c.status == "running" for c in created)

        probe = await _probe(port, password, alive)
        if not probe["healthy"]:
            tail = await asyncio.to_thread(_log_tail, grafana)
            what = (
                "The Grafana container exited during start-up."
                if probe["container_exited"]
                else f"Grafana did not become healthy within {int(HEALTH_TIMEOUT_SECONDS)} s."
            )
            raise GrafanaError(
                what + (f" Last log lines:\n{tail}" if tail else ""),
                "The containers have been removed. Retry, or pick another port if something else "
                "answered on this one.",
            )
    except BaseException:
        for c in created:
            await asyncio.to_thread(_remove_container, c)
        await asyncio.to_thread(_remove_networks, client)
        await asyncio.to_thread(_cleanup_files, base)
        raise

    notes = list(view.notes)
    if pulled:
        notes.append(f"Pulled {GRAFANA_IMAGE} (first run).")
    notes.append(
        f"The SQLite datasource plugin was downloaded by this server (version "
        f"{SQLITE_PLUGIN_VERSION}, SHA-256 verified) and mounted read-only."
    )
    notes.append(
        "Grafana, which holds the database, runs on an internal Docker network with no route "
        "out: it cannot reach the internet, this host or other containers. Not blocked: the "
        f"`{PROXY_NAME}` forwarder that publishes the loopback port keeps ordinary outbound "
        "access; it holds no data and no secrets."
    )
    result: dict[str, Any] = {
        "running": True,
        "url": f"http://127.0.0.1:{port}/",
        "port": port,
        "username": ADMIN_USER,
        "password_file": str(prep.password_file),
        "db_mount": view.mount,
        "database": str(src.path),
        "datasource_ok": probe["datasource_ok"],
        "container": CONTAINER_NAME,
        "proxy_container": PROXY_NAME,
        "image": GRAFANA_IMAGE,
        "plugin": f"{SQLITE_PLUGIN} {SQLITE_PLUGIN_VERSION}",
        "grafana_has_outbound_network": False,
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
                f"The SQLite datasource plugin ({SQLITE_PLUGIN}) was unpacked but Grafana did not "
                "register it, so every panel will error. Run grafana_stop then grafana_start; "
                "if it persists, `docker logs` on the Grafana container names the plugin error."
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
    result["read_password_with"] = f"cat {prep.password_file}"
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
    networks = len(await asyncio.to_thread(_our_networks, client))
    await asyncio.to_thread(_remove_networks, client)
    removed_dir = await asyncio.to_thread(_cleanup_files, get_settings().grafana_dir)
    return {
        "stopped": bool(found),
        "was_running": was_running,
        "removed_containers": len(found),
        "removed_networks": networks,
        "removed_link_dir": removed_dir,
        "note": (
            "Grafana stopped and its private files were removed."
            if found or removed_dir or networks
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
    main = next((c for c in found if (c.labels or {}).get(LABEL_ROLE) != ROLE_PROXY), found[0])
    proxy = next((c for c in found if (c.labels or {}).get(LABEL_ROLE) == ROLE_PROXY), None)
    labels = main.labels or {}
    state = (main.attrs or {}).get("State", {})
    running = main.status == "running" and (proxy is None or proxy.status == "running")
    port = _published_port(proxy) if proxy is not None else _published_port(main)
    started_at, uptime = _uptime(state.get("StartedAt")) if running else (None, None)
    out: dict[str, Any] = {
        "running": running,
        "container": main.name,
        "container_status": main.status,
        "database": labels.get(LABEL_DB),
        "db_mount": labels.get(LABEL_DB_MOUNT),
        "started_at": started_at,
        "uptime_seconds": round(uptime, 1) if uptime is not None else None,
    }
    if proxy is not None:
        out["proxy_container"] = proxy.name
        out["proxy_status"] = proxy.status
    if port is not None:
        out["url"] = f"http://127.0.0.1:{port}/"
        out.update(_dashboards_result(port))
    expected = 2 if proxy is not None else 1
    if len(found) > expected:
        out["note"] = f"{len(found)} containers carry the Grafana label; grafana_stop removes all."
    elif not running:
        out["note"] = "The containers exist but are not all running; grafana_stop removes them."
    return out
