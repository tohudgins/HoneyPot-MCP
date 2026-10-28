"""Replay a capture through Suricata or Zeek, and read the answer back as a digest.

`pcap_extract` writes one attacker's packets to a file and the documentation says it can be
"replayed through Suricata or Zeek". Until this module nothing did that: an analyst ran
`suricata -r` by hand. `pcap_detect` (tools/detect.py) is that step, and `detection_rules_update`
fetches the ruleset it uses. This module is the container lifecycle and the output parsers; the
tools are thin wrappers that add the audit trail.

Design decisions, because each one is a way this goes wrong quietly:

**The capture is hostile input, so the engine is the thing that gets sandboxed.** Suricata and
Zeek parse attacker-chosen bytes with large native parsers, and both have had memory-safety bugs
in protocol dissectors. The container has no network (`network_mode=none`), a read-only root
filesystem, every capability dropped, `no-new-privileges`, a non-root user, memory (swap
disabled), pid and CPU limits, a bounded log driver, and a hard wall-clock limit after which it is
killed. It is labelled `honeypot-mcp=detect` and removed in a `finally`, so a timeout or an
exception cannot leave it behind; a container that outlived a crashed server is reaped on the next
run. Everything an engine could write goes to one output directory that is watched while it runs
(the container is killed past `detection_max_output_mb`) and that is read back with
`O_NOFOLLOW` and a regular-file check, since a compromised engine could plant a symlink there.

**The pcap is copied, never mounted from where it lives.** It is read from the descriptor
`pcap_analysis.open_capture` verified (confined to `reports_dir`/`pcap_dir`, no `..`, no
symlink escape, regular file, size cap), copied into a private 0700 temporary directory, and that
copy's directory is mounted read-only. A copy rather than a hardlink because a hardlink shares the
inode and so its permissions and ownership, and the copy cannot race a path that changes after the
check.

**Only `detection_rules_update` ever has a network.** `pcap_detect` runs offline against a rules
cache. It never fetches rules, and without a cache it still runs (protocol, flow and anomaly
events need none) and says so in `rules_loaded: 0` plus a note, instead of quietly returning "no
alerts", which reads as a clean bill of health. Pulling an engine image is the only other network
action and happens only inside these two tools (`image_pulled: true` says when it did).

**Suricata 8, not 7.** `tcpdump -i any` (what `pcap.py` runs) writes Linux "cooked v2" frames
(link type 276). Suricata 7.0 refuses those ("datalink type 276 not supported") and decodes zero
packets, which is why the pinned image is 8.x. If the engine decodes none of a capture that has
packets the result is an error naming the engine's own message, not an empty digest.

**Results are digests.** No payload, packet or raw log line ever reaches a result: only counts,
names, and short cleaned strings of the kind `pcap_analyze` already quotes (user-agents, URIs,
signature text). The whole parsed event stream (allow-listed fields, capped) goes to a JSON Lines
artifact in `reports_dir` through `write_artifact`; the result carries its path and size.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import shutil
import stat
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from honeypot_mcp import pcap_analysis
from honeypot_mcp._loop_bound import LoopBound
from honeypot_mcp.config import get_settings
from honeypot_mcp.docker_errors import guard_refusal
from honeypot_mcp.pcap_analysis import _clean, _iso, _Tally
from honeypot_mcp.secure_io import ensure_private_dir

log = logging.getLogger(__name__)

ENGINES = ("suricata", "zeek")

# The label identifies a container as ours. Name alone is not enough, and nothing without the
# label is ever touched by this module.
LABEL_KEY = "honeypot-mcp"
LABEL_VALUE = "detect"
LABEL_ENGINE = "honeypot-mcp-engine"

# Resolved by name inside the image, so an operator-supplied image keeps working. Both exist in
# the pinned images; neither is root.
_USERS = {"suricata": "suricata", "zeek": "nobody"}

_IN = "/in"
_OUT = "/out"
_RULES = "/rules"
CAPTURE_NAME = "capture.pcap"
RULES_FILE = "suricata.rules"
CLASSIFICATION_FILE = "classification.config"
CUSTOM_RULES_FILE = "custom.rules"
META_FILE = "ruleset.json"
RULESET_NAME = "Emerging Threats Open"

_MB = 1024 * 1024
_PIDS_LIMIT = 512
_TMPFS_MB = 64
_UPDATE_TMPFS_MB = 1024
_LOG_TAIL_LINES = 2000
_POLL_SECONDS = 0.25
# Files and directories an engine may leave in its output directory. A real run writes a few dozen.
_MAX_OUTPUT_ENTRIES = 5000
_MAX_RULES_BYTES = 512 * _MB

# Row/line caps. The output directory is already bounded in bytes; these bound parse time.
_MAX_ROWS = 1_000_000
_MAX_LINE_BYTES = 1 << 20
_MAX_ARTIFACT_ROWS = 100_000
_MAX_SIG_GROUPS = 2_000
_MAX_DISTINCT = 128
_MAX_TALKERS = 20_000
_MAX_SCAN_RECORDS = 5_000_000
_CLIP = 160

# `suricata -v` prints this once the rules are loaded.
_RULES_LOADED = re.compile(r"(\d+) rules successfully loaded, (\d+) rules failed")
_SURICATA_VERSION = re.compile(r"This is Suricata version (\S+)")
_UPDATE_TOTALS = re.compile(r"total: (\d+); enabled: (\d+)")
_UPDATE_SOURCE = re.compile(r"Fetching (https://\S+?)\.?\s*$", re.M)
# Decoder rules that fire on checksum errors. A capture taken on the host that sent the packet
# carries unfilled checksums (NIC offload), so these say little about the attacker.
_CHECKSUM_SIG = re.compile(r"invalid checksum", re.I)

_lock: LoopBound[asyncio.Lock] = LoopBound(asyncio.Lock)


class DetectError(Exception):
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


_TOOLS = "pcap_detect and detection_rules_update"


def _refused(exc: BaseException, what: str = _TOOLS) -> DetectError | None:
    """A `DetectError` saying the hardened Docker guard refused the request, or None."""
    found = guard_refusal(exc, what)
    return DetectError(found["error"], found["hint"]) if found else None


# ── the capture ─────────────────────────────────────────────────────────────────────────────


@dataclass
class CaptureScan:
    packets: int = 0
    first: float | None = None
    last: float | None = None
    format: str | None = None
    link_types: list[int] = field(default_factory=list)
    truncated: bool = False
    problem: str | None = None


def scan_capture(fh: BinaryIO, size: int, *, max_records: int = _MAX_SCAN_RECORDS) -> CaptureScan:
    """Count packets and find the first/last timestamp by walking record headers only."""
    reader = pcap_analysis.CaptureReader(fh, size)
    scan = CaptureScan()
    for ts, _link, _data, _orig in reader.packets(want_data=False):
        scan.packets += 1
        if ts is not None:
            if scan.first is None or ts < scan.first:
                scan.first = ts
            if scan.last is None or ts > scan.last:
                scan.last = ts
        if scan.packets >= max_records:
            scan.truncated = True
            break
    scan.format = reader.format
    scan.link_types = list(reader.link_types)
    if reader.format is None and reader.note is None:
        scan.problem = reader.problem or "not a pcap or pcapng file"
    return scan


def _window(first: float | None, last: float | None) -> dict[str, Any] | None:
    if first is None or last is None:
        return None
    return {
        "first": _iso(first),
        "last": _iso(last),
        "seconds": round(max(0.0, last - first), 3),
    }


# ── docker ──────────────────────────────────────────────────────────────────────────────────


def _docker_client() -> Any:
    """A connected Docker client, or `DetectError` saying how to get one."""
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
        refused = _refused(e)
        if refused is not None:
            raise refused from None
        raise DetectError(
            f"Docker is not available ({type(e).__name__}: {str(e)[:200]}).",
            "Start Docker (Docker Desktop, or the docker service) and make sure this user can "
            "reach its socket; DOCKER_HOST or DOCKER_SOCKET can point at a non-default one.",
        ) from None
    return client


def _split_image(image: str) -> tuple[str, str | None]:
    if "@" in image:
        return image, None
    head, sep, tag = image.rpartition(":")
    if sep and "/" not in tag:
        return head, tag
    return image, "latest"


def _ensure_image(client: Any, image: str, what: str = _TOOLS) -> bool:
    """True when the image had to be pulled (a network action: only these two tools do it)."""
    import docker.errors

    try:
        client.images.get(image)
        return False
    except docker.errors.ImageNotFound:
        pass
    except Exception as e:
        refused = _refused(e, what)
        if refused is not None:
            raise refused from None
        raise DetectError(
            f"Docker could not look up {image} ({type(e).__name__}: {str(e)[:200]})."
        ) from None
    repo, tag = _split_image(image)
    try:
        client.images.pull(repo, tag=tag)
    except Exception as e:
        refused = _refused(e, what)
        if refused is not None:
            raise refused from None
        raise DetectError(
            f"Could not pull {image} ({type(e).__name__}: {str(e)[:200]}). "
            "This usually means there is no internet access or the registry is unreachable.",
            f"Pull it once while online (`docker pull {image}`) and call the tool again; it is "
            "not pulled again afterwards.",
        ) from None
    return True


def _container_spec(
    *,
    image: str,
    engine: str,
    command: list[str],
    user: str,
    mounts: list[tuple[Path, str, str]],
    mem_mb: int,
    cpus: float,
    tmpfs_mb: int = _TMPFS_MB,
    entrypoint: list[str] | None = None,
    working_dir: str | None = None,
    network: bool = False,
) -> dict[str, Any]:
    """Every argument of `containers.create`, in one place so a test can pin them.

    `network=True` is passed by exactly one caller, the rules download. Everything else runs
    with `network_mode=none`.
    """
    import docker.types

    spec: dict[str, Any] = {
        "image": image,
        "command": command,
        "user": user,
        "volumes": {str(host): {"bind": target, "mode": mode} for host, target, mode in mounts},
        "labels": {LABEL_KEY: LABEL_VALUE, LABEL_ENGINE: engine},
        "network_mode": "bridge" if network else "none",
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": f"{mem_mb}m",
        # Equal to the memory limit: no swap, so a runaway parser is killed, not slowly paged.
        "memswap_limit": f"{mem_mb}m",
        "nano_cpus": int(cpus * 1_000_000_000),
        "pids_limit": _PIDS_LIMIT,
        # Writable scratch that is not the host and cannot run code.
        "tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={tmpfs_mb}m"},
        # A hostile capture can make an engine very chatty; the log driver keeps 1 MB.
        "log_config": docker.types.LogConfig(
            type=docker.types.LogConfig.types.JSON, config={"max-size": "1m", "max-file": "1"}
        ),
    }
    if entrypoint is not None:
        spec["entrypoint"] = entrypoint
    if working_dir is not None:
        spec["working_dir"] = working_dir
    return spec


@dataclass
class RunOutcome:
    exit_code: int | None
    oom: bool
    # "timeout" | "output_limit" | "output_entries" | "output_unreadable" | None
    reason: str | None
    logs: str
    seconds: float


@dataclass
class OutputUsage:
    nbytes: int = 0
    entries: int = 0
    unreadable: int = 0  # directories that could not be listed (so were not measured)


def _output_usage(path: Path, byte_limit: int, entry_limit: int) -> OutputUsage:
    """What lives under `path` (no symlink followed), stopping as soon as any limit is crossed.

    Every entry counts, not only bytes: millions of empty files cost no bytes and exhaust the
    filesystem's inodes. Disk actually allocated counts, not the apparent size, so a sparse file
    cannot hide. A directory that cannot be listed is counted, never skipped: the engine runs as a
    different user and can make a 0700 subdirectory the host cannot read, and a limit that only sees
    what it can read is no limit."""
    use = OutputUsage()
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    use.entries += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        info = None
                    if info is not None:
                        if stat.S_ISDIR(info.st_mode):
                            stack.append(Path(entry.path))
                        else:
                            use.nbytes += max(info.st_size, getattr(info, "st_blocks", 0) * 512)
                    if use.nbytes > byte_limit or use.entries > entry_limit:
                        return use
        except FileNotFoundError:
            continue  # removed while the engine was working
        except OSError:
            use.unreadable += 1
            return use
    return use


def _output_reason(path: Path, byte_limit: int) -> str | None:
    """The `RunOutcome.reason` that output under `path` calls for, or None while it is within bounds."""
    use = _output_usage(path, byte_limit, _MAX_OUTPUT_ENTRIES)
    if use.unreadable:
        return "output_unreadable"
    if use.nbytes > byte_limit:
        return "output_limit"
    if use.entries > _MAX_OUTPUT_ENTRIES:
        return "output_entries"
    return None


def _remove_container(container: Any) -> None:
    """Kill and delete a container (and its anonymous volumes). Never raises."""
    try:
        container.remove(force=True, v=True)
    except Exception as e:
        # NotFound is the common, harmless case (already gone). Anything else is worth a line.
        if type(e).__name__ != "NotFound":
            log.warning("could not remove detection container: %s", e)


def _age_seconds(container: Any) -> float | None:
    created = (getattr(container, "attrs", None) or {}).get("Created")
    if not isinstance(created, str):
        return None
    try:
        # Docker reports nanoseconds; datetime stops at microseconds.
        text = re.sub(r"(\.\d{6})\d+", r"\1", created.replace("Z", "+00:00"))
        return (datetime.now(UTC) - datetime.fromisoformat(text)).total_seconds()
    except ValueError:
        return None


def _reap_stale(client: Any, max_age_seconds: float) -> int:
    """Remove labelled containers older than any run could last (a server killed mid-run)."""
    removed = 0
    try:
        found = list(
            client.containers.list(all=True, filters={"label": f"{LABEL_KEY}={LABEL_VALUE}"})
        )
    except Exception:
        return 0
    for container in found:
        age = _age_seconds(container)
        if age is not None and age > max_age_seconds:
            _remove_container(container)
            removed += 1
    return removed


def _run_container(
    client: Any,
    spec: dict[str, Any],
    *,
    timeout: float,
    out_dir: Path | None = None,
    out_limit: int = 0,
    poll: float | None = None,
) -> RunOutcome:
    """Run one container to completion under a wall-clock limit. Blocking: run in a thread.

    The container is killed when `timeout` passes or when `out_dir` grows past `out_limit`, and
    it is removed in every case, including an exception between create and start.
    """
    started = time.monotonic()
    container = None
    try:
        container = client.containers.create(**spec)
        container.start()
        reason: str | None = None
        while True:
            container.reload()
            if container.status in ("exited", "dead"):
                break
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
                reason = "timeout"
                break
            if out_dir is not None and out_limit:
                reason = _output_reason(out_dir, out_limit)
                if reason is not None:
                    break
            time.sleep(_POLL_SECONDS if poll is None else poll)
        if reason is not None:
            with contextlib.suppress(Exception):
                container.kill()
        with contextlib.suppress(Exception):
            container.reload()
        state = (getattr(container, "attrs", None) or {}).get("State") or {}
        exit_code = state.get("ExitCode")
        try:
            raw = container.logs(stdout=True, stderr=True, tail=_LOG_TAIL_LINES)
            logs = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        except Exception:
            logs = ""
        return RunOutcome(
            exit_code=exit_code if isinstance(exit_code, int) else None,
            oom=bool(state.get("OOMKilled")),
            reason=reason,
            logs=logs,
            seconds=round(time.monotonic() - started, 2),
        )
    finally:
        if container is not None:
            _remove_container(container)


def _map_docker_error(exc: Exception, engine: str) -> DetectError:
    refused = _refused(
        exc, "detection_rules_update" if engine == "suricata-update" else "pcap_detect"
    )
    if refused is not None:
        return refused
    text = str(exc)
    low = text.lower()
    if "mounts denied" in low or "not shared" in low or "is not shared from the host" in low:
        return DetectError(
            f"Docker is not allowed to mount the working directory ({text[:160]}).",
            "Share the system temporary directory in Docker Desktop (Settings > Resources > "
            "File sharing), or set TMPDIR to a shared path such as one under your home directory.",
        )
    if "no such image" in low or "not found" in low and "image" in low:
        return DetectError(f"Docker does not have the {engine} image ({text[:160]}).")
    return DetectError(f"Docker could not run {engine}: {text[:300]}")


def _outcome_error(
    outcome: RunOutcome,
    engine: str,
    settings: Any,
    exit_hint: str = "The capture may be damaged. Check it with pcap_analyze.",
) -> DetectError | None:
    """The error an abnormal run maps to, or None when it exited cleanly."""
    if outcome.reason == "timeout":
        return DetectError(
            f"{engine} did not finish within {settings.detection_timeout_seconds} s and was killed.",
            "Replay a smaller capture (pcap_extract one source) or raise "
            "DETECTION_TIMEOUT_SECONDS.",
        )
    if outcome.reason == "output_limit":
        return DetectError(
            f"{engine} wrote more than {settings.detection_max_output_mb} MB of output and was "
            "killed.",
            "Replay a smaller capture or raise DETECTION_MAX_OUTPUT_MB.",
        )
    if outcome.reason == "output_entries":
        return DetectError(
            f"{engine} created more than {_MAX_OUTPUT_ENTRIES} files and directories in its output "
            "and was killed.",
            "A capture produces a handful of log files; this one was likely crafted to exhaust the "
            "filesystem.",
        )
    if outcome.reason == "output_unreadable":
        return DetectError(
            f"{engine} created a directory in its output that this server cannot read and was "
            "killed.",
            "The output is read back from the host, so anything unreadable cannot be measured "
            "against DETECTION_MAX_OUTPUT_MB.",
        )
    if outcome.oom or outcome.exit_code == 137:
        return DetectError(
            f"{engine} ran out of memory (limit {settings.detection_memory_mb} MB) and was killed.",
            "Raise DETECTION_MEMORY_MB, or give Docker Desktop more memory.",
        )
    if outcome.exit_code not in (0, None):
        return DetectError(
            f"{engine} exited with status {outcome.exit_code}: {_log_problem(outcome.logs)}",
            exit_hint,
        )
    return None


def _log_problem(logs: str) -> str:
    """The last error-looking lines of an engine log, cleaned and short."""
    lines = [ln for ln in logs.splitlines() if re.search(r"\b(error|fatal|critical)\b", ln, re.I)]
    chosen = lines[-3:] if lines else logs.splitlines()[-3:]
    return _clean(" | ".join(chosen), 400) or "no log output"


# ── staging ─────────────────────────────────────────────────────────────────────────────────


@dataclass
class Staging:
    root: Path
    in_dir: Path
    out_dir: Path
    rules_dir: Path | None = None

    def cleanup(self) -> None:
        """Remove the working directory. Blocking: run in a thread."""
        _open_up_directories(self.root)
        shutil.rmtree(self.root, ignore_errors=True)
        if self.root.exists():
            log.warning(
                "could not fully remove the detection working directory %s (an engine created "
                "files this user does not own); remove it as root",
                self.root,
            )


def _open_up_directories(root: Path) -> None:
    """Give this user rwx on every directory under `root`, so `rmtree` can list and empty it. The
    engine runs as another user and may have made a subdirectory 0700; without this the removal
    silently left whatever it held on disk. Works on what this user owns; never follows a link."""
    stack = [root]
    while stack:
        current = stack.pop()
        with contextlib.suppress(OSError, NotImplementedError):
            if current != root:
                os.chmod(current, 0o700, follow_symlinks=False)
        with contextlib.suppress(OSError), os.scandir(current) as it:
            stack.extend(Path(e.path) for e in it if e.is_dir(follow_symlinks=False))


def _open_regular(path: Path, max_bytes: int) -> tuple[BinaryIO, int]:
    """Open `path` without following a symlink; it must be a regular file under `max_bytes`."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise DetectError(f"{path.name} is not a regular file.")
        if info.st_size > max_bytes:
            raise DetectError(f"{path.name} is larger than {max_bytes // _MB} MB.")
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb"), info.st_size


def _copy_bounded(src: BinaryIO, dest: Path, limit: int) -> int:
    """Copy at most `limit` bytes into a new file; DetectError if the source has more."""
    written = 0
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as out:
        while True:
            chunk = src.read(min(1 << 20, limit - written + 1))
            if not chunk:
                break
            written += len(chunk)
            if written > limit:
                raise DetectError(
                    f"The capture is larger than {limit // _MB} MB (DETECTION_MAX_PCAP_MB)."
                )
            out.write(chunk)
    return written


def _stage(fh: BinaryIO, max_bytes: int) -> Staging:
    """Copy the capture into a private working directory. Blocking: run in a thread."""
    root = Path(tempfile.mkdtemp(prefix="hp-detect-")).resolve()  # 0700
    staging = Staging(root=root, in_dir=root / "in", out_dir=root / "out")
    try:
        staging.in_dir.mkdir(mode=0o755)
        staging.out_dir.mkdir()
        # Inside a 0700 parent, so "world writable" means "the container's user", not the host's.
        os.chmod(staging.in_dir, 0o755)
        os.chmod(staging.out_dir, 0o777)
        fh.seek(0)
        _copy_bounded(fh, staging.in_dir / CAPTURE_NAME, max_bytes)
    except BaseException:
        staging.cleanup()
        raise
    return staging


@dataclass
class RulesState:
    """What the offline rules cache holds, as staged for one run."""

    present: bool = False
    custom: bool = False
    meta: dict[str, Any] | None = None


def _read_meta(rules_dir: Path) -> dict[str, Any] | None:
    try:
        fh, _ = _open_regular(rules_dir / META_FILE, 1 << 20)
    except (OSError, DetectError):
        return None
    with fh:
        try:
            data = json.loads(fh.read().decode("utf-8", "replace"))
        except ValueError:
            return None
    return data if isinstance(data, dict) else None


def _stage_rules(staging: Staging, cache: Path) -> RulesState:
    """Combine the cached ruleset and the operator's `custom.rules` into the run's rules."""
    out = staging.root / "rules"
    out.mkdir(mode=0o755)
    os.chmod(out, 0o755)
    staging.rules_dir = out
    state = RulesState(meta=_read_meta(cache))
    combined = out / "all.rules"
    fd = os.open(combined, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as dest:
        for name, is_custom in ((RULES_FILE, False), (CUSTOM_RULES_FILE, True)):
            try:
                src, _ = _open_regular(cache / name, _MAX_RULES_BYTES)
            except FileNotFoundError:
                continue
            except (OSError, DetectError) as e:
                log.warning("ignoring %s in the rules cache: %s", name, e)
                continue
            with src:
                shutil.copyfileobj(src, dest, 1 << 20)
            dest.write(b"\n")
            if is_custom:
                state.custom = True
            else:
                state.present = True
    try:
        src, _ = _open_regular(cache / CLASSIFICATION_FILE, 1 << 20)
    except (OSError, DetectError):
        pass
    else:
        with src:
            _copy_bounded(src, out / CLASSIFICATION_FILE, 1 << 20)
    return state


# ── reading engine output ───────────────────────────────────────────────────────────────────


@dataclass
class ReadStats:
    rows: int = 0
    bytes: int = 0
    skipped: int = 0
    truncated: bool = False


def _iter_json_lines(path: Path, stats: ReadStats, *, max_rows: int = _MAX_ROWS) -> Iterator[Any]:
    """Parsed JSON objects from a log, one per line. Tolerant of damage, bounded in rows.

    Opened with O_NOFOLLOW and checked for a regular file: the directory is writable by the
    engine, which parsed hostile bytes.
    """
    try:
        fh, size = _open_regular(path, 1 << 62)
    except FileNotFoundError:
        return
    except (OSError, DetectError):
        stats.skipped += 1
        return
    stats.bytes = size
    with fh:
        while True:
            raw = fh.readline(_MAX_LINE_BYTES + 1)
            if not raw:
                return
            if len(raw) > _MAX_LINE_BYTES and not raw.endswith(b"\n"):
                # Skip the remainder of an over-long line without holding it.
                while True:
                    rest = fh.readline(_MAX_LINE_BYTES)
                    if not rest or rest.endswith(b"\n"):
                        break
                stats.skipped += 1
                continue
            raw = raw.strip()
            if not raw:
                continue
            if stats.rows >= max_rows:
                stats.truncated = True
                return
            try:
                obj = json.loads(raw)
            except ValueError:
                stats.skipped += 1
                continue
            stats.rows += 1
            yield obj


def _str(value: Any, limit: int = _CLIP) -> str | None:
    """A short, printable string from a log field, or None."""
    if isinstance(value, str) and value:
        return _clean(value, limit)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _get(obj: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _tops(tally: _Tally, n: int) -> list[dict[str, Any]]:
    return tally.top(n)


class _Artifact:
    """The parsed event stream, as capped JSON Lines."""

    def __init__(self, cap: int | None = None) -> None:
        self.cap = _MAX_ARTIFACT_ROWS if cap is None else cap
        self.rows: list[str] = []
        self.dropped = 0

    def add(self, row: dict[str, Any]) -> None:
        if len(self.rows) >= self.cap:
            self.dropped += 1
            return
        self.rows.append(json.dumps(row, separators=(",", ":"), ensure_ascii=True))

    def text(self, header: dict[str, Any]) -> str:
        head = json.dumps({"_meta": header}, separators=(",", ":"), ensure_ascii=True)
        return "\n".join([head, *self.rows]) + "\n"


def _compact(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if v is not None}


# ── Suricata EVE ────────────────────────────────────────────────────────────────────────────


def _norm_ts(value: Any) -> str | None:
    """An EVE timestamp (`...+0000`) as ISO 8601 (`...+00:00`)."""
    if not isinstance(value, str) or not value:
        return None
    return re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", value[:40])


class _SigGroup:
    __slots__ = (
        "count", "sid", "gid", "rev", "msg", "category", "severity",
        "srcs", "dsts", "first", "last", "example", "artifact",
    )  # fmt: skip

    def __init__(self, sid: int, gid: int, rev: int, msg: str, category: str, severity: int):
        self.count = 0
        self.sid, self.gid, self.rev = sid, gid, rev
        self.msg, self.category, self.severity = msg, category, severity
        self.srcs: set[str] = set()
        self.dsts: set[str] = set()
        self.first: str | None = None
        self.last: str | None = None
        self.example: dict[str, Any] | None = None
        self.artifact = bool(_CHECKSUM_SIG.search(msg))


class EveDigest:
    """Reduce Suricata's EVE JSON stream to a digest. Feed it parsed events."""

    def __init__(self, top: int, artifact: _Artifact | None = None) -> None:
        self.top = top
        self.artifact = artifact
        self.events = _Tally()
        self.groups: dict[tuple[int, int], _SigGroup] = {}
        self.group_overflow = 0
        self.alerts = 0
        self.alerts_checksum = 0
        self.by_category = _Tally()
        self.by_severity = _Tally()
        self.talkers: dict[str, list[int]] = {}  # ip -> flows, packets, bytes, alerts
        self.flows = 0
        self.flows_app = _Tally()
        self.flows_proto = _Tally()
        self.dest_ports = _Tally()
        self.anomalies = _Tally()
        self.first_ts: str | None = None
        self.last_ts: str | None = None
        self.stats: dict[str, Any] | None = None
        self.sip_methods = _Tally()
        self.sip_codes = _Tally()
        self.sip_uris = _Tally()
        self.dns_names = _Tally()
        self.dns_types = _Tally()
        self.dns_rcodes = _Tally()
        self.http_hosts = _Tally()
        self.http_urls = _Tally()
        self.http_agents = _Tally()
        self.http_methods = _Tally()
        self.tls_sni = _Tally()
        self.tls_versions = _Tally()
        self.ssh_clients = _Tally()
        self.ssh_servers = _Tally()
        self.skipped = 0

    def _talker(self, ip: str | None) -> list[int] | None:
        if not ip:
            return None
        row = self.talkers.get(ip)
        if row is None:
            if len(self.talkers) >= _MAX_TALKERS:
                return None
            row = self.talkers[ip] = [0, 0, 0, 0]
        return row

    def feed(self, ev: Any) -> None:
        if not isinstance(ev, dict):
            self.skipped += 1
            return
        etype = _str(ev.get("event_type"), 32) or "unknown"
        self.events.add(etype)
        if etype == "stats":
            stats = ev.get("stats")
            if isinstance(stats, dict):
                self.stats = stats
            return
        ts = _norm_ts(ev.get("timestamp"))
        if ts:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        handler = getattr(self, f"_on_{etype}", None)
        if handler is not None:
            handler(ev, ts)
        if self.artifact is not None:
            self.artifact.add(self._row(etype, ev, ts))

    # -- per type ------------------------------------------------------------------------

    def _originator(self, ev: dict[str, Any]) -> tuple[str | None, str | None]:
        """The flow's initiator and responder, not the direction of this one packet."""
        flow = ev.get("flow")
        src = _get(flow, "src_ip") or ev.get("src_ip")
        dst = _get(flow, "dest_ip") or ev.get("dest_ip")
        return (_str(src, 64), _str(dst, 64))

    def _on_alert(self, ev: dict[str, Any], ts: str | None) -> None:
        alert = ev.get("alert")
        if not isinstance(alert, dict):
            return
        sid, gid = _int(alert.get("signature_id")), _int(alert.get("gid"))
        msg = _str(alert.get("signature"), 200) or f"sid {sid}"
        category = _str(alert.get("category"), 80) or "Uncategorised"
        severity = _int(alert.get("severity")) or 3
        self.alerts += 1
        artifact = bool(_CHECKSUM_SIG.search(msg))
        self.by_category.add(category)
        self.by_severity.add(severity)
        group = self.groups.get((gid, sid))
        if group is None:
            if len(self.groups) >= _MAX_SIG_GROUPS:
                self.group_overflow += 1
            else:
                group = self.groups[(gid, sid)] = _SigGroup(
                    sid, gid, _int(alert.get("rev")), msg, category, severity
                )
        src, dst = self._originator(ev)
        if group is not None:
            group.count += 1
            if src and len(group.srcs) < _MAX_DISTINCT:
                group.srcs.add(src)
            if dst and len(group.dsts) < _MAX_DISTINCT:
                group.dsts.add(dst)
            if ts:
                if group.first is None or ts < group.first:
                    group.first = ts
                if group.last is None or ts > group.last:
                    group.last = ts
            if group.example is None:
                group.example = _compact(
                    {
                        "src": _str(ev.get("src_ip"), 64),
                        "src_port": ev.get("src_port")
                        if isinstance(ev.get("src_port"), int)
                        else None,
                        "dst": _str(ev.get("dest_ip"), 64),
                        "dst_port": ev.get("dest_port")
                        if isinstance(ev.get("dest_port"), int)
                        else None,
                        "proto": _str(ev.get("proto"), 16),
                        "app_proto": _str(ev.get("app_proto"), 24),
                        "direction": _str(ev.get("direction"), 16),
                    }
                )
        if artifact:
            self.alerts_checksum += 1
        else:
            row = self._talker(src)
            if row is not None:
                row[3] += 1

    def _on_anomaly(self, ev: dict[str, Any], ts: str | None) -> None:
        a = ev.get("anomaly")
        if isinstance(a, dict):
            kind = _str(a.get("type"), 24) or "anomaly"
            event = _str(a.get("event"), 80) or "unknown"
            self.anomalies.add(f"{kind}:{event}")

    def _on_flow(self, ev: dict[str, Any], ts: str | None) -> None:
        flow: dict[str, Any] = ev["flow"] if isinstance(ev.get("flow"), dict) else {}
        self.flows += 1
        self.flows_app.add(_str(ev.get("app_proto"), 24) or "unrecognised")
        proto = _str(ev.get("proto"), 16) or "?"
        self.flows_proto.add(proto)
        port = ev.get("dest_port")
        if isinstance(port, int):
            self.dest_ports.add(f"{port}/{proto}")
        pkts = _int(flow.get("pkts_toserver")) + _int(flow.get("pkts_toclient"))
        size = _int(flow.get("bytes_toserver")) + _int(flow.get("bytes_toclient"))
        row = self._talker(_str(ev.get("src_ip"), 64))
        if row is not None:
            row[0] += 1
            row[1] += pkts
            row[2] += size

    def _on_sip(self, ev: dict[str, Any], ts: str | None) -> None:
        sip = ev.get("sip")
        if not isinstance(sip, dict):
            return
        if sip.get("method"):
            self.sip_methods.add(_str(sip.get("method"), 24) or "?")
            uri = _str(sip.get("uri"), 120)
            if uri:
                self.sip_uris.add(uri)
        elif sip.get("code") is not None:
            self.sip_codes.add(_str(sip.get("code"), 8) or "?")

    def _on_dns(self, ev: dict[str, Any], ts: str | None) -> None:
        dns = ev.get("dns")
        if not isinstance(dns, dict):
            return
        name = _str(dns.get("rrname"), 120)
        if name and dns.get("type") != "answer":
            self.dns_names.add(name.lower())
            self.dns_types.add(_str(dns.get("rrtype"), 12) or "?")
        rcode = _str(dns.get("rcode"), 16)
        if rcode and dns.get("type") == "answer":
            self.dns_rcodes.add(rcode)

    def _on_http(self, ev: dict[str, Any], ts: str | None) -> None:
        http = ev.get("http")
        if not isinstance(http, dict):
            return
        for key, tally in (
            ("hostname", self.http_hosts),
            ("url", self.http_urls),
            ("http_user_agent", self.http_agents),
            ("http_method", self.http_methods),
        ):
            value = _str(http.get(key), 120)
            if value:
                tally.add(value)

    def _on_tls(self, ev: dict[str, Any], ts: str | None) -> None:
        tls = ev.get("tls")
        if not isinstance(tls, dict):
            return
        sni = _str(tls.get("sni"), 120)
        if sni:
            self.tls_sni.add(sni.lower())
        version = _str(tls.get("version"), 24)
        if version:
            self.tls_versions.add(version)

    def _on_ssh(self, ev: dict[str, Any], ts: str | None) -> None:
        ssh = ev.get("ssh")
        if not isinstance(ssh, dict):
            return
        client = _str(_get(ssh, "client", "software_version"), 80)
        server = _str(_get(ssh, "server", "software_version"), 80)
        if client:
            self.ssh_clients.add(client)
        if server:
            self.ssh_servers.add(server)

    # -- artifact row --------------------------------------------------------------------

    def _row(self, etype: str, ev: dict[str, Any], ts: str | None) -> dict[str, Any]:
        row: dict[str, Any] = {
            "t": ts,
            "type": etype,
            "src": _str(ev.get("src_ip"), 64),
            "sport": ev.get("src_port") if isinstance(ev.get("src_port"), int) else None,
            "dst": _str(ev.get("dest_ip"), 64),
            "dport": ev.get("dest_port") if isinstance(ev.get("dest_port"), int) else None,
            "proto": _str(ev.get("proto"), 16),
            "app": _str(ev.get("app_proto"), 24),
            "flow_id": ev.get("flow_id") if isinstance(ev.get("flow_id"), int) else None,
        }
        extra: dict[str, Any] = {}
        body = ev.get(etype)
        if etype == "alert" and isinstance(body, dict):
            extra = {
                "sid": _int(body.get("signature_id")),
                "rev": _int(body.get("rev")),
                "sig": _str(body.get("signature"), 200),
                "cat": _str(body.get("category"), 80),
                "sev": _int(body.get("severity")),
                "action": _str(body.get("action"), 16),
                "dir": _str(ev.get("direction"), 16),
            }
        elif etype == "anomaly" and isinstance(body, dict):
            extra = {"kind": _str(body.get("type"), 24), "event": _str(body.get("event"), 80)}
        elif etype == "flow" and isinstance(body, dict):
            extra = {
                "pkts_ts": _int(body.get("pkts_toserver")),
                "pkts_tc": _int(body.get("pkts_toclient")),
                "bytes_ts": _int(body.get("bytes_toserver")),
                "bytes_tc": _int(body.get("bytes_toclient")),
                "state": _str(body.get("state"), 24),
                "reason": _str(body.get("reason"), 24),
            }
        elif etype == "sip" and isinstance(body, dict):
            extra = {
                "method": _str(body.get("method"), 24),
                "uri": _str(body.get("uri"), 120),
                "code": _str(body.get("code"), 8),
            }
        elif etype == "dns" and isinstance(body, dict):
            extra = {
                "rrname": _str(body.get("rrname"), 120),
                "rrtype": _str(body.get("rrtype"), 12),
                "rcode": _str(body.get("rcode"), 16),
                "dns": _str(body.get("type"), 12),
            }
        elif etype == "http" and isinstance(body, dict):
            extra = {
                "host": _str(body.get("hostname"), 120),
                "url": _str(body.get("url"), 160),
                "method": _str(body.get("http_method"), 16),
                "ua": _str(body.get("http_user_agent"), 120),
                "status": body.get("status") if isinstance(body.get("status"), int) else None,
            }
        elif etype == "tls" and isinstance(body, dict):
            extra = {"sni": _str(body.get("sni"), 120), "version": _str(body.get("version"), 24)}
        elif etype == "ssh" and isinstance(body, dict):
            extra = {
                "client": _str(_get(body, "client", "software_version"), 80),
                "server": _str(_get(body, "server", "software_version"), 80),
            }
        elif etype == "fileinfo" and isinstance(ev.get("fileinfo"), dict):
            fi = ev["fileinfo"]
            extra = {
                "name": _str(fi.get("filename"), 120),
                "size": _int(fi.get("size")),
                "magic": _str(fi.get("magic"), 80),
                "sha256": _str(fi.get("sha256"), 64),
                "state": _str(fi.get("state"), 24),
            }
        row.update(extra)
        return _compact(row)

    # -- result --------------------------------------------------------------------------

    def _signatures(self) -> list[dict[str, Any]]:
        ranked = sorted(
            self.groups.values(),
            key=lambda g: (g.artifact, g.severity, -g.count, g.sid),
        )
        out = []
        for g in ranked[: self.top]:
            item: dict[str, Any] = {
                "sid": g.sid,
                "rev": g.rev,
                "signature": g.msg,
                "category": g.category,
                "severity": g.severity,
                "count": g.count,
                "sources": len(g.srcs),
                "destinations": len(g.dsts),
                "first_seen": g.first,
                "last_seen": g.last,
                "example": g.example,
            }
            if g.gid not in (0, 1):
                item["gid"] = g.gid
            if len(g.srcs) >= _MAX_DISTINCT or len(g.dsts) >= _MAX_DISTINCT:
                item["distinct_capped"] = _MAX_DISTINCT
            if g.artifact:
                item["capture_artifact"] = True
            out.append(item)
        return out

    def _stats(self) -> dict[str, Any]:
        s = self.stats or {}
        decoder: dict[str, Any] = s["decoder"] if isinstance(s.get("decoder"), dict) else {}
        out = {
            "packets_decoded": _int(decoder.get("pkts")),
            "bytes": _int(decoder.get("bytes")),
            "invalid_packets": _int(decoder.get("invalid")),
            "flows": _int(_get(s, "flow", "total")),
            "alerts_generated": _int(_get(s, "detect", "alert")),
            "alerts_suppressed": _int(_get(s, "detect", "alerts_suppressed")),
            "tcp_reassembly_gaps": _int(_get(s, "tcp", "reassembly_gap")),
            "capture_dropped": _int(_get(s, "capture", "kernel_drops")),
        }
        return {k: v for k, v in out.items() if v or k in ("packets_decoded", "invalid_packets")}

    def decoded_packets(self) -> int:
        return self._stats()["packets_decoded"] if self.stats else 0

    def result(self) -> dict[str, Any]:
        top = self.top
        talkers = sorted(self.talkers.items(), key=lambda kv: (-kv[1][1], -kv[1][0], kv[0]))
        sections: dict[str, Any] = {}
        detail: dict[str, Any] = {}
        for name, parts in (
            ("sip", (("methods", self.sip_methods), ("status_codes", self.sip_codes), ("uris", self.sip_uris))),
            ("dns", (("queries", self.dns_names), ("types", self.dns_types), ("rcodes", self.dns_rcodes))),
            ("http", (("hosts", self.http_hosts), ("urls", self.http_urls), ("user_agents", self.http_agents), ("methods", self.http_methods))),
            ("tls", (("sni", self.tls_sni), ("versions", self.tls_versions))),
            ("ssh", (("clients", self.ssh_clients), ("servers", self.ssh_servers))),
        ):  # fmt: skip
            block = {label: _tops(t, top) for label, t in parts if t.counts}
            if block:
                detail[name] = block
        sections["alerts"] = {
            "total": self.alerts,
            "excluding_checksum_artifacts": self.alerts - self.alerts_checksum,
            "checksum_artifacts": self.alerts_checksum,
            "signatures": len(self.groups) + self.group_overflow,
            "by_signature": self._signatures(),
            "by_category": self.by_category.mapping(top),
            "by_severity": {str(k): v for k, v in sorted(self.by_severity.counts.items())},
        }
        sections["top_sources"] = [
            {"ip": ip, "flows": r[0], "packets": r[1], "bytes": r[2], "alerts": r[3]}
            for ip, r in talkers[:top]
        ]
        sections["protocols"] = {
            "events": self.events.mapping(40),
            "flows": self.flows,
            "flows_by_app_proto": self.flows_app.mapping(top),
            "flows_by_transport": self.flows_proto.mapping(top),
            "destination_ports": _tops(self.dest_ports, top),
        }
        if detail:
            sections["app_layer"] = detail
        sections["anomalies"] = {
            "total": self.anomalies.total(),
            "by_event": self.anomalies.mapping(top),
        }
        sections["engine_stats"] = self._stats()
        return sections


# ── Zeek logs ───────────────────────────────────────────────────────────────────────────────

ZEEK_LOGS = (
    "conn", "notice", "weird", "dns", "http", "ssh", "sip", "ssl", "files", "software", "reporter",
)  # fmt: skip
_CONN_ANOMALIES = ("S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR", "OTH")


class ZeekDigest:
    """Reduce Zeek's JSON logs to a digest. Feed it `(log name, parsed row)`."""

    def __init__(self, top: int, artifact: _Artifact | None = None) -> None:
        self.top = top
        self.artifact = artifact
        self.rows: dict[str, int] = {}
        self.skipped = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        # conn
        self.conns = 0
        self.conn_service = _Tally()
        self.conn_state = _Tally()
        self.conn_proto = _Tally()
        self.conn_history = _Tally()
        self.conn_ports = _Tally()
        self.talkers: dict[str, list[int]] = {}  # ip -> connections, bytes, unanswered
        # notice / weird
        self.notices: dict[tuple[str, str], list[Any]] = {}
        self.notice_total = 0
        self.weird: dict[str, list[Any]] = {}
        self.weird_total = 0
        # protocols
        self.dns_q = _Tally()
        self.dns_qtype = _Tally()
        self.dns_rcode = _Tally()
        self.http_host = _Tally()
        self.http_ua = _Tally()
        self.http_method = _Tally()
        self.http_uri = _Tally()
        self.http_status = _Tally()
        self.ssh_client = _Tally()
        self.ssh_server = _Tally()
        self.ssh_attempts = 0
        self.ssh_auth = _Tally()
        self.sip_method = _Tally()
        self.sip_ua = _Tally()
        self.sip_uri = _Tally()
        self.sip_status = _Tally()
        self.sip_from = _Tally()
        self.ssl_sni = _Tally()
        self.ssl_version = _Tally()
        self.ssl_cipher = _Tally()
        self.ssl_established = _Tally()
        self.file_mime = _Tally()
        self.file_source = _Tally()
        self.file_bytes = 0
        self.file_hashes: dict[str, list[Any]] = {}
        self.software = _Tally()
        self.reporter: list[str] = []

    def feed(self, log_name: str, row: Any) -> None:
        if not isinstance(row, dict):
            self.skipped += 1
            return
        self.rows[log_name] = self.rows.get(log_name, 0) + 1
        ts = row.get("ts")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool) and log_name == "conn":
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = float(ts)
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = float(ts)
        getattr(self, f"_on_{log_name}")(row)
        if self.artifact is not None:
            self.artifact.add(_zeek_row(log_name, row))

    def _talker(self, ip: str | None) -> list[int] | None:
        if not ip:
            return None
        row = self.talkers.get(ip)
        if row is None:
            if len(self.talkers) >= _MAX_TALKERS:
                return None
            row = self.talkers[ip] = [0, 0, 0]
        return row

    def _on_conn(self, r: dict[str, Any]) -> None:
        self.conns += 1
        self.conn_service.add(_str(r.get("service"), 40) or "-")
        state = _str(r.get("conn_state"), 12) or "-"
        self.conn_state.add(state)
        proto = _str(r.get("proto"), 12) or "?"
        self.conn_proto.add(proto)
        self.conn_history.add(_str(r.get("history"), 40) or "-")
        port = r.get("id.resp_p")
        if isinstance(port, int):
            self.conn_ports.add(f"{port}/{proto}")
        row = self._talker(_str(r.get("id.orig_h"), 64))
        if row is not None:
            row[0] += 1
            row[1] += _int(r.get("orig_bytes")) + _int(r.get("resp_bytes"))
            if state in ("S0", "REJ"):
                row[2] += 1

    def _on_notice(self, r: dict[str, Any]) -> None:
        self.notice_total += 1
        note = _str(r.get("note"), 80) or "Notice"
        msg = _str(r.get("msg"), 160) or ""
        key = (note, msg)
        entry = self.notices.get(key)
        if entry is None:
            if len(self.notices) >= _MAX_SIG_GROUPS:
                return
            entry = self.notices[key] = [
                0,
                _str(r.get("src") or r.get("id.orig_h"), 64),
                _str(r.get("dst") or r.get("id.resp_h"), 64),
            ]
        entry[0] += 1

    def _on_weird(self, r: dict[str, Any]) -> None:
        self.weird_total += 1
        name = _str(r.get("name"), 80) or "unknown"
        entry = self.weird.get(name)
        if entry is None:
            if len(self.weird) >= _MAX_SIG_GROUPS:
                return
            entry = self.weird[name] = [0, set()]
        entry[0] += 1
        src = _str(r.get("id.orig_h"), 64)
        if src and len(entry[1]) < _MAX_DISTINCT:
            entry[1].add(src)

    def _on_dns(self, r: dict[str, Any]) -> None:
        query = _str(r.get("query"), 120)
        if query:
            self.dns_q.add(query.lower())
        qtype = _str(r.get("qtype_name"), 12)
        if qtype:
            self.dns_qtype.add(qtype)
        rcode = _str(r.get("rcode_name"), 16)
        if rcode:
            self.dns_rcode.add(rcode)

    def _on_http(self, r: dict[str, Any]) -> None:
        for key, tally in (
            ("host", self.http_host),
            ("user_agent", self.http_ua),
            ("method", self.http_method),
            ("uri", self.http_uri),
        ):
            value = _str(r.get(key), 120)
            if value:
                tally.add(value)
        status = r.get("status_code")
        if isinstance(status, int):
            self.http_status.add(str(status))

    def _on_ssh(self, r: dict[str, Any]) -> None:
        client, server = _str(r.get("client"), 80), _str(r.get("server"), 80)
        if client:
            self.ssh_client.add(client)
        if server:
            self.ssh_server.add(server)
        self.ssh_attempts += _int(r.get("auth_attempts"))
        success = r.get("auth_success")
        self.ssh_auth.add(
            "success" if success is True else "failure" if success is False else "unknown"
        )

    def _on_sip(self, r: dict[str, Any]) -> None:
        for key, tally in (
            ("method", self.sip_method),
            ("user_agent", self.sip_ua),
            ("uri", self.sip_uri),
            ("request_from", self.sip_from),
        ):
            value = _str(r.get(key), 120)
            if value:
                tally.add(value)
        code = r.get("status_code")
        if isinstance(code, int):
            self.sip_status.add(str(code))

    def _on_ssl(self, r: dict[str, Any]) -> None:
        sni = _str(r.get("server_name"), 120)
        if sni:
            self.ssl_sni.add(sni.lower())
        for key, tally in (("version", self.ssl_version), ("cipher", self.ssl_cipher)):
            value = _str(r.get(key), 64)
            if value:
                tally.add(value)
        self.ssl_established.add(
            "established" if r.get("established") is True else "not established"
        )

    def _on_files(self, r: dict[str, Any]) -> None:
        mime = _str(r.get("mime_type"), 80)
        self.file_mime.add(mime or "unknown")
        self.file_source.add(_str(r.get("source"), 24) or "unknown")
        size = _int(r.get("seen_bytes"))
        self.file_bytes += size
        digest = _str(r.get("sha1"), 64) or _str(r.get("md5"), 64) or _str(r.get("sha256"), 80)
        if digest:
            entry = self.file_hashes.get(digest)
            if entry is None:
                if len(self.file_hashes) >= 5_000:
                    return
                entry = self.file_hashes[digest] = [
                    0,
                    mime,
                    size,
                    _str(r.get("md5"), 64),
                    _str(r.get("sha256"), 80),
                ]
            entry[0] += 1

    def _on_software(self, r: dict[str, Any]) -> None:
        name = _str(r.get("name"), 60) or "unknown"
        version = _str(r.get("unparsed_version"), 80)
        self.software.add(f"{name} {version}".strip() if version else name)

    def _on_reporter(self, r: dict[str, Any]) -> None:
        if len(self.reporter) < 5:
            msg = _str(r.get("message"), 200)
            if msg:
                self.reporter.append(msg)

    # -- result --------------------------------------------------------------------------

    def result(self) -> dict[str, Any]:
        top = self.top
        out: dict[str, Any] = {}
        if self.conns:
            talkers = sorted(self.talkers.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))
            states = self.conn_state.counts
            out["connections"] = {
                "total": self.conns,
                "by_service": self.conn_service.mapping(top),
                "by_state": self.conn_state.mapping(top),
                "by_transport": self.conn_proto.mapping(top),
                "history_top": _tops(self.conn_history, top),
                "anomalies": {s: states[s] for s in _CONN_ANOMALIES if states.get(s)},
                "destination_ports": _tops(self.conn_ports, top),
                "top_sources": [
                    {"ip": ip, "connections": r[0], "bytes": r[1], "unanswered_or_rejected": r[2]}
                    for ip, r in talkers[:top]
                ],
            }
        if self.rows.get("notice"):
            ranked = sorted(self.notices.items(), key=lambda kv: (-kv[1][0], kv[0]))
            out["notices"] = {
                "total": self.notice_total,
                "groups": [
                    _compact(
                        {
                            "note": k[0],
                            "message": k[1] or None,
                            "count": v[0],
                            "example_src": v[1],
                            "example_dst": v[2],
                        }
                    )
                    for k, v in ranked[:top]
                ],
            }
        if self.rows.get("weird"):
            ranked_w = sorted(self.weird.items(), key=lambda kv: (-kv[1][0], kv[0]))
            out["weird"] = {
                "total": self.weird_total,
                "by_name": [
                    {"name": name, "count": v[0], "sources": len(v[1])}
                    for name, v in ranked_w[:top]
                ],
            }
        protocols: dict[str, Any] = {}
        if self.rows.get("dns"):
            protocols["dns"] = {
                "queries": _tops(self.dns_q, top),
                "types": self.dns_qtype.mapping(top),
                "rcodes": self.dns_rcode.mapping(top),
            }
        if self.rows.get("http"):
            protocols["http"] = {
                "hosts": _tops(self.http_host, top),
                "user_agents": _tops(self.http_ua, top),
                "methods": self.http_method.mapping(top),
                "uris": _tops(self.http_uri, top),
                "status_codes": self.http_status.mapping(top),
            }
        if self.rows.get("ssh"):
            protocols["ssh"] = {
                "clients": _tops(self.ssh_client, top),
                "servers": _tops(self.ssh_server, top),
                "auth_attempts": self.ssh_attempts,
                "auth": self.ssh_auth.mapping(5),
            }
        if self.rows.get("sip"):
            protocols["sip"] = {
                "methods": self.sip_method.mapping(top),
                "status_codes": self.sip_status.mapping(top),
                "user_agents": _tops(self.sip_ua, top),
                "uris": _tops(self.sip_uri, top),
                "from": _tops(self.sip_from, top),
                "note": "sip.log has one row per request/response exchange, so a request that "
                "is never answered (an ACK, most of a flood) is not counted; pcap_analyze counts "
                "packets.",
            }
        if self.rows.get("ssl"):
            protocols["tls"] = {
                "sni": _tops(self.ssl_sni, top),
                "versions": self.ssl_version.mapping(top),
                "ciphers": self.ssl_cipher.mapping(top),
                "handshakes": self.ssl_established.mapping(5),
            }
        if protocols:
            out["protocols"] = protocols
        if self.rows.get("files"):
            ranked_f = sorted(self.file_hashes.items(), key=lambda kv: (-kv[1][0], kv[0]))
            out["files"] = {
                "total": self.rows["files"],
                "seen_bytes": self.file_bytes,
                "by_mime_type": self.file_mime.mapping(top),
                "by_source": self.file_source.mapping(top),
                "hashes": [
                    _compact(
                        {
                            "sha1_or_md5": h,
                            "count": v[0],
                            "mime_type": v[1],
                            "bytes": v[2],
                            "sha256": v[4],
                        }
                    )
                    for h, v in ranked_f[:top]
                ],
            }
        if self.rows.get("software"):
            out["software"] = _tops(self.software, top)
        if self.reporter:
            out["engine_messages"] = self.reporter
        return out


def _zeek_row(log_name: str, row: dict[str, Any]) -> dict[str, Any]:
    """A Zeek row for the artifact: scalar fields only, every string clipped and cleaned."""
    out: dict[str, Any] = {"log": log_name}
    for key, value in row.items():
        if isinstance(value, str):
            out[key] = _clean(value, 300)
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = [
                _clean(v, 120) if isinstance(v, str) else v
                for v in value[:8]
                if not isinstance(v, (dict, list))
            ]
    return out


# ── running an engine ───────────────────────────────────────────────────────────────────────


def _suricata_command(rules: RulesState, has_classification: bool) -> list[str]:
    cmd = [
        "-v",
        "-r", f"{_IN}/{CAPTURE_NAME}",
        "-k", "none",
        # One thread: packets are processed in capture order, so threshold and flood rules count
        # the same on every replay (autofp splits flows across workers and the counts wander).
        "--runmode", "single",
        "-l", _OUT,
        "-S", f"{_RULES}/all.rules",
        # The image's default HOME_NET is the private ranges only, and a honeypot has a public
        # address, so the rules written "from outside to $HOME_NET" (most of the exploit and scan
        # signatures) never matched inbound traffic: a Shellshock request and a SIPVicious scan
        # replayed with no alert. A replayed capture has no known inside, so everything is both.
        # EXTERNAL_NET must be set too: it is defined as !$HOME_NET, which would be empty.
        "--set", "vars.address-groups.HOME_NET=any",
        "--set", "vars.address-groups.EXTERNAL_NET=any",
    ]  # fmt: skip
    if has_classification:
        cmd += ["--set", f"classification-file={_RULES}/{CLASSIFICATION_FILE}"]
    return cmd


def _zeek_command() -> list[str]:
    # -C: do not discard packets for a bad checksum (a capture taken on the sending host has
    # unfilled ones). Default scripts, JSON logs, written to the working directory.
    return ["zeek", "-C", "-r", f"{_IN}/{CAPTURE_NAME}", "LogAscii::use_json=T"]


def _image_version(image: str) -> str | None:
    _, tag = _split_image(image)
    return tag


def _parse_suricata(
    out_dir: Path, top: int, max_rows: int
) -> tuple[dict[str, Any], _Artifact, ReadStats, EveDigest]:
    artifact = _Artifact()
    digest = EveDigest(top, artifact)
    stats = ReadStats()
    for event in _iter_json_lines(out_dir / "eve.json", stats, max_rows=max_rows):
        digest.feed(event)
    return digest.result(), artifact, stats, digest


def _parse_zeek(
    out_dir: Path, top: int, max_rows: int
) -> tuple[dict[str, Any], _Artifact, dict[str, ReadStats], ZeekDigest]:
    artifact = _Artifact()
    digest = ZeekDigest(top, artifact)
    per_log: dict[str, ReadStats] = {}
    for name in ZEEK_LOGS:
        path = out_dir / f"{name}.log"
        stats = ReadStats()
        for row in _iter_json_lines(path, stats, max_rows=max_rows):
            digest.feed(name, row)
        if stats.rows or stats.bytes or stats.skipped:
            per_log[name] = stats
    return digest.result(), artifact, per_log, digest


def _rule_errors(logs: str) -> list[str]:
    lines = [
        ln
        for ln in logs.splitlines()
        if "error parsing signature" in ln.lower() or "Error: detect" in ln
    ]
    return [_clean(ln, 200) for ln in lines[:5]]


def _file_name_stem(name: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", Path(name).stem)[:60].strip("._-")
    return stem or "capture"


async def _write_artifact(
    artifact: _Artifact, header: dict[str, Any], engine: str, file_name: str
) -> dict[str, Any]:
    from honeypot_mcp.tools._format import write_artifact

    text = await asyncio.to_thread(artifact.text, header)
    info = await asyncio.to_thread(
        write_artifact,
        text,
        prefix=f"detect-{engine}-{_file_name_stem(file_name)}",
        extension="jsonl",
    )
    if "error" in info:
        return {"error": info["error"]}
    out: dict[str, Any] = {
        "path": info["path"],
        "bytes": info["bytes"],
        "rows": len(artifact.rows),
        "format": "jsonl (first line is _meta)",
    }
    if artifact.dropped:
        out["truncated"] = True
        out["rows_not_written"] = artifact.dropped
    return out


# ── the plain-language reading ──────────────────────────────────────────────────────────────

_RULES_STALE_DAYS = 30
_SEVERITY_NAMES = {1: "high", 2: "medium", 3: "low"}
# Signature text first, because ET categories mislead: a Sipvicious scan is filed under
# "Attempted Information Leak" and a MySQL `show databases` under "Generic Protocol Command Decode".
_SIGNATURE_READINGS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "exploit",
        re.compile(r"\bET (EXPLOIT|WEB_|CVE|ACTIVEX|SHELLCODE)|\bCVE-\d|\bexploit\b", re.I),
        "an exploitation attempt",
    ),
    (
        "malware",
        re.compile(r"\bET (MALWARE|TROJAN|CNC|BOTCC|MOBILE_MALWARE)\b|\bC2\b", re.I),
        "malware or command-and-control traffic",
    ),
    (
        "blocklist",
        re.compile(r"\bET (DROP|CINS|DSHIELD|COMPROMISED)\b|Dshield|Block Listed", re.I),
        "a source on a known-bad list",
    ),
    (
        "scan",
        re.compile(r"\bscan(ner|ning)?\b|sipvicious|friendly-scanner|nmap|masscan", re.I),
        "scanning or reconnaissance",
    ),
    (
        "sip",
        re.compile(r"\b(VOIP|SIP)\b.*\b(flood|unauthorized)", re.I),
        "a SIP login flood, consistent with password guessing (the 'Denial of Service' label is "
        "the honeypot's own 401 'Unauthorized' replies, not an attack on you)",
    ),
    (
        "database",
        re.compile(r"\b(GPL|ET) SQL\b|\bMYSQL\b|\bMSSQL\b|\bPOSTGRES", re.I),
        "database commands sent to the decoy",
    ),
    ("info", re.compile(r"\b(ET|GPL) INFO\b", re.I), "informational matches only"),
)
_CATEGORY_READINGS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "exploit",
        re.compile(r"web application attack|privilege gain|misc attack|exploit kit", re.I),
        "an exploitation attempt",
    ),
    (
        "malware",
        re.compile(r"trojan|executable code|malware|command and control", re.I),
        "malware or command-and-control traffic",
    ),
    ("dos", re.compile(r"denial of service", re.I), "a denial-of-service attempt"),
    ("scan", re.compile(r"network scan", re.I), "scanning or reconnaissance"),
    ("info", re.compile(r"misc activity|not suspicious", re.I), "informational matches only"),
)
_PHRASES = {tag: phrase for tag, _rx, phrase in (*_SIGNATURE_READINGS, *_CATEGORY_READINGS)}
_PRIORITY = ("exploit", "malware", "blocklist", "scan", "sip", "dos", "database", "info")


def _word(value: Any, limit: int = 16) -> str:
    """An engine protocol name reduced to `[a-z0-9_-]`."""
    return re.sub(r"[^a-z0-9_.-]", "", str(value).lower())[:limit]


def _ruleset_staleness(result: dict[str, Any]) -> str | None:
    """Why the ruleset is old, in a few words, or None when it is current enough."""
    rules = result.get("rules") or {}
    validated = rules.get("validated_with")
    running = result.get("engine_version")
    if validated and running and validated != running:
        return f"validated with Suricata {_word(validated, 12)}, run with {_word(running, 12)}"
    retrieved = rules.get("retrieved_at")
    if isinstance(retrieved, str):
        try:
            when = datetime.fromisoformat(retrieved)
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        age = (datetime.now(UTC) - when).days
        if age > _RULES_STALE_DAYS:
            return f"downloaded {age} days ago"
    return None


def _app_protocols(flows_by_app: dict[str, int]) -> str:
    """The recognised application protocols in the flows, by volume (engine vocabulary)."""
    ranked = sorted(flows_by_app.items(), key=lambda kv: (-kv[1], kv[0]))
    names = [_word(n) for n, _c in ranked if n not in ("failed", "unrecognised")]
    return ", ".join([n for n in names if n][:3])


def suricata_headline(result: dict[str, Any]) -> str:
    """Read a Suricata digest in plain words from fields it already holds."""
    alerts = result.get("alerts") or {}
    protocols = result.get("protocols") or {}
    rules_loaded = int(result.get("rules_loaded") or 0)
    total = int(alerts.get("total") or 0)
    artifacts = int(alerts.get("checksum_artifacts") or 0)
    real = int(alerts.get("excluding_checksum_artifacts", total - artifacts) or 0)
    flows = int(protocols.get("flows") or 0)
    protos = _app_protocols(protocols.get("flows_by_app_proto") or {})
    seen = ""
    if flows:
        seen = f"It followed {flows:,} flow(s)" + (f" ({protos})." if protos else ".")
    artifact_note = (
        f"{artifacts:,} 'invalid checksum' alert(s) are capture artifacts, not attacks."
        if artifacts
        else ""
    )
    if rules_loaded == 0:
        return pcap_analysis.fit_headline(
            "Suricata loaded 0 rules, so no alert here is NOT a clean result: nothing was "
            "checked against signatures. Call detection_rules_update() (admin), then replay.",
            [seen],
        )
    stale = _ruleset_staleness(result)
    stale_note = (
        f"The ruleset is stale ({stale}), so a quiet result is weak: call detection_rules_update()."
        if stale
        else ""
    )
    if real == 0:
        core = (
            f"Suricata ({rules_loaded:,} rules) matched no attack signature."
            + (f" {artifact_note}" if artifact_note else "")
            + " That means no known signature matched, not that the traffic was benign."
        )
        return pcap_analysis.fit_headline(core, [stale_note, seen])

    tags: set[str] = set()
    unread = 0
    for sig in alerts.get("by_signature") or []:
        if sig.get("capture_artifact"):
            continue
        text = str(sig.get("signature") or "")
        hit = next((t for t, rx, _p in _SIGNATURE_READINGS if rx.search(text)), None)
        if hit is None:
            category = str(sig.get("category") or "")
            hit = next((t for t, rx, _p in _CATEGORY_READINGS if rx.search(category)), None)
        if hit is None:
            unread += 1
        else:
            tags.add(hit)
    ordered = [t for t in _PRIORITY if t in tags]
    reading = "; ".join(_PHRASES[t] for t in ordered[:2]) or "signatures with no standard meaning"
    more = max(len(ordered) - 2, 0) + (unread if ordered else 0)
    if more:
        reading += f" (+{more} other kind(s))"
    ratings = [int(s) for s in (alerts.get("by_severity") or {}) if str(s).isdigit()]
    severity = ""
    if ratings:
        worst = min(ratings)
        severity = f" Worst severity {worst} ({_SEVERITY_NAMES.get(worst, 'unrated')})."
    core = (
        f"Suricata ({rules_loaded:,} rules) raised {real:,} real alert(s), reading as "
        f"{reading}.{severity}"
    )
    return pcap_analysis.fit_headline(
        core,
        [
            stale_note,
            artifact_note,
            "A replay shows which signatures match, not whether the attack worked.",
            seen,
        ],
    )


def zeek_headline(result: dict[str, Any]) -> str:
    """Read a Zeek digest in plain words: connection and protocol counts, notices, oddities."""
    conns = result.get("connections") or {}
    total = int(conns.get("total") or 0)
    if not total:
        return (
            "Zeek found no IP connections to follow in the capture, so it says nothing about "
            "the traffic; try pcap_analyze on the same file."
        )
    ranked = sorted((conns.get("by_service") or {}).items(), key=lambda kv: (-kv[1], kv[0]))
    services = [w for n, _c in ranked if n != "-" and (w := _word(n))][:3]
    anomalies = conns.get("anomalies") or {}
    unanswered = int(anomalies.get("S0", 0)) + int(anomalies.get("REJ", 0))
    notices = result.get("notices") or {}
    notice_total = int(notices.get("total") or 0)
    weird = int((result.get("weird") or {}).get("total") or 0)
    core = f"Zeek logged {total:,} connection(s)" + (
        f" ({', '.join(services)})" if services else ""
    )
    if unanswered:
        core += (
            f"; {unanswered:,} got no answer or were refused, which is what probing closed or "
            "filtered ports looks like"
        )
    elif anomalies:
        odd = sum(int(v) for v in anomalies.values())
        core += f"; {odd:,} ended abnormally (resets or half-open)"
    else:
        core += "; every one completed normally"
    if notice_total:
        names = [
            pcap_analysis.quote_value(g.get("note")) for g in (notices.get("groups") or [])[:2]
        ]
        core += f"; {notice_total:,} notice(s), led by {', '.join(names)}"
    else:
        core += "; no notices"
    core += "."
    return pcap_analysis.fit_headline(
        core,
        [
            f"{weird:,} protocol oddity log(s) in `weird`." if weird else "",
            "Zeek raises notices only for a few behaviours (scans, SSH guessing, some exploits), "
            "so no notice is not a clean bill; pcap_detect with Suricata checks signatures.",
        ],
    )


def _with_headline(result: dict[str, Any], headline: str) -> dict[str, Any]:
    """`result` with `headline` as its first key."""
    return {"headline": headline, **result}


def _empty_result(engine: str, scan: CaptureScan, size: int) -> dict[str, Any]:
    return {
        "headline": (
            "The capture holds no packets, so nothing was replayed. That says nothing about the "
            "attacker: its traffic was probably older than the ring buffer. Try another file "
            "from pcap_files."
        ),
        "engine": engine,
        "ran": False,
        "count": 0,
        "packets": 0,
        "window": None,
        "truncated": False,
        "note": (
            f"The capture holds no packets ({size} bytes), so nothing was replayed and no "
            "container was started."
        ),
    }


async def detect(path: str | None, engine: str, top: int = 10) -> dict[str, Any]:
    """Replay a capture through `engine` and return a digest. Never raises."""
    async with _lock.get():
        try:
            return await _detect(path, engine, top)
        except DetectError as e:
            return e.as_dict()
        except Exception as e:
            refused = _refused(e, "pcap_detect")
            if refused is not None:
                return refused.as_dict()
            log.exception("pcap_detect failed unexpectedly")
            return {
                "error": f"Unexpected failure running {engine} ({type(e).__name__}): {str(e)[:300]}"
            }


async def _detect(path: str | None, engine: str, top: int) -> dict[str, Any]:
    if engine not in ENGINES:
        raise DetectError(
            f"Unknown engine {engine!r}.",
            "Say Suricata (signature alerts, the default) or Zeek (protocol logs).",
        )
    top = max(1, min(int(top), 50))
    settings = get_settings()
    roots = [
        ("extract", Path(settings.reports_dir).expanduser()),
        ("ring", Path(settings.pcap_dir).expanduser()),
    ]
    max_bytes = settings.detection_max_pcap_mb * _MB
    chosen, how, problem = await asyncio.to_thread(pcap_analysis.choose_capture, path, roots)
    if problem is not None or chosen is None:
        return problem or {"error": "No capture file to read."}
    try:
        # The size cap is checked below against the settings of this tool, not the analyser's.
        fh, resolved, kind, size = pcap_analysis.open_capture(chosen, roots, 1 << 62)
    except pcap_analysis.CaptureAccessError as exc:
        return await asyncio.to_thread(pcap_analysis.access_error, exc, chosen, roots)
    file_info = {"name": resolved.name, "kind": kind, "bytes": size}
    if how:
        file_info["chosen"] = pcap_analysis.describe_choice(how, resolved.name)
    try:
        if size > max_bytes:
            return {
                "error": (
                    f"capture is {size / _MB:.0f} MB, over the {settings.detection_max_pcap_mb} MB "
                    "detection limit (DETECTION_MAX_PCAP_MB)"
                ),
                "hint": "Extract one source with pcap_extract, or raise the limit.",
                "file": file_info,
            }
        scan = await asyncio.to_thread(scan_capture, fh, size)
        if scan.problem:
            return {"error": scan.problem, "file": file_info}
        if scan.packets == 0:
            empty = _empty_result(engine, scan, size)
            return {"headline": empty.pop("headline"), "file": file_info, **empty}
        try:
            result = await _run_engine(fh, engine, top, scan, resolved.name, settings)
        except DetectError as e:
            return {**e.as_dict(), "file": file_info}
        headline = result.pop("headline", None)
        return {**({"headline": headline} if headline else {}), "file": file_info, **result}
    finally:
        fh.close()


async def _run_engine(
    fh: BinaryIO, engine: str, top: int, scan: CaptureScan, file_name: str, settings: Any
) -> dict[str, Any]:
    image = (
        settings.detection_suricata_image if engine == "suricata" else settings.detection_zeek_image
    )
    max_bytes = settings.detection_max_pcap_mb * _MB
    client = await asyncio.to_thread(_docker_client)
    await asyncio.to_thread(_reap_stale, client, settings.detection_timeout_seconds * 2 + 120)
    pulled = await asyncio.to_thread(_ensure_image, client, image, "pcap_detect")

    staging = await asyncio.to_thread(_stage, fh, max_bytes)
    try:
        rules = RulesState()
        has_class = False
        mounts = [
            (staging.in_dir, _IN, "ro"),
            (staging.out_dir, _OUT, "rw"),
        ]
        if engine == "suricata":
            rules = await asyncio.to_thread(
                _stage_rules, staging, Path(settings.detection_rules_dir)
            )
            assert staging.rules_dir is not None
            has_class = (staging.rules_dir / CLASSIFICATION_FILE).exists()
            mounts.append((staging.rules_dir, _RULES, "ro"))
            spec = _container_spec(
                image=image,
                engine=engine,
                command=_suricata_command(rules, has_class),
                entrypoint=["/usr/bin/suricata"],
                user=_USERS[engine],
                mounts=mounts,
                mem_mb=settings.detection_memory_mb,
                cpus=settings.detection_cpus,
            )
        else:
            spec = _container_spec(
                image=image,
                engine=engine,
                command=_zeek_command(),
                user=_USERS[engine],
                mounts=mounts,
                working_dir=_OUT,
                mem_mb=settings.detection_memory_mb,
                cpus=settings.detection_cpus,
            )
        try:
            outcome = await asyncio.to_thread(
                _run_container,
                client,
                spec,
                timeout=settings.detection_timeout_seconds,
                out_dir=staging.out_dir,
                out_limit=settings.detection_max_output_mb * _MB,
            )
        except DetectError:
            raise
        except Exception as e:
            raise _map_docker_error(e, engine) from None
        problem = _outcome_error(outcome, engine, settings)
        if problem is not None:
            raise problem
        if engine == "suricata":
            return await _finish_suricata(
                staging, outcome, rules, image, pulled, top, scan, file_name, settings
            )
        return await _finish_zeek(staging, outcome, image, pulled, top, scan, file_name, settings)
    finally:
        await asyncio.to_thread(staging.cleanup)


def _common(
    engine: str,
    image: str,
    pulled: bool,
    version: str | None,
    outcome: RunOutcome,
    scan: CaptureScan,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "engine": engine,
        "ran": True,
        "engine_version": version,
        "image": image,
        "image_pulled": pulled,
        "elapsed_seconds": outcome.seconds,
        "packets": scan.packets,
        "capture_format": scan.format,
        "window": _window(scan.first, scan.last),
    }
    return out


def _finalize(result: dict[str, Any], notes: list[str], truncated: bool) -> dict[str, Any]:
    result["truncated"] = truncated
    if notes:
        result["note"] = " ".join(notes)
    return result


async def _finish_suricata(
    staging: Staging, outcome: RunOutcome, rules: RulesState, image: str, pulled: bool,
    top: int, scan: CaptureScan, file_name: str, settings: Any,
) -> dict[str, Any]:  # fmt: skip
    sections, artifact, stats, digest = await asyncio.to_thread(
        _parse_suricata, staging.out_dir, top, _MAX_ROWS
    )
    if stats.rows == 0:
        raise DetectError(
            "Suricata produced no readable EVE output"
            + (f" ({stats.skipped} unreadable line(s))." if stats.skipped else ".")
            + f" {_log_problem(outcome.logs)}",
            "The capture may be damaged. Check it with pcap_analyze.",
        )
    decoded = digest.decoded_packets()
    if digest.stats is not None and decoded == 0:
        raise DetectError(
            f"Suricata decoded none of the {scan.packets} packets in the capture: "
            f"{_log_problem(outcome.logs)}",
            "The capture's link type may not be supported by the pinned Suricata image "
            f"({image}); Suricata 8 or later is needed for captures taken with tcpdump -i any.",
        )
    loaded = _RULES_LOADED.search(outcome.logs)
    rules_loaded = int(loaded.group(1)) if loaded else 0
    rules_failed = int(loaded.group(2)) if loaded else 0
    version_match = _SURICATA_VERSION.search(outcome.logs)
    version = version_match.group(1) if version_match else _image_version(image)
    meta = rules.meta or {}
    notes: list[str] = []
    if rules_loaded == 0:
        notes.append(
            "rules_loaded is 0: no detection rules were available, so there are no signature "
            "alerts, only protocol, flow and anomaly events. Call detection_rules_update() "
            "(admin, needs internet and Docker; about 15 s once the image is present, downloads "
            f"~45 MB of Emerging Threats Open rules), then pcap_detect(path={file_name!r}) again."
            if not rules.present and not rules.custom
            else "rules_loaded is 0: the rules files in the cache could not be loaded, so there "
            "are no signature alerts. Call detection_rules_update() (admin) to replace them, "
            "then replay; it reports rules_loaded when it is done."
        )
    if rules_failed:
        notes.append(f"{rules_failed} rule(s) failed to load (check {CUSTOM_RULES_FILE}).")
    if (
        rules.meta
        and meta.get("suricata_version")
        and version
        and meta["suricata_version"] != version
    ):
        notes.append(
            f"The ruleset was validated with Suricata {meta['suricata_version']} but this run "
            f"used {version}; call detection_rules_update() (admin) to re-download rules "
            "that match, then replay."
        )
    if sections["alerts"]["checksum_artifacts"]:
        notes.append(
            f"{sections['alerts']['checksum_artifacts']} 'invalid checksum' alert(s) are listed "
            "last and flagged capture_artifact: a capture taken on the sending host carries "
            "unfilled checksums (NIC offload), so they say little about the attacker."
        )
    if digest.stats is None:
        notes.append("Suricata's final statistics were not read, so packet counts are unchecked.")
    elif decoded != scan.packets:
        notes.append(f"Suricata decoded {decoded} of the capture's {scan.packets} packets.")
    truncated = stats.truncated or bool(artifact.dropped)
    if stats.truncated:
        notes.append(f"Only the first {_MAX_ROWS} EVE events were read.")
    if stats.skipped:
        notes.append(f"{stats.skipped} unreadable EVE line(s) were skipped.")

    result = _common("suricata", image, pulled, version, outcome, scan)
    result["count"] = sections["alerts"]["total"]
    result["rules_loaded"] = rules_loaded
    rules_block: dict[str, Any] = {
        "loaded": rules_loaded,
        "failed": rules_failed,
        "ruleset": meta.get("name") if rules.present else None,
        "retrieved_at": meta.get("retrieved_at") if rules.present else None,
        "validated_with": meta.get("suricata_version") if rules.present else None,
        "custom_rules": rules.custom,
    }
    if rules_failed:
        rules_block["errors"] = _rule_errors(outcome.logs)
    result["rules"] = rules_block
    result.update(sections)
    if stats.rows and digest.first_ts and result["window"] is None:
        result["window"] = {"first": digest.first_ts, "last": digest.last_ts, "seconds": None}
    header = {
        "engine": "suricata",
        "engine_version": version,
        "source": file_name,
        "rules_loaded": rules_loaded,
        "events": stats.rows,
    }
    result["artifact"] = await _write_artifact(artifact, header, "suricata", file_name)
    return _finalize(_with_headline(result, suricata_headline(result)), notes, truncated)


async def _finish_zeek(
    staging: Staging, outcome: RunOutcome, image: str, pulled: bool,
    top: int, scan: CaptureScan, file_name: str, settings: Any,
) -> dict[str, Any]:  # fmt: skip
    sections, artifact, per_log, digest = await asyncio.to_thread(
        _parse_zeek, staging.out_dir, top, _MAX_ROWS
    )
    notes: list[str] = []
    rows = sum(s.rows for s in per_log.values())
    unreadable = sum(s.skipped for s in per_log.values())
    if rows == 0 and unreadable:
        raise DetectError(
            f"Zeek wrote logs that could not be parsed as JSON ({unreadable} unreadable line(s)).",
            "The Zeek image may not support LogAscii::use_json; check DETECTION_ZEEK_IMAGE.",
        )
    if not digest.conns:
        notes.append(
            "Zeek wrote no connection log: the capture holds no IP traffic Zeek could follow."
        )
    truncated = any(s.truncated for s in per_log.values()) or bool(artifact.dropped)
    if any(s.truncated for s in per_log.values()):
        notes.append(f"Only the first {_MAX_ROWS} rows of a large log were read.")
    if unreadable:
        notes.append(f"{unreadable} unreadable log line(s) were skipped.")
    window = _window(scan.first, scan.last)
    if window is None and digest.first_ts is not None and digest.last_ts is not None:
        window = _window(digest.first_ts, digest.last_ts)

    result = _common("zeek", image, pulled, _image_version(image), outcome, scan)
    result["window"] = window
    result["count"] = digest.notice_total + digest.weird_total
    result["detections"] = {"notices": digest.notice_total, "weird": digest.weird_total}
    result["logs"] = {
        name: {"rows": s.rows, "bytes": s.bytes, **({"skipped": s.skipped} if s.skipped else {})}
        for name, s in per_log.items()
    }
    result.update(sections)
    header = {
        "engine": "zeek",
        "engine_version": _image_version(image),
        "source": file_name,
        "logs": {name: s.rows for name, s in per_log.items()},
    }
    result["artifact"] = await _write_artifact(artifact, header, "zeek", file_name)
    return _finalize(_with_headline(result, zeek_headline(result)), notes, truncated)


# ── the ruleset ─────────────────────────────────────────────────────────────────────────────


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _install_file(src: Path, dest: Path) -> None:
    """Copy `src` over `dest` atomically, owner-only. The old file stays until the very end."""
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
            shutil.copyfileobj(inp, out, 1 << 20)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _update_blocking(client: Any, settings: Any) -> dict[str, Any]:
    """Download, validate and install the ruleset. Blocking: run in a thread.

    The rules reach the cache only after Suricata itself loads them (`-T`, init failures fatal),
    so a truncated or incompatible download cannot replace a working ruleset.
    """
    image = settings.detection_suricata_image
    cache = Path(settings.detection_rules_dir)
    ensure_private_dir(cache)
    pulled = _ensure_image(client, image, "detection_rules_update")
    _reap_stale(client, settings.detection_timeout_seconds * 2 + 120)

    root = Path(tempfile.mkdtemp(prefix="hp-detect-rules-")).resolve()
    work = root / "rules"
    try:
        work.mkdir()
        os.chmod(work, 0o777)
        limit = settings.detection_max_output_mb * _MB
        fetch_spec = _container_spec(
            image=image,
            engine="suricata-update",
            command=["-D", "/tmp/su", "-o", _RULES, "--no-reload", "--no-test"],
            entrypoint=["suricata-update"],
            user=_USERS["suricata"],
            mounts=[(work, _RULES, "rw")],
            mem_mb=settings.detection_memory_mb,
            cpus=settings.detection_cpus,
            tmpfs_mb=_UPDATE_TMPFS_MB,
            network=True,  # the one place a detection container gets a network
        )
        try:
            fetched = _run_container(
                client,
                fetch_spec,
                timeout=settings.detection_timeout_seconds,
                out_dir=work,
                out_limit=limit,
            )
        except Exception as e:
            raise _map_docker_error(e, "suricata-update") from None
        problem = _outcome_error(
            fetched,
            "suricata-update",
            settings,
            "suricata-update needs internet access to rules.emergingthreats.net; check the "
            "connection and try again.",
        )
        if problem is not None:
            raise DetectError(problem.message + " The existing rules were kept.", problem.hint)
        rules_path = work / RULES_FILE
        try:
            rules_fh, rules_size = _open_regular(rules_path, _MAX_RULES_BYTES)
        except (OSError, DetectError):
            raise DetectError(
                "suricata-update finished but wrote no ruleset. The existing rules were kept.",
                "Check the connection and try again.",
            ) from None
        rules_fh.close()
        if rules_size == 0:
            raise DetectError(
                "suricata-update wrote an empty ruleset. The existing rules were kept."
            )
        totals = _UPDATE_TOTALS.search(fetched.logs)
        source = _UPDATE_SOURCE.search(fetched.logs)

        check_spec = _container_spec(
            image=image,
            engine="suricata-test",
            command=[
                "-T",
                "-v",
                "-S",
                f"{_RULES}/{RULES_FILE}",
                "--set",
                f"classification-file={_RULES}/{CLASSIFICATION_FILE}",
                "--set",
                "engine.init-failure-fatal=yes",
                "-l",
                "/tmp",
            ],  # fmt: skip
            entrypoint=["/usr/bin/suricata"],
            user=_USERS["suricata"],
            mounts=[(work, _RULES, "ro")],
            mem_mb=settings.detection_memory_mb,
            cpus=settings.detection_cpus,
        )
        try:
            checked = _run_container(client, check_spec, timeout=settings.detection_timeout_seconds)
        except Exception as e:
            raise _map_docker_error(e, "suricata") from None
        problem = _outcome_error(checked, "suricata", settings)
        loaded = _RULES_LOADED.search(checked.logs)
        if problem is not None or not loaded or int(loaded.group(1)) == 0 or int(loaded.group(2)):
            detail = problem.message if problem else _log_problem(checked.logs)
            raise DetectError(
                f"The downloaded ruleset did not pass validation by Suricata ({detail}). "
                "The existing rules were kept.",
                "Try again later; the upstream ruleset may be mid-publication.",
            )
        version_match = _SURICATA_VERSION.search(checked.logs)
        version = version_match.group(1) if version_match else _image_version(image)

        digest = _sha256_file(rules_path)
        _install_file(rules_path, cache / RULES_FILE)
        classification = work / CLASSIFICATION_FILE
        if classification.is_file() and not classification.is_symlink():
            _install_file(classification, cache / CLASSIFICATION_FILE)
        meta = {
            "name": RULESET_NAME,
            "source": source.group(1) if source else None,
            "retrieved_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "suricata_version": version,
            "image": image,
            "rules_total": int(totals.group(1)) if totals else None,
            "rules_enabled": int(totals.group(2)) if totals else None,
            "rules_loaded": int(loaded.group(1)),
            "bytes": rules_size,
            "sha256": digest,
        }
        meta_tmp = work / META_FILE
        meta_tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        _install_file(meta_tmp, cache / META_FILE)
        return {
            **{k: v for k, v in meta.items() if k != "name"},
            "ruleset": RULESET_NAME,
            "rules_dir": str(cache),
            "image_pulled": pulled,
            "custom_rules": (cache / CUSTOM_RULES_FILE).is_file(),
            "elapsed_seconds": round(fetched.seconds + checked.seconds, 2),
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


async def update_rules() -> dict[str, Any]:
    """Fetch Emerging Threats Open into the rules cache. Never raises."""
    async with _lock.get():
        try:
            settings = get_settings()
            client = await asyncio.to_thread(_docker_client)
            return await asyncio.to_thread(_update_blocking, client, settings)
        except DetectError as e:
            return e.as_dict()
        except Exception as e:
            refused = _refused(e, "detection_rules_update")
            if refused is not None:
                return refused.as_dict()
            log.exception("detection_rules_update failed unexpectedly")
            return {
                "error": f"Unexpected failure updating the rules ({type(e).__name__}): {str(e)[:300]}"
            }
