"""Free-disk monitoring for the places this server writes.

A full disk is the quietest way for a honeypot to stop working: the listeners keep
answering attackers perfectly (they never touch the disk), while every captured event
fails to persist — and SQLite on a full volume fails mid-transaction, so it can also
corrupt the write in flight. Nothing watched for it. The watchdog, the readiness probe
and the metrics endpoint now share this one definition of "low".
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.engine import make_url

from honeypot_mcp.config import get_settings


@dataclass(frozen=True)
class DiskSample:
    label: str
    path: str
    free_bytes: int
    total_bytes: int

    @property
    def free_mb(self) -> int:
        return self.free_bytes // (1024 * 1024)


def watched_paths() -> list[tuple[str, Path]]:
    """What the server writes to: the database (when it is a local SQLite file),
    generated reports/exports/archives, and the packet-capture ring when enabled."""
    settings = get_settings()
    paths: list[tuple[str, Path]] = []
    try:
        url = make_url(settings.database_url)
        if (
            url.get_backend_name() == "sqlite"
            and url.database
            and ":memory:" not in settings.database_url
            and "mode=memory" not in settings.database_url
        ):
            paths.append(("database", Path(url.database).resolve().parent))
    except Exception:
        pass
    paths.append(("reports", Path(settings.reports_dir)))
    if settings.pcap_enabled:
        paths.append(("pcap", Path(settings.pcap_dir).expanduser()))
    return paths


def _existing_ancestor(path: Path) -> Path | None:
    for candidate in (path, *path.parents):
        if candidate.exists():
            return candidate
    return None


def sample() -> list[DiskSample]:
    """Free space for each watched location, one entry per underlying volume."""
    seen_devices: set[int] = set()
    out: list[DiskSample] = []
    for label, path in watched_paths():
        target = _existing_ancestor(path)
        if target is None:
            continue
        try:
            device = target.stat().st_dev
            usage = shutil.disk_usage(target)
        except OSError:
            continue
        if device in seen_devices:
            continue
        seen_devices.add(device)
        out.append(DiskSample(label, str(target), usage.free, usage.total))
    return out


def low_volumes(samples: list[DiskSample] | None = None) -> list[DiskSample]:
    """Volumes below `min_free_disk_mb`. Empty when the check is disabled (0)."""
    threshold_mb = get_settings().min_free_disk_mb
    if threshold_mb <= 0:
        return []
    return [s for s in (samples if samples is not None else sample()) if s.free_mb < threshold_mb]
