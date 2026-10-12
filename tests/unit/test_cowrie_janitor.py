"""Cowrie's RAM-backed artifact directories must not grow until the container is OOM-killed.

Found on the live droplet: the telnet container was OOM-killed 246 times in 20 hours. 43,591 empty
leftovers of failed downloads and 10,654 session recordings (~85 MB against a 64 MB tmpfs) cost
~80 MiB of kernel memory against a 256 MiB limit, and the full directory meant new recordings and
real downloads were failing to write. Each kill discarded every session, recording and sample.
The cleanup runs inside the container (the host's Docker guard refuses `exec`), so it is tested as
the code that ships there: `cowrie_sitecustomize.prune_artifacts`.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from honeypot_mcp.engines import cowrie_sitecustomize as patch


def _layout(tmp_path: Path) -> Path:
    root = tmp_path / "cowrie"
    (root / "downloads").mkdir(parents=True)
    (root / "tty").mkdir()
    return root


def _touch(path: Path, size: int, age_seconds: float) -> Path:
    path.write_bytes(b"x" * size)
    stamp = time.time() - age_seconds
    os.utime(path, (stamp, stamp), follow_symlinks=False)
    return path


def test_failed_download_leftovers_are_removed_but_real_samples_and_young_files_stay(tmp_path):
    root = _layout(tmp_path)
    old_empty = [_touch(root / "downloads" / f"tmp{i}", 0, 3600) for i in range(5)]
    old_empty.append(_touch(root / "downloads" / "redir_00ab", 0, 3600))
    malware = _touch(root / "downloads" / ("a" * 64), 4096, 3600)  # evidence: never touched
    young_empty = _touch(root / "downloads" / "in-flight", 0, 10)  # may still be transferring
    result = patch.prune_artifacts((str(root),), keep_tty=100)
    assert result["empty_downloads"] == 6
    assert not any(p.exists() for p in old_empty)
    assert malware.read_bytes() == b"x" * 4096 and young_empty.exists()


def test_only_the_newest_recordings_are_kept(tmp_path):
    root = _layout(tmp_path)
    files = [_touch(root / "tty" / f"s{i:03d}", 10, age_seconds=1000 - i) for i in range(50)]
    result = patch.prune_artifacts((str(root),), keep_tty=20)
    survivors = sorted(p.name for p in (root / "tty").iterdir())
    assert survivors == [f.name for f in files[-20:]], "the 20 newest, by modification time"
    assert result["tty_pruned"] == 30 and result["tty_kept"] == 20


def test_a_symlink_is_never_followed_or_deleted_through(tmp_path):
    """A recording or download name is attacker-influenced, so a planted link must not turn the
    janitor into a way to delete something else."""
    root = _layout(tmp_path)
    secret = _touch(tmp_path / "outside.txt", 0, 3600)  # empty and old: would qualify if followed
    (root / "downloads" / "link").symlink_to(secret)
    (root / "tty" / "link").symlink_to(secret)
    for i in range(5):
        _touch(root / "tty" / f"t{i}", 1, 100 + i)
    patch.prune_artifacts((str(root),), keep_tty=2)
    assert secret.exists(), "the target of a symlink must survive"
    assert (root / "downloads" / "link").is_symlink(), "and the link itself is left alone"
    assert (root / "tty" / "link").is_symlink()


def test_the_second_known_data_root_is_used_when_the_first_does_not_exist(tmp_path):
    root = _layout(tmp_path)
    _touch(root / "downloads" / "old", 0, 3600)
    result = patch.prune_artifacts((str(tmp_path / "nowhere"), str(root)), keep_tty=10)
    assert result is not None and result["empty_downloads"] == 1


def test_no_data_directory_is_none_not_an_empty_success(tmp_path):
    """Same rule as the backup's sample step: 'nothing to do' must not hide 'looked in the wrong
    place'."""
    assert patch.prune_artifacts((str(tmp_path / "nowhere"),), keep_tty=10) is None


def test_a_negative_keep_disables_recording_pruning(tmp_path):
    root = _layout(tmp_path)
    for i in range(10):
        _touch(root / "tty" / f"t{i}", 1, 100 + i)
    assert patch.prune_artifacts((str(root),), keep_tty=-1)["tty_pruned"] == 0
    assert len(list((root / "tty").iterdir())) == 10


def test_missing_subdirectories_are_not_an_error(tmp_path):
    root = tmp_path / "cowrie"
    root.mkdir()  # a fresh container: neither downloads/ nor tty/ exist yet
    assert patch.prune_artifacts((str(root),), keep_tty=10) == {
        "empty_downloads": 0,
        "tty_pruned": 0,
        "tty_kept": 0,
    }


def test_the_thread_starts_once_and_only_with_a_usable_interval(monkeypatch):
    started: list = []

    class _Thread:
        def __init__(self, **kwargs):
            started.append(kwargs)

        def start(self):
            pass

    monkeypatch.setattr(patch.threading, "Thread", _Thread)
    monkeypatch.setattr(patch, "_janitor_started", False)
    monkeypatch.setenv("HONEYPOT_JANITOR_INTERVAL", "120")
    monkeypatch.setenv("HONEYPOT_MAX_TTY", "777")
    patch.start_janitor()
    patch.start_janitor()
    assert len(started) == 1, "one thread per process however many patched modules load"
    assert started[0]["args"] == (120.0, 777) and started[0]["daemon"] is True

    for bad in ("0", "-5", "soon"):
        monkeypatch.setattr(patch, "_janitor_started", False)
        monkeypatch.setenv("HONEYPOT_JANITOR_INTERVAL", bad)
        patch.start_janitor()
    assert len(started) == 1, "0 turns it off; garbage is ignored rather than crashing Cowrie"


def test_only_importing_a_patched_cowrie_module_starts_the_janitor(monkeypatch):
    """The backup's sample step runs `docker exec python3 -c` in the container, which loads
    sitecustomize too; it must not grow a background thread. The thread starts from the patch
    functions, which run only when Cowrie imports its SSH/telnet modules."""
    calls: list[str] = []
    monkeypatch.setattr(patch, "start_janitor", lambda: calls.append("started"))
    monkeypatch.setattr(sys, "meta_path", list(sys.meta_path))  # restored after the test
    patch.install()  # what Python's `site` does at start-up: installs the import hook only
    assert calls == []

    class _Factory:
        buildProtocol = staticmethod(lambda self, addr: None)

    module = type("M", (), {"CowrieSSHFactory": _Factory})
    patch.patch_ssh_factory(module)
    assert calls == ["started"]


@pytest.mark.asyncio
async def test_status_of_a_docker_sensor_never_asks_the_docker_api_for_the_image():
    """Found by calling `honeypot_status` on the live droplet: it failed with a 403 from the host's
    Docker guard because `container.image` makes the SDK fetch `GET /images/<id>/json`, which the
    guard (rightly) refuses. The tool worked on every in-process sensor and broke on every
    Docker-backed one in the hardened deployment. It also exposes the restart count, because a
    sensor that is OOM-killed every few minutes still reads "running" between kills."""
    import docker
    from honeypot_mcp.engines.ssh import SSHEngine

    class _Container:
        status = "running"
        attrs = {
            "Config": {"Image": "cowrie/cowrie:latest"},
            "State": {"StartedAt": "2026-10-12T11:55:25Z", "OOMKilled": True},
            "RestartCount": 246,
        }

        @property
        def image(self):
            raise docker.errors.APIError("honeypot docker guard: GET /images/… is not permitted")

    class _Client:
        class containers:  # noqa: N801
            @staticmethod
            def get(_cid):
                return _Container()

    engine = SSHEngine.__new__(SSHEngine)
    engine._client = _Client()
    assert await engine.status("abc") == {
        "docker_status": "running",
        "image": "cowrie/cowrie:latest",
        "started_at": "2026-10-12T11:55:25Z",
        "restart_count": 246,
        "oom_killed": True,
    }
