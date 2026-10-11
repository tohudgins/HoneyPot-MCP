"""`scripts/fetch_backup.sh`: pull a backup off the VPS, verify it, and say whether the run worked.

The script is the laptop half of the "turn the droplet off but keep the data" procedure, so it has
to be right the one time it matters: it must refuse a hostile archive (the VPS is the machine
attackers have been talking to), it must notice a bad transfer, and its verdict must not count the
platform's own probes as attacker activity or call an empty run healthy.

The real backup script runs for real (against a real database built from the project's models);
only the transport is faked. `ssh` is a shim that runs the remote command locally, `sudo` drops
`-n`, `docker` replays a sample directory, and `sha256sum` exists for macOS. The whole thing over
a real sshd (ControlMaster, sudo, `docker exec` into a Cowrie container) was run by hand once;
see docs/HARDENING.md.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "fetch_backup.sh"

pytestmark = pytest.mark.skipif(shutil.which("sqlite3") is None, reason="needs the sqlite3 CLI")

SHIMS = {
    # An ssh that ignores its options and the host, and runs the remote command locally. With no
    # command it only "connects" (the script's `ssh -O exit` cleanup and its `true` probe).
    "ssh": """\
        #!/usr/bin/env bash
        while [ $# -gt 0 ]; do
          case "$1" in
            -o|-i|-p|-l|-F|-S|-O) shift 2 ;;
            -*) shift ;;
            *) break ;;
          esac
        done
        shift
        [ $# -gt 0 ] || exit 0
        exec bash -c "$*"
        """,
    # `sudo -n cmd`, with switches to simulate a hostile or broken VPS.
    "sudo": """\
        #!/usr/bin/env bash
        [ "${FAKE_NO_SUDO:-}" = 1 ] && { echo "sudo: a password is required" >&2; exit 1; }
        [ "$1" = "-n" ] && shift
        if [ "${FAKE_EVIL:-}" = 1 ] && [ "$1" = "tar" ]; then
          exec python3 - <<'PY'
        import io, sys, tarfile
        t = tarfile.open(fileobj=sys.stdout.buffer, mode="w|")
        for name in ("honeypot-20260101T000000Z/ok.txt", "../escaped.txt", "/tmp/absolute.txt"):
            data = b"x"; i = tarfile.TarInfo(name); i.size = 1; t.addfile(i, io.BytesIO(data))
        t.close()
        PY
        fi
        if [ "${FAKE_BADSHA:-}" = 1 ] && [ "$1" = "sha256sum" ]; then
          echo "0000000000000000000000000000000000000000000000000000000000000000  $2"; exit 0
        fi
        exec "$@"
        """,
    "sha256sum": """\
        #!/usr/bin/env bash
        exec shasum -a 256 "$@"
        """,
    # `docker ps` lists FAKE_CONTAINERS. `docker exec NAME python3 -c <b64 script>` runs the script
    # the fetcher really sent, with /cowrie remapped into FAKE_FS - so a wrong path in the script
    # fails here instead of silently reporting "0 files" on a real VPS. FAKE_NO_PYTHON=1 mimics a
    # container with no python3 (exec exits 126).
    "docker": """\
        #!/usr/bin/env bash
        case "$1" in
          ps) for c in $FAKE_CONTAINERS; do echo "$c"; done ;;
          exec)
            [ "${FAKE_NO_PYTHON:-}" = 1 ] && exit 126
            b64="$(printf '%s' "$5" | sed -E "s/.*b64decode\\('([^']*)'\\).*/\\1/")"
            printf '%s' "$b64" | base64 -d \\
              | sed "s#\\"/cowrie#\\"${FAKE_FS:-/nonexistent-fake-fs}/cowrie#g" | python3 - ;;
          *) exit 1 ;;
        esac
        """,
}


@pytest.fixture
def rig(tmp_path):
    shims = tmp_path / "shims"
    shims.mkdir()
    for name, body in SHIMS.items():
        path = shims / name
        path.write_text(textwrap.dedent(body))
        path.chmod(0o755)

    install = tmp_path / "install"
    (install / "scripts").mkdir(parents=True)
    for name in ("backup.sh", "_pgurl.py"):
        shutil.copy(ROOT / "scripts" / name, install / "scripts" / name)
    (install / "data").mkdir()
    db = install / "data" / "honeypot_mcp.db"
    (install / ".env").write_text(
        f"DATABASE_URL=sqlite+aiosqlite:///{db}\n"
    )  # four slashes: absolute

    # A real schema, from the project's own models.
    subprocess.run(
        [
            sys.executable, "-c",
            "import asyncio; from honeypot_mcp.storage.database import init_db, close_db\n"
            "async def m():\n    await init_db(); await close_db()\n"
            "asyncio.run(m())",
        ],
        env={**os.environ, "DATABASE_URL": f"sqlite+aiosqlite:///{db}"},
        check=True,
        capture_output=True,
    )  # fmt: skip

    class Rig:
        pass

    r = Rig()
    r.tmp, r.install, r.db, r.shims = tmp_path, install, db, shims
    r.remote_dir = tmp_path / "remote-backups"
    r.dest = tmp_path / "laptop"
    # Other test modules set DATABASE_URL=:memory: at import time. backup.sh prefers the
    # environment over the install's .env (as the server does), so a leaked value would make it
    # back up "memory": scrub every variable that picks the database.
    clean = {
        k: v
        for k, v in os.environ.items()
        if k not in ("DATABASE_URL", "TEST_DATABASE_URL", "HONEYPOT_DB_PATH")
    }
    r.env = {
        **clean,
        "PATH": f"{shims}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "TMPDIR": str(tmp_path),
    }

    def seed(honeypots, alerts, tokens=()):
        con = sqlite3.connect(db)
        for hid, name, kind, port, status in honeypots:
            con.execute(
                "INSERT INTO honeypots(id,name,type,port,status,config,created_at,updated_at) "
                "VALUES (?,?,?,?,?,'{}','2026-10-11 02:00:00','2026-10-11 02:00:00')",
                (hid, name, kind, port, status),
            )
        for hid, ip, event, payload, severity, ts in alerts:
            con.execute(
                "INSERT INTO alerts(honeypot_id,source_ip,event_type,payload,severity,acknowledged,timestamp) "
                "VALUES (?,?,?,?,?,0,?)",
                (hid, ip, event, payload, severity, ts),
            )
        for label, status, when in tokens:
            con.execute(
                "INSERT INTO honeytokens(type,label,token_value,status,token_meta,trigger_metadata,created_at,triggered_at) "
                "VALUES ('credential',?,'v',?,'{}','{}','2026-10-11 02:00:00',?)",
                (label, status, when),
            )
        con.commit()
        con.close()

    def run(*args, env=None, check=False):
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            env={**r.env, **(env or {})},
            capture_output=True,
            text=True,
            timeout=120,
            check=check,
        )

    def fetch(*extra, env=None):
        return run(
            "--host", "203.0.113.10", "--install-dir", str(install), "--remote-dir", str(r.remote_dir),
            "--dest", str(r.dest), *extra, env=env,
        )  # fmt: skip

    r.seed, r.run, r.fetch = seed, run, fetch
    return r


HEALTHY = (
    [
        (1, "hp-ssh", "ssh", 22, "RUNNING"),
        (2, "hp-web", "http", 8080, "RUNNING"),
        (3, "hp-rdp", "rdp", 3389, "RUNNING"),
    ],
    [
        (
            1,
            "203.0.113.5",
            "ssh_login_failed",
            '{"username":"root","password":"123456"}',
            "MEDIUM",
            "2026-10-11 03:10:00.1",
        ),
        (
            1,
            "203.0.113.5",
            "ssh_login_failed",
            '{"username":"root","password":"admin"}',
            "MEDIUM",
            "2026-10-11 03:40:00.1",
        ),
        (2, "198.51.100.9", "http_request", '{"path":"/.env"}', "LOW", "2026-10-11 04:30:00.1"),
        (
            3,
            "203.0.113.77",
            "rdp_handshake",
            '{"user":"administrator"}',
            "HIGH",
            "2026-10-11 05:00:00.1",
        ),
    ],
)


def _backup_dirs(rig):
    return sorted(p for p in rig.dest.glob("honeypot-*") if p.is_dir())


def test_a_healthy_run_is_fetched_verified_and_reported(rig):
    rig.seed(*HEALTHY, tokens=[("decoy-admin", "TRIGGERED", "2026-10-11 04:31:00")])
    done = rig.fetch()
    out = done.stdout + done.stderr
    assert done.returncode == 0, out

    (backup,) = _backup_dirs(rig)
    assert (backup / "honeypot_mcp.db").is_file() and (backup / ".env").is_file()
    assert stat.S_IMODE(backup.stat().st_mode) == 0o700, "the backup holds secrets"
    assert stat.S_IMODE((backup / ".env").stat().st_mode) == 0o600
    assert not list(rig.dest.glob("*.partial")) and not list(rig.dest.glob("*.tar"))
    assert "transfer verified" in out
    report = (backup / "report.txt").read_text()
    for expected in (
        "[PASS] database integrity_check is ok",
        "[PASS] 4 attacker events from 3 source addresses over 1.8 hours",
        "[INFO] honeytoken decoy-admin was TRIGGERED at 2026-10-11 04:31:00",
        "hp-ssh",
    ):
        assert expected in report, report
    assert "[FAIL]" not in report and "0 failed" in out
    # The sample credentials are summarised, not lost.
    assert "123456" in report and "administrator" not in report.split("credentials tried")[0]


def test_only_attacker_activity_counts_not_probes_or_platform_alerts(rig):
    sensors, alerts = HEALTHY
    alerts = [
        *alerts,
        # our own self-test probe from loopback, and one carrying the marker from a public address
        (
            2,
            "127.0.0.1",
            "http_request",
            '{"user_agent":"HoneyPotSelfTest/selftest_abc123"}',
            "LOW",
            "2026-10-11 02:05:00.1",
        ),
        (
            1,
            "203.0.113.99",
            "ssh_client_version",
            '{"client":"SSH-2.0-HoneyPotSelfTest/selftest_def456"}',
            "LOW",
            "2026-10-11 02:06:00.1",
        ),
        # a platform alert: not an attacker
        (
            1,
            "0.0.0.0",
            "honeypot_health_failed",
            '{"alive":false}',
            "CRITICAL",
            "2026-10-11 06:00:00.1",
        ),
    ]
    rig.seed(sensors, alerts)
    rig.fetch()
    report = (_backup_dirs(rig)[0] / "report.txt").read_text()
    assert "[PASS] 4 attacker events from 3 source addresses" in report, report
    assert "203.0.113.99" not in report.split("platform alerts")[0], (
        "a self-test probe is not a source"
    )
    # ...but the platform alert is still surfaced, as a warning about the run.
    assert "[WARN] 1 health failure alert(s)" in report


def test_the_verdict_names_a_dead_sensor_a_silent_one_a_missing_type_and_an_outage(rig):
    sensors = [
        (1, "hp-ssh", "ssh", 22, "RUNNING"),
        (2, "hp-redis", "redis", 6379, "ERROR"),
        (3, "hp-ldap", "ldap", 1389, "RUNNING"),
        (4, "hp-web", "http", 8080, "RUNNING"),
    ]
    alerts = [
        (
            1,
            "203.0.113.5",
            "ssh_login_failed",
            '{"username":"root"}',
            "MEDIUM",
            "2026-10-11 01:00:00.1",
        ),
        (4, "198.51.100.9", "http_request", "{}", "LOW", "2026-10-11 02:00:00.1"),
        # nothing at all for the next 20 hours, then one sensor wakes up: a gap and a silent sensor
        (
            1,
            "203.0.113.5",
            "ssh_login_failed",
            '{"username":"admin"}',
            "MEDIUM",
            "2026-10-12 00:00:00.1",
        ),
    ]
    rig.seed(sensors, alerts)
    done = rig.fetch("--expect-types", "ssh,redis,smb")
    report = (_backup_dirs(rig)[0] / "report.txt").read_text()
    assert done.returncode == 1, "a dead sensor and a missing expected type fail the run"
    assert "[FAIL] sensor hp-redis (redis/6379) is error in the database" in report
    assert "[FAIL] expected a smb honeypot but the database has none" in report
    assert "[PASS] 1 ssh honeypot(s) present" in report
    assert "[WARN] sensor hp-ldap (ldap/1389) recorded no attacker events" in report
    assert "[WARN] sensor hp-web has been silent for 22.0 hours while others were active" in report
    assert "had no activity at all" in report
    assert "[PASS] database integrity_check is ok" in report, (
        "still verified: the failures are about the run"
    )


def test_an_empty_run_is_a_failure_not_a_healthy_zero(rig):
    rig.seed([(1, "hp-ssh", "ssh", 22, "RUNNING")], [])
    done = rig.fetch()
    report = (_backup_dirs(rig)[0] / "report.txt").read_text()
    assert done.returncode == 1
    assert "[FAIL] no attacker activity was recorded at all" in report


def test_report_mode_analyses_a_backup_you_already_have_and_rejects_a_missing_one(rig):
    rig.seed(*HEALTHY)
    done = rig.run("report", str(rig.db))
    assert done.returncode == 0 and "[PASS] 4 attacker events" in done.stdout
    assert (rig.db.parent / "report.txt").exists()
    missing = rig.run("report", str(rig.tmp / "nowhere"))
    assert missing.returncode == 2 and "no database at" in missing.stderr


def test_a_hostile_archive_is_refused_before_anything_is_unpacked(rig, tmp_path):
    """The VPS is the machine attackers have been talking to. A tar naming `../escaped.txt` or an
    absolute path must be refused on the listing, so nothing is written outside the backup."""
    rig.seed(*HEALTHY)
    done = rig.fetch(env={"FAKE_EVIL": "1"})
    assert done.returncode != 0
    assert "refusing to unpack" in done.stderr
    assert not (tmp_path / "escaped.txt").exists() and not Path("/tmp/absolute.txt").exists()
    assert not _backup_dirs(rig), "no half-trusted backup is left behind"
    assert not list(rig.dest.glob("*.tar"))


def test_a_transfer_that_does_not_match_the_vps_checksum_fails_the_run(rig):
    rig.seed(*HEALTHY)
    done = rig.fetch(env={"FAKE_BADSHA": "1"})
    assert done.returncode == 1
    assert "SHA-256 mismatch" in done.stderr and "do not trust this copy" in done.stderr
    assert "the transfer did not verify" in done.stderr
    assert "VERIFIED" not in done.stdout


def test_delete_remote_happens_only_after_a_verified_transfer(rig):
    rig.seed(*HEALTHY)
    good = rig.fetch("--delete-remote")
    assert good.returncode == 0 and "removed the VPS copy" in good.stdout
    assert not list(rig.remote_dir.glob("honeypot-*")), (
        "the VPS copy was removed after verification"
    )

    rig.dest.rename(rig.tmp / "laptop-first")
    bad = rig.fetch("--delete-remote", env={"FAKE_BADSHA": "1"})
    assert bad.returncode == 1
    assert list(rig.remote_dir.glob("honeypot-*")), (
        "a copy that did not verify must not cost the VPS original"
    )


def _container_fs(tmp_path, root="cowrie/cowrie-git/var/lib/cowrie"):
    """A fake container filesystem holding Cowrie's state at `root` (the real image's layout by
    default), with a symlink planted in downloads as a hostile archive would."""
    fs = tmp_path / "fs"
    samples = fs / root
    (samples / "downloads").mkdir(parents=True)
    (samples / "tty").mkdir()
    (samples / "downloads" / ("a" * 64)).write_bytes(b"\x7fELF fake dropper")
    (samples / "downloads" / ("b" * 64)).write_bytes(b"#!/bin/sh\nrm -rf /\n")
    (samples / "tty" / ("c" * 64)).write_bytes(b"session")
    (samples / "downloads" / "evil-link").symlink_to("/etc/passwd")
    return fs


def test_samples_are_quarantined_without_permissions_and_symlinks_are_dropped(rig, tmp_path):
    rig.seed(*HEALTHY)
    fs = _container_fs(tmp_path)
    done = rig.fetch("--samples", env={"FAKE_CONTAINERS": "honeypot-hp-ssh", "FAKE_FS": str(fs)})
    assert done.returncode == 0, done.stdout + done.stderr

    quarantine = _backup_dirs(rig)[0] / "samples-QUARANTINE"
    files = sorted(
        p
        for p in quarantine.rglob("*")
        if p.is_file() and p.name not in ("README.txt", "SHA256SUMS")
    )
    assert len(files) == 3
    assert all(stat.S_IMODE(p.stat().st_mode) == 0 for p in files), (
        "no read, write or execute for anyone"
    )
    assert not any(p.is_symlink() for p in quarantine.rglob("*")), (
        "a symlink in a hostile archive is removed"
    )
    sums = (quarantine / "SHA256SUMS").read_text()
    assert sums.count("\n") == 3 and "honeypot-hp-ssh/downloads/" + "a" * 64 in sums
    assert "LIVE MALWARE" in (quarantine / "README.txt").read_text()


def test_cowrie_data_in_the_older_layout_is_found_too(rig, tmp_path):
    rig.seed(*HEALTHY)
    fs = _container_fs(tmp_path, "cowrie/var/lib/cowrie")
    done = rig.fetch("--samples", env={"FAKE_CONTAINERS": "honeypot-hp-ssh", "FAKE_FS": str(fs)})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "honeypot-hp-ssh: 3 file(s)" in done.stdout


def test_an_empty_cowrie_data_directory_is_zero_files_not_an_error(rig, tmp_path):
    rig.seed(*HEALTHY)
    fs = tmp_path / "fs"
    (fs / "cowrie/cowrie-git/var/lib/cowrie/downloads").mkdir(parents=True)
    done = rig.fetch("--samples", env={"FAKE_CONTAINERS": "honeypot-hp-ssh", "FAKE_FS": str(fs)})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "honeypot-hp-ssh: 0 file(s)" in done.stdout


def test_a_container_whose_cowrie_directory_cannot_be_found_is_a_failure_not_zero_files(
    rig, tmp_path
):
    """The bug this pins: the script looked in /cowrie/var/lib/cowrie, the real image keeps its
    state under /cowrie/cowrie-git, and every run reported "0 file(s)" - indistinguishable from
    "no malware yet" - while the container held dozens of samples."""
    rig.seed(*HEALTHY)
    fs = tmp_path / "fs"
    (fs / "cowrie/somewhere/else").mkdir(parents=True)
    done = rig.fetch("--samples", env={"FAKE_CONTAINERS": "honeypot-hp-ssh", "FAKE_FS": str(fs)})
    assert done.returncode != 0
    assert "samples were NOT collected" in done.stderr + done.stdout


def test_a_container_without_python_is_skipped_as_not_cowrie(rig):
    rig.seed(*HEALTHY)
    done = rig.fetch("--samples", env={"FAKE_CONTAINERS": "honeypot-hp-ssh", "FAKE_NO_PYTHON": "1"})
    assert done.returncode == 0, done.stdout + done.stderr
    assert "nothing to copy" in done.stdout


def test_a_vps_without_passwordless_sudo_gets_an_explanation_not_a_stack_of_errors(rig):
    done = rig.fetch(env={"FAKE_NO_SUDO": "1"})
    assert done.returncode == 1
    assert "cannot run sudo without a password" in done.stderr
    assert not _backup_dirs(rig)


@pytest.mark.parametrize(
    "args",
    [
        ["--host", "1.2.3.4; rm -rf ~"],
        ["--host", "1.2.3.4", "--user", "x y"],
        ["--host", "1.2.3.4", "--install-dir", "/opt/a b"],
        ["--host", "1.2.3.4", "--remote-dir", "/var/$(id)"],
        ["--host", "1.2.3.4", "--port", "22; id"],
        ["--host", "1.2.3.4", "--key", "/home/me/my key"],
        ["--bogus"],
        [],
    ],
)
def test_unusual_values_are_refused_before_anything_connects(rig, args):
    done = rig.run(*args)
    assert done.returncode == 2
    assert not rig.dest.exists()


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_a_wal_mode_backup_is_reported_without_side_files_or_changing_a_byte(rig):
    """The server runs its database in WAL mode and `.backup` keeps that in the file header. A plain
    read-only open of a WAL database needs its -shm/-wal side files ("unable to open database file"
    otherwise), which a downloaded snapshot does not have: on the real droplet the transfer verified
    and then every report query failed, because every test database before this one was in rollback
    mode. The snapshot must be read as `immutable`: no side files, no writes, checksum intact."""
    con = sqlite3.connect(rig.db)
    con.execute("PRAGMA journal_mode=WAL")
    con.close()
    rig.seed(*HEALTHY)
    done = rig.fetch()
    assert done.returncode == 0, done.stdout + done.stderr

    (backup,) = _backup_dirs(rig)
    db = backup / "honeypot_mcp.db"
    assert db.read_bytes()[18:20] == b"\x02\x02", "the fixture is really a WAL-mode snapshot"
    report = (backup / "report.txt").read_text()
    assert "[PASS] database integrity_check is ok" in report, report
    assert "[PASS] 4 attacker events from 3 source addresses" in report, report
    assert "unable to open" not in report
    assert not list(backup.glob("honeypot_mcp.db-*")), "no -shm/-wal files beside the evidence"

    before = _sha256(db)
    again = rig.run("report", str(backup))
    assert again.returncode == 0 and "[PASS] 4 attacker events" in again.stdout
    assert _sha256(db) == before and not list(backup.glob("honeypot_mcp.db-*"))


@pytest.mark.parametrize("folder", ["my backups", "run #1", "100%25 done", "what?"])
def test_a_destination_with_uri_special_characters_still_opens_the_database(rig, folder):
    """The database is opened through a `file:` URI, so a space, `#`, `%` or `?` in the path must be
    escaped or sqlite reads the wrong file (or none)."""
    rig.seed(*HEALTHY)
    done = rig.fetch("--dest", str(rig.tmp / folder))
    assert done.returncode == 0, done.stdout + done.stderr
    (backup,) = sorted((rig.tmp / folder).glob("honeypot-*"))
    assert "[PASS] 4 attacker events from 3 source addresses" in (backup / "report.txt").read_text()


def test_internal_sources_are_the_platforms_own_traffic_and_public_neighbours_of_those_ranges_are_not(
    rig,
):
    """On the droplet the Docker bridge address (172.17.0.1) is the source Cowrie sees for the
    self-tests and the pre-flight probes, and only some of those events carry the self-test marker:
    the first real report counted it as an attacker with 28 events. Private ranges cannot be the
    internet, so they are reported on their own line; but an address just outside a private range is
    a real source and must stay (172.32.x is public, 172.31.x is not; 192.169.x is public)."""
    sensors, alerts = HEALTHY
    internal = [
        "172.17.0.1",
        "10.0.0.5",
        "192.168.1.9",
        "169.254.169.254",
        "172.31.255.255",
        "fd12::1",
        "FE80::1",
    ]
    public_neighbours = ["172.32.0.1", "172.15.0.1", "192.169.0.1", "11.0.0.1"]
    extra = [
        (1, ip, "ssh_session_connect", "{}", "LOW", f"2026-10-11 06:0{i}:00.1")
        for i, ip in enumerate(internal + public_neighbours)
    ]
    rig.seed(sensors, [*alerts, *extra])
    rig.fetch()
    report = (_backup_dirs(rig)[0] / "report.txt").read_text()

    assert "[PASS] 8 attacker events from 7 source addresses" in report, report
    assert "[INFO] 7 event(s) came from internal addresses" in report, report
    top_sources = report.split("--- top sources")[1].split("\n--- ")[0]
    for ip in public_neighbours:
        assert ip in top_sources, f"{ip} is a public address and must be reported"
    for ip in internal:
        assert ip.lower() not in top_sources.lower(), f"{ip} is internal and must not be a 'source'"
