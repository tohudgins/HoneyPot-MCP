"""The pre-flight checks catch the mistakes that are cheap before traffic and costly after.

Each test builds the bad configuration the check exists for and asserts it is refused with a
fix, and builds the good one and asserts it passes: a check that can only say "pass" is worse
than none.
"""

import json
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from honeypot_mcp import preflight as pf  # noqa: E402
from honeypot_mcp.config import get_settings  # noqa: E402


def settings(**overrides):
    return get_settings().model_copy(update=overrides)


GOOD_TOKEN = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_a_networked_control_plane_needs_a_token_and_may_not_opt_out():
    fail = pf.check_transport(settings(mcp_transport="streamable-http", mcp_auth_token=""))
    assert fail.status == pf.FAIL and "MCP_AUTH_TOKEN" in fail.fix
    open_door = pf.check_transport(
        settings(
            mcp_transport="streamable-http",
            mcp_auth_token=GOOD_TOKEN,
            mcp_allow_unauthenticated=True,
        )
    )
    assert open_door.status == pf.FAIL
    assert (
        pf.check_transport(
            settings(mcp_transport="streamable-http", mcp_auth_token=GOOD_TOKEN)
        ).status
        == pf.PASS
    )
    assert pf.check_transport(settings(mcp_transport="none")).status == pf.PASS
    assert (
        pf.check_transport(settings(mcp_transport="stdio")).status == pf.WARN
    )  # dies with the chat


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("short", pf.FAIL),
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", pf.FAIL),
        ("a1b2c3d4e5f60718293a4b5c", pf.WARN),
        (GOOD_TOKEN, pf.PASS),
    ],
)
def test_token_strength(token, expected):
    assert pf.check_tokens(settings(mcp_auth_token=token, mcp_auth_tokens="")).status == expected


def test_no_tokens_means_nothing_to_judge():
    assert pf.check_tokens(settings(mcp_auth_token="", mcp_auth_tokens="")).status == pf.SKIP


def test_the_console_and_metrics_must_not_be_bound_to_the_world():
    bad = pf.check_bind_addresses(
        settings(console_host="0.0.0.0", metrics_host="0.0.0.0", mcp_transport="stdio")
    )
    assert [c.status for c in bad] == [pf.FAIL, pf.FAIL] and "SSH tunnel" in bad[0].fix
    good = pf.check_bind_addresses(
        settings(console_host="127.0.0.1", metrics_host="127.0.0.1", mcp_transport="stdio")
    )
    assert all(c.status == pf.PASS for c in good)
    exposed = pf.check_bind_addresses(settings(mcp_transport="streamable-http", mcp_host="0.0.0.0"))
    assert any(c.name == "control plane bind address" and c.status == pf.WARN for c in exposed)


def test_env_file_permissions(tmp_path):
    env = tmp_path / ".env"
    assert pf.check_env_permissions(env).status == pf.SKIP
    env.write_text("MCP_AUTH_TOKEN=x")
    env.chmod(0o644)
    assert pf.check_env_permissions(env).status == pf.FAIL
    env.chmod(0o600)
    assert pf.check_env_permissions(env).status == pf.PASS


def test_database_must_survive_a_restart(tmp_path):
    assert (
        pf.check_database(settings(database_url="sqlite+aiosqlite:///:memory:")).status == pf.FAIL
    )
    assert (
        pf.check_database(settings(database_url=f"sqlite+aiosqlite:///{tmp_path}/hp.db")).status
        == pf.PASS
    )
    assert (
        pf.check_database(
            settings(database_url=f"sqlite+aiosqlite:///{tmp_path}/nope/hp.db")
        ).status
        == pf.WARN
    )
    assert (
        pf.check_database(settings(database_url="postgresql+asyncpg://u:p@db.example/hp")).status
        == pf.PASS
    )


def test_disk_is_judged_against_the_alert_floor_and_the_packet_ring(monkeypatch, tmp_path):
    def free(mb):
        monkeypatch.setattr(
            pf.shutil, "disk_usage", lambda _p: SimpleNamespace(free=mb * 1024 * 1024)
        )

    s = settings(min_free_disk_mb=500, pcap_enabled=False)
    free(100)
    assert [c.status for c in pf.check_disk(s, path=tmp_path)] == [pf.FAIL]
    free(1500)
    assert [c.status for c in pf.check_disk(s, path=tmp_path)] == [pf.WARN]
    free(50_000)
    assert [c.status for c in pf.check_disk(s, path=tmp_path)] == [pf.PASS]


def test_the_packet_ring_is_charged_to_the_volume_that_holds_it(monkeypatch, tmp_path):
    """The ring was added to the database volume's requirement and `pcap_dir` never looked at;
    for PostgreSQL the check looked at the reports directory instead of any database volume."""
    monkeypatch.setattr(
        pf.shutil, "disk_usage", lambda _p: SimpleNamespace(free=1200 * 1024 * 1024)
    )
    with_ring = settings(
        min_free_disk_mb=500, pcap_enabled=True, pcap_file_mb=100, pcap_files=10,
        pcap_dir=tmp_path / "ring", reports_dir=tmp_path / "reports",
        database_url=f"sqlite+aiosqlite:///{tmp_path}/db/hp.db",
    )  # fmt: skip
    checks = pf.check_disk(with_ring)
    failing = [c for c in checks if c.status == pf.FAIL]
    assert failing and "packet capture" in failing[0].name and "1500 MB" in failing[0].detail

    remote = settings(database_url="postgresql+asyncpg://u:p@db.example/hp", pcap_enabled=False,
                      reports_dir=tmp_path / "reports")  # fmt: skip
    names = [c.name for c in pf.check_disk(remote)]
    assert "free disk (database)" in names  # says plainly that a remote volume is not checked


def test_ports_in_use_and_the_admin_port_lockout():
    held = socket.socket()
    held.bind(("0.0.0.0", 0))
    held.listen()
    busy = held.getsockname()[1]
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 0))
        free_port = probe.getsockname()[1]
    try:
        by_name = {c.name: c for c in pf.check_ports([busy, free_port])}
        assert by_name[f"port {busy}"].status == pf.FAIL
        assert by_name[f"port {free_port}"].status == pf.PASS
        lockout = pf.check_ports([free_port], admin_port=free_port)
        assert lockout[0].name == "admin access" and lockout[0].status == pf.FAIL
        assert pf.check_ports([free_port], admin_port=2222)[0].status == pf.PASS
    finally:
        held.close()


def _snapshot(root, name="honeypot-20261005T000000Z", content=b"SQLite format 3\x00data"):
    snapshot = root / name
    snapshot.mkdir()
    (snapshot / "honeypot_mcp.db").write_bytes(content)
    return snapshot


def test_backups(tmp_path):
    assert pf.check_backup(None).status == pf.WARN
    assert pf.check_backup(tmp_path / "missing").status == pf.FAIL
    snapshot = _snapshot(tmp_path)
    assert pf.check_backup(tmp_path).status == pf.PASS
    old = time.time() - 60 * 3600
    os.utime(snapshot, (old, old))
    assert pf.check_backup(tmp_path).status == pf.WARN


def test_a_failed_backup_does_not_count_as_one(tmp_path):
    """backup.sh used to create its directory first, so a run that failed left an empty
    `honeypot-<stamp>/` that looked like a fresh backup."""
    (tmp_path / "honeypot-20261005T000000Z").mkdir()  # failed run, empty
    assert pf.check_backup(tmp_path).status == pf.FAIL
    _snapshot(tmp_path, "honeypot-20261005T010000Z", content=b"")  # zero-byte database
    assert pf.check_backup(tmp_path).status == pf.FAIL
    _snapshot(tmp_path, "honeypot-20261005T020000Z.partial")  # still being written
    assert pf.check_backup(tmp_path).status == pf.FAIL
    (tmp_path / "honeypot-latest").symlink_to("/nonexistent")  # dangling link must not crash
    assert pf.check_backup(tmp_path).status == pf.FAIL
    _snapshot(tmp_path, "honeypot-20261005T030000Z")
    assert pf.check_backup(tmp_path).status == pf.PASS


@pytest.mark.skipif(not Path("/bin/bash").exists(), reason="needs bash")
def test_backup_sh_leaves_nothing_behind_when_it_fails(tmp_path):
    import subprocess

    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["bash", str(repo / "scripts" / "backup.sh"), str(tmp_path / "out")],
        env={**os.environ, "HONEYPOT_DB_PATH": "/nonexistent", "DATABASE_URL": ""},
        capture_output=True, cwd=tmp_path,
    )  # fmt: skip
    assert result.returncode != 0
    assert not list((tmp_path / "out").glob("honeypot-*"))


@pytest.mark.parametrize(
    "token",
    [
        "passwordpasswordpasswordpassword", "0123456789" * 4, "abcdefghijklmnopqrstuvwxyz012345",
        "change-me-change-me-change-me-change-me", "a" * 40, "ab12" * 10,
    ],
)  # fmt: skip
def test_long_but_guessable_tokens_fail(token):
    assert pf.check_tokens(settings(mcp_auth_token=token, mcp_auth_tokens="")).status == pf.FAIL


def test_a_disabled_console_or_metrics_server_is_not_an_exposure():
    """`CONSOLE_PORT=0` / `METRICS_PORT=0` mean the server is not started at all."""
    off = pf.check_bind_addresses(
        settings(console_host="0.0.0.0", console_port=0, metrics_host="0.0.0.0", metrics_port=0,
                 mcp_transport="stdio")
    )  # fmt: skip
    assert all(c.status == pf.PASS and "disabled" in c.detail for c in off)


def test_env_permissions_are_read_from_where_the_server_reads_them(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("x")
    env.chmod(0o644)
    monkeypatch.setattr(pf, "_PROJECT_ROOT", tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)  # run from another directory, as `python -m` allows
    assert pf.check_env_permissions().status == pf.FAIL


def test_ports_are_probed_the_way_asyncio_binds_and_udp_is_probed_too():
    # A port left in TIME_WAIT by a just-stopped honeypot is bindable (asyncio sets
    # SO_REUSEADDR); a plain bind said "already in use".
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 0))
    server.listen()
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _ = server.accept()
    accepted.close()  # server side closes first -> TIME_WAIT on this port
    client.close()
    server.close()
    assert pf.check_ports([port])[0].status == pf.PASS

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 0))
    held = udp.getsockname()[1]
    try:
        assert pf.check_ports([(held, "udp")])[0].status == pf.FAIL
        assert pf.check_ports([(held, "both")])[0].status == pf.FAIL
        assert pf.check_ports([(held, "tcp")])[0].status == pf.PASS  # UDP and TCP are separate
    finally:
        udp.close()


# ── live checks, against a fake control plane ───────────────────────────────


def fake_plane(**responses):
    healthy = {
        "ping": {"status": "ok", "role": "owner"},
        "honeypot_list": [
            {"name": "ssh-1", "status": "running"},
            {"name": "rdp-1", "status": "running"},
        ],
        "honeypot_health": [{"name": "ssh-1", "alive": True}, {"name": "rdp-1", "alive": True}],
        "honeypot_self_test": {"alert_received": True},
        "alert_subscriptions_list": [{"id": 1}],
    }
    healthy.update(responses)
    calls = []

    async def call(tool, arguments):
        calls.append((tool, arguments))
        value = healthy[tool]
        if isinstance(value, Exception):
            raise value
        return value(arguments) if callable(value) else value

    call.calls = calls
    return call


async def run_plane(call, self_test=True):
    return {c.name: c for c in await pf.control_plane_checks(call, self_test=self_test)}


@pytest.mark.asyncio
async def test_a_healthy_estate_passes_and_every_sensor_is_probed():
    call = fake_plane()
    checks = await run_plane(call)
    assert all(c.status == pf.PASS for c in checks.values()), checks
    probed = [a["name"] for t, a in call.calls if t == "honeypot_self_test"]
    assert probed == ["ssh-1", "rdp-1"]


@pytest.mark.asyncio
async def test_each_way_the_estate_can_be_broken_is_reported():
    assert (await run_plane(fake_plane(ping=RuntimeError("401"))))[
        "control plane"
    ].status == pf.FAIL
    assert (await run_plane(fake_plane(ping={"role": "read-only"})))[
        "sensor ownership"
    ].status == pf.FAIL
    assert (await run_plane(fake_plane(honeypot_list=[])))["sensors"].status == pf.FAIL
    errored = fake_plane(
        honeypot_list=[{"name": "x", "status": "running"}, {"name": "y", "status": "error"}]
    )
    assert "y" in (await run_plane(errored))["sensors"].detail
    dead = fake_plane(honeypot_health=[{"name": "ssh-1", "alive": False}])
    assert (await run_plane(dead))["sensor health"].status == pf.FAIL
    silent = fake_plane(
        honeypot_self_test=lambda a: {"alert_received": a["name"] != "rdp-1", "detail": "no alert"}
    )
    result = (await run_plane(silent))["end-to-end self-test"]
    assert result.status == pf.FAIL and "rdp-1" in result.detail and "ssh-1" not in result.detail
    assert (await run_plane(fake_plane(alert_subscriptions_list=[])))[
        "alert channel"
    ].status == pf.WARN


@pytest.mark.asyncio
async def test_the_self_test_can_be_skipped_without_probing():
    call = fake_plane()
    checks = await run_plane(call, self_test=False)
    assert checks["end-to-end self-test"].status == pf.SKIP
    assert not [t for t, _ in call.calls if t == "honeypot_self_test"]


# ── readiness against a real metrics server ─────────────────────────────────


@pytest.mark.asyncio
async def test_readiness_reads_the_real_readyz_endpoint():
    from honeypot_mcp.metrics import start_metrics_server
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    runner = await start_metrics_server("127.0.0.1", port)
    try:
        assert (await pf.check_readiness(f"http://127.0.0.1:{port}")).status == pf.PASS
    finally:
        await runner.cleanup()
        await close_db()
        event_buffer.reset_for_tests()
    assert (await pf.check_readiness(f"http://127.0.0.1:{port}")).status == pf.FAIL  # nothing there


# ── output ────────────────────────────────────────────────────────────────────


def test_exit_status_and_rendering():
    ok = [pf.Check("a", pf.PASS, "fine"), pf.Check("b", pf.WARN, "hmm", "do x")]
    assert pf.exit_code(ok, strict=False) == 0 and pf.exit_code(ok, strict=True) == 1
    assert pf.exit_code([pf.Check("c", pf.FAIL, "bad")], strict=False) == 1
    text = pf.render(ok)
    assert (
        "[PASS] a: fine" in text
        and "-> do x" in text
        and "0 failed, 1 warning(s), 1 passed" in text
    )


def test_the_cli_runs_the_static_checks_and_emits_json(capsys, tmp_path):
    with socket.socket() as probe:
        probe.bind(("0.0.0.0", 0))
        port = probe.getsockname()[1]
    code = pf.main(["--json", "--ports", f"{port}", "--backup-dir", str(tmp_path)])
    checks = json.loads(capsys.readouterr().out)
    names = {c["name"] for c in checks}
    assert {"control plane transport", "database", f"port {port}", "backups"} <= names
    assert any(n.startswith("free disk") for n in names)
    assert code in (0, 1)


def test_a_ports_argument_may_name_a_protocol_and_must_be_valid(capsys):
    import argparse

    assert pf._ports("22, 80,3389") == [(22, "tcp"), (80, "tcp"), (3389, "tcp")]
    assert pf._ports("53/udp,5060/both") == [(53, "udp"), (5060, "both")]
    for bad in ("0", "ssh", "99999", "-5", "80/sctp", "٣"):
        with pytest.raises(argparse.ArgumentTypeError):
            pf._ports(bad)
    # on the command line a bad value is a usage error, not a traceback
    with pytest.raises(SystemExit) as exit_info:
        pf.main(["--ports", "99999"])
    assert exit_info.value.code == 2 and "bad port" in capsys.readouterr().err


def test_admin_port_is_read_from_the_ssh_session(monkeypatch):
    monkeypatch.setenv("SSH_CONNECTION", "203.0.113.5 51234 192.0.2.10 2222")
    assert pf._admin_port() == 2222
    monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5555 10.0.0.1 \u00b2")  # int() would crash
    assert pf._admin_port() is None
    monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5555 10.0.0.1 99999")
    assert pf._admin_port() is None
    monkeypatch.delenv("SSH_CONNECTION")
    assert pf._admin_port() is None


def test_the_checks_work_on_an_unmodified_checkout(tmp_path, monkeypatch):
    """No check may crash on a default configuration: a pre-flight that raises protects
    nobody."""
    monkeypatch.chdir(tmp_path)
    checks = pf.static_checks(get_settings(), ports=[], admin_port=None, backup_dir=None)
    assert checks and all(isinstance(c, pf.Check) and Path is not None for c in checks)


@pytest.mark.asyncio
async def test_unexpected_tool_answers_are_failures_not_passes_or_crashes():
    """An error object where a list was expected must not read as "no sensor is dead"."""
    plane = await run_plane(fake_plane(honeypot_health={"error": "boom"}))
    assert plane["sensor health"].status == pf.FAIL
    nonlist = await run_plane(fake_plane(honeypot_list={"error": "x"}))
    assert nonlist["sensors"].status == pf.FAIL
    mixed = await run_plane(fake_plane(honeypot_list=["not a dict"]))
    assert mixed["sensors"].status == pf.FAIL
    nameless = await run_plane(fake_plane(honeypot_list=[{"status": "running"}]))
    assert nameless["sensors"].status == pf.FAIL
    for bad in ([], "oops", {"alert_received": "false"}, {"error": "not running"}):
        got = await run_plane(fake_plane(honeypot_self_test=bad))
        assert got["end-to-end self-test"].status == pf.FAIL, bad
    assert (await run_plane(fake_plane(alert_subscriptions_list={"x": 1})))[
        "alert channel"
    ].status == pf.WARN


@pytest.mark.asyncio
async def test_a_sensor_that_was_not_probed_is_not_reported_healthy():
    """In a read-only second process every in-process sensor reports alive=None."""
    not_probed = fake_plane(
        honeypot_health=[{"name": "ssh-1", "alive": None}, {"name": "rdp-1", "alive": None}]
    )
    check = (await run_plane(not_probed))["sensor health"]
    assert check.status == pf.FAIL and "ssh-1" in check.detail
    # a running sensor missing from the health list altogether is not confirmed either
    missing = fake_plane(honeypot_health=[{"name": "ssh-1", "alive": True}])
    assert "rdp-1" in (await run_plane(missing))["sensor health"].detail
