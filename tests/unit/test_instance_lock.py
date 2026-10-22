"""One process owns a deployment's sensors; the rest are read-only."""

import json
import os
import signal
import subprocess
import sys
import time

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
def restore_ownership():
    from honeypot_mcp import instance_lock

    yield
    instance_lock.set_ownership(True)


def _url(tmp_path) -> str:
    return f"sqlite+aiosqlite:///{tmp_path / 'hp.db'}"


def test_the_first_process_owns_the_sensors_and_the_second_is_told_who(tmp_path):
    from honeypot_mcp import instance_lock

    first, holder = instance_lock.try_acquire(_url(tmp_path), "stdio")
    assert first is not None and holder is None

    second, holder = instance_lock.try_acquire(_url(tmp_path), "streamable-http")
    assert second is None
    assert holder is not None and holder.pid == os.getpid() and holder.transport == "stdio"
    assert str(os.getpid()) in holder.describe()

    first.release()
    third, holder = instance_lock.try_acquire(_url(tmp_path), "stdio")
    assert third is not None and holder is None, "releasing the lock must hand over ownership"
    third.release()


def test_an_in_memory_database_is_never_contended():
    from honeypot_mcp import instance_lock

    for _ in range(2):
        lock, holder = instance_lock.try_acquire("sqlite+aiosqlite:///:memory:", "stdio")
        assert lock is not None and holder is None


def test_a_killed_owner_does_not_leave_a_stale_lock(tmp_path):
    """The OS drops the lock when the owner dies, however it dies — there is no pid
    file to go stale and no manual cleanup after a crash."""
    from honeypot_mcp import instance_lock

    code = (
        "import sys, time\n"
        "from honeypot_mcp import instance_lock\n"
        f"lock, _ = instance_lock.try_acquire({_url(tmp_path)!r}, 'stdio')\n"
        "print('held' if lock else 'denied', flush=True)\n"
        "time.sleep(60)\n"
    )
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "held"
        blocked, holder = instance_lock.try_acquire(_url(tmp_path), "stdio")
        assert blocked is None and holder.pid == child.pid
        child.send_signal(signal.SIGKILL)  # no chance to clean up
        child.wait(timeout=10)
        deadline = time.time() + 5
        lock = None
        while lock is None and time.time() < deadline:
            lock, _ = instance_lock.try_acquire(_url(tmp_path), "stdio")
            time.sleep(0.05)
        assert lock is not None, "the lock outlived its owner"
        lock.release()
    finally:
        if child.poll() is None:
            child.kill()


def test_the_owner_records_itself_for_the_message_other_processes_show(tmp_path):
    from honeypot_mcp import instance_lock

    lock, _ = instance_lock.try_acquire(_url(tmp_path), "streamable-http")
    data = json.loads(lock.path.read_text())
    assert data["pid"] == os.getpid() and data["transport"] == "streamable-http"
    lock.release()


def test_a_lock_that_cannot_be_created_does_not_stop_the_server(tmp_path, monkeypatch):
    from honeypot_mcp import instance_lock

    monkeypatch.setattr(
        instance_lock.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("ro"))
    )
    lock, holder = instance_lock.try_acquire(_url(tmp_path / "nope"), "stdio")
    assert lock is not None and holder is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool,args",
    [
        ("tools.honeypot:honeypot_deploy", {"type": "http"}),
        ("tools.honeypot:honeypot_stop", {"name": "x"}),
        ("tools.honeypot:honeypot_pause", {"name": "x"}),
        ("tools.honeypot:honeypot_resume", {"name": "x"}),
        ("tools.honeypot:honeypot_clone", {"source_name": "x", "new_port": 9999}),
        ("tools.honeypot:honeypot_configure", {"name": "x", "config": {}}),
        ("tools.honeypot:honeypot_self_test", {"name": "x"}),
        ("tools.deception:deception_deploy_plan", {"sensors": [], "tokens": []}),
        ("tools.pcap:pcap_control", {"action": "start"}),
    ],
)
async def test_every_tool_that_changes_sensors_refuses_in_a_read_only_process(tool, args):
    import importlib
    import inspect

    from honeypot_mcp import instance_lock

    module_name, func_name = tool.split(":")
    fn = getattr(importlib.import_module(f"honeypot_mcp.{module_name}"), func_name)
    params = set(inspect.signature(fn.fn if hasattr(fn, "fn") else fn).parameters)
    call_args = {k: v for k, v in args.items() if k in params}

    instance_lock.set_ownership(False, instance_lock.Holder(pid=4242, transport="stdio"))
    out = await fn(**call_args)
    assert "read-only" in out["error"] and "4242" in out["error"], out
    assert out["sensor_owner"] == {"pid": 4242, "transport": "stdio", "host": None}


@pytest.mark.asyncio
async def test_read_only_processes_still_serve_reads_and_say_what_they_are():
    from honeypot_mcp import instance_lock
    from honeypot_mcp.server import ping
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools.honeypot import honeypot_list

    event_buffer.reset_for_tests()
    await init_db()
    try:
        assert (await ping())["role"] == "owner"
        instance_lock.set_ownership(False, instance_lock.Holder(pid=1))
        assert (await ping())["role"] == "read-only"
        assert (await honeypot_list())["honeypots"] == []
    finally:
        await close_db()
        event_buffer.reset_for_tests()


@pytest.mark.asyncio
async def test_a_read_only_process_never_probes_or_inspects_in_process_sensors():
    """A TCP probe from the read-only process is indistinguishable from an attacker to the
    owner (self_probe is per-process), so it was recorded as a redis_connection alert; and
    asking an in-process engine for status from here said 'not running' for a sensor the
    database lists RUNNING."""
    from sqlalchemy import func, select

    from honeypot_mcp import instance_lock
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import Alert, Honeypot, HoneypotStatus, HoneypotType
    from honeypot_mcp.tools.honeypot import honeypot_health, honeypot_status

    event_buffer.reset_for_tests()
    await init_db()
    try:
        async with get_session() as session:
            session.add(
                Honeypot(
                    name="r1",
                    type=HoneypotType.REDIS,
                    port=16379,
                    status=HoneypotStatus.RUNNING,
                    container_id="in-process",
                )
            )
        instance_lock.set_ownership(False, instance_lock.Holder(pid=4242))
        result = await honeypot_health("r1")
        health = result["honeypots"][0]
        assert health["method"] == "not-probed" and health["alive"] is None
        assert result["answering"] == 0 and result["not_answering"] == []
        status = await honeypot_status("r1")
        assert status["engine_status"]["method"] == "not-probed"
        async with get_session() as session:
            assert (
                await session.execute(select(func.count()).select_from(Alert))
            ).scalar_one() == 0
    finally:
        instance_lock.set_ownership(True)
        await close_db()


def test_in_memory_url_variants_share_no_lock_and_postgres_uses_no_local_file():
    from honeypot_mcp import instance_lock

    for url in (
        "sqlite+aiosqlite:///:memory:",
        "sqlite+aiosqlite:///file::memory:?cache=shared&uri=true",
        # PostgreSQL ownership is an advisory lock in the database, not a file in a
        # directory another local user could write to.
        "postgresql+asyncpg://u:p@db/hp",
    ):
        assert instance_lock.lock_path_for(url) is None, url


def test_the_lock_file_is_never_written_through_a_planted_symlink(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    db = tmp_path / "hp.db"
    (tmp_path / "hp.db.owner").symlink_to(victim)
    from honeypot_mcp import instance_lock

    lock, holder = instance_lock.try_acquire(f"sqlite+aiosqlite:///{db}", "stdio")
    try:
        assert victim.read_text() == "precious"
        assert lock is not None  # refusing to follow the link must not stop the server
    finally:
        if lock:
            lock.release()


@pytest.mark.asyncio
async def test_a_read_only_process_takes_over_when_the_owner_goes_away(tmp_path, monkeypatch):
    """Read-only used to be permanent: if the owner exited, every remaining session stayed
    unable to deploy or stop anything until it was restarted by hand."""
    import asyncio

    from honeypot_mcp import instance_lock, server
    from honeypot_mcp.config import get_settings

    url = _url(tmp_path)
    monkeypatch.setattr(get_settings(), "database_url", url)
    monkeypatch.setattr(get_settings(), "owner_check_seconds", 1)
    owner, _ = await instance_lock.acquire(url, "stdio")
    assert owner is not None

    started = []

    class FakeServices:
        async def start(self):
            started.append(True)

    state: dict = {"lock": None}
    instance_lock.set_ownership(False, instance_lock.Holder(pid=1))
    task = asyncio.create_task(server._ownership_loop(FakeServices(), state))
    try:
        await asyncio.sleep(1.6)
        assert not instance_lock.sensors_owned() and not started  # owner still alive

        await owner.aclose()
        for _ in range(40):
            await asyncio.sleep(0.1)
            if instance_lock.sensors_owned():
                break
        assert instance_lock.sensors_owned() and started == [True]
        assert state["lock"] is not None
    finally:
        task.cancel()
        instance_lock.set_ownership(True)
        if state["lock"] is not None:
            await state["lock"].aclose()


_PG = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.skipif(not _PG.startswith("postgresql"), reason="needs PostgreSQL")
@pytest.mark.asyncio
async def test_postgres_ownership_is_an_advisory_lock_that_works_across_connections():
    """Two servers on different hosts share only the database, which the file lock cannot
    see. Held on a dedicated connection, the advisory lock names the holder and frees
    itself the moment that connection goes away."""
    from honeypot_mcp import instance_lock

    first, holder = await instance_lock.acquire(_PG, "stdio")
    assert first is not None and holder is None and await first.alive()

    second, holder = await instance_lock.acquire(_PG, "streamable-http")
    assert second is None
    assert holder.pid == os.getpid() and holder.transport == "stdio"

    await first.aclose()
    assert not await first.alive()
    third, holder = await instance_lock.acquire(_PG, "stdio")
    assert third is not None, holder
    await third.aclose()


@pytest.mark.skipif(not _PG.startswith("postgresql"), reason="needs PostgreSQL")
@pytest.mark.asyncio
async def test_a_dropped_postgres_connection_is_noticed_not_assumed_held():
    """A network blip closes the lock connection and silently releases the lock; `alive()`
    must say so, or two servers would both believe they own the sensors."""
    from sqlalchemy import text

    from honeypot_mcp import instance_lock

    lock, _ = await instance_lock.acquire(_PG, "stdio")
    assert lock is not None
    try:
        pid = (await lock._connection.execute(text("SELECT pg_backend_pid()"))).scalar_one()
        from sqlalchemy.ext.asyncio import create_async_engine

        engine = create_async_engine(_PG)
        async with engine.begin() as conn:
            await conn.execute(text("SELECT pg_terminate_backend(:p)"), {"p": pid})
        await engine.dispose()
        assert not await lock.alive()
        again, _ = await instance_lock.acquire(_PG, "stdio")
        assert again is not None  # the lock really was released
        await again.aclose()
    finally:
        await lock.aclose()


# ── hardening found in review ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_lock_that_cannot_be_consulted_changes_nobodys_role(monkeypatch):
    """An unreachable database is not an answer. An owner used to read "could not take the
    lock" as success (replacing its lock with a no-op), and a reader read it as "the owner is
    gone" and promoted itself, putting two processes on the same ports."""
    import asyncio

    from honeypot_mcp import instance_lock, server
    from honeypot_mcp.config import get_settings

    monkeypatch.setattr(get_settings(), "owner_check_seconds", 1)

    async def unreachable(*_a, **_k):
        raise instance_lock.LockError("database unreachable")

    monkeypatch.setattr(instance_lock, "acquire", unreachable)

    class Services:
        started = False

        async def start(self):
            raise AssertionError("a reader promoted itself on an error")

    class Owned:
        async def alive(self):
            return False  # the connection looks dead

        async def aclose(self):
            return None

    for owned in (False, True):
        instance_lock.set_ownership(owned, instance_lock.Holder(pid=1))
        state = {"lock": Owned() if owned else None}
        task = asyncio.create_task(server._ownership_loop(Services(), state))
        await asyncio.sleep(2.3)
        task.cancel()
        assert instance_lock.sensors_owned() is owned
    instance_lock.set_ownership(True)


@pytest.mark.asyncio
async def test_a_failed_takeover_releases_the_lock_and_is_retried(tmp_path, monkeypatch):
    """If starting the sensors raised after the lock was taken, the process sat on the lock
    forever with nothing running and nobody else able to take over."""
    from honeypot_mcp import instance_lock, server
    from honeypot_mcp.config import get_settings

    url = _url(tmp_path)
    monkeypatch.setattr(get_settings(), "database_url", url)
    attempts = []

    class Services:
        async def start(self):
            attempts.append(1)
            if len(attempts) == 1:
                raise RuntimeError("port in use")

    state: dict = {"lock": None}
    instance_lock.set_ownership(False, instance_lock.Holder(pid=1))
    await server._try_promote(Services(), state)
    assert not instance_lock.sensors_owned() and state["lock"] is None
    # the lock is free again: somebody else could have taken it
    other, _ = await instance_lock.acquire(url, "stdio")
    assert other is not None
    await other.aclose()

    await server._try_promote(Services(), state)
    assert instance_lock.sensors_owned() and state["lock"] is not None and len(attempts) == 2
    await state["lock"].aclose()
    instance_lock.set_ownership(True)


@pytest.mark.asyncio
async def test_owner_services_start_once_and_tear_down_what_a_failed_start_began():
    from honeypot_mcp import server

    cleaned = []

    class Runner:
        async def cleanup(self):
            cleaned.append(1)

    services = server._OwnerServices()

    async def failing_start():
        services._canary = Runner()
        raise RuntimeError("metrics port in use")

    services._start = failing_start  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await services.start()
    assert cleaned == [1] and not services.started

    # an already-started set is not started again (a second start rebinds every port)
    started = []

    async def fine_start():
        started.append(1)
        services.started = True

    services._start = fine_start  # type: ignore[method-assign]
    await services.start()
    await services.start()
    assert started == [1]


@pytest.mark.skipif(not _PG.startswith("postgresql"), reason="needs PostgreSQL")
@pytest.mark.asyncio
async def test_the_postgres_lock_survives_an_idle_in_transaction_timeout():
    """Held in a transaction, the lock's connection is "idle in transaction" for as long as
    the lock lives, and a server configured with `idle_in_transaction_session_timeout` kills
    it, silently releasing the lock while the owner believes it still owns the sensors."""
    import asyncio

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from honeypot_mcp import instance_lock

    admin = create_async_engine(_PG, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(
            text("ALTER DATABASE honeypot_test SET idle_in_transaction_session_timeout = '1s'")
        )
    try:
        lock, _ = await instance_lock.acquire(_PG, "stdio")
        assert lock is not None
        await asyncio.sleep(2.5)
        assert await lock.alive()
        await lock.aclose()
    finally:
        async with admin.connect() as conn:
            await conn.execute(
                text("ALTER DATABASE honeypot_test RESET idle_in_transaction_session_timeout")
            )
        await admin.dispose()


@pytest.mark.asyncio
async def test_analysis_mode_opens_the_data_without_starting_or_owning_any_sensor(monkeypatch):
    """A restored backup lists every sensor as RUNNING. Opening it for analysis on a laptop must not
    try to re-launch them (ports, Docker), take ownership, or start capture and notifications."""
    from honeypot_mcp import instance_lock, server
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    def forbidden(*_a, **_k):
        raise AssertionError("analysis mode started something that belongs to the sensor host")

    monkeypatch.setattr(get_settings(), "analysis_mode", True)
    monkeypatch.setattr(server, "reconcile_running_honeypots", forbidden)
    monkeypatch.setattr(server, "adopt_labelled_containers", forbidden)
    monkeypatch.setattr(instance_lock, "acquire", forbidden)
    monkeypatch.setattr(server._OwnerServices, "start", forbidden)
    event_buffer.reset_for_tests()

    async with server.lifespan(server.mcp):
        assert instance_lock.sensors_owned() is False
        out = await honeypot_deploy(type="http")
        assert "analysis mode" in out["error"], out
        # Reads are unaffected.
        assert (await server.ping())["status"]

    event_buffer.reset_for_tests()


def test_leaving_analysis_mode_restores_the_normal_read_only_message():
    from honeypot_mcp import instance_lock

    instance_lock.set_analysis_mode()
    assert "analysis mode" in instance_lock.read_only_error()["error"]
    instance_lock.set_ownership(False, instance_lock.Holder(pid=7))
    assert "analysis mode" not in instance_lock.read_only_error()["error"]
    instance_lock.set_ownership(True)
    assert instance_lock.read_only_error() is None
