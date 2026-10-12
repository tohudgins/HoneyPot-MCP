"""The FTP honeypot's tree: LIST, SIZE, MDTM and RETR must agree with each other.

Driven by the standard library's real `ftplib` client in a worker thread. The old
engine printed one fixed listing and answered every RETR with 550, although FEAT
advertised SIZE/MDTM/REST/EPSV that were never implemented — so a scanner that
followed LIST with SIZE on a name it had just been shown got a refusal.
"""

import asyncio
import contextlib
import ftplib
import hashlib
import os
import re
import socket

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("0.0.0.0", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await asyncio.sleep(0.2)
    await buffer.stop()
    event_buffer.reset_for_tests()
    await close_db()


@pytest.fixture
async def ftp_port():
    from honeypot_mcp.engines.ftp import FTPEngine
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotType

    port = _free_port()
    async with get_session() as session:
        session.add(Honeypot(name="ftp-tree", type=HoneypotType.FTP, port=port))
        await session.flush()
    engine = FTPEngine()
    cid = await engine.start("ftp-tree", port, {})
    yield port
    await engine.stop(cid)


def _session(port: int) -> ftplib.FTP:
    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", port, timeout=5)
    ftp.login("anonymous", "scanner@example.com")
    return ftp


async def _in_thread(fn, *args):
    return await asyncio.to_thread(fn, *args)


async def test_listing_size_and_downloaded_bytes_all_agree(ftp_port):
    def run() -> dict:
        ftp = _session(ftp_port)
        listing: list[str] = []
        ftp.retrlines("LIST", listing.append)
        listed = {}
        for line in listing[1:]:
            m = re.match(r"\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+ \d+ [\d:]+ (.+)$", line)
            assert m, line
            listed[m.group(2)] = int(m.group(1))
        out = {"listed": listed, "names": ftp.nlst(), "sizes": {}, "bytes": {}, "mdtm": {}}
        for name in ("passwords.txt", "README.txt", "backup.tar.gz"):
            out["sizes"][name] = ftp.size(name)
            chunks: list[bytes] = []
            ftp.retrbinary(f"RETR {name}", chunks.append)
            out["bytes"][name] = b"".join(chunks)
            out["mdtm"][name] = ftp.voidcmd(f"MDTM {name}")
        ftp.quit()
        return out

    r = await _in_thread(run)
    assert set(r["names"]) >= {"pub", "incoming", "passwords.txt", "README.txt"}
    for name, data in r["bytes"].items():
        assert r["listed"][name] == r["sizes"][name] == len(data), name
        assert r["mdtm"][name].startswith("213 ")
    assert r["bytes"]["README.txt"].startswith(b"Welcome")
    # backup.tar.gz is a real gzip'd tar, so an attacker's `tar xzf` works.
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(r["bytes"]["backup.tar.gz"]), mode="r:gz") as tar:
        assert "etc/hosts" in tar.getnames()


async def test_cwd_into_real_directories_and_refusal_of_missing_ones(ftp_port):
    def run() -> tuple:
        ftp = _session(ftp_port)
        ftp.cwd("pub")
        here = ftp.pwd()
        names = ftp.nlst()
        ftp.cwd("..")
        try:
            ftp.cwd("does-not-exist")
            missing = "accepted"
        except ftplib.error_perm as e:
            missing = str(e)
        try:
            ftp.size("nope.txt")
            size_missing = "accepted"
        except ftplib.error_perm as e:
            size_missing = str(e)
        try:
            ftp.retrbinary("RETR nope.txt", lambda _b: None)
            retr_missing = "accepted"
        except ftplib.error_perm as e:
            retr_missing = str(e)
        return here, names, missing, size_missing, retr_missing

    here, names, missing, size_missing, retr_missing = await _in_thread(run)
    assert here == "/pub" and names == ["welcome.msg"]
    assert "No such file or directory" in missing
    assert "No such file or directory" in size_missing
    assert "No such file or directory" in retr_missing


async def test_dotdot_cannot_climb_above_the_root(ftp_port):
    def run() -> str:
        ftp = _session(ftp_port)
        ftp.cwd("/../../..")
        return ftp.pwd()

    assert await _in_thread(run) == "/"


async def test_rest_resumes_a_download_at_the_offset(ftp_port):
    def run() -> tuple[bytes, bytes]:
        ftp = _session(ftp_port)
        whole: list[bytes] = []
        ftp.retrbinary("RETR README.txt", whole.append)
        tail: list[bytes] = []
        ftp.retrbinary("RETR README.txt", tail.append, rest=10)
        return b"".join(whole), b"".join(tail)

    whole, tail = await _in_thread(run)
    assert tail == whole[10:]


async def test_epsv_is_implemented_since_feat_advertises_it(ftp_port):
    def run() -> str:
        ftp = _session(ftp_port)
        return ftp.sendcmd("EPSV")

    reply = await _in_thread(run)
    assert reply.startswith("229 Entering Extended Passive Mode (|||")


async def test_unknown_commands_get_proftpds_500_not_502(ftp_port):
    def run() -> str:
        ftp = _session(ftp_port)
        try:
            ftp.sendcmd("XYZZY")
        except ftplib.error_perm as e:
            return str(e)
        return "accepted"

    assert (await _in_thread(run)).startswith("500 XYZZY not understood")


async def test_an_uploaded_file_appears_in_the_sessions_next_listing(ftp_port):
    import io

    def run() -> tuple[list[str], int | None, bytes]:
        ftp = _session(ftp_port)
        ftp.cwd("incoming")
        ftp.storbinary("STOR shell.php", io.BytesIO(b"<?php system($_GET['c']); ?>"))
        names = ftp.nlst()
        size = ftp.size("shell.php")
        got: list[bytes] = []
        ftp.retrbinary("RETR shell.php", got.append)
        return names, size, b"".join(got)

    names, size, data = await _in_thread(run)
    assert names == ["shell.php"] and size == len(data) == 28


async def test_downloads_are_recorded_with_a_hash_of_what_was_served(ftp_port):
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert

    def run() -> bytes:
        ftp = _session(ftp_port)
        chunks: list[bytes] = []
        ftp.retrbinary("RETR passwords.txt", chunks.append)
        return b"".join(chunks)

    data = await _in_thread(run)
    event = None
    for _ in range(40):
        await asyncio.sleep(0.1)
        async with get_session() as session:
            rows = (
                (
                    await session.execute(
                        select(Alert).where(Alert.event_type == "ftp_file_download")
                    )
                )
                .scalars()
                .all()
            )
        if rows:
            event = rows[0]
            break
    assert event is not None
    assert event.payload["sha256"] == hashlib.sha256(data).hexdigest()
    assert event.payload["size_bytes"] == len(data)
    assert event.payload["path"] == "/passwords.txt"


# ── Bait: passwords.txt carries a tracked credential ─────────────────────────


async def _plant(service: str, user: str, password: str) -> None:
    from honeypot_mcp import credential_match
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        session.add(
            Honeytoken(
                type=HoneytokenType.CREDENTIAL,
                label=f"bait-{service}",
                token_value=f"cred:bait-{service}",
                status=HoneytokenStatus.ACTIVE,
                token_meta={
                    "service": service,
                    "credentials": [{"username": user, "password": password}],
                },
            )
        )
    credential_match.invalidate_cache()
    await credential_match.planted_credential(
        service
    )  # warm the index, as any connection event does


def test_the_bait_is_part_of_the_file_so_list_size_and_bytes_still_agree():
    from honeypot_mcp.engines.ftp_fs import FakeFS

    pair = {"value": ("svc-portal", "Zx9!kLm2#qq")}
    fs = FakeFS("seed", planted=lambda: pair["value"])
    plain = FakeFS("seed")

    listed = next(n for n in fs.listdir("/") if n.name == "passwords.txt")
    fetched = fs.lookup("/passwords.txt")
    assert listed.content == fetched.content and listed.size == fetched.size == len(fetched.content)
    assert fetched.content.startswith(plain.lookup("/passwords.txt").content), "decoy lines stay"
    assert fetched.content.endswith(b"svc-portal:Zx9!kLm2#qq\n")
    assert fs.bait_active() and not plain.bait_active()
    pair["value"] = None  # the token was revoked
    assert fs.lookup("/passwords.txt").content == plain.lookup("/passwords.txt").content
    assert not fs.bait_active()


async def test_a_scanner_that_takes_the_file_and_replays_the_credential_trips_it(ftp_port):
    """The point of the bait, end to end with a real client: read passwords.txt over FTP, log in with
    the pair found in it, and get a CRITICAL naming the token. The download is marked `bait_served`."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    await _plant("ftp", "svc-portal", "Zx9!kLm2#qq")

    def run() -> str:
        ftp = _session(ftp_port)
        chunks: list[bytes] = []
        ftp.retrbinary("RETR passwords.txt", chunks.append)
        ftp.quit()
        text = b"".join(chunks).decode()
        user, _, password = text.strip().splitlines()[-1].partition(":")
        again = ftplib.FTP()
        again.connect("127.0.0.1", ftp_port, timeout=5)
        with contextlib.suppress(ftplib.error_perm):
            again.login(user, password)
        again.close()
        return text

    text = await _in_thread(run)
    assert "svc-portal:Zx9!kLm2#qq" in text
    await asyncio.sleep(1.2)
    async with get_session() as session:
        alerts = (await session.execute(select(Alert))).scalars().all()
    download = [a for a in alerts if a.event_type == "ftp_file_download"]
    assert download and download[0].payload.get("bait_served") is True
    tripped = [
        a
        for a in alerts
        if a.severity == AlertSeverity.CRITICAL
        and a.event_type.startswith("honeytoken_triggered_credential_via_ftp")
    ]
    assert tripped, [a.event_type for a in alerts]


# ── Passive data ports: the range the firewall can open ──────────────────────


def _free_range(size: int) -> tuple[int, int]:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        low = s.getsockname()[1]
    return low, low + size - 1


async def test_passive_listeners_open_only_inside_the_configured_range(ftp_port, monkeypatch):
    """Behind a default-drop firewall only an opened range is reachable. An ephemeral port is not, so
    every FTP session over the internet stalled after login (the live run recorded 9 anonymous logins
    and not one listing, download or upload)."""
    from honeypot_mcp.config import get_settings

    low, high = _free_range(5)
    monkeypatch.setattr(get_settings(), "ftp_pasv_port_min", low)
    monkeypatch.setattr(get_settings(), "ftp_pasv_port_max", high)

    def run() -> list[int]:
        ports = []
        for _ in range(6):
            ftp = _session(ftp_port)
            _host, port = ftp.makepasv()
            ports.append(port)
            ftp.quit()
        return ports

    ports = await _in_thread(run)
    assert all(low <= p <= high for p in ports), (ports, low, high)


async def test_an_exhausted_range_is_refused_cleanly_not_by_a_hang(ftp_port, monkeypatch):
    import ftplib

    from honeypot_mcp.config import get_settings

    low, high = _free_range(1)
    monkeypatch.setattr(get_settings(), "ftp_pasv_port_min", low)
    monkeypatch.setattr(get_settings(), "ftp_pasv_port_max", high)

    def run() -> str:
        first = _session(ftp_port)
        first.makepasv()  # holds the only port
        second = _session(ftp_port)
        try:
            second.makepasv()
        except ftplib.Error as exc:
            return str(exc)
        return "no error"

    assert (await _in_thread(run)).startswith("425")
