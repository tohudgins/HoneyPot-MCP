"""The FTP honeypot's tree: LIST, SIZE, MDTM and RETR must agree with each other.

Driven by the standard library's real `ftplib` client in a worker thread. The old
engine printed one fixed listing and answered every RETR with 550, although FEAT
advertised SIZE/MDTM/REST/EPSV that were never implemented — so a scanner that
followed LIST with SIZE on a name it had just been shown got a refusal.
"""

import asyncio
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
