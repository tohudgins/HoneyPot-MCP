"""FTP honeypot engine — ProFTPD-flavoured asyncio FTP server.

Fidelity notes
--------------
Real FTP servers handle a richer command set than just USER / PASS / QUIT.
Scanner-grade honeypots also need:

* Anonymous-login flow (`USER anonymous` → `331` → any `PASS` → `230`). Many
  scanners test for anonymous read access before they brute-force, so failing
  it correctly is itself a signal source.
* Realistic `FEAT` list (PASV, EPSV, SIZE, MDTM, REST STREAM, LANG en-US, UTF8).
* `PASV` / `PORT` responses — even without a real data connection, real
  attackers parse the `227 Entering Passive Mode (h,h,h,h,p1,p2)` tuple. We
  return a closed local port so subsequent data-connection attempts fail
  cleanly, which still records the attempt.
* Basic post-login verbs (`PWD`, `CWD`, `TYPE`, `NOOP`, `SYST`) so anonymous
  sessions don't immediately die at the first `LIST`.

* `LIST`/`NLST` over PASV serve a real directory listing over a real data
  socket, and `STOR`/`APPE` **accept the upload** over the data channel and
  capture the bytes — a dropped webshell or malware stager is the artefact
  worth keeping. Uploads are classified (`_classify_upload`), SHA-256'd, and
  bounded to `_MAX_UPLOAD_BYTES`; `RETR`/`DELE` stay logged-and-refused.

It is still low-fidelity FTP — no persistent file system — but it now captures
the two things that matter most (credentials and uploaded payloads) and is
significantly harder to fingerprint than the previous `502` skeleton.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)

# Cap captured uploads so a large STOR can't exhaust honeypot memory. 1 MB is
# plenty to fingerprint a dropped webshell or malware stager.
_MAX_UPLOAD_BYTES = 1_048_576


def _classify_upload(filename: str, data: bytes) -> str | None:
    """Recognise the artefact an attacker STORs. Returns a short label or None.
    This is the high-value intel — what they tried to drop on the box."""
    name = filename.lower()
    head = data[:2048]
    lowered = head.lower()
    if name.endswith((".php", ".phtml", ".php5")) or b"<?php" in head or b"<?=" in head:
        return "php_webshell"
    if name.endswith((".jsp", ".jspx")) or b"<%" in head and b"runtime" in lowered:
        return "jsp_webshell"
    if name.endswith((".asp", ".aspx")):
        return "asp_webshell"
    if head[:2] == b"MZ":
        return "windows_executable"
    if head[:4] == b"\x7fELF":
        return "linux_executable"
    if head[:2] == b"#!" and (b"/bin/sh" in head or b"/bin/bash" in head or b"python" in lowered):
        return "shell_script"
    if b"/dev/tcp/" in head or b"bash -i" in head or b"nc -e" in head:
        return "reverse_shell"
    return None


# ProFTPD-style FEAT listing.
_FEAT_RESPONSE = (
    b"211-Features:\r\n"
    b" PASV\r\n"
    b" EPSV\r\n"
    b" SIZE\r\n"
    b" MDTM\r\n"
    b" REST STREAM\r\n"
    b" LANG en-US\r\n"
    b" UTF8\r\n"
    b"211 End\r\n"
)

# Anonymous login usernames that real FTP servers accept under the anonymous
# pseudo-account.
_ANONYMOUS_USERS = {"anonymous", "ftp"}

# ProFTPD-flavoured `ls -l` output served when an authenticated session
# issues LIST or NLST. Previously the engine returned `425 Use PORT or PASV
# first.` regardless of state — a single LIST attempt confirmed the server
# never served data and is therefore a honeypot. Returning a believable
# listing keeps scanners engaged (they often follow LIST with RETR / SIZE /
# MDTM on the named files) which gives us deeper TTP data.
_FAKE_LISTING = (
    b"total 142\r\n"
    b"drwxr-xr-x   2 ftp      ftp           512 Mar 15 14:23 pub\r\n"
    b"drwxr-xr-x   2 ftp      ftp           512 Feb 02 09:14 incoming\r\n"
    b"-rw-r--r--   1 ftp      ftp        102400 Feb 28 09:11 backup.tar.gz\r\n"
    b"-rw-r--r--   1 ftp      ftp          4096 Feb 28 09:11 passwords.txt\r\n"
    b"-rw-r--r--   1 ftp      ftp           256 Jan 12 16:45 README.txt\r\n"
    b"-rw-r--r--   1 ftp      ftp         32768 Dec 04 11:02 db_dump.sql.gz\r\n"
)


class _FTPProtocol(asyncio.Protocol):
    """ProFTPD-flavoured FTP control-channel handler."""

    def __init__(self, honeypot_name: str, honeypot_id: int | None, banner: str) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._banner = banner
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._pending_user: str | None = None
        self._authed: bool = False
        self._anonymous: bool = False
        self._cwd: str = "/"
        self._buf = b""
        # PASV state. `_pasv_server` is the listening socket created in
        # response to a PASV command; `_pasv_data_queue` receives the
        # (reader, writer) pair when the client connects to it. One-shot
        # per PASV — real FTP requires a fresh PASV before each data
        # transfer.
        self._pasv_server: asyncio.AbstractServer | None = None
        self._pasv_data_queue: (
            asyncio.Queue[tuple[asyncio.StreamReader, asyncio.StreamWriter]] | None
        ) = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        transport.write(f"220 {self._banner}\r\n".encode())
        asyncio.create_task(self._record("ftp_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while b"\r\n" in self._buf:
            line, self._buf = self._buf.split(b"\r\n", 1)
            cmd = line.decode("utf-8", errors="replace").strip()
            if cmd:
                self._handle_command(cmd)

    def _handle_command(self, cmd: str) -> None:
        parts = cmd.split(" ", 1)
        verb = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        t = self._transport
        if t is None:
            return

        if verb == "USER":
            self._pending_user = arg
            if arg.lower() in _ANONYMOUS_USERS:
                t.write(b"331 Anonymous login ok, send your email as password\r\n")
            else:
                t.write(b"331 Password required for " + arg.encode() + b"\r\n")

        elif verb == "PASS":
            self._handle_pass(arg)

        elif verb == "QUIT":
            t.write(b"221 Goodbye.\r\n")
            t.close()

        elif verb == "SYST":
            t.write(b"215 UNIX Type: L8\r\n")

        elif verb == "FEAT":
            t.write(_FEAT_RESPONSE)

        elif verb == "NOOP":
            t.write(b"200 NOOP command successful\r\n")

        elif verb == "TYPE":
            # Most clients send TYPE I (binary). Accept any single-letter type.
            if arg and arg[0].upper() in ("I", "A", "L", "E"):
                t.write(f"200 Type set to {arg.upper()}.\r\n".encode())
            else:
                t.write(b"501 Unrecognised TYPE.\r\n")

        elif verb == "PWD" or verb == "XPWD":
            self._require_auth_or(t)
            if self._authed:
                t.write(f'257 "{self._cwd}" is the current directory.\r\n'.encode())

        elif verb == "CWD":
            self._require_auth_or(t)
            if self._authed:
                target = arg if arg.startswith("/") else f"{self._cwd.rstrip('/')}/{arg}"
                # Pretend the directory exists for shallow paths; deny anything
                # that looks like a brute-force traversal beyond a few levels.
                if target.count("/") > 8:
                    t.write(b"550 Failed to change directory.\r\n")
                else:
                    self._cwd = target.rstrip("/") or "/"
                    t.write(b"250 Directory successfully changed.\r\n")

        elif verb == "LIST" or verb == "NLST":
            self._require_auth_or(t)
            if self._authed:
                # Real data transfer over the previously-advertised PASV
                # listener. Falling back to 425 only if no PASV has been
                # issued — same wording as real ProFTPD.
                if self._pasv_data_queue is None:
                    t.write(b"425 Use PORT or PASV first.\r\n")
                else:
                    asyncio.create_task(self._serve_listing(verb))

        elif verb == "PASV":
            self._require_auth_or(t)
            if self._authed:
                asyncio.create_task(self._setup_pasv())

        elif verb == "PORT":
            self._require_auth_or(t)
            if self._authed:
                t.write(b"200 PORT command successful.\r\n")
                asyncio.create_task(
                    self._record("ftp_port_command", AlertSeverity.MEDIUM, {"argument": arg})
                )

        elif verb == "STOR" or verb == "APPE":
            self._require_auth_or(t)
            if self._authed:
                # Accept the upload over the data channel and capture the bytes.
                # A malware sample or webshell an attacker tries to STOR is
                # exactly the artefact worth keeping — so we take delivery
                # rather than rejecting with 550 (which learns us nothing).
                if self._pasv_data_queue is None:
                    t.write(b"425 Use PORT or PASV first.\r\n")
                else:
                    asyncio.create_task(self._receive_upload(verb, arg))

        elif verb == "RETR" or verb == "DELE":
            self._require_auth_or(t)
            if self._authed:
                # We don't serve real files or delete anything; log the intent.
                t.write(b"550 Permission denied.\r\n")
                asyncio.create_task(
                    self._record(
                        "ftp_file_op_blocked",
                        AlertSeverity.HIGH,
                        {"verb": verb, "argument": arg},
                    )
                )

        else:
            t.write(b"502 Command not implemented.\r\n")
            asyncio.create_task(self._record("ftp_command", AlertSeverity.LOW, {"command": cmd}))

    def _handle_pass(self, password: str) -> None:
        t = self._transport
        if t is None:
            return
        user = self._pending_user or ""
        self._pending_user = None

        if user.lower() in _ANONYMOUS_USERS:
            # Anonymous accepts any password (conventionally an email).
            self._authed = True
            self._anonymous = True
            t.write(b"230 Anonymous access granted, restrictions apply.\r\n")
            asyncio.create_task(
                self._record(
                    "ftp_anonymous_login",
                    AlertSeverity.MEDIUM,
                    {"username": user, "password": password},
                )
            )
            return

        # Authenticated login attempt — record the credential pair and reject.
        asyncio.create_task(
            self._record(
                "ftp_login_attempt",
                AlertSeverity.HIGH,
                {"username": user, "password": password},
            )
        )
        t.write(b"530 Login incorrect.\r\n")

    async def _setup_pasv(self) -> None:
        """Open a real listening socket for the upcoming data transfer.

        Each PASV is one-shot: any prior PASV server is torn down first so
        a scanner that issues PASV → LIST → PASV → LIST sees independent
        ports. The 227 reply is sent only after `start_server` returns, so
        the client never races us to the listener.
        """
        t = self._transport
        if t is None:
            return

        # Tear down any prior PASV state.
        await self._teardown_pasv()

        queue: asyncio.Queue[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = asyncio.Queue(
            maxsize=1
        )
        self._pasv_data_queue = queue

        async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                queue.put_nowait((reader, writer))
            except asyncio.QueueFull:
                # Already have an inbound connection for this PASV — close
                # the duplicate so we don't leak sockets.
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        try:
            self._pasv_server = await asyncio.start_server(_accept, "0.0.0.0", 0)
        except OSError as e:
            log.warning("PASV listener could not bind: %s", e)
            t.write(b"425 Cannot open passive data connection.\r\n")
            self._pasv_data_queue = None
            return

        sock_port: int = self._pasv_server.sockets[0].getsockname()[1]
        p1, p2 = divmod(sock_port, 256)
        t.write(f"227 Entering Passive Mode (127,0,0,1,{p1},{p2}).\r\n".encode())
        await self._record("ftp_passive_attempt", AlertSeverity.MEDIUM, {"port": sock_port})

    async def _serve_listing(self, verb: str) -> None:
        """Accept the client's data connection, write a fake directory listing,
        close the data channel, then send 226 on the control channel."""
        t = self._transport
        if t is None or self._pasv_data_queue is None:
            return

        t.write(b"150 Opening ASCII mode data connection for file list\r\n")
        try:
            reader, writer = await asyncio.wait_for(self._pasv_data_queue.get(), timeout=10.0)
        except TimeoutError:
            t.write(b"425 No data connection received.\r\n")
            await self._teardown_pasv()
            return

        try:
            writer.write(_FAKE_LISTING)
            await writer.drain()
        except Exception as e:
            log.debug("LIST data write failed: %s", e)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        t.write(b"226 Transfer complete.\r\n")
        await self._record(
            "ftp_list_served",
            AlertSeverity.MEDIUM,
            {
                "verb": verb,
                "bytes_sent": len(_FAKE_LISTING),
                "entry_count": _FAKE_LISTING.count(b"\r\n"),
            },
        )
        await self._teardown_pasv()

    async def _receive_upload(self, verb: str, filename: str) -> None:
        """Accept the client's data connection for a STOR/APPE and capture the
        uploaded bytes — a malware sample or webshell drop is the artefact worth
        keeping. Bounded so a huge upload can't exhaust honeypot memory."""
        t = self._transport
        if t is None or self._pasv_data_queue is None:
            return

        t.write(b"150 Ok to send data.\r\n")
        try:
            reader, writer = await asyncio.wait_for(self._pasv_data_queue.get(), timeout=10.0)
        except TimeoutError:
            t.write(b"425 No data connection received.\r\n")
            await self._teardown_pasv()
            return

        chunks: list[bytes] = []
        total = 0
        try:
            while total < _MAX_UPLOAD_BYTES:
                chunk = await asyncio.wait_for(reader.read(_MAX_UPLOAD_BYTES - total), timeout=10.0)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        except Exception as e:
            # Timeout or client reset ends the transfer — keep what we got.
            log.debug("STOR data read ended: %s", e)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

        data = b"".join(chunks)
        t.write(b"226 Transfer complete.\r\n")

        kind = _classify_upload(filename, data)
        severity = AlertSeverity.CRITICAL if kind else AlertSeverity.HIGH
        await self._record(
            "ftp_file_upload",
            severity,
            {
                "verb": verb,
                "filename": filename,
                "size_bytes": total,
                "sha256": hashlib.sha256(data).hexdigest(),
                "payload_kind": kind,
                # A short printable preview so an analyst sees what it is without
                # needing to pull the raw sample.
                "preview": data[:512].decode("utf-8", errors="replace"),
            },
        )
        await self._teardown_pasv()

    async def _teardown_pasv(self) -> None:
        """Close any active PASV listener — safe to call multiple times."""
        server = self._pasv_server
        self._pasv_server = None
        self._pasv_data_queue = None
        if server is None:
            return
        server.close()
        with contextlib.suppress(Exception):
            await server.wait_closed()

    def _require_auth_or(self, t: asyncio.Transport) -> None:
        """Emit `530 Please login with USER and PASS` for unauthenticated calls.
        Callers branch on `self._authed` after this."""
        if not self._authed:
            t.write(b"530 Please login with USER and PASS.\r\n")

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        src_ip, src_port = self._peer
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=src_ip,
                source_port=src_port,
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        # Reap any orphan PASV listener so port-leaks don't accumulate over
        # the lifetime of the honeypot under sustained scanning.
        if self._pasv_server is not None:
            asyncio.create_task(self._teardown_pasv())


class FTPEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        banner = config.get("fake_banner", "ProFTPD 1.3.5 Server (Debian) ready")

        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _FTPProtocol(name, hp_id, banner),
            host="0.0.0.0",
            port=port,
        )
        cid = f"ftp-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("FTP honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_ftp"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["FTP honeypot is in-process — events are stored directly in the database."]
