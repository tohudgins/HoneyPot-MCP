"""SMB2 for the SMB honeypot: negotiate, then play the server side of NTLM session setup.

Every current client starts with SMB2 (`smbclient`, impacket, NetExec, Metasploit's
`smb_login`, Windows itself). Before this module the engine answered SMB1 only and closed on
SMB2, so none of them could get as far as a login and the credential spray the share exists to
catch was invisible. What is served now is exactly enough to take a login:

1. NEGOTIATE: dialect 2.1 (the Windows 7 / Server 2008 R2 persona the SMB1 answer already
   claims) or 2.0.2, with a SPNEGO blob offering NTLM.
2. SESSION_SETUP with an NTLM NEGOTIATE: `STATUS_MORE_PROCESSING_REQUIRED` and an NTLM
   CHALLENGE (the same `build_challenge` the RDP honeypot uses, so a host's two services
   disclose one identity).
3. SESSION_SETUP with an NTLM AUTHENTICATE: the response is captured (username, domain,
   workstation, NetNTLMv2 and the hashcat line that cracks it offline), then refused with
   `STATUS_LOGON_FAILURE`.

There is no tree connect and no file I/O, so a login is never granted. The capture is the
point: what a share receives from the internet is credentials, not file requests.

Wire reference: MS-SMB2 §2.2 (message syntax); MS-NLMP for the NTLM messages.
"""

from __future__ import annotations

import os
import struct
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from honeypot_mcp.engines.rdp_nla import (
    AuthMessage,
    HostIdentity,
    build_challenge,
    negotiate_token_init,
    parse_authenticate,
    parse_negotiate,
    unwrap_ntlm,
    wrap_challenge,
)

SMB2_MAGIC = b"\xfeSMB"

CMD_NEGOTIATE = 0x0000
CMD_SESSION_SETUP = 0x0001
CMD_ECHO = 0x000D

STATUS_SUCCESS = 0x00000000
STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_LOGON_FAILURE = 0xC000006D

# Dialect revisions, best first. 0x02FF is the wildcard a server answers an SMB1 multi-protocol
# negotiate with, telling the client to start again in SMB2.
DIALECT_2_1 = 0x0210
DIALECT_2_0_2 = 0x0202
DIALECT_WILDCARD = 0x02FF
_SERVED = (DIALECT_2_1, DIALECT_2_0_2)

_HEADER = struct.Struct("<4sHHIHHIIQIIQ16s")  # 64 bytes
_SECURITY_BUFFER_OFFSET = 128  # header (64) + fixed negotiate-response body (64)

# A real exchange is three messages in a row (negotiate, two session setups), repeated per
# attempt; this bounds a client that keeps going.
MAX_MESSAGES = 24
MAX_ATTEMPTS = 6
_READ_TIMEOUT = 8.0

_BOOT = time.time() - 5 * 86400


def _filetime(unix_seconds: float) -> int:
    return int((unix_seconds + 11644473600) * 10_000_000)


@dataclass(frozen=True)
class Header:
    command: int
    message_id: int
    credits: int
    session_id: int
    tree_id: int


def parse_header(msg: bytes) -> Header | None:
    if len(msg) < 64 or msg[:4] != SMB2_MAGIC:
        return None
    (
        _magic,
        _size,
        _charge,
        _status,
        command,
        credits,
        _flags,
        _next,
        message_id,
        _rsv,
        tree_id,
        session_id,
        _sig,
    ) = _HEADER.unpack_from(msg, 0)
    return Header(command, message_id, credits, session_id, tree_id)


def _header(
    command: int,
    status: int,
    request: Header | None,
    *,
    session_id: int | None = None,
) -> bytes:
    message_id = request.message_id if request else 0
    asked = request.credits if request else 1
    return _HEADER.pack(
        SMB2_MAGIC,
        64,
        0,
        status,
        command,
        max(1, min(asked, 32)),
        0x00000001,  # SMB2_FLAGS_SERVER_TO_REDIR
        0,
        message_id,
        0,
        request.tree_id if request else 0,
        (request.session_id if session_id is None and request else session_id) or 0,
        b"\x00" * 16,
    )


def client_dialects(msg: bytes) -> list[int]:
    """Dialect revisions an SMB2 NEGOTIATE offers (header 64 + body: size, count, ...)."""
    if len(msg) < 100:
        return []
    (count,) = struct.unpack_from("<H", msg, 66)
    count = min(count, 16)
    end = min(len(msg), 100 + 2 * count)
    return [struct.unpack_from("<H", msg, at)[0] for at in range(100, end - 1, 2)]


def pick_dialect(offered: list[int]) -> int | None:
    for dialect in _SERVED:
        if dialect in offered:
            return dialect
    return None


def negotiate_response(request: Header | None, dialect: int, guid: bytes) -> bytes:
    """An SMB2 NEGOTIATE response. `request` is None when answering an SMB1 multi-protocol
    negotiate, which has no SMB2 header to echo."""
    blob = negotiate_token_init()
    big = dialect == DIALECT_2_1
    body = struct.pack(
        "<HHHH16sIIIIQQHHI",
        65,  # StructureSize
        0x0001,  # SecurityMode: signing enabled, not required
        dialect,
        0,
        guid,
        0x00000007 if big else 0x00000001,  # DFS (+ leasing, large MTU on 2.1)
        0x100000 if big else 0x10000,  # MaxTransactSize
        0x100000 if big else 0x10000,  # MaxReadSize
        0x100000 if big else 0x10000,  # MaxWriteSize
        _filetime(time.time()),
        _filetime(_BOOT),
        _SECURITY_BUFFER_OFFSET,
        len(blob),
        0,
    )
    return _header(CMD_NEGOTIATE, STATUS_SUCCESS, request) + body + blob


def session_setup_response(request: Header, status: int, session_id: int, token: bytes) -> bytes:
    body = struct.pack("<HHHH", 9, 0, 64 + 8, len(token)) + token
    return _header(CMD_SESSION_SETUP, status, request, session_id=session_id) + body


def error_response(request: Header, status: int) -> bytes:
    """An SMB2 ERROR response: StructureSize 9, no error contexts, one pad byte."""
    return _header(request.command, status, request) + struct.pack("<HBBIB", 9, 0, 0, 0, 0)


def echo_response(request: Header) -> bytes:
    return _header(CMD_ECHO, STATUS_SUCCESS, request) + struct.pack("<HH", 4, 0)


def _security_buffer(msg: bytes) -> bytes:
    """The SPNEGO/NTLM token of a SESSION_SETUP request (offset and length at body +12)."""
    if len(msg) < 88:
        return b""
    offset, length = struct.unpack_from("<HH", msg, 76)
    if offset < 64 or offset + length > len(msg):
        return b""
    return msg[offset : offset + length]


Send = Callable[[bytes], Awaitable[None]]
ReadFrame = Callable[[float], Awaitable[bytes | None]]
OnAuth = Callable[[AuthMessage, bytes, dict[str, Any]], Awaitable[None]]


async def serve_smb2(
    first: bytes | None,
    read_frame: ReadFrame,
    send: Send,
    ident: HostIdentity,
    guid: bytes,
    on_auth: OnAuth,
) -> int:
    """Serve SMB2 messages until the client stops. `first` is a frame already read, or None to
    read one. Returns the number of NTLM logins captured and refused."""
    attempts = 0
    server_challenge = b""
    session_id = 0
    negotiate: dict[str, Any] = {}
    message: bytes | None = first
    for _ in range(MAX_MESSAGES):
        if message is None:
            message = await read_frame(_READ_TIMEOUT)
            if message is None:
                break
        header = parse_header(message)
        if header is None:
            break

        if header.command == CMD_NEGOTIATE:
            dialect = pick_dialect(client_dialects(message))
            if dialect is None:
                await send(error_response(header, STATUS_NOT_SUPPORTED))
                break
            await send(negotiate_response(header, dialect, guid))
        elif header.command == CMD_SESSION_SETUP:
            ntlm, spnego = unwrap_ntlm(_security_buffer(message))
            offered = parse_negotiate(ntlm)
            auth = None if offered else parse_authenticate(ntlm)
            if offered is not None:
                negotiate = offered
                session_id = session_id or (struct.unpack("<Q", os.urandom(8))[0] | 1)
                server_challenge = os.urandom(8)
                challenge = build_challenge(ident, server_challenge)
                token = wrap_challenge(challenge) if spnego else challenge
                await send(
                    session_setup_response(
                        header, STATUS_MORE_PROCESSING_REQUIRED, session_id, token
                    )
                )
            elif auth is not None and server_challenge:
                attempts += 1
                await on_auth(auth, server_challenge, negotiate)
                server_challenge = b""
                await send(error_response(header, STATUS_LOGON_FAILURE))
                if attempts >= MAX_ATTEMPTS:
                    break
            else:
                await send(error_response(header, STATUS_LOGON_FAILURE))
                break
        elif header.command == CMD_ECHO:
            await send(echo_response(header))
        else:
            # Tree connect, logoff, anything else before a session exists.
            await send(error_response(header, STATUS_ACCESS_DENIED))
        message = None
    return attempts


def stable_guid(seed: str) -> bytes:
    """A ServerGuid that is the same on every connection to this honeypot."""
    return uuid.uuid5(uuid.NAMESPACE_URL, f"smb2/{seed}").bytes_le
