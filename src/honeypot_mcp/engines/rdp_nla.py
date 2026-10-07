"""CredSSP (NLA) with an NTLM exchange for the RDP honeypot.

Windows clients and scanners ask for Network Level Authentication, which runs
CredSSP inside the TLS tunnel *before* any RDP traffic: the client sends an NTLM
NEGOTIATE, the server answers with a CHALLENGE, and the client sends an
AUTHENTICATE carrying a NetNTLMv2 response. The old engine selected plain TLS
regardless and then waited for an MCS PDU an NLA client never sends, so modern
clients got nothing and no NTLM material was ever captured.

This module plays the server side of that exchange for as long as it is useful:

* The CHALLENGE carries realistic target info (NetBIOS/DNS names, timestamp,
  Windows build), which is exactly what `nmap --script rdp-ntlm-info` reads and
  what a real Windows host discloses before authentication.
* The AUTHENTICATE is parsed for username, domain, workstation and the NetNTLMv2
  response, and rendered as a hashcat-ready line (`-m 5600`, or `-m 5500` for
  NTLMv1) so the capture is directly crackable and, via `verify_ntlmv2`, checkable
  against planted honeytoken passwords.
* Authentication then fails with STATUS_LOGON_FAILURE, as it would for a wrong
  password — unless the caller recognises the password (a planted honeytoken, or this
  honeypot's one weak pair). Then the exchange is completed for real: the NTLM session
  key is derived from the password, the server's public-key binding is sealed with it,
  and the client, satisfied, sends its credentials and starts an RDP session.

Everything here parses attacker bytes. Reads are length-capped, DER lengths are
checked against the buffer before use, and nothing loops without advancing.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

_MAX_TSREQUEST = 32 * 1024
_READ_TIMEOUT = 10.0

_NTLMSSP = b"NTLMSSP\x00"
_NTLM_NEGOTIATE, _NTLM_CHALLENGE, _NTLM_AUTHENTICATE = 1, 2, 3

# NEGOTIATE_UNICODE | REQUEST_TARGET | SIGN | SEAL | NTLM | ALWAYS_SIGN |
# TARGET_TYPE_SERVER | EXTENDED_SESSIONSECURITY | TARGET_INFO | VERSION | 128 |
# KEY_EXCH | 56 — the value Windows Server sends.
_CHALLENGE_FLAGS = 0xE28A8215

_STATUS_LOGON_FAILURE = 0xC000006D

# Windows builds a host can plausibly report (major, minor, build).
_BUILDS = ((10, 0, 14393), (10, 0, 17763), (10, 0, 20348))
_DOMAINS = (("CORP", "corp.local"), ("ACME", "acme.internal"), ("LAB", "lab.local"))


# ── Identity ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HostIdentity:
    computer: str  # NetBIOS computer name
    domain: str  # NetBIOS domain
    dns_domain: str
    version: tuple[int, int, int]

    @property
    def dns_computer(self) -> str:
        return f"{self.computer.lower()}.{self.dns_domain}"


def identity_for(seed: str, config: dict[str, Any] | None = None) -> HostIdentity:
    """A stable Windows identity for one honeypot (so repeated probes agree), with
    optional `rdp_hostname` / `rdp_domain` overrides from its config."""
    h = hashlib.sha256(f"rdp:{seed}".encode()).digest()
    cfg = config or {}
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    computer = "WIN-" + "".join(alphabet[b % len(alphabet)] for b in h[:11])
    nb_domain, dns_domain = _DOMAINS[h[12] % len(_DOMAINS)]
    override = str(cfg.get("rdp_hostname") or "").strip().upper()
    if override.isalnum() or (override.replace("-", "").isalnum() and override):
        computer = override[:15]
    domain_override = str(cfg.get("rdp_domain") or "").strip()
    if domain_override and domain_override.replace(".", "").replace("-", "").isalnum():
        dns_domain = domain_override.lower()
        nb_domain = dns_domain.split(".")[0].upper()[:15]
    return HostIdentity(computer, nb_domain, dns_domain, _BUILDS[h[13] % len(_BUILDS)])


# ── DER (just enough for a TSRequest) ───────────────────────────────────────


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    elif n < 0x100:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82, n >> 8, n & 0xFF])
    return head + content


def _der_int(value: int) -> bytes:
    """A DER INTEGER; NTSTATUS codes (high bit set) are carried as signed 32-bit,
    which is what CredSSP implementations read them as."""
    if value >= 0x80000000:
        return _der(0x02, struct.pack(">I", value))  # two's-complement 4 bytes
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    return _der(0x02, raw)


def _tlv(buf: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Read one TLV at `pos`: returns (tag, content_start, content_end). Raises
    ValueError on anything that does not fit inside `buf[:end]`."""
    if pos + 2 > end:
        raise ValueError("truncated header")
    tag = buf[pos]
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 3 or pos + n > end:
            raise ValueError("bad length form")
        length = int.from_bytes(buf[pos : pos + n], "big")
        pos += n
    if pos + length > end:
        raise ValueError("length exceeds buffer")
    return tag, pos, pos + length


def build_ts_request(
    version: int,
    nego_token: bytes | None = None,
    error_code: int | None = None,
    pub_key_auth: bytes | None = None,
) -> bytes:
    body = _der(0xA0, _der_int(version))
    if nego_token is not None:
        token = _der(0xA0, _der(0x04, nego_token))
        body += _der(0xA1, _der(0x30, _der(0x30, token)))
    if pub_key_auth is not None:
        body += _der(0xA3, _der(0x04, pub_key_auth))
    if error_code is not None:
        body += _der(0xA4, _der_int(error_code))
    return _der(0x30, body)


@dataclass
class TSRequest:
    version: int = 2
    nego_token: bytes | None = None
    has_pub_key_auth: bool = False
    has_auth_info: bool = False
    client_nonce: bytes | None = None


def parse_ts_request(data: bytes) -> TSRequest:
    """Parse a CredSSP TSRequest. Raises ValueError if it is not one."""
    tag, start, end = _tlv(data, 0, len(data))
    if tag != 0x30:
        raise ValueError("not a SEQUENCE")
    out = TSRequest()
    pos = start
    while pos < end:
        ftag, fstart, fend = _tlv(data, pos, end)
        if ftag == 0xA0:  # version
            itag, istart, iend = _tlv(data, fstart, fend)
            if itag == 0x02 and 0 < iend - istart <= 4:
                out.version = int.from_bytes(data[istart:iend], "big", signed=True)
        elif ftag == 0xA1 and out.nego_token is None:  # negoTokens
            stag, sstart, send = _tlv(data, fstart, fend)  # SEQUENCE OF
            if stag == 0x30 and sstart < send:
                itag, istart, iend = _tlv(data, sstart, send)  # first NegoDataItem
                if itag == 0x30 and istart < iend:
                    ttag, tstart, tend = _tlv(data, istart, iend)  # [0] negoToken
                    if ttag == 0xA0 and tstart < tend:
                        otag, ostart, oend = _tlv(data, tstart, tend)
                        if otag == 0x04:
                            out.nego_token = data[ostart:oend]
        elif ftag == 0xA2:
            out.has_auth_info = True
        elif ftag == 0xA3:
            out.has_pub_key_auth = True
        elif ftag == 0xA5:  # clientNonce (CredSSP v5+)
            ntag, nstart, nend = _tlv(data, fstart, fend)
            if ntag == 0x04 and nend - nstart <= 64:
                out.client_nonce = data[nstart:nend]
        pos = fend  # always advances: fend >= fstart > pos
    return out


# ── SPNEGO ──────────────────────────────────────────────────────────────────
#
# Windows' own client (and anything built on its "Negotiate" package) does not send a bare
# NTLM message inside CredSSP: it wraps it in a SPNEGO NegTokenInit, and expects the answer
# wrapped in a NegTokenResp. Scanners such as nmap send bare NTLM. Both are served; the
# reply is wrapped exactly when the request was.

_NTLM_OID = bytes.fromhex("2b06010401823702020a")


def unwrap_ntlm(token: bytes) -> tuple[bytes, bool]:
    """(the NTLM message inside `token`, whether `token` wrapped it in SPNEGO)."""
    at = token.find(_NTLMSSP)
    if at <= 0:
        return token, False
    return token[at:], True


def wrap_challenge(challenge: bytes) -> bytes:
    """A SPNEGO NegTokenResp carrying an NTLM CHALLENGE (negState accept-incomplete)."""
    state = _der(0xA0, _der(0x0A, b"\x01"))
    mech = _der(0xA1, _der(0x06, _NTLM_OID))
    response = _der(0xA2, _der(0x04, challenge))
    return _der(0xA1, _der(0x30, state + mech + response))


_SPNEGO_OID = bytes.fromhex("2b0601050502")


def negotiate_token_init() -> bytes:
    """The SPNEGO NegTokenInit a server puts in its SMB2 NEGOTIATE response: a mechanism list
    offering NTLM, which is what a workgroup or NTLM-only Windows host advertises."""
    mech_types = _der(0x30, _der(0x06, _NTLM_OID))
    init = _der(0x30, _der(0xA0, mech_types))
    return _der(0x60, _der(0x06, _SPNEGO_OID) + _der(0xA0, init))


# ── NTLM ────────────────────────────────────────────────────────────────────


def _field(buf: bytes, at: int) -> bytes:
    """A security-buffer field (len, maxlen, offset) at `at`, bounds-checked."""
    if at + 8 > len(buf):
        return b""
    length, _maxlen, offset = struct.unpack_from("<HHI", buf, at)
    if offset > len(buf) or offset + length > len(buf):
        return b""
    return buf[offset : offset + length]


def _u16(text: str) -> bytes:
    return text.encode("utf-16-le")


def _decode(raw: bytes) -> str:
    return raw.decode("utf-16-le", errors="replace")[:256]


def _filetime_now() -> bytes:
    return struct.pack("<Q", int((time.time() + 11644473600) * 10_000_000))


def _av(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def build_challenge(ident: HostIdentity, server_challenge: bytes) -> bytes:
    """NTLM CHALLENGE_MESSAGE with the target info a Windows server discloses."""
    target_name = _u16(ident.domain)
    info = (
        _av(2, _u16(ident.domain))  # MsvAvNbDomainName
        + _av(1, _u16(ident.computer))  # MsvAvNbComputerName
        + _av(4, _u16(ident.dns_domain))  # MsvAvDnsDomainName
        + _av(3, _u16(ident.dns_computer))  # MsvAvDnsComputerName
        + _av(5, _u16(ident.dns_domain))  # MsvAvDnsTreeName
        + _av(7, _filetime_now())  # MsvAvTimestamp
        + _av(0, b"")  # MsvAvEOL
    )
    base = 56  # fixed header incl. version
    major, minor, build = ident.version
    version = struct.pack("<BBH3sB", major, minor, build, b"\x00\x00\x00", 15)
    return (
        _NTLMSSP
        + struct.pack("<I", _NTLM_CHALLENGE)
        + struct.pack("<HHI", len(target_name), len(target_name), base)
        + struct.pack("<I", _CHALLENGE_FLAGS)
        + server_challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(info), len(info), base + len(target_name))
        + version
        + target_name
        + info
    )


def parse_negotiate(msg: bytes) -> dict[str, Any] | None:
    if len(msg) < 16 or msg[:8] != _NTLMSSP or struct.unpack_from("<I", msg, 8)[0] != 1:
        return None
    out: dict[str, Any] = {"ntlm_flags": struct.unpack_from("<I", msg, 12)[0]}
    domain = _field(msg, 16).decode("latin-1", errors="replace")[:128]
    workstation = _field(msg, 24).decode("latin-1", errors="replace")[:128]
    if domain:
        out["offered_domain"] = domain
    if workstation:
        out["offered_workstation"] = workstation
    return out


@dataclass
class AuthMessage:
    username: str
    domain: str
    workstation: str
    lm_response: bytes
    nt_response: bytes
    # Negotiated flags and the client's wrapped random session key (MS-NLMP 2.2.1.3).
    # Absent from very old clients, which is why they default.
    flags: int = 0
    encrypted_session_key: bytes = field(default=b"", repr=False)


def parse_authenticate(msg: bytes) -> AuthMessage | None:
    if len(msg) < 52 or msg[:8] != _NTLMSSP or struct.unpack_from("<I", msg, 8)[0] != 3:
        return None
    flags = struct.unpack_from("<I", msg, 60)[0] if len(msg) >= 64 else 0
    return AuthMessage(
        username=_decode(_field(msg, 36)),
        domain=_decode(_field(msg, 28)),
        workstation=_decode(_field(msg, 44)),
        lm_response=_field(msg, 12),
        nt_response=_field(msg, 20),
        flags=flags,
        encrypted_session_key=_field(msg, 52) if len(msg) >= 64 else b"",
    )


def hashcat_line(auth: AuthMessage, server_challenge: bytes) -> tuple[str, str] | None:
    """The crackable form of the capture: (hashcat_mode, line). None when the
    response is too short to be either NTLM version."""
    nt = auth.nt_response
    if len(nt) > 24:  # NTLMv2: 16-byte NTProofStr, then the client blob
        line = (
            f"{auth.username}::{auth.domain}:{server_challenge.hex()}:"
            f"{nt[:16].hex()}:{nt[16:].hex()}"
        )
        return "5600", line
    if len(nt) == 24:  # NTLMv1
        line = (
            f"{auth.username}::{auth.domain}:{auth.lm_response.hex()}:"
            f"{nt.hex()}:{server_challenge.hex()}"
        )
        return "5500", line
    return None


# ── Verifying a planted password against a captured NetNTLMv2 response ──────


def _md4(data: bytes) -> bytes:
    """MD4, in pure Python. `hashlib.new('md4')` is gone from OpenSSL 3 builds
    (legacy provider), and NTLM cannot be computed without it."""

    def lrot(x: int, n: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bit_len)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = struct.unpack_from("<16I", msg, off)
        aa, bb, cc, dd = a, b, c, d

        def f(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (~x_ & z)

        def g(x_: int, y: int, z: int) -> int:
            return (x_ & y) | (x_ & z) | (y & z)

        def h(x_: int, y: int, z: int) -> int:
            return x_ ^ y ^ z

        for i in range(16):
            k, s = i, (3, 7, 11, 19)[i % 4]
            a, b, c, d = d, lrot(a + f(b, c, d) + x[k], s), b, c
        for i in range(16):
            k = (i % 4) * 4 + i // 4
            s = (3, 5, 9, 13)[i % 4]
            a, b, c, d = d, lrot(a + g(b, c, d) + x[k] + 0x5A827999, s), b, c
        for i in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]
            s = (3, 9, 11, 15)[i % 4]
            a, b, c, d = d, lrot(a + h(b, c, d) + x[k] + 0x6ED9EBA1, s), b, c
        a, b, c, d = (
            (a + aa) & 0xFFFFFFFF,
            (b + bb) & 0xFFFFFFFF,
            (c + cc) & 0xFFFFFFFF,
            (d + dd) & 0xFFFFFFFF,
        )
    return struct.pack("<4I", a, b, c, d)


def verify_ntlmv2(
    server_challenge: bytes, nt_response: bytes, username: str, domain: str, password: str
) -> bool:
    """True if `password` produced this NetNTLMv2 response for this challenge."""
    if len(nt_response) <= 24:
        return False
    nt_hash = _md4(_u16(password))
    ntlmv2_key = hmac.new(nt_hash, _u16(username.upper() + domain), hashlib.md5).digest()
    expected = hmac.new(ntlmv2_key, server_challenge + nt_response[16:], hashlib.md5).digest()
    return hmac.compare_digest(expected, nt_response[:16])


# ── Sealing the server's reply (MS-NLMP 3.4, MS-CSSP 3.1.5) ──────────────────

_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
_NEGOTIATE_128 = 0x20000000
_NEGOTIATE_KEY_EXCH = 0x40000000
_NEGOTIATE_56 = 0x80000000


def _rc4(key: bytes):
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
    from cryptography.hazmat.primitives.ciphers import Cipher

    return Cipher(ARC4(key), mode=None).encryptor()


def server_to_client_keys(auth: AuthMessage, password: str) -> tuple[bytes, bytes]:
    """(signing key, sealing key) for the server-to-client direction, given the password
    that produced `auth`. The client never sends the session key, it sends it wrapped
    under a key only someone who knows the password can derive; so being able to seal a
    message the client accepts is itself proof that the password is right."""
    if not auth.flags & _NEGOTIATE_EXTENDED_SESSIONSECURITY:
        raise ValueError("client did not negotiate extended session security")
    nt_hash = _md4(_u16(password))
    ntlmv2_key = hmac.new(nt_hash, _u16(auth.username.upper() + auth.domain), hashlib.md5).digest()
    session_base_key = hmac.new(ntlmv2_key, auth.nt_response[:16], hashlib.md5).digest()
    if auth.flags & _NEGOTIATE_KEY_EXCH and len(auth.encrypted_session_key) == 16:
        exported = _rc4(session_base_key).update(auth.encrypted_session_key)
    else:
        exported = session_base_key
    if auth.flags & _NEGOTIATE_128:
        seal_material = exported
    elif auth.flags & _NEGOTIATE_56:
        seal_material = exported[:7]
    else:
        seal_material = exported[:5] + b"\xe5\x38\xb0"
    seal_key = hashlib.md5(
        seal_material + b"session key to server-to-client sealing key magic constant\x00"
    ).digest()
    sign_key = hashlib.md5(
        exported + b"session key to server-to-client signing key magic constant\x00"
    ).digest()
    return sign_key, seal_key


def seal(message: bytes, sign_key: bytes, seal_key: bytes, flags: int, seq: int = 0) -> bytes:
    """NTLMSSP EncryptMessage with extended session security: 16-byte signature, then the
    ciphertext. The checksum is encrypted with the same RC4 stream, after the message."""
    handle = _rc4(seal_key)
    ciphertext = handle.update(message)
    checksum = hmac.new(sign_key, struct.pack("<I", seq) + message, hashlib.md5).digest()[:8]
    if flags & _NEGOTIATE_KEY_EXCH:
        checksum = handle.update(checksum)
    return struct.pack("<I", 1) + checksum + struct.pack("<I", seq) + ciphertext


def server_public_key_reply(
    version: int, public_key: bytes, client_nonce: bytes | None, sign_key: bytes,
    seal_key: bytes, flags: int,
) -> bytes | None:  # fmt: skip
    """The server's proof that it holds the key the client authenticated against
    (CredSSP's defence against a man in the middle). v2-4 echo the key with its first byte
    incremented; v5 and later hash it with the client's nonce. None when a v5+ client
    sent no nonce."""
    if version >= 5:
        if not client_nonce:
            return None
        material = hashlib.sha256(
            b"CredSSP Server-To-Client Binding Hash\x00" + client_nonce + public_key
        ).digest()
    else:
        bumped = bytearray(public_key)
        bumped[0] = (bumped[0] + 1) & 0xFF
        material = bytes(bumped)
    return seal(material, sign_key, seal_key, flags)


# ── The exchange ────────────────────────────────────────────────────────────


async def _read_der_message(reader: asyncio.StreamReader) -> bytes:
    """Read exactly one DER-framed message from the TLS stream, length-capped."""
    head = await asyncio.wait_for(reader.readexactly(2), _READ_TIMEOUT)
    if head[0] != 0x30:
        raise ValueError("not a TSRequest")
    first = head[1]
    extra = b""
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0 or n > 3:
            raise ValueError("bad length form")
        extra = await asyncio.wait_for(reader.readexactly(n), _READ_TIMEOUT)
        length = int.from_bytes(extra, "big")
    if length > _MAX_TSREQUEST:
        raise ValueError("TSRequest too large")
    body = await asyncio.wait_for(reader.readexactly(length), _READ_TIMEOUT)
    return head + extra + body


# Decides whether a captured AUTHENTICATE is for a credential this honeypot lets in, and
# returns the plaintext password if so (needed to derive the session key), else None.
Authorizer = Callable[[dict[str, Any]], Awaitable[str | None]]


async def run_credssp(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ident: HostIdentity,
    *,
    authorize: Authorizer | None = None,
    public_key: bytes | None = None,
) -> dict[str, Any]:
    """Play the server side of CredSSP/NTLM. Returns what was captured:

    * ``stage``: "none" | "negotiate" | "authenticate"
    * ``negotiate``: parsed NEGOTIATE fields (once reached)
    * ``auth``: an AuthMessage plus ``server_challenge`` (once reached)
    * ``accepted``: True when `authorize` recognised the password and the exchange ran
      to completion; the stream is then ready for the RDP session
    """
    result: dict[str, Any] = {"stage": "none"}
    try:
        first = parse_ts_request(await _read_der_message(reader))
    except (ValueError, asyncio.IncompleteReadError, TimeoutError, OSError):
        return result
    ntlm_negotiate, spnego = unwrap_ntlm(first.nego_token or b"")
    negotiate = parse_negotiate(ntlm_negotiate)
    if negotiate is None:
        return result
    result["stage"] = "negotiate"
    result["negotiate"] = negotiate
    result["client_version"] = first.version

    version = max(2, min(first.version, 6))
    server_challenge = os.urandom(8)
    challenge_message = build_challenge(ident, server_challenge)
    writer.write(
        build_ts_request(
            version, wrap_challenge(challenge_message) if spnego else challenge_message
        )
    )
    try:
        await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
        second = parse_ts_request(await _read_der_message(reader))
    except (ValueError, asyncio.IncompleteReadError, TimeoutError, OSError):
        return result  # a scanner that only wanted the CHALLENGE (rdp-ntlm-info)
    auth = parse_authenticate(unwrap_ntlm(second.nego_token or b"")[0])
    if auth is None:
        return result
    result["stage"] = "authenticate"
    result["auth"] = auth
    result["server_challenge"] = server_challenge

    password = await authorize(result) if authorize is not None else None
    if password is not None and public_key is not None:
        try:
            sign_key, seal_key = server_to_client_keys(auth, password)
            reply = server_public_key_reply(
                version, public_key, second.client_nonce, sign_key, seal_key, auth.flags
            )
            if reply is not None:
                writer.write(build_ts_request(version, pub_key_auth=reply))
                await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
                # The client now sends its (sealed) credentials. We already know the
                # password, so the message is only consumed.
                await _read_der_message(reader)
                result["accepted"] = True
                return result
        except (ValueError, asyncio.IncompleteReadError, TimeoutError, OSError):
            return result

    # A wrong password: CredSSP v3+ clients are told so with an errorCode;
    # older ones just see the connection end.
    if version >= 3:
        try:
            writer.write(build_ts_request(version, error_code=_STATUS_LOGON_FAILURE))
            await asyncio.wait_for(writer.drain(), _READ_TIMEOUT)
        except (TimeoutError, OSError):
            pass
    return result
