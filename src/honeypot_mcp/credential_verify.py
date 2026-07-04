"""Hashed-credential verification for the MySQL and VNC engines.

MySQL and VNC never send the plaintext password on the wire — MySQL sends a
SHA1-based scramble keyed by a server-chosen salt, VNC sends the server's
challenge DES-encrypted under the password. The plaintext-pair matcher in
`credential_match.py` therefore can't see them.

But in both cases *we* generated the salt / challenge, so given a candidate
plaintext (a planted honeytoken password) we can recompute what the response
*would* have been and compare. That lets a planted MySQL/VNC credential still
fire the CRITICAL-escalation pipeline, closing the gap noted in
KNOWN_LIMITATIONS.md.

These are constant-time-ish equality checks over 16–20 byte digests; the cost
is one SHA1 pair (MySQL) or one DES block-pair (VNC) per candidate, only
evaluated when a `mysql_*` / `vnc_*` login event carries a usable response.
"""

from __future__ import annotations

import hashlib
import hmac
import logging

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes

log = logging.getLogger(__name__)


def mysql_native_token(password: bytes, salt: bytes) -> bytes:
    """Compute the `mysql_native_password` client token for a candidate:

        SHA1(pw) XOR SHA1( salt || SHA1(SHA1(pw)) )

    `salt` is the full 20-byte scramble the server advertised in its Initial
    Handshake (auth-plugin-data parts 1 + 2). Returns the 20-byte token.
    """
    h1 = hashlib.sha1(password).digest()
    h2 = hashlib.sha1(h1).digest()
    inner = hashlib.sha1(salt + h2).digest()
    return bytes(a ^ b for a, b in zip(h1, inner, strict=True))


def verify_mysql(salt: bytes, auth_response: bytes, candidate_password: str) -> bool:
    """True if `candidate_password` reproduces the captured MySQL scramble.

    An empty `auth_response` (client sent an anonymous / no-password login)
    never matches a non-empty planted password.
    """
    if len(salt) != 20 or len(auth_response) != 20:
        return False
    expected = mysql_native_token(candidate_password.encode("utf-8", "surrogatepass"), salt)
    return hmac.compare_digest(expected, auth_response)


def _reverse_bits(byte: int) -> int:
    """VNC mangles each DES key byte by reversing its bit order (a quirk of the
    original RFB implementation using a bit-reversed DES key schedule)."""
    return int(f"{byte:08b}"[::-1], 2)


def vnc_expected_response(password: bytes, challenge: bytes) -> bytes:
    """DES-ECB encrypt the 16-byte `challenge` under the VNC-mangled password
    key. The password is truncated/zero-padded to 8 bytes and each byte is
    bit-reversed; the two 8-byte challenge halves are encrypted independently
    (ECB). Returns the 16-byte response the client should have sent."""
    key8 = bytes(_reverse_bits(b) for b in (password[:8] + b"\x00" * 8)[:8])
    # Single DES via TripleDES with K1=K2=K3 (a 24-byte key of the 8-byte key
    # repeated) — avoids the deprecated single-key-TripleDES path.
    cipher = Cipher(TripleDES(key8 * 3), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(challenge) + enc.finalize()


def verify_vnc(challenge: bytes, response: bytes, candidate_password: str) -> bool:
    """True if `candidate_password` reproduces the captured VNC auth response.

    VNC keys are effectively limited to 8 bytes; a longer planted password is
    truncated the same way a real client would truncate it, so it still
    verifies against what the attacker actually typed.
    """
    if len(challenge) != 16 or len(response) != 16:
        return False
    expected = vnc_expected_response(candidate_password.encode("utf-8", "surrogatepass"), challenge)
    return hmac.compare_digest(expected, response)
