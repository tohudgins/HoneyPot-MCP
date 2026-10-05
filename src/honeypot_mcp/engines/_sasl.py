"""SASL payload decoding shared by the mail engines (RFC 4616 PLAIN, the LOGIN mechanism).

Both decode what a client sends into a (username, password) pair so every path, whether
`USER`/`PASS`, `LOGIN`, `AUTHENTICATE PLAIN` or `AUTH LOGIN`, ends in the same capture and
the same planted-credential check."""

from __future__ import annotations

import base64

# What a server sends to ask for each LOGIN field (base64 of "Username:" / "Password:").
LOGIN_USERNAME_PROMPT = base64.b64encode(b"Username:").decode()
LOGIN_PASSWORD_PROMPT = base64.b64encode(b"Password:").decode()

_MAX_B64 = 2048


def decode_text(blob: str) -> str:
    """One base64 field (AUTH LOGIN sends the username and the password separately)."""
    try:
        return base64.b64decode(blob.strip()[:_MAX_B64], validate=False).decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def decode_plain(blob: str) -> tuple[str, str]:
    """`authzid NUL username NUL password`, base64-encoded, per RFC 4616."""
    try:
        decoded = base64.b64decode(blob.strip()[:_MAX_B64], validate=False)
    except Exception:
        return "", ""
    parts = decoded.split(b"\x00")
    if len(parts) >= 3:
        return (
            parts[1].decode("utf-8", errors="replace"),
            parts[2].decode("utf-8", errors="replace"),
        )
    if len(parts) == 2:
        return (
            parts[0].decode("utf-8", errors="replace"),
            parts[1].decode("utf-8", errors="replace"),
        )
    return "", ""
