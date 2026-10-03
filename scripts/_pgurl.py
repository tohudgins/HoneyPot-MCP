#!/usr/bin/env python3
"""Split a libpq URL into a password-free URL (stdout) and a PGPASSFILE.

Passing the password inside the URL on a command line puts it in argv, which
`ps` shows to every local user. `pg_dump`/`psql` read it from PGPASSFILE
instead. Usage: _pgurl.py <database-url> <passfile-to-write>
"""

from __future__ import annotations

import os
import sys
from urllib.parse import unquote, urlsplit, urlunsplit


def _esc(value: str) -> str:
    return value.replace("\\", "\\\\").replace(":", "\\:")


def main() -> None:
    url = sys.argv[1].replace("+asyncpg", "", 1)
    passfile = sys.argv[2]
    u = urlsplit(url)
    user = unquote(u.username) if u.username else ""
    host = u.hostname or ""
    if ":" in host:  # IPv6 literal: urlsplit strips the brackets, put them back
        host = f"[{host}]"
    netloc = (f"{u.username}@" if u.username else "") + host
    if u.port:
        netloc += f":{u.port}"
    clean = urlunsplit((u.scheme, netloc, u.path, u.query, ""))
    line = ":".join(
        [
            _esc(u.hostname or "*"),
            str(u.port or "*"),
            _esc(u.path.lstrip("/") or "*"),
            _esc(user or "*"),
            _esc(unquote(u.password) if u.password else ""),
        ]
    )
    fd = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(line + "\n")
    print(clean)


if __name__ == "__main__":
    main()
