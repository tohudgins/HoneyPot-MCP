"""Filesystem helpers for files that hold private key material.

Writing a key with `write_bytes()` and `chmod(0o600)` afterwards leaves a window
in which the file exists with the process umask's permissions (typically 0644)
— any local account can read it in that window. These helpers create the file
with its final mode from the first instant, and publish it by atomic rename so
a concurrent reader never sees a half-written key.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from pathlib import Path


def ensure_private_dir(path: Path) -> None:
    """Create `path` (and missing parents) with the leaf restricted to its owner.

    An already-existing directory is left as it is — tightening a directory the
    operator chose and set up would be surprising.
    """
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def write_private_file(path: Path, data: bytes | str) -> None:
    """Write `data` to `path` as an owner-only (0600) file, atomically.

    The bytes go to a sibling temp file created with `O_EXCL` and mode 0600,
    then `os.replace` moves it into place. The mode is therefore correct from
    creation — there is no readable-by-others interval to race.
    """
    payload = data.encode("utf-8") if isinstance(data, str) else data
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
