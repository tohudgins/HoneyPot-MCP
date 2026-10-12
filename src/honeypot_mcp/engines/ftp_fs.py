"""A small, internally consistent file tree for the FTP honeypot.

The old engine printed one hard-coded `ls -l` block and answered every `RETR`
with `550`. Scanners that follow `LIST` with `SIZE`/`MDTM`/`RETR` on the names it
showed (and the FEAT reply advertises both) got a refusal for files that had just
been listed — a one-command tell, and no download means no second-stage behaviour
to observe.

Here the listing, `SIZE`, `MDTM` and `RETR` are all derived from the same nodes,
so the numbers an attacker sees agree with the bytes they receive: a size in the
listing is the length of the content served.

Content is deterministic per honeypot (seeded by name), so a scanner that reads a
file twice, or two scanners reading the same sensor, see the same bytes, and two
sensors do not share a fingerprint. Everything is decoy: no real credentials,
hosts or data.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import random
import tarfile
from collections.abc import Callable
from dataclasses import dataclass, field, replace

# Last-modified stamps are fixed strings in `ls -l` form so the output is stable.
_MTIMES = {
    "pub": ("Mar 15 14:23", "20240315142300"),
    "incoming": ("Feb 02 09:14", "20240202091400"),
    "backup.tar.gz": ("Feb 28 09:11", "20240228091100"),
    "passwords.txt": ("Feb 28 09:11", "20240228091100"),
    "README.txt": ("Jan 12 16:45", "20240112164500"),
    "db_dump.sql.gz": ("Dec 04 11:02", "20231204110200"),
    "welcome.msg": ("Mar 15 14:23", "20240315142300"),
}


@dataclass(frozen=True)
class Node:
    name: str
    is_dir: bool
    mtime_ls: str
    mtime_mdtm: str
    content: bytes = field(default=b"", repr=False)

    @property
    def size(self) -> int:
        return 512 if self.is_dir else len(self.content)

    def ls_line(self) -> bytes:
        mode = "drwxr-xr-x" if self.is_dir else "-rw-r--r--"
        links = 2 if self.is_dir else 1
        return (
            f"{mode} {links:>3} ftp      ftp      {self.size:>10} {self.mtime_ls} {self.name}\r\n"
        ).encode()


def _decoy_tar_gz(rng: random.Random) -> bytes:
    """A real gzip'd tar of plausible config files, so `tar xzf` works."""
    files = {
        "etc/hosts": b"127.0.0.1 localhost\n10.0.0.12 app01\n10.0.0.13 db01\n",
        "etc/app/settings.conf": (
            b"[database]\nhost = db01\nuser = app\npassword = changeme-%d\n"
            % rng.randint(1000, 9999)
        ),
        "var/backups/notes.txt": b"rotate keys after the migration\n" * 20,
        # Incompressible filler, so the archive is the size a real backup is
        # rather than a few hundred bytes that no operator would keep.
        "var/backups/app.db": rng.randbytes(96_000),
    }
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for path, data in files.items():
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mtime = 1709111460
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


def _decoy_sql_gz(rng: random.Random) -> bytes:
    rows = "\n".join(
        f"INSERT INTO users VALUES ({i}, 'user{i}', '{rng.getrandbits(128):032x}');"
        for i in range(1, 1400)
    )
    sql = f"-- MySQL dump 10.13\nCREATE TABLE users (id int, name varchar(32), pw char(32));\n{rows}\n"
    return gzip.compress(sql.encode(), mtime=0)


def _decoy_passwords(rng: random.Random) -> bytes:
    lines = ["# service accounts - DO NOT SHARE"]
    for name in ("svc-backup", "svc-deploy", "ftpadmin", "monitor"):
        lines.append(f"{name}:{rng.getrandbits(40):010x}!")
    return ("\n".join(lines) + "\n").encode()


class FakeFS:
    """The tree for one honeypot. Immutable apart from per-session overlays that
    the protocol layer manages itself."""

    def __init__(
        self, seed: str, planted: Callable[[], tuple[str, str] | None] | None = None
    ) -> None:
        # `planted` returns a tracked (user, password) pair or None; see `_baited`.
        self._planted = planted
        rng = random.Random(hashlib.sha256(seed.encode()).digest())

        def node(name: str, is_dir: bool = False, content: bytes = b"") -> Node:
            ls, mdtm = _MTIMES[name]
            return Node(name, is_dir, ls, mdtm, content)

        readme = (
            b"Welcome to the file server.\n"
            b"Anonymous users may download from /pub. Uploads go to /incoming and are\n"
            b"reviewed by an administrator before being published.\n"
        )
        self._tree: dict[str, list[Node]] = {
            "/": [
                node("pub", True),
                node("incoming", True),
                node("backup.tar.gz", content=_decoy_tar_gz(rng)),
                node("passwords.txt", content=_decoy_passwords(rng)),
                node("README.txt", content=readme),
                node("db_dump.sql.gz", content=_decoy_sql_gz(rng)),
            ],
            "/pub": [node("welcome.msg", content=b"Welcome to the public area.\n")],
            "/incoming": [],
        }

    @staticmethod
    def normalise(cwd: str, path: str) -> str:
        """Resolve `path` against `cwd` into an absolute path, collapsing `.` and
        `..` the way a chroot'd server does (it can never climb above `/`)."""
        base = path if path.startswith("/") else f"{cwd.rstrip('/')}/{path}"
        parts: list[str] = []
        for piece in base.split("/"):
            if piece in ("", "."):
                continue
            if piece == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(piece)
        return "/" + "/".join(parts)

    def is_dir(self, path: str) -> bool:
        return path in self._tree

    def listdir(self, path: str) -> list[Node] | None:
        nodes = self._tree.get(path)
        return None if nodes is None else [self._baited(n) for n in nodes]

    def lookup(self, path: str) -> Node | None:
        if path == "/":
            return Node("/", True, "Mar 15 14:23", "20240315142300")
        parent, _, name = path.rpartition("/")
        for entry in self._tree.get(parent or "/", []):
            if entry.name == name:
                return self._baited(entry)
        return None

    def bait_active(self) -> bool:
        """Whether `passwords.txt` currently carries a tracked credential."""
        return self._planted is not None and self._planted() is not None

    def _baited(self, node: Node) -> Node:
        """`passwords.txt` plus the tracked pair, when there is one. LIST, SIZE and RETR all go through
        here, so the size an attacker sees is the length of the bytes they get."""
        pair = (
            self._planted() if self._planted is not None and node.name == "passwords.txt" else None
        )
        if pair is None:
            return node
        return replace(node, content=node.content + f"{pair[0]}:{pair[1]}\n".encode())

    def render_list(self, nodes: list[Node], extra: list[Node] | None = None) -> bytes:
        every = [*nodes, *(extra or [])]
        total = sum((n.size + 1023) // 1024 for n in every)
        return b"".join([f"total {total}\r\n".encode(), *(n.ls_line() for n in every)])

    def render_nlst(self, nodes: list[Node], extra: list[Node] | None = None) -> bytes:
        return b"".join(f"{n.name}\r\n".encode() for n in [*nodes, *(extra or [])])
