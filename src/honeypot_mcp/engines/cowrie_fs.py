"""A filesystem for the Cowrie honeypot that agrees with its persona.

The persona (`ssh_personas.py`) makes `uname`, the SSH banner and the prompt claim
a particular server. Cowrie's bundled filesystem, though, is a fixed Debian image
with its own opinions, and the first things an attacker reads contradict the
persona: `cat /etc/hostname` says `svr04` while `hostname` says `web-prod-03`,
`/etc/issue` says Debian on an "Ubuntu 22.04" box, `/etc/os-release` is an empty
dangling symlink, `/proc/version` names another kernel, and `ls /home` shows
`phil` — the best-known Cowrie default there is. Each is a one-command tell, and
they are all in one file: Cowrie keeps the whole tree, contents included, in
`fs.pickle`.

`build_persona_fs` rewrites the bundled pickle so those files describe the persona,
and `persona_tar` packs the result for `docker put_archive`.

The pickle is read through a restricted unpickler that refuses to import anything:
the file is plain nested lists, so a pickle that asks for a class is not one of
ours and is rejected rather than executed.
"""

from __future__ import annotations

import hashlib
import io
import pickle
import random
import shlex
import tarfile
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Type-only. This module is stdlib-only at runtime so that it can also be loaded
    # straight from its file inside the Cowrie image (docker/cowrie/build_persona_fs.py),
    # where the honeypot_mcp package is not installed.
    from honeypot_mcp.engines.ssh_personas import SSHPersona

# Field indexes of a Cowrie filesystem node, and its node types.
(A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE) = range(
    10
)
T_LINK, T_DIR, T_FILE = 0, 1, 2

Node = list[Any]

# Where the bundled pickle lives in the Cowrie image, and where the persona's goes.
BASE_PICKLE_PATH = "/cowrie/cowrie-git/src/cowrie/data/fs.pickle"
PERSONA_DIR = "/cowrie/persona"
PERSONA_PICKLE_PATH = f"{PERSONA_DIR}/fs.pickle"

_FILE = 0o100644
_DIR = 0o040755
_PRIVATE_DIR = 0o040700
_SECRET = 0o100640

# 2023-09-01: a plausible install date for files this module writes.
_BASE_CTIME = 1693526400


class _PlainUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> Any:
        raise pickle.UnpicklingError(f"refusing to load {module}.{name}")


def load_fs(data: bytes) -> Node:
    root = _PlainUnpickler(io.BytesIO(data)).load()
    if not isinstance(root, list) or len(root) < 8 or root[A_NAME] != "/":
        raise ValueError("not a Cowrie filesystem pickle")
    return root


# ── Tree helpers ────────────────────────────────────────────────────────────


def _child(directory: Node, name: str) -> Node | None:
    for node in directory[A_CONTENTS]:
        if node[A_NAME] == name:
            return node
    return None


def _walk(root: Node, path: str) -> Node | None:
    cur: Node | None = root
    for part in (p for p in path.split("/") if p):
        if cur is None or cur[A_TYPE] != T_DIR:
            return None
        cur = _child(cur, part)
    return cur


def _mkdir(root: Node, path: str, *, uid: int = 0, gid: int = 0, mode: int = _DIR) -> Node:
    cur = root
    parts = [p for p in path.split("/") if p]
    for i, part in enumerate(parts):
        nxt = _child(cur, part)
        if nxt is None:
            last = i == len(parts) - 1
            nxt = [part, T_DIR, uid if last else 0, gid if last else 0, 4096,
                   mode if last else _DIR, _BASE_CTIME, [], None, None]  # fmt: skip
            cur[A_CONTENTS].append(nxt)
        cur = nxt
    return cur


def _put(
    root: Node, path: str, data: str | bytes, *, mode: int = _FILE, uid: int = 0, gid: int = 0
) -> None:
    """Create or replace a regular file (replacing a symlink or a stale node)."""
    raw = data.encode() if isinstance(data, str) else data
    parent_path, _, name = path.rpartition("/")
    parent = _mkdir(root, parent_path)
    for old in [n for n in parent[A_CONTENTS] if n[A_NAME] == name]:
        parent[A_CONTENTS].remove(old)
    parent[A_CONTENTS].append(
        [name, T_FILE, uid, gid, len(raw), mode, _BASE_CTIME, raw, None, None]
    )


def _remove(root: Node, path: str) -> None:
    parent_path, _, name = path.rpartition("/")
    parent = _walk(root, parent_path or "/")
    if parent is None:
        return
    for old in [n for n in parent[A_CONTENTS] if n[A_NAME] == name]:
        parent[A_CONTENTS].remove(old)


def _read(root: Node, path: str) -> str:
    node = _walk(root, path)
    if node is not None and node[A_TYPE] == T_FILE and isinstance(node[A_CONTENTS], bytes):
        return node[A_CONTENTS].decode("utf-8", errors="replace")
    return ""


# ── What each persona says about itself ─────────────────────────────────────

_OS_RELEASE = {
    "ubuntu_22_04": (
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\n'
        'ID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        "UBUNTU_CODENAME=jammy\n"
    ),
    "ubuntu_20_04": (
        'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        "VERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n"
    ),
    "debian_12": (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\n'
        'VERSION_ID="12"\nVERSION="12 (bookworm)"\nVERSION_CODENAME=bookworm\nID=debian\n'
        'HOME_URL="https://www.debian.org/"\nSUPPORT_URL="https://www.debian.org/support"\n'
        'BUG_REPORT_URL="https://bugs.debian.org/"\n'
    ),
    "rhel_8": (
        'NAME="Red Hat Enterprise Linux"\nVERSION="8.8 (Ootpa)"\nID="rhel"\nID_LIKE="fedora"\n'
        'VERSION_ID="8.8"\nPLATFORM_ID="platform:el8"\n'
        'PRETTY_NAME="Red Hat Enterprise Linux 8.8 (Ootpa)"\nANSI_COLOR="0;31"\n'
        'CPE_NAME="cpe:/o:redhat:enterprise_linux:8::baseos"\n'
        'HOME_URL="https://www.redhat.com/"\n'
        'DOCUMENTATION_URL="https://access.redhat.com/documentation/red_hat_enterprise_linux/8/"\n'
        'BUG_REPORT_URL="https://bugzilla.redhat.com/"\n'
        'REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 8"\n'
        'REDHAT_BUGZILLA_PRODUCT_VERSION=8.8\nREDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"\n'
        'REDHAT_SUPPORT_PRODUCT_VERSION="8.8"\n'
    ),
}

_ISSUE = {
    "ubuntu_22_04": "Ubuntu 22.04.3 LTS \\n \\l\n\n",
    "ubuntu_20_04": "Ubuntu 20.04.6 LTS \\n \\l\n\n",
    "debian_12": "Debian GNU/Linux 12 \\n \\l\n\n",
    "rhel_8": "\\S\nKernel \\r on an \\m\n\n",
}

_PROC_VERSION = {
    "ubuntu_22_04": (
        "Linux version {k} (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) "
        "11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) {b}\n"
    ),
    "ubuntu_20_04": (
        "Linux version {k} (buildd@lgw01-amd64-054) (gcc version 9.4.0 "
        "(Ubuntu 9.4.0-1ubuntu1~20.04.1)) {b}\n"
    ),
    "debian_12": (
        "Linux version {k} (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) "
        "12.2.0, GNU ld (GNU Binutils for Debian) 2.40) {b}\n"
    ),
    "rhel_8": (
        "Linux version {k} (mockbuild@x86-vm-08.build.eng.bos.redhat.com) (gcc version "
        "8.5.0 20210514 (Red Hat 8.5.0-18) (GCC)) {b}\n"
    ),
}

_DEBIAN_VERSION = {
    "ubuntu_22_04": "bookworm/sid\n",
    "ubuntu_20_04": "bullseye/sid\n",
    "debian_12": "12.2\n",
}

_LSB_RELEASE = {
    "ubuntu_22_04": (
        "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\n"
        'DISTRIB_DESCRIPTION="Ubuntu 22.04.3 LTS"\n'
    ),
    "ubuntu_20_04": (
        "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\nDISTRIB_CODENAME=focal\n"
        'DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"\n'
    ),
}

_UBUNTU_MOTD = (
    "Welcome to {pretty} (GNU/Linux {k} x86_64)\n\n"
    " * Documentation:  https://help.ubuntu.com\n"
    " * Management:     https://landscape.canonical.com\n"
    " * Support:        https://ubuntu.com/advantage\n\n"
    "Expanded Security Maintenance for Applications is not enabled.\n\n"
    "0 updates can be applied immediately.\n\n"
    "Enable ESM Apps to receive additional future security updates.\n"
    "See https://ubuntu.com/esm or run: sudo pro status\n\n\n"
)
_DEBIAN_MOTD = (
    "\nThe programs included with the Debian GNU/Linux system are free software;\n"
    "the exact distribution terms for each program are described in the\n"
    "individual files in /usr/share/doc/*/copyright.\n\n"
    "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent\n"
    "permitted by applicable law.\n"
)
_RHEL_MOTD = "Activate the web console with: systemctl enable --now cockpit.socket\n\n"

_HOSTS = {
    "debian": (
        "127.0.0.1\tlocalhost\n127.0.1.1\t{h}\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\n"
        "ff02::2 ip6-allrouters\n"
    ),
    "rhel": (
        "127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4\n"
        "::1         localhost localhost.localdomain localhost6 localhost6.localdomain6\n"
    ),
}

# RHEL-family accounts; the bundled passwd is a Debian one.
_RHEL_ACCOUNTS = (
    ("root", 0, 0, "root", "/root", "/bin/bash"),
    ("bin", 1, 1, "bin", "/bin", "/sbin/nologin"),
    ("daemon", 2, 2, "daemon", "/sbin", "/sbin/nologin"),
    ("adm", 3, 4, "adm", "/var/adm", "/sbin/nologin"),
    ("lp", 4, 7, "lp", "/var/spool/lpd", "/sbin/nologin"),
    ("sync", 5, 0, "sync", "/sbin", "/bin/sync"),
    ("shutdown", 6, 0, "shutdown", "/sbin", "/sbin/shutdown"),
    ("halt", 7, 0, "halt", "/sbin", "/sbin/halt"),
    ("mail", 8, 12, "mail", "/var/spool/mail", "/sbin/nologin"),
    ("operator", 11, 0, "operator", "/root", "/sbin/nologin"),
    ("games", 12, 100, "games", "/usr/games", "/sbin/nologin"),
    ("ftp", 14, 50, "FTP User", "/var/ftp", "/sbin/nologin"),
    ("nobody", 65534, 65534, "Kernel Overflow User", "/", "/sbin/nologin"),
    ("dbus", 81, 81, "System message bus", "/", "/sbin/nologin"),
    ("systemd-coredump", 999, 997, "systemd Core Dumper", "/", "/sbin/nologin"),
    ("systemd-resolve", 193, 193, "systemd Resolver", "/", "/sbin/nologin"),
    ("polkitd", 998, 996, "User for polkitd", "/", "/sbin/nologin"),
    ("sshd", 74, 74, "Privilege-separated SSH", "/var/empty/sshd", "/sbin/nologin"),
    ("chrony", 997, 995, "", "/var/lib/chrony", "/sbin/nologin"),
)

_USERS = {
    "ubuntu_22_04": ("ubuntu", "deploy", "admin", "appuser"),
    "ubuntu_20_04": ("ubuntu", "deploy", "admin", "appuser"),
    "debian_12": ("admin", "deploy", "appuser", "svc-web"),
    "rhel_8": ("ec2-user", "deploy", "admin", "appuser"),
}

_HISTORY = {
    "debian": (
        "sudo systemctl status nginx\ncd /var/www\nls -la\nsudo tail -n 50 /var/log/syslog\n"
        "df -h\nfree -m\nsudo apt update\nsudo apt upgrade -y\ncd ~\nexit\n"
    ),
    "rhel": (
        "sudo systemctl status httpd\ncd /var/www\nls -la\nsudo tail -n 50 /var/log/messages\n"
        "df -h\nfree -m\nsudo dnf check-update\nsudo dnf upgrade -y\ncd ~\nexit\n"
    ),
}


def _sha512_crypt_lookalike(rng: random.Random) -> str:
    """A `$6$salt$hash`-shaped string. Not a real hash of anything: the account
    has no usable password, and the shape is what a `cat /etc/shadow` shows."""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    salt = "".join(rng.choice(alphabet) for _ in range(16))
    digest = "".join(rng.choice(alphabet) for _ in range(86))
    return f"$6${salt}${digest}"


def username_for(persona: SSHPersona, seed: str) -> str:
    """The unprivileged account this honeypot has, stable per honeypot."""
    pool = _USERS[persona.id]
    return pool[hashlib.sha256(f"user:{seed}".encode()).digest()[0] % len(pool)]


# ── The build ───────────────────────────────────────────────────────────────


def bait_credential(seed: str) -> tuple[str, str]:
    """The untracked decoy MySQL pair used when no credential token exists: stable per
    honeypot, shaped like a service account an admin would script with."""
    digest = hashlib.sha256(f"bait:{seed}".encode()).hexdigest()
    return f"app_{digest[:4]}", f"{digest[4:12]}{digest[12:16].upper()}!{digest[16:18]}"


def bait_files(user: str, home: str, credential: tuple[str, str]) -> dict[str, tuple[str, int]]:
    """The files in a home directory that carry the bait credential, as
    `{path: (content, mode)}`. Pure: the same credential always yields the same bytes, so a
    `cat` and an `ls -l` (or two reads) agree."""
    db_user, db_pass = credential
    host = "db1.internal"
    # Quoted: an unquoted `#` in a my.cnf value starts a comment, and generated passwords
    # contain one; a real admin's file would be quoted for exactly that reason.
    quoted = db_pass.replace("\\", "\\\\").replace('"', '\\"')
    cnf = f'[client]\nuser={db_user}\npassword="{quoted}"\nhost={host}\n'
    return {
        f"{home}/.my.cnf": (cnf, 0o100600),
    }


def bait_history_line(credential: tuple[str, str]) -> str:
    """The `mysql` invocation an administrator left in shell history."""
    db_user, db_pass = credential
    return f"mysql -u {shlex.quote(db_user)} {shlex.quote('-p' + db_pass)} -h db1.internal\n"


def build_persona_fs(
    base: bytes,
    persona: SSHPersona,
    hostname: str,
    seed: str,
    credential: tuple[str, str] | None = None,
) -> bytes:
    """Rewrite Cowrie's bundled filesystem so it describes `persona`.

    `credential` is a tracked (user, password) pair from a honeytoken, planted in the home
    directory as bait; without one, a deterministic untracked decoy pair takes its place."""
    root = load_fs(base)
    rng = random.Random(hashlib.sha256(f"fs:{seed}".encode()).digest())
    pid = persona.id
    rhel = pid.startswith("rhel")
    family = "rhel" if rhel else "debian"
    user = username_for(persona, seed)

    _put(root, "/etc/hostname", f"{hostname}\n")
    _put(root, "/etc/hosts", _HOSTS[family].format(h=hostname))
    _put(root, "/etc/issue", _ISSUE[pid])
    # /etc/issue.net is deliberately NOT written. Cowrie sends its contents as the
    # SSH pre-auth banner on every connection when it is non-empty, and a stock
    # Ubuntu/Debian/RHEL sshd sends none (`Banner` is off by default); the bundled
    # file is empty for that reason.
    _put(root, "/etc/os-release", _OS_RELEASE[pid])
    _put(root, "/usr/lib/os-release", _OS_RELEASE[pid])  # os-release is normally a symlink to this
    _put(
        root,
        "/proc/version",
        _PROC_VERSION[pid].format(k=persona.kernel_version, b=persona.kernel_build_string),
    )

    if rhel:
        _remove(root, "/etc/debian_version")
        _put(root, "/etc/redhat-release", "Red Hat Enterprise Linux release 8.8 (Ootpa)\n")
        _put(root, "/etc/motd", _RHEL_MOTD)
    else:
        _put(root, "/etc/debian_version", _DEBIAN_VERSION[pid])
        if pid in _LSB_RELEASE:
            _put(root, "/etc/lsb-release", _LSB_RELEASE[pid])
            _put(
                root,
                "/etc/motd",
                _UBUNTU_MOTD.format(pretty=persona.distro_pretty_name, k=persona.kernel_version),
            )
        else:
            _put(root, "/etc/motd", _DEBIAN_MOTD)

    _rewrite_accounts(root, rhel=rhel, user=user, rng=rng)
    _rewrite_home(
        root,
        user=user,
        family=family,
        rng=rng,
        credential=credential or bait_credential(seed),
    )

    # protocol 4 is readable by every Python Cowrie ships on.
    return pickle.dumps(root, protocol=4)


def _rewrite_accounts(root: Node, *, rhel: bool, user: str, rng: random.Random) -> None:
    """passwd, group and shadow, with Cowrie's own `phil`/`richard` accounts gone
    and one plausible unprivileged user in their place."""
    uid = gid = 1000
    gecos = user.replace("-", " ").title()
    if rhel:
        passwd_lines = [f"{n}:x:{u}:{g}:{c}:{h}:{s}" for n, u, g, c, h, s in _RHEL_ACCOUNTS]
        group_lines = [f"{n}:x:{g}:" for n, _u, g, _c, _h, _s in _RHEL_ACCOUNTS]
        group_lines = [
            *(ln for ln in group_lines if not ln.startswith("nobody:")),
            "wheel:x:10:" + user,
            "nobody:x:65534:",
        ]
    else:
        passwd_lines = [
            ln
            for ln in _read(root, "/etc/passwd").splitlines()
            if ln and not ln.startswith(("phil:", "richard:"))
        ]
        group_lines = []
        for ln in _read(root, "/etc/group").splitlines():
            if not ln or ln.startswith(("phil:", "richard:")):
                continue
            name, pw, gnum, members = (ln.split(":") + ["", "", "", ""])[:4]
            people = [m for m in members.split(",") if m and m not in ("phil", "richard")]
            if name in ("sudo", "adm", "cdrom", "audio", "video", "plugdev", "users"):
                people.append(user)
            group_lines.append(f"{name}:{pw}:{gnum}:{','.join(people)}")
    passwd_lines.append(f"{user}:x:{uid}:{gid}:{gecos},,,:/home/{user}:/bin/bash")
    group_lines.append(f"{user}:x:{gid}:")

    shadow_lines = []
    locked = "!!" if rhel else "*"
    for ln in passwd_lines:
        name = ln.split(":")[0]
        if name in ("root", user):
            shadow_lines.append(f"{name}:{_sha512_crypt_lookalike(rng)}:19600:0:99999:7:::")
        else:
            shadow_lines.append(f"{name}:{locked}:19600:0:99999:7:::")

    _put(root, "/etc/passwd", "\n".join(passwd_lines) + "\n")
    _put(root, "/etc/group", "\n".join(group_lines) + "\n")
    _put(root, "/etc/shadow", "\n".join(shadow_lines) + "\n", mode=_SECRET)


def _rewrite_home(
    root: Node, *, user: str, family: str, rng: random.Random, credential: tuple[str, str]
) -> None:
    """Replace `/home/phil` with `/home/<user>`, with the files a used account has."""
    home = _mkdir(root, "/home")
    for old in [n for n in home[A_CONTENTS] if n[A_NAME] in ("phil", "richard")]:
        home[A_CONTENTS].remove(old)
    base = f"/home/{user}"
    _mkdir(root, base, uid=1000, gid=1000, mode=_PRIVATE_DIR)
    _mkdir(root, f"{base}/.ssh", uid=1000, gid=1000, mode=_PRIVATE_DIR)
    history = _HISTORY[family]
    lines = history.splitlines(keepends=True)
    lines.insert(len(lines) - 2, bait_history_line(credential))  # before `cd ~` / `exit`
    history = "".join(lines)
    bashrc = "# ~/.bashrc: executed by bash(1) for non-login shells.\n[ -z \"$PS1\" ] && return\nalias ll='ls -alF'\n"
    for name, data, mode in (
        (".bash_history", history, 0o100600),
        (".bash_logout", "# ~/.bash_logout: executed by bash(1) when login shell exits.\n", _FILE),
        (".bashrc", bashrc, _FILE),
        (
            ".profile",
            "# ~/.profile: executed by the command interpreter for login shells.\n",
            _FILE,
        ),
    ):
        _put(root, f"{base}/{name}", data, mode=mode, uid=1000, gid=1000)
    for path, (data, mode) in bait_files(user, base, credential).items():
        _put(root, path, data, mode=mode, uid=1000, gid=1000)
    # Give the history a believable age that varies between honeypots.
    node = _walk(root, f"{base}/.bash_history")
    if node is not None:
        node[A_CTIME] = _BASE_CTIME + rng.randint(0, 20_000_000)


def persona_tar(fs_pickle: bytes, sitecustomize: bytes | None = None) -> bytes:
    """A tar archive for `put_archive(PERSONA_DIR, …)`: `fs.pickle`, and (when given)
    `patch/sitecustomize.py`, which Python imports first inside the container because the
    engine puts `PERSONA_DIR/patch` on `PYTHONPATH` (see `cowrie_sitecustomize`).

    It is extracted *into* the volume mounted at `PERSONA_DIR`: Docker checks the
    extraction path against the read-only root filesystem, so a path inside the
    mount is accepted where `/` is refused."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("fs.pickle")
        info.size = len(fs_pickle)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(fs_pickle))
        if sitecustomize is not None:
            directory = tarfile.TarInfo("patch")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            tar.addfile(directory)
            patch = tarfile.TarInfo("patch/sitecustomize.py")
            patch.size = len(sitecustomize)
            patch.mode = 0o644
            tar.addfile(patch, io.BytesIO(sitecustomize))
    return buf.getvalue()
