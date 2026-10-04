"""The HTTP honeypot's authenticated area.

Until now `POST /login` answered 401 to everything. That is what a hardened site
does, and it is also why a credential-spraying bot — which only moves on once it
sees a success — never showed us anything past the login form: no post-login
requests, no upload attempts, nothing about what it does with a foothold.

This module is that foothold: a small, internally consistent admin console that a
*successful* login redirects to. What counts as success is deliberately narrow:

* a credential an operator planted as a honeytoken (the event buffer's matcher
  marks the event, and the caller passes that fact in), and
* one weak pair per honeypot, chosen from a pool by hashing the honeypot's name,
  so a spray of the usual suspects lands on it within a handful of guesses while
  two sensors do not share a fingerprint ("admin/admin works everywhere").

`accepted_logins` in the honeypot's config replaces the derived pair (an empty
list turns the area off entirely).

Everything shown is decoy. Downloads reuse the FTP honeypot's file tree, so a
size on a page is the length of the bytes that link serves.
"""

from __future__ import annotations

import hashlib
import html
import random
from dataclasses import dataclass

from honeypot_mcp.engines.ftp_fs import FakeFS

# The pool a weak pair is drawn from. Ordinary spray-list material.
_WEAK_PASSWORDS = (
    "admin", "password", "123456", "admin123", "P@ssw0rd", "welcome1", "changeme",
)  # fmt: skip
_WEAK_USERS = ("admin", "administrator")

# Where an authenticated visitor may go. Any other path is handled as before.
DASHBOARD = "/dashboard"
SECTIONS = ("users", "settings", "backup", "logs", "upload")
_BACKUP_FILES = {"db_dump.sql.gz": "/db_dump.sql.gz", "site_backup.tar.gz": "/backup.tar.gz"}


def derive_login(seed: str) -> tuple[str, str]:
    """The weak (username, password) pair this honeypot accepts."""
    h = hashlib.sha256(f"login:{seed}".encode()).digest()
    return _WEAK_USERS[h[0] % len(_WEAK_USERS)], _WEAK_PASSWORDS[h[1] % len(_WEAK_PASSWORDS)]


def accepted_pairs(seed: str, configured: object) -> frozenset[tuple[str, str]]:
    """Pairs that log in. `configured` is the honeypot config's `accepted_logins`:
    a list of "user:password" strings, or None to use the derived pair."""
    if configured is None:
        user, password = derive_login(seed)
        return frozenset({(user.lower(), password)})
    pairs: set[tuple[str, str]] = set()
    if isinstance(configured, list):
        for item in configured[:32]:
            if isinstance(item, str) and ":" in item:
                user, _, password = item.partition(":")
                pairs.add((user.lower(), password))
    return frozenset(pairs)


def pick_credentials(post_data: dict[str, object]) -> tuple[str, str]:
    """The submitted (username, password) from a parsed form, tolerant of the
    usual field aliases."""
    lowered = {str(k).lower(): v for k, v in post_data.items()}

    def first(*names: str) -> str:
        for n in names:
            v = lowered.get(n)
            if isinstance(v, str) and v:
                return v
        return ""

    return first("username", "user", "email", "login", "log"), first(
        "password", "pass", "passwd", "pwd"
    )


@dataclass(frozen=True)
class Page:
    body: str
    status: int = 200
    content_type: str = "text/html"


def _rng(seed: str, salt: str) -> random.Random:
    return random.Random(hashlib.sha256(f"{seed}:{salt}".encode()).digest())


def _fake_users(seed: str) -> list[tuple[str, str, str, str]]:
    rng = _rng(seed, "users")
    names = ["admin", "j.carter", "m.nguyen", "s.patel", "backup-svc", "d.okafor", "r.silva"]
    domains = ["corp.local"]
    roles = ["Administrator", "Editor", "Editor", "Viewer", "Service", "Viewer", "Editor"]
    rows = []
    for name, role in zip(names, roles, strict=True):
        last = f"2026-{rng.randint(8, 9):02d}-{rng.randint(1, 28):02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}"
        rows.append((name, f"{name}@{rng.choice(domains)}", role, last))
    return rows


def _layout(title: str, hostname: str, username: str, content: str, active: str = "") -> str:
    def nav(href: str, label: str, key: str) -> str:
        cls = ' class="active"' if key == active else ""
        return f'<a href="{href}"{cls}>{label}</a>'

    links = "".join(
        [
            nav(DASHBOARD, "Dashboard", "dashboard"),
            nav("/admin/users", "Users", "users"),
            nav("/admin/settings", "Settings", "settings"),
            nav("/admin/backup", "Backups", "backup"),
            nav("/admin/logs", "Logs", "logs"),
            nav("/admin/upload", "Uploads", "upload"),
        ]
    )
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        f"<title>{html.escape(title)} - {html.escape(hostname)}</title>"
        "<style>body{font-family:Arial,sans-serif;margin:0;background:#f4f5f7}"
        "header{background:#243447;color:#fff;padding:10px 20px;display:flex;justify-content:space-between}"
        "nav{background:#fff;padding:8px 20px;border-bottom:1px solid #ddd}"
        "nav a{margin-right:16px;text-decoration:none;color:#243447}nav a.active{font-weight:bold}"
        "main{padding:20px}table{border-collapse:collapse;background:#fff}"
        "td,th{border:1px solid #ddd;padding:6px 12px;text-align:left}</style></head><body>"
        f"<header><span>{html.escape(hostname)} &middot; Admin Console</span>"
        f'<span>Signed in as {html.escape(username)} &middot; <a style="color:#fff" href="/logout">Log out</a></span></header>'
        f"<nav>{links}</nav><main><h2>{html.escape(title)}</h2>{content}</main></body></html>"
    )


def render(section: str, *, seed: str, hostname: str, username: str, method: str = "GET") -> Page:
    """The page for `section` ("dashboard" or one of SECTIONS)."""
    rng = _rng(seed, "stats")
    if section == "dashboard":
        stats = [
            ("Registered users", rng.randint(180, 940)),
            ("Active sessions", rng.randint(4, 38)),
            ("Pending uploads", rng.randint(0, 6)),
            ("Failed logins (24h)", rng.randint(120, 4000)),
        ]
        cells = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in stats)
        return Page(
            _layout("Dashboard", hostname, username, f"<table>{cells}</table>", "dashboard")
        )

    if section == "users":
        rows = "".join(
            f"<tr><td>{html.escape(n)}</td><td>{html.escape(e)}</td><td>{r}</td><td>{ls}</td></tr>"
            for n, e, r, ls in _fake_users(seed)
        )
        table = f"<table><tr><th>User</th><th>Email</th><th>Role</th><th>Last login</th></tr>{rows}</table>"
        return Page(_layout("Users", hostname, username, table, "users"))

    if section == "settings":
        notice = "<p><b>Settings saved.</b></p>" if method == "POST" else ""
        form = (
            f'{notice}<form method="POST" action="/admin/settings">'
            '<p><label>Site name <input name="site_name" value="Corporate Portal"></label></p>'
            '<p><label>Admin email <input name="admin_email" value="admin@corp.local"></label></p>'
            '<p><label>SMTP host <input name="smtp_host" value="mail.corp.local"></label></p>'
            '<p><button type="submit">Save changes</button></p></form>'
        )
        return Page(_layout("Settings", hostname, username, form, "settings"))

    if section == "backup":
        fs = FakeFS(seed)
        rows = ""
        for shown, path in _BACKUP_FILES.items():
            node = fs.lookup(path)
            size = len(node.content) if node else 0
            rows += (
                f'<tr><td><a href="/admin/backup/{shown}">{shown}</a></td>'
                f"<td>{size:,} bytes</td><td>2026-09-{rng.randint(10, 28)}</td></tr>"
            )
        table = f"<table><tr><th>File</th><th>Size</th><th>Created</th></tr>{rows}</table>"
        return Page(_layout("Backups", hostname, username, table, "backup"))

    if section == "logs":
        lines = []
        for _ in range(14):
            lines.append(
                f"2026-10-0{rng.randint(1, 3)} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:"
                f"{rng.randint(0, 59):02d} [{rng.choice(['INFO', 'INFO', 'WARN'])}] "
                f"{rng.choice(['login ok user=j.carter', 'cron backup finished', 'cache cleared', 'login failed user=admin', 'mail queue flushed'])}"
            )
        pre = "<pre>" + html.escape("\n".join(sorted(lines))) + "</pre>"
        return Page(_layout("Logs", hostname, username, pre, "logs"))

    if section == "upload":
        notice = (
            "<p><b>File uploaded successfully.</b> It will appear after review.</p>"
            if method == "POST"
            else ""
        )
        form = (
            f'{notice}<form method="POST" action="/admin/upload" enctype="multipart/form-data">'
            '<p><input type="file" name="file"></p>'
            '<p><button type="submit">Upload</button></p></form>'
        )
        return Page(_layout("Uploads", hostname, username, form, "upload"))

    return Page("", status=404)


def backup_download(seed: str, name: str) -> bytes | None:
    """The bytes behind a Backups link (same bytes the FTP tree would serve)."""
    path = _BACKUP_FILES.get(name)
    if path is None:
        return None
    node = FakeFS(seed).lookup(path)
    return node.content if node else None


def route(path: str) -> tuple[str, str] | None:
    """Map a request path to ("page", section) or ("download", filename)."""
    if path == DASHBOARD:
        return ("page", "dashboard")
    if path.startswith("/admin/backup/"):
        return ("download", path.removeprefix("/admin/backup/"))
    if path.startswith("/admin/"):
        section = path.removeprefix("/admin/").rstrip("/")
        if section in SECTIONS:
            return ("page", section)
    return None
