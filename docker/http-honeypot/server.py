"""Standalone HTTP honeypot (used in Docker Compose)."""
import logging
from aiohttp import web

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(message)s")


def _safe(value: str, limit: int = 200) -> str:
    """Make attacker-controlled text safe to put on one log line.

    aiohttp hands us the *decoded* path, so `%0a` arrives as a real newline and
    would let a request forge a second, fake log line. Escape every
    non-printable character (CR, LF, ESC, NUL, ...) instead of emitting it.
    """
    out = []
    for ch in value[:limit]:
        if ch == "\\":
            out.append("\\\\")
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(f"\\u{ord(ch):04x}")
    return "".join(out)


_FAKE_ENV = """APP_KEY=base64:xWnYiXxhsUFvBmm7pOVWXWoG0000000000==
DB_HOST=127.0.0.1
DB_DATABASE=production
DB_USERNAME=root
DB_PASSWORD=SuperSecret123!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"""

_ADMIN_HTML = """<!DOCTYPE html><html><head><title>Admin Login</title></head>
<body><h2>Administration Panel</h2>
<form method="POST">
<input name="username" placeholder="Username"><br>
<input type="password" name="password" placeholder="Password"><br>
<input type="submit" value="Login">
</form></body></html>"""


async def handle(request: web.Request) -> web.Response:
    path = request.path
    method = request.method
    ip = request.remote
    ua = request.headers.get("User-Agent", "")
    log.info("%s %s %s | UA=%s", _safe(method, 16), _safe(path), _safe(str(ip), 64), _safe(ua, 60))

    if path == "/.env":
        return web.Response(text=_FAKE_ENV, content_type="text/plain",
                            headers={"Server": "Apache/2.4.41"})
    return web.Response(text=_ADMIN_HTML, content_type="text/html",
                        headers={"Server": "Apache/2.4.41", "X-Powered-By": "PHP/7.4.33"})


app = web.Application()
app.router.add_route("*", "/{tail:.*}", handle)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=8080)
