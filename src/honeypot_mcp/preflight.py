"""Pre-flight checks for putting this server on the public internet.

    python -m honeypot_mcp.preflight --ports 22,80,3389 --mcp-url http://127.0.0.1:8000/mcp

A honeypot is judged by what it is not doing when nobody is looking: a console bound to the
world, a token nobody rotated, a disk that will fill at 3 a.m., a sensor that answers on the
wrong port, an alert channel nobody subscribed. Each of those is cheap to find before traffic
arrives and expensive after. This runs every check that can be run and says what to change.

Two kinds of check:

* Static: read the configuration and the host (bind addresses, token strength, file modes,
  database, free disk, Docker, whether the ports you plan to use are free).
* Live (with ``--mcp-url`` / ``--metrics-url``): ask the running server (``/readyz``, ``ping``,
  ``honeypot_status``, ``honeypot_self_test`` per sensor, the alert subscriptions).

Exit status 0 when nothing failed, 1 otherwise (``--strict`` also fails on warnings), so it can
gate a deploy script. ``honeypot_self_test`` sends a synthetic probe to each sensor, which
leaves a clearly marked alert behind; run this before go-live, or pass ``--no-self-test``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import errno
import json
import math
import os
import shutil
import socket
import stat
import sys
import time
import zlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url

from honeypot_mcp.config import _PROJECT_ROOT, Settings, get_settings
from honeypot_mcp.rbac import parse_auth_tokens

PASS, WARN, FAIL, SKIP = "pass", "warn", "fail", "skip"

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}
# Ports a honeypot commonly takes, for the lock-out check below.
_MIN_TOKEN_CHARS_FAIL, _MIN_TOKEN_CHARS_WARN = 16, 32


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    fix: str = ""


# ── Static checks ────────────────────────────────────────────────────────────


def check_transport(s: Settings) -> Check:
    transport = s.mcp_transport
    if transport == "stdio":
        return Check(
            "control plane transport",
            WARN,
            "stdio: the honeypots live inside the chat session's process and stop with it.",
            "Set MCP_TRANSPORT=streamable-http (a daemon with a token), or `none` for a "
            "collector with no control plane.",
        )
    if transport == "none":
        return Check("control plane transport", PASS, "collector mode: no control plane exposed")
    tokens = parse_auth_tokens(s.mcp_auth_token, s.mcp_auth_tokens)
    if not tokens and not s.mcp_allow_unauthenticated:
        return Check(
            "control plane transport", FAIL, f"{transport} with no token configured",
            "Set MCP_AUTH_TOKEN (openssl rand -hex 32) or MCP_AUTH_TOKENS.",
        )  # fmt: skip
    if s.mcp_allow_unauthenticated:
        return Check(
            "control plane transport",
            FAIL,
            f"{transport} with MCP_ALLOW_UNAUTHENTICATED: anyone who can reach it can deploy "
            "honeypots and read every captured credential",
            "Remove MCP_ALLOW_UNAUTHENTICATED and set a token.",
        )
    return Check("control plane transport", PASS, f"{transport} with {len(tokens)} token(s)")


def _guessable(token: str) -> bool:
    """A token that is long enough but not random: repeats, or a run of consecutive characters."""
    if len(set(token)) < 6:
        return True
    if len(zlib.compress(token.encode())) < len(token) * 0.6:  # repeated pieces
        return True
    steps = sum(1 for a, b in zip(token, token[1:], strict=False) if abs(ord(a) - ord(b)) == 1)
    if steps > len(token) * 0.5:  # abcdef..., 012345...
        return True
    counts = {c: token.count(c) for c in set(token)}
    entropy = -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())
    return entropy < 3.0


def check_tokens(s: Settings) -> Check:
    tokens = parse_auth_tokens(s.mcp_auth_token, s.mcp_auth_tokens)
    if not tokens:
        return Check("token strength", SKIP, "no tokens configured")
    shortest = min(len(t) for t in tokens)
    if shortest < _MIN_TOKEN_CHARS_FAIL or any(_guessable(t) for t in tokens):
        return Check(
            "token strength",
            FAIL,
            f"a token is {shortest} characters, repeats itself, or is not random",
            "Generate each with `openssl rand -hex 32`.",
        )
    if shortest < _MIN_TOKEN_CHARS_WARN:
        return Check(
            "token strength", WARN, f"shortest token is {shortest} characters",
            "Use at least 32 characters (`openssl rand -hex 32`).",
        )  # fmt: skip
    return Check("token strength", PASS, f"{len(tokens)} token(s), shortest {shortest} characters")


def check_bind_addresses(s: Settings) -> list[Check]:
    out = []
    for label, host, port, why in (
        (
            "console",
            s.console_host,
            s.console_port,
            "an unauthenticated dashboard of every captured credential",
        ),
        (
            "metrics",
            s.metrics_host,
            s.metrics_port,
            "unauthenticated /metrics, /readyz and sensor inventory",
        ),
    ):
        if port <= 0:
            out.append(Check(f"{label} bind address", PASS, f"{label} server disabled"))
        elif host in _LOOPBACK:
            out.append(Check(f"{label} bind address", PASS, host))
        else:
            out.append(
                Check(
                    f"{label} bind address",
                    FAIL,
                    f"{host} exposes {why} to the network",
                    f"Set {label.upper()}_HOST=127.0.0.1 and reach it over an SSH tunnel.",
                )
            )
    if s.mcp_transport in ("streamable-http", "sse", "http") and s.mcp_host not in _LOOPBACK:
        out.append(
            Check(
                "control plane bind address",
                WARN,
                f"{s.mcp_host}: the bearer token crosses the network in clear text unless "
                "TLS is terminated in front",
                "Bind MCP_HOST=127.0.0.1 and use an SSH tunnel or a TLS reverse proxy.",
            )
        )
    elif s.mcp_transport != "stdio":
        out.append(Check("control plane bind address", PASS, s.mcp_host))
    return out


def check_env_permissions(path: Path | None = None) -> Check:
    """The `.env` the server itself reads (beside the code), not whichever one is in the
    directory this happens to be run from.

    The documented production layout is `root:honeypot 0640`: the service reads it through its
    own group and nobody else can. So the group is allowed read access *when it is a dedicated
    group* (a user's private group, or `honeypot`); anything readable or writable by "other"
    fails, and so does a group that can write the file.
    """
    env = path or (_PROJECT_ROOT / ".env")
    if not env.exists():
        return Check(".env permissions", SKIP, f"no .env file at {env}")
    info = env.stat()
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o007 or mode & 0o020:
        return Check(
            ".env permissions",
            FAIL,
            f"mode {mode:o}: other local accounts can read the control-plane token",
            f"chmod 640 {env} (root:honeypot) or 600",
        )
    if mode & 0o040:
        from honeypot_mcp.config import env_group

        name, dedicated = env_group(env)
        if not dedicated:
            return Check(
                ".env permissions",
                FAIL,
                f"mode {mode:o} with group {name!r}: that group's members can read the token",
                f"chgrp honeypot {env} && chmod 640 {env}, or chmod 600",
            )
    return Check(".env permissions", PASS, f"mode {mode:o}")


def check_database(s: Settings) -> Check:
    url = make_url(s.database_url)
    backend = url.get_backend_name()
    if backend == "sqlite":
        if ":memory:" in s.database_url or not url.database:
            return Check(
                "database", FAIL, "in-memory SQLite: every capture is lost on restart",
                "Point DATABASE_URL at a file under data/ or at PostgreSQL.",
            )  # fmt: skip
        directory = Path(url.database).resolve().parent
        if not directory.exists():
            return Check("database", WARN, f"{directory} does not exist yet (created at start)")
        if not os.access(directory, os.W_OK):
            return Check(
                "database", FAIL, f"{directory} is not writable", f"chown/chmod {directory}"
            )
        return Check("database", PASS, f"SQLite at {url.database}")
    return Check("database", PASS, f"{backend} at {url.host or 'local'}")


def _nearest_existing(path: Path) -> Path:
    while not path.exists() and path != path.parent:
        path = path.parent
    return path


def check_disk(s: Settings, *, path: Path | None = None) -> list[Check]:
    """Free space on each volume the server writes to, judged against what lands there: the
    alert floor everywhere, plus the packet-capture ring on the volume that holds it. Volumes
    shared by several locations are checked once, against the sum."""
    floor = s.min_free_disk_mb
    ring_mb = s.pcap_file_mb * s.pcap_files
    url = make_url(s.database_url)
    wanted: list[tuple[str, Path, int]] = []
    if path is not None:
        wanted.append(("data", path, floor))
    else:
        if url.get_backend_name() == "sqlite" and ":memory:" not in s.database_url and url.database:
            wanted.append(("database", Path(url.database).resolve().parent, floor))
        wanted.append(("reports", Path(s.reports_dir), floor))
        if s.pcap_enabled:
            wanted.append(("packet capture", Path(s.pcap_dir).expanduser(), floor + ring_mb))
    by_device: dict[int, tuple[list[str], Path, int]] = {}
    for label, location, need in wanted:
        existing = _nearest_existing(location)
        device = existing.stat().st_dev
        labels, where, total = by_device.get(device, ([], existing, 0))
        by_device[device] = ([*labels, label], where, max(total, floor) + (need - floor))
    out = []
    for labels, where, need in by_device.values():
        free_mb = shutil.disk_usage(where).free // (1024 * 1024)
        name = f"free disk ({', '.join(labels)})"
        if free_mb < need:
            out.append(
                Check(name, FAIL, f"{free_mb} MB free on {where}; need {need} MB "
                      f"(alert floor {floor} MB, packet-capture ring {ring_mb} MB if on this volume)",
                      "Free space, move the packet ring elsewhere, or lower PCAP_FILE_MB x PCAP_FILES.")
            )  # fmt: skip
        elif free_mb < max(2048, need * 2):
            out.append(
                Check(name, WARN, f"{free_mb} MB free on {where}: enough to start, thin for a long run",
                      "Give the data volume more room, or enable RETENTION_DAYS.")
            )  # fmt: skip
        else:
            out.append(Check(name, PASS, f"{free_mb} MB free on {where}"))
    if path is None and url.get_backend_name() != "sqlite":
        out.append(Check("free disk (database)", SKIP,
                         f"{url.get_backend_name()} is remote: check its volume on that host"))  # fmt: skip
    return out


def check_docker() -> Check:
    try:
        import docker

        docker.from_env().ping()  # type: ignore[attr-defined]
    except Exception as e:
        return Check(
            "docker", WARN, f"not reachable ({type(e).__name__}): the SSH/Telnet honeypot "
            "(Cowrie) needs it; the in-process engines do not",
            "Install Docker and add this user to the docker group, or skip the ssh/telnet types.",
        )  # fmt: skip
    return Check("docker", PASS, "daemon reachable")


def check_retention(s: Settings) -> Check:
    if s.retention_days > 0:
        return Check("retention", PASS, f"alerts older than {s.retention_days} days are archived")
    return Check(
        "retention", WARN,
        "RETENTION_DAYS=0: the database grows without bound (fine for a 24-hour run)",
        "Set RETENTION_DAYS for anything longer.",
    )  # fmt: skip


Port = int | tuple[int, str]


def _bind_probe(port: int, kind: int) -> OSError | None:
    """Try to bind `port`; the way asyncio does (SO_REUSEADDR on TCP, so a port in TIME_WAIT
    from a just-stopped honeypot is not reported as taken)."""
    probe = socket.socket(socket.AF_INET, kind)
    try:
        if kind == socket.SOCK_STREAM:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("0.0.0.0", port))
    except OSError as e:
        return e
    finally:
        probe.close()
    return None


def check_ports(ports: Sequence[Port], *, admin_port: int | None = None) -> list[Check]:
    """Can each planned honeypot port be bound (TCP, UDP, or both), and is the way you are
    connected in safe? A port is a number (TCP) or a (number, "tcp"|"udp"|"both") pair."""
    out: list[Check] = []
    normalised = [(p, "tcp") if isinstance(p, int) else p for p in ports]
    if admin_port is not None and any(p == admin_port for p, _ in normalised):
        out.append(
            Check(
                "admin access",
                FAIL,
                f"you are connected over port {admin_port}, which a honeypot is about to take: "
                "starting it would lock you out",
                "Move sshd to another port (and open it in the firewall) before deploying.",
            )
        )
    for port, proto in normalised:
        kinds = {"tcp": [socket.SOCK_STREAM], "udp": [socket.SOCK_DGRAM],
                 "both": [socket.SOCK_STREAM, socket.SOCK_DGRAM]}[proto]  # fmt: skip
        name = f"port {port}" if proto == "tcp" else f"port {port}/{proto}"
        problem = None
        for kind in kinds:
            problem = _bind_probe(port, kind)
            if problem is not None:
                break
        if problem is None:
            out.append(Check(name, PASS, "free"))
        elif problem.errno == errno.EADDRINUSE:
            out.append(
                Check(name, FAIL, "already in use by another process",
                      f"Stop whatever holds it (`ss -lntup 'sport = :{port}'`).")
            )  # fmt: skip
        elif problem.errno == errno.EACCES:
            out.append(
                Check(name, WARN, "privileged port and this user cannot bind it",
                      "Run with CAP_NET_BIND_SERVICE, or "
                      "`sysctl net.ipv4.ip_unprivileged_port_start=0`.")
            )  # fmt: skip
        else:
            out.append(Check(name, FAIL, f"cannot bind: {problem.strerror}"))
    return out


def _snapshot_complete(path: Path) -> bool:
    """A backup directory that actually holds a database (a failed run can leave an empty
    directory, and a half-written file is not a backup)."""
    try:
        if path.name.endswith((".partial", ".tmp")) or not path.is_dir():
            return False
        return any(
            (path / name).is_file() and (path / name).stat().st_size > 0
            for name in ("honeypot_mcp.db", "honeypot_mcp.sql")
        )
    except OSError:  # a dangling symlink, a permission error
        return False


def check_backup(directory: Path | None, *, max_age_hours: float = 25) -> Check:
    if directory is None:
        return Check(
            "backups", WARN, "no --backup-dir given, so nothing checks that a backup exists",
            "Schedule scripts/backup.sh (cron) and pass --backup-dir.",
        )  # fmt: skip
    complete = []
    try:
        candidates = sorted(directory.glob("honeypot-*")) if directory.exists() else []
    except OSError:
        candidates = []
    for candidate in candidates:
        if _snapshot_complete(candidate):
            complete.append((candidate.stat().st_mtime, candidate))
    if not complete:
        return Check("backups", FAIL, f"no complete backup under {directory}",
                     "Run scripts/backup.sh once now.")  # fmt: skip
    newest = max(complete)[0]
    age_h = (time.time() - newest) / 3600
    if age_h > max_age_hours:
        return Check(
            "backups", WARN, f"newest backup is {age_h:.0f} hours old", "Check the cron job."
        )
    return Check("backups", PASS, f"newest backup {age_h:.1f} hours old")


def static_checks(
    s: Settings, *, ports: list[int], admin_port: int | None, backup_dir: Path | None
) -> list[Check]:
    return [
        check_transport(s),
        check_tokens(s),
        *check_bind_addresses(s),
        check_env_permissions(),
        check_database(s),
        *check_disk(s),
        check_docker(),
        check_retention(s),
        *check_ports(ports, admin_port=admin_port),
        check_backup(backup_dir),
    ]


# ── Live checks ──────────────────────────────────────────────────────────────

ToolCaller = Callable[[str, dict[str, Any]], Awaitable[Any]]


async def check_readiness(url: str) -> Check:
    """`/readyz` distinguishes "running" from "collecting": a server whose database has gone
    away still answers attackers perfectly while storing nothing."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url.rstrip("/") + "/readyz")
    except Exception as e:
        return Check("readiness", FAIL, f"{url}/readyz unreachable: {type(e).__name__}",
                     "Is the server running, and is METRICS_PORT right?")  # fmt: skip
    body: dict[str, Any] = {}
    with contextlib.suppress(ValueError):
        body = response.json()
    if response.status_code == 200:
        return Check("readiness", PASS, f"/readyz ok ({body.get('checks', {})})")
    return Check("readiness", FAIL, f"/readyz {response.status_code}: {body.get('checks', body)}",
                 "Fix the failing check before exposing anything.")  # fmt: skip


def _dicts(value: Any) -> list[dict[str, Any]] | None:
    """`value` as a list of dicts, or None if it is anything else (an error object, a string,
    a list with something else in it)."""
    if isinstance(value, list) and all(isinstance(v, dict) for v in value):
        return value
    return None


async def control_plane_checks(call: ToolCaller, *, self_test: bool) -> list[Check]:
    """Ask the running server about itself. `call(tool, arguments)` returns the tool's data.

    Every answer is checked for its shape as well as its content: an error object where a list
    was expected must not read as "no sensors are dead"."""
    out: list[Check] = []
    try:
        ping = await call("ping", {})
    except Exception as e:
        return [Check("control plane", FAIL, f"ping failed: {type(e).__name__}: {e}",
                      "Check --mcp-url and the token.")]  # fmt: skip
    role = ping.get("role") if isinstance(ping, dict) else None
    out.append(
        Check("control plane", PASS, "ping ok")
        if role == "owner"
        else Check(
            "sensor ownership",
            FAIL,
            f"this server is '{role}', not the sensor owner",
            "Another process owns the sensors for this database; stop it or use that one.",
        )  # fmt: skip
    )

    listed = await call("honeypot_list", {})
    sensors = _dicts(listed.get("honeypots")) if isinstance(listed, dict) else None
    if sensors is None or any("name" not in h for h in sensors):
        out.append(Check("sensors", FAIL, "honeypot_list did not return a list of sensors",
                         "The server answered unexpectedly; check its log."))  # fmt: skip
        return out
    running = [h for h in sensors if h.get("status") == "running"]
    if not running:
        out.append(Check("sensors", FAIL, "no honeypot is running",
                         "Deploy the estate (deception_plan, then deception_deploy_plan)."))  # fmt: skip
        return out
    broken = [str(h["name"]) for h in sensors if h.get("status") not in ("running", "stopped")]
    out.append(
        Check("sensors", PASS, f"{len(running)} running")
        if not broken
        else Check("sensors", FAIL, f"in error: {', '.join(broken)}", "honeypot_status shows why.")
    )

    status = await call("honeypot_status", {})
    health = _dicts(status.get("honeypots")) if isinstance(status, dict) else None
    answered = {str(h.get("name")): h.get("alive") for h in health or []}
    not_alive = [str(h["name"]) for h in running if answered.get(str(h["name"])) is not True]
    if health is None:
        out.append(Check("sensor health", FAIL, "honeypot_status did not return the sensor list",
                         "The server answered unexpectedly; check its log."))  # fmt: skip
    elif not_alive:
        out.append(Check("sensor health", FAIL, f"not confirmed alive: {', '.join(not_alive)}",
                         "See honeypot_status (a read-only process cannot probe)."))  # fmt: skip
    else:
        out.append(Check("sensor health", PASS, "every running sensor answered its probe"))

    if self_test:
        failures = []
        for sensor in running:
            result = await call("honeypot_self_test", {"name": sensor["name"]})
            if not (isinstance(result, dict) and result.get("alert_received") is True):
                detail = (
                    result.get("detail") or result.get("error")
                    if isinstance(result, dict)
                    else None
                )
                failures.append(f"{sensor['name']} ({detail or 'no result'})")
        out.append(
            Check("end-to-end self-test", PASS, f"{len(running)} sensor(s): probe became an alert")
            if not failures
            else Check(
                "end-to-end self-test",
                FAIL,
                "; ".join(failures),
                "A sensor that answers but records nothing is the worst failure.",
            )  # fmt: skip
        )
    else:
        out.append(Check("end-to-end self-test", SKIP, "--no-self-test"))

    listed_subs = await call("alert_subscriptions_list", {})
    subscriptions = listed_subs.get("subscriptions") if isinstance(listed_subs, dict) else None
    if not isinstance(subscriptions, list):
        out.append(Check("alert channel", WARN, "could not read the alert subscriptions",
                         "alert_subscriptions_list returned something unexpected."))  # fmt: skip
    elif not subscriptions:
        out.append(Check("alert channel", WARN, "nobody is subscribed: a CRITICAL will wait for you to look",
                         "alert_subscribe(label=..., url=..., format='slack', severity_threshold='high')"))  # fmt: skip
    else:
        out.append(Check("alert channel", PASS, f"{len(subscriptions)} subscription(s)"))
    return out


def _mcp_caller(url: str, token: str | None) -> tuple[ToolCaller, Callable[[], Awaitable[None]]]:
    """A tool caller backed by a FastMCP client, plus a coroutine that closes it."""
    from fastmcp import Client

    client = Client(url, auth=token) if token else Client(url)
    state = {"opened": False}

    async def call(tool: str, arguments: dict[str, Any]) -> Any:
        if not state["opened"]:
            await client.__aenter__()
            state["opened"] = True
        result = await client.call_tool(tool, arguments, raise_on_error=False)
        if result.is_error:
            raise RuntimeError(str(result.content)[:200])
        return result.data

    async def close() -> None:
        if state["opened"]:
            await client.__aexit__(None, None, None)

    return call, close


# ── CLI ──────────────────────────────────────────────────────────────────────

_MARK = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL", SKIP: "skip"}


def render(checks: list[Check]) -> str:
    lines = []
    for check in checks:
        lines.append(f"[{_MARK[check.status]}] {check.name}: {check.detail}")
        if check.fix and check.status in (WARN, FAIL):
            lines.append(f"        -> {check.fix}")
    failed = sum(c.status == FAIL for c in checks)
    warned = sum(c.status == WARN for c in checks)
    lines.append(
        f"\n{failed} failed, {warned} warning(s), {sum(c.status == PASS for c in checks)} passed"
    )
    return "\n".join(lines)


def exit_code(checks: list[Check], *, strict: bool) -> int:
    bad = {FAIL, WARN} if strict else {FAIL}
    return 1 if any(c.status in bad for c in checks) else 0


def _ports(text: str) -> list[tuple[int, str]]:
    """`22,80,53/udp,5060/both` -> [(22, 'tcp'), (80, 'tcp'), (53, 'udp'), (5060, 'both')]."""
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        number, _, proto = part.partition("/")
        proto = proto.strip().lower() or "tcp"
        if not (number.isascii() and number.isdigit() and 1 <= int(number) <= 65535):
            raise argparse.ArgumentTypeError(f"bad port {part!r} (expected 1-65535)")
        if proto not in ("tcp", "udp", "both"):
            raise argparse.ArgumentTypeError(f"bad protocol in {part!r} (tcp, udp or both)")
        out.append((int(number), proto))
    return out


def _admin_port() -> int | None:
    """The server port of the SSH session this is run from, if any."""
    parts = os.environ.get("SSH_CONNECTION", "").split()
    if len(parts) == 4 and parts[3].isascii() and parts[3].isdigit() and int(parts[3]) <= 65535:
        return int(parts[3])
    return None


async def run(args: argparse.Namespace) -> list[Check]:
    s = get_settings()
    ports = args.ports or []
    admin_port = args.admin_port or _admin_port()
    checks = static_checks(
        s, ports=ports, admin_port=admin_port,
        backup_dir=Path(args.backup_dir) if args.backup_dir else None,
    )  # fmt: skip
    if not args.no_host_checks:
        from honeypot_mcp.hardening.hostcheck import host_checks

        listening = args.listen_ports or ports
        checks.extend(host_checks(listening, admin_port, [p for p, _ in (*ports, *listening)]))
    if args.metrics_url:
        checks.append(await check_readiness(args.metrics_url))
    if args.mcp_url:
        call, close = _mcp_caller(
            args.mcp_url, args.token or os.environ.get("HONEYPOT_PREFLIGHT_TOKEN")
        )
        try:
            checks.extend(await control_plane_checks(call, self_test=not args.no_self_test))
        except Exception as e:
            checks.append(Check("control plane", FAIL, f"{type(e).__name__}: {e}"))
        finally:
            await close()
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="honeypot-preflight", description=__doc__.split("\n\n")[0]
    )
    parser.add_argument(
        "--ports",
        type=_ports,
        help="honeypot ports you plan to use, e.g. 22,80,3389,53/udp,5060/both",
    )
    parser.add_argument(
        "--listen-ports",
        type=_ports,
        help="ports the engines will LISTEN on after any firewall redirect (e.g. 8080,1110,3389,22); "
        "defaults to --ports. Used to find unplanned public listeners.",
    )
    parser.add_argument(
        "--admin-port", type=int, help="admin SSH port (default: read from SSH_CONNECTION)"
    )
    parser.add_argument(
        "--no-host-checks",
        action="store_true",
        help="skip the Linux host checks (firewall, sshd, ...)",
    )
    parser.add_argument("--metrics-url", help="e.g. http://127.0.0.1:9090 (checks /readyz)")
    parser.add_argument(
        "--mcp-url", help="e.g. http://127.0.0.1:8000/mcp (checks sensors and alerting)"
    )
    parser.add_argument(
        "--token", help="control-plane token (or HONEYPOT_PREFLIGHT_TOKEN); operator is enough"
    )
    parser.add_argument("--backup-dir", help="directory scripts/backup.sh writes to")
    parser.add_argument("--no-self-test", action="store_true", help="skip the per-sensor probe")
    parser.add_argument("--strict", action="store_true", help="treat warnings as failures")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    checks = asyncio.run(run(args))
    print(json.dumps([asdict(c) for c in checks], indent=2) if args.json else render(checks))
    return exit_code(checks, strict=args.strict)


if __name__ == "__main__":
    sys.exit(main())
