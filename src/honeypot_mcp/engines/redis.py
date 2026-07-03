"""Redis honeypot engine — RESP protocol with believable command responses.

Exposed unauthenticated Redis is one of the most heavily-exploited
configurations on the public internet. Mirai-family and cryptominer
campaigns all check for it because the classic exploit (`CONFIG SET dir`
+ `CONFIG SET dbfilename` + `BGSAVE` to drop a keypair into ~/.ssh) is
trivial and reliable. SLAVEOF / REPLICAOF to an attacker-controlled
master is the modern variant.

This engine speaks just enough RESP (RFC-ish — see https://redis.io/docs/
reference/protocol-spec) to look like a real unauthenticated Redis until
the attacker tries to actually exfil keys. Specifically:

* `AUTH` — logs the credential and replies `-WRONGPASS`.
* `PING` / `SELECT` / `COMMAND` / `QUIT` — terse correct responses.
* `INFO` — synthesized real-looking server-info block.
* Keyspace (`SET`/`GET`/`DEL`/`EXISTS`/`TYPE`/`KEYS`/`STRLEN`/`TTL`/`DBSIZE`/
  `FLUSHALL`) — a real bounded in-memory keyspace, so the attacker's writes
  read back and the exploit tool believes it succeeded.
* `CONFIG GET` — reflects the attacker's own `CONFIG SET`s, then falls back to
  believable defaults. Empty replies were a tell that aborted the exploit.
* `CONFIG SET <dir|dbfilename>` — persisted and escalated: redirecting the RDB
  write path is the setup half of the unauth-RCE dropper.
* `SAVE` / `BGSAVE` — when the write path was redirected, this is where the
  file drop would land. We capture the full payload — target path + every
  planted key — as a CRITICAL `redis_rce_dropper` event, and classify the
  payload (SSH key / cron / webshell / reverse shell).
* `SLAVEOF` / `REPLICAOF` — replies `+OK` and escalates: the rogue-replica
  exploit.
* `EVAL` — captures the Lua script body (sandbox-escape research) and `-ERR`.
* Anything else — logs the command and replies `-ERR unknown command`.

The full RCE chain therefore plays out end-to-end
(`CONFIG SET dir /root/.ssh` → `CONFIG SET dbfilename authorized_keys` →
`SET x "ssh-rsa AAAA…"` → `SAVE`), and we come away with the attacker's actual
SSH public key and target path instead of just a truncated first command.

Every login-shaped command (`AUTH`) is fed through `credential_match.match`
so planted CREDENTIAL honeytokens trigger across Redis just like SSH/FTP.

Memory is bounded: at most `_MAX_KEYS` keys and `_MAX_VALUE_BYTES` per value,
so the keyspace can't be used to exhaust the honeypot.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


# Synthesised INFO response. Real Redis 7.x emits ~150 fields; we ship the
# section headers + a curated subset that scanners look at for version
# pinning. Build matches a stock Debian package install.
_INFO_RESPONSE = (
    "# Server\r\n"
    "redis_version:7.0.5\r\n"
    "redis_git_sha1:00000000\r\n"
    "redis_git_dirty:0\r\n"
    "redis_build_id:abcdef0123456789\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 5.15.0-101-generic x86_64\r\n"
    "arch_bits:64\r\n"
    "multiplexing_api:epoll\r\n"
    "process_id:1\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:84231\r\n"
    "\r\n"
    "# Clients\r\n"
    "connected_clients:1\r\n"
    "\r\n"
    "# Memory\r\n"
    "used_memory:854288\r\n"
    "used_memory_human:834.27K\r\n"
    "\r\n"
    "# Persistence\r\n"
    "loading:0\r\n"
    "rdb_changes_since_last_save:0\r\n"
    "\r\n"
    "# Stats\r\n"
    "total_connections_received:42\r\n"
    "total_commands_processed:100\r\n"
    "\r\n"
    "# Replication\r\n"
    "role:master\r\n"
    "connected_slaves:0\r\n"
    "\r\n"
    "# CPU\r\n"
    "used_cpu_sys:1.23\r\n"
    "used_cpu_user:0.45\r\n"
    "\r\n"
    "# Keyspace\r\n"
    "db0:keys=0,expires=0,avg_ttl=0\r\n"
)


def _bulk_string(s: str) -> bytes:
    body = s.encode()
    return f"${len(body)}\r\n".encode() + body + b"\r\n"


def _simple(s: str) -> bytes:
    return f"+{s}\r\n".encode()


def _error(s: str) -> bytes:
    return f"-{s}\r\n".encode()


def _integer(n: int) -> bytes:
    return f":{n}\r\n".encode()


def _empty_array() -> bytes:
    return b"*0\r\n"


def _null_bulk() -> bytes:
    return b"$-1\r\n"


def _classify_payload(value: str) -> str | None:
    """Recognise the payload an attacker plants in a Redis value during the
    RDB-write RCE. Returns a short label or None. This is the high-value intel:
    it tells you exactly what they'd have implanted."""
    v = value.strip()
    if "ssh-rsa " in v or "ssh-ed25519 " in v or "ssh-dss " in v or "ecdsa-sha2-" in v:
        return "ssh_authorized_key"
    lowered = v.lower()
    # Cron line: has a schedule and a shell fetch/exec.
    if ("* * * * *" in v or "@reboot" in lowered) and any(
        tok in lowered for tok in ("curl", "wget", "bash", "sh ", "/bin/")
    ):
        return "cron_reverse_shell"
    if v.startswith("<?php") or "<?=" in v:
        return "php_webshell"
    if "/bin/bash -i" in v or "bash -i >&" in v or "/dev/tcp/" in v:
        return "reverse_shell"
    return None


def _array(items: list[str]) -> bytes:
    out = f"*{len(items)}\r\n".encode()
    for item in items:
        out += _bulk_string(item)
    return out


# Keyspace safety bounds — an attacker could otherwise SET millions of huge
# keys to exhaust honeypot memory. We accept enough to look real and to capture
# the dropper payload, and silently cap beyond that.
_MAX_KEYS = 256
_MAX_VALUE_BYTES = 65536

# Default CONFIG GET answers for the parameters attackers probe before the
# dir/dbfilename exploit — believable values for a stock Debian package install.
_CONFIG_DEFAULTS = {
    "dir": "/var/lib/redis",
    "dbfilename": "dump.rdb",
    "maxmemory": "0",
    "maxmemory-policy": "noeviction",
    "save": "3600 1 300 100 60 10000",
    "appendonly": "no",
    "requirepass": "",
    "bind": "127.0.0.1 -::1",
    "protected-mode": "yes",
}


class _RESPParser:
    """Minimal RESP parser handling both inline (`PING\\r\\n`) and bulk-string
    array (`*N\\r\\n$len\\r\\nfoo\\r\\n…`) command forms.

    Returns `(args, consumed_bytes)` from `try_parse`; if there isn't enough
    data yet, returns `(None, 0)`.
    """

    @staticmethod
    def try_parse(buf: bytes) -> tuple[list[str] | None, int]:
        if not buf:
            return None, 0
        if buf[:1] == b"*":
            return _RESPParser._parse_array(buf)
        # Inline command form — single line ending in CRLF.
        end = buf.find(b"\r\n")
        if end == -1:
            return None, 0
        line = buf[:end].decode("utf-8", errors="replace")
        return line.split(), end + 2

    @staticmethod
    def _parse_array(buf: bytes) -> tuple[list[str] | None, int]:
        # `*N\r\n` followed by N bulk strings: `$len\r\nvalue\r\n`.
        end = buf.find(b"\r\n")
        if end == -1:
            return None, 0
        try:
            n_args = int(buf[1:end])
        except ValueError:
            return [], end + 2  # malformed — skip
        if n_args <= 0:
            return [], end + 2

        pos = end + 2
        args: list[str] = []
        for _ in range(n_args):
            if pos >= len(buf) or buf[pos : pos + 1] != b"$":
                return None, 0
            len_end = buf.find(b"\r\n", pos)
            if len_end == -1:
                return None, 0
            try:
                str_len = int(buf[pos + 1 : len_end])
            except ValueError:
                return None, 0
            value_start = len_end + 2
            value_end = value_start + str_len
            if value_end + 2 > len(buf):
                return None, 0
            args.append(buf[value_start:value_end].decode("utf-8", errors="replace"))
            pos = value_end + 2
        return args, pos


class _RedisProtocol(asyncio.Protocol):
    def __init__(self, honeypot_name: str, honeypot_id: int | None) -> None:
        self._name = honeypot_name
        self._hp_id = honeypot_id
        self._transport: asyncio.Transport | None = None
        self._peer: tuple[str, int] = ("0.0.0.0", 0)
        self._buf = b""
        # Per-connection state so the full RCE chain plays out: the attacker
        # SETs a key (usually an SSH pubkey or cron line), CONFIG SETs dir +
        # dbfilename to redirect the RDB write, then SAVE/BGSAVE. We keep the
        # keyspace + overridden config so GET/CONFIG GET reflect their writes
        # (they verify), then capture the whole payload at SAVE time.
        self._store: dict[str, str] = {}
        self._config: dict[str, str] = {}
        self._save_reported = False

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self._peer = transport.get_extra_info("peername") or ("0.0.0.0", 0)
        asyncio.create_task(self._record("redis_connection", AlertSeverity.LOW, {}))

    def data_received(self, data: bytes) -> None:
        self._buf += data
        while True:
            args, consumed = _RESPParser.try_parse(self._buf)
            if args is None:
                return
            self._buf = self._buf[consumed:]
            if args:
                self._dispatch(args)

    def _dispatch(self, args: list[str]) -> None:
        t = self._transport
        if t is None:
            return
        verb = args[0].upper()

        if verb == "PING":
            t.write(_simple("PONG"))
            return

        if verb == "QUIT":
            t.write(_simple("OK"))
            t.close()
            return

        if verb == "SELECT":
            t.write(_simple("OK"))
            return

        if verb == "COMMAND":
            # Real Redis emits a huge nested array describing every command.
            # An empty array is wrong but acceptable for a "limited mode"
            # server and most clients tolerate it.
            t.write(_empty_array())
            return

        if verb == "AUTH":
            # `AUTH <password>` (legacy) or `AUTH <user> <password>` (Redis 6+).
            if len(args) == 2:
                user, pwd = "default", args[1]
            elif len(args) >= 3:
                user, pwd = args[1], args[2]
            else:
                t.write(_error("ERR wrong number of arguments for 'auth' command"))
                return
            t.write(_error("WRONGPASS invalid username-password pair or user is disabled."))
            asyncio.create_task(self._record_auth_attempt(user, pwd))
            return

        if verb == "INFO":
            t.write(_bulk_string(_INFO_RESPONSE))
            asyncio.create_task(
                self._record("redis_info_probe", AlertSeverity.MEDIUM, {"args": args[1:]})
            )
            return

        if verb == "CONFIG":
            self._handle_config(args, t)
            return

        if verb in ("SLAVEOF", "REPLICAOF"):
            # Classic rogue-replica exploit: point the server at an attacker-
            # controlled master, the master streams a malicious replication
            # payload. We accept with +OK so the attacker thinks it worked
            # — gives us their next move (often EVAL / MODULE LOAD).
            t.write(_simple("OK"))
            asyncio.create_task(
                self._record(
                    "redis_rogue_replica",
                    AlertSeverity.HIGH,
                    {"verb": verb, "args": args[1:]},
                )
            )
            return

        if verb == "EVAL" or verb == "EVALSHA":
            # Lua scripting — sandbox-escape research target. Capture the
            # script body verbatim.
            script = args[1] if len(args) > 1 else ""
            t.write(_error("ERR unknown command (script blocked)"))
            asyncio.create_task(
                self._record(
                    "redis_eval",
                    AlertSeverity.HIGH,
                    {"script_preview": script[:2048]},
                )
            )
            return

        if verb in ("MODULE",):
            # MODULE LOAD with a malicious .so — another known RCE path.
            t.write(_error("ERR module loading is disabled"))
            asyncio.create_task(
                self._record(
                    "redis_module_load",
                    AlertSeverity.HIGH,
                    {"args": args[1:]},
                )
            )
            return

        if verb in ("SAVE", "BGSAVE", "BGREWRITEAOF"):
            self._handle_save(verb, t)
            return

        # ── Keyspace commands ────────────────────────────────────────────────
        # Modelling these is what lets the RCE dropper chain complete: the
        # attacker SETs their payload key, and GET/EXISTS/DBSIZE reflect it so
        # the exploit tool believes it worked and proceeds to SAVE.
        if verb == "SET":
            self._handle_set(args, t)
            return

        if verb == "GET":
            key = args[1] if len(args) > 1 else ""
            val = self._store.get(key)
            t.write(_null_bulk() if val is None else _bulk_string(val))
            return

        if verb in ("DEL", "UNLINK"):
            removed = sum(1 for k in args[1:] if self._store.pop(k, None) is not None)
            t.write(_integer(removed))
            return

        if verb == "EXISTS":
            t.write(_integer(sum(1 for k in args[1:] if k in self._store)))
            return

        if verb == "TYPE":
            key = args[1] if len(args) > 1 else ""
            t.write(_simple("string") if key in self._store else _simple("none"))
            return

        if verb == "STRLEN":
            key = args[1] if len(args) > 1 else ""
            t.write(_integer(len(self._store.get(key, ""))))
            return

        if verb == "KEYS":
            # Real KEYS honours a glob; scanners almost always send `*`. Matching
            # exactly is fine — the keys present are the attacker's own.
            import fnmatch

            pattern = args[1] if len(args) > 1 else "*"
            matched = [k for k in self._store if fnmatch.fnmatch(k, pattern)]
            t.write(_array(matched))
            return

        if verb == "TTL" or verb == "PTTL":
            key = args[1] if len(args) > 1 else ""
            t.write(_integer(-1 if key in self._store else -2))
            return

        if verb in ("FLUSHALL", "FLUSHDB"):
            self._store.clear()
            t.write(_simple("OK"))
            return

        if verb == "DBSIZE":
            t.write(_integer(len(self._store)))
            return

        # Unknown / un-modelled command — log and respond like Redis 7.
        t.write(_error(f"ERR unknown command `{args[0]}`"))
        asyncio.create_task(
            self._record(
                "redis_command",
                AlertSeverity.LOW,
                {"args": args},
            )
        )

    def _handle_set(self, args: list[str], t: asyncio.Transport) -> None:
        if len(args) < 3:
            t.write(_error("ERR wrong number of arguments for 'set' command"))
            return
        key, value = args[1], args[2]
        # Bound memory: cap key count and value size. Beyond the cap we still
        # reply +OK (looks normal) but don't grow the store.
        if len(self._store) < _MAX_KEYS or key in self._store:
            self._store[key] = value[:_MAX_VALUE_BYTES]
        t.write(_simple("OK"))
        # An SSH public key or cron line landing in a Redis value is the dropper
        # payload itself — flag it HIGH even before the SAVE.
        severity = AlertSeverity.MEDIUM
        payload_kind = _classify_payload(value)
        if payload_kind:
            severity = AlertSeverity.HIGH
        asyncio.create_task(
            self._record(
                "redis_key_set",
                severity,
                {"key": key, "value": value[:2048], "payload_kind": payload_kind},
            )
        )

    def _handle_save(self, verb: str, t: asyncio.Transport) -> None:
        # SAVE/BGSAVE writes the keyspace to <dir>/<dbfilename>. When the
        # attacker has redirected those via CONFIG SET, this is the moment the
        # RDB-write RCE would have dropped their file. Capture the complete
        # payload: target path + every key they planted.
        if verb == "BGSAVE":
            t.write(_simple("Background saving started"))
        elif verb == "BGREWRITEAOF":
            t.write(_simple("Background append only file rewriting started"))
        else:
            t.write(_simple("OK"))

        target_dir = self._config.get("dir")
        target_file = self._config.get("dbfilename")
        redirected = target_dir is not None or target_file is not None
        if redirected and self._store and not self._save_reported:
            self._save_reported = True
            target_path = f"{target_dir or _CONFIG_DEFAULTS['dir']}/{target_file or 'dump.rdb'}"
            payloads = [
                {"key": k, "value": v[:2048], "payload_kind": _classify_payload(v)}
                for k, v in self._store.items()
            ]
            asyncio.create_task(
                self._record(
                    "redis_rce_dropper",
                    AlertSeverity.CRITICAL,
                    {
                        "verb": verb,
                        "target_path": target_path,
                        "config": dict(self._config),
                        "planted_keys": payloads,
                        "technique": "redis RDB-write file drop (CVE-class unauth RCE)",
                    },
                )
            )

    def _handle_config(self, args: list[str], t: asyncio.Transport) -> None:
        if len(args) < 2:
            t.write(_error("ERR wrong number of arguments for 'config' command"))
            return
        sub = args[1].upper()
        if sub == "GET":
            param = args[2] if len(args) > 2 else "*"
            # Reflect the attacker's own CONFIG SETs first (they verify their
            # `dir`/`dbfilename` writes took), then fall back to believable
            # defaults. A real unauth Redis answers these; empty replies were a
            # tell that broke the exploit chain we want to observe.
            key = param.lower()
            value = self._config.get(key, _CONFIG_DEFAULTS.get(key))
            t.write(_array([param, value]) if value is not None else _empty_array())
            asyncio.create_task(
                self._record(
                    "redis_config_get",
                    AlertSeverity.MEDIUM,
                    {"parameter": param},
                )
            )
            return
        if sub == "SET":
            param = args[2] if len(args) > 2 else ""
            value = args[3] if len(args) > 3 else ""
            # Persist the override so a follow-up CONFIG GET reflects it and the
            # SAVE handler knows where the drop is aimed.
            self._config[param.lower()] = value
            severity = AlertSeverity.MEDIUM
            # The classic exploit pattern: redirect `dir` + `dbfilename` to bend
            # BGSAVE into dropping a file at an attacker-controlled location.
            if param.lower() in ("dir", "dbfilename", "save"):
                severity = AlertSeverity.HIGH
            t.write(_simple("OK"))
            asyncio.create_task(
                self._record(
                    "redis_config_set",
                    severity,
                    {"parameter": param, "value": value},
                )
            )
            return
        if sub == "REWRITE":
            t.write(_error("ERR The server is running without a config file"))
            return
        t.write(_error(f"ERR unknown CONFIG subcommand or wrong number of arguments for '{sub}'"))

    async def _record_auth_attempt(self, user: str, pwd: str) -> None:
        # Cross-reference against planted CREDENTIAL tokens so a fake
        # password tried against Redis triggers the same CRITICAL escalation
        # the SSH / HTTP / FTP / SMTP engines get for free via the buffer.
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type="redis_auth_attempt",
                payload={"username": user, "password": pwd, "service": "redis"},
                severity=AlertSeverity.HIGH,
            )
        )

    async def _record(self, event_type: str, severity: AlertSeverity, payload: dict) -> None:
        await submit_event(
            PendingEvent(
                honeypot_id=self._hp_id,
                source_ip=self._peer[0],
                source_port=self._peer[1],
                event_type=event_type,
                payload=payload,
                severity=severity,
            )
        )

    def connection_lost(self, exc: Exception | None) -> None:
        pass


class RedisEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._servers: dict[str, asyncio.AbstractServer] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        loop = asyncio.get_event_loop()
        server = await loop.create_server(
            lambda: _RedisProtocol(name, hp_id),
            host="0.0.0.0",
            port=port,
        )
        cid = f"redis-{secrets.token_hex(8)}"
        self._servers[cid] = server
        log.info("Redis honeypot '%s' listening on port %d", name, port)
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        server = self._servers.pop(container_id, None)
        if server:
            server.close()
            await server.wait_closed()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {"running": container_id in self._servers, "type": "asyncio_redis"}

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return ["Redis honeypot is in-process — events are stored directly in the database."]
