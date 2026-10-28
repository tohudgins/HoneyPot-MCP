"""Honeypot management MCP tools."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import difflib
import errno
import logging
import secrets
import socket
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, update

from honeypot_mcp import instance_lock
from honeypot_mcp.deception.capabilities import BY_TYPE, resolve_type, suggest_types
from honeypot_mcp.deception.planner import reserved_ports
from honeypot_mcp.engines import get_engine
from honeypot_mcp.engines.http_personas import all_persona_ids as _http_persona_ids
from honeypot_mcp.engines.ssh_personas import all_persona_ids as _ssh_persona_ids
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries, rollups
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.models import Alert, Honeypot, HoneypotStatus, HoneypotType
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._format import mark_untrusted, validate_honeypot_name

log = logging.getLogger(__name__)
_SELF_TEST_SECONDS = 10
_SELF_TEST_DOCKER_SECONDS = 30

# Upper bound on one engine's stop. An in-process engine's server.wait_closed()
# can wait on a lingering attacker connection indefinitely, and retiring a
# sensor must not depend on the attacker hanging up.
_ENGINE_STOP_TIMEOUT_SECONDS = 15.0

# What a person might say a sensor is in the middle of: used to read a status word and to cap what
# a list tool puts in front of a model.
_STATUS_NAMES = ", ".join(s.value for s in HoneypotStatus)
_NAME_LIST_CAP = 30
_LIST_CAP = 100
_PORT_SCAN_SPAN = 200
_LOG_LINE_CHARS = 240
_STATUS_LOG_LINES = 20
_LOG_TOTAL_CHARS = 8000
_TRANSPORT_LABEL = {"tcp": "tcp", "udp": "udp", "both": "tcp+udp"}


def _type_error(value: Any, *, extra: str = "") -> dict[str, Any]:
    """The error for a sensor type nobody offers, with the closest valid ones and all of them."""
    near = suggest_types(value) if isinstance(value, str) else []
    return {
        "error": f"Unknown honeypot type '{value}'.",
        "hint": (f"Did you mean {', '.join(near)}? " if near else "")
        + f"Valid types: {', '.join(BY_TYPE)}{extra}. `deception_profiles` says what each captures.",
    }


def _parse_status(value: Any) -> tuple[HoneypotStatus | None, dict[str, Any] | None]:
    if value is None or value == "":
        return None, None
    try:
        return HoneypotStatus(str(value).strip().lower()), None
    except ValueError:
        return None, {
            "error": f"Unknown status '{value}'.",
            "hint": f"Use one of: {_STATUS_NAMES}.",
        }


def _port_is_free(port: int, transport: str) -> bool:
    """Whether this host can listen on `port` right now (every interface, as the engines do)."""
    kinds = {"tcp": (socket.SOCK_STREAM,), "udp": (socket.SOCK_DGRAM,)}.get(
        transport, (socket.SOCK_STREAM, socket.SOCK_DGRAM)
    )
    for kind in kinds:
        with socket.socket(socket.AF_INET, kind) as probe:
            try:
                probe.bind(("0.0.0.0", port))  # noqa: S104 - the engines bind the same way
            except OSError:
                return False
    return True


def _free_port(start: int, transport: str, taken: set[int]) -> int | None:
    """The first port from `start` that nothing here uses or listens on, or None."""
    candidates = list(range(max(start, 1), min(start + _PORT_SCAN_SPAN, 65535) + 1))
    if start < 1024:  # privileged ports usually cannot be bound; fall back to a high range
        candidates += range(20000, 20000 + _PORT_SCAN_SPAN)
    reserved = reserved_ports()
    for port in candidates:
        if port not in taken and port not in reserved and _port_is_free(port, transport):
            return port
    return None


def _auto_name(hp_type: str, port: int, taken: set[str]) -> str:
    """`ftp-2121`: the kind and where it listens, which is how a person refers to a sensor."""
    base = f"{hp_type}-{port}"
    name, n = base, 1
    while name in taken:
        n += 1
        name = f"{base}-{n}"
    return name


def _bind_problem(exc: BaseException) -> str | None:
    """`in_use` or `privileged` when a start failure is about the port, else None."""
    text = str(exc).lower()
    code = getattr(exc, "errno", None)
    if code == errno.EADDRINUSE or "address already in use" in text or "already allocated" in text:
        return "in_use"
    if code in (errno.EACCES, errno.EPERM) or "permission denied" in text:
        return "privileged"
    return None


async def _find_sensor(session: Any, name: Any) -> tuple[Honeypot | None, dict[str, Any] | None]:
    """The sensor a person meant: its exact name, the same ignoring case, or a type or port that
    only one sensor has ("the ftp one", "2121"). An error object, with what exists, otherwise."""
    wanted = str(name).strip() if name is not None else ""
    hp = await queries.get_honeypot_by_name(session, wanted) if wanted else None
    if hp is not None:
        return hp, None
    sensors = await queries.list_honeypots(session)
    lowered = wanted.lower()
    matches = [h for h in sensors if h.name.lower() == lowered]
    if not matches and wanted:
        kind = resolve_type(wanted)
        if kind is not None:
            matches = [
                h
                for h in sensors
                if h.type.value == kind and h.status is not HoneypotStatus.STOPPED
            ]
        elif wanted.isdigit():
            matches = [h for h in sensors if h.port == int(wanted)]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, {
            "error": f"'{wanted}' matches {len(matches)} honeypots: {', '.join(h.name for h in matches)}.",
            "hint": "Say which one, by its exact name.",
        }
    names = [h.name for h in sensors]
    if not names:
        return None, {
            "error": f"No honeypot named '{wanted}': none are deployed.",
            "hint": "Deploy one with `honeypot_deploy`, or a whole environment with `deception_plan`.",
        }
    near = difflib.get_close_matches(wanted, names, n=3, cutoff=0.5)
    shown = ", ".join(names[:_NAME_LIST_CAP]) + (" ..." if len(names) > _NAME_LIST_CAP else "")
    return None, {
        "error": f"No honeypot named '{wanted}'.",
        "hint": (f"Did you mean {', '.join(near)}? " if near else "")
        + f"Deployed: {shown}. `honeypot_list` shows them all.",
    }


@mcp.tool(auth=require_role("operator"), **hints("honeypot_deploy"))
async def honeypot_deploy(
    type: str,
    port: int | None = None,
    name: str | None = None,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Deploy a honeypot (a decoy network service) and start capturing attacks against it.

    Use it for "deploy an SSH honeypot", "put a fake Redis on the network", "open a decoy MySQL".
    Only `type` is needed: a free port (the type's usual one when free) and a readable name are
    chosen, and the result says where it listens. Check it with `honeypot_self_test`. To copy an
    existing honeypot, deploy its `type` with its `config` (`honeypot_status` shows both). For
    several decoys that should look like one environment, use `deception_plan` instead.

    Args:
        type: ssh, telnet, http, smtp, ftp, dns, rdp, vnc, redis, mysql, elasticsearch, smb,
            postgresql, mongodb, mssql, memcached, snmp, ldap, docker_api, imap, sip, rsync, nfs,
            pop3 or kubernetes ("postgres", "k8s" work). ssh and telnet need Docker.
        port: Only if the user names a port ("on 8080"); otherwise leave out.
        name: Only if the user names it; otherwise something like `ftp-2121` is used.
        config: Rarely needed settings for this type; `deception_profiles` with the type lists them.
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    from honeypot_mcp.config import get_settings

    resolved_type = resolve_type(type)
    if resolved_type is None:
        return _type_error(type)
    type = resolved_type
    capability = BY_TYPE[type]
    resolved_config = {} if config is None else config
    # The same allow-list and value checks `honeypot_configure` applies: deploy,
    # deception_deploy_plan both store this dict verbatim and hand it to
    # the engine, so a CR/LF in a banner or an unread key slipped in here.
    if not isinstance(resolved_config, dict):
        return {"error": "config must be a JSON object.", "hint": _config_hint(type)}
    if err := _validate_config(type, resolved_config):
        return {"error": err, "hint": _config_hint(type)}
    if name and (err := validate_honeypot_name(name)):
        return {"error": err}
    if port is not None and not 1 <= port <= 65535:
        return {
            "error": f"Port {port} is out of range.",
            "hint": "Ports run from 1 to 65535; leave `port` out to have a free one chosen.",
        }

    hp_type = HoneypotType(type)
    engine = get_engine(hp_type)
    default_port = getattr(get_settings(), f"default_{type}_port", None)
    default_port = default_port or capability.default_port

    async with get_session() as session:
        rows = await queries.list_honeypots(session)
        taken_names = {h.name for h in rows}
        # A stopped sensor no longer holds its port; a paused one will want it back on resume.
        taken_ports = {
            h.port: h for h in rows if h.status in (HoneypotStatus.RUNNING, HoneypotStatus.PAUSED)
        }
        if name and name in taken_names:
            existing = next(h for h in rows if h.name == name)
            return {
                "error": f"A honeypot named '{name}' already exists (id={existing.id}, "
                f"status={existing.status.value}).",
                "hint": "Leave `name` out for a fresh one"
                + (
                    f", or remove it first with honeypot_stop(name='{name}', remove=true)."
                    if existing.status is HoneypotStatus.STOPPED
                    else "."
                ),
            }
        moved_from: int | None = None
        if port is None:
            resolved_port = _free_port(default_port, capability.transport, set(taken_ports))
            if resolved_port is None:
                return {
                    "error": f"No free port found at or after {default_port}.",
                    "hint": "Name a port that is free on this host with `port`.",
                }
            if resolved_port != default_port:
                moved_from = default_port
        else:
            resolved_port = port
            # A port collision with one of our own honeypots is the most common
            # deploy failure. Catching it here names the conflicting honeypot,
            # instead of surfacing a bind error from deep inside the engine.
            if conflict := taken_ports.get(port):
                alt = _free_port(port + 1, capability.transport, set(taken_ports))
                return {
                    "error": (
                        f"Port {port} is already used by honeypot "
                        f"'{conflict.name}' ({conflict.type.value}, id={conflict.id})."
                    ),
                    "hint": (
                        f"Use port {alt}, leave `port` out to have a free one chosen, "
                        f"or stop '{conflict.name}' first."
                        if alt
                        else f"Stop '{conflict.name}' first, or pick another port."
                    ),
                    **({"suggested_port": alt} if alt else {}),
                }
        resolved_name = name or _auto_name(type, resolved_port, taken_names)

        hp = Honeypot(
            name=resolved_name,
            type=hp_type,
            port=resolved_port,
            status=HoneypotStatus.STOPPED,
            config=resolved_config,
        )
        session.add(hp)
        await session.flush()
        hp_id = hp.id

    try:
        container_id = await engine.start(resolved_name, resolved_port, resolved_config)
    except Exception as e:
        # Roll back the reservation — otherwise the name is burned by a row
        # stuck in STOPPED and every retry gets "already exists".
        async with get_session() as session:
            hp_row = await queries.get_honeypot_by_id(session, hp_id)
            if hp_row:
                await session.delete(hp_row)
        await record_action(
            "honeypot_deploy",
            summary=f"failed to deploy {type} honeypot '{resolved_name}' on port {resolved_port}",
            arguments={"type": type, "port": resolved_port, "name": resolved_name},
            target=resolved_name,
            outcome="error",
            error=str(e),
        )
        problem = _bind_problem(e)
        failure: dict[str, Any] = {
            "error": f"Failed to start {type} honeypot on port {resolved_port}: {e}"
        }
        if problem is not None:
            alt = _free_port(resolved_port + 1, capability.transport, set(taken_ports))
            failure["error"] = (
                f"Port {resolved_port} is already in use by another program on this host."
                if problem == "in_use"
                else f"Port {resolved_port} cannot be opened here (ports below 1024 need root)."
            )
            failure["hint"] = (
                f"Retry with port={alt}, or leave `port` out and a free one is chosen."
                if alt
                else "Pick another port with `port`."
            )
            if alt:
                failure["suggested_port"] = alt
        elif capability.requires_docker:
            failure["hint"] = (
                f"{type} runs in a Docker container: check Docker is running and this user can "
                "reach it, then retry."
            )
        else:
            failure["hint"] = (
                "`honeypot_list` shows what is deployed; `honeypot_status` may say more."
            )
        return failure

    async with get_session() as session:
        hp_refresh = await queries.get_honeypot_by_id(session, hp_id)
        if hp_refresh:
            hp_refresh.status = HoneypotStatus.RUNNING
            hp_refresh.container_id = container_id

    await record_action(
        "honeypot_deploy",
        summary=f"deployed {type} honeypot '{resolved_name}' on port {resolved_port}",
        arguments={"type": type, "port": resolved_port, "name": resolved_name},
        target=resolved_name,
    )
    # The packet-capture filter is built from the deployed port set, so a new
    # sensor is invisible to it until the filter is rebuilt. Silent no-op when
    # capture is disabled, which is the default.
    from honeypot_mcp.pcap import refresh_capture

    await refresh_capture()
    result: dict[str, Any] = {
        "id": hp_id,
        "name": resolved_name,
        "type": type,
        "port": resolved_port,
        "status": "running",
        "listening_on": f"0.0.0.0:{resolved_port}/{_TRANSPORT_LABEL.get(capability.transport, 'tcp')}",
        "next_step": f"Verify it captures: honeypot_self_test(name='{resolved_name}').",
    }
    if capability.requires_docker:
        result["container_id"] = container_id
    if moved_from is not None:
        result["note"] = f"The usual port {moved_from} was taken, so it listens on {resolved_port}."
    if capability.public_cloud_caution:
        result["caution"] = capability.public_cloud_caution
    return result


def _row_verdict(status: HoneypotStatus, hits: int, total_hits: int) -> str:
    """A plain reading of one sensor row. In analysis mode nothing runs, so a row is only what the
    original server last recorded."""
    share = f"{round(100 * hits / total_hits)}% of the listed alerts" if total_hits else "no alerts"
    if instance_lock.in_analysis_mode():
        return f"Last recorded as {status.value} on the original server, {hits:,} alerts."
    if status == HoneypotStatus.ERROR:
        return "In error and not capturing: honeypot_status(name) shows why."
    if status == HoneypotStatus.PAUSED:
        return "Paused, so not capturing: honeypot_resume(name) restarts it."
    if status == HoneypotStatus.STOPPED:
        return f"Stopped; not capturing, history kept ({hits:,} alerts)."
    if hits == 0:
        return (
            "Running but has captured nothing: quiet, or not reachable by attackers; "
            "honeypot_status(name) probes it."
        )
    return f"Running; {hits:,} alerts ({share})."


def _list_headline(rows: list[dict[str, Any]], total: int, by_status: dict[str, int]) -> str:
    """One sentence for a sensor list: how many, in what state, busiest, and any silent ones."""
    if not rows:
        return "No honeypots match; honeypot_deploy or deception_plan creates some."
    n = f"{total} sensor{'s' if total != 1 else ''}"
    if len(by_status) == 1:
        state = f"all {next(iter(by_status))}"
    else:
        state = ", ".join(f"{c} {s}" for s, c in sorted(by_status.items()))
    if instance_lock.in_analysis_mode():
        text = (
            f"Analysis copy, nothing runs here: {n} as the original server last recorded ({state})"
        )
    else:
        text = f"{n}, {state}"
    total_hits = sum(int(r["hits"]) for r in rows)
    if total_hits:
        busiest = max(rows, key=lambda r: int(r["hits"]))
        pct = round(100 * int(busiest["hits"]) / total_hits)
        text += f"; busiest {busiest['name']} with {pct}% of alerts"
    if not instance_lock.in_analysis_mode():
        silent = [r["name"] for r in rows if r["status"] == "running" and not r["hits"]]
        if silent:
            text += f"; {len(silent)} running with zero events: check with honeypot_status(name)"
    other = [r["name"] for r in rows if r["status"] in ("error", "paused")]
    if other:
        text += f"; {len(other)} in error or paused: honeypot_status(name) says why"
    return text + "."


@mcp.tool(**hints("honeypot_list"))
async def honeypot_list(status: str | None = None, type: str | None = None) -> dict[str, Any]:
    """Which honeypots are deployed, and how busy is each?

    Use it for "what is running?", "list the sensors", "which ssh honeypots do I have?". One row
    per honeypot: name, type, port, status and the number of alerts it has captured. Use
    `honeypot_status` (no name) to confirm they actually answer, or with a name for one in detail.

    Args:
        status: Only honeypots in this state: running, paused, stopped or error. Omit for all.
        type: Only this kind (ssh, http, redis, ...). Omit for all.
    """
    hp_status, bad = _parse_status(status)
    if bad:
        return bad
    kind: str | None = None
    if type:
        kind = resolve_type(type)
        if kind is None:
            return _type_error(type)
    async with get_session() as session:
        honeypots = await queries.list_honeypots(session, status=hp_status)
        if kind:
            honeypots = [h for h in honeypots if h.type.value == kind]
        total = len(honeypots)
        by_status: dict[str, int] = {}
        for hp in honeypots:
            by_status[hp.status.value] = by_status.get(hp.status.value, 0) + 1
        shown = honeypots[:_LIST_CAP]
        ids = [hp.id for hp in shown]
        counts = await queries.get_hit_counts(session, ids) if ids else {}
        total_hits = sum(counts.get(i, 0) for i in ids)
        rows = [
            {
                "id": hp.id,
                "name": hp.name,
                "type": hp.type.value,
                "port": hp.port,
                "status": hp.status.value,
                "hits": counts.get(hp.id, 0),
                "created_at": hp.created_at.isoformat() if hp.created_at else None,
                "verdict": _row_verdict(hp.status, counts.get(hp.id, 0), total_hits),
            }
            for hp in shown
        ]
    if not rows:
        note = (
            "No honeypots match that filter. Omit it to see everything."
            if hp_status or kind
            else "No honeypots are deployed. Use `honeypot_deploy` for one, or `deception_plan` "
            "to design a whole environment."
        )
    elif total > len(rows):
        note = f"Showing {len(rows)} of {total}; ask for one status or type to narrow it."
    else:
        note = "`hits` is the number of alerts each captured, lifetime."
    return {
        "headline": _list_headline(rows, total, by_status),
        "count": total,
        "by_status": by_status,
        "honeypots": rows,
        "note": note,
    }


def _owned_elsewhere(hp: Honeypot) -> dict[str, Any] | None:
    """For a read-only process: why it cannot inspect this sensor's live engine state.

    In-process engines (everything except Cowrie) live in the owner's memory, so a
    second process asking one for its status gets "not running" while the database
    says RUNNING — and a TCP probe from here is indistinguishable from an attacker to
    the owner, which would record it as traffic. Docker-backed sensors are reachable
    through the daemon from anywhere, so they are inspected normally.
    """
    if instance_lock.in_analysis_mode():
        # A copy of someone else's database: its Docker-backed sensors are not on this machine, so
        # probing them would report every one of them dead.
        return {
            "note": "Analysis mode: this server holds a copy of a database and runs no sensors, so "
            "none is probed. The row below is what the original server last recorded.",
            "alive": None,
            "method": "not-probed",
        }
    if instance_lock.sensors_owned():
        return None
    capability = BY_TYPE.get(hp.type.value)
    if capability is not None and capability.requires_docker:
        return None
    return {
        "note": "This session is read-only; the process that owns the sensors holds this "
        "engine's live state, so it is not inspected from here. The database row below "
        "is the owner's last record.",
        "alive": None,
        "method": "not-probed",
    }


def _status_headline(
    hp: Honeypot, hits: int, engine_status: dict[str, Any], log_lines: list[str]
) -> str:
    """One sentence for a named sensor: alive/dead/not probed, port, log in a few words, hits."""
    where = f"{hp.name} ({hp.type.value}, port {hp.port})"
    recorded = hp.status.value
    if engine_status.get("method") == "not-probed":
        if instance_lock.in_analysis_mode():
            state = (
                f"was last recorded as {recorded} by the original server; nothing runs in this copy"
            )
        else:
            state = f"was last recorded as {recorded}; its live state belongs to another process"
    elif hp.status == HoneypotStatus.PAUSED:
        state = "is paused, so it captures nothing until honeypot_resume"
    elif hp.status == HoneypotStatus.STOPPED:
        state = "is stopped; it captures nothing and keeps its history"
    elif hp.status == HoneypotStatus.ERROR:
        state = "is in ERROR and not capturing"
    elif "error" in engine_status or engine_status.get("available") is False:
        state = "is recorded as running but its engine state could not be read"
    elif engine_status.get("running") is False:
        state = "is recorded as running but its engine reports it is not: likely it died"
    elif engine_status.get("running") is True:
        state = "is running"
    else:
        state = f"is recorded as {recorded}"
    log = ""
    if log_lines:
        low = " ".join(log_lines).lower()
        if "traceback" in low or "error" in low or "exception" in low:
            log = " Its log mentions errors."
        else:
            log = " Its log looks routine."
    got = f"{hits:,} alerts captured" if hits else "no alerts captured yet"
    return f"{where} {state}; {got}.{log}"


@mcp.tool(**hints("honeypot_status"))
async def honeypot_status(name: str | None = None) -> dict[str, Any]:
    """How is a honeypot doing, or are all of them answering on their ports?

    Use it for "how is the ftp honeypot doing?", "what is hp-ssh configured as?", "are all the
    sensors up?", "why is hp-ftp failing?". With a name: settings, engine state, recent alerts and
    the sensor's own last log lines. Without: probes every running one's port (and the Docker
    container for ssh/telnet). `honeypot_self_test` proves one records attacks.

    Args:
        name: The honeypot's name (its type or port also work when only one matches). Omit to
            probe every running honeypot.
    """
    if not name:
        return await _health_of_running()
    async with get_session() as session:
        hp, problem = await _find_sensor(session, name)
        if hp is None:
            return problem or {"error": f"No honeypot named '{name}'."}

        hits = await queries.get_honeypot_hit_count(session, hp.id)
        recent = await queries.get_recent_alerts(session, limit=10, honeypot_id=hp.id)

        engine = get_engine(hp.type)
        engine_status: dict[str, Any] = {}
        log_lines: list[str] = []
        log_note: str | None
        if foreign := _owned_elsewhere(hp):
            engine_status = foreign
            log_note = "The log is not read from this session."
        elif hp.container_id:
            try:
                engine_status = await engine.status(hp.container_id)
            except Exception as e:  # noqa: BLE001 - report it rather than fail the whole answer
                engine_status = {"error": f"Could not read the engine's state: {e}"}
            try:
                log_lines, log_note = _log_tail(
                    await engine.get_logs(hp.container_id, lines=_STATUS_LOG_LINES)
                )
            except Exception as e:  # noqa: BLE001 - the log is a bonus, never fail the status
                log_note = f"The log could not be read: {e}"
        else:
            log_note = f"Not running (status={hp.status.value}), so it has no log."

        config = dict(hp.config or {})
        endpoints = config.get("endpoints")
        if isinstance(endpoints, list) and len(endpoints) > 10:
            config["endpoints"] = endpoints[:10]
            config["endpoints_note"] = f"first 10 of {len(endpoints)}"

        result: dict[str, Any] = {
            "headline": _status_headline(hp, hits, engine_status, log_lines),
            "id": hp.id,
            "name": hp.name,
            "type": hp.type.value,
            "port": hp.port,
            "status": hp.status.value,
            "container_id": hp.container_id,
            "total_hits": hits,
            "config": config,
            "created_at": hp.created_at.isoformat() if hp.created_at else None,
            "engine_status": engine_status,
            "recent_alerts": [
                {
                    "id": a.id,
                    "source_ip": a.source_ip,
                    "event_type": a.event_type,
                    "severity": a.severity.value,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in recent
            ],
            "recent_log": log_lines,
            "note": (
                "The newest 10 alerts are listed; use `alerts_recent` or `alerts_search` for more."
                if hits > len(recent)
                else "All of this honeypot's alerts are listed."
            ),
        }
        if log_note:
            result["log_note"] = log_note
        return mark_untrusted(result)


@mcp.tool(auth=require_role("operator"), **hints("honeypot_stop"))
async def honeypot_stop(
    name: str | None = None,
    names: list[str] | None = None,
    type: str | None = None,
    status: str | None = None,
    remove: bool = False,
) -> dict[str, Any]:
    """Stop honeypots for good: one, several by name, or every one of a kind or state.

    Use it for "stop the ftp honeypot", "shut down the Windows decoys", "stop everything". Collection
    ends and a stopped honeypot cannot be resumed (`honeypot_pause` is the reversible one); its
    alerts are kept. It never guesses: name what to stop, or pass type="all" for the whole estate.

    Args:
        name: One honeypot's name.
        names: Several names.
        type: Every honeypot of this kind ("smb", "redis", ...), or "all" for every kind.
        status: Every honeypot in this state: running, paused, error (or stopped, with remove).
        remove: True when the user says remove or delete: also deletes the honeypot's record and
            container so its name can be reused (past alerts stay).
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    wanted: list[str] = []
    if isinstance(names, str):
        wanted.append(names)
    elif names:
        wanted.extend(str(n) for n in names)
    if name:
        wanted.append(name)
    type_filter = type.strip() if isinstance(type, str) else None
    if not wanted and not type_filter and not status:
        return {
            "error": "Nothing says which honeypots to stop.",
            "hint": "Give `name` or `names`, or filter with `type` and/or `status`, or pass "
            "type='all' to stop every honeypot. This is never guessed: stopping everything "
            "ends collection.",
        }
    status_filter, bad = _parse_status(status)
    if bad:
        return bad
    wanted_type: str | None = None
    if type_filter and type_filter.lower() != "all":
        wanted_type = resolve_type(type_filter)
        if wanted_type is None:
            return _type_error(type_filter, extra=" or 'all'")

    already_stopped: list[str] = []
    async with get_session() as session:
        targets: list[Honeypot] = []
        if wanted:
            for candidate in wanted:
                hp, problem = await _find_sensor(session, candidate)
                if hp is None:
                    return problem or {"error": f"No honeypot named '{candidate}'."}
                if all(t.id != hp.id for t in targets):
                    targets.append(hp)
        else:
            for hp in await queries.list_honeypots(session):
                if wanted_type and hp.type.value != wanted_type:
                    continue
                if status_filter and hp.status is not status_filter:
                    continue
                if hp.status is HoneypotStatus.STOPPED and not remove:
                    continue
                targets.append(hp)

        if not targets:
            return {
                "stopped": [],
                "count": 0,
                "note": "Nothing matched, so no honeypot was changed. `honeypot_list` shows what "
                "is deployed.",
            }

        stopped: list[str] = []
        failed: list[dict[str, str]] = []
        timed_out: list[str] = []
        for hp in targets:
            was_stopped = hp.status == HoneypotStatus.STOPPED
            # An already-stopped sensor has nothing to stop, but `remove` must still delete it: this
            # used to `continue` unconditionally, so a stopped sensor could never be removed and
            # its row and name stayed reserved forever, with `stopped: []` as the only answer.
            if was_stopped and not remove:
                already_stopped.append(hp.name)
                continue
            try:
                engine = get_engine(hp.type)
                if hp.container_id and not was_stopped:
                    await asyncio.wait_for(
                        engine.stop(hp.container_id, remove=remove),
                        timeout=_ENGINE_STOP_TIMEOUT_SECONDS,
                    )
            except TimeoutError:
                # A lingering peer must not keep the sensor alive in the DB:
                # leaving it RUNNING would let reconcile restart it on the
                # next boot. The operator sees the overrun in `timed_out`.
                log.warning(
                    "Engine stop for honeypot %r exceeded %gs; marking it stopped anyway",
                    hp.name,
                    _ENGINE_STOP_TIMEOUT_SECONDS,
                )
                timed_out.append(hp.name)
            except Exception as e:
                failed.append({"name": hp.name, "error": str(e)})
                continue
            stopped.append(hp.name)
            if remove:
                # Never `session.delete(hp)`: with a plain relationship SQLAlchemy
                # loads every alert the sensor ever captured (full JSON payloads)
                # just to NULL its honeypot_id one object at a time — gigabytes on a
                # busy sensor. Set-based statements do the same in constant memory. The rollups
                # carry the sensor id too, so they are re-filed under "no sensor" in step.
                await session.execute(
                    update(Alert).where(Alert.honeypot_id == hp.id).values(honeypot_id=None)
                )
                await rollups.detach_sensor(session, hp.id)
                await session.execute(delete(Honeypot).where(Honeypot.id == hp.id))
                session.expunge(hp)
            else:
                hp.status = HoneypotStatus.STOPPED
                hp.container_id = None

    await record_action(
        "honeypot_stop",
        summary=(
            f"{'removed' if remove else 'stopped'} {len(stopped)} honeypot(s) — "
            f"collection ended for: {', '.join(stopped) or 'none'}"
        ),
        arguments={"name": name, "names": names, "type": type, "status": status, "remove": remove},
        target=", ".join(stopped)[:128] or None,
        outcome="error" if failed else "ok",
        error="; ".join(f["error"] for f in failed) if failed else None,
    )
    # Narrow the capture filter to what is still running — otherwise it keeps
    # recording a port nothing listens on, which is pure disk cost.
    from honeypot_mcp.pcap import refresh_capture

    await refresh_capture()
    result: dict[str, Any] = {
        "action": "removed" if remove else "stopped",
        "stopped": stopped,
        "count": len(stopped),
        "failed": failed,
        "status": "ok" if not failed else "partial",
        "note": (
            "Collection has ended for these; their alerts are kept but no longer tied to a "
            "honeypot."
            if remove
            else "Collection has ended for these and their alerts are kept. They cannot be "
            "resumed: deploy again (remove the old one first to reuse its name)."
        )
        if stopped
        else "Nothing was stopped.",
    }
    if already_stopped:
        result["already_stopped"] = already_stopped
    if failed:
        result["hint"] = "Failures are listed under `failed`; `honeypot_status` shows the state."
    if timed_out:
        result["timed_out"] = timed_out
        result["note"] += (
            f" Engine teardown exceeded {_ENGINE_STOP_TIMEOUT_SECONDS:g}s for "
            f"{', '.join(timed_out)}; marked stopped anyway."
        )
    return result


@mcp.tool(auth=require_role("operator"), **hints("honeypot_pause"))
async def honeypot_pause(name: str) -> dict[str, Any]:
    """Pause a running honeypot so it stops capturing, keeping its settings and history.

    Use it for "pause the ssh honeypot for now". `honeypot_resume` brings it back; use
    `honeypot_stop` when it should not return.

    Args:
        name: The honeypot's name (its type or port also work when only one matches).
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    async with get_session() as session:
        hp, problem = await _find_sensor(session, name)
        if hp is None:
            return problem or {"error": f"No honeypot named '{name}'."}
        if hp.status != HoneypotStatus.RUNNING:
            return {
                "error": f"Honeypot '{hp.name}' is not running (status={hp.status.value}).",
                "hint": "Only a running honeypot can be paused; `honeypot_resume` restarts a "
                "paused one and `honeypot_status` says why one is in error.",
            }

        engine = get_engine(hp.type)
        if hp.container_id:
            if engine.native_pause:
                await engine.pause(hp.container_id)
            else:
                # An in-process engine has nothing to freeze, and its pause() used to be a no-op:
                # the status said PAUSED while the port kept answering and recording. Pausing now
                # closes the listener, so the status is true; resume starts a fresh one.
                await engine.stop(hp.container_id)
        hp.status = HoneypotStatus.PAUSED
        resolved = hp.name

    await record_action(
        "honeypot_pause",
        summary=f"paused honeypot '{resolved}' — collection suspended",
        arguments={"name": name},
        target=resolved,
    )
    return {
        "name": resolved,
        "status": "paused",
        "note": f"'{resolved}' is not capturing. `honeypot_resume` brings it back.",
    }


@mcp.tool(auth=require_role("operator"), **hints("honeypot_resume"))
async def honeypot_resume(name: str) -> dict[str, Any]:
    """Resume a paused honeypot so it captures again, with its settings and history intact.

    Use it for "resume the ssh honeypot", "bring it back". Settings changed with
    `honeypot_configure` take effect here for in-process types.

    Args:
        name: The honeypot's name (its type or port also work when only one matches).
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    async with get_session() as session:
        hp, problem = await _find_sensor(session, name)
        if hp is None:
            return problem or {"error": f"No honeypot named '{name}'."}
        if hp.status != HoneypotStatus.PAUSED:
            return {
                "error": f"Honeypot '{hp.name}' is not paused (status={hp.status.value}).",
                "hint": "Only a paused honeypot can be resumed. A stopped one is deployed again "
                "with `honeypot_deploy`; `honeypot_list` shows each one's status.",
            }

        engine = get_engine(hp.type)
        if engine.native_pause:
            if hp.container_id:
                await engine.resume(hp.container_id)
        else:
            try:
                hp.container_id = await engine.start(hp.name, hp.port, dict(hp.config or {}))
            except Exception as e:  # noqa: BLE001 - report it, leave the sensor paused
                return {
                    "error": f"Could not resume '{hp.name}' on port {hp.port}: {e}. It stays paused.",
                    "hint": "If something else took the port, stop it and resume again, or "
                    "remove this honeypot and deploy a new one on a free port.",
                }
        hp.status = HoneypotStatus.RUNNING
        resolved = hp.name

    await record_action(
        "honeypot_resume",
        summary=f"resumed honeypot '{resolved}'",
        arguments={"name": name},
        target=resolved,
    )
    return {
        "name": resolved,
        "status": "running",
        "next_step": f"Verify it: honeypot_self_test(name='{resolved}').",
    }


@mcp.tool(auth=require_role("operator"), **hints("honeypot_configure"))
async def honeypot_configure(name: str, config: dict[str, Any]) -> dict[str, Any]:
    """Change a honeypot's settings (its banner, hostname, web persona, ...).

    Use it for "make the ftp honeypot announce itself as ...". The keys differ per type and a
    wrong key or value is refused with the valid ones; `deception_profiles` with the type lists
    them too. Settings are merged into the current ones and apply the next time it starts.

    Args:
        name: The honeypot's name (its type or port also work when only one matches).
        config: Key/value pairs, e.g. {"fake_banner": "220 FTP ready"} for ftp.
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    if not isinstance(config, dict):
        return {
            "error": "config must be an object of key/value pairs.",
            "hint": 'For example {"fake_banner": "220 FTP ready"}.',
        }

    async with get_session() as session:
        hp, problem = await _find_sensor(session, name)
        if hp is None:
            return problem or {"error": f"No honeypot named '{name}'."}
        if err := _validate_config(hp.type.value, config):
            return {"error": err, "hint": _config_hint(hp.type.value)}
        if "telnet_port" in config:
            telnet_port = config["telnet_port"]
            if telnet_port == hp.port:
                return {
                    "error": (
                        f"telnet_port {telnet_port} is this honeypot's own port — "
                        "pick a different one."
                    ),
                    "hint": "Choose a port that nothing else uses.",
                }
            conflict = await queries.get_honeypot_by_port(session, telnet_port)
            if conflict and conflict.id != hp.id and conflict.status == HoneypotStatus.RUNNING:
                return {
                    "error": (
                        f"Port {telnet_port} is already used by honeypot "
                        f"'{conflict.name}' ({conflict.type.value}, id={conflict.id})."
                    ),
                    "hint": "Pick a different port, or stop that honeypot first.",
                }
        hp.config = {**hp.config, **config}
        new_config = hp.config
        resolved = hp.name
        restart = (
            "stop it with remove=true and deploy it again"
            if get_engine(hp.type).native_pause
            else "`honeypot_pause` then `honeypot_resume`"
        )
        running = hp.status is HoneypotStatus.RUNNING

    await record_action(
        "honeypot_configure",
        summary=f"reconfigured honeypot '{resolved}' ({', '.join(sorted(config)) or 'no keys'})",
        arguments={"name": name, "config": config},
        target=resolved,
    )
    return {
        "name": resolved,
        "config": new_config,
        "note": f"Saved. To apply it to the running honeypot, {restart}."
        if running
        else "Saved. It applies the next time this honeypot starts.",
    }


def _is_text(value: Any, max_len: int = 255) -> bool:
    """A single-line string. These values land in protocol banners and in
    container environment variables, where a CR/LF would inject a line."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= max_len
        and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
    )


def _is_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _is_endpoints(value: Any) -> bool:
    if not isinstance(value, list) or len(value) > 200:
        return False
    for ep in value:
        if not isinstance(ep, dict) or not _is_text(ep.get("path"), 1024):
            return False
        if not str(ep["path"]).startswith("/"):
            return False
        if "template" in ep and not _is_text(ep["template"], 64):
            return False
    return True


_CHECKS: dict[str, tuple[Any, str]] = {
    "ssh_persona": (
        lambda v: v in _ssh_persona_ids(),
        f"one of: {', '.join(_ssh_persona_ids())}",
    ),
    "ssh_hostname": (_is_text, "a single-line string"),
    "fake_hostname": (_is_text, "a single-line string"),
    "fake_kernel": (_is_text, "a single-line string"),
    "telnet_enabled": (lambda v: isinstance(v, bool), "true or false"),
    "telnet_port": (_is_port, "an integer port between 1 and 65535"),
    "persona": (
        lambda v: v in _http_persona_ids(),
        f"one of: {', '.join(_http_persona_ids())}",
    ),
    "tls": (lambda v: isinstance(v, bool), "true or false"),
    "endpoints": (_is_endpoints, 'a list of {"path": "/...", "template": "..."} objects'),
    "fake_banner": (_is_text, "a single-line string"),
    "smtp_hostname": (_is_text, "a single-line string"),
    "fake_banner_hostname": (_is_text, "a single-line string"),
}

# The keys each engine actually reads from `Honeypot.config` (grep the engines
# for `config.get(` when adding one). Anything else would be stored and then
# silently ignored, which reads as "configured" while changing nothing.
_COWRIE_KEYS = frozenset(
    {"ssh_persona", "ssh_hostname", "fake_hostname", "fake_kernel", "telnet_enabled", "telnet_port"}
)
_CONFIG_KEYS: dict[str, frozenset[str]] = {
    "ssh": _COWRIE_KEYS,
    "telnet": _COWRIE_KEYS,
    "http": frozenset({"persona", "tls", "endpoints"}),
    "ftp": frozenset({"fake_banner"}),
    "smtp": frozenset({"smtp_hostname", "fake_banner_hostname"}),
}


def _validate_config(hp_type: str, config: dict[str, Any]) -> str | None:
    """Return an error for keys the engine does not read or values of the wrong shape."""
    allowed = _CONFIG_KEYS.get(hp_type, frozenset())
    unknown = sorted(str(k) for k in config if k not in allowed)
    if unknown:
        return (
            f"Unsupported config key(s) for {hp_type}: {', '.join(unknown)}. "
            f"Supported: {', '.join(sorted(allowed)) or 'none'}."
        )
    for key, value in config.items():
        check, expected = _CHECKS[key]
        if not check(value):
            return f"Invalid value for '{key}': expected {expected}."
    return None


def _config_hint(hp_type: str) -> str:
    """What a honeypot of this type accepts, for the error a bad `config` returns."""
    keys = sorted(_CONFIG_KEYS.get(hp_type, ()))
    if not keys:
        return f"{hp_type} honeypots take no settings: leave `config` out."
    return f"{hp_type} accepts: " + "; ".join(f"{k} ({_CHECKS[k][1]})" for k in keys) + "."


def _log_tail(log_data: list[str]) -> tuple[list[str], str | None]:
    """The newest log lines within a character budget (long ones clipped), and a note if cut."""
    clipped = [
        line if len(line) <= _LOG_LINE_CHARS else line[:_LOG_LINE_CHARS] + "..."
        for line in log_data
    ]
    kept: list[str] = []
    used = 0
    for line in reversed(clipped):
        if kept and used + len(line) > _LOG_TOTAL_CHARS:
            break
        kept.append(line)
        used += len(line)
    kept.reverse()
    if not kept:
        return kept, "The log is empty."
    if len(kept) < len(log_data):
        return kept, f"Showing the newest {len(kept)} of {len(log_data)} lines."
    if any(c != o for c, o in zip(clipped, log_data, strict=True)):
        return kept, "Long lines are clipped."
    return kept, None


async def _probe_health(hp: Honeypot) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": hp.name,
        "type": hp.type.value,
        "port": hp.port,
        "status": hp.status.value,
    }
    if hp.container_id is None:
        entry.update({"alive": False, "detail": "Not started (no container or listener)."})
    elif foreign := _owned_elsewhere(hp):
        entry.update(foreign)
    else:
        try:
            entry.update(await get_engine(hp.type).health_check(hp.container_id, hp.port))
        except Exception as e:
            entry.update({"alive": False, "detail": f"Health check error: {e}", "method": "error"})
    return entry


def _down_reason(entry: dict[str, Any]) -> str:
    """A plain reason a sensor does not answer, from fixed vocabulary only."""
    if str(entry.get("detail", "")).startswith("Not started"):
        return "never started"
    if entry.get("method") == "error":
        return "the health check itself failed"
    return "nothing is listening on its port"


def _probe_headline(
    results: list[dict[str, Any]], up: int, down: list[str], unknown: list[str]
) -> str:
    """One sentence for the probe-all answer: how many answer, which do not and why."""
    n = len(results)
    if not n:
        return (
            "No honeypot is running, so nothing was probed; honeypot_list shows what is deployed."
        )
    if down:
        by_name = {r["name"]: r for r in results}
        shown = [f"{d} ({_down_reason(by_name[d])})" for d in down[:3]]
        more = f" and {len(down) - 3} more" if len(down) > 3 else ""
        return (
            f"{up} of {n} sensors answer; {len(down)} do not: {', '.join(shown)}{more}. "
            "A sensor that is down captures nothing: honeypot_status(name) shows its log."
        )
    if unknown and len(unknown) == n:
        if instance_lock.in_analysis_mode():
            return (
                f"Analysis copy: nothing runs here, so none of the {n} sensors was probed; the "
                "rows are what the original server last recorded."
            )
        return (
            f"None of the {n} running sensors could be probed from this session: another "
            "process owns them (honeypot_list shows their last recorded state)."
        )
    if unknown:
        return (
            f"{up} of {n} sensors answer; {len(unknown)} belong to another process and were "
            "not probed from this session."
        )
    return f"All {n} sensors answer on their ports."


async def _health_of_running() -> dict[str, Any]:
    """Probe every running honeypot: who answers, who does not, who cannot be probed from here."""
    async with get_session() as session:
        honeypots = await queries.list_honeypots(session, status=HoneypotStatus.RUNNING)

    results = list(await asyncio.gather(*(_probe_health(hp) for hp in honeypots)))
    down = [r["name"] for r in results if r.get("alive") is False]
    unknown = [r["name"] for r in results if r.get("alive") is None]
    up = len(results) - len(down) - len(unknown)
    if not results:
        note = "No honeypot is running. `honeypot_list` shows what is deployed."
    elif down:
        note = (
            f"{len(down)} of {len(results)} not answering: {', '.join(down)}. "
            "`honeypot_status` with a name shows its log; stop and redeploy one that stays down."
        )
    elif unknown:
        note = f"{up} answering; {len(unknown)} could not be probed from this session."
        # The same explanation on every row is noise: say it once and keep it on the rows only
        # when they differ.
        reasons = {r.get("note") for r in results if r.get("alive") is None}
        if len(reasons) == 1 and None not in reasons:
            note += f" {reasons.pop()}"
            for r in results:
                if r.get("alive") is None:
                    r.pop("note", None)
    else:
        note = f"All {len(results)} answering."
    return {
        "headline": _probe_headline(results, up, down, unknown),
        "count": len(results),
        "answering": up,
        "not_probed": len(unknown),
        "not_answering": down,
        "honeypots": results,
        "note": note,
    }


@mcp.tool(auth=require_role("operator"), **hints("honeypot_self_test"))
async def honeypot_self_test(name: str) -> dict[str, Any]:
    """Prove a honeypot really records attacks: send it a probe and check an alert appears.

    Use it for "test the new honeypot", "does hp-http actually log?". It catches what
    `honeypot_status` misses (an engine that accepts connections but never logs, suppression
    dropping events, a stalled event buffer). The probe is harmless and speaks the sensor's own
    protocol; its alert is marked as a self-test. Takes a few seconds (up to 30 for ssh/telnet).

    Args:
        name: The honeypot's name (its type or port also work when only one matches).
    """
    if (read_only := instance_lock.read_only_error()) is not None:
        return read_only
    from sqlalchemy import String, cast, select

    from honeypot_mcp.storage.models import Alert

    async with get_session() as session:
        hp, problem = await _find_sensor(session, name)
        if hp is None:
            return problem or {"error": f"No honeypot named '{name}'."}
        if hp.status != HoneypotStatus.RUNNING:
            return {
                "error": f"Honeypot '{hp.name}' is not running (status={hp.status.value}).",
                "hint": "`honeypot_resume` restarts a paused one; `honeypot_status` says why one "
                "is in error.",
            }
        name = hp.name
        hp_id = hp.id
        hp_type = hp.type.value
        hp_port = hp.port

    marker = f"selftest_{secrets.token_hex(6)}"
    probe_start = datetime.now(UTC)

    sent_ok, send_detail, match_token = await _send_probe(hp_type, hp_port, marker)
    if not sent_ok:
        return {
            "name": name,
            "type": hp_type,
            "probe_sent": False,
            "alert_received": False,
            "detail": send_detail,
            "hint": "`honeypot_status` shows whether the honeypot answers at all.",
        }

    # Cowrie's log is polled, so ssh and telnet take longer to show their alert.
    timeout_seconds = (
        _SELF_TEST_DOCKER_SECONDS if BY_TYPE[hp_type].requires_docker else _SELF_TEST_SECONDS
    )
    for _ in range(timeout_seconds):
        await asyncio.sleep(1)
        async with get_session() as session:
            result = await session.execute(
                select(Alert)
                .where(
                    Alert.honeypot_id == hp_id,
                    Alert.timestamp >= probe_start,
                    cast(Alert.payload, String).contains(match_token),
                )
                .limit(1)
            )
            match = result.scalar_one_or_none()
            if match:
                duration = (datetime.now(UTC) - probe_start).total_seconds()
                return {
                    "name": name,
                    "type": hp_type,
                    "probe_marker": marker,
                    "probe_sent": True,
                    "probe_detail": send_detail,
                    "alert_received": True,
                    "alert_id": match.id,
                    "alert_event_type": match.event_type,
                    "duration_seconds": round(duration, 2),
                    "detail": "End-to-end pipeline working — probe was captured as an alert.",
                }

    return {
        "name": name,
        "type": hp_type,
        "probe_marker": marker,
        "probe_sent": True,
        "probe_detail": send_detail,
        "alert_received": False,
        "detail": (
            f"Probe sent but no matching alert within {timeout_seconds}s. "
            "Possible causes: honeypot crashed (run honeypot_status), suppression "
            "rule is dropping the event, or the event buffer flusher has stalled."
        ),
        "hint": "Run `honeypot_status` with this honeypot's name (it shows the last log lines), and "
        "check `suppression_list` for a rule matching 127.0.0.1.",
    }


async def _send_probe(hp_type: str, port: int, marker: str) -> tuple[bool, str, str]:
    """Dispatch to the per-protocol probe. Each probe embeds `marker` in a
    field the engine writes into the alert payload.

    Returns `(sent_ok, detail, match_token)`. `match_token` is the string to
    search the resulting alert payload for — usually `marker` itself, but a
    protocol that can only carry raw bytes (VNC) returns the hex form it
    actually put on the wire.
    """
    probe = _PROBES.get(hp_type)
    if probe is None:
        return False, f"No self-test probe defined for honeypot type {hp_type}", marker
    try:
        return await probe(port, marker)
    except Exception as e:
        return False, f"Probe failed: {e}", marker


async def _ssh_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Open a TCP connection and send an SSH banner containing the marker.
    Cowrie logs `cowrie.client.version` with the banner — the marker lands in
    the version field of the alert payload."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(f"SSH-2.0-{marker}\r\n".encode())
        await writer.drain()
        # Give Cowrie a beat to log the version event before we tear down.
        await asyncio.sleep(0.5)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "SSH banner sent", marker


async def _http_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """HTTP GET with marker in the User-Agent — lands in payload['user_agent']."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"http://127.0.0.1:{port}/.env",
            headers={"User-Agent": f"HoneyPotSelfTest/{marker}"},
        )
    return True, f"HTTP {resp.status_code}", marker


async def _smtp_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """AUTH PLAIN whose username is the marker. The engine decodes AUTH into username and
    password (so planted credentials can be matched), so that is where the marker lands."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"EHLO selftest.local\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(256), timeout=3.0)
        blob = base64.b64encode(f"\0{marker}\0selftest".encode()).decode()
        writer.write(f"AUTH PLAIN {blob}\r\n".encode())
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "SMTP AUTH sent", marker


async def _ftp_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """USER + PASS — marker goes in the username, lands in payload['username']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(f"USER {marker}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"PASS x\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "FTP USER+PASS sent", marker


async def _dns_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """DNS query for `<marker>.selftest` — marker lands in payload['qname']."""
    try:
        import dnslib
    except ImportError:
        return False, "dnslib not installed — cannot self-test DNS", marker

    class _Probe(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.received = asyncio.Event()

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            self.received.set()

    loop = asyncio.get_event_loop()
    proto = _Probe()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: proto, remote_addr=("127.0.0.1", port)
    )
    try:
        query = dnslib.DNSRecord.question(f"{marker}.selftest").pack()
        transport.sendto(query)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proto.received.wait(), timeout=2.0)
    finally:
        transport.close()
    return True, "DNS query sent", marker


async def _rdp_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send an X.224 Connection Request carrying `Cookie: mstshash=<marker>`
    — the RDP engine parses it into payload['mstshash'] / ['username']."""
    cookie = f"Cookie: mstshash={marker}\r\n".encode()
    neg_req = bytes([0x01, 0x00]) + (8).to_bytes(2, "little") + (0).to_bytes(4, "little")
    # X.224 body: code(0xE0) + dst-ref(2) + src-ref(2) + class(1) + variable.
    x224_body = bytes([0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + cookie + neg_req
    x224 = bytes([len(x224_body)]) + x224_body
    tpkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(tpkt + x224)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "RDP X.224 CR sent", marker


async def _vnc_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Drive the RFB handshake through to the auth response. VNC can only
    carry 16 raw bytes there, so we send the marker's bytes and match on their
    hex form (what lands in payload['response_hex'])."""
    response = marker.encode()[:16].ljust(16, b"\x00")
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readexactly(12), timeout=3.0)  # server version
        writer.write(b"RFB 003.008\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(8), timeout=3.0)  # security-types list
        writer.write(bytes([2]))  # select VNC auth
        await writer.drain()
        await asyncio.wait_for(reader.readexactly(16), timeout=3.0)  # challenge
        writer.write(response)
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "VNC auth response sent", response.hex()


async def _redis_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """`AUTH default <marker>` — the marker lands in payload['password']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"AUTH default {marker}\r\n".encode())
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(128), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "Redis AUTH sent", marker


async def _mysql_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send a HandshakeResponse41 with the marker as username — lands in
    payload['username']."""
    import struct

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.read(256), timeout=3.0)  # server handshake
        body = (
            struct.pack("<I", 0x0005A685)  # client capability flags
            + struct.pack("<I", 16_777_216)  # max packet size
            + bytes([0x21])  # charset
            + b"\x00" * 23  # reserved
            + marker.encode()
            + b"\x00"  # username null terminator
            + b"\x00"  # auth-response length = 0
        )
        header = struct.pack("<I", len(body))[:3] + bytes([1])  # seq id 1
        writer.write(header + body)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "MySQL handshake response sent", marker


async def _elasticsearch_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """HTTP GET with marker in the User-Agent — lands in payload['user_agent']."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"http://127.0.0.1:{port}/",
            headers={"User-Agent": f"HoneyPotSelfTest/{marker}"},
        )
    return True, f"HTTP {resp.status_code}", marker


async def _mssql_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send a minimal TDS Login7 with the marker as the username — lands in
    payload['username']."""
    import struct

    from honeypot_mcp.engines.mssql import _TDS_LOGIN7, _tds_packet

    marker_u16 = marker.encode("utf-16-le")
    data_offset = 72  # right after the fixed header (36) + 9-entry table (36)
    body = bytearray(72) + marker_u16
    # UserName is table index 1 → offset 36 + 1*4 = 40. Store ib + cch (chars).
    struct.pack_into("<HH", body, 40, data_offset, len(marker))
    struct.pack_into("<I", body, 0, len(body))  # Length field
    packet = _tds_packet(_TDS_LOGIN7, bytes(body))
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(packet)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "MSSQL Login7 sent", marker


async def _smb_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send an SMB1 negotiate whose dialect list contains the marker — lands in
    payload['dialects']."""
    # SMB1 header: \xffSMB + command 0x72 (negotiate) + 27 more bytes.
    smb_header = b"\xffSMB" + bytes([0x72]) + b"\x00" * 27
    # WordCount(0) + ByteCount + dialect list: 0x02 + <marker>\0
    dialects = b"\x02" + marker.encode() + b"\x00" + b"\x02NT LM 0.12\x00"
    body = bytes([0]) + len(dialects).to_bytes(2, "little") + dialects
    smb = smb_header + body
    frame = b"\x00" + len(smb).to_bytes(3, "big") + smb
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(frame)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "SMB negotiate sent", marker


async def _postgresql_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send a StartupMessage with user=<marker> — lands in payload['user']."""
    import struct

    params = b"user\x00" + marker.encode() + b"\x00database\x00postgres\x00\x00"
    body = struct.pack("!I", 196608) + params
    msg = struct.pack("!I", len(body) + 4) + body
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(msg)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "PostgreSQL startup sent", marker


async def _mongodb_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send an OP_QUERY isMaster whose command doc carries the marker as a
    string field — lands in payload['strings']."""
    import struct

    from honeypot_mcp.engines.mongodb import _bson_encode

    doc = _bson_encode({"ismaster": 1, "comment": marker})
    # OP_QUERY body: flags(4) + fullCollectionName + skip(4) + return(4) + doc
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, 1) + doc
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)  # opcode 2004 = OP_QUERY
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(header + body)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(512), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "MongoDB isMaster sent", marker


async def _telnet_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Send a login attempt with the marker as the username. Unlike SSH,
    Telnet has no version-banner exchange, so the marker rides the login line
    instead — Cowrie logs cowrie.login.failed (retagged to telnet_login_failed
    by ssh.py:_retag_for_protocol) with the marker in payload['username'].

    Deliberately tolerant of Telnet's IAC option negotiation: real scanners
    (Mirai and descendants, the dominant traffic on this port) mostly skip a
    compliant handshake and just send raw login lines, and Cowrie's telnet
    listener is built to catch exactly that."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
            await asyncio.wait_for(reader.read(512), timeout=1.0)
        writer.write(f"{marker}\r\n".encode())
        await writer.drain()
        with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
            await asyncio.wait_for(reader.read(512), timeout=1.0)
        writer.write(b"x\r\n")
        await writer.drain()
        await asyncio.sleep(0.5)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "Telnet login sent", marker


async def _memcached_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """`set <marker> 0 0 3` — the key lands in payload['key']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(f"set {marker} 0 0 3\r\nabc\r\n".encode())
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(128), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "Memcached set sent", marker


async def _snmp_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """UDP GetRequest with `marker` as the community string — lands in
    payload['community'] (mirrored to username/password for cross-referencing
    planted community-string honeytokens)."""
    from honeypot_mcp.engines.snmp import build_get_request

    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(build_get_request("1.3.6.1.2.1.1.1.0", community=marker))
        await asyncio.sleep(0.3)
    finally:
        transport.close()
    return True, "SNMP GetRequest sent", marker


async def _ldap_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Simple bind with `marker` as the DN — lands in payload['bind_dn'] (and
    payload['username'])."""
    from honeypot_mcp.engines.ldap import _BIND_REQUEST, _OCTET_STRING, _SEQUENCE, _encode_int, _tlv

    auth = _tlv(0x80, b"x")  # context tag 0: simple auth, password "x"
    bind_body = _encode_int(3) + _tlv(_OCTET_STRING, marker.encode()) + auth
    message = _tlv(_SEQUENCE, _encode_int(1) + _tlv(_BIND_REQUEST, bind_body))

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(message)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "LDAP bind request sent", marker


async def _docker_api_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """HTTP GET /version with marker in the User-Agent — lands in
    payload['user_agent']."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(
            f"http://127.0.0.1:{port}/version",
            headers={"User-Agent": f"HoneyPotSelfTest/{marker}"},
        )
    return True, f"HTTP {resp.status_code}", marker


async def _imap_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """`a1 LOGIN <marker> x` — lands in payload['username']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)  # greeting
        writer.write(f"a1 LOGIN {marker} x\r\n".encode())
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=3.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "IMAP LOGIN sent", marker


async def _sip_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """UDP OPTIONS with marker as the User-Agent — lands in
    payload['user_agent']. Not a scanner UA, so it classifies as
    sip_options_probe rather than sip_scan."""
    message = (
        f"OPTIONS sip:probe@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK-selftest\r\n"
        f"From: <sip:selftest@127.0.0.1>;tag=1\r\n"
        f"To: <sip:probe@127.0.0.1>\r\n"
        f"Call-ID: selftest-{marker}\r\n"
        f"CSeq: 1 OPTIONS\r\n"
        f"User-Agent: {marker}\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(message)
        await asyncio.sleep(0.3)
    finally:
        transport.close()
    return True, "SIP OPTIONS sent", marker


async def _rsync_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """Handshake, then request a module named `marker` — no module matches,
    so it lands in payload['module'] via rsync_unknown_module."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)  # @RSYNCD: greeting
        writer.write(b"@RSYNCD: 31.0\n")
        await writer.drain()
        writer.write(f"{marker}\n".encode())
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.readline(), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "rsync module request sent", marker


async def _nfs_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """ONC RPC MOUNT/MNT call requesting export path `/<marker>` — lands in
    payload['path'] via nfs_mount_attempt."""
    import struct

    from honeypot_mcp.engines.nfs import MOUNT_MNT, PROG_MOUNT, xdr_string

    path = f"/{marker}"
    header = struct.pack(">IIIIII", 1, 0, 2, PROG_MOUNT, 3, MOUNT_MNT)
    credential = struct.pack(">II", 0, 0)  # AUTH_NULL: flavour=0, length=0
    verifier = struct.pack(">II", 0, 0)  # AUTH_NULL: flavour=0, length=0
    body = header + credential + verifier + xdr_string(path)
    frame = struct.pack(">I", 0x80000000 | len(body)) + body

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(frame)
        await writer.drain()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(reader.read(256), timeout=2.0)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "NFS MOUNT/MNT sent", path


async def _pop3_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """USER + PASS — marker goes in the username, lands in
    payload['username']."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await asyncio.wait_for(reader.readline(), timeout=3.0)  # greeting
        writer.write(f"USER {marker}\r\n".encode())
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"PASS x\r\n")
        await writer.drain()
        await asyncio.sleep(0.3)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    return True, "POP3 USER+PASS sent", marker


async def _kubernetes_probe(port: int, marker: str) -> tuple[bool, str, str]:
    """HTTPS GET /version with marker in the User-Agent — lands in
    payload['user_agent']. The API server only speaks TLS and ours is self-signed."""
    import httpx

    async with httpx.AsyncClient(timeout=5.0, verify=False) as client:  # noqa: S501
        resp = await client.get(
            f"https://127.0.0.1:{port}/version",
            headers={"User-Agent": f"HoneyPotSelfTest/{marker}"},
        )
    return True, f"HTTP {resp.status_code}", marker


# Registry, not an if-chain, so completeness against `HoneypotType` is
# directly assertable (see test_self_test.py) rather than parsed out of an
# if-chain's source. Same idiom as `capabilities.BY_TYPE` / `get_provider()` /
# `engines.get_engine()` elsewhere in this codebase.
_PROBES: dict[str, Any] = {
    "ssh": _ssh_probe,
    "http": _http_probe,
    "smtp": _smtp_probe,
    "ftp": _ftp_probe,
    "dns": _dns_probe,
    "rdp": _rdp_probe,
    "vnc": _vnc_probe,
    "redis": _redis_probe,
    "mysql": _mysql_probe,
    "elasticsearch": _elasticsearch_probe,
    "smb": _smb_probe,
    "postgresql": _postgresql_probe,
    "mongodb": _mongodb_probe,
    "mssql": _mssql_probe,
    "telnet": _telnet_probe,
    "memcached": _memcached_probe,
    "snmp": _snmp_probe,
    "ldap": _ldap_probe,
    "docker_api": _docker_api_probe,
    "imap": _imap_probe,
    "sip": _sip_probe,
    "rsync": _rsync_probe,
    "nfs": _nfs_probe,
    "pop3": _pop3_probe,
    "kubernetes": _kubernetes_probe,
}
