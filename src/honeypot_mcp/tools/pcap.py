"""Packet-capture tools.

Four operations, matching what someone actually does with a capture: check it
is running, get one attacker's packets, list what is on disk, and turn it on or
off. The extract is the point — a 1 GB ring buffer is not an answer to "what
did this IP send", and handing an analyst the whole ring is the same as handing
them nothing.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from honeypot_mcp import pcap as pcap_module
from honeypot_mcp.server import mcp
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._format import validate_ip

log = logging.getLogger(__name__)


@mcp.tool
async def pcap_status() -> dict[str, Any]:
    """Is packet capture running, and how much disk is it using?

    Also reports *why* it is not running when it is not — missing tcpdump,
    insufficient privileges, or simply disabled — because the alternative is an
    operator discovering during an incident that the evidence was never being
    recorded.
    """
    capture = pcap_module.get_capture()
    status = capture.status()
    if not status["running"]:
        status["capability"] = pcap_module.probe_capability().as_dict()
    return status


@mcp.tool
async def pcap_extract(
    source_ip: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    """Pull every captured packet involving one IP into a single pcap file.

    The investigation workflow: an alert names an attacker, and you want their
    traffic in Wireshark, or replayed through Suricata/Zeek, or attached to a
    ticket. Searches the whole ring buffer.

    Args:
        source_ip: Attacker IP, as it appears on the alert.
        output_path: Filename for the extract. Defaults to a timestamped name.
                     Confined to the reports directory.
    """
    error = validate_ip(source_ip)
    if error:
        return {"error": error}

    if output_path is None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        output_path = f"pcap-{source_ip.replace(':', '_')}-{stamp}.pcap"

    result = await pcap_module.get_capture().extract(source_ip, output_path)
    if "error" not in result:
        await _audit.record_action(
            "pcap_extract",
            f"extracted {result.get('packets', 0)} packet(s) for {source_ip}",
            arguments={"source_ip": source_ip, "output_path": output_path},
            target=source_ip,
        )
    return result


@mcp.tool
async def pcap_files() -> dict[str, Any]:
    """List the capture ring's files, oldest first, with sizes and ages.

    Tells you how far back the capture reaches — the question that decides
    whether an extract returning nothing means "no such traffic" or "that was
    before the ring wrapped".
    """
    capture = pcap_module.get_capture()
    files = capture.files()
    now = datetime.now(UTC).timestamp()
    rows = []
    for path in files:
        stat = path.stat()
        rows.append(
            {
                "name": path.name,
                "bytes": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime, UTC).isoformat(),
                "age_minutes": round((now - stat.st_mtime) / 60, 1),
            }
        )
    oldest = rows[0]["modified"] if rows else None
    return {
        "count": len(rows),
        "files": rows,
        "total_bytes": sum(r["bytes"] for r in rows),
        "capture_reaches_back_to": oldest,
        "note": (
            "Ring buffer — the oldest file is overwritten once the ceiling is hit. "
            "An extract can only find traffic newer than `capture_reaches_back_to`."
        ),
    }


@mcp.tool
async def pcap_control(action: str) -> dict[str, Any]:
    """Start, stop or restart packet capture.

    Restart is the one to reach for after deploying a honeypot on a new port —
    the capture filter is built from the deployed set, so a stale filter means
    the newest sensor is the one not being recorded. (Deploy and stop refresh it
    automatically; this is the manual escape hatch.)

    Args:
        action: "start", "stop", or "restart".
    """
    action = (action or "").strip().lower()
    if action not in ("start", "stop", "restart"):
        return {"error": f"action must be start, stop or restart (got {action!r})"}

    capture = pcap_module.get_capture()
    if action == "stop":
        await capture.stop()
        await _audit.record_action("pcap_control", "packet capture stopped")
        return {"stopped": True, **capture.status()}

    result = await pcap_module.start_capture_for_running_honeypots()
    await _audit.record_action(
        "pcap_control",
        f"packet capture {action}",
        arguments={"action": action},
        outcome="ok" if result.get("started") else "failed",
        error=None if result.get("started") else str(result.get("reason"))[:200],
    )
    return {**result, "status": capture.status()}
