"""Packet capture for deployed honeypots.

Why this exists alongside per-event payload capture: the engines record what
they *understood*, and that is the right thing for triage — parsed credentials,
decoded commands, classified exploits. But three jobs need the bytes on the
wire, and no amount of application-layer logging substitutes:

- **Malware carving.** A dropper's second stage arrives as a TCP stream. The
  engine records that a download happened; the pcap contains the file.
- **IDS/replay.** Suricata and Zeek take pcap. Being able to replay real
  attacker traffic through a detection stack is how signatures get tested.
- **Evidence.** A parsed summary is an assertion by our code. A packet capture
  is the artefact, and it is what an IR process or a legal one will ask for.

Implementation shells out to `tcpdump` rather than sniffing in-process. Raw
sockets need the same privileges either way, and tcpdump's BPF filtering,
ring-buffer rotation and file format are all things a hand-rolled sniffer would
reimplement worse. The cost is a runtime dependency, which is handled by
detecting it honestly rather than failing at an unhelpful moment — see
`probe_capability()`.

**Disk is the hazard.** A honeypot on a public IP captures continuously, and a
full disk stops the database, which ends collection entirely — the failure is
much worse than not having pcap. So capture is opt-in (`PCAP_ENABLED`) and the
ring buffer is bounded by construction: `pcap_file_mb * pcap_files` is a hard
ceiling that tcpdump enforces itself by overwriting the oldest file.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import shutil
import struct
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from honeypot_mcp.config import get_settings

log = logging.getLogger(__name__)

# libpcap file header: magic, version, tz offset, sigfigs, snaplen, linktype.
_PCAP_GLOBAL_HEADER_LEN = 24
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4": ">",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1": "<",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d": ">",  # big-endian, nanosecond
}


@dataclass(frozen=True)
class Capability:
    """Whether packet capture can actually run here, and why not if it can't."""

    available: bool
    reason: str
    tcpdump_path: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"available": self.available, "reason": self.reason, "tcpdump": self.tcpdump_path}


def probe_capability() -> Capability:
    """Can we capture? Answered before anything depends on the answer.

    Reported as a first-class result rather than an exception at start time,
    because "packet capture is silently not running" is precisely the state an
    operator must never be in without being told: they would discover it when
    they went looking for the evidence, which is always after the incident.
    """
    binary = shutil.which("tcpdump")
    if binary is None:
        return Capability(
            False,
            "tcpdump is not installed. Install it (`apt install tcpdump` / "
            "`dnf install tcpdump`); it is the standard packet-capture tool and "
            "is available on every mainstream distribution.",
        )
    # Root, or the CAP_NET_RAW+CAP_NET_ADMIN pair that setcap grants, or macOS
    # BPF device access. Rather than guess at capabilities, ask tcpdump to open
    # the interface and list link types — the cheapest operation that actually
    # exercises the permission we need.
    try:
        result = subprocess.run(
            [binary, "-L", "-i", get_settings().pcap_interface],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as e:
        return Capability(False, f"could not execute tcpdump: {type(e).__name__}: {e}", binary)

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        tail = detail[-1][:200] if detail else f"exit {result.returncode}"
        if "permission" in tail.lower() or "operation not permitted" in tail.lower():
            return Capability(
                False,
                f"tcpdump lacks permission to capture ({tail}). Either run the server as "
                "root, or grant the binary the capabilities it needs without root: "
                "`sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`.",
                binary,
            )
        return Capability(False, f"tcpdump cannot open the interface: {tail}", binary)
    return Capability(True, "ready", binary)


def build_filter(ports: Sequence[tuple[int, str]]) -> str:
    """BPF expression covering the deployed honeypot ports.

    `ports` is [(port, "tcp"|"udp"), ...]. Scoping to honeypot ports keeps the
    capture proportionate: on a VPS the management SSH session, the console and
    the metrics endpoint are not attack traffic, and recording an operator's own
    administrative session is both noise and a privacy problem.
    """
    if not ports:
        return ""
    clauses = []
    for port, proto in sorted(set(ports)):
        proto = (proto or "tcp").lower()
        if proto == "both":
            # SIP is the case: a service reachable on TCP and UDP at the same
            # port. `port N` with no protocol qualifier covers both in BPF.
            clauses.append(f"port {port}")
        elif proto in ("tcp", "udp"):
            clauses.append(f"{proto} port {port}")
        else:
            clauses.append(f"port {port}")
    return " or ".join(clauses)


def _read_pcap(path: Path) -> tuple[bytes, list[bytes]] | None:
    """(global header, [raw packet records]) or None if unreadable/empty.

    Records keep their 16-byte per-packet header so they can be written back
    verbatim — there is no reason to decode a packet we are only relaying.
    """
    try:
        blob = path.read_bytes()
    except OSError:
        return None
    if len(blob) < _PCAP_GLOBAL_HEADER_LEN:
        return None
    endian = _PCAP_MAGICS.get(blob[:4])
    if endian is None:
        return None

    header, body, offset, records = (
        blob[:_PCAP_GLOBAL_HEADER_LEN],
        blob,
        _PCAP_GLOBAL_HEADER_LEN,
        [],
    )
    while offset + 16 <= len(body):
        _ts_sec, _ts_frac, caplen, _origlen = struct.unpack_from(f"{endian}IIII", body, offset)
        end = offset + 16 + caplen
        if end > len(body):
            # A truncated trailing record is normal: tcpdump may be mid-write
            # on the live file. Keep everything before it rather than discarding
            # the file, which would lose the most recent — most relevant — data.
            break
        records.append(body[offset:end])
        offset = end
    return header, records


def merge_pcaps(sources: list[Path], destination: Path) -> int:
    """Concatenate pcap files into one. Returns the packet count.

    Written by hand rather than shelling out to `mergecap`, which lives in
    Wireshark and is far less likely to be installed than tcpdump. Safe here
    because every file comes from the same capture with the same link type, so
    the global headers are identical and records can be appended verbatim.
    """
    header: bytes | None = None
    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as out:
        for source in sources:
            parsed = _read_pcap(source)
            if parsed is None:
                continue
            file_header, records = parsed
            if header is None:
                header = file_header
                out.write(header)
            for record in records:
                out.write(record)
                total += 1
    if header is None:
        # No readable input: leave a valid empty pcap rather than a 0-byte file
        # that every downstream tool reports as corrupt.
        with destination.open("wb") as out:
            out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    return total


class PcapCapture:
    """Owns the tcpdump ring-buffer process."""

    def __init__(self) -> None:
        self._process: asyncio.subprocess.Process | None = None
        self._started_at: float | None = None
        self._filter: str = ""
        self._error: str | None = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    def _directory(self) -> Path:
        return Path(get_settings().pcap_dir).expanduser()

    async def start(self, ports: Sequence[tuple[int, str]]) -> dict[str, Any]:
        """Start capture over `ports`. Idempotent-ish: restarts if already up,
        because the port set is what changes and a stale filter means the newest
        honeypot is the one not being recorded."""
        settings = get_settings()
        if self.running:
            await self.stop()

        # Nothing to capture is checked first: it is free, and it is the more
        # useful answer. Reporting a privilege problem to someone who simply
        # has no honeypots running sends them to fix the wrong thing.
        bpf = build_filter(ports)
        if not bpf:
            self._error = "no honeypots deployed — nothing to capture"
            return {"started": False, "reason": self._error}

        capability = probe_capability()
        if not capability.available:
            self._error = capability.reason
            return {"started": False, **capability.as_dict()}

        directory = self._directory()
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "honeypot.pcap"

        command = [
            capability.tcpdump_path or "tcpdump",
            "-i",
            settings.pcap_interface,
            "-s",
            str(settings.pcap_snaplen),
            "-w",
            str(target),
            # Ring buffer: rotate at -C megabytes, keep -W files, overwrite the
            # oldest. This is the disk ceiling, enforced by tcpdump itself.
            "-C",
            str(settings.pcap_file_mb),
            "-W",
            str(settings.pcap_files),
            # Packet-buffered. Without it the current file lags by a full 4 KB
            # buffer, so an extract run moments after an attack silently misses
            # the packets the operator is asking about.
            "-U",
            # Never resolve names: a reverse lookup per attacker IP is slow,
            # leaks the honeypot's interest to DNS, and can block the writer.
            "-n",
            bpf,
        ]
        try:
            self._process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            self._error = f"could not start tcpdump: {e}"
            return {"started": False, "available": True, "reason": self._error}

        # tcpdump exits fast on a bad filter or a permission problem. Give it a
        # moment and surface the real message instead of reporting success and
        # letting the operator find out when the directory stays empty.
        await asyncio.sleep(0.4)
        if self._process.returncode is not None:
            stderr = b""
            if self._process.stderr is not None:
                with contextlib.suppress(Exception):
                    stderr = await self._process.stderr.read()
            detail = stderr.decode(errors="replace").strip().splitlines()
            self._error = (
                detail[-1][:200] if detail else f"tcpdump exited {self._process.returncode}"
            )
            self._process = None
            return {"started": False, "available": True, "reason": self._error}

        self._filter = bpf
        self._started_at = time.time()
        self._error = None
        ceiling_mb = settings.pcap_file_mb * settings.pcap_files
        log.info(
            "Packet capture started on %s (%d ports, ring ceiling %d MB)",
            settings.pcap_interface,
            len(ports),
            ceiling_mb,
        )
        return {
            "started": True,
            "available": True,
            "interface": settings.pcap_interface,
            "filter": bpf,
            "directory": str(directory),
            "disk_ceiling_mb": ceiling_mb,
        }

    async def stop(self) -> None:
        process, self._process = self._process, None
        if process is None or process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=5.0)
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        self._started_at = None

    def files(self) -> list[Path]:
        """Ring files, oldest first. tcpdump suffixes them 0..N-1 and cycles,
        so mtime is the only reliable ordering."""
        directory = self._directory()
        if not directory.is_dir():
            return []
        found = [p for p in directory.glob("honeypot.pcap*") if p.is_file()]
        return sorted(found, key=lambda p: p.stat().st_mtime)

    def status(self) -> dict[str, Any]:
        files = self.files()
        total = sum(p.stat().st_size for p in files)
        settings = get_settings()
        return {
            "enabled": settings.pcap_enabled,
            "running": self.running,
            "interface": settings.pcap_interface,
            "filter": self._filter or None,
            "last_error": self._error,
            "uptime_seconds": (round(time.time() - self._started_at) if self._started_at else None),
            "files": len(files),
            "bytes_on_disk": total,
            "disk_ceiling_mb": settings.pcap_file_mb * settings.pcap_files,
            "directory": str(self._directory()),
        }

    async def extract(self, source_ip: str, output: str | None = None) -> dict[str, Any]:
        """Every captured packet involving `source_ip`, as one pcap file.

        This is the workflow the capture exists for: an alert names an attacker,
        and the analyst wants that attacker's traffic — not a 1 GB ring to sift
        through. Filtering runs through tcpdump's own BPF rather than a
        hand-rolled parser, because link-layer framing varies by interface
        (`any` yields Linux SLL, not Ethernet) and getting that subtly wrong
        would silently return no packets.
        """
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            return {"error": f"{source_ip!r} is not a valid IP address"}

        capability = probe_capability()
        if capability.tcpdump_path is None:
            return {"error": capability.reason}

        sources = self.files()
        if not sources:
            return {
                "error": "no capture files on disk",
                "hint": "packet capture may be disabled (PCAP_ENABLED) or not yet started",
            }

        from honeypot_mcp.tools._format import resolve_artifact_path

        # Confined to reports_dir like every other artifact writer: this
        # filename can originate from a model that has been reading
        # attacker-authored payloads.
        resolved = resolve_artifact_path(
            str(output) if output else None, prefix="pcap", extension="pcap"
        )
        if isinstance(resolved, str):
            return {"error": resolved}
        destination = resolved
        pieces: list[Path] = []
        scratch = destination.parent / f".extract-{os.getpid()}"
        scratch.mkdir(parents=True, exist_ok=True)
        try:
            for index, source in enumerate(sources):
                piece = scratch / f"part-{index}.pcap"
                proc = await asyncio.create_subprocess_exec(
                    capability.tcpdump_path,
                    "-r",
                    str(source),
                    "-w",
                    str(piece),
                    "-n",
                    f"host {source_ip}",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
                if piece.exists() and piece.stat().st_size > _PCAP_GLOBAL_HEADER_LEN:
                    pieces.append(piece)
            packets = merge_pcaps(pieces, destination)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

        return {
            "path": str(destination),
            "packets": packets,
            "bytes": destination.stat().st_size if destination.exists() else 0,
            "source_ip": source_ip,
            "searched_files": len(sources),
            "note": (
                "Open with Wireshark, or replay through Suricata/Zeek. "
                "Empty results mean the traffic predates the ring buffer's oldest file."
            ),
        }


_capture: PcapCapture | None = None


def get_capture() -> PcapCapture:
    global _capture
    if _capture is None:
        _capture = PcapCapture()
    return _capture


async def start_capture_for_running_honeypots() -> dict[str, Any]:
    """Derive the port list from the DB and start capture. Called at startup
    and after a deploy/stop changes which ports matter."""
    if not get_settings().pcap_enabled:
        return {"started": False, "enabled": False, "reason": "PCAP_ENABLED is false"}

    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeypot, HoneypotStatus

    async with get_session() as session:
        rows = (
            await session.execute(
                select(Honeypot.port, Honeypot.type).where(
                    Honeypot.status == HoneypotStatus.RUNNING
                )
            )
        ).all()

    from honeypot_mcp.deception.capabilities import transport_for

    ports = [
        (port, transport_for(hp_type.value if hasattr(hp_type, "value") else str(hp_type)))
        for port, hp_type in rows
    ]
    return await get_capture().start(ports)


async def refresh_capture() -> None:
    """Re-derive the filter after the deployed set changes. Silent no-op when
    capture is disabled, so callers don't need to know whether it is on."""
    if not get_settings().pcap_enabled:
        return
    with contextlib.suppress(Exception):
        await start_capture_for_running_honeypots()
