"""Abstract base class for all honeypot engines."""

from __future__ import annotations

import asyncio
import contextlib
import socket
from abc import ABC, abstractmethod
from typing import Any

from honeypot_mcp import self_probe


async def tcp_probe(port: int, host: str = "127.0.0.1", timeout: float = 2.0) -> dict[str, Any]:
    """Default health-check primitive: open a TCP connection and immediately close.
    Confirms the OS is actually accepting connections on the port — catches
    cases where a server crashed but the engine's internal state still says
    'running'.

    The engine on the other end records this connection as an attack; it cannot
    tell us apart from a real peer. We bind the source port ourselves and claim
    it via `self_probe` *before* connecting, so `submit_event` can drop the
    resulting event.

    Ordering is the whole trick. Registering after the connect returns loses a
    race against any engine that records in `connection_made` — that callback
    runs as soon as the kernel completes the handshake, which is before
    `connect()` hands control back to us. FTP and SMTP do exactly that, and
    kept logging probes as attacks until the claim moved ahead of the connect.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        # Only valid when the target is a local address, which is the only way
        # the watchdog uses this. Anywhere else the bind fails harmlessly and
        # we simply probe without a claim.
        with contextlib.suppress(OSError):
            sock.bind((host, 0))
            self_probe.register(sock.getsockname())

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
        return {"alive": True, "detail": "TCP port responsive", "method": "tcp"}
    except TimeoutError:
        return {"alive": False, "detail": f"TCP probe timed out after {timeout}s", "method": "tcp"}
    except (ConnectionRefusedError, OSError) as e:
        return {"alive": False, "detail": f"TCP probe failed: {e}", "method": "tcp"}
    finally:
        sock.close()


class HoneypotEngine(ABC):
    """All honeypot engines must implement this interface.

    Each engine manages the lifecycle of one type of honeypot and is responsible
    for starting/stopping containers or processes and ingesting events into the DB.
    """

    @abstractmethod
    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        """Start a new honeypot instance.

        Returns the container/process ID string.
        """

    @abstractmethod
    async def stop(self, container_id: str, remove: bool = False) -> None:
        """Stop (and optionally remove) a running honeypot instance."""

    @abstractmethod
    async def status(self, container_id: str) -> dict[str, Any]:
        """Return current runtime status for the instance."""

    @abstractmethod
    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        """Return the most recent log lines from the instance."""

    async def reattach(
        self, name: str, port: int, config: dict[str, Any], container_id: str
    ) -> str:
        """Re-establish a honeypot that the DB says is RUNNING after a server
        restart. In-process engines die with the process, so the default is to
        start fresh. Returns the (possibly new) container/process ID.

        Docker-backed engines override this: their containers survive the
        restart, but per-honeypot background work (log ingestion) must be
        re-attached to the still-running container.
        """
        return await self.start(name, port, config)

    async def pause(self, container_id: str) -> None:
        """Pause a running instance (default: no-op for non-Docker engines)."""

    async def resume(self, container_id: str) -> None:
        """Resume a paused instance (default: no-op for non-Docker engines)."""

    async def health_check(self, container_id: str, port: int) -> dict[str, Any]:
        """Return `{alive: bool, detail: str, method: str, ...}`.

        Default: TCP probe to localhost:port. Override for protocols that
        need a deeper check (Docker container status, UDP, etc.).
        """
        return await tcp_probe(port)
