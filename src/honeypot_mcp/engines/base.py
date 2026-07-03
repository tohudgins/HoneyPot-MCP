"""Abstract base class for all honeypot engines."""

from __future__ import annotations

import asyncio
import contextlib
from abc import ABC, abstractmethod
from typing import Any


async def tcp_probe(port: int, host: str = "127.0.0.1", timeout: float = 2.0) -> dict[str, Any]:
    """Default health-check primitive: open a TCP connection and immediately close.
    Confirms the OS is actually accepting connections on the port — catches
    cases where a server crashed but the engine's internal state still says
    'running'."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return {"alive": True, "detail": "TCP port responsive", "method": "tcp"}
    except TimeoutError:
        return {"alive": False, "detail": f"TCP probe timed out after {timeout}s", "method": "tcp"}
    except (ConnectionRefusedError, OSError) as e:
        return {"alive": False, "detail": f"TCP probe failed: {e}", "method": "tcp"}


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
