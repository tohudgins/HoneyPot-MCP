"""Abstract base class for all honeypot engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


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

    async def pause(self, container_id: str) -> None:
        """Pause a running instance (default: no-op for non-Docker engines)."""

    async def resume(self, container_id: str) -> None:
        """Resume a paused instance (default: no-op for non-Docker engines)."""
