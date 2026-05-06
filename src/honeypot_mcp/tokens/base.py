"""Abstract base class for all honeytoken providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class HoneytokenProvider(ABC):
    """Subclass this to add a new honeytoken type.

    create() returns (token_value, extra_metadata).
    plant_instructions() returns human-readable guidance for planting the token.
    """

    @abstractmethod
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Generate a new token value and any extra metadata to store.

        Returns:
            (token_value, extra_metadata)
        """

    @abstractmethod
    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        """Return human-readable instructions for planting this token."""
