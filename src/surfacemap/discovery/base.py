"""Base class for all discovery modules.

Every discovery module inherits from DiscoveryModule and implements
the discover() method. The safe_discover() wrapper handles errors
gracefully so one failing module doesn't crash the pipeline.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from surfacemap.core.models import ScanResult

logger = logging.getLogger(__name__)


class DiscoveryModule(ABC):
    """Abstract base class for discovery modules."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this module."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what this module discovers."""

    @abstractmethod
    async def discover(self, target: str, result: ScanResult) -> None:
        """Run discovery against the target and add assets to result.

        Args:
            target: The primary target (company name or domain).
            result: The ScanResult to add discovered assets to.
        """

    async def safe_discover(self, target: str, result: ScanResult) -> bool:
        """Run discover() with error handling.

        Returns True if the module completed successfully, False otherwise.
        """
        try:
            logger.info("[%s] Starting discovery for %s", self.name, target)
            await self.discover(target, result)
            logger.info(
                "[%s] Completed — %d total assets",
                self.name,
                len(result.assets),
            )
            return True
        except Exception as e:
            logger.error("[%s] Failed: %s", self.name, e, exc_info=True)
            return False
