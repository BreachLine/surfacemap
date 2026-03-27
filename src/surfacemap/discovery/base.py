"""Base class for all discovery modules.

Every discovery module inherits from DiscoveryModule and implements
the discover() method. The safe_discover() wrapper handles errors
gracefully so one failing module doesn't crash the pipeline.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod

from surfacemap.core.models import ScanResult

logger = logging.getLogger(__name__)

# Maximum time any single module can run before being killed.
# Configurable via SURFACEMAP_MODULE_TIMEOUT env var (default 120s).
import os
_MODULE_TIMEOUT = int(os.getenv("SURFACEMAP_MODULE_TIMEOUT", "120"))


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
        """Run discover() with error handling and a hard timeout.

        Returns True if the module completed successfully, False otherwise.
        Each module gets at most _MODULE_TIMEOUT seconds before being cancelled.
        """
        try:
            await asyncio.wait_for(
                self.discover(target, result),
                timeout=_MODULE_TIMEOUT,
            )
            return True
        except asyncio.TimeoutError:
            logger.warning("[%s] Timed out after %ds for %s", self.name, _MODULE_TIMEOUT, target)
            return False
        except Exception as e:
            logger.error("[%s] Failed: %s", self.name, e)
            return False
