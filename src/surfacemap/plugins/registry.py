"""Plugin registry — singleton that holds registered discovery module classes."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Singleton registry for discovery module plugins."""

    _instance: PluginRegistry | None = None

    def __new__(cls) -> PluginRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._modules: dict[str, list[type[DiscoveryModule]]] = {
                "passive": [],
                "active": [],
            }
        return cls._instance

    def register(self, module_class: type[DiscoveryModule], phase: str = "passive") -> None:
        """Register a DiscoveryModule subclass for a given phase.

        Args:
            module_class: A class that extends DiscoveryModule.
            phase: Either "passive" or "active".
        """
        if phase not in self._modules:
            logger.warning("Unknown phase %r, defaulting to 'passive'", phase)
            phase = "passive"

        if module_class not in self._modules[phase]:
            self._modules[phase].append(module_class)
            logger.debug("Registered plugin %s for phase %s", module_class.__name__, phase)

    def get_modules(self, phase: str) -> list[DiscoveryModule]:
        """Return instantiated modules for the given phase.

        Args:
            phase: Either "passive" or "active".

        Returns:
            List of instantiated DiscoveryModule objects.
        """
        classes = self._modules.get(phase, [])
        instances: list[DiscoveryModule] = []
        for cls in classes:
            try:
                instances.append(cls())
            except Exception as e:
                logger.error("Failed to instantiate plugin %s: %s", cls.__name__, e)
        return instances

    def list_plugins(self) -> list[dict]:
        """Return a list of plugin info dicts (name, description, phase)."""
        plugins: list[dict] = []
        for phase, classes in self._modules.items():
            for cls in classes:
                try:
                    instance = cls()
                    plugins.append({
                        "name": instance.name,
                        "description": instance.description,
                        "phase": phase,
                    })
                except Exception as e:
                    plugins.append({
                        "name": cls.__name__,
                        "description": f"(error: {e})",
                        "phase": phase,
                    })
        return plugins


def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    return PluginRegistry()
