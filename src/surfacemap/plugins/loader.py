"""Plugin loader — discovers and loads plugins from entry points and local directories."""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import inspect
import logging
from pathlib import Path

from surfacemap.core.config import get_config
from surfacemap.discovery.base import DiscoveryModule
from surfacemap.plugins.registry import get_registry

logger = logging.getLogger(__name__)

_loaded = False


def load_plugins() -> None:
    """Load plugins from entry points and local plugin directories.

    Sources:
        1. Python entry points in the ``surfacemap.modules`` group.
        2. ``.py`` files found in ``~/.surfacemap/plugins/`` and any extra
           directories listed in ``SURFACEMAP_PLUGIN_DIRS`` (comma-separated).

    This function is idempotent — subsequent calls are no-ops.
    """
    global _loaded
    if _loaded:
        return
    _loaded = True

    registry = get_registry()

    _load_entry_points(registry)
    _load_local_plugins(registry)


def _load_entry_points(registry) -> None:
    """Load plugins registered via Python entry points."""
    try:
        eps = importlib.metadata.entry_points(group="surfacemap.modules")
    except TypeError:
        eps = importlib.metadata.entry_points().get("surfacemap.modules", [])

    for ep in eps:
        try:
            obj = ep.load()
            if inspect.isclass(obj) and issubclass(obj, DiscoveryModule) and obj is not DiscoveryModule:
                phase = getattr(obj, "plugin_phase", "passive")
                registry.register(obj, phase=phase)
                logger.info("Loaded entry-point plugin: %s (%s)", ep.name, phase)
        except Exception as e:
            logger.warning("Failed to load entry-point plugin %s: %s", ep.name, e)


def _load_local_plugins(registry) -> None:
    """Load plugins from local filesystem directories."""
    config = get_config()

    plugin_dirs: list[Path] = [Path.home() / ".surfacemap" / "plugins"]

    if config.plugin_dirs:
        for d in config.plugin_dirs.split(","):
            d = d.strip()
            if d:
                plugin_dirs.append(Path(d))

    for plugin_dir in plugin_dirs:
        if not plugin_dir.is_dir():
            continue

        logger.debug("Scanning plugin directory: %s", plugin_dir)

        for py_file in sorted(plugin_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue

            module_name = f"surfacemap_plugin_{py_file.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        inspect.isclass(attr)
                        and issubclass(attr, DiscoveryModule)
                        and attr is not DiscoveryModule
                    ):
                        phase = getattr(attr, "plugin_phase", "passive")
                        registry.register(attr, phase=phase)
                        logger.info("Loaded local plugin: %s from %s (%s)", attr_name, py_file.name, phase)

            except Exception as e:
                logger.warning("Failed to load plugin from %s: %s", py_file, e)
