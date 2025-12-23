"""Strix Plugin System.

This package provides a flexible plugin architecture for security tools:
- BasePlugin: Abstract base class for all plugins
- PluginRegistry: Central registry for plugin management
- PluginLoader: Dynamic plugin loading and validation
- PluginManifest: Plugin metadata and configuration

Usage:
    from strix.plugins import PluginRegistry, get_plugin_registry
    
    registry = get_plugin_registry()
    
    # Get a plugin
    nuclei = registry.get_plugin("nuclei")
    
    # Execute plugin
    async for event in nuclei.execute(target, phase, params):
        print(event)
"""

from strix.plugins.base import (
    BasePlugin,
    PluginCapability,
    PluginEvent,
    PluginResult,
    PluginStatus,
    ScanPhase,
)
from strix.plugins.registry import (
    PluginRegistry,
    get_plugin_registry,
    set_plugin_registry,
)
from strix.plugins.loader import PluginLoader
from strix.plugins.manifest import PluginManifest

__all__ = [
    # Base classes
    "BasePlugin",
    "PluginCapability",
    "PluginEvent",
    "PluginResult",
    "PluginStatus",
    "ScanPhase",
    # Registry
    "PluginRegistry",
    "get_plugin_registry",
    "set_plugin_registry",
    # Loader
    "PluginLoader",
    # Manifest
    "PluginManifest",
]
