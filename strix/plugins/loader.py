"""Plugin Loader.

This module handles dynamic loading of plugins from the filesystem.
It discovers plugins in the plugins directory, validates them, and
creates plugin instances.
"""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.plugins.base import BasePlugin, PluginConfig
from strix.plugins.manifest import PluginManifest

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class PluginLoadError(Exception):
    """Error loading a plugin."""
    pass


class PluginLoader:
    """Loads plugins from the filesystem.
    
    Plugins are expected to have the following structure:
    
    plugins/
        my_plugin/
            manifest.yaml      # Plugin metadata
            plugin.py          # Plugin implementation (must have PluginClass)
            templates/         # Optional: template files
            config/            # Optional: default configurations
    
    The plugin.py file must define a class that inherits from BasePlugin.
    By convention, the class should be named after the plugin with "Plugin" suffix.
    """
    
    def __init__(
        self,
        builtin_plugins_dir: Path | None = None,
        user_plugins_dir: Path | None = None,
    ):
        """Initialize the plugin loader.
        
        Args:
            builtin_plugins_dir: Directory containing built-in plugins
            user_plugins_dir: Directory containing user-installed plugins
        """
        # Default directories
        self.builtin_plugins_dir = builtin_plugins_dir or (
            Path(__file__).parent.parent.parent / "plugins"
        )
        self.user_plugins_dir = user_plugins_dir or (
            Path.home() / ".strix" / "plugins"
        )
        
        # Ensure directories exist
        self.builtin_plugins_dir.mkdir(parents=True, exist_ok=True)
        self.user_plugins_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache of loaded plugins
        self._plugins: dict[str, type[BasePlugin]] = {}
        self._manifests: dict[str, PluginManifest] = {}
    
    def discover_plugins(self) -> list[str]:
        """Discover all available plugins.
        
        Returns:
            List of plugin names
        """
        plugins = []
        
        # Scan built-in plugins
        plugins.extend(self._scan_directory(self.builtin_plugins_dir))
        
        # Scan user plugins
        plugins.extend(self._scan_directory(self.user_plugins_dir))
        
        return list(set(plugins))  # Remove duplicates
    
    def _scan_directory(self, directory: Path) -> list[str]:
        """Scan a directory for plugins."""
        plugins = []
        
        if not directory.exists():
            return plugins
        
        for item in directory.iterdir():
            if item.is_dir() and not item.name.startswith("_"):
                manifest_path = item / "manifest.yaml"
                plugin_path = item / "plugin.py"
                
                if manifest_path.exists() and plugin_path.exists():
                    plugins.append(item.name)
                    logger.debug(f"Discovered plugin: {item.name}")
        
        return plugins
    
    def load_manifest(self, plugin_name: str) -> PluginManifest:
        """Load a plugin's manifest.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            PluginManifest object
            
        Raises:
            PluginLoadError: If manifest cannot be loaded
        """
        if plugin_name in self._manifests:
            return self._manifests[plugin_name]
        
        plugin_dir = self._find_plugin_dir(plugin_name)
        manifest_path = plugin_dir / "manifest.yaml"
        
        if not manifest_path.exists():
            raise PluginLoadError(f"Manifest not found for plugin: {plugin_name}")
        
        try:
            manifest = PluginManifest.from_yaml(manifest_path)
            
            # Validate manifest
            is_valid, errors = manifest.validate()
            if not is_valid:
                raise PluginLoadError(
                    f"Invalid manifest for {plugin_name}: {', '.join(errors)}"
                )
            
            self._manifests[plugin_name] = manifest
            return manifest
            
        except Exception as e:
            raise PluginLoadError(f"Error loading manifest for {plugin_name}: {e}") from e
    
    def load_plugin_class(self, plugin_name: str) -> type[BasePlugin]:
        """Load a plugin class.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin class (not instance)
            
        Raises:
            PluginLoadError: If plugin cannot be loaded
        """
        if plugin_name in self._plugins:
            return self._plugins[plugin_name]
        
        plugin_dir = self._find_plugin_dir(plugin_name)
        plugin_path = plugin_dir / "plugin.py"
        
        if not plugin_path.exists():
            raise PluginLoadError(f"Plugin file not found: {plugin_path}")
        
        try:
            # Load the module
            spec = importlib.util.spec_from_file_location(
                f"strix_plugins.{plugin_name}",
                plugin_path,
            )
            if spec is None or spec.loader is None:
                raise PluginLoadError(f"Cannot load spec for {plugin_name}")
            
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            
            # Find the plugin class
            plugin_class = None
            for name in dir(module):
                obj = getattr(module, name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                ):
                    plugin_class = obj
                    break
            
            if plugin_class is None:
                raise PluginLoadError(
                    f"No BasePlugin subclass found in {plugin_path}"
                )
            
            self._plugins[plugin_name] = plugin_class
            logger.info(f"Loaded plugin class: {plugin_name}")
            return plugin_class
            
        except Exception as e:
            raise PluginLoadError(f"Error loading plugin {plugin_name}: {e}") from e
    
    def create_plugin(
        self,
        plugin_name: str,
        config: PluginConfig | None = None,
    ) -> BasePlugin:
        """Create a plugin instance.
        
        Args:
            plugin_name: Name of the plugin
            config: Optional plugin configuration
            
        Returns:
            Plugin instance
        """
        plugin_class = self.load_plugin_class(plugin_name)
        return plugin_class(config=config)
    
    def _find_plugin_dir(self, plugin_name: str) -> Path:
        """Find the directory for a plugin.
        
        Checks user plugins first, then built-in plugins.
        """
        # Check user plugins first (allows overriding built-in)
        user_path = self.user_plugins_dir / plugin_name
        if user_path.exists():
            return user_path
        
        # Check built-in plugins
        builtin_path = self.builtin_plugins_dir / plugin_name
        if builtin_path.exists():
            return builtin_path
        
        raise PluginLoadError(f"Plugin not found: {plugin_name}")
    
    def get_plugin_info(self, plugin_name: str) -> dict[str, Any]:
        """Get information about a plugin without loading it fully.
        
        Returns:
            Dictionary with plugin metadata
        """
        manifest = self.load_manifest(plugin_name)
        return manifest.to_dict()
    
    def reload_plugin(self, plugin_name: str) -> type[BasePlugin]:
        """Reload a plugin (useful for development).
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Reloaded plugin class
        """
        # Remove from caches
        self._plugins.pop(plugin_name, None)
        self._manifests.pop(plugin_name, None)
        
        # Remove from sys.modules
        module_name = f"strix_plugins.{plugin_name}"
        if module_name in sys.modules:
            del sys.modules[module_name]
        
        # Reload
        return self.load_plugin_class(plugin_name)
    
    def validate_plugin(self, plugin_name: str) -> tuple[bool, list[str]]:
        """Validate a plugin.
        
        Checks:
        - Manifest is valid
        - Plugin class can be loaded
        - Plugin class implements required methods
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check manifest
        try:
            manifest = self.load_manifest(plugin_name)
            is_valid, manifest_errors = manifest.validate()
            if not is_valid:
                errors.extend(manifest_errors)
        except PluginLoadError as e:
            errors.append(f"Manifest error: {e}")
            return False, errors
        
        # Check plugin class
        try:
            plugin_class = self.load_plugin_class(plugin_name)
            
            # Check required class attributes
            required_attrs = ["name", "version", "phases", "capabilities"]
            for attr in required_attrs:
                if not hasattr(plugin_class, attr):
                    errors.append(f"Missing required attribute: {attr}")
            
            # Check required methods are implemented
            required_methods = [
                "check_installed",
                "install",
                "update",
                "execute",
                "parse_output",
            ]
            for method in required_methods:
                if not hasattr(plugin_class, method):
                    errors.append(f"Missing required method: {method}")
                    
        except PluginLoadError as e:
            errors.append(f"Plugin load error: {e}")
        
        return len(errors) == 0, errors


# Global loader instance
_loader: PluginLoader | None = None


def get_plugin_loader() -> PluginLoader:
    """Get the global plugin loader instance."""
    global _loader
    if _loader is None:
        _loader = PluginLoader()
    return _loader


def set_plugin_loader(loader: PluginLoader) -> None:
    """Set the global plugin loader instance."""
    global _loader
    _loader = loader
