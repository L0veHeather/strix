"""Plugin System Module.

This module defines the core architecture for Strix's plugin system, allowing
extensions to provide tools, prompt modules, and TCI logic.
"""

import importlib
import inspect
import logging
import pkgutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Type

from jinja2 import BaseLoader, TemplateNotFound

from strix.core.tci import TCIResult, TargetFingerprint

logger = logging.getLogger(__name__)


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""

    name: str
    version: str
    description: str
    author: str
    website: str = ""


class Plugin(ABC):
    """Abstract base class for Strix plugins."""

    def __init__(self) -> None:
        self.metadata = PluginMetadata(
            name=self.__class__.__name__,
            version="0.1.0",
            description="Strix Plugin",
            author="Unknown",
        )

    @abstractmethod
    def get_tools(self) -> list[Any]:
        """Return a list of tools (functions or classes) provided by this plugin."""
        return []

    @abstractmethod
    def get_prompt_modules(self) -> dict[str, str]:
        """Return a dictionary of prompt modules provided by this plugin.
        
        Key: module name
        Value: prompt template content or path
        """
        return {}

    def get_tci_weights(self) -> dict[str, float]:
        """Return custom TCI weights provided by this plugin."""
        return {}

    def on_load(self) -> None:
        """Called when the plugin is loaded."""
        pass

    def on_unload(self) -> None:
        """Called when the plugin is unloaded."""
        pass


class PluginManager:
    """Manages the lifecycle of Strix plugins."""

    def __init__(self) -> None:
        self.plugins: dict[str, Plugin] = {}
        self.tools: list[Any] = []
        self.prompt_modules: dict[str, str] = {}
        self.tci_weights: dict[str, float] = {}

    def load_plugin(self, plugin_class: Type[Plugin]) -> None:
        """Load a single plugin class."""
        try:
            # Import here to avoid circular dependency
            from strix.tools.registry import register_tool, get_tool_by_name
            
            plugin = plugin_class()
            plugin.on_load()
            
            # Register tools
            new_tools = plugin.get_tools()
            for tool in new_tools:
                # Check if tool is already registered
                if hasattr(tool, "__name__") and not get_tool_by_name(tool.__name__):
                    register_tool(tool)
            
            self.tools.extend(new_tools)
            
            # Register prompt modules
            new_modules = plugin.get_prompt_modules()
            self.prompt_modules.update(new_modules)
            
            # Register TCI weights
            new_weights = plugin.get_tci_weights()
            self.tci_weights.update(new_weights)
            
            self.plugins[plugin.metadata.name] = plugin
            logger.info(f"Loaded plugin: {plugin.metadata.name} v{plugin.metadata.version}")
            
        except Exception as e:
            logger.error(f"Failed to load plugin {plugin_class.__name__}: {e}")

    def load_plugins_from_dir(self, directory: Path) -> None:
        """Load all plugins from a directory."""
        if not directory.exists():
            return

        # Add directory to sys.path so we can import modules
        sys.path.insert(0, str(directory))
        
        for _, name, _ in pkgutil.iter_modules([str(directory)]):
            try:
                module = importlib.import_module(name)
                self._load_plugins_from_module(module)
            except Exception as e:
                logger.error(f"Failed to import module {name} from {directory}: {e}")
        
        # Remove directory from sys.path
        sys.path.pop(0)

    def _load_plugins_from_module(self, module: Any) -> None:
        """Scan a module for Plugin subclasses and load them."""
        for name, obj in inspect.getmembers(module):
            if (
                inspect.isclass(obj)
                and issubclass(obj, Plugin)
                and obj is not Plugin
            ):
                self.load_plugin(obj)

    def get_all_tools(self) -> list[Any]:
        """Get all registered tools."""
        return self.tools

    def get_all_prompt_modules(self) -> dict[str, str]:
        """Get all registered prompt modules."""
        return self.prompt_modules

    def get_plugin(self, name: str) -> Plugin | None:
        """Get a loaded plugin by name."""
        return self.plugins.get(name)

# Global singleton instance
_plugin_manager = PluginManager()

def get_plugin_manager() -> PluginManager:
    """Get the global plugin manager instance."""
    return _plugin_manager


class PluginPromptLoader(BaseLoader):
    """Jinja2 loader for plugin-provided prompts."""

    def __init__(self, plugin_manager: PluginManager) -> None:
        self.plugin_manager = plugin_manager

    def get_source(self, environment: Any, template: str) -> tuple[str, str | None, Any]:
        prompts = self.plugin_manager.get_all_prompt_modules()
        
        # Check if template name matches a plugin module
        # Plugins might provide templates like "module_name.jinja" or just "module_name"
        template_name = template.replace(".jinja", "")
        
        if template_name in prompts:
            source = prompts[template_name]
            return source, None, lambda: True
            
        raise TemplateNotFound(template)
