"""Plugin Manifest Parser.

This module handles parsing and validation of plugin manifest files (manifest.yaml).
The manifest defines plugin metadata, dependencies, and configuration schema.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from strix.plugins.base import PluginCapability, ScanPhase

logger = logging.getLogger(__name__)


@dataclass
class ExecutableConfig:
    """Configuration for the plugin's executable."""
    
    type: str  # go_binary, python_package, system_binary, npm_package
    binary_name: str
    install_command: str | None = None
    version_command: str | None = None
    update_command: str | None = None
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExecutableConfig:
        return cls(
            type=data.get("type", "system_binary"),
            binary_name=data.get("binary_name", ""),
            install_command=data.get("install_command"),
            version_command=data.get("version_command"),
            update_command=data.get("update_command"),
        )


@dataclass
class TemplateConfig:
    """Configuration for template-based tools (like nuclei)."""
    
    enabled: bool = False
    update_command: str | None = None
    custom_dir: str | None = None
    default_categories: list[str] = field(default_factory=list)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TemplateConfig:
        return cls(
            enabled=data.get("enabled", False),
            update_command=data.get("update_command"),
            custom_dir=data.get("custom_dir"),
            default_categories=data.get("default_categories", []),
        )


@dataclass
class ParameterDefinition:
    """Definition of a plugin parameter."""
    
    name: str
    type: str  # string, number, boolean, select, multiselect, file
    description: str
    required: bool = False
    default: Any = None
    options: list[str] | None = None
    options_source: str | None = None  # For dynamic options
    min_value: int | float | None = None
    max_value: int | float | None = None
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParameterDefinition:
        return cls(
            name=data.get("name", ""),
            type=data.get("type", "string"),
            description=data.get("description", ""),
            required=data.get("required", False),
            default=data.get("default"),
            options=data.get("options"),
            options_source=data.get("options_source"),
            min_value=data.get("min"),
            max_value=data.get("max"),
        )
    
    def to_json_schema(self) -> dict[str, Any]:
        """Convert to JSON Schema for form generation."""
        schema: dict[str, Any] = {
            "title": self.name.replace("_", " ").title(),
            "description": self.description,
        }
        
        if self.type == "string":
            schema["type"] = "string"
            if self.options:
                schema["enum"] = self.options
        elif self.type == "number":
            schema["type"] = "number"
            if self.min_value is not None:
                schema["minimum"] = self.min_value
            if self.max_value is not None:
                schema["maximum"] = self.max_value
        elif self.type == "boolean":
            schema["type"] = "boolean"
        elif self.type == "select":
            schema["type"] = "string"
            schema["enum"] = self.options or []
        elif self.type == "multiselect":
            schema["type"] = "array"
            schema["items"] = {"type": "string", "enum": self.options or []}
        elif self.type == "file":
            schema["type"] = "string"
            schema["format"] = "file"
        
        if self.default is not None:
            schema["default"] = self.default
        
        return schema


@dataclass
class OutputConfig:
    """Configuration for parsing plugin output."""
    
    format: str  # json, jsonl, xml, csv, text
    parser: str | None = None  # Custom parser name
    vulnerability_mapping: dict[str, str] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OutputConfig:
        return cls(
            format=data.get("format", "text"),
            parser=data.get("parser"),
            vulnerability_mapping=data.get("vulnerability_mapping", {}),
        )


@dataclass
class UIConfig:
    """UI-specific configuration."""
    
    icon: str = "🔧"
    color: str = "#6366f1"
    category: str = "general"
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UIConfig:
        return cls(
            icon=data.get("icon", "🔧"),
            color=data.get("color", "#6366f1"),
            category=data.get("category", "general"),
        )


@dataclass
class PluginManifest:
    """Complete plugin manifest.
    
    Parsed from manifest.yaml in the plugin directory.
    """
    
    name: str
    version: str
    display_name: str
    description: str
    author: str = "Unknown"
    homepage: str = ""
    license: str = "MIT"
    
    # Scan phases this plugin supports
    phases: list[ScanPhase] = field(default_factory=list)
    
    # Capabilities
    capabilities: list[PluginCapability] = field(default_factory=list)
    
    # Executable configuration
    executable: ExecutableConfig | None = None
    
    # Template configuration (optional)
    templates: TemplateConfig | None = None
    
    # Parameter definitions
    parameters: list[ParameterDefinition] = field(default_factory=list)
    
    # Output configuration
    output: OutputConfig | None = None
    
    # UI configuration
    ui: UIConfig = field(default_factory=UIConfig)
    
    # Dependencies on other plugins
    dependencies: list[str] = field(default_factory=list)
    
    # Tags for categorization
    tags: list[str] = field(default_factory=list)
    
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> PluginManifest:
        """Load manifest from YAML file."""
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PluginManifest:
        """Create manifest from dictionary."""
        # Parse phases
        phases = []
        for phase_str in data.get("phases", []):
            try:
                phases.append(ScanPhase(phase_str))
            except ValueError:
                logger.warning(f"Unknown phase: {phase_str}")
        
        # Parse capabilities
        capabilities = []
        for cap_str in data.get("capabilities", []):
            try:
                capabilities.append(PluginCapability(cap_str))
            except ValueError:
                logger.warning(f"Unknown capability: {cap_str}")
        
        # Parse parameters
        parameters = [
            ParameterDefinition.from_dict(p)
            for p in data.get("parameters", [])
        ]
        
        return cls(
            name=data.get("name", "unknown"),
            version=data.get("version", "0.0.0"),
            display_name=data.get("display_name", data.get("name", "Unknown")),
            description=data.get("description", ""),
            author=data.get("author", "Unknown"),
            homepage=data.get("homepage", ""),
            license=data.get("license", "MIT"),
            phases=phases,
            capabilities=capabilities,
            executable=ExecutableConfig.from_dict(data["executable"]) if "executable" in data else None,
            templates=TemplateConfig.from_dict(data["templates"]) if "templates" in data else None,
            parameters=parameters,
            output=OutputConfig.from_dict(data["output"]) if "output" in data else None,
            ui=UIConfig.from_dict(data.get("ui", {})),
            dependencies=data.get("dependencies", []),
            tags=data.get("tags", []),
        )
    
    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "display_name": self.display_name,
            "description": self.description,
            "author": self.author,
            "homepage": self.homepage,
            "license": self.license,
            "phases": [p.value for p in self.phases],
            "capabilities": [c.value for c in self.capabilities],
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type,
                    "description": p.description,
                    "required": p.required,
                    "default": p.default,
                }
                for p in self.parameters
            ],
            "ui": {
                "icon": self.ui.icon,
                "color": self.ui.color,
                "category": self.ui.category,
            },
            "dependencies": self.dependencies,
            "tags": self.tags,
        }
    
    def get_json_schema(self) -> dict[str, Any]:
        """Generate JSON Schema for parameter form."""
        properties = {}
        required = []
        
        for param in self.parameters:
            properties[param.name] = param.to_json_schema()
            if param.required:
                required.append(param.name)
        
        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }
    
    def validate(self) -> tuple[bool, list[str]]:
        """Validate the manifest.
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        if not self.name:
            errors.append("Plugin name is required")
        
        if not self.version:
            errors.append("Plugin version is required")
        
        if not self.phases:
            errors.append("Plugin must support at least one scan phase")
        
        if self.executable is None:
            errors.append("Executable configuration is required")
        elif not self.executable.binary_name:
            errors.append("Executable binary_name is required")
        
        # Check parameter names are unique
        param_names = [p.name for p in self.parameters]
        if len(param_names) != len(set(param_names)):
            errors.append("Parameter names must be unique")
        
        return len(errors) == 0, errors
