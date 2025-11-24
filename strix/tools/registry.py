import inspect
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from inspect import signature
from pathlib import Path
from typing import Any


tools: list[dict[str, Any]] = []
_tools_by_name: dict[str, Callable[..., Any]] = {}
_tool_metadata: dict[str, "ToolMetadata"] = {}
logger = logging.getLogger(__name__)


class ToolPriority(str, Enum):
    """Priority level for tool execution in scan plans."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OPTIONAL = "optional"


@dataclass
class ToolMetadata:
    """Extended metadata for tools supporting adaptive scanning.

    This metadata enables the ScanPlanner to make intelligent decisions
    about tool selection, ordering, and resource allocation.
    """

    name: str
    priority: ToolPriority = ToolPriority.MEDIUM
    safe_mode: bool = True
    timeout_seconds: int = 300
    max_iterations: int = 100
    quota: int = 50  # Max requests/operations per invocation
    parallelizable: bool = True
    requires_auth: bool = False
    risk_level: str = "low"  # low, medium, high
    vulnerability_types: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "priority": self.priority.value,
            "safe_mode": self.safe_mode,
            "timeout_seconds": self.timeout_seconds,
            "max_iterations": self.max_iterations,
            "quota": self.quota,
            "parallelizable": self.parallelizable,
            "requires_auth": self.requires_auth,
            "risk_level": self.risk_level,
            "vulnerability_types": self.vulnerability_types,
            "tags": self.tags,
            "dependencies": self.dependencies,
        }


class AgentRole(str, Enum):
    """Roles that agents can have, determining tool access."""

    COORDINATOR = "coordinator"
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_TESTER = "vulnerability_tester"
    VALIDATOR = "validator"
    REPORTER = "reporter"
    FIX_GENERATOR = "fix_generator"
    FULL_ACCESS = "full_access"


# Tool profiles mapping roles to allowed tools
TOOL_PROFILES: dict[AgentRole, set[str]] = {
    AgentRole.COORDINATOR: {
        "agents_graph",
        "finish",
        "thinking",
        "notes",
    },
    AgentRole.RECONNAISSANCE: {
        "terminal",
        "proxy",
        "browser",
        "web_search",
        "notes",
        "thinking",
        "python",
    },
    AgentRole.VULNERABILITY_TESTER: {
        "terminal",
        "proxy",
        "browser",
        "python",
        "file_edit",
        "notes",
        "thinking",
        "reporting",
        "agents_graph",
    },
    AgentRole.VALIDATOR: {
        "terminal",
        "proxy",
        "browser",
        "python",
        "notes",
        "thinking",
    },
    AgentRole.REPORTER: {
        "notes",
        "reporting",
        "thinking",
        "file_edit",
    },
    AgentRole.FIX_GENERATOR: {
        "file_edit",
        "notes",
        "thinking",
        "python",
    },
    AgentRole.FULL_ACCESS: set(),  # Empty means all tools allowed
}

# Tools that are sequential and should not run in parallel
SEQUENTIAL_TOOLS: set[str] = {
    "terminal",
    "browser",
    "file_edit",
}

# Tools that can be parallelized
PARALLEL_TOOLS: set[str] = {
    "proxy",
    "notes",
    "thinking",
    "web_search",
    "python",
}


class ImplementedInClientSideOnlyError(Exception):
    def __init__(
        self,
        message: str = "This tool is implemented in the client side only",
    ) -> None:
        self.message = message
        super().__init__(self.message)


def _process_dynamic_content(content: str) -> str:
    if "{{DYNAMIC_MODULES_DESCRIPTION}}" in content:
        try:
            from strix.prompts import generate_modules_description

            modules_description = generate_modules_description()
            content = content.replace("{{DYNAMIC_MODULES_DESCRIPTION}}", modules_description)
        except ImportError:
            logger.warning("Could not import prompts utilities for dynamic schema generation")
            content = content.replace(
                "{{DYNAMIC_MODULES_DESCRIPTION}}",
                "List of prompt modules to load for this agent (max 5). Module discovery failed.",
            )

    return content


def _load_xml_schema(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        content = path.read_text()

        content = _process_dynamic_content(content)

        start_tag = '<tool name="'
        end_tag = "</tool>"
        tools_dict = {}

        pos = 0
        while True:
            start_pos = content.find(start_tag, pos)
            if start_pos == -1:
                break

            name_start = start_pos + len(start_tag)
            name_end = content.find('"', name_start)
            if name_end == -1:
                break
            tool_name = content[name_start:name_end]

            end_pos = content.find(end_tag, name_end)
            if end_pos == -1:
                break
            end_pos += len(end_tag)

            tool_element = content[start_pos:end_pos]
            tools_dict[tool_name] = tool_element

            pos = end_pos

            if pos >= len(content):
                break
    except (IndexError, ValueError, UnicodeError) as e:
        logger.warning(f"Error loading schema file {path}: {e}")
        return None
    else:
        return tools_dict


def _get_module_name(func: Callable[..., Any]) -> str:
    module = inspect.getmodule(func)
    if not module:
        return "unknown"

    module_name = module.__name__
    if ".tools." in module_name:
        parts = module_name.split(".tools.")[-1].split(".")
        if len(parts) >= 1:
            return parts[0]
    return "unknown"


def register_tool(
    func: Callable[..., Any] | None = None,
    *,
    sandbox_execution: bool = True,
    priority: ToolPriority | str = ToolPriority.MEDIUM,
    safe_mode: bool = True,
    timeout_seconds: int = 300,
    max_iterations: int = 100,
    quota: int = 50,
    parallelizable: bool = True,
    requires_auth: bool = False,
    risk_level: str = "low",
    vulnerability_types: list[str] | None = None,
    tags: list[str] | None = None,
    dependencies: list[str] | None = None,
) -> Callable[..., Any]:
    """Register a tool with optional metadata for adaptive scanning.

    Args:
        func: The function to register (used when decorator has no args)
        sandbox_execution: Whether tool runs in sandbox
        priority: Tool priority level (critical, high, medium, low, optional)
        safe_mode: Whether tool is safe for production environments
        timeout_seconds: Default timeout for tool execution
        max_iterations: Maximum iterations allowed
        quota: Maximum requests/operations per invocation
        parallelizable: Whether tool can run in parallel with others
        requires_auth: Whether tool requires authentication to target
        risk_level: Risk level (low, medium, high)
        vulnerability_types: Vulnerability types this tool can detect
        tags: Tags for filtering and categorization
        dependencies: Other tools this tool depends on
    """
    def decorator(f: Callable[..., Any]) -> Callable[..., Any]:
        # Convert string priority to enum if needed
        tool_priority = (
            ToolPriority(priority) if isinstance(priority, str) else priority
        )

        func_dict = {
            "name": f.__name__,
            "function": f,
            "module": _get_module_name(f),
            "sandbox_execution": sandbox_execution,
            "priority": tool_priority.value,
            "safe_mode": safe_mode,
        }

        # Create and store tool metadata
        metadata = ToolMetadata(
            name=f.__name__,
            priority=tool_priority,
            safe_mode=safe_mode,
            timeout_seconds=timeout_seconds,
            max_iterations=max_iterations,
            quota=quota,
            parallelizable=parallelizable,
            requires_auth=requires_auth,
            risk_level=risk_level,
            vulnerability_types=vulnerability_types or [],
            tags=tags or [],
            dependencies=dependencies or [],
        )
        _tool_metadata[f.__name__] = metadata
        func_dict["metadata"] = metadata

        sandbox_mode = os.getenv("STRIX_SANDBOX_MODE", "false").lower() == "true"
        if not sandbox_mode:
            try:
                module_path = Path(inspect.getfile(f))
                schema_file_name = f"{module_path.stem}_schema.xml"
                schema_path = module_path.parent / schema_file_name

                xml_tools = _load_xml_schema(schema_path)

                if xml_tools is not None and f.__name__ in xml_tools:
                    func_dict["xml_schema"] = xml_tools[f.__name__]
                else:
                    func_dict["xml_schema"] = (
                        f'<tool name="{f.__name__}">'
                        "<description>Schema not found for tool.</description>"
                        "</tool>"
                    )
            except (TypeError, FileNotFoundError) as e:
                logger.warning(f"Error loading schema for {f.__name__}: {e}")
                func_dict["xml_schema"] = (
                    f'<tool name="{f.__name__}">'
                    "<description>Error loading schema.</description>"
                    "</tool>"
                )

        tools.append(func_dict)
        _tools_by_name[str(func_dict["name"])] = f

        @wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return f(*args, **kwargs)

        return wrapper

    if func is None:
        return decorator
    return decorator(func)


def get_tool_by_name(name: str) -> Callable[..., Any] | None:
    return _tools_by_name.get(name)


def get_tool_names() -> list[str]:
    return list(_tools_by_name.keys())


def needs_agent_state(tool_name: str) -> bool:
    tool_func = get_tool_by_name(tool_name)
    if not tool_func:
        return False
    sig = signature(tool_func)
    return "agent_state" in sig.parameters


def should_execute_in_sandbox(tool_name: str) -> bool:
    for tool in tools:
        if tool.get("name") == tool_name:
            return bool(tool.get("sandbox_execution", True))
    return True


def get_tools_prompt() -> str:
    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in tools:
        module = tool.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        tools_by_module[module].append(tool)

    xml_sections = []
    for module, module_tools in sorted(tools_by_module.items()):
        tag_name = f"{module}_tools"
        section_parts = [f"<{tag_name}>"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented_tool = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented_tool)
        section_parts.append(f"</{tag_name}>")
        xml_sections.append("\n".join(section_parts))

    return "\n\n".join(xml_sections)


def clear_registry() -> None:
    """Clear all registered tools and metadata."""
    tools.clear()
    _tools_by_name.clear()
    _tool_metadata.clear()


def is_tool_allowed_for_role(tool_name: str, role: AgentRole) -> bool:
    """
    Check if a tool is allowed for a given agent role.

    Args:
        tool_name: Name of the tool to check
        role: The agent's role

    Returns:
        True if the tool is allowed, False otherwise
    """
    # Full access role can use all tools
    if role == AgentRole.FULL_ACCESS:
        return True

    # Get the allowed tools for this role
    allowed_tools = TOOL_PROFILES.get(role, set())

    # Check if tool is in allowed set
    # Tools are stored by module name in registry, so we check module
    for tool in tools:
        if tool.get("name") == tool_name:
            tool_module = tool.get("module", "unknown")
            return tool_module in allowed_tools or tool_name in allowed_tools

    return False


def get_tools_for_role(role: AgentRole) -> list[dict[str, Any]]:
    """
    Get all tools available for a given role.

    Args:
        role: The agent's role

    Returns:
        List of tool dictionaries available to the role
    """
    if role == AgentRole.FULL_ACCESS:
        return tools.copy()

    allowed_modules = TOOL_PROFILES.get(role, set())
    return [
        tool for tool in tools
        if tool.get("module", "unknown") in allowed_modules
        or tool.get("name") in allowed_modules
    ]


def get_tools_prompt_for_role(role: AgentRole) -> str:
    """
    Generate tool prompt XML for a specific role.

    Args:
        role: The agent's role

    Returns:
        XML string with tool definitions for the role
    """
    role_tools = get_tools_for_role(role)

    tools_by_module: dict[str, list[dict[str, Any]]] = {}
    for tool in role_tools:
        module = tool.get("module", "unknown")
        if module not in tools_by_module:
            tools_by_module[module] = []
        tools_by_module[module].append(tool)

    xml_sections = []
    for module, module_tools in sorted(tools_by_module.items()):
        tag_name = f"{module}_tools"
        section_parts = [f"<{tag_name}>"]
        for tool in module_tools:
            tool_xml = tool.get("xml_schema", "")
            if tool_xml:
                indented_tool = "\n".join(f"  {line}" for line in tool_xml.split("\n"))
                section_parts.append(indented_tool)
        section_parts.append(f"</{tag_name}>")
        xml_sections.append("\n".join(section_parts))

    return "\n\n".join(xml_sections)


def validate_tool_availability(
    tool_name: str,
    role: AgentRole | None = None,
) -> tuple[bool, str | None]:
    """
    Validate if a tool is available and allowed.

    Args:
        tool_name: Name of the tool
        role: Optional role to check against

    Returns:
        Tuple of (is_available, error_message)
    """
    # Check if tool exists
    if tool_name not in _tools_by_name:
        return False, f"Tool '{tool_name}' not found in registry"

    # Check role permissions if role specified
    if role is not None and not is_tool_allowed_for_role(tool_name, role):
        return False, f"Tool '{tool_name}' not allowed for role '{role.value}'"

    return True, None


def get_parallelization_strategy(tool_names: list[str]) -> dict[str, list[str]]:
    """
    Determine parallelization strategy for a set of tools.

    Args:
        tool_names: List of tool names to execute

    Returns:
        Dict with 'parallel' and 'sequential' lists of tool names
    """
    parallel = []
    sequential = []

    for name in tool_names:
        # Get tool module
        tool_module = "unknown"
        for tool in tools:
            if tool.get("name") == name:
                tool_module = tool.get("module", "unknown")
                break

        if tool_module in SEQUENTIAL_TOOLS or name in SEQUENTIAL_TOOLS:
            sequential.append(name)
        else:
            parallel.append(name)

    return {
        "parallel": parallel,
        "sequential": sequential,
    }


def get_available_roles() -> list[str]:
    """Get list of available agent roles."""
    return [role.value for role in AgentRole]


# =============================================================================
# Tool Metadata Functions for Adaptive Scanning
# =============================================================================


def get_tool_metadata(tool_name: str) -> ToolMetadata | None:
    """Get metadata for a specific tool.

    Args:
        tool_name: Name of the tool

    Returns:
        ToolMetadata if found, None otherwise
    """
    return _tool_metadata.get(tool_name)


def get_all_tool_metadata() -> dict[str, ToolMetadata]:
    """Get metadata for all registered tools.

    Returns:
        Dictionary mapping tool names to their metadata
    """
    return _tool_metadata.copy()


def get_tools_by_priority(priority: ToolPriority | str) -> list[dict[str, Any]]:
    """Get all tools with a specific priority.

    Args:
        priority: Priority level to filter by

    Returns:
        List of tool dictionaries matching the priority
    """
    if isinstance(priority, str):
        priority = ToolPriority(priority)

    return [
        tool for tool in tools
        if tool.get("priority") == priority.value
    ]


def get_safe_mode_tools() -> list[dict[str, Any]]:
    """Get all tools marked as safe mode.

    Returns:
        List of tool dictionaries that are safe mode
    """
    return [tool for tool in tools if tool.get("safe_mode", True)]


def get_tools_by_vulnerability_type(vuln_type: str) -> list[dict[str, Any]]:
    """Get tools that can detect a specific vulnerability type.

    Args:
        vuln_type: Vulnerability type to search for

    Returns:
        List of matching tool dictionaries
    """
    result = []
    vuln_lower = vuln_type.lower()

    for tool in tools:
        metadata = tool.get("metadata")
        if metadata and hasattr(metadata, "vulnerability_types"):
            if any(vuln_lower in v.lower() for v in metadata.vulnerability_types):
                result.append(tool)

    return result


def get_tools_by_tags(tags: list[str]) -> list[dict[str, Any]]:
    """Get tools matching any of the specified tags.

    Args:
        tags: List of tags to match

    Returns:
        List of matching tool dictionaries
    """
    result = []
    tags_lower = {t.lower() for t in tags}

    for tool in tools:
        metadata = tool.get("metadata")
        if metadata and hasattr(metadata, "tags"):
            tool_tags = {t.lower() for t in metadata.tags}
            if tool_tags & tags_lower:
                result.append(tool)

    return result


def get_tool_dependencies(tool_name: str) -> list[str]:
    """Get dependencies for a specific tool.

    Args:
        tool_name: Name of the tool

    Returns:
        List of tool names this tool depends on
    """
    metadata = _tool_metadata.get(tool_name)
    if metadata:
        return metadata.dependencies
    return []


def get_tools_for_scan_plan(
    safe_mode: bool = True,
    max_risk_level: str = "medium",
    priority_threshold: ToolPriority | None = None,
) -> list[dict[str, Any]]:
    """Get tools suitable for a scan plan based on constraints.

    Args:
        safe_mode: Only include safe mode tools
        max_risk_level: Maximum risk level (low, medium, high)
        priority_threshold: Minimum priority level to include

    Returns:
        List of tool dictionaries meeting the criteria
    """
    risk_levels = {"low": 0, "medium": 1, "high": 2}
    max_risk_value = risk_levels.get(max_risk_level, 1)

    priority_values = {
        ToolPriority.CRITICAL: 0,
        ToolPriority.HIGH: 1,
        ToolPriority.MEDIUM: 2,
        ToolPriority.LOW: 3,
        ToolPriority.OPTIONAL: 4,
    }

    result = []
    for tool in tools:
        metadata = tool.get("metadata")
        if not metadata:
            continue

        # Check safe mode
        if safe_mode and not metadata.safe_mode:
            continue

        # Check risk level
        tool_risk = risk_levels.get(metadata.risk_level, 1)
        if tool_risk > max_risk_value:
            continue

        # Check priority threshold
        if priority_threshold:
            threshold_value = priority_values.get(priority_threshold, 2)
            tool_priority_value = priority_values.get(metadata.priority, 2)
            if tool_priority_value > threshold_value:
                continue

        result.append(tool)

    return result


def update_tool_metadata(
    tool_name: str,
    priority: ToolPriority | None = None,
    safe_mode: bool | None = None,
    timeout_seconds: int | None = None,
    quota: int | None = None,
) -> bool:
    """Update metadata for an existing tool.

    Args:
        tool_name: Name of the tool to update
        priority: New priority level
        safe_mode: New safe mode setting
        timeout_seconds: New timeout
        quota: New quota

    Returns:
        True if updated successfully, False if tool not found
    """
    metadata = _tool_metadata.get(tool_name)
    if not metadata:
        return False

    if priority is not None:
        metadata.priority = priority

    if safe_mode is not None:
        metadata.safe_mode = safe_mode

    if timeout_seconds is not None:
        metadata.timeout_seconds = timeout_seconds

    if quota is not None:
        metadata.quota = quota

    # Update corresponding tool dict
    for tool in tools:
        if tool.get("name") == tool_name:
            if priority is not None:
                tool["priority"] = priority.value
            if safe_mode is not None:
                tool["safe_mode"] = safe_mode
            break

    return True


def get_execution_order(tool_names: list[str]) -> list[str]:
    """Determine optimal execution order based on dependencies and priority.

    Args:
        tool_names: List of tool names to order

    Returns:
        Ordered list of tool names respecting dependencies
    """
    # Build dependency graph
    dependencies: dict[str, set[str]] = {}
    priorities: dict[str, int] = {}

    priority_values = {
        ToolPriority.CRITICAL: 0,
        ToolPriority.HIGH: 1,
        ToolPriority.MEDIUM: 2,
        ToolPriority.LOW: 3,
        ToolPriority.OPTIONAL: 4,
    }

    for name in tool_names:
        metadata = _tool_metadata.get(name)
        if metadata:
            # Only include dependencies that are in our list
            deps = set(metadata.dependencies) & set(tool_names)
            dependencies[name] = deps
            priorities[name] = priority_values.get(metadata.priority, 2)
        else:
            dependencies[name] = set()
            priorities[name] = 2  # Default to medium

    # Topological sort with priority ordering
    result: list[str] = []
    remaining = set(tool_names)

    while remaining:
        # Find tools with no unsatisfied dependencies
        ready = []
        for name in remaining:
            unsatisfied = dependencies[name] - set(result)
            if not unsatisfied:
                ready.append(name)

        if not ready:
            # Circular dependency - just add remaining tools
            logger.warning(f"Circular dependency detected among: {remaining}")
            ready = list(remaining)

        # Sort ready tools by priority (lower value = higher priority)
        ready.sort(key=lambda x: priorities.get(x, 2))

        # Add highest priority ready tool
        chosen = ready[0]
        result.append(chosen)
        remaining.remove(chosen)

    return result
