"""Custom Plugins API Routes.

REST API endpoints for managing user-defined custom plugins.
These plugins can be added via the frontend and will be automatically
considered by the LLM for tool selection during scans.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from trix.storage import get_database

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Request/Response Models ====================

class CreateCustomPluginRequest(BaseModel):
    """Request model for creating a custom plugin."""
    
    name: str = Field(..., min_length=1, max_length=100)
    command: str = Field(..., min_length=1, description="Command template with {target} placeholder")
    description: str = Field(..., min_length=1, description="What this plugin does")
    use_cases: list[str] = Field(default_factory=list, description="When to use this plugin")
    capabilities: list[str] = Field(default_factory=list, description="Plugin capabilities for filtering")
    phases: list[str] = Field(default_factory=list, description="Scan phases this plugin supports")
    plugin_dir: str | None = Field(default=None, description="Plugin directory name under plugins/ or user_plugins/")
    input_type: str = Field(default="url", description="Input type: url, domain, ip, file")
    output_format: str = Field(default="lines", description="Output format: json, lines, regex")
    output_pattern: str | None = Field(default=None, description="Regex pattern for parsing")
    author: str | None = Field(default=None)
    icon: str = Field(default="🔧", max_length=10)


class UpdateCustomPluginRequest(BaseModel):
    """Request model for updating a custom plugin."""
    
    name: str | None = None
    command: str | None = None
    description: str | None = None
    use_cases: list[str] | None = None
    capabilities: list[str] | None = None
    phases: list[str] | None = None
    plugin_dir: str | None = None
    input_type: str | None = None
    output_format: str | None = None
    output_pattern: str | None = None
    enabled: bool | None = None
    author: str | None = None
    icon: str | None = None


class TestPluginRequest(BaseModel):
    """Request model for testing a plugin."""
    
    target: str = Field(..., description="Target to test against")
    timeout: int = Field(default=30, ge=1, le=300, description="Timeout in seconds")


class CustomPluginResponse(BaseModel):
    """Response model for a custom plugin."""
    
    id: str
    name: str
    command: str
    description: str
    use_cases: list[str]
    capabilities: list[str]
    phases: list[str]
    plugin_dir: str | None
    working_dir: str | None
    input_type: str
    output_format: str
    output_pattern: str | None
    enabled: bool
    installed: bool
    author: str | None
    version: str
    icon: str
    created_at: str | None
    updated_at: str | None


# ==================== Endpoints ====================

@router.get("/directories")
async def list_plugin_directories():
    """List available plugin directories for binding.
    
    Scans plugins/ and user_plugins/ for directories that can be
    associated with custom plugins.
    """
    dirs = []
    for base in [Path("plugins"), Path("user_plugins")]:
        if base.exists():
            for d in sorted(base.iterdir()):
                if d.is_dir() and not d.name.startswith("."):
                    dirs.append({
                        "name": d.name,
                        "path": str(d),
                        "base": str(base),
                        "has_manifest": (d / "manifest.yaml").exists(),
                        "has_bin": (d / "bin").exists(),
                        "has_plugin_py": (d / "plugin.py").exists(),
                    })
    return {"directories": dirs, "total": len(dirs)}


@router.get("")
async def list_custom_plugins(enabled_only: bool = False):
    """List all custom plugins."""
    db = get_database()
    plugins = db.list_custom_plugins(enabled_only=enabled_only)
    
    return {
        "plugins": [p.to_dict() for p in plugins],
        "total": len(plugins),
    }


@router.post("")
async def create_custom_plugin(request: CreateCustomPluginRequest):
    """Create a new custom plugin."""
    db = get_database()
    
    # Check if name already exists
    existing = db.get_custom_plugin_by_name(request.name)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Plugin with name '{request.name}' already exists"
        )
    
    # Validate command contains {target} placeholder
    if "{target}" not in request.command:
        raise HTTPException(
            status_code=400,
            detail="Command must contain {target} placeholder"
        )
    
    try:
        plugin = db.create_custom_plugin(
            name=request.name,
            command=request.command,
            description=request.description,
            use_cases=request.use_cases,
            capabilities=request.capabilities,
            phases=request.phases,
            plugin_dir=request.plugin_dir,
            input_type=request.input_type,
            output_format=request.output_format,
            output_pattern=request.output_pattern,
            author=request.author,
            icon=request.icon,
        )
        
        logger.info(f"Created custom plugin: {plugin.name}")
        
        return {
            "status": "created",
            "plugin": plugin.to_dict(),
        }
    except Exception as e:
        logger.exception(f"Failed to create custom plugin: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{plugin_id}")
async def get_custom_plugin(plugin_id: str):
    """Get a custom plugin by ID."""
    db = get_database()
    plugin = db.get_custom_plugin(plugin_id)
    
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return plugin.to_dict()


@router.put("/{plugin_id}")
async def update_custom_plugin(plugin_id: str, request: UpdateCustomPluginRequest):
    """Update a custom plugin."""
    db = get_database()
    
    # Check plugin exists
    existing = db.get_custom_plugin(plugin_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    # Validate command if provided
    if request.command and "{target}" not in request.command:
        raise HTTPException(
            status_code=400,
            detail="Command must contain {target} placeholder"
        )
    
    # Check name uniqueness if changing
    if request.name and request.name != existing.name:
        name_exists = db.get_custom_plugin_by_name(request.name)
        if name_exists:
            raise HTTPException(
                status_code=400,
                detail=f"Plugin with name '{request.name}' already exists"
            )
    
    # Update
    updates = request.model_dump(exclude_unset=True)
    plugin = db.update_custom_plugin(plugin_id, **updates)
    
    logger.info(f"Updated custom plugin: {plugin.name}")
    
    return {
        "status": "updated",
        "plugin": plugin.to_dict(),
    }


@router.delete("/{plugin_id}")
async def delete_custom_plugin(plugin_id: str):
    """Delete a custom plugin."""
    db = get_database()
    
    plugin = db.get_custom_plugin(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    name = plugin.name
    success = db.delete_custom_plugin(plugin_id)
    
    if success:
        logger.info(f"Deleted custom plugin: {name}")
        return {"status": "deleted", "plugin_id": plugin_id}
    else:
        raise HTTPException(status_code=500, detail="Failed to delete plugin")


@router.post("/{plugin_id}/enable")
async def enable_custom_plugin(plugin_id: str):
    """Enable a custom plugin."""
    db = get_database()
    
    plugin = db.update_custom_plugin(plugin_id, enabled=True)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return {"status": "enabled", "plugin": plugin.name}


@router.post("/{plugin_id}/disable")
async def disable_custom_plugin(plugin_id: str):
    """Disable a custom plugin."""
    db = get_database()
    
    plugin = db.update_custom_plugin(plugin_id, enabled=False)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return {"status": "disabled", "plugin": plugin.name}


@router.post("/{plugin_id}/test")
async def test_custom_plugin(plugin_id: str, request: TestPluginRequest):
    """Test a custom plugin with a target.
    
    This executes the plugin command and returns the output.
    """
    db = get_database()
    
    plugin = db.get_custom_plugin(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    # Build command
    command = plugin.command.replace("{target}", request.target)
    
    # Resolve working directory
    cwd = None
    if plugin.working_dir:
        cwd = Path(plugin.working_dir)
    elif plugin.plugin_dir:
        # Try plugins/ first, then user_plugins/
        for base in [Path("plugins"), Path("user_plugins")]:
            candidate = base / plugin.plugin_dir
            if candidate.exists():
                cwd = candidate
                break
    
    logger.info(f"Testing plugin {plugin.name}: {command} (cwd={cwd})")
    
    try:
        # Parse command for shell execution
        args = shlex.split(command)
        
        # Execute command with optional cwd
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=request.timeout,
            )
        except asyncio.TimeoutError:
            process.kill()
            return {
                "status": "timeout",
                "message": f"Command timed out after {request.timeout}s",
                "plugin": plugin.name,
                "cwd": str(cwd) if cwd else None,
            }
        
        # Parse output based on format
        output = stdout.decode("utf-8", errors="replace")
        parsed = _parse_output(output, plugin.output_format, plugin.output_pattern)
        
        return {
            "status": "success" if process.returncode == 0 else "error",
            "return_code": process.returncode,
            "stdout": output[:5000],  # Limit output size
            "stderr": stderr.decode("utf-8", errors="replace")[:1000],
            "parsed": parsed,
            "plugin": plugin.name,
            "cwd": str(cwd) if cwd else None,
        }
        
    except FileNotFoundError:
        return {
            "status": "error",
            "message": f"Command not found: {args[0] if args else command}",
            "plugin": plugin.name,
            "cwd": str(cwd) if cwd else None,
        }
    except Exception as e:
        logger.exception(f"Plugin test error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "plugin": plugin.name,
        }


@router.get("/llm/descriptions")
async def get_llm_descriptions():
    """Get plugin descriptions formatted for LLM context."""
    db = get_database()
    descriptions = db.get_custom_plugins_for_llm()
    
    return {
        "descriptions": descriptions,
        "count": len(descriptions),
    }


def _parse_output(output: str, format_type: str, pattern: str | None) -> list[Any]:
    """Parse plugin output based on format type."""
    import json
    
    if not output.strip():
        return []
    
    if format_type == "json":
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            # Try JSONL
            results = []
            for line in output.strip().split("\n"):
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return results
    
    elif format_type == "lines":
        return [line.strip() for line in output.strip().split("\n") if line.strip()]
    
    elif format_type == "regex" and pattern:
        try:
            regex = re.compile(pattern)
            return regex.findall(output)
        except re.error:
            return []
    
    return [output]
