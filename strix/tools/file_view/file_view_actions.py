import os
import subprocess
from pathlib import Path
from typing import Any

from openhands_aci.utils.shell import run_shell_cmd
from strix.tools.registry import register_tool

@register_tool(
    priority="high",
    vulnerability_types=["all"],
    tags=["discovery", "code_analysis"]
)
def view_file(
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
) -> dict[str, Any]:
    """View contents of a file, optionally specifying a line range."""
    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
            path_obj = Path(path)

        if not path_obj.exists():
            return {"error": f"File not found: {path}"}
        
        if not path_obj.is_file():
            return {"error": f"Path is not a file: {path}"}

        # Read file with line limits
        lines = []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                if end_line is None:
                    # If file is too large (>2000 lines) and no end_line, truncate
                    # We iterate to avoid loading everything into memory if possible, though readlines() loads all.
                    # For safety, we use a simple read
                    all_lines = f.readlines()
                    if len(all_lines) > 2000:
                         lines = all_lines[start_line-1:2000]
                         truncated = True
                    else:
                         lines = all_lines[start_line-1:]
                         truncated = False
                else:
                    all_lines = f.readlines()
                    lines = all_lines[start_line-1:end_line]
                    truncated = False
            
            content = "".join(lines)
            return {
                "file_path": path,
                "content": content,
                "start_line": start_line,
                "end_line": start_line + len(lines) - 1,
                "truncated": truncated if end_line is None and len(lines) >= 2000 else False
            }
        except Exception as e:
            return {"error": f"Error reading file: {str(e)}"}

    except Exception as e:
        return {"error": f"Error viewing file: {str(e)}"}

@register_tool(
    priority="high",
    tags=["discovery"]
)
def list_dir(
    path: str,
    recursive: bool = False,
    max_depth: int = 2
) -> dict[str, Any]:
    """List contents of a directory."""
    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
            path_obj = Path(path)

        if not path_obj.exists():
            return {"error": f"Directory not found: {path}"}

        if not path_obj.is_dir():
            return {"error": f"Path is not a directory: {path}"}

        # Use find for recursive, ls for flat
        if recursive:
            cmd = f"find '{path}' -maxdepth {max_depth} -not -path '*/.*' | head -n 500"
        else:
            cmd = f"ls -1F '{path}'"

        exit_code, stdout, stderr = run_shell_cmd(cmd)
        
        if exit_code != 0:
            return {"error": f"Error listing directory: {stderr}"}

        items = stdout.strip().split('\n') if stdout.strip() else []
        return {
            "path": path,
            "items": items,
            "count": len(items),
            "recursive": recursive
        }

    except Exception as e:
        return {"error": f"Error listing directory: {str(e)}"}

@register_tool(
    priority="medium",
    tags=["discovery", "code_analysis"]
)
def grep_search(
    path: str,
    pattern: str,
    recursive: bool = True,
    case_insensitive: bool = True,
    include_line_numbers: bool = True
) -> dict[str, Any]:
    """Search for a pattern in files using grep/ripgrep."""
    try:
        path_obj = Path(path)
        if not path_obj.is_absolute():
            path = str(Path("/workspace") / path_obj)
        
        flags = []
        if recursive:
            flags.append("-r")
        if case_insensitive:
            flags.append("-i")
        if include_line_numbers:
            flags.append("-n")
            
        # Use grep as fallback if rg not available, but user env usually has rg or grep
        # Just use grep for simplicity and ubiquity in the container
        flags_str = " ".join(flags)
        # Escape pattern single quotes
        safe_pattern = pattern.replace("'", "'\"'\"'")
        
        cmd = f"grep {flags_str} --exclude-dir=.* '{safe_pattern}' '{path}' | head -n 200"
        
        exit_code, stdout, stderr = run_shell_cmd(cmd)
        
        # grep exit code 1 means no matches, which is not an error
        if exit_code > 1:
            return {"error": f"Grep error: {stderr}"}
            
        matches = stdout.strip().split('\n') if stdout.strip() else []
        return {
            "matches": matches,
            "count": len(matches),
            "path": path,
            "pattern": pattern
        }

    except Exception as e:
        return {"error": f"Error searching: {str(e)}"}
