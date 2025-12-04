"""
Container Tools for IAST-like Testing

These tools allow agents to interact with deployed target containers,
enabling interactive application security testing (IAST).
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Global reference to deployment manager (set by main.py)
_deployment_manager = None


def set_deployment_manager(manager: Any) -> None:
    """Set the global deployment manager reference."""
    global _deployment_manager
    _deployment_manager = manager


def get_deployment_manager() -> Any:
    """Get the deployment manager."""
    return _deployment_manager


def read_container_logs(
    service_name: str | None = None,
    tail: int = 100
) -> dict[str, Any]:
    """
    Read logs from deployed target containers.
    
    This is useful for IAST-like analysis where you can observe
    application behavior in response to your tests.
    
    Args:
        service_name: Optional service name to filter logs from.
        tail: Number of log lines to retrieve (default 100).
        
    Returns:
        Dictionary containing logs by service/container name.
    """
    if not _deployment_manager:
        return {
            "error": "No deployment manager available. Use --deploy flag to enable container deployment.",
            "logs": {}
        }
    
    try:
        logs = _deployment_manager.get_logs(service_name=service_name, tail=tail)
        return {
            "success": True,
            "logs": logs
        }
    except Exception as e:
        logger.exception("Failed to read container logs")
        return {
            "error": str(e),
            "logs": {}
        }


def list_deployed_services() -> dict[str, Any]:
    """
    List all deployed services and their network information.
    
    Returns information about running containers including:
    - Container name and ID
    - Service name (from docker-compose)
    - IP address on strix-network
    - Port mappings
    - Current status
    
    Returns:
        Dictionary containing list of services or error.
    """
    if not _deployment_manager:
        return {
            "error": "No deployment manager available. Use --deploy flag to enable container deployment.",
            "services": []
        }
    
    try:
        services = _deployment_manager.list_services()
        return {
            "success": True,
            "services": services
        }
    except Exception as e:
        logger.exception("Failed to list deployed services")
        return {
            "error": str(e),
            "services": []
        }


# Tool definitions for the registry
CONTAINER_TOOLS = [
    {
        "name": "read_container_logs",
        "description": (
            "Read logs from deployed target containers. "
            "Use this to observe how the application responds to your security tests (IAST-like analysis). "
            "Look for error messages, stack traces, SQL queries, authentication failures, etc."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "service_name": {
                    "type": "string",
                    "description": "Optional service name to filter logs. If not provided, returns logs from all services."
                },
                "tail": {
                    "type": "integer",
                    "description": "Number of log lines to retrieve (default: 100, max: 500)",
                    "default": 100
                }
            },
            "required": []
        },
        "handler": read_container_logs
    },
    {
        "name": "list_deployed_services",
        "description": (
            "List all deployed services from docker-compose and their network information. "
            "Shows container names, internal IP addresses, and port mappings. "
            "Use this to discover available services to target."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        },
        "handler": list_deployed_services
    }
]
