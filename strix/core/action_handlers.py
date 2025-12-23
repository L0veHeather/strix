"""Action Handlers - Execute IntendedActions from LLM.

This module provides handlers for different action types.
The LLM proposes actions, these handlers execute them.

Key principle: LLM never executes, only proposes.
These handlers are the ONLY code that performs actions.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional
from datetime import datetime, UTC

import httpx

from strix.core.agent_philosophy import IntendedAction, ActionType

logger = logging.getLogger(__name__)


class ActionHandlerRegistry:
    """Registry for action handlers.
    
    Each handler:
    1. Receives an IntendedAction from LLM
    2. Executes the action
    3. Returns raw results for feedback
    
    The handler does NOT interpret results - that's the LLM's job after
    receiving the feedback.
    """
    
    def __init__(self):
        self._handlers: dict[ActionType, callable] = {}
        self._plugin_registry: dict[str, callable] = {}
        
        # Register default handlers
        self._register_defaults()
    
    def _register_defaults(self) -> None:
        """Register default action handlers."""
        self._handlers[ActionType.REQUEST] = self._handle_request
        self._handlers[ActionType.EXPLORE] = self._handle_explore
        self._handlers[ActionType.VERIFY] = self._handle_verify
        self._handlers[ActionType.PLUGIN] = self._handle_plugin
        self._handlers[ActionType.WAIT] = self._handle_wait
    
    def register_plugin(self, name: str, handler: callable) -> None:
        """Register a plugin handler.
        
        Args:
            name: Plugin name (e.g., "nuclei", "sqlmap")
            handler: Async function that executes the plugin
        """
        self._plugin_registry[name.lower()] = handler
        logger.debug(f"Registered plugin handler: {name}")
    
    async def execute(self, action: IntendedAction) -> dict[str, Any]:
        """Execute an IntendedAction.
        
        Args:
            action: The action to execute
            
        Returns:
            Dict with execution results
        """
        handler = self._handlers.get(action.action_type)
        
        if not handler:
            return {
                "success": False,
                "error": f"No handler for action type: {action.action_type.value}",
                "action": action.name,
            }
        
        try:
            result = await handler(action)
            return {
                "success": True,
                "result": result,
                "action": action.name,
                "goal": action.goal,
                "executed_at": datetime.now(UTC).isoformat(),
            }
        except Exception as e:
            logger.exception(f"Action execution failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "action": action.name,
                "goal": action.goal,
            }
    
    # ==========================================================================
    # Default Handlers
    # ==========================================================================
    
    async def _handle_request(self, action: IntendedAction) -> dict[str, Any]:
        """Handle HTTP request actions."""
        params = action.parameters
        
        url = params.get("url")
        if not url:
            raise ValueError("HTTP request requires 'url' parameter")
        
        method = params.get("method", "GET").upper()
        headers = params.get("headers", {})
        body = params.get("body")
        
        logger.info(f"[HTTP] {method} {url}")
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
        ) as client:
            if method == "GET":
                response = await client.get(url, headers=headers)
            elif method == "POST":
                response = await client.post(url, headers=headers, data=body)
            elif method == "PUT":
                response = await client.put(url, headers=headers, data=body)
            elif method == "DELETE":
                response = await client.delete(url, headers=headers)
            elif method == "HEAD":
                response = await client.head(url, headers=headers)
            elif method == "OPTIONS":
                response = await client.options(url, headers=headers)
            else:
                response = await client.request(method, url, headers=headers, content=body)
        
        # Return raw response data (LLM will interpret)
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],  # Limit response size
            "elapsed_ms": response.elapsed.total_seconds() * 1000,
            "url": str(response.url),
            "redirects": len(response.history),
        }
    
    async def _handle_explore(self, action: IntendedAction) -> dict[str, Any]:
        """Handle exploration actions (discover endpoints, params, etc)."""
        params = action.parameters
        
        url = params.get("url")
        if not url:
            raise ValueError("Explore action requires 'url' parameter")
        
        exploration_type = params.get("type", "endpoint")
        
        logger.info(f"[EXPLORE] {exploration_type} at {url}")
        
        # Make discovery request
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0),
        ) as client:
            response = await client.get(url)
        
        # Extract exploration data (raw - LLM interprets)
        result = {
            "url": url,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "body_preview": response.text[:3000],
            "links_found": self._extract_links(response.text, url),
            "forms_found": self._extract_forms(response.text),
            "headers": dict(response.headers),
        }
        
        return result
    
    async def _handle_verify(self, action: IntendedAction) -> dict[str, Any]:
        """Handle verification actions (test specific hypothesis)."""
        params = action.parameters
        
        url = params.get("url")
        if not url:
            raise ValueError("Verify action requires 'url' parameter")
        
        payload = params.get("payload", "")
        inject_point = params.get("inject_point", "url")
        
        logger.info(f"[VERIFY] Testing at {url}")
        
        # Build verification request
        headers = params.get("headers", {})
        method = params.get("method", "GET").upper()
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0),
        ) as client:
            if inject_point == "url":
                # Inject into URL
                test_url = url.replace("INJECT", payload) if "INJECT" in url else f"{url}{payload}"
                response = await client.request(method, test_url, headers=headers)
            elif inject_point == "body":
                body = params.get("body", "").replace("INJECT", payload)
                response = await client.request(method, url, headers=headers, content=body)
            elif inject_point == "header":
                header_name = params.get("header_name", "X-Test")
                headers[header_name] = payload
                response = await client.request(method, url, headers=headers)
            else:
                response = await client.request(method, url, headers=headers)
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text[:5000],
            "elapsed_ms": response.elapsed.total_seconds() * 1000,
            "verification_target": url,
            "payload_used": payload,
        }
    
    async def _handle_plugin(self, action: IntendedAction) -> dict[str, Any]:
        """Handle plugin execution actions."""
        plugin_name = action.name.lower()
        
        handler = self._plugin_registry.get(plugin_name)
        if not handler:
            # Try to load plugin dynamically
            handler = await self._load_plugin(plugin_name)
        
        if not handler:
            return {
                "success": False,
                "error": f"Plugin '{plugin_name}' not found or not loaded",
                "available_plugins": list(self._plugin_registry.keys()),
            }
        
        logger.info(f"[PLUGIN] Executing {plugin_name}")
        
        # Execute plugin
        try:
            result = await handler(action.parameters)
            return {
                "plugin": plugin_name,
                "result": result,
            }
        except Exception as e:
            return {
                "plugin": plugin_name,
                "error": str(e),
            }
    
    async def _handle_wait(self, action: IntendedAction) -> dict[str, Any]:
        """Handle wait actions (pause for more info)."""
        reason = action.parameters.get("reason", "Waiting for more information")
        duration = action.parameters.get("duration_seconds", 0)
        
        logger.info(f"[WAIT] {reason}")
        
        if duration > 0:
            await asyncio.sleep(min(duration, 30))  # Max 30 second wait
        
        return {
            "waited": True,
            "reason": reason,
            "duration_seconds": duration,
        }
    
    # ==========================================================================
    # Utility Methods
    # ==========================================================================
    
    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML (simple regex extraction)."""
        import re
        from urllib.parse import urljoin
        
        links = set()
        
        # Find href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            link = match.group(1)
            if not link.startswith(('javascript:', 'mailto:', '#')):
                full_url = urljoin(base_url, link)
                links.add(full_url)
        
        # Find src attributes
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            link = match.group(1)
            if not link.startswith('data:'):
                full_url = urljoin(base_url, link)
                links.add(full_url)
        
        return list(links)[:50]  # Limit to 50 links
    
    def _extract_forms(self, html: str) -> list[dict[str, Any]]:
        """Extract form information from HTML."""
        import re
        
        forms = []
        
        # Simple form extraction
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>',
            re.IGNORECASE
        )
        
        for match in form_pattern.finditer(html):
            forms.append({
                "action": match.group(1),
                "method": match.group(2).upper(),
            })
        
        return forms[:20]  # Limit to 20 forms
    
    async def _load_plugin(self, plugin_name: str) -> Optional[callable]:
        """Try to dynamically load a plugin."""
        try:
            # Try to import from strix plugins
            from strix.plugins.loader import load_plugin
            plugin = await load_plugin(plugin_name)
            if plugin:
                self._plugin_registry[plugin_name] = plugin.execute
                return plugin.execute
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Failed to load plugin {plugin_name}: {e}")
        
        return None


# =============================================================================
# Global Handler Registry
# =============================================================================

_global_registry: Optional[ActionHandlerRegistry] = None


def get_action_registry() -> ActionHandlerRegistry:
    """Get the global action handler registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ActionHandlerRegistry()
    return _global_registry


async def execute_intended_action(action: IntendedAction) -> dict[str, Any]:
    """Execute an IntendedAction using the global registry.
    
    This is the main entry point for action execution.
    """
    registry = get_action_registry()
    return await registry.execute(action)
