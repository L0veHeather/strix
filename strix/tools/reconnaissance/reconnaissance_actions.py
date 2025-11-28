"""Reconnaissance actions for JavaScript analysis and route extraction."""

import logging
from typing import Any

from strix.tools.registry import register_tool

logger = logging.getLogger(__name__)

# Constants
VALID_PRIORITIES = {"critical", "high", "medium", "low"}
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@register_tool(sandbox_execution=False)
def analyze_javascript_routes(
    js_content: str,
    base_url: str | None = None,
    source_file: str = "unknown.js",
    context: str | None = None
) -> dict[str, Any]:
    """Intelligently analyze JavaScript content to discover API routes and endpoints.
    
    This tool leverages the LLM's intelligence to analyze JavaScript code and identify
    routes, endpoints, and API patterns. Unlike rigid regex-based approaches, this method
    understands code context, framework conventions, and dynamic patterns.
    
    COMPLETE WORKFLOW:
    1. Agent calls this tool with JavaScript content
    2. Tool validates input and returns analysis instructions
    3. Agent (LLM) reads and analyzes the js_content field
    4. Agent identifies all routes using intelligence and understanding
    5. Agent creates a list of route dictionaries with required fields
    6. Agent calls validate_discovered_routes with the routes list
    7. Tool validates, categorizes, and returns structured data
    
    HOW TO USE:
    1. Call this tool with JavaScript content
    2. The tool returns analysis instructions and JS content
    3. YOU (the LLM) should analyze the js_content in the response
    4. Identify all routes using your understanding of JavaScript
    5. Return your analysis as a list of route dictionaries
    6. Call validate_discovered_routes with your routes list
    
    WHAT TO ANALYZE:
    - Variable declarations containing URLs or paths
    - HTTP request calls (fetch, axios, XMLHttpRequest, etc.)
    - Route configuration objects and arrays
    - String literals that appear to be API paths
    - Template literals constructing URLs
    - Framework-specific routing patterns
    - Base URL configurations
    - Microservice and gateway patterns
    - Dynamic route construction
    - Routes hidden in configuration objects
    
    Args:
        js_content: The JavaScript file content to analyze
        base_url: Optional base URL hint for constructing full paths
        source_file: Name of the source file for tracking
        context: Optional context about the application (framework, purpose, etc.)
        
    Returns:
        Dictionary with analysis instructions and the JS content to analyze
        
    Example Usage:
        ```python
        # Step 1: Agent calls the tool
        result = analyze_javascript_routes(
            js_content=js_code,
            base_url="https://api.example.com",
            source_file="main.js"
        )
        
        # Step 2: Agent receives instructions and analyzes
        # Agent reads result['js_content'] and identifies routes
        
        # Step 3: Agent creates routes list
        discovered_routes = [
            {
                "path": "/api/v1/users",
                "full_url": "https://api.example.com/api/v1/users",
                "type": "REST API",
                "priority": "medium",
                "reasoning": "Found in api.users variable, used in fetch call"
            }
        ]
        
        # Step 4: Agent validates routes
        final_result = validate_discovered_routes(
            routes=discovered_routes,
            source_file="main.js"
        )
        ```
    
    Expected Route Format:
        Each route should be a dictionary with:
        {
            "path": "string - the route path",
            "full_url": "string - complete URL if base URL available",
            "type": "string - route category (be creative, not limited)",
            "priority": "critical|high|medium|low",
            "reasoning": "string - why you identified this as a route",
            "methods": ["GET", "POST", ...] (optional),
            "source_location": "string - where in code" (optional)
        }
    
    Priority Guidelines:
        - critical: Admin, internal, debug, staff paths
        - high: Authentication, gateway, microservices
        - medium: Versioned APIs, GraphQL, data APIs
        - low: Public APIs, static content
    """
    # Validate input
    if not js_content or not js_content.strip():
        logger.warning(f"Empty JavaScript content for {source_file}")
        return {
            "success": False,
            "error": "Empty JavaScript content provided",
            "source_file": source_file
        }
    
    # Prepare analysis instructions
    logger.info(f"Preparing intelligent analysis for {source_file} ({len(js_content)} chars)")
    
    return {
        "success": True,
        "status": "ready_for_analysis",
        "source_file": source_file,
        "base_url_hint": base_url,
        "context": context,
        "js_content": js_content,
        "instructions": """
ANALYZE THIS JAVASCRIPT CODE TO EXTRACT ALL API ROUTES AND ENDPOINTS.

Use your intelligence and understanding of:
- JavaScript syntax and semantics
- Web application architecture
- API design patterns
- Framework conventions (React Router, Vue Router, Angular, Next.js, Express, etc.)
- Microservice and gateway architectures

Look for routes in:
1. String literals: "/api/users", '/v1/products'
2. Variables: const endpoint = "/admin/dashboard"
3. HTTP calls: fetch("/api/data"), axios.get("/users")
4. Route configs: { path: "/admin", component: Admin }
5. Template literals: `${baseURL}/api/${resource}`
6. Base URLs: API_BASE_URL = "https://api.example.com"
7. Dynamic construction: services.forEach(s => fetch(`/api/${s}`))
8. Configuration objects: window.__CONFIG__.endpoints
9. Framework patterns: Vue Router, React Router, Express routes
10. Comments and debug code

For EACH route found, provide:
- path: The actual route path
- full_url: Complete URL (use base_url_hint if provided)
- type: Category (be creative - "Admin Dashboard", "User API", "Health Check", etc.)
- priority: critical/high/medium/low based on sensitivity
- reasoning: Why you identified this as a route
- methods: HTTP methods if evident (optional)
- source_location: Where in the code (optional)

Be creative and flexible:
- Don't just look for "/api/" patterns
- Understand dynamic route construction
- Consider framework-specific conventions
- Identify routes hidden in configurations
- Recognize obfuscated or minified patterns

Return a list of route dictionaries, then call validate_discovered_routes with your list.
""",
        "message": f"Please analyze the JavaScript content in 'js_content' field and identify all routes. "
                  f"Use your understanding of code, not just pattern matching. "
                  f"Create a list of route dictionaries, then call validate_discovered_routes."
    }


@register_tool(sandbox_execution=False)
def validate_discovered_routes(
    routes: list[dict[str, Any]],
    source_file: str = "unknown.js",
    base_url: str | None = None
) -> dict[str, Any]:
    """Validate and structure discovered routes from LLM analysis.
    
    This tool processes routes discovered by the LLM, validates the format,
    normalizes priorities, deduplicates, categorizes, and prepares them for
    use by other agents.
    
    Args:
        routes: List of route dictionaries from LLM analysis
        source_file: Source file name
        base_url: Optional base URL for constructing full URLs from paths
        
    Returns:
        Structured and validated route data
        
    Example:
        ```python
        routes = [
            {
                "path": "/api/users",
                "full_url": "https://api.example.com/api/users",
                "type": "User API",
                "priority": "medium",
                "reasoning": "REST endpoint for user management"
            }
        ]
        result = validate_discovered_routes(routes, "main.js", "https://api.example.com")
        ```
    """
    try:
        if not routes:
            logger.warning(f"No routes provided for validation from {source_file}")
            return {
                "success": True,
                "source_file": source_file,
                "routes": [],
                "total_routes": 0,
                "categorized": {},
                "priority_counts": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }
        
        # Validate and clean routes
        validated_routes = []
        for route in routes:
            # Ensure required fields
            if not isinstance(route, dict):
                logger.warning(f"Invalid route format: {route}")
                continue
            
            # Check path exists and is not empty
            if "path" not in route or not str(route.get("path", "")).strip():
                logger.warning(f"Route missing or empty 'path' field: {route}")
                continue
            
            # Normalize priority
            priority = str(route.get("priority", "low")).lower()
            if priority not in VALID_PRIORITIES:
                logger.warning(
                    f"Invalid priority '{priority}' for route {route['path']}, "
                    f"defaulting to 'low'"
                )
                priority = "low"
            
            # Validate and normalize methods
            methods = route.get("methods", [])
            if isinstance(methods, str):
                methods = [methods]
            elif not isinstance(methods, list):
                logger.warning(f"Invalid methods type for route {route['path']}: {type(methods)}")
                methods = []
            
            # Get or construct full_url
            full_url = route.get("full_url", "")
            if not full_url and base_url:
                # Auto-construct full_url from base_url + path
                path = str(route["path"])
                if path.startswith("/"):
                    full_url = base_url.rstrip("/") + path
                else:
                    full_url = f"{base_url.rstrip('/')}/{path}"
            elif not full_url:
                # Use path as full_url if no base_url provided
                full_url = str(route["path"])
            
            # Add defaults for missing fields
            validated_route = {
                "path": str(route["path"]).strip(),
                "full_url": full_url,
                "type": route.get("type", "Unknown"),
                "priority": priority,
                "reasoning": route.get("reasoning", ""),
                "methods": methods,
                "source": source_file,
                "source_location": route.get("source_location", "")
            }
            validated_routes.append(validated_route)
        
        # Deduplicate by full_url, merging information
        seen_urls = {}
        for route in validated_routes:
            url = route["full_url"]
            if url not in seen_urls:
                seen_urls[url] = route
            else:
                # Merge methods
                existing_methods = set(seen_urls[url].get("methods", []))
                new_methods = set(route.get("methods", []))
                merged_methods = existing_methods | new_methods
                if merged_methods:
                    seen_urls[url]["methods"] = sorted(list(merged_methods))
                
                # Merge reasoning
                existing_reasoning = seen_urls[url].get("reasoning", "")
                new_reasoning = route.get("reasoning", "")
                if new_reasoning and new_reasoning not in existing_reasoning:
                    if existing_reasoning:
                        seen_urls[url]["reasoning"] = f"{existing_reasoning}; {new_reasoning}"
                    else:
                        seen_urls[url]["reasoning"] = new_reasoning
                
                # Keep higher priority (lower number = higher priority)
                existing_priority = PRIORITY_ORDER[seen_urls[url]["priority"]]
                new_priority = PRIORITY_ORDER[route["priority"]]
                if new_priority < existing_priority:
                    seen_urls[url]["priority"] = route["priority"]
                    logger.debug(f"Updated priority for duplicate route {url} to {route['priority']}")
        
        validated_routes = list(seen_urls.values())
        
        # Categorize by type
        categorized = {}
        for route in validated_routes:
            route_type = route["type"]
            if route_type not in categorized:
                categorized[route_type] = []
            categorized[route_type].append(route)
        
        # Count by priority
        priority_counts = {
            "critical": len([r for r in validated_routes if r["priority"] == "critical"]),
            "high": len([r for r in validated_routes if r["priority"] == "high"]),
            "medium": len([r for r in validated_routes if r["priority"] == "medium"]),
            "low": len([r for r in validated_routes if r["priority"] == "low"])
        }
        
        logger.info(
            f"Validated {len(validated_routes)} routes from {source_file}: "
            f"{priority_counts['critical']} critical, {priority_counts['high']} high, "
            f"{priority_counts['medium']} medium, {priority_counts['low']} low"
        )
        
        return {
            "success": True,
            "source_file": source_file,
            "routes": validated_routes,
            "total_routes": len(validated_routes),
            "categorized": categorized,
            "priority_counts": priority_counts
        }
        
    except (TypeError, KeyError, ValueError, AttributeError) as e:
        logger.error(f"Validation error for {source_file}: {e}")
        return {
            "success": False,
            "error": f"Validation error: {str(e)}",
            "source_file": source_file,
            "routes": [],
            "total_routes": 0
        }
    except Exception as e:
        logger.exception(f"Unexpected error validating routes from {source_file}: {e}")
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}",
            "source_file": source_file,
            "routes": [],
            "total_routes": 0
        }
