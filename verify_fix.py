
import logging
from typing import Any

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
VALID_PRIORITIES = {"critical", "high", "medium", "low"}
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Copied from strix/tools/reconnaissance/reconnaissance_actions.py
def validate_discovered_routes(
    routes: list[dict[str, Any]],
    source_file: str = "unknown.js",
    base_url: str | None = None,
    primary_target: str | None = None
) -> dict[str, Any]:
    """Validate and structure discovered routes from LLM analysis.
    
    This tool processes routes discovered by the LLM, validates the format,
    normalizes priorities, deduplicates, categorizes, and prepares them for
    use by other agents.
    
    Args:
        routes: List of route dictionaries from LLM analysis
        source_file: Source file name
        base_url: Optional base URL for constructing full URLs from paths
        primary_target: Optional primary target URL to use as base for full URLs (overrides base_url)
        
    Returns:
        Structured and validated route data
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
            
            # Determine which base to use: primary_target takes precedence over base_url
            target_base = primary_target if primary_target else base_url
            
            if not full_url and target_base:
                # Auto-construct full_url from target_base + path
                path = str(route["path"])
                if path.startswith("/"):
                    full_url = target_base.rstrip("/") + path
                else:
                    full_url = f"{target_base.rstrip('/')}/{path}"
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

def verify_fix():
    print("Verifying fix for basehost issue...")

    # Test case:
    # - We found a route "/api/v1/users"
    # - The JS file was found on "https://login.example.com/auth/login" (base_url)
    # - The primary target is "https://example.com" (primary_target)
    # - We expect the full URL to be "https://example.com/api/v1/users"

    routes = [
        {
            "path": "/api/v1/users",
            "type": "User API",
            "priority": "medium",
            "reasoning": "Found in JS"
        }
    ]
    
    source_file = "login.js"
    base_url = "https://login.example.com"
    primary_target = "https://example.com"

    print(f"Input:")
    print(f"  Route Path: {routes[0]['path']}")
    print(f"  Base URL (e.g. login page): {base_url}")
    print(f"  Primary Target: {primary_target}")

    # Call the function with the new argument
    result = validate_discovered_routes(
        routes=routes,
        source_file=source_file,
        base_url=base_url,
        primary_target=primary_target
    )

    if not result["success"]:
        print(f"Validation failed: {result.get('error')}")
        exit(1)

    validated_routes = result["routes"]
    if not validated_routes:
        print("No routes returned.")
        exit(1)

    first_route = validated_routes[0]
    full_url = first_route["full_url"]

    print(f"Output:")
    print(f"  Full URL: {full_url}")

    expected_url = "https://example.com/api/v1/users"
    
    if full_url == expected_url:
        print("\nSUCCESS: Full URL matches the primary target.")
    else:
        print(f"\nFAILURE: Full URL does not match. Expected '{expected_url}', got '{full_url}'")
        exit(1)

    # Test case 2: Without primary_target (backward compatibility)
    print("\nVerifying backward compatibility (no primary_target)...")
    result_legacy = validate_discovered_routes(
        routes=routes,
        source_file=source_file,
        base_url=base_url
    )
    full_url_legacy = result_legacy["routes"][0]["full_url"]
    expected_legacy = "https://login.example.com/api/v1/users"
    
    print(f"  Full URL (Legacy): {full_url_legacy}")
    
    if full_url_legacy == expected_legacy:
         print("SUCCESS: Legacy behavior preserved.")
    else:
         print(f"FAILURE: Legacy behavior broken. Expected '{expected_legacy}', got '{full_url_legacy}'")
         exit(1)

if __name__ == "__main__":
    verify_fix()
