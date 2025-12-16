"""Concurrent HTTP request executor for performance optimization.

This module enables parallel execution of HTTP requests while maintaining
the deterministic flow control of ScanController.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from strix.core.scan_phase import ScanTask

logger = logging.getLogger(__name__)


class ConcurrentExecutor:
    """Executes HTTP requests concurrently for better performance.
    
    Maintains request rate limiting and connection pooling while
    executing multiple requests in parallel.
    """
    
    def __init__(self, max_concurrent: int = 10, timeout: float = 10.0):
        """Initialize concurrent executor.
        
        Args:
            max_concurrent: Maximum concurrent requests
            timeout: Request timeout in seconds
        """
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Shared HTTP client for connection pooling
        self.client: httpx.AsyncClient | None = None
    
    async def __aenter__(self):
        """Create shared HTTP client."""
        self.client = httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=self.max_concurrent * 2,
                max_keepalive_connections=self.max_concurrent
            )
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close shared HTTP client."""
        if self.client:
            await self.client.aclose()
    
    async def execute_request(self, task: ScanTask) -> dict[str, Any]:
        """Execute a single HTTP request with rate limiting.
        
        Args:
            task: ScanTask to execute
            
        Returns:
            Response data dict
        """
        async with self.semaphore:  # Rate limiting
            try:
                if task.method.upper() == "GET":
                    response = await self.client.get(task.url, params=task.parameters)
                elif task.method.upper() == "POST":
                    response = await self.client.post(task.url, data=task.parameters)
                elif task.method.upper() == "PUT":
                    response = await self.client.put(task.url, data=task.parameters)
                elif task.method.upper() == "DELETE":
                    response = await self.client.delete(task.url, params=task.parameters)
                elif task.method.upper() == "PATCH":
                    response = await self.client.patch(task.url, data=task.parameters)
                elif task.method.upper() == "OPTIONS":
                    response = await self.client.options(task.url)
                elif task.method.upper() == "HEAD":
                    response = await self.client.head(task.url, params=task.parameters)
                else:
                    response = await self.client.request(task.method, task.url, params=task.parameters)
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:2000],  # Limit response size
                    "url": str(response.url),
                    "method": task.method
                }
            
            except Exception as e:
                logger.error(f"Request failed: {task.method} {task.url} - {e}")
                return {
                    "status_code": 0,
                    "error": str(e),
                    "method": task.method,
                    "url": task.url
                }
    
    async def execute_batch(self, tasks: list[ScanTask]) -> list[dict[str, Any]]:
        """Execute multiple requests concurrently.
        
        Args:
            tasks: List of ScanTasks to execute
            
        Returns:
            List of response dicts in same order as tasks
        """
        if not tasks:
            return []
        
        logger.info(f"Executing {len(tasks)} requests concurrently (max {self.max_concurrent} parallel)")
        
        # Execute all tasks concurrently, respecting semaphore limit
        results = await asyncio.gather(
            *[self.execute_request(task) for task in tasks],
            return_exceptions=True
        )
        
        # Convert exceptions to error dicts
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Task {i} failed with exception: {result}")
                processed_results.append({
                    "status_code": 0,
                    "error": str(result),
                    "method": tasks[i].method,
                    "url": tasks[i].url
                })
            else:
                processed_results.append(result)
        
        return processed_results
