"""Concurrent HTTP Request Executor.

This module provides an async context manager for executing
HTTP requests concurrently with controlled parallelism.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from trix.core.scan_phase import ScanTask

logger = logging.getLogger(__name__)


class ConcurrentExecutor:
    """Async context manager for concurrent HTTP request execution.
    
    Provides controlled parallelism for HTTP requests during scanning,
    with connection pooling and timeout handling.
    
    Example:
        async with ConcurrentExecutor(max_concurrent=10) as executor:
            result = await executor.execute_request(task)
    """
    
    def __init__(self, max_concurrent: int = 10):
        """Initialize executor.
        
        Args:
            max_concurrent: Maximum concurrent requests
        """
        self._max_concurrent = max_concurrent
        self._semaphore: asyncio.Semaphore | None = None
        self._client: httpx.AsyncClient | None = None
    
    async def __aenter__(self) -> "ConcurrentExecutor":
        """Enter async context."""
        self._semaphore = asyncio.Semaphore(self._max_concurrent)
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=self._max_concurrent * 2,
                max_keepalive_connections=self._max_concurrent,
            ),
        )
        logger.debug(f"ConcurrentExecutor started (max_concurrent={self._max_concurrent})")
        return self
    
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
            self._client = None
        self._semaphore = None
        logger.debug("ConcurrentExecutor closed")
    
    async def execute_request(self, task: "ScanTask") -> dict[str, Any]:
        """Execute HTTP request for a task.
        
        Args:
            task: ScanTask with request details
            
        Returns:
            Dict with status_code, headers, body, or error
        """
        if not self._client or not self._semaphore:
            raise RuntimeError("Executor not started. Use 'async with' context.")
        
        async with self._semaphore:
            try:
                if task.method == "GET":
                    response = await self._client.get(
                        task.url,
                        params=task.parameters,
                    )
                elif task.method == "POST":
                    response = await self._client.post(
                        task.url,
                        data=task.parameters,
                    )
                elif task.method == "PUT":
                    response = await self._client.put(
                        task.url,
                        data=task.parameters,
                    )
                elif task.method == "DELETE":
                    response = await self._client.delete(
                        task.url,
                        params=task.parameters,
                    )
                elif task.method == "PATCH":
                    response = await self._client.patch(
                        task.url,
                        data=task.parameters,
                    )
                elif task.method == "OPTIONS":
                    response = await self._client.options(task.url)
                elif task.method == "HEAD":
                    response = await self._client.head(task.url)
                else:
                    # Generic request for other methods
                    response = await self._client.request(
                        task.method,
                        task.url,
                        params=task.parameters,
                    )
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:2000],  # Limit response size
                }
                
            except httpx.TimeoutException as e:
                logger.warning(f"Request timeout: {task.method} {task.url}")
                return {"status_code": 0, "error": f"Timeout: {e}"}
                
            except httpx.RequestError as e:
                logger.warning(f"Request error: {task.method} {task.url} - {e}")
                return {"status_code": 0, "error": str(e)}
                
            except Exception as e:
                logger.error(f"Unexpected error: {task.method} {task.url} - {e}")
                return {"status_code": 0, "error": str(e)}
