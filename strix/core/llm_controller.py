"""Scan Controller - Orchestrates the LLM-driven scanning flow.

This is the main coordinator that:
1. Takes targets and plugins as input
2. Uses plugins to generate payloads (no judgment)
3. Sends HTTP requests (deterministic logic)
4. Submits responses to LLM for judgment (AI Brain)
5. Collects and returns standardized findings
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Any

import httpx

from strix.brain.llm_judge import LLMJudge
from strix.models.finding import VulnFinding
from strix.models.judgment import JudgmentRequest
from strix.models.request import HttpRequest, HttpResponse, ScanTarget
from strix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec

logger = logging.getLogger(__name__)


class ScanController:
    """Main scan controller - orchestrates LLM-driven vulnerability scanning.
    
    Architecture:
    - Controller handles: task scheduling, HTTP requests, concurrency
    - Plugin handles: payload generation
    - LLM handles: vulnerability judgment
    
    Usage:
        controller = ScanController(llm_judge=OpenAIJudge())
        async for finding in controller.scan(target, plugins):
            print(finding)
    """
    
    def __init__(
        self,
        llm_judge: LLMJudge,
        max_concurrent: int = 10,
        timeout: float = 30.0,
        verify_ssl: bool = False,
    ):
        """Initialize the controller.
        
        Args:
            llm_judge: LLM judge instance for vulnerability analysis
            max_concurrent: Maximum concurrent HTTP requests
            timeout: HTTP request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.llm_judge = llm_judge
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        self._semaphore: asyncio.Semaphore | None = None
        self._client: httpx.AsyncClient | None = None
        
        # Statistics
        self.stats = {
            "requests_sent": 0,
            "payloads_tested": 0,
            "findings_confirmed": 0,
            "llm_calls": 0,
        }
    
    async def __aenter__(self) -> "ScanController":
        """Enter async context."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._client = httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, *args) -> None:
        """Exit async context."""
        if self._client:
            await self._client.aclose()
        self._client = None
        self._semaphore = None
    
    async def scan(
        self,
        target: ScanTarget,
        plugins: list[BaseVulnPlugin],
    ) -> AsyncIterator[VulnFinding]:
        """Scan a target with multiple plugins.
        
        Main scanning flow:
        1. Get baseline response
        2. For each plugin, generate payloads
        3. Send requests concurrently
        4. Submit to LLM for judgment
        5. Yield confirmed findings
        
        Args:
            target: Target to scan
            plugins: List of vulnerability plugins
            
        Yields:
            VulnFinding for each confirmed vulnerability
        """
        if not self._client:
            raise RuntimeError("Controller not started. Use 'async with' context.")
        
        # Get baseline response
        baseline = await self._get_baseline(target)
        
        # Scan with each plugin
        for plugin in plugins:
            if not plugin.enabled:
                continue
            
            logger.info(f"Scanning with plugin: {plugin.name}")
            
            async for finding in self._scan_with_plugin(target, plugin, baseline):
                yield finding
    
    async def scan_parameter(
        self,
        target: ScanTarget,
        parameter: str,
        plugins: list[BaseVulnPlugin],
    ) -> AsyncIterator[VulnFinding]:
        """Scan a specific parameter with multiple plugins.
        
        Args:
            target: Target to scan
            parameter: Parameter name to test
            plugins: List of vulnerability plugins
            
        Yields:
            VulnFinding for each confirmed vulnerability
        """
        # Get baseline
        baseline = await self._get_baseline(target)
        
        for plugin in plugins:
            if not plugin.enabled:
                continue
            
            # Create context
            context = PayloadContext(
                target=target.url,
                parameter=parameter,
                method=target.method,
            )
            
            # Generate payloads
            payloads = plugin.generate_payloads(context)
            
            # Test each payload
            for payload in payloads:
                finding = await self._test_payload(
                    target, parameter, plugin, payload, baseline
                )
                if finding:
                    yield finding
    
    async def _get_baseline(self, target: ScanTarget) -> HttpResponse:
        """Get baseline response without any payloads."""
        try:
            response = await self._client.request(
                target.method,
                target.url,
                headers=target.headers,
            )
            
            return HttpResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.text[:10000],
                response_time_ms=response.elapsed.total_seconds() * 1000,
            )
        except Exception as e:
            logger.error(f"Failed to get baseline: {e}")
            return HttpResponse(status_code=0, error=str(e))
    
    async def _scan_with_plugin(
        self,
        target: ScanTarget,
        plugin: BaseVulnPlugin,
        baseline: HttpResponse,
    ) -> AsyncIterator[VulnFinding]:
        """Scan target with a single plugin."""
        
        # For each parameter
        for parameter in target.parameters or ["id", "q", "search", "page"]:
            context = PayloadContext(
                target=target.url,
                parameter=parameter,
                method=target.method,
            )
            
            # Generate payloads
            payloads = plugin.generate_payloads(context)
            logger.debug(f"Generated {len(payloads)} payloads for {parameter}")
            
            # Test payloads concurrently
            tasks = [
                self._test_payload(target, parameter, plugin, payload, baseline)
                for payload in payloads
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, VulnFinding):
                    yield result
                elif isinstance(result, Exception):
                    logger.warning(f"Payload test failed: {result}")
    
    async def _test_payload(
        self,
        target: ScanTarget,
        parameter: str,
        plugin: BaseVulnPlugin,
        payload_spec: PayloadSpec,
        baseline: HttpResponse,
    ) -> VulnFinding | None:
        """Test a single payload and get LLM judgment.
        
        Flow:
        1. Send HTTP request with payload
        2. Build judgment request
        3. Submit to LLM
        4. Process result through plugin
        """
        async with self._semaphore:
            self.stats["payloads_tested"] += 1
            
            # 1. Send HTTP request with payload
            request, response = await self._send_payload_request(
                target, parameter, payload_spec.payload
            )
            self.stats["requests_sent"] += 1
            
            if response.error:
                return None
            
            # 2. Build judgment request
            judgment_request = JudgmentRequest(
                vuln_type=plugin.vuln_type,
                target=target.url,
                payload=payload_spec.payload,
                raw_request=request.to_raw(),
                raw_response=response.to_raw(),
                baseline_response=baseline.to_raw(),
                response_time_ms=response.response_time_ms,
                baseline_time_ms=baseline.response_time_ms,
                context=plugin.get_judgment_context(payload_spec),
                expected_behavior=payload_spec.expected_behavior,
            )
            
            # 3. Submit to LLM
            self.stats["llm_calls"] += 1
            judgment_result = await self.llm_judge.judge(judgment_request)
            
            # 4. Process through plugin
            finding = plugin.process_judgment(
                payload_spec,
                judgment_result,
                request.to_raw(),
                response.to_raw(),
                target.url,
            )
            
            if finding:
                self.stats["findings_confirmed"] += 1
                logger.info(f"[+] Found {plugin.vuln_type}: {target.url}")
            
            return finding
    
    async def _send_payload_request(
        self,
        target: ScanTarget,
        parameter: str,
        payload: str,
    ) -> tuple[HttpRequest, HttpResponse]:
        """Send HTTP request with payload injected."""
        
        # Build URL with payload
        if target.method == "GET":
            url = target.url
            if "?" in url:
                url = f"{url}&{parameter}={payload}"
            else:
                url = f"{url}?{parameter}={payload}"
            params = {}
            body = ""
        else:
            url = target.url
            params = {parameter: payload}
            body = f"{parameter}={payload}"
        
        request = HttpRequest(
            method=target.method,
            url=url,
            headers=target.headers,
            body=body,
            params=params,
            injected_parameter=parameter,
            injected_payload=payload,
        )
        
        try:
            if target.method == "GET":
                resp = await self._client.get(url, headers=target.headers)
            else:
                resp = await self._client.request(
                    target.method,
                    target.url,
                    data=params,
                    headers=target.headers,
                )
            
            response = HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:10000],
                response_time_ms=resp.elapsed.total_seconds() * 1000,
            )
            
        except Exception as e:
            response = HttpResponse(status_code=0, error=str(e))
        
        return request, response
    
    def get_stats(self) -> dict[str, Any]:
        """Get scanning statistics."""
        return self.stats.copy()
