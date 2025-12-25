"""PoC Validator for Vulnerability Verification.

This module provides programmatic validation of suspected vulnerabilities
by executing PoC requests and analyzing responses for indicators.

The validator makes the final determination - NOT the LLM.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class PoCRequest:
    """Proof-of-Concept request definition."""
    
    method: str
    url: str
    parameters: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    expected_indicators: list[str] = field(default_factory=list)
    vulnerability_type: str = "unknown"


@dataclass
class ValidationResult:
    """Result of PoC validation."""
    
    is_vulnerable: bool = False
    confidence: str = "low"  # high/medium/low
    evidence: list[str] = field(default_factory=list)
    validation_method: str = "pattern_matching"


# Common vulnerability indicators by type
VULNERABILITY_INDICATORS = {
    "sqli": [
        r"sql syntax",
        r"mysql_fetch",
        r"ORA-\d+",
        r"PostgreSQL.*ERROR",
        r"sqlite3\.OperationalError",
        r"SQLSTATE\[",
        r"You have an error in your SQL syntax",
        r"Warning.*mysql",
        r"Unclosed quotation mark",
    ],
    "xss": [
        r"<script>alert",
        r"javascript:alert",
        r"onerror=",
        r"onload=",
    ],
    "ssrf": [
        r"127\.0\.0\.1",
        r"localhost",
        r"169\.254\.169\.254",
        r"metadata\.google",
    ],
    "lfi": [
        r"root:.*:0:0:",
        r"\[boot loader\]",
        r"<\?php",
        r"Warning.*include",
        r"Warning.*file_get_contents",
    ],
    "rce": [
        r"uid=\d+.*gid=\d+",
        r"root:x:0:0",
        r"command not found",
        r"sh: \d+:",
    ],
}


class PoCValidator:
    """Validates suspected vulnerabilities by executing PoC requests.
    
    This class makes the FINAL determination on vulnerability status.
    The LLM generates PoC ideas, but CODE validates them.
    """
    
    def __init__(self, timeout: float = 10.0):
        """Initialize validator.
        
        Args:
            timeout: Request timeout in seconds
        """
        self._timeout = timeout
    
    async def validate_poc(self, poc: PoCRequest) -> ValidationResult:
        """Validate a PoC request.
        
        Args:
            poc: PoC request to validate
            
        Returns:
            ValidationResult with vulnerability determination
        """
        result = ValidationResult(
            is_vulnerable=False,
            confidence="low",
            evidence=[],
            validation_method="pattern_matching",
        )
        
        try:
            # Execute PoC request
            response = await self._execute_request(poc)
            
            if response is None:
                result.evidence.append("Request failed")
                return result
            
            response_text = response.get("body", "")
            status_code = response.get("status_code", 0)
            
            # Check expected indicators from LLM
            matched_expected = self._check_indicators(
                response_text,
                poc.expected_indicators,
            )
            
            # Check known vulnerability patterns
            matched_known = self._check_known_patterns(
                response_text,
                poc.vulnerability_type,
            )
            
            # Combine evidence
            all_matches = matched_expected + matched_known
            
            if all_matches:
                result.is_vulnerable = True
                result.evidence = all_matches
                
                # Determine confidence based on match count and type
                if len(all_matches) >= 3 or matched_known:
                    result.confidence = "high"
                elif len(all_matches) >= 2:
                    result.confidence = "medium"
                else:
                    result.confidence = "low"
                
                logger.info(
                    f"Vulnerability validated: {poc.vulnerability_type} "
                    f"(confidence={result.confidence}, evidence={len(all_matches)})"
                )
            else:
                result.evidence.append(f"No indicators found (status={status_code})")
            
        except Exception as e:
            logger.error(f"PoC validation error: {e}")
            result.evidence.append(f"Validation error: {e}")
        
        return result
    
    async def _execute_request(self, poc: PoCRequest) -> dict[str, Any] | None:
        """Execute the PoC HTTP request.
        
        Args:
            poc: PoC request definition
            
        Returns:
            Response dict or None on error
        """
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self._timeout,
                follow_redirects=True,
            ) as client:
                
                if poc.method.upper() == "GET":
                    response = await client.get(
                        poc.url,
                        params=poc.parameters,
                        headers=poc.headers,
                    )
                elif poc.method.upper() == "POST":
                    response = await client.post(
                        poc.url,
                        data=poc.parameters,
                        headers=poc.headers,
                    )
                else:
                    response = await client.request(
                        poc.method,
                        poc.url,
                        params=poc.parameters,
                        headers=poc.headers,
                    )
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:5000],
                }
                
        except Exception as e:
            logger.warning(f"PoC request failed: {poc.method} {poc.url} - {e}")
            return None
    
    def _check_indicators(
        self,
        response_text: str,
        indicators: list[str],
    ) -> list[str]:
        """Check response for expected indicators.
        
        Args:
            response_text: Response body text
            indicators: List of indicator patterns
            
        Returns:
            List of matched indicators
        """
        matches = []
        response_lower = response_text.lower()
        
        for indicator in indicators:
            try:
                # Try as regex first
                if re.search(indicator, response_text, re.IGNORECASE):
                    matches.append(f"Pattern matched: {indicator[:50]}")
            except re.error:
                # Fall back to substring match
                if indicator.lower() in response_lower:
                    matches.append(f"Substring found: {indicator[:50]}")
        
        return matches
    
    def _check_known_patterns(
        self,
        response_text: str,
        vulnerability_type: str,
    ) -> list[str]:
        """Check response for known vulnerability patterns.
        
        Args:
            response_text: Response body text
            vulnerability_type: Type of vulnerability
            
        Returns:
            List of matched known patterns
        """
        matches = []
        
        # Get patterns for this vulnerability type
        patterns = VULNERABILITY_INDICATORS.get(vulnerability_type.lower(), [])
        
        for pattern in patterns:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    matches.append(f"Known pattern: {pattern[:50]}")
            except re.error:
                continue
        
        return matches
