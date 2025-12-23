"""OpenAI-compatible LLM Judge implementation.

Uses litellm for broad model compatibility (OpenAI, Claude, local models, etc.)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import litellm

from strix.brain.llm_judge import LLMJudge
from strix.models.finding import ConfidenceLevel, RiskLevel, VulnFinding
from strix.models.judgment import JudgmentRequest, JudgmentResult

logger = logging.getLogger(__name__)


class OpenAIJudge(LLMJudge):
    """LLM Judge implementation using OpenAI-compatible APIs.
    
    Supports any model through litellm:
    - OpenAI: gpt-4o, gpt-4o-mini
    - Anthropic: claude-3-5-sonnet
    - Local: ollama/llama3
    - And more...
    
    Example:
        judge = OpenAIJudge(model="gpt-4o-mini")
        result = await judge.judge(request)
    """
    
    def __init__(
        self,
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        temperature: float = 0.1,
        max_tokens: int = 2000,
    ):
        """Initialize the OpenAI Judge.
        
        Args:
            model: Model name (litellm format)
            api_key: API key (defaults to env var)
            temperature: LLM temperature (lower = more deterministic)
            max_tokens: Maximum tokens for response
        """
        self.model = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        # Configure litellm
        if self.api_key:
            litellm.api_key = self.api_key
    
    async def judge(self, request: JudgmentRequest) -> JudgmentResult:
        """Execute LLM judgment on a single request."""
        
        # Build prompts
        system_prompt = self.build_system_prompt(request.vuln_type)
        user_prompt = self._build_user_prompt(request)
        
        try:
            # Call LLM
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"},
            )
            
            # Parse response
            content = response.choices[0].message.content
            return self._parse_response(content)
            
        except Exception as e:
            logger.error(f"LLM judgment failed: {e}")
            return JudgmentResult.create_negative(
                reasoning=f"LLM analysis failed: {str(e)}"
            )
    
    async def batch_judge(
        self, 
        requests: list[JudgmentRequest]
    ) -> list[JudgmentResult]:
        """Batch judgment for multiple requests.
        
        Currently processes sequentially, but could be optimized
        to batch similar requests into single LLM calls.
        """
        results = []
        for request in requests:
            result = await self.judge(request)
            results.append(result)
        return results
    
    async def analyze_false_positive(
        self,
        finding: VulnFinding,
        additional_context: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        """Analyze whether a finding is a false positive."""
        
        prompt = f"""Analyze this vulnerability finding and determine if it's a false positive.

## Finding Details:
- Vulnerability Type: {finding.vuln_type}
- Target: {finding.target}
- Payload: {finding.payload}
- Original Confidence: {finding.confidence_score:.0%}
- Original Reasoning: {finding.llm_reasoning}

## Evidence:
{chr(10).join(f'- {e}' for e in finding.evidence)}

## HTTP Response:
```
{finding.raw_response[:3000]}
```

{f'## Additional Context: {additional_context}' if additional_context else ''}

Respond with JSON: {{"is_false_positive": boolean, "reasoning": "..."}}
"""
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert reviewing potential false positives."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=500,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            return data.get("is_false_positive", False), data.get("reasoning", "")
            
        except Exception as e:
            logger.error(f"False positive analysis failed: {e}")
            return False, f"Analysis failed: {e}"
    
    async def suggest_mutations(
        self,
        vuln_type: str,
        failed_payloads: list[str],
        response_patterns: list[str],
    ) -> list[str]:
        """Suggest payload mutations when current payloads fail."""
        
        # Load vuln-specific knowledge
        vuln_knowledge = self.get_vuln_prompt(vuln_type)
        
        prompt = f"""Based on the failed payloads and observed response patterns,
suggest new payload variations that might bypass defenses.

## Vulnerability Type: {vuln_type}

## Failed Payloads:
{chr(10).join(f'- {p}' for p in failed_payloads[:10])}

## Observed Response Patterns:
{chr(10).join(f'- {p}' for p in response_patterns[:10])}

{f'## Vulnerability Knowledge:{chr(10)}{vuln_knowledge[:2000]}' if vuln_knowledge else ''}

Suggest 5-10 new payload variations. Consider:
- Encoding bypasses (URL, Unicode, HTML entities)
- WAF evasion techniques
- Alternative syntax
- Case variations
- Comment injection

Respond with JSON: {{"suggestions": ["payload1", "payload2", ...]}}
"""
        
        try:
            response = await litellm.acompletion(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher specializing in payload crafting."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.7,  # Higher for creativity
                max_tokens=1000,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            data = json.loads(content)
            return data.get("suggestions", [])
            
        except Exception as e:
            logger.error(f"Mutation suggestion failed: {e}")
            return []
    
    def _build_user_prompt(self, request: JudgmentRequest) -> str:
        """Build the user prompt from the judgment request."""
        return f"""Analyze this HTTP request/response for {request.vuln_type} vulnerability.

{request.to_prompt_context()}

## Your Task:
1. Analyze if the payload triggered a vulnerability
2. Look for the expected behavior: {request.expected_behavior}
3. Consider false positive possibilities
4. Provide confidence score and evidence

Respond with JSON matching this schema:
{{
    "is_vulnerable": boolean,
    "confidence_score": float (0.0-1.0),
    "risk_level": "critical" | "high" | "medium" | "low" | "info",
    "reasoning": "Detailed analysis...",
    "evidence": ["evidence1", "evidence2"],
    "false_positive_reasons": ["reason1"] or [],
    "mutation_suggestions": ["suggestion1"] or []
}}
"""
    
    def _parse_response(self, content: str) -> JudgmentResult:
        """Parse LLM response into JudgmentResult."""
        try:
            data = json.loads(content)
            
            # Map risk level
            risk_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
                "info": RiskLevel.INFO,
            }
            
            # Map confidence level
            score = data.get("confidence_score", 0.0)
            if score >= 0.9:
                conf_level = ConfidenceLevel.CONFIRMED
            elif score >= 0.7:
                conf_level = ConfidenceLevel.LIKELY
            elif score >= 0.4:
                conf_level = ConfidenceLevel.SUSPECTED
            else:
                conf_level = ConfidenceLevel.FALSE_POSITIVE
            
            return JudgmentResult(
                is_vulnerable=data.get("is_vulnerable", False),
                confidence_score=score,
                confidence_level=conf_level,
                risk_level=risk_map.get(data.get("risk_level", "info"), RiskLevel.INFO),
                reasoning=data.get("reasoning", ""),
                evidence=data.get("evidence", []),
                is_false_positive=not data.get("is_vulnerable", False),
                false_positive_reasons=data.get("false_positive_reasons", []),
                needs_further_testing=bool(data.get("mutation_suggestions")),
                mutation_suggestions=data.get("mutation_suggestions", []),
                raw_llm_response=content,
            )
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}\nContent: {content[:500]}")
            return JudgmentResult.create_negative(
                reasoning=f"Failed to parse LLM response: {e}"
            )
