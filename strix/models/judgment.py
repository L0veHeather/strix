"""LLM Judgment request and result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from strix.models.finding import ConfidenceLevel, RiskLevel


@dataclass
class JudgmentRequest:
    """Request for LLM vulnerability judgment.
    
    Contains all information needed for LLM to analyze a potential vulnerability.
    """
    
    # === Vulnerability context ===
    vuln_type: str               # Vulnerability type (sqli, xss, ssrf, etc.)
    target: str                  # Target URL
    payload: str                 # The payload used
    
    # === HTTP data ===
    raw_request: str             # Raw HTTP request
    raw_response: str            # Raw HTTP response
    baseline_response: str = ""  # Baseline response for comparison
    
    # === Timing data (for time-based detection) ===
    response_time_ms: float = 0.0
    baseline_time_ms: float = 0.0
    
    # === Plugin-specific context ===
    context: dict[str, Any] = field(default_factory=dict)
    
    # === Expected behavior (from PayloadSpec) ===
    expected_behavior: str = ""
    
    def to_prompt_context(self) -> str:
        """Convert to context string for LLM prompt."""
        parts = [
            f"## Vulnerability Type: {self.vuln_type}",
            f"## Target: {self.target}",
            f"## Payload Used:\n```\n{self.payload}\n```",
            f"## Expected Behavior: {self.expected_behavior}",
            "",
            f"## Raw HTTP Request:\n```http\n{self.raw_request}\n```",
            "",
            f"## Raw HTTP Response:\n```http\n{self.raw_response[:5000]}\n```",
        ]
        
        if self.baseline_response:
            parts.extend([
                "",
                f"## Baseline Response (without payload):\n```http\n{self.baseline_response[:2000]}\n```",
            ])
        
        if self.response_time_ms > 0:
            parts.extend([
                "",
                f"## Timing: Response took {self.response_time_ms:.0f}ms (baseline: {self.baseline_time_ms:.0f}ms)",
            ])
        
        if self.context:
            parts.extend([
                "",
                f"## Additional Context:\n{self.context}",
            ])
        
        return "\n".join(parts)


@dataclass
class JudgmentResult:
    """Result of LLM vulnerability judgment.
    
    Contains the LLM's analysis and decision about the potential vulnerability.
    """
    
    # === Core judgment ===
    is_vulnerable: bool          # Whether vulnerability exists
    confidence_score: float      # Confidence (0.0 - 1.0)
    confidence_level: ConfidenceLevel
    risk_level: RiskLevel
    
    # === Reasoning ===
    reasoning: str               # LLM's reasoning process
    evidence: list[str] = field(default_factory=list)  # Evidence list
    
    # === False positive analysis ===
    is_false_positive: bool = False
    false_positive_reasons: list[str] = field(default_factory=list)
    
    # === Mutation suggestions ===
    needs_further_testing: bool = False
    mutation_suggestions: list[str] = field(default_factory=list)
    
    # === Remediation ===
    remediation_advice: str = ""
    
    # === Raw LLM response (for debugging) ===
    raw_llm_response: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_vulnerable": self.is_vulnerable,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "risk_level": self.risk_level.value,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "is_false_positive": self.is_false_positive,
            "false_positive_reasons": self.false_positive_reasons,
            "needs_further_testing": self.needs_further_testing,
            "mutation_suggestions": self.mutation_suggestions,
            "remediation_advice": self.remediation_advice,
        }
    
    @classmethod
    def create_negative(cls, reasoning: str = "No vulnerability detected") -> "JudgmentResult":
        """Create a negative (no vulnerability) result."""
        return cls(
            is_vulnerable=False,
            confidence_score=0.0,
            confidence_level=ConfidenceLevel.FALSE_POSITIVE,
            risk_level=RiskLevel.INFO,
            reasoning=reasoning,
        )
    
    @classmethod
    def create_confirmed(
        cls,
        reasoning: str,
        evidence: list[str],
        risk_level: RiskLevel,
        confidence_score: float = 0.95,
    ) -> "JudgmentResult":
        """Create a confirmed vulnerability result."""
        return cls(
            is_vulnerable=True,
            confidence_score=confidence_score,
            confidence_level=ConfidenceLevel.CONFIRMED,
            risk_level=risk_level,
            reasoning=reasoning,
            evidence=evidence,
        )
