"""Pydantic models for validating LLM outputs in each scan phase.

These schemas ensure LLM outputs conform to expected structure,
preventing silent failures from malformed JSON.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field, field_validator


class EnumerationOutput(BaseModel):
    """Schema for ENUMERATION phase output."""
    
    new_urls: list[str] = Field(default_factory=list, description="Discovered URLs")
    new_params: list[str] = Field(default_factory=list, description="Discovered parameters")
    technologies: list[str] = Field(default_factory=list, description="Detected technologies")
    
    @field_validator('new_urls')
    @classmethod
    def validate_urls(cls, v: list[str]) -> list[str]:
        """Ensure URLs are non-empty strings."""
        return [url.strip() for url in v if url and isinstance(url, str) and url.strip()]
    
    @field_validator('new_params')
    @classmethod
    def validate_params(cls, v: list[str]) -> list[str]:
        """Ensure params are non-empty strings."""
        return [param.strip() for param in v if param and isinstance(param, str) and param.strip()]


class ParamExpansionOutput(BaseModel):
    """Schema for PARAM_EXPANSION phase output."""
    
    suggested_params: list[str] = Field(default_factory=list, description="Suggested hidden parameters")
    reasoning: str = Field(default="", description="Reasoning for suggestions")
    
    @field_validator('suggested_params')
    @classmethod
    def validate_params(cls, v: list[str]) -> list[str]:
        """Ensure params are valid."""
        return [param.strip() for param in v if param and isinstance(param, str) and param.strip()]


class VulnerabilityTestOutput(BaseModel):
    """Schema for VULNERABILITY_TEST phase output."""
    
    vulnerable: bool = Field(default=False, description="Whether vulnerability indicators found")
    vulnerability_type: str = Field(default="unknown", description="Type of vulnerability")
    confidence: str = Field(default="low", description="Confidence level: high/medium/low")
    evidence: str = Field(default="", description="Evidence description")
    severity: str = Field(default="medium", description="Severity: critical/high/medium/low")
    
    @field_validator('confidence')
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        """Ensure confidence is valid."""
        valid = ["high", "medium", "low"]
        return v.lower() if v.lower() in valid else "low"
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Ensure severity is valid."""
        valid = ["critical", "high", "medium", "low"]
        return v.lower() if v.lower() in valid else "medium"


class PoCRequestSchema(BaseModel):
    """Schema for a single PoC request."""
    
    poc_name: str = Field(default="Unnamed PoC", description="Name of the PoC")
    method: str = Field(default="GET", description="HTTP method")
    url: str = Field(..., description="Target URL")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Request parameters")
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    expected_indicators: list[str] = Field(default_factory=list, description="Expected indicators in response")
    validation_strategy: str = Field(default="pattern_matching", description="Validation strategy")
    reasoning: str = Field(default="", description="Why this PoC will work")


class LLMVerificationOutput(BaseModel):
    """Schema for LLM_VERIFICATION phase output."""
    
    poc_requests: list[PoCRequestSchema] = Field(default_factory=list, description="PoC requests to execute")
    attack_vectors: list[str] = Field(default_factory=list, description="Attack vector descriptions")
    validation_notes: str = Field(default="", description="Additional validation context")
    
    @field_validator('poc_requests')
    @classmethod
    def validate_pocs(cls, v: list[PoCRequestSchema]) -> list[PoCRequestSchema]:
        """Ensure at least one PoC if list provided."""
        return v if v else []


class DeepAnalysisOutput(BaseModel):
    """Schema for DEEP_ANALYSIS phase output."""
    
    chains: list[str] = Field(default_factory=list, description="Vulnerability chain descriptions")
    recommendations: list[str] = Field(default_factory=list, description="Recommendations")
    impact_assessment: str = Field(default="", description="Overall impact assessment")
