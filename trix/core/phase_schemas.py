"""Phase Output Schemas for LLM Response Validation.

This module defines Pydantic models for validating structured LLM outputs
across different scan phases. These schemas ensure deterministic parsing
of LLM responses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class EnumerationOutput(BaseModel):
    """Schema for ENUMERATION phase LLM output."""
    
    new_urls: list[str] = Field(default_factory=list)
    new_params: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)


class ParamExpansionOutput(BaseModel):
    """Schema for PARAM_EXPANSION phase LLM output."""
    
    suggested_params: list[str] = Field(default_factory=list)
    reasoning: str = ""


class VulnerabilityTestOutput(BaseModel):
    """Schema for VULNERABILITY_TEST phase LLM output."""
    
    vulnerable: bool = False
    vulnerability_type: str = ""
    confidence: str = "low"  # high/medium/low
    evidence: str = ""
    severity: str = "low"  # critical/high/medium/low


class PoCRequestSchema(BaseModel):
    """Schema for a single PoC request in LLM_VERIFICATION phase."""
    
    poc_name: str = ""
    method: str = "GET"
    url: str = ""
    parameters: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    expected_indicators: list[str] = Field(default_factory=list)
    validation_strategy: str = "pattern_matching"
    reasoning: str = ""


class LLMVerificationOutput(BaseModel):
    """Schema for LLM_VERIFICATION phase LLM output."""
    
    poc_requests: list[PoCRequestSchema] = Field(default_factory=list)
    attack_vectors: list[str] = Field(default_factory=list)
    validation_notes: str = ""


class DeepAnalysisOutput(BaseModel):
    """Schema for DEEP_ANALYSIS phase LLM output."""
    
    chains: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
