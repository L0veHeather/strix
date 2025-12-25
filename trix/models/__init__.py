"""Trix Models Package - Standardized data structures for LLM-driven scanning."""

from trix.models.finding import (
    ConfidenceLevel,
    RiskLevel,
    VulnFinding,
)
from trix.models.judgment import (
    JudgmentRequest,
    JudgmentResult,
)
from trix.models.request import (
    HttpRequest,
    HttpResponse,
    ScanTarget,
)

__all__ = [
    # Finding
    "ConfidenceLevel",
    "RiskLevel", 
    "VulnFinding",
    # Judgment
    "JudgmentRequest",
    "JudgmentResult",
    # Request
    "HttpRequest",
    "HttpResponse",
    "ScanTarget",
]
