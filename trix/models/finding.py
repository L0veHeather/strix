"""Standardized vulnerability finding data model.

All detection results must conform to this format for UI display and report generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    """Risk severity level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConfidenceLevel(str, Enum):
    """Confidence level of the finding."""
    CONFIRMED = "confirmed"      # LLM confirmed as true positive
    LIKELY = "likely"            # Likely a vulnerability
    SUSPECTED = "suspected"      # Needs further verification
    FALSE_POSITIVE = "false_positive"  # LLM determined as false positive


@dataclass
class VulnFinding:
    """Standardized vulnerability finding result.
    
    All detection results must conform to this format for:
    - UI display
    - Report generation
    - JSON export
    
    Attributes:
        target: Target URL
        vuln_type: Vulnerability type (sqli, xss, ssrf, etc.)
        payload: The payload used
        raw_request: Raw HTTP request
        raw_response: Raw HTTP response
        llm_reasoning: LLM's reasoning process
        confidence_score: Confidence score (0.0 - 1.0)
        confidence_level: Confidence level enum
        risk_level: Risk severity level
    """
    
    # === Required fields ===
    target: str
    vuln_type: str
    payload: str
    
    # === Request/Response ===
    raw_request: str
    raw_response: str
    
    # === LLM judgment results ===
    llm_reasoning: str
    confidence_score: float
    confidence_level: ConfidenceLevel
    risk_level: RiskLevel
    
    # === Optional fields ===
    parameter: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    cve_id: str | None = None
    cwe_id: str | None = None
    owasp_category: str | None = None
    
    # === Metadata ===
    plugin_name: str = ""
    scan_id: str = ""
    discovered_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-compatible dictionary."""
        return {
            "target": self.target,
            "vuln_type": self.vuln_type,
            "payload": self.payload,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response,
            "llm_reasoning": self.llm_reasoning,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "risk_level": self.risk_level.value,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "plugin_name": self.plugin_name,
            "scan_id": self.scan_id,
            "discovered_at": self.discovered_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VulnFinding":
        """Create from dictionary."""
        return cls(
            target=data["target"],
            vuln_type=data["vuln_type"],
            payload=data["payload"],
            raw_request=data["raw_request"],
            raw_response=data["raw_response"],
            llm_reasoning=data["llm_reasoning"],
            confidence_score=data["confidence_score"],
            confidence_level=ConfidenceLevel(data["confidence_level"]),
            risk_level=RiskLevel(data["risk_level"]),
            parameter=data.get("parameter", ""),
            evidence=data.get("evidence", []),
            remediation=data.get("remediation", ""),
            cve_id=data.get("cve_id"),
            cwe_id=data.get("cwe_id"),
            owasp_category=data.get("owasp_category"),
            plugin_name=data.get("plugin_name", ""),
            scan_id=data.get("scan_id", ""),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) 
                if "discovered_at" in data else datetime.now(),
        )
    
    def __str__(self) -> str:
        """Human-readable representation."""
        return (
            f"[{self.risk_level.value.upper()}] {self.vuln_type} @ {self.target}\n"
            f"  Payload: {self.payload[:50]}{'...' if len(self.payload) > 50 else ''}\n"
            f"  Confidence: {self.confidence_score:.0%} ({self.confidence_level.value})\n"
            f"  Reasoning: {self.llm_reasoning[:100]}..."
        )
