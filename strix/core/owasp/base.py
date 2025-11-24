"""OWASP Base Classes and Types.

Shared dataclasses and enums for OWASP Top 10 security standards.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OWASPStandard(str, Enum):
    """OWASP Security Standards."""

    WEB_TOP10_2025 = "OWASP Web Top 10 2025"
    API_TOP10_2025 = "OWASP API Security Top 10 2025"
    LLM_TOP10_2025 = "OWASP LLM Top 10 2025"
    MCP_TOP10_2025 = "OWASP MCP Top 10 2025"


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class OWASPCategory:
    """Represents an OWASP category/vulnerability class."""

    id: str  # e.g., "A01", "API1", "LLM01", "MCP01"
    name: str
    description: str
    standard: OWASPStandard
    severity: Severity
    cwe_ids: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    impact: str = ""
    detection_methods: list[str] = field(default_factory=list)
    prevention: list[str] = field(default_factory=list)
    testing_guidance: list[str] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "standard": self.standard.value,
            "severity": self.severity.value,
            "cwe_ids": self.cwe_ids,
            "attack_vectors": self.attack_vectors,
            "impact": self.impact,
            "detection_methods": self.detection_methods,
            "prevention": self.prevention,
            "testing_guidance": self.testing_guidance,
            "examples": self.examples,
            "mitre_techniques": self.mitre_techniques,
            "url": self.url,
        }


@dataclass
class OWASPMapping:
    """Maps a vulnerability to OWASP categories."""

    vulnerability: str
    standard: OWASPStandard
    category: OWASPCategory
    relevance: float = 1.0  # 0.0 - 1.0 relevance score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability": self.vulnerability,
            "standard": self.standard.value,
            "category_id": self.category.id,
            "category_name": self.category.name,
            "relevance": self.relevance,
        }
