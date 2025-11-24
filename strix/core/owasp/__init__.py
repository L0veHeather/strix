"""OWASP Top 10 Security Reference Package.

Comprehensive reference for OWASP security standards covering:
- OWASP Web Application Top 10 (2025)
- OWASP API Security Top 10 (2025)
- OWASP LLM Top 10 (2025)
- OWASP MCP Top 10 (2025)

Usage:
    from strix.core.owasp import (
        get_web_top10,
        get_api_top10,
        get_llm_top10,
        get_mcp_top10,
        map_vulnerability_to_owasp,
        OWASPCategory,
    )

    # Get specific category details
    category = get_web_top10("A01")
    print(f"{category.id}: {category.name}")

    # Map a vulnerability to OWASP categories
    mappings = map_vulnerability_to_owasp("SQL Injection")
    for m in mappings:
        print(f"{m.standard}: {m.category.id}")
"""

from __future__ import annotations

from .api_security import API_TOP10_2025, get_api_top10
from .base import OWASPCategory, OWASPMapping, OWASPStandard, Severity
from .llm_top10 import LLM_TOP10_2025, get_llm_top10
from .mcp_top10 import MCP_TOP10_2025, get_mcp_top10
from .web_applications import WEB_TOP10_2025, get_web_top10

__all__ = [
    # Base classes
    "OWASPCategory",
    "OWASPMapping",
    "OWASPStandard",
    "Severity",
    # Data dictionaries
    "WEB_TOP10_2025",
    "API_TOP10_2025",
    "LLM_TOP10_2025",
    "MCP_TOP10_2025",
    # Getter functions
    "get_web_top10",
    "get_api_top10",
    "get_llm_top10",
    "get_mcp_top10",
    # Utility functions
    "map_vulnerability_to_owasp",
    "get_all_categories_by_severity",
    "generate_report_appendix",
    "get_testing_guidance",
    "get_mitre_mappings",
]


def map_vulnerability_to_owasp(vulnerability: str) -> list[OWASPMapping]:
    """Map a vulnerability type to relevant OWASP categories.

    Args:
        vulnerability: Vulnerability type (e.g., "SQL Injection", "IDOR")

    Returns:
        List of OWASPMapping objects across all standards
    """
    mappings: list[OWASPMapping] = []
    vuln_lower = vulnerability.lower()

    # Vulnerability to OWASP category mapping
    vuln_map: dict[str, list[tuple[str, str, float]]] = {
        # (standard_prefix, category_id, relevance)
        "sql injection": [("WEB", "A03", 1.0), ("API", "API8", 0.7)],
        "sqli": [("WEB", "A03", 1.0)],
        "xss": [("WEB", "A03", 1.0), ("LLM", "LLM05", 0.8)],
        "cross-site scripting": [("WEB", "A03", 1.0)],
        "idor": [("WEB", "A01", 1.0), ("API", "API1", 1.0)],
        "insecure direct object reference": [("WEB", "A01", 1.0), ("API", "API1", 1.0)],
        "broken access control": [("WEB", "A01", 1.0), ("API", "API1", 0.9), ("API", "API5", 0.9)],
        "ssrf": [("WEB", "A10", 1.0), ("API", "API7", 1.0), ("MCP", "MCP05", 1.0)],
        "server-side request forgery": [("WEB", "A10", 1.0), ("API", "API7", 1.0), ("MCP", "MCP05", 1.0)],
        "authentication": [("WEB", "A07", 1.0), ("API", "API2", 1.0)],
        "jwt": [("WEB", "A07", 0.9), ("API", "API2", 0.9)],
        "csrf": [("WEB", "A01", 0.8)],
        "xxe": [("WEB", "A05", 0.9), ("WEB", "A03", 0.7)],
        "xml external entity": [("WEB", "A05", 0.9)],
        "cryptographic": [("WEB", "A02", 1.0)],
        "sensitive data": [("WEB", "A02", 1.0), ("LLM", "LLM02", 0.9), ("MCP", "MCP03", 0.8)],
        "injection": [("WEB", "A03", 1.0), ("LLM", "LLM01", 0.9), ("LLM", "LLM05", 0.8), ("MCP", "MCP01", 0.9)],
        "deserialization": [("WEB", "A08", 1.0)],
        "misconfiguration": [("WEB", "A05", 1.0), ("API", "API8", 1.0)],
        "security misconfiguration": [("WEB", "A05", 1.0), ("API", "API8", 1.0)],
        "vulnerable component": [("WEB", "A06", 1.0), ("LLM", "LLM03", 0.8)],
        "outdated": [("WEB", "A06", 1.0)],
        "logging": [("WEB", "A09", 1.0), ("MCP", "MCP10", 1.0)],
        "monitoring": [("WEB", "A09", 1.0), ("MCP", "MCP10", 1.0)],
        "business logic": [("WEB", "A04", 1.0), ("API", "API6", 1.0)],
        "insecure design": [("WEB", "A04", 1.0)],
        "rate limit": [("API", "API4", 1.0), ("LLM", "LLM10", 0.8), ("MCP", "MCP09", 0.8)],
        "dos": [("API", "API4", 0.9), ("LLM", "LLM10", 0.8), ("MCP", "MCP09", 1.0)],
        "mass assignment": [("API", "API3", 1.0)],
        "excessive data": [("API", "API3", 1.0)],
        "prompt injection": [("LLM", "LLM01", 1.0)],
        "jailbreak": [("LLM", "LLM01", 1.0)],
        "hallucination": [("LLM", "LLM09", 1.0)],
        "llm": [("LLM", "LLM01", 0.8), ("LLM", "LLM02", 0.7)],
        "model": [("LLM", "LLM03", 0.7), ("LLM", "LLM04", 0.7)],
        "agent": [("LLM", "LLM06", 1.0)],
        "tool use": [("LLM", "LLM06", 0.9), ("MCP", "MCP01", 0.9), ("MCP", "MCP06", 0.9)],
        "rag": [("LLM", "LLM08", 1.0)],
        "embedding": [("LLM", "LLM08", 1.0)],
        "graphql": [("WEB", "A03", 0.8), ("API", "API1", 0.8)],
        "api": [("API", "API1", 0.7), ("API", "API2", 0.7)],
        "mcp": [("MCP", "MCP01", 0.8), ("MCP", "MCP02", 0.8)],
        "tool injection": [("MCP", "MCP01", 1.0)],
        "resource access": [("MCP", "MCP02", 1.0)],
        "transport": [("MCP", "MCP04", 1.0)],
        "sandbox escape": [("MCP", "MCP06", 1.0)],
        "server impersonation": [("MCP", "MCP07", 1.0)],
    }

    # Find matching mappings
    for key, category_list in vuln_map.items():
        if key in vuln_lower or vuln_lower in key:
            for standard_prefix, cat_id, relevance in category_list:
                category = None
                standard = None

                if standard_prefix == "WEB":
                    category = WEB_TOP10_2025.get(cat_id)
                    standard = OWASPStandard.WEB_TOP10_2025
                elif standard_prefix == "API":
                    category = API_TOP10_2025.get(cat_id)
                    standard = OWASPStandard.API_TOP10_2025
                elif standard_prefix == "LLM":
                    category = LLM_TOP10_2025.get(cat_id)
                    standard = OWASPStandard.LLM_TOP10_2025
                elif standard_prefix == "MCP":
                    category = MCP_TOP10_2025.get(cat_id)
                    standard = OWASPStandard.MCP_TOP10_2025

                if category and standard:
                    mapping = OWASPMapping(
                        vulnerability=vulnerability,
                        standard=standard,
                        category=category,
                        relevance=relevance,
                    )
                    # Avoid duplicates
                    if not any(m.category.id == mapping.category.id for m in mappings):
                        mappings.append(mapping)

    return mappings


def get_all_categories_by_severity(severity: Severity) -> list[OWASPCategory]:
    """Get all OWASP categories with a specific severity.

    Args:
        severity: Severity level to filter by

    Returns:
        List of matching categories across all standards
    """
    categories = []

    for cat in WEB_TOP10_2025.values():
        if cat.severity == severity:
            categories.append(cat)

    for cat in API_TOP10_2025.values():
        if cat.severity == severity:
            categories.append(cat)

    for cat in LLM_TOP10_2025.values():
        if cat.severity == severity:
            categories.append(cat)

    for cat in MCP_TOP10_2025.values():
        if cat.severity == severity:
            categories.append(cat)

    return categories


def get_testing_guidance(category: OWASPCategory) -> list[str]:
    """Get testing guidance for an OWASP category."""
    return category.testing_guidance.copy()


def get_mitre_mappings(category: OWASPCategory) -> list[str]:
    """Get MITRE ATT&CK technique IDs for an OWASP category."""
    return category.mitre_techniques.copy()


def generate_report_appendix(standard: OWASPStandard) -> str:
    """Generate a markdown appendix for an OWASP standard.

    Args:
        standard: OWASP standard to generate appendix for

    Returns:
        Markdown-formatted appendix string
    """
    categories: dict[str, OWASPCategory] = {}

    if standard == OWASPStandard.WEB_TOP10_2025:
        categories = WEB_TOP10_2025
        title = "OWASP Web Application Top 10 (2025)"
    elif standard == OWASPStandard.API_TOP10_2025:
        categories = API_TOP10_2025
        title = "OWASP API Security Top 10 (2025)"
    elif standard == OWASPStandard.LLM_TOP10_2025:
        categories = LLM_TOP10_2025
        title = "OWASP LLM Top 10 (2025)"
    elif standard == OWASPStandard.MCP_TOP10_2025:
        categories = MCP_TOP10_2025
        title = "OWASP MCP Top 10 (2025)"
    else:
        return ""

    lines = [f"# {title}\n"]

    for cat_id in sorted(categories.keys()):
        cat = categories[cat_id]
        lines.append(f"## {cat.id} - {cat.name}\n")
        lines.append(f"**Severity:** {cat.severity.value.upper()}\n")
        lines.append(f"\n{cat.description}\n")

        if cat.attack_vectors:
            lines.append("\n### Attack Vectors\n")
            for av in cat.attack_vectors:
                lines.append(f"- {av}")

        if cat.prevention:
            lines.append("\n### Prevention\n")
            for p in cat.prevention:
                lines.append(f"- {p}")

        if cat.url:
            lines.append(f"\n**Reference:** {cat.url}\n")

        lines.append("\n---\n")

    return "\n".join(lines)
