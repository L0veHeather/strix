"""OWASP API Security Top 10 (2025).

Reference for API-specific security risks and vulnerabilities.
"""

from __future__ import annotations

from .base import OWASPCategory, OWASPStandard, Severity

API_TOP10_2025: dict[str, OWASPCategory] = {
    "API1": OWASPCategory(
        id="API1:2025",
        name="Broken Object Level Authorization",
        description="APIs expose endpoints handling object identifiers, creating a wide attack surface for Object Level Access Control issues (IDOR).",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-284", "CWE-285", "CWE-639"],
        attack_vectors=[
            "Object ID manipulation",
            "IDOR attacks",
            "UUID/GUID enumeration",
            "Batch request manipulation",
        ],
        impact="Unauthorized access to other users' data, data exfiltration.",
        prevention=[
            "Implement authorization checks for every object access",
            "Use random, unpredictable object IDs (UUIDs)",
            "Verify user ownership/permissions on every request",
            "Implement proper access control tests",
        ],
        testing_guidance=[
            "Test object IDs with different user sessions",
            "Enumerate and swap object IDs",
            "Test batch/bulk operations",
            "Check GraphQL node queries",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ),
    "API2": OWASPCategory(
        id="API2:2025",
        name="Broken Authentication",
        description="Authentication mechanisms implemented incorrectly allowing attackers to compromise tokens or exploit implementation flaws.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-287", "CWE-798", "CWE-306"],
        attack_vectors=[
            "Credential stuffing",
            "JWT attacks (alg:none, key confusion)",
            "Token theft/replay",
            "Brute force",
            "Password spraying",
        ],
        impact="Account takeover, unauthorized API access.",
        prevention=[
            "Use strong authentication (OAuth 2.0, OpenID Connect)",
            "Implement proper JWT validation (algorithm, signature, expiry)",
            "Use rate limiting and account lockout",
            "Implement MFA for sensitive operations",
        ],
        testing_guidance=[
            "Test JWT signature validation",
            "Test algorithm substitution",
            "Test token expiration",
            "Brute force testing",
        ],
        mitre_techniques=["T1110", "T1528"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    "API3": OWASPCategory(
        id="API3:2025",
        name="Broken Object Property Level Authorization",
        description="APIs exposing object properties without proper authorization, allowing excessive data exposure or mass assignment.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-213", "CWE-915"],
        attack_vectors=[
            "Excessive data exposure",
            "Mass assignment",
            "Property injection",
            "Hidden field manipulation",
        ],
        impact="Data leakage, privilege escalation via property modification.",
        prevention=[
            "Return only necessary properties",
            "Implement property-level authorization",
            "Use DTOs with explicit allowlists",
            "Avoid generic binding methods",
        ],
        testing_guidance=[
            "Check responses for sensitive fields",
            "Test mass assignment attacks",
            "Modify unexpected properties",
            "Compare user vs admin responses",
        ],
        mitre_techniques=["T1078", "T1087"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    ),
    "API4": OWASPCategory(
        id="API4:2025",
        name="Unrestricted Resource Consumption",
        description="APIs not properly limiting size/number of resources, leading to DoS, financial impact, or resource exhaustion.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-770", "CWE-400", "CWE-799"],
        attack_vectors=[
            "Resource exhaustion",
            "API abuse/scraping",
            "Denial of Service",
            "Cost amplification (cloud)",
        ],
        impact="Service unavailability, increased operational costs.",
        prevention=[
            "Implement rate limiting per client",
            "Set resource quotas and pagination limits",
            "Validate payload sizes",
            "Implement cost-based throttling",
        ],
        testing_guidance=[
            "Test rate limits",
            "Send oversized payloads",
            "Test pagination limits",
            "GraphQL query complexity testing",
        ],
        mitre_techniques=["T1498", "T1499"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    ),
    "API5": OWASPCategory(
        id="API5:2025",
        name="Broken Function Level Authorization",
        description="Complex access control policies allowing attackers to access administrative endpoints without proper authorization.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-285"],
        attack_vectors=[
            "Privilege escalation",
            "Admin function access",
            "HTTP method tampering",
            "Path traversal to admin endpoints",
        ],
        impact="Complete system compromise, unauthorized administrative access.",
        prevention=[
            "Deny access by default",
            "Implement role-based access control (RBAC)",
            "Verify authorization for all endpoints",
            "Use centralized authorization module",
        ],
        testing_guidance=[
            "Test admin endpoints with user tokens",
            "Change HTTP methods (GET to PUT)",
            "Test function-level access controls",
            "Enumerate hidden admin endpoints",
        ],
        mitre_techniques=["T1078", "T1068"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    "API6": OWASPCategory(
        id="API6:2025",
        name="Unrestricted Access to Sensitive Business Flows",
        description="APIs exposing business flows vulnerable to abuse when accessed in automated manner without proper controls.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-799", "CWE-639"],
        attack_vectors=[
            "Business logic abuse",
            "Automated attacks (bots)",
            "Scalping/hoarding",
            "Spam/fake engagement",
        ],
        impact="Business impact, financial loss, unfair competitive advantage.",
        prevention=[
            "Identify sensitive business flows",
            "Implement anti-automation (CAPTCHA, rate limits)",
            "Use device fingerprinting",
            "Monitor for anomalous patterns",
        ],
        testing_guidance=[
            "Automate business-critical workflows",
            "Test rate limits on business functions",
            "Bypass anti-automation controls",
        ],
        mitre_techniques=["T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/",
    ),
    "API7": OWASPCategory(
        id="API7:2025",
        name="Server Side Request Forgery",
        description="SSRF when API fetches remote resources without validating user-supplied URLs, enabling access to internal services.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-918"],
        attack_vectors=[
            "Internal service access",
            "Cloud metadata access",
            "Internal port scanning",
            "Protocol smuggling",
        ],
        impact="Internal data exposure, cloud credential theft, lateral movement.",
        prevention=[
            "Validate and sanitize URLs",
            "Use URL allowlists",
            "Disable unnecessary protocols",
            "Segment internal networks",
        ],
        testing_guidance=[
            "Test URL parameters with internal addresses",
            "Cloud metadata endpoint testing",
            "Protocol smuggling tests",
        ],
        mitre_techniques=["T1190", "T1046"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/",
    ),
    "API8": OWASPCategory(
        id="API8:2025",
        name="Security Misconfiguration",
        description="APIs and supporting systems with misconfigurations creating security vulnerabilities.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-16", "CWE-200", "CWE-497"],
        attack_vectors=[
            "Verbose error messages",
            "Default credentials",
            "Unnecessary features enabled",
            "Missing security headers",
            "Exposed debug endpoints",
        ],
        impact="Information disclosure, system compromise.",
        prevention=[
            "Implement security hardening",
            "Disable unnecessary features",
            "Secure error handling",
            "Regular configuration audits",
        ],
        testing_guidance=[
            "Check error messages for stack traces",
            "Verify security headers",
            "Test default credentials",
            "Find debug/test endpoints",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    ),
    "API9": OWASPCategory(
        id="API9:2025",
        name="Improper Inventory Management",
        description="APIs exposing more endpoints than intended, including deprecated, test, or shadow APIs.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1059"],
        attack_vectors=[
            "Shadow API exploitation",
            "Deprecated endpoint abuse",
            "Version bypass attacks",
            "Undocumented endpoint discovery",
        ],
        impact="Exposure of sensitive functionality through forgotten APIs.",
        prevention=[
            "Maintain comprehensive API inventory",
            "Deprecate old versions properly",
            "Monitor for unauthorized APIs",
            "Use API gateways with strict routing",
        ],
        testing_guidance=[
            "Enumerate API versions",
            "Search for hidden endpoints",
            "Test deprecated APIs",
            "Compare documentation vs reality",
        ],
        mitre_techniques=["T1595"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    ),
    "API10": OWASPCategory(
        id="API10:2025",
        name="Unsafe Consumption of APIs",
        description="Developers trusting third-party API data more than user input, adopting weaker security standards for external data.",
        standard=OWASPStandard.API_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-20", "CWE-346"],
        attack_vectors=[
            "Third-party API manipulation",
            "Redirect attacks",
            "Injection via trusted sources",
            "Supply chain API attacks",
        ],
        impact="Data injection, SSRF, information disclosure.",
        prevention=[
            "Validate all third-party API responses",
            "Use timeouts and circuit breakers",
            "Limit redirect following",
            "Apply same input validation to external data",
        ],
        testing_guidance=[
            "Intercept third-party API calls",
            "Inject malicious responses",
            "Test error handling for external failures",
        ],
        mitre_techniques=["T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/",
    ),
}


def get_api_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP API Security Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "API1"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return API_TOP10_2025.copy()

    normalized = category_id.upper()
    if not normalized.startswith("API"):
        normalized = f"API{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return API_TOP10_2025.get(normalized)
