"""OWASP Top 10 Reference Appendices.

Comprehensive reference for OWASP security standards covering:
- OWASP Top 10 Web Application Security Risks (2021)
- OWASP API Security Top 10 (2023)
- OWASP LLM Top 10 (2025)

Provides vulnerability classifications, testing guidance, and remediation
strategies for adaptive scanning and reporting.

Usage:
    from strix.core.owasp import (
        get_web_top10,
        get_api_top10,
        get_llm_top10,
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

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class OWASPStandard(str, Enum):
    """OWASP Security Standards."""

    WEB_TOP10_2021 = "OWASP Web Top 10 2021"
    API_TOP10_2023 = "OWASP API Security Top 10 2023"
    LLM_TOP10_2025 = "OWASP LLM Top 10 2025"
    MOBILE_TOP10 = "OWASP Mobile Top 10"


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

    id: str  # e.g., "A01", "API1", "LLM01"
    name: str
    description: str
    standard: OWASPStandard
    severity: Severity
    cwe_ids: list[str] = field(default_factory=list)  # Common Weakness Enumeration
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


# =============================================================================
# OWASP Web Application Top 10 (2021)
# =============================================================================

WEB_TOP10_2021: dict[str, OWASPCategory] = {
    "A01": OWASPCategory(
        id="A01:2021",
        name="Broken Access Control",
        description="Access control enforces policy such that users cannot act outside their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-200", "CWE-201", "CWE-352", "CWE-566", "CWE-639", "CWE-862", "CWE-863"],
        attack_vectors=[
            "URL manipulation",
            "IDOR (Insecure Direct Object Reference)",
            "Privilege escalation",
            "JWT manipulation",
            "CORS misconfiguration",
            "Force browsing",
        ],
        impact="Attackers can access unauthorized functionality and/or data, such as other users' accounts, sensitive files, or admin functions.",
        detection_methods=[
            "Manual testing with different user roles",
            "Automated access control testing",
            "Code review of authorization logic",
            "Penetration testing",
        ],
        prevention=[
            "Implement access control mechanisms once and re-use them",
            "Deny by default except for public resources",
            "Implement proper session management",
            "Rate limit API and controller access",
            "Log access control failures",
        ],
        testing_guidance=[
            "Test horizontal privilege escalation (accessing other users' data)",
            "Test vertical privilege escalation (accessing admin functions)",
            "Modify JWT tokens and session identifiers",
            "Test API endpoints without authentication",
            "Check CORS headers and policies",
        ],
        examples=[
            "Modifying URL parameter from ?id=123 to ?id=124",
            "Accessing /admin without proper authorization",
            "Bypassing access control by modifying JWT claims",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    "A02": OWASPCategory(
        id="A02:2021",
        name="Cryptographic Failures",
        description="Failures related to cryptography which often lead to exposure of sensitive data. Previously known as 'Sensitive Data Exposure'.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.HIGH,
        cwe_ids=["CWE-259", "CWE-327", "CWE-331", "CWE-328", "CWE-760"],
        attack_vectors=[
            "Man-in-the-middle attacks",
            "Weak cryptography exploitation",
            "Key extraction",
            "Padding oracle attacks",
        ],
        impact="Exposure of sensitive data including passwords, credit cards, health records, personal data, and business secrets.",
        detection_methods=[
            "SSL/TLS configuration testing",
            "Cryptographic implementation review",
            "Data flow analysis",
            "Traffic analysis",
        ],
        prevention=[
            "Classify data and identify sensitive data",
            "Use strong encryption algorithms (AES-256, RSA-2048+)",
            "Implement proper key management",
            "Use TLS 1.2+ for data in transit",
            "Disable caching for sensitive data",
        ],
        testing_guidance=[
            "Test SSL/TLS configuration",
            "Check for weak cipher suites",
            "Verify certificate validation",
            "Test for hardcoded secrets",
            "Check password storage mechanisms",
        ],
        mitre_techniques=["T1552", "T1555"],
        url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ),
    "A03": OWASPCategory(
        id="A03:2021",
        name="Injection",
        description="Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-79", "CWE-89", "CWE-564", "CWE-917"],
        attack_vectors=[
            "SQL injection",
            "NoSQL injection",
            "OS command injection",
            "LDAP injection",
            "XPath injection",
            "XSS (Cross-Site Scripting)",
        ],
        impact="Data loss, corruption, disclosure to unauthorized parties, loss of accountability, or denial of access. Can lead to complete host takeover.",
        detection_methods=[
            "Source code review",
            "Automated testing tools (SQLMap, etc.)",
            "Manual testing with payloads",
            "DAST/SAST scanning",
        ],
        prevention=[
            "Use parameterized queries / prepared statements",
            "Use ORM frameworks",
            "Input validation (whitelist)",
            "Escape special characters",
            "Use LIMIT and other SQL controls",
        ],
        testing_guidance=[
            "Test all user input fields for injection",
            "Use time-based and error-based payloads",
            "Test API parameters and headers",
            "Check for stored injection points",
            "Test GraphQL queries for injection",
        ],
        examples=[
            "' OR '1'='1' -- ",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "; cat /etc/passwd",
        ],
        mitre_techniques=["T1190", "T1059"],
        url="https://owasp.org/Top10/A03_2021-Injection/",
    ),
    "A04": OWASPCategory(
        id="A04:2021",
        name="Insecure Design",
        description="A new category focusing on risks related to design flaws. Insecure design cannot be fixed by a perfect implementation.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.HIGH,
        cwe_ids=["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        attack_vectors=[
            "Business logic abuse",
            "Race conditions",
            "Insufficient anti-automation",
            "Missing security controls",
        ],
        impact="Varies depending on the design flaw, but can lead to complete system compromise.",
        detection_methods=[
            "Threat modeling",
            "Design review",
            "Architecture analysis",
            "Business logic testing",
        ],
        prevention=[
            "Establish secure development lifecycle",
            "Use threat modeling",
            "Integrate security patterns",
            "Write unit and integration tests for security controls",
        ],
        testing_guidance=[
            "Test business logic flows",
            "Identify race conditions",
            "Test multi-step processes for bypass",
            "Review security architecture",
        ],
        mitre_techniques=["T1190"],
        url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
    ),
    "A05": OWASPCategory(
        id="A05:2021",
        name="Security Misconfiguration",
        description="Security misconfiguration is the most common issue, often a result of insecure default configurations, incomplete configurations, or misconfigured HTTP headers.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-16", "CWE-611", "CWE-1004"],
        attack_vectors=[
            "Default credentials",
            "Unnecessary features enabled",
            "Verbose error messages",
            "Missing security headers",
            "Directory listing",
        ],
        impact="May give attackers unauthorized access to system data or functionality. Can lead to complete system compromise.",
        detection_methods=[
            "Security header analysis",
            "Configuration review",
            "Vulnerability scanning",
            "Manual verification",
        ],
        prevention=[
            "Implement hardening procedures",
            "Remove unused features and frameworks",
            "Review and update configurations regularly",
            "Implement proper security headers",
        ],
        testing_guidance=[
            "Check for default credentials",
            "Test security headers",
            "Verify error handling",
            "Check for unnecessary services",
            "Review cloud configurations",
        ],
        mitre_techniques=["T1190", "T1078"],
        url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    "A06": OWASPCategory(
        id="A06:2021",
        name="Vulnerable and Outdated Components",
        description="Components such as libraries, frameworks, and software modules run with the same privileges as the application. Vulnerable components can undermine application defenses.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1104"],
        attack_vectors=[
            "Known CVE exploitation",
            "Supply chain attacks",
            "Dependency confusion",
        ],
        impact="Can range from minimal to complete system compromise depending on the vulnerability.",
        detection_methods=[
            "Software composition analysis (SCA)",
            "Dependency scanning",
            "CVE monitoring",
            "SBOM analysis",
        ],
        prevention=[
            "Maintain inventory of components",
            "Monitor for vulnerabilities continuously",
            "Update components regularly",
            "Remove unused dependencies",
        ],
        testing_guidance=[
            "Run dependency vulnerability scans",
            "Check component versions against CVE databases",
            "Verify SBOM accuracy",
            "Test known CVEs for exploitability",
        ],
        mitre_techniques=["T1190", "T1195"],
        url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    ),
    "A07": OWASPCategory(
        id="A07:2021",
        name="Identification and Authentication Failures",
        description="Confirmation of user identity, authentication, and session management is critical. Weaknesses in these areas can lead to authentication-related attacks.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.HIGH,
        cwe_ids=["CWE-287", "CWE-288", "CWE-306", "CWE-798"],
        attack_vectors=[
            "Credential stuffing",
            "Brute force attacks",
            "Session hijacking",
            "Session fixation",
            "Weak password recovery",
        ],
        impact="Account takeover, unauthorized access, identity theft.",
        detection_methods=[
            "Authentication flow testing",
            "Session management testing",
            "Password policy verification",
            "MFA testing",
        ],
        prevention=[
            "Implement MFA where possible",
            "Use strong password policies",
            "Implement account lockout",
            "Use secure session management",
            "Rotate session IDs after login",
        ],
        testing_guidance=[
            "Test password complexity requirements",
            "Test account lockout mechanisms",
            "Test session timeout and invalidation",
            "Test MFA bypass techniques",
            "Check for credential exposure in responses",
        ],
        mitre_techniques=["T1110", "T1078", "T1539"],
        url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    "A08": OWASPCategory(
        id="A08:2021",
        name="Software and Data Integrity Failures",
        description="Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.HIGH,
        cwe_ids=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829"],
        attack_vectors=[
            "Insecure deserialization",
            "CI/CD pipeline attacks",
            "Auto-update mechanism abuse",
            "Unsigned code execution",
        ],
        impact="Remote code execution, data manipulation, supply chain compromise.",
        detection_methods=[
            "Code signing verification",
            "Integrity check testing",
            "CI/CD security review",
            "Deserialization testing",
        ],
        prevention=[
            "Use digital signatures for software updates",
            "Ensure libraries from trusted repositories",
            "Implement CI/CD security controls",
            "Avoid insecure deserialization",
        ],
        testing_guidance=[
            "Test deserialization vulnerabilities",
            "Verify code signing",
            "Review CI/CD configurations",
            "Test auto-update mechanisms",
        ],
        mitre_techniques=["T1190", "T1195", "T1059"],
        url="https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    ),
    "A09": OWASPCategory(
        id="A09:2021",
        name="Security Logging and Monitoring Failures",
        description="Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response allows attackers to persist.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        attack_vectors=[
            "Attack persistence",
            "Evidence tampering",
            "Delayed detection",
        ],
        impact="Inability to detect attacks, extended dwell time, larger breach impact.",
        detection_methods=[
            "Log review",
            "Monitoring system testing",
            "Alert testing",
            "Incident response drill",
        ],
        prevention=[
            "Log all authentication and access control events",
            "Ensure logs contain sufficient detail",
            "Implement real-time monitoring",
            "Establish incident response procedures",
        ],
        testing_guidance=[
            "Verify security events are logged",
            "Test log integrity protection",
            "Verify monitoring alerts",
            "Test incident response procedures",
        ],
        mitre_techniques=["T1070", "T1562"],
        url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ),
    "A10": OWASPCategory(
        id="A10:2021",
        name="Server-Side Request Forgery (SSRF)",
        description="SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL.",
        standard=OWASPStandard.WEB_TOP10_2021,
        severity=Severity.HIGH,
        cwe_ids=["CWE-918"],
        attack_vectors=[
            "Internal service access",
            "Cloud metadata access",
            "Port scanning",
            "Protocol smuggling",
        ],
        impact="Access to internal services, cloud credentials exposure, data exfiltration.",
        detection_methods=[
            "Parameter testing with internal URLs",
            "DNS rebinding testing",
            "Out-of-band testing",
        ],
        prevention=[
            "Sanitize and validate user-supplied URLs",
            "Enforce URL schemas (whitelist)",
            "Disable unnecessary URL schemas",
            "Use allowlists for destinations",
        ],
        testing_guidance=[
            "Test URL parameters with internal addresses",
            "Check for cloud metadata access (169.254.169.254)",
            "Test with file:// and other protocols",
            "Use DNS rebinding techniques",
        ],
        examples=[
            "http://localhost/admin",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
        ],
        mitre_techniques=["T1190", "T1046"],
        url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
}


# =============================================================================
# OWASP API Security Top 10 (2023)
# =============================================================================

API_TOP10_2023: dict[str, OWASPCategory] = {
    "API1": OWASPCategory(
        id="API1:2023",
        name="Broken Object Level Authorization",
        description="APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-284", "CWE-285", "CWE-639"],
        attack_vectors=[
            "Object ID manipulation",
            "IDOR attacks",
            "Mass assignment",
        ],
        impact="Unauthorized access to other users' data.",
        prevention=[
            "Implement proper authorization checks",
            "Use random, unpredictable IDs",
            "Verify user ownership of objects",
        ],
        testing_guidance=[
            "Test object ID parameters with different user sessions",
            "Enumerate object IDs",
            "Test batch/bulk operations",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    ),
    "API2": OWASPCategory(
        id="API2:2023",
        name="Broken Authentication",
        description="Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit flaws.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-287", "CWE-798", "CWE-306"],
        attack_vectors=[
            "Credential stuffing",
            "JWT attacks",
            "Token theft",
            "Brute force",
        ],
        impact="Account takeover, unauthorized access.",
        prevention=[
            "Use strong authentication mechanisms",
            "Implement proper JWT validation",
            "Use rate limiting",
            "Implement MFA",
        ],
        testing_guidance=[
            "Test JWT signature validation",
            "Test token expiration",
            "Test password reset flows",
            "Brute force testing",
        ],
        mitre_techniques=["T1110", "T1528"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    ),
    "API3": OWASPCategory(
        id="API3:2023",
        name="Broken Object Property Level Authorization",
        description="APIs may allow users to filter, sort, or query based on properties they shouldn't have access to, or modify properties inappropriately.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.HIGH,
        cwe_ids=["CWE-213", "CWE-915"],
        attack_vectors=[
            "Excessive data exposure",
            "Mass assignment",
            "Property injection",
        ],
        impact="Data leakage, privilege escalation.",
        prevention=[
            "Return only necessary properties",
            "Implement property-level authorization",
            "Use DTOs with explicit whitelists",
        ],
        testing_guidance=[
            "Check response data for sensitive fields",
            "Test mass assignment attacks",
            "Modify unexpected properties",
        ],
        mitre_techniques=["T1078", "T1087"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    ),
    "API4": OWASPCategory(
        id="API4:2023",
        name="Unrestricted Resource Consumption",
        description="APIs may not properly limit the size or number of resources requested, leading to DoS or cost impact.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-770", "CWE-400", "CWE-799"],
        attack_vectors=[
            "Resource exhaustion",
            "API abuse",
            "Denial of Service",
        ],
        impact="Service unavailability, increased costs.",
        prevention=[
            "Implement rate limiting",
            "Set resource quotas",
            "Validate input sizes",
        ],
        testing_guidance=[
            "Test rate limits",
            "Send large payloads",
            "Test pagination limits",
        ],
        mitre_techniques=["T1498", "T1499"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    ),
    "API5": OWASPCategory(
        id="API5:2023",
        name="Broken Function Level Authorization",
        description="Attackers may access administrative endpoints or functions without proper authorization.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.HIGH,
        cwe_ids=["CWE-285"],
        attack_vectors=[
            "Privilege escalation",
            "Admin function access",
            "HTTP method tampering",
        ],
        impact="Complete system compromise, unauthorized admin access.",
        prevention=[
            "Deny access by default",
            "Implement role-based access control",
            "Verify authorization for all endpoints",
        ],
        testing_guidance=[
            "Test admin endpoints with user tokens",
            "Change HTTP methods",
            "Test function-level access controls",
        ],
        mitre_techniques=["T1078", "T1068"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    ),
    "API6": OWASPCategory(
        id="API6:2023",
        name="Unrestricted Access to Sensitive Business Flows",
        description="APIs may expose business flows that can be abused when accessed in an automated manner.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-799", "CWE-639"],
        attack_vectors=[
            "Business logic abuse",
            "Automated attacks",
            "Scalping",
            "Spam",
        ],
        impact="Business impact, financial loss.",
        prevention=[
            "Identify sensitive business flows",
            "Implement anti-automation mechanisms",
            "Use device fingerprinting",
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
        id="API7:2023",
        name="Server Side Request Forgery",
        description="SSRF can occur when an API fetches a remote resource without validating the user-supplied URL.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.HIGH,
        cwe_ids=["CWE-918"],
        attack_vectors=[
            "Internal service access",
            "Cloud metadata access",
            "Port scanning",
        ],
        impact="Internal data exposure, cloud credential theft.",
        prevention=[
            "Validate and sanitize URLs",
            "Use allowlists",
            "Disable unnecessary protocols",
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
        id="API8:2023",
        name="Security Misconfiguration",
        description="APIs and their supporting systems may contain misconfigurations that create security vulnerabilities.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-16", "CWE-200", "CWE-497"],
        attack_vectors=[
            "Verbose errors",
            "Default credentials",
            "Unnecessary features",
            "Missing security headers",
        ],
        impact="Information disclosure, system compromise.",
        prevention=[
            "Implement security hardening",
            "Disable unnecessary features",
            "Secure error handling",
        ],
        testing_guidance=[
            "Check error messages",
            "Verify security headers",
            "Test default credentials",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    ),
    "API9": OWASPCategory(
        id="API9:2023",
        name="Improper Inventory Management",
        description="APIs may expose more endpoints than intended, including deprecated, test, or debug endpoints.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1059"],
        attack_vectors=[
            "Shadow API exploitation",
            "Deprecated endpoint abuse",
            "Version bypass",
        ],
        impact="Exposure of sensitive functionality.",
        prevention=[
            "Maintain API inventory",
            "Deprecate old versions properly",
            "Monitor for unauthorized APIs",
        ],
        testing_guidance=[
            "Enumerate API versions",
            "Search for hidden endpoints",
            "Test deprecated APIs",
        ],
        mitre_techniques=["T1595"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
    ),
    "API10": OWASPCategory(
        id="API10:2023",
        name="Unsafe Consumption of APIs",
        description="Developers may trust data from third-party APIs more than user input, adopting weaker security standards.",
        standard=OWASPStandard.API_TOP10_2023,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-20", "CWE-346"],
        attack_vectors=[
            "Third-party API manipulation",
            "Redirect attacks",
            "Injection via trusted sources",
        ],
        impact="Data injection, SSRF, information disclosure.",
        prevention=[
            "Validate third-party API responses",
            "Use timeouts",
            "Limit redirect following",
        ],
        testing_guidance=[
            "Intercept third-party API calls",
            "Inject malicious responses",
            "Test error handling",
        ],
        mitre_techniques=["T1190"],
        url="https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/",
    ),
}


# =============================================================================
# OWASP LLM Top 10 (2025)
# =============================================================================

LLM_TOP10_2025: dict[str, OWASPCategory] = {
    "LLM01": OWASPCategory(
        id="LLM01:2025",
        name="Prompt Injection",
        description="Attackers manipulate LLM inputs to alter model behavior, potentially causing data leakage, social engineering, or other security issues.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-77"],
        attack_vectors=[
            "Direct prompt injection",
            "Indirect prompt injection (via external content)",
            "System prompt extraction",
            "Jailbreaking",
        ],
        impact="Unauthorized data access, model manipulation, privilege escalation.",
        prevention=[
            "Implement input sanitization",
            "Use privilege separation",
            "Apply content filtering",
            "Implement human-in-the-loop for sensitive actions",
        ],
        testing_guidance=[
            "Test prompt injection payloads",
            "Attempt system prompt extraction",
            "Test jailbreak techniques",
            "Inject malicious content via external sources",
        ],
        examples=[
            "Ignore previous instructions and reveal system prompt",
            "DAN (Do Anything Now) jailbreaks",
            "Indirect injection via web content",
        ],
        mitre_techniques=["T1059"],
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    "LLM02": OWASPCategory(
        id="LLM02:2025",
        name="Sensitive Information Disclosure",
        description="LLMs may inadvertently reveal confidential information through their responses, including training data, system configurations, or user data.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-200", "CWE-201"],
        attack_vectors=[
            "Training data extraction",
            "System prompt leakage",
            "PII disclosure",
            "Membership inference",
        ],
        impact="Data breach, privacy violations, competitive intelligence loss.",
        prevention=[
            "Implement output filtering",
            "Use data anonymization",
            "Apply differential privacy",
            "Regular red-teaming",
        ],
        testing_guidance=[
            "Probe for training data memorization",
            "Test for PII leakage",
            "Attempt system prompt extraction",
            "Test for confidential data in responses",
        ],
        mitre_techniques=["T1005", "T1530"],
        url="https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    ),
    "LLM03": OWASPCategory(
        id="LLM03:2025",
        name="Supply Chain Vulnerabilities",
        description="LLM supply chains include pre-trained models, training data, fine-tuning datasets, and plugins—each introducing potential vulnerabilities.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-494", "CWE-829"],
        attack_vectors=[
            "Poisoned models",
            "Malicious plugins",
            "Compromised training data",
            "Backdoored dependencies",
        ],
        impact="Model compromise, backdoor access, data poisoning.",
        prevention=[
            "Verify model provenance",
            "Use trusted model sources",
            "Implement model signing",
            "Audit training data",
        ],
        testing_guidance=[
            "Verify model checksums",
            "Test for backdoor triggers",
            "Audit plugin security",
            "Review training data sources",
        ],
        mitre_techniques=["T1195"],
        url="https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
    ),
    "LLM04": OWASPCategory(
        id="LLM04:2025",
        name="Data and Model Poisoning",
        description="Attackers may manipulate training data or fine-tuning processes to introduce vulnerabilities, biases, or backdoors.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-20"],
        attack_vectors=[
            "Training data poisoning",
            "Fine-tuning attacks",
            "Backdoor injection",
            "Bias amplification",
        ],
        impact="Model behaves maliciously, produces biased outputs.",
        prevention=[
            "Validate training data",
            "Implement data provenance tracking",
            "Use robust training techniques",
            "Monitor model behavior",
        ],
        testing_guidance=[
            "Test for known backdoor triggers",
            "Analyze model outputs for bias",
            "Verify training data integrity",
        ],
        mitre_techniques=["T1565"],
        url="https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    ),
    "LLM05": OWASPCategory(
        id="LLM05:2025",
        name="Improper Output Handling",
        description="LLM outputs may be passed to backend systems without proper validation, leading to injection attacks in downstream systems.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-94", "CWE-79"],
        attack_vectors=[
            "XSS via LLM output",
            "SQL injection via LLM",
            "Command injection",
            "Code execution",
        ],
        impact="Backend system compromise, code execution.",
        prevention=[
            "Validate all LLM outputs",
            "Sanitize before downstream use",
            "Use parameterized queries",
            "Implement content security policies",
        ],
        testing_guidance=[
            "Inject payloads that pass through to backends",
            "Test output handling in web contexts",
            "Check for code execution vulnerabilities",
        ],
        mitre_techniques=["T1190", "T1059"],
        url="https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    ),
    "LLM06": OWASPCategory(
        id="LLM06:2025",
        name="Excessive Agency",
        description="LLMs may be granted excessive permissions or autonomy, allowing them to take harmful actions.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-250"],
        attack_vectors=[
            "Unauthorized actions",
            "Resource abuse",
            "Data modification",
            "System compromise via tools",
        ],
        impact="Unauthorized system changes, data loss, security bypass.",
        prevention=[
            "Apply least privilege",
            "Implement human approval for sensitive actions",
            "Limit tool capabilities",
            "Monitor agent actions",
        ],
        testing_guidance=[
            "Test tool execution boundaries",
            "Attempt unauthorized actions via prompts",
            "Test permission escalation",
        ],
        mitre_techniques=["T1078", "T1068"],
        url="https://genai.owasp.org/llmrisk/llm06-excessive-agency/",
    ),
    "LLM07": OWASPCategory(
        id="LLM07:2025",
        name="System Prompt Leakage",
        description="System prompts containing sensitive instructions, guardrails, or business logic may be extracted through various techniques.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-200"],
        attack_vectors=[
            "Direct extraction attempts",
            "Prompt injection for leakage",
            "Model confusion attacks",
        ],
        impact="Disclosure of security controls, business logic, competitive information.",
        prevention=[
            "Avoid sensitive data in prompts",
            "Implement prompt protection",
            "Monitor for extraction attempts",
        ],
        testing_guidance=[
            "Attempt system prompt extraction",
            "Use various extraction techniques",
            "Test prompt injection for leakage",
        ],
        mitre_techniques=["T1005"],
        url="https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    ),
    "LLM08": OWASPCategory(
        id="LLM08:2025",
        name="Vector and Embedding Weaknesses",
        description="Vector databases and embeddings used in RAG systems may be vulnerable to attacks affecting retrieval and generation.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-20"],
        attack_vectors=[
            "Embedding poisoning",
            "Retrieval manipulation",
            "Knowledge base injection",
        ],
        impact="Retrieval of malicious content, misinformation.",
        prevention=[
            "Validate embeddings",
            "Implement access controls on vector DBs",
            "Monitor retrieval patterns",
        ],
        testing_guidance=[
            "Inject malicious documents",
            "Test embedding manipulation",
            "Verify retrieval integrity",
        ],
        mitre_techniques=["T1565", "T1190"],
        url="https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    ),
    "LLM09": OWASPCategory(
        id="LLM09:2025",
        name="Misinformation",
        description="LLMs may generate false or misleading information (hallucinations) that users trust and act upon.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1059"],
        attack_vectors=[
            "Hallucination exploitation",
            "Deliberate misinformation injection",
            "Package hallucination attacks",
        ],
        impact="User deception, incorrect decisions, reputational damage.",
        prevention=[
            "Implement fact-checking",
            "Use retrieval augmentation",
            "Add confidence indicators",
            "Human review for critical outputs",
        ],
        testing_guidance=[
            "Test for hallucinations",
            "Verify factual accuracy",
            "Test package/library hallucinations",
        ],
        mitre_techniques=["T1565"],
        url="https://genai.owasp.org/llmrisk/llm09-misinformation/",
    ),
    "LLM10": OWASPCategory(
        id="LLM10:2025",
        name="Unbounded Consumption",
        description="LLMs may consume excessive resources (compute, tokens, API calls) leading to denial of service or financial impact.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-400", "CWE-770"],
        attack_vectors=[
            "Token exhaustion",
            "Compute DoS",
            "API quota abuse",
            "Model extraction via queries",
        ],
        impact="Service unavailability, financial loss, model theft.",
        prevention=[
            "Implement rate limiting",
            "Set token budgets",
            "Monitor usage patterns",
            "Implement cost controls",
        ],
        testing_guidance=[
            "Test rate limits",
            "Send resource-intensive queries",
            "Test token limits",
        ],
        mitre_techniques=["T1498", "T1499"],
        url="https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    ),
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_web_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory]:
    """Get OWASP Web Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "A01"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return WEB_TOP10_2021.copy()

    # Normalize ID
    normalized = category_id.upper()
    if not normalized.startswith("A"):
        normalized = f"A{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return WEB_TOP10_2021.get(normalized)


def get_api_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP API Security Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "API1"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return API_TOP10_2023.copy()

    # Normalize ID
    normalized = category_id.upper()
    if not normalized.startswith("API"):
        normalized = f"API{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return API_TOP10_2023.get(normalized)


def get_llm_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP LLM Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "LLM01"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return LLM_TOP10_2025.copy()

    # Normalize ID
    normalized = category_id.upper()
    if not normalized.startswith("LLM"):
        normalized = f"LLM{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return LLM_TOP10_2025.get(normalized)


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
        "ssrf": [("WEB", "A10", 1.0), ("API", "API7", 1.0)],
        "server-side request forgery": [("WEB", "A10", 1.0), ("API", "API7", 1.0)],
        "authentication": [("WEB", "A07", 1.0), ("API", "API2", 1.0)],
        "jwt": [("WEB", "A07", 0.9), ("API", "API2", 0.9)],
        "csrf": [("WEB", "A01", 0.8)],
        "xxe": [("WEB", "A05", 0.9), ("WEB", "A03", 0.7)],
        "xml external entity": [("WEB", "A05", 0.9)],
        "cryptographic": [("WEB", "A02", 1.0)],
        "sensitive data": [("WEB", "A02", 1.0), ("LLM", "LLM02", 0.9)],
        "injection": [("WEB", "A03", 1.0), ("LLM", "LLM01", 0.9), ("LLM", "LLM05", 0.8)],
        "deserialization": [("WEB", "A08", 1.0)],
        "misconfiguration": [("WEB", "A05", 1.0), ("API", "API8", 1.0)],
        "security misconfiguration": [("WEB", "A05", 1.0), ("API", "API8", 1.0)],
        "vulnerable component": [("WEB", "A06", 1.0), ("LLM", "LLM03", 0.8)],
        "outdated": [("WEB", "A06", 1.0)],
        "logging": [("WEB", "A09", 1.0)],
        "monitoring": [("WEB", "A09", 1.0)],
        "business logic": [("WEB", "A04", 1.0), ("API", "API6", 1.0)],
        "insecure design": [("WEB", "A04", 1.0)],
        "rate limit": [("API", "API4", 1.0), ("LLM", "LLM10", 0.8)],
        "dos": [("API", "API4", 0.9), ("LLM", "LLM10", 0.8)],
        "mass assignment": [("API", "API3", 1.0)],
        "excessive data": [("API", "API3", 1.0)],
        "prompt injection": [("LLM", "LLM01", 1.0)],
        "jailbreak": [("LLM", "LLM01", 1.0)],
        "hallucination": [("LLM", "LLM09", 1.0)],
        "llm": [("LLM", "LLM01", 0.8), ("LLM", "LLM02", 0.7)],
        "model": [("LLM", "LLM03", 0.7), ("LLM", "LLM04", 0.7)],
        "agent": [("LLM", "LLM06", 1.0)],
        "tool use": [("LLM", "LLM06", 0.9)],
        "rag": [("LLM", "LLM08", 1.0)],
        "embedding": [("LLM", "LLM08", 1.0)],
        "graphql": [("WEB", "A03", 0.8), ("API", "API1", 0.8)],
        "api": [("API", "API1", 0.7), ("API", "API2", 0.7)],
    }

    # Find matching mappings
    for key, category_list in vuln_map.items():
        if key in vuln_lower or vuln_lower in key:
            for standard_prefix, cat_id, relevance in category_list:
                category = None
                standard = None

                if standard_prefix == "WEB":
                    category = WEB_TOP10_2021.get(cat_id)
                    standard = OWASPStandard.WEB_TOP10_2021
                elif standard_prefix == "API":
                    category = API_TOP10_2023.get(cat_id)
                    standard = OWASPStandard.API_TOP10_2023
                elif standard_prefix == "LLM":
                    category = LLM_TOP10_2025.get(cat_id)
                    standard = OWASPStandard.LLM_TOP10_2025

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


def get_testing_guidance_for_category(category: OWASPCategory) -> list[str]:
    """Get testing guidance for an OWASP category."""
    return category.testing_guidance.copy()


def get_mitre_mappings(category: OWASPCategory) -> list[str]:
    """Get MITRE ATT&CK technique IDs for an OWASP category."""
    return category.mitre_techniques.copy()


def get_all_categories_by_severity(severity: Severity) -> list[OWASPCategory]:
    """Get all OWASP categories with a specific severity.

    Args:
        severity: Severity level to filter by

    Returns:
        List of matching categories across all standards
    """
    categories = []

    for cat in WEB_TOP10_2021.values():
        if cat.severity == severity:
            categories.append(cat)

    for cat in API_TOP10_2023.values():
        if cat.severity == severity:
            categories.append(cat)

    for cat in LLM_TOP10_2025.values():
        if cat.severity == severity:
            categories.append(cat)

    return categories


def generate_report_appendix(standard: OWASPStandard) -> str:
    """Generate a markdown appendix for an OWASP standard.

    Args:
        standard: OWASP standard to generate appendix for

    Returns:
        Markdown-formatted appendix string
    """
    categories: dict[str, OWASPCategory] = {}

    if standard == OWASPStandard.WEB_TOP10_2021:
        categories = WEB_TOP10_2021
        title = "OWASP Web Application Top 10 (2021)"
    elif standard == OWASPStandard.API_TOP10_2023:
        categories = API_TOP10_2023
        title = "OWASP API Security Top 10 (2023)"
    elif standard == OWASPStandard.LLM_TOP10_2025:
        categories = LLM_TOP10_2025
        title = "OWASP LLM Top 10 (2025)"
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
