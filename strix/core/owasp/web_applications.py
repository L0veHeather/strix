"""OWASP Web Application Security Top 10 (2025).

Reference for web application security risks and vulnerabilities.
"""

from __future__ import annotations

from .base import OWASPCategory, OWASPStandard, Severity

WEB_TOP10_2025: dict[str, OWASPCategory] = {
    "A01": OWASPCategory(
        id="A01:2025",
        name="Broken Access Control",
        description="Access control enforces policy such that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-200", "CWE-201", "CWE-352", "CWE-566", "CWE-639", "CWE-862", "CWE-863"],
        attack_vectors=[
            "URL/API parameter manipulation",
            "IDOR (Insecure Direct Object Reference)",
            "Privilege escalation",
            "JWT/session token manipulation",
            "CORS misconfiguration",
            "Force browsing to unauthorized pages",
        ],
        impact="Unauthorized access to functionality and data, including other users' accounts, sensitive files, or admin functions.",
        detection_methods=[
            "Manual testing with different user roles",
            "Automated access control testing",
            "Code review of authorization logic",
            "Penetration testing",
        ],
        prevention=[
            "Implement access control once and reuse across application",
            "Deny by default except for public resources",
            "Implement proper session management",
            "Rate limit API and controller access",
            "Log and alert on access control failures",
        ],
        testing_guidance=[
            "Test horizontal privilege escalation",
            "Test vertical privilege escalation",
            "Modify JWT tokens and session identifiers",
            "Test API endpoints without authentication",
            "Check CORS headers and policies",
        ],
        mitre_techniques=["T1078", "T1190"],
        url="https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    ),
    "A02": OWASPCategory(
        id="A02:2025",
        name="Cryptographic Failures",
        description="Failures related to cryptography leading to exposure of sensitive data. Includes weak algorithms, improper key management, and insufficient encryption.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-259", "CWE-327", "CWE-331", "CWE-328", "CWE-760"],
        attack_vectors=[
            "Man-in-the-middle attacks",
            "Weak cryptography exploitation",
            "Key extraction from code/config",
            "Padding oracle attacks",
            "Downgrade attacks",
        ],
        impact="Exposure of passwords, credit cards, health records, personal data, and business secrets.",
        prevention=[
            "Classify data and identify sensitive data",
            "Use strong algorithms (AES-256-GCM, RSA-2048+, Ed25519)",
            "Implement proper key management",
            "Use TLS 1.3 for data in transit",
            "Disable caching for sensitive data",
        ],
        testing_guidance=[
            "Test SSL/TLS configuration",
            "Check for weak cipher suites",
            "Verify certificate validation",
            "Test for hardcoded secrets",
            "Check password hashing (Argon2id, bcrypt)",
        ],
        mitre_techniques=["T1552", "T1555", "T1040"],
        url="https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    ),
    "A03": OWASPCategory(
        id="A03:2025",
        name="Injection",
        description="Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Includes SQL, NoSQL, OS, LDAP, and expression language injection.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-79", "CWE-89", "CWE-94", "CWE-917"],
        attack_vectors=[
            "SQL/NoSQL injection",
            "OS command injection",
            "LDAP/XPath injection",
            "Expression Language injection",
            "Cross-Site Scripting (XSS)",
            "Template injection",
        ],
        impact="Data loss, corruption, disclosure, denial of access, or complete host takeover.",
        prevention=[
            "Use parameterized queries/prepared statements",
            "Use ORM frameworks properly",
            "Input validation (allowlist approach)",
            "Escape special characters contextually",
            "Use LIMIT and SQL controls",
        ],
        testing_guidance=[
            "Test all input fields for injection",
            "Use time-based and error-based payloads",
            "Test API parameters and headers",
            "Check for stored injection points",
            "Test GraphQL for injection",
        ],
        examples=["' OR '1'='1", "'; DROP TABLE users;--", "${7*7}", "{{constructor.constructor('return this')()}}"],
        mitre_techniques=["T1190", "T1059"],
        url="https://owasp.org/Top10/A03_2021-Injection/",
    ),
    "A04": OWASPCategory(
        id="A04:2025",
        name="Insecure Design",
        description="Risks from missing or ineffective security controls due to design flaws. Insecure design cannot be fixed by implementation alone.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-209", "CWE-256", "CWE-501", "CWE-522"],
        attack_vectors=[
            "Business logic abuse",
            "Race conditions (TOCTOU)",
            "Insufficient anti-automation",
            "Missing security controls",
            "Trust boundary violations",
        ],
        impact="Varies based on flaw severity; can lead to complete system compromise.",
        prevention=[
            "Establish secure development lifecycle (SDL)",
            "Use threat modeling (STRIDE, PASTA)",
            "Integrate security patterns and reference architectures",
            "Unit and integration tests for security controls",
        ],
        testing_guidance=[
            "Test business logic flows",
            "Identify race conditions",
            "Test multi-step processes for bypass",
            "Review threat models",
        ],
        mitre_techniques=["T1190"],
        url="https://owasp.org/Top10/A04_2021-Insecure_Design/",
    ),
    "A05": OWASPCategory(
        id="A05:2025",
        name="Security Misconfiguration",
        description="Security misconfiguration from insecure defaults, incomplete configurations, misconfigured headers, or verbose error messages.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-16", "CWE-611", "CWE-1004"],
        attack_vectors=[
            "Default credentials",
            "Unnecessary features enabled",
            "Verbose error messages",
            "Missing security headers",
            "Directory listing enabled",
            "Cloud storage misconfiguration",
        ],
        impact="Unauthorized access to system data or functionality, potentially complete compromise.",
        prevention=[
            "Implement hardening procedures",
            "Remove unused features/frameworks",
            "Review configurations regularly",
            "Implement security headers",
            "Automated configuration verification",
        ],
        testing_guidance=[
            "Check for default credentials",
            "Test security headers",
            "Verify error handling",
            "Check cloud configurations",
            "Review server banners",
        ],
        mitre_techniques=["T1190", "T1078"],
        url="https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    ),
    "A06": OWASPCategory(
        id="A06:2025",
        name="Vulnerable and Outdated Components",
        description="Using components with known vulnerabilities or unsupported/outdated software that can undermine application defenses.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1104"],
        attack_vectors=[
            "Known CVE exploitation",
            "Supply chain attacks",
            "Dependency confusion",
            "Typosquatting",
        ],
        impact="Ranges from minimal to complete system compromise depending on vulnerability.",
        prevention=[
            "Maintain component inventory (SBOM)",
            "Monitor vulnerabilities continuously",
            "Update components regularly",
            "Remove unused dependencies",
            "Use only trusted sources",
        ],
        testing_guidance=[
            "Run SCA/dependency scans",
            "Check versions against CVE databases",
            "Verify SBOM accuracy",
            "Test known CVEs for exploitability",
        ],
        mitre_techniques=["T1190", "T1195"],
        url="https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    ),
    "A07": OWASPCategory(
        id="A07:2025",
        name="Identification and Authentication Failures",
        description="Weaknesses in user identity confirmation, authentication, and session management leading to authentication-related attacks.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-287", "CWE-288", "CWE-306", "CWE-798"],
        attack_vectors=[
            "Credential stuffing",
            "Brute force attacks",
            "Session hijacking/fixation",
            "Weak password recovery",
            "MFA bypass",
        ],
        impact="Account takeover, unauthorized access, identity theft.",
        prevention=[
            "Implement MFA",
            "Use strong password policies",
            "Implement account lockout",
            "Use secure session management",
            "Rotate session IDs after login",
        ],
        testing_guidance=[
            "Test password complexity",
            "Test account lockout",
            "Test session timeout/invalidation",
            "Test MFA bypass techniques",
            "Check credential exposure in responses",
        ],
        mitre_techniques=["T1110", "T1078", "T1539"],
        url="https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ),
    "A08": OWASPCategory(
        id="A08:2025",
        name="Software and Data Integrity Failures",
        description="Code and infrastructure vulnerabilities that don't protect against integrity violations, including insecure deserialization and CI/CD attacks.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502"],
        attack_vectors=[
            "Insecure deserialization",
            "CI/CD pipeline attacks",
            "Auto-update mechanism abuse",
            "Unsigned code execution",
            "Dependency tampering",
        ],
        impact="Remote code execution, data manipulation, supply chain compromise.",
        prevention=[
            "Use digital signatures for updates",
            "Use libraries from trusted repositories",
            "Implement CI/CD security controls",
            "Avoid insecure deserialization",
            "Use integrity verification",
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
        id="A09:2025",
        name="Security Logging and Monitoring Failures",
        description="Insufficient logging, detection, monitoring, and active response allows attackers to persist and pivot undetected.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        attack_vectors=[
            "Attack persistence",
            "Evidence tampering",
            "Delayed detection",
            "Alert fatigue exploitation",
        ],
        impact="Inability to detect attacks, extended dwell time, larger breach impact.",
        prevention=[
            "Log authentication and access control events",
            "Ensure logs contain sufficient context",
            "Implement real-time monitoring/alerting",
            "Establish incident response procedures",
            "Protect log integrity",
        ],
        testing_guidance=[
            "Verify security events are logged",
            "Test log integrity protection",
            "Verify monitoring alerts",
            "Test incident response",
        ],
        mitre_techniques=["T1070", "T1562"],
        url="https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    ),
    "A10": OWASPCategory(
        id="A10:2025",
        name="Server-Side Request Forgery (SSRF)",
        description="SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to reach internal services.",
        standard=OWASPStandard.WEB_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-918"],
        attack_vectors=[
            "Internal service access",
            "Cloud metadata access (169.254.169.254)",
            "Internal port scanning",
            "Protocol smuggling",
            "DNS rebinding",
        ],
        impact="Access to internal services, cloud credentials exposure, data exfiltration.",
        prevention=[
            "Validate and sanitize user URLs",
            "Enforce URL schemas (allowlist)",
            "Disable unnecessary URL schemas",
            "Use allowlists for destinations",
            "Segment internal networks",
        ],
        testing_guidance=[
            "Test URL params with internal addresses",
            "Check cloud metadata access",
            "Test file:// and other protocols",
            "Use DNS rebinding techniques",
        ],
        examples=["http://localhost/admin", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"],
        mitre_techniques=["T1190", "T1046"],
        url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    ),
}


def get_web_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP Web Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "A01"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return WEB_TOP10_2025.copy()

    normalized = category_id.upper()
    if not normalized.startswith("A"):
        normalized = f"A{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return WEB_TOP10_2025.get(normalized)
