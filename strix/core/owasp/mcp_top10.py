"""OWASP MCP (Model Context Protocol) Top 10 (2025).

Reference for MCP-specific security risks and vulnerabilities.
MCP enables LLMs to interact with external tools, data sources, and services.
"""

from __future__ import annotations

from .base import OWASPCategory, OWASPStandard, Severity

MCP_TOP10_2025: dict[str, OWASPCategory] = {
    "MCP01": OWASPCategory(
        id="MCP01:2025",
        name="Tool Injection",
        description="Attackers inject malicious tool definitions or manipulate tool invocations to execute unauthorized operations through the MCP server.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-77", "CWE-94"],
        attack_vectors=[
            "Malicious tool registration",
            "Tool definition tampering",
            "Parameter injection in tool calls",
            "Tool schema manipulation",
            "Shadow tool injection",
        ],
        impact="Arbitrary code execution, data exfiltration, system compromise.",
        prevention=[
            "Validate tool definitions against allowlist",
            "Implement tool signature verification",
            "Sanitize all tool parameters",
            "Use strict JSON schema validation",
            "Audit tool registrations",
        ],
        testing_guidance=[
            "Attempt to register malicious tools",
            "Inject payloads in tool parameters",
            "Test tool schema validation",
            "Check for tool definition tampering",
        ],
        mitre_techniques=["T1059", "T1190"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP02": OWASPCategory(
        id="MCP02:2025",
        name="Resource Access Control Bypass",
        description="Inadequate access controls allowing unauthorized access to MCP resources, including files, databases, and external services.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-284", "CWE-285", "CWE-862"],
        attack_vectors=[
            "Resource URI manipulation",
            "Path traversal in resources",
            "Unauthorized resource enumeration",
            "Cross-tenant resource access",
            "Capability escalation",
        ],
        impact="Unauthorized data access, file system traversal, data breach.",
        prevention=[
            "Implement strict resource URI validation",
            "Use capability-based access control",
            "Validate resource paths against allowlist",
            "Implement per-resource authorization",
            "Audit resource access patterns",
        ],
        testing_guidance=[
            "Test resource URI manipulation",
            "Attempt path traversal attacks",
            "Enumerate accessible resources",
            "Test cross-session resource access",
        ],
        mitre_techniques=["T1078", "T1083"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP03": OWASPCategory(
        id="MCP03:2025",
        name="Prompt Leakage via Tools",
        description="Tools inadvertently exposing system prompts, context, or sensitive information through their responses or error messages.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-200", "CWE-209", "CWE-497"],
        attack_vectors=[
            "Error message information disclosure",
            "Tool response data leakage",
            "Context extraction through tools",
            "Debug information exposure",
            "Verbose logging exploitation",
        ],
        impact="System prompt disclosure, security control exposure, attack surface mapping.",
        prevention=[
            "Sanitize tool responses",
            "Implement secure error handling",
            "Remove debug information in production",
            "Filter sensitive data from tool outputs",
            "Use structured error responses",
        ],
        testing_guidance=[
            "Trigger error conditions in tools",
            "Analyze tool responses for leakage",
            "Test with invalid inputs",
            "Check logs for sensitive data",
        ],
        mitre_techniques=["T1005", "T1592"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP04": OWASPCategory(
        id="MCP04:2025",
        name="Insecure Transport",
        description="MCP communications over insecure channels allowing interception, tampering, or replay of messages.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-319", "CWE-294", "CWE-523"],
        attack_vectors=[
            "Man-in-the-middle attacks",
            "Message interception",
            "Replay attacks",
            "Session hijacking",
            "Downgrade attacks",
        ],
        impact="Data interception, credential theft, session compromise.",
        prevention=[
            "Use TLS 1.3 for all transport",
            "Implement message signing",
            "Use secure WebSocket (wss://)",
            "Implement replay protection",
            "Certificate pinning for known servers",
        ],
        testing_guidance=[
            "Test for unencrypted transport",
            "Attempt message replay",
            "Check certificate validation",
            "Test for downgrade vulnerabilities",
        ],
        mitre_techniques=["T1040", "T1557"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP05": OWASPCategory(
        id="MCP05:2025",
        name="Server-Side Request Forgery via Tools",
        description="Tools that make network requests can be exploited to access internal services or exfiltrate data.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-918"],
        attack_vectors=[
            "Internal service access via tools",
            "Cloud metadata exploitation",
            "DNS rebinding through tools",
            "Protocol smuggling",
            "Data exfiltration channels",
        ],
        impact="Internal network access, credential theft, data exfiltration.",
        prevention=[
            "Allowlist external URLs for tools",
            "Block internal IP ranges",
            "Implement egress filtering",
            "Disable unnecessary protocols",
            "Monitor outbound connections",
        ],
        testing_guidance=[
            "Test tools with internal URLs",
            "Check cloud metadata access",
            "Test DNS rebinding",
            "Verify URL allowlist enforcement",
        ],
        mitre_techniques=["T1190", "T1046"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP06": OWASPCategory(
        id="MCP06:2025",
        name="Insecure Tool Execution",
        description="Tools executing with excessive privileges or without proper sandboxing, enabling system compromise.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-250", "CWE-269", "CWE-732"],
        attack_vectors=[
            "Privilege escalation via tools",
            "Container escape",
            "File system access abuse",
            "Process injection",
            "Environment variable manipulation",
        ],
        impact="System compromise, privilege escalation, data destruction.",
        prevention=[
            "Run tools with least privilege",
            "Implement proper sandboxing",
            "Use container isolation",
            "Limit file system access",
            "Restrict environment variables",
        ],
        testing_guidance=[
            "Test tool privilege levels",
            "Attempt sandbox escape",
            "Test file system boundaries",
            "Check process isolation",
        ],
        mitre_techniques=["T1068", "T1611"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP07": OWASPCategory(
        id="MCP07:2025",
        name="Malicious Server Impersonation",
        description="Attackers impersonating legitimate MCP servers to intercept communications or inject malicious responses.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-295", "CWE-346", "CWE-923"],
        attack_vectors=[
            "Server impersonation",
            "DNS spoofing",
            "Certificate forgery",
            "Rogue server deployment",
            "BGP hijacking",
        ],
        impact="Credential theft, data interception, malicious tool injection.",
        prevention=[
            "Implement server authentication",
            "Use certificate pinning",
            "Validate server identity",
            "Monitor for rogue servers",
            "Use DNSSEC",
        ],
        testing_guidance=[
            "Test server certificate validation",
            "Attempt server impersonation",
            "Check DNS resolution security",
            "Test with invalid certificates",
        ],
        mitre_techniques=["T1557", "T1584"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP08": OWASPCategory(
        id="MCP08:2025",
        name="Insufficient Input Validation",
        description="Inadequate validation of inputs to MCP servers and tools, enabling injection and manipulation attacks.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-20", "CWE-79", "CWE-89"],
        attack_vectors=[
            "JSON injection",
            "Schema bypass",
            "Type confusion",
            "Buffer overflow via large inputs",
            "Unicode/encoding attacks",
        ],
        impact="Injection attacks, denial of service, unexpected behavior.",
        prevention=[
            "Implement strict JSON schema validation",
            "Validate all input types",
            "Set input size limits",
            "Normalize Unicode input",
            "Use safe parsing libraries",
        ],
        testing_guidance=[
            "Test with malformed JSON",
            "Send oversized inputs",
            "Test type coercion",
            "Try encoding bypass techniques",
        ],
        mitre_techniques=["T1190", "T1059"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP09": OWASPCategory(
        id="MCP09:2025",
        name="Denial of Service",
        description="Attacks exhausting MCP server resources through malicious requests, recursive calls, or resource-intensive operations.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-400", "CWE-770", "CWE-835"],
        attack_vectors=[
            "Resource exhaustion",
            "Recursive tool calls",
            "Large payload attacks",
            "Connection exhaustion",
            "Slowloris-style attacks",
        ],
        impact="Service unavailability, resource exhaustion, cascading failures.",
        prevention=[
            "Implement rate limiting",
            "Set request timeouts",
            "Limit concurrent connections",
            "Implement circuit breakers",
            "Monitor resource usage",
        ],
        testing_guidance=[
            "Test rate limits",
            "Send recursive tool calls",
            "Test with large payloads",
            "Attempt connection exhaustion",
        ],
        mitre_techniques=["T1498", "T1499"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
    "MCP10": OWASPCategory(
        id="MCP10:2025",
        name="Logging and Monitoring Failures",
        description="Insufficient logging of MCP operations, tool invocations, and security events, hindering incident detection and response.",
        standard=OWASPStandard.MCP_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-117", "CWE-223", "CWE-778"],
        attack_vectors=[
            "Attack obfuscation",
            "Log injection",
            "Evidence tampering",
            "Blind exploitation",
            "Audit bypass",
        ],
        impact="Inability to detect attacks, delayed incident response, compliance failures.",
        prevention=[
            "Log all tool invocations",
            "Implement structured logging",
            "Protect log integrity",
            "Real-time alerting",
            "Audit sensitive operations",
        ],
        testing_guidance=[
            "Verify security event logging",
            "Test log injection",
            "Check log completeness",
            "Verify alert triggers",
        ],
        mitre_techniques=["T1070", "T1562"],
        url="https://spec.modelcontextprotocol.io/specification/security/",
    ),
}


def get_mcp_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP MCP Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "MCP01"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return MCP_TOP10_2025.copy()

    normalized = category_id.upper()
    if not normalized.startswith("MCP"):
        normalized = f"MCP{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return MCP_TOP10_2025.get(normalized)
