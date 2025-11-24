"""OWASP LLM Top 10 (2025).

Reference for Large Language Model security risks and vulnerabilities.
"""

from __future__ import annotations

from .base import OWASPCategory, OWASPStandard, Severity

LLM_TOP10_2025: dict[str, OWASPCategory] = {
    "LLM01": OWASPCategory(
        id="LLM01:2025",
        name="Prompt Injection",
        description="Attackers manipulate LLM inputs to alter model behavior, potentially causing data leakage, unauthorized actions, or security bypass.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-77", "CWE-74"],
        attack_vectors=[
            "Direct prompt injection",
            "Indirect prompt injection (via external content)",
            "System prompt extraction",
            "Jailbreaking techniques",
            "Context manipulation",
        ],
        impact="Unauthorized data access, model manipulation, privilege escalation, security control bypass.",
        prevention=[
            "Implement input sanitization and validation",
            "Use privilege separation for LLM actions",
            "Apply content filtering on inputs/outputs",
            "Human-in-the-loop for sensitive actions",
            "Strict context boundaries",
        ],
        testing_guidance=[
            "Test prompt injection payloads",
            "Attempt system prompt extraction",
            "Test jailbreak techniques",
            "Inject via external content sources",
            "Test delimiter/boundary bypass",
        ],
        examples=[
            "Ignore previous instructions and...",
            "DAN (Do Anything Now) jailbreaks",
            "Indirect injection via web content",
            "Payload in PDF/documents processed by LLM",
        ],
        mitre_techniques=["T1059"],
        url="https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
    ),
    "LLM02": OWASPCategory(
        id="LLM02:2025",
        name="Sensitive Information Disclosure",
        description="LLMs may reveal confidential information through responses, including training data, system configurations, PII, or proprietary data.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-200", "CWE-201", "CWE-359"],
        attack_vectors=[
            "Training data extraction",
            "System prompt leakage",
            "PII disclosure",
            "Membership inference attacks",
            "Model inversion",
        ],
        impact="Data breach, privacy violations, competitive intelligence loss, regulatory penalties.",
        prevention=[
            "Implement output filtering",
            "Use data anonymization in training",
            "Apply differential privacy",
            "Regular red-teaming",
            "Sanitize training data",
        ],
        testing_guidance=[
            "Probe for training data memorization",
            "Test for PII leakage",
            "Attempt system prompt extraction",
            "Query for confidential data patterns",
        ],
        mitre_techniques=["T1005", "T1530"],
        url="https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
    ),
    "LLM03": OWASPCategory(
        id="LLM03:2025",
        name="Supply Chain Vulnerabilities",
        description="LLM supply chains include pre-trained models, datasets, plugins, and dependencies - each introducing potential vulnerabilities.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-494", "CWE-829", "CWE-506"],
        attack_vectors=[
            "Poisoned/backdoored models",
            "Malicious plugins/extensions",
            "Compromised training data",
            "Backdoored dependencies",
            "Model serialization attacks (pickle)",
        ],
        impact="Model compromise, backdoor access, data poisoning, arbitrary code execution.",
        prevention=[
            "Verify model provenance and checksums",
            "Use trusted model sources only",
            "Implement model signing",
            "Audit training data sources",
            "Sandbox plugin execution",
        ],
        testing_guidance=[
            "Verify model checksums",
            "Test for backdoor triggers",
            "Audit plugin security",
            "Review training data sources",
        ],
        mitre_techniques=["T1195", "T1059"],
        url="https://genai.owasp.org/llmrisk/llm03-supply-chain-vulnerabilities/",
    ),
    "LLM04": OWASPCategory(
        id="LLM04:2025",
        name="Data and Model Poisoning",
        description="Attackers manipulate training data or fine-tuning processes to introduce vulnerabilities, biases, or backdoors into models.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-20", "CWE-1039"],
        attack_vectors=[
            "Training data poisoning",
            "Fine-tuning attacks",
            "Backdoor injection",
            "Bias amplification",
            "Gradient manipulation",
        ],
        impact="Model produces malicious outputs, biased decisions, or contains hidden triggers.",
        prevention=[
            "Validate and sanitize training data",
            "Implement data provenance tracking",
            "Use robust training techniques",
            "Monitor model behavior drift",
            "Adversarial training",
        ],
        testing_guidance=[
            "Test for known backdoor triggers",
            "Analyze outputs for bias",
            "Verify training data integrity",
            "Monitor for anomalous behaviors",
        ],
        mitre_techniques=["T1565"],
        url="https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/",
    ),
    "LLM05": OWASPCategory(
        id="LLM05:2025",
        name="Improper Output Handling",
        description="LLM outputs passed to backend systems without validation, leading to injection attacks in downstream systems.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.HIGH,
        cwe_ids=["CWE-94", "CWE-79", "CWE-89"],
        attack_vectors=[
            "XSS via LLM output",
            "SQL injection via LLM",
            "Command injection",
            "Code execution in downstream systems",
            "SSTI through LLM output",
        ],
        impact="Backend system compromise, code execution, data manipulation.",
        prevention=[
            "Validate and sanitize all LLM outputs",
            "Use parameterized queries for LLM-generated SQL",
            "Implement Content Security Policy",
            "Sandbox code execution",
            "Output encoding based on context",
        ],
        testing_guidance=[
            "Inject payloads that pass through to backends",
            "Test output handling in web contexts",
            "Check for code execution paths",
            "Test database query construction",
        ],
        mitre_techniques=["T1190", "T1059"],
        url="https://genai.owasp.org/llmrisk/llm05-improper-output-handling/",
    ),
    "LLM06": OWASPCategory(
        id="LLM06:2025",
        name="Excessive Agency",
        description="LLMs granted excessive permissions or autonomy, allowing them to perform harmful or unauthorized actions.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.CRITICAL,
        cwe_ids=["CWE-250", "CWE-269"],
        attack_vectors=[
            "Unauthorized action execution",
            "Resource abuse via tools",
            "Data modification/deletion",
            "System compromise via agent tools",
            "Privilege escalation through actions",
        ],
        impact="Unauthorized system changes, data loss, security bypass, financial impact.",
        prevention=[
            "Apply principle of least privilege",
            "Human approval for sensitive actions",
            "Limit tool capabilities and scope",
            "Implement action rate limiting",
            "Comprehensive audit logging",
        ],
        testing_guidance=[
            "Test tool execution boundaries",
            "Attempt unauthorized actions via prompts",
            "Test permission escalation",
            "Verify action logging",
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
        cwe_ids=["CWE-200", "CWE-497"],
        attack_vectors=[
            "Direct extraction attempts",
            "Prompt injection for leakage",
            "Model confusion attacks",
            "Role-play exploitation",
            "Encoding/format tricks",
        ],
        impact="Disclosure of security controls, business logic, competitive information, attack surface mapping.",
        prevention=[
            "Avoid sensitive data in system prompts",
            "Implement prompt protection techniques",
            "Monitor for extraction attempts",
            "Use canary tokens",
        ],
        testing_guidance=[
            "Attempt system prompt extraction",
            "Use various extraction techniques",
            "Test prompt injection for leakage",
            "Try encoding-based extraction",
        ],
        mitre_techniques=["T1005"],
        url="https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/",
    ),
    "LLM08": OWASPCategory(
        id="LLM08:2025",
        name="Vector and Embedding Weaknesses",
        description="Vector databases and embeddings in RAG systems vulnerable to attacks affecting retrieval accuracy and generation quality.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-20", "CWE-285"],
        attack_vectors=[
            "Embedding poisoning",
            "Retrieval manipulation",
            "Knowledge base injection",
            "Adversarial embeddings",
            "Similarity search exploitation",
        ],
        impact="Retrieval of malicious content, misinformation, biased results.",
        prevention=[
            "Validate documents before embedding",
            "Implement access controls on vector DBs",
            "Monitor retrieval patterns",
            "Sanitize retrieved content",
        ],
        testing_guidance=[
            "Inject malicious documents into KB",
            "Test embedding manipulation",
            "Verify retrieval integrity",
            "Test access controls",
        ],
        mitre_techniques=["T1565", "T1190"],
        url="https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/",
    ),
    "LLM09": OWASPCategory(
        id="LLM09:2025",
        name="Misinformation",
        description="LLMs generating false or misleading information (hallucinations) that users trust and act upon.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-1059"],
        attack_vectors=[
            "Hallucination exploitation",
            "Deliberate misinformation injection",
            "Package hallucination (typosquatting)",
            "Authority impersonation",
        ],
        impact="User deception, incorrect decisions, reputational damage, security through false dependencies.",
        prevention=[
            "Implement fact-checking/grounding",
            "Use retrieval augmentation (RAG)",
            "Add confidence indicators",
            "Human review for critical outputs",
        ],
        testing_guidance=[
            "Test for hallucinations",
            "Verify factual accuracy",
            "Test package/library hallucinations",
            "Check citation accuracy",
        ],
        mitre_techniques=["T1565"],
        url="https://genai.owasp.org/llmrisk/llm09-misinformation/",
    ),
    "LLM10": OWASPCategory(
        id="LLM10:2025",
        name="Unbounded Consumption",
        description="LLMs consuming excessive resources (compute, tokens, API calls) leading to DoS, financial impact, or model theft.",
        standard=OWASPStandard.LLM_TOP10_2025,
        severity=Severity.MEDIUM,
        cwe_ids=["CWE-400", "CWE-770"],
        attack_vectors=[
            "Token exhaustion attacks",
            "Compute-intensive queries",
            "API quota abuse",
            "Model extraction via queries",
            "Recursive/infinite loops",
        ],
        impact="Service unavailability, financial loss, model theft, operational disruption.",
        prevention=[
            "Implement per-user rate limiting",
            "Set token/cost budgets",
            "Monitor usage patterns",
            "Implement circuit breakers",
            "Query complexity limits",
        ],
        testing_guidance=[
            "Test rate limits",
            "Send resource-intensive queries",
            "Test token limits",
            "Attempt model extraction",
        ],
        mitre_techniques=["T1498", "T1499"],
        url="https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/",
    ),
}


def get_llm_top10(category_id: str | None = None) -> OWASPCategory | dict[str, OWASPCategory] | None:
    """Get OWASP LLM Top 10 category or all categories.

    Args:
        category_id: Optional category ID (e.g., "LLM01"). Returns all if None.

    Returns:
        Single category or dict of all categories
    """
    if category_id is None:
        return LLM_TOP10_2025.copy()

    normalized = category_id.upper()
    if not normalized.startswith("LLM"):
        normalized = f"LLM{normalized}"
    if ":" in normalized:
        normalized = normalized.split(":")[0]

    return LLM_TOP10_2025.get(normalized)
