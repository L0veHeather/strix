"""Adaptive Scan Planner Module.

Generates dynamic, context-aware vulnerability scanning plans based on
Target Complexity Index (TCI) and target fingerprint data. Transforms
static checklist execution into tactical, prioritized scanning.

Key Features:
- Maps TCI scores to structured scan plans
- Generates priority-ordered testing steps
- Selects appropriate prompt modules per target
- Supports safe_mode and resource quotas
- Integrates with ExecutionPipeline for deterministic stages

Usage:
    from strix.agents.planner import ScanPlanner
    from strix.core.tci import compute_tci, TargetFingerprint

    fingerprint = TargetFingerprint(
        open_ports=[80, 443],
        technologies=["django", "postgresql"],
        auth_types=["jwt"],
    )

    tci_result = compute_tci(fingerprint)

    planner = ScanPlanner()
    plan = planner.generate_plan(
        target="https://api.example.local",
        fingerprint=fingerprint,
        tci_result=tci_result,
    )

    print(plan.to_json())
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from strix.core.tci import TCIResult, TargetFingerprint

logger = logging.getLogger(__name__)


class PlanPriority(str, Enum):
    """Priority level for scan steps."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    OPTIONAL = "optional"


class ScanPhase(str, Enum):
    """Phase of the scanning process."""

    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"


class StepStatus(str, Enum):
    """Status of a scan step."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class TTPReference:
    """MITRE ATT&CK TTP reference for a scan step."""

    technique_id: str  # e.g., "T1190", "T1059.001"
    technique_name: str
    tactic: str
    description: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "description": self.description,
            "url": self.url,
        }


@dataclass
class OWASPReference:
    """OWASP category reference for a scan step."""

    category_id: str  # e.g., "A01:2025", "API1:2025", "LLM01:2025", "MCP01:2025"
    category_name: str
    standard: str  # "Web Top 10", "API Top 10", "LLM Top 10", "MCP Top 10"
    severity: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "standard": self.standard,
            "severity": self.severity,
            "url": self.url,
        }


@dataclass
class ScanStep:
    """A single step in the scan plan with threat intelligence tagging."""

    step_id: str
    step_number: int
    module: str
    description: str
    priority: PlanPriority
    phase: ScanPhase
    safe_mode: bool = True
    timeout_seconds: int = 300
    max_retries: int = 1
    dependencies: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    status: StepStatus = StepStatus.PENDING
    result: dict[str, Any] | None = None
    notes: str = ""
    quota: int = 0  # Max iterations/requests for this step
    # Threat intelligence tags
    mitre_ttps: list[TTPReference] = field(default_factory=list)
    owasp_refs: list[OWASPReference] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "step": self.step_number,
            "step_id": self.step_id,
            "module": self.module,
            "description": self.description,
            "priority": self.priority.value,
            "phase": self.phase.value,
            "safe_mode": self.safe_mode,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "dependencies": self.dependencies,
            "parameters": self.parameters,
            "status": self.status.value,
            "result": self.result,
            "notes": self.notes,
            "quota": self.quota,
            "threat_intel": {
                "mitre_attack": [ttp.to_dict() for ttp in self.mitre_ttps],
                "owasp": [ref.to_dict() for ref in self.owasp_refs],
                "cwe_ids": self.cwe_ids,
            },
        }


@dataclass
class ResourceQuota:
    """Resource quotas for scan execution."""

    max_requests: int = 1000
    max_duration_minutes: int = 60
    max_parallel_tests: int = 5
    max_payload_size_kb: int = 100
    rate_limit_rps: float = 10.0  # Requests per second
    max_retries_per_step: int = 2


class ScanPlanConfig(BaseModel):
    """Configuration for scan plan generation."""

    # Plan behavior
    enable_safe_mode: bool = Field(
        default=True,
        description="Enable safe mode by default for all steps",
    )
    include_reconnaissance: bool = Field(
        default=True,
        description="Include reconnaissance phase in plan",
    )
    include_validation: bool = Field(
        default=True,
        description="Include validation phase for findings",
    )
    auto_prioritize: bool = Field(
        default=True,
        description="Auto-prioritize based on TCI score",
    )

    # Quotas
    default_timeout_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Default timeout per step",
    )
    max_steps: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum steps in plan",
    )
    max_modules: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Maximum prompt modules to include",
    )

    # TCI thresholds
    low_complexity_threshold: float = Field(
        default=30.0,
        description="TCI threshold for low complexity targets",
    )
    high_complexity_threshold: float = Field(
        default=70.0,
        description="TCI threshold for high complexity targets",
    )

    # Priority mapping
    critical_vulns: list[str] = Field(
        default_factory=lambda: [
            "SQL Injection",
            "RCE",
            "Authentication Bypass",
            "SSRF",
            "XXE",
        ],
        description="Vulnerability types considered critical",
    )
    high_vulns: list[str] = Field(
        default_factory=lambda: [
            "IDOR",
            "XSS",
            "CSRF",
            "JWT Vulnerabilities",
            "Broken Access Control",
        ],
        description="Vulnerability types considered high priority",
    )


# Module to phase mapping
MODULE_PHASES: dict[str, ScanPhase] = {
    "reconnaissance": ScanPhase.RECONNAISSANCE,
    "enumeration": ScanPhase.ENUMERATION,
    "sql_injection": ScanPhase.VULNERABILITY_SCAN,
    "sql_injection.detection": ScanPhase.VULNERABILITY_SCAN,
    "sql_injection.exploitation": ScanPhase.EXPLOITATION,
    "xss": ScanPhase.VULNERABILITY_SCAN,
    "xss.reflected": ScanPhase.VULNERABILITY_SCAN,
    "xss.stored": ScanPhase.VULNERABILITY_SCAN,
    "xss.dom": ScanPhase.VULNERABILITY_SCAN,
    "authentication_jwt": ScanPhase.VULNERABILITY_SCAN,
    "idor": ScanPhase.VULNERABILITY_SCAN,
    "ssrf": ScanPhase.VULNERABILITY_SCAN,
    "xxe": ScanPhase.VULNERABILITY_SCAN,
    "csrf": ScanPhase.VULNERABILITY_SCAN,
    "rce": ScanPhase.VULNERABILITY_SCAN,
    "graphql_security": ScanPhase.VULNERABILITY_SCAN,
    "websocket_testing": ScanPhase.VULNERABILITY_SCAN,
    "api_security": ScanPhase.VULNERABILITY_SCAN,
    "business_logic": ScanPhase.VULNERABILITY_SCAN,
    "file_upload": ScanPhase.VULNERABILITY_SCAN,
    "deserialization": ScanPhase.VULNERABILITY_SCAN,
    "oauth_testing": ScanPhase.VULNERABILITY_SCAN,
    "cloud_security": ScanPhase.VULNERABILITY_SCAN,
}

# Module descriptions for plan steps
MODULE_DESCRIPTIONS: dict[str, str] = {
    "reconnaissance": "Perform initial reconnaissance and information gathering",
    "enumeration": "Enumerate endpoints, parameters, and functionality",
    "sql_injection": "Test for SQL injection vulnerabilities (general)",
    "sql_injection.detection": "Detect potential SQL injection points",
    "sql_injection.exploitation": "Attempt to exploit SQL injection vulnerabilities",
    "xss": "Test for Cross-Site Scripting vulnerabilities (general)",
    "xss.reflected": "Test for Reflected XSS",
    "xss.stored": "Test for Stored XSS",
    "xss.dom": "Test for DOM-based XSS",
    "authentication_jwt": "Test JWT implementation and authentication flows",
    "idor": "Test for Insecure Direct Object Reference vulnerabilities",
    "ssrf": "Test for Server-Side Request Forgery vulnerabilities",
    "xxe": "Test for XML External Entity vulnerabilities",
    "csrf": "Test for Cross-Site Request Forgery vulnerabilities",
    "rce": "Test for Remote Code Execution vulnerabilities",
    "graphql_security": "Test GraphQL endpoint security",
    "websocket_testing": "Test WebSocket implementation security",
    "api_security": "Test API security controls and authorization",
    "business_logic": "Test business logic and workflow vulnerabilities",
    "file_upload": "Test file upload functionality for vulnerabilities",
    "deserialization": "Test for insecure deserialization",
    "oauth_testing": "Test OAuth implementation security",
    "cloud_security": "Test cloud-specific security configurations",
}

# Module timeout recommendations (seconds)
MODULE_TIMEOUTS: dict[str, int] = {
    "reconnaissance": 600,
    "enumeration": 900,
    "sql_injection": 600,
    "sql_injection.detection": 300,
    "sql_injection.exploitation": 600,
    "xss": 300,
    "xss.reflected": 300,
    "xss.stored": 450,
    "xss.dom": 300,
    "authentication_jwt": 300,
    "idor": 450,
    "ssrf": 300,
    "xxe": 300,
    "csrf": 180,
    "rce": 600,
    "graphql_security": 450,
    "websocket_testing": 300,
    "api_security": 450,
    "business_logic": 600,
    "file_upload": 300,
    "deserialization": 300,
    "oauth_testing": 300,
    "cloud_security": 450,
}

# =============================================================================
# MITRE ATT&CK TTP Mappings for Modules
# =============================================================================
# Maps scan modules to relevant MITRE ATT&CK techniques
MODULE_MITRE_TTPS: dict[str, list[dict[str, str]]] = {
    "reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"},
        {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
        {"id": "T1590", "name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    ],
    "enumeration": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
        {"id": "T1595.001", "name": "Scanning IP Blocks", "tactic": "Reconnaissance"},
    ],
    "sql_injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "xss": [
        {"id": "T1059.007", "name": "JavaScript Execution", "tactic": "Execution"},
        {"id": "T1539", "name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    ],
    "authentication_jwt": [
        {"id": "T1528", "name": "Steal Application Access Token", "tactic": "Credential Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "idor": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    ],
    "ssrf": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "xxe": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1005", "name": "Data from Local System", "tactic": "Collection"},
    ],
    "csrf": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "rce": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    ],
    "graphql_security": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1087", "name": "Account Discovery", "tactic": "Discovery"},
    ],
    "websocket_testing": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "api_security": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    ],
    "business_logic": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    ],
    "file_upload": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence"},
    ],
    "deserialization": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    ],
    "oauth_testing": [
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
        {"id": "T1528", "name": "Steal Application Access Token", "tactic": "Credential Access"},
    ],
    "cloud_security": [
        {"id": "T1078.004", "name": "Cloud Accounts", "tactic": "Initial Access"},
        {"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"},
    ],
}

# =============================================================================
# OWASP Reference Mappings for Modules
# =============================================================================
MODULE_OWASP_REFS: dict[str, list[dict[str, str]]] = {
    "sql_injection": [
        {"id": "A03:2025", "name": "Injection", "standard": "Web Top 10 2025", "severity": "critical"},
    ],
    "xss": [
        {"id": "A03:2025", "name": "Injection", "standard": "Web Top 10 2025", "severity": "high"},
    ],
    "authentication_jwt": [
        {"id": "A07:2025", "name": "Identification and Authentication Failures", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "API2:2025", "name": "Broken Authentication", "standard": "API Top 10 2025", "severity": "critical"},
    ],
    "idor": [
        {"id": "A01:2025", "name": "Broken Access Control", "standard": "Web Top 10 2025", "severity": "critical"},
        {"id": "API1:2025", "name": "Broken Object Level Authorization", "standard": "API Top 10 2025", "severity": "critical"},
    ],
    "ssrf": [
        {"id": "A10:2025", "name": "Server-Side Request Forgery", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "API7:2025", "name": "Server Side Request Forgery", "standard": "API Top 10 2025", "severity": "high"},
        {"id": "MCP05:2025", "name": "Server-Side Request Forgery via Tools", "standard": "MCP Top 10 2025", "severity": "high"},
    ],
    "xxe": [
        {"id": "A05:2025", "name": "Security Misconfiguration", "standard": "Web Top 10 2025", "severity": "high"},
    ],
    "csrf": [
        {"id": "A01:2025", "name": "Broken Access Control", "standard": "Web Top 10 2025", "severity": "medium"},
    ],
    "rce": [
        {"id": "A03:2025", "name": "Injection", "standard": "Web Top 10 2025", "severity": "critical"},
    ],
    "graphql_security": [
        {"id": "A03:2025", "name": "Injection", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "API1:2025", "name": "Broken Object Level Authorization", "standard": "API Top 10 2025", "severity": "high"},
    ],
    "api_security": [
        {"id": "API1:2025", "name": "Broken Object Level Authorization", "standard": "API Top 10 2025", "severity": "critical"},
        {"id": "API5:2025", "name": "Broken Function Level Authorization", "standard": "API Top 10 2025", "severity": "high"},
    ],
    "business_logic": [
        {"id": "A04:2025", "name": "Insecure Design", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "API6:2025", "name": "Unrestricted Access to Sensitive Business Flows", "standard": "API Top 10 2025", "severity": "medium"},
    ],
    "file_upload": [
        {"id": "A03:2025", "name": "Injection", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "A08:2025", "name": "Software and Data Integrity Failures", "standard": "Web Top 10 2025", "severity": "high"},
    ],
    "deserialization": [
        {"id": "A08:2025", "name": "Software and Data Integrity Failures", "standard": "Web Top 10 2025", "severity": "high"},
    ],
    "oauth_testing": [
        {"id": "A07:2025", "name": "Identification and Authentication Failures", "standard": "Web Top 10 2025", "severity": "high"},
        {"id": "API2:2025", "name": "Broken Authentication", "standard": "API Top 10 2025", "severity": "critical"},
    ],
    "cloud_security": [
        {"id": "A05:2025", "name": "Security Misconfiguration", "standard": "Web Top 10 2025", "severity": "medium"},
    ],
    "prompt_injection": [
        {"id": "LLM01:2025", "name": "Prompt Injection", "standard": "LLM Top 10 2025", "severity": "critical"},
        {"id": "MCP01:2025", "name": "Tool Injection", "standard": "MCP Top 10 2025", "severity": "critical"},
    ],
    "llm_security": [
        {"id": "LLM01:2025", "name": "Prompt Injection", "standard": "LLM Top 10 2025", "severity": "critical"},
        {"id": "LLM02:2025", "name": "Sensitive Information Disclosure", "standard": "LLM Top 10 2025", "severity": "high"},
        {"id": "LLM06:2025", "name": "Excessive Agency", "standard": "LLM Top 10 2025", "severity": "critical"},
    ],
    "mcp_security": [
        {"id": "MCP01:2025", "name": "Tool Injection", "standard": "MCP Top 10 2025", "severity": "critical"},
        {"id": "MCP02:2025", "name": "Resource Access Control Bypass", "standard": "MCP Top 10 2025", "severity": "critical"},
        {"id": "MCP06:2025", "name": "Insecure Tool Execution", "standard": "MCP Top 10 2025", "severity": "critical"},
    ],
}

# CWE IDs for modules
MODULE_CWE_IDS: dict[str, list[str]] = {
    "sql_injection": ["CWE-89", "CWE-564"],
    "xss": ["CWE-79"],
    "authentication_jwt": ["CWE-287", "CWE-798"],
    "idor": ["CWE-639", "CWE-863"],
    "ssrf": ["CWE-918"],
    "xxe": ["CWE-611"],
    "csrf": ["CWE-352"],
    "rce": ["CWE-94", "CWE-78"],
    "graphql_security": ["CWE-89", "CWE-639"],
    "api_security": ["CWE-285", "CWE-862"],
    "business_logic": ["CWE-840"],
    "file_upload": ["CWE-434"],
    "deserialization": ["CWE-502"],
    "oauth_testing": ["CWE-287"],
    "cloud_security": ["CWE-16", "CWE-1004"],
}


@dataclass
class ScanPlan:
    """Complete scan plan for a target."""

    plan_id: str
    target: str
    tci_score: float
    complexity_level: str
    created_at: str
    fingerprint_summary: dict[str, Any]
    steps: list[ScanStep]
    modules: list[str]
    quotas: ResourceQuota
    safe_mode: bool
    estimated_duration_minutes: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "tci_score": round(self.tci_score, 2),
            "complexity_level": self.complexity_level,
            "created_at": self.created_at,
            "fingerprint_summary": self.fingerprint_summary,
            "plan": [step.to_dict() for step in self.steps],
            "modules": self.modules,
            "quotas": {
                "max_requests": self.quotas.max_requests,
                "max_duration_minutes": self.quotas.max_duration_minutes,
                "max_parallel_tests": self.quotas.max_parallel_tests,
                "max_payload_size_kb": self.quotas.max_payload_size_kb,
                "rate_limit_rps": self.quotas.rate_limit_rps,
            },
            "safe_mode": self.safe_mode,
            "estimated_duration_minutes": self.estimated_duration_minutes,
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def get_steps_by_phase(self, phase: ScanPhase) -> list[ScanStep]:
        """Get all steps for a specific phase."""
        return [s for s in self.steps if s.phase == phase]

    def get_steps_by_priority(self, priority: PlanPriority) -> list[ScanStep]:
        """Get all steps with specific priority."""
        return [s for s in self.steps if s.priority == priority]

    def get_pending_steps(self) -> list[ScanStep]:
        """Get all pending steps."""
        return [s for s in self.steps if s.status == StepStatus.PENDING]

    def get_next_step(self) -> ScanStep | None:
        """Get the next step to execute based on dependencies."""
        completed_ids = {s.step_id for s in self.steps if s.status == StepStatus.COMPLETED}

        for step in self.steps:
            if step.status != StepStatus.PENDING:
                continue

            # Check if all dependencies are satisfied
            deps_satisfied = all(dep_id in completed_ids for dep_id in step.dependencies)
            if deps_satisfied:
                return step

        return None

    def mark_step_completed(self, step_id: str, result: dict[str, Any] | None = None) -> bool:
        """Mark a step as completed."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = StepStatus.COMPLETED
                step.result = result
                return True
        return False

    def mark_step_failed(self, step_id: str, notes: str = "") -> bool:
        """Mark a step as failed."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = StepStatus.FAILED
                step.notes = notes
                return True
        return False


class ScanPlanner:
    """Adaptive scan planner that generates context-aware vulnerability scanning plans.

    The planner uses TCI scores and target fingerprints to create optimized
    scan plans with appropriate prioritization, resource allocation, and
    module selection.
    """

    def __init__(self, config: ScanPlanConfig | None = None):
        """Initialize the scan planner.

        Args:
            config: Optional configuration for plan generation
        """
        self.config = config or ScanPlanConfig()
        self._step_counter = 0

    def generate_plan(
        self,
        target: str,
        fingerprint: TargetFingerprint,
        tci_result: TCIResult,
        additional_modules: list[str] | None = None,
        override_safe_mode: bool | None = None,
    ) -> ScanPlan:
        """Generate a scan plan from TCI result and fingerprint.

        Args:
            target: Target URL or identifier
            fingerprint: Target fingerprint data
            tci_result: TCI calculation result
            additional_modules: Additional modules to include
            override_safe_mode: Override safe mode setting

        Returns:
            Complete ScanPlan with prioritized steps
        """
        self._step_counter = 0

        # Determine safe mode
        safe_mode = override_safe_mode if override_safe_mode is not None else (
            self.config.enable_safe_mode or tci_result.suggested_safe_mode
        )

        # Calculate quotas based on TCI
        quotas = self._calculate_quotas(tci_result)

        # Select modules
        modules = self._select_modules(tci_result, fingerprint, additional_modules)

        # Generate steps
        steps = self._generate_steps(
            tci_result=tci_result,
            fingerprint=fingerprint,
            modules=modules,
            safe_mode=safe_mode,
        )

        # Calculate estimated duration
        estimated_duration = self._estimate_duration(steps)

        # Generate fingerprint summary
        fingerprint_summary = self._create_fingerprint_summary(fingerprint)

        # Create plan
        plan = ScanPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            target=target,
            tci_score=tci_result.score,
            complexity_level=tci_result.complexity_level.value,
            created_at=datetime.now(UTC).isoformat(),
            fingerprint_summary=fingerprint_summary,
            steps=steps,
            modules=modules,
            quotas=quotas,
            safe_mode=safe_mode,
            estimated_duration_minutes=estimated_duration,
            notes=self._generate_plan_notes(tci_result, fingerprint),
        )

        logger.info(
            f"Generated scan plan {plan.plan_id} for {target}: "
            f"TCI={tci_result.score:.1f}, {len(steps)} steps"
        )

        return plan

    def _calculate_quotas(self, tci_result: TCIResult) -> ResourceQuota:
        """Calculate resource quotas based on TCI."""
        # Base quotas adjusted by complexity
        score = tci_result.score

        if score <= self.config.low_complexity_threshold:
            # Low complexity: fewer resources needed
            return ResourceQuota(
                max_requests=500,
                max_duration_minutes=30,
                max_parallel_tests=min(8, tci_result.max_parallel_tests),
                max_payload_size_kb=50,
                rate_limit_rps=20.0,
                max_retries_per_step=1,
            )
        elif score <= self.config.high_complexity_threshold:
            # Medium complexity
            return ResourceQuota(
                max_requests=1000,
                max_duration_minutes=60,
                max_parallel_tests=min(5, tci_result.max_parallel_tests),
                max_payload_size_kb=100,
                rate_limit_rps=10.0,
                max_retries_per_step=2,
            )
        else:
            # High complexity: more resources, slower rate
            return ResourceQuota(
                max_requests=2000,
                max_duration_minutes=120,
                max_parallel_tests=min(3, tci_result.max_parallel_tests),
                max_payload_size_kb=200,
                rate_limit_rps=5.0,
                max_retries_per_step=3,
            )

    def _select_modules(
        self,
        tci_result: TCIResult,
        fingerprint: TargetFingerprint,
        additional_modules: list[str] | None,
    ) -> list[str]:
        """Select prompt modules based on TCI and fingerprint."""
        modules: list[str] = []

        # Start with TCI recommendations
        modules.extend(tci_result.recommended_modules)

        # Add additional modules if specified
        if additional_modules:
            for mod in additional_modules:
                if mod not in modules:
                    modules.append(mod)

        # Ensure reconnaissance is first if enabled
        if self.config.include_reconnaissance and "reconnaissance" not in modules:
            modules.insert(0, "reconnaissance")

        # Limit to max modules
        return modules[: self.config.max_modules]

    def _generate_steps(
        self,
        tci_result: TCIResult,
        fingerprint: TargetFingerprint,
        modules: list[str],
        safe_mode: bool,
    ) -> list[ScanStep]:
        """Generate scan steps from modules and TCI."""
        steps: list[ScanStep] = []
        recon_step_id: str | None = None

        # Phase 1: Reconnaissance (if enabled)
        if self.config.include_reconnaissance and "reconnaissance" in modules:
            recon_step = self._create_step(
                module="reconnaissance",
                priority=PlanPriority.HIGH,
                phase=ScanPhase.RECONNAISSANCE,
                safe_mode=True,  # Recon is always safe mode
                tci_result=tci_result,
            )
            steps.append(recon_step)
            recon_step_id = recon_step.step_id

        # Phase 2: Enumeration
        enum_step = self._create_step(
            module="enumeration",
            priority=PlanPriority.HIGH,
            phase=ScanPhase.ENUMERATION,
            safe_mode=safe_mode,
            tci_result=tci_result,
            dependencies=[recon_step_id] if recon_step_id else [],
        )
        steps.append(enum_step)
        enum_step_id = enum_step.step_id

        # Phase 3: Vulnerability scanning steps
        vuln_modules = [m for m in modules if m not in ["reconnaissance", "enumeration"]]

        for module in vuln_modules:
            priority = self._determine_module_priority(module, tci_result)
            step = self._create_step(
                module=module,
                priority=priority,
                phase=MODULE_PHASES.get(module, ScanPhase.VULNERABILITY_SCAN),
                safe_mode=safe_mode,
                tci_result=tci_result,
                dependencies=[enum_step_id],
            )
            steps.append(step)

        # Phase 4: Validation (if enabled)
        if self.config.include_validation and len(steps) > 0:
            vuln_step_ids = [s.step_id for s in steps if s.phase == ScanPhase.VULNERABILITY_SCAN]
            validation_step = self._create_step(
                module="validation",
                priority=PlanPriority.HIGH,
                phase=ScanPhase.VALIDATION,
                safe_mode=safe_mode,
                tci_result=tci_result,
                dependencies=vuln_step_ids,
                description="Validate discovered vulnerabilities with PoC",
            )
            steps.append(validation_step)

        # Sort by priority and phase order
        steps.sort(key=lambda s: (
            self._phase_order(s.phase),
            self._priority_order(s.priority),
            s.step_number,
        ))

        # Renumber steps after sorting
        for i, step in enumerate(steps, 1):
            step.step_number = i

        # Limit total steps
        return steps[: self.config.max_steps]

    def _create_step(
        self,
        module: str,
        priority: PlanPriority,
        phase: ScanPhase,
        safe_mode: bool,
        tci_result: TCIResult,
        dependencies: list[str] | None = None,
        description: str | None = None,
    ) -> ScanStep:
        """Create a single scan step with threat intelligence tagging."""
        self._step_counter += 1

        # Get timeout with TCI multiplier
        base_timeout = MODULE_TIMEOUTS.get(module, self.config.default_timeout_seconds)
        adjusted_timeout = int(base_timeout * tci_result.suggested_timeout_multiplier)

        # Calculate quota for this step based on priority
        quota = self._calculate_step_quota(priority)

        # Get MITRE ATT&CK TTPs for this module
        mitre_ttps = self._get_module_ttps(module)

        # Get OWASP references for this module
        owasp_refs = self._get_module_owasp_refs(module)

        # Get CWE IDs for this module
        cwe_ids = MODULE_CWE_IDS.get(module, [])

        return ScanStep(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            step_number=self._step_counter,
            module=module,
            description=description or MODULE_DESCRIPTIONS.get(
                module, f"Execute {module} testing"
            ),
            priority=priority,
            phase=phase,
            safe_mode=safe_mode,
            timeout_seconds=adjusted_timeout,
            max_retries=2 if priority in [PlanPriority.CRITICAL, PlanPriority.HIGH] else 1,
            dependencies=dependencies or [],
            parameters={
                "tci_score": tci_result.score,
                "complexity": tci_result.complexity_level.value,
            },
            quota=quota,
            mitre_ttps=mitre_ttps,
            owasp_refs=owasp_refs,
            cwe_ids=cwe_ids,
        )

    def _get_module_ttps(self, module: str) -> list[TTPReference]:
        """Get MITRE ATT&CK TTP references for a module."""
        ttp_data = MODULE_MITRE_TTPS.get(module, [])
        return [
            TTPReference(
                technique_id=ttp["id"],
                technique_name=ttp["name"],
                tactic=ttp["tactic"],
                url=f"https://attack.mitre.org/techniques/{ttp['id'].replace('.', '/')}/",
            )
            for ttp in ttp_data
        ]

    def _get_module_owasp_refs(self, module: str) -> list[OWASPReference]:
        """Get OWASP references for a module."""
        owasp_data = MODULE_OWASP_REFS.get(module, [])
        return [
            OWASPReference(
                category_id=ref["id"],
                category_name=ref["name"],
                standard=ref["standard"],
                severity=ref.get("severity", ""),
            )
            for ref in owasp_data
        ]

    def _determine_module_priority(
        self, module: str, tci_result: TCIResult
    ) -> PlanPriority:
        """Determine priority for a module based on TCI and config."""
        # Check if module matches critical vulnerability types
        module_lower = module.lower().replace("_", " ")

        for critical_vuln in self.config.critical_vulns:
            if critical_vuln.lower() in module_lower or module_lower in critical_vuln.lower():
                return PlanPriority.CRITICAL

        for high_vuln in self.config.high_vulns:
            if high_vuln.lower() in module_lower or module_lower in high_vuln.lower():
                return PlanPriority.HIGH

        # Check TCI recommended priority vulnerabilities
        for priority_vuln in tci_result.priority_vulnerabilities[:3]:
            vuln_lower = priority_vuln.lower()
            if vuln_lower in module_lower or module_lower in vuln_lower:
                return PlanPriority.HIGH

        # Default based on TCI score
        if tci_result.score >= self.config.high_complexity_threshold:
            return PlanPriority.MEDIUM
        else:
            return PlanPriority.LOW

    def _calculate_step_quota(self, priority: PlanPriority) -> int:
        """Calculate iteration quota for a step based on priority."""
        quotas = {
            PlanPriority.CRITICAL: 100,
            PlanPriority.HIGH: 75,
            PlanPriority.MEDIUM: 50,
            PlanPriority.LOW: 30,
            PlanPriority.OPTIONAL: 20,
        }
        return quotas.get(priority, 30)

    def _phase_order(self, phase: ScanPhase) -> int:
        """Get sort order for phase."""
        order = {
            ScanPhase.RECONNAISSANCE: 0,
            ScanPhase.ENUMERATION: 1,
            ScanPhase.VULNERABILITY_SCAN: 2,
            ScanPhase.EXPLOITATION: 3,
            ScanPhase.VALIDATION: 4,
            ScanPhase.REPORTING: 5,
        }
        return order.get(phase, 99)

    def _priority_order(self, priority: PlanPriority) -> int:
        """Get sort order for priority (lower = higher priority)."""
        order = {
            PlanPriority.CRITICAL: 0,
            PlanPriority.HIGH: 1,
            PlanPriority.MEDIUM: 2,
            PlanPriority.LOW: 3,
            PlanPriority.OPTIONAL: 4,
        }
        return order.get(priority, 99)

    def _estimate_duration(self, steps: list[ScanStep]) -> int:
        """Estimate total duration in minutes."""
        total_seconds = sum(s.timeout_seconds for s in steps)
        # Add buffer for overhead
        total_with_buffer = total_seconds * 1.2
        return max(1, int(total_with_buffer / 60))

    def _create_fingerprint_summary(self, fingerprint: TargetFingerprint) -> dict[str, Any]:
        """Create a summary of the fingerprint for the plan."""
        return {
            "category": fingerprint.category.value,
            "open_ports_count": len(fingerprint.open_ports),
            "technologies": fingerprint.technologies[:5],
            "auth_types": fingerprint.auth_types,
            "has_waf": fingerprint.has_waf,
            "has_graphql": fingerprint.has_graphql,
            "api_endpoints": fingerprint.api_endpoints,
            "data_sensitivity": fingerprint.data_sensitivity_score,
        }

    def _generate_plan_notes(
        self, tci_result: TCIResult, fingerprint: TargetFingerprint
    ) -> list[str]:
        """Generate notes and warnings for the plan."""
        notes = []

        # Security posture notes
        if tci_result.security_posture.value == "hardened":
            notes.append("Target appears hardened - expect WAF/rate limiting challenges")
        elif tci_result.security_posture.value == "permissive":
            notes.append("Target has permissive security posture - higher success likelihood")

        # Complexity notes
        if tci_result.score >= 80:
            notes.append("Critical complexity target - extended testing recommended")
        elif tci_result.score <= 30:
            notes.append("Low complexity target - quick scan may be sufficient")

        # Technology-specific notes
        if fingerprint.has_graphql:
            notes.append("GraphQL detected - test introspection and query depth")
        if fingerprint.has_websocket:
            notes.append("WebSocket detected - include real-time testing")
        if fingerprint.handles_payment:
            notes.append("Payment processing detected - extra care required")

        # WAF notes
        if fingerprint.has_waf:
            notes.append(f"WAF detected ({fingerprint.waf_type or 'unknown'}) - use evasion techniques")

        return notes

    def update_plan_from_results(
        self,
        plan: ScanPlan,
        step_id: str,
        findings: list[dict[str, Any]],
    ) -> list[ScanStep]:
        """Update plan based on scan results, potentially adding new steps.

        Args:
            plan: Current scan plan
            step_id: ID of completed step
            findings: List of findings from the step

        Returns:
            List of any new steps added to the plan
        """
        new_steps: list[ScanStep] = []

        # Mark step as completed
        plan.mark_step_completed(step_id, {"findings": findings})

        # Analyze findings to potentially add follow-up steps
        for finding in findings:
            vuln_type = finding.get("type", "").lower()

            # Add validation step if critical finding
            severity = finding.get("severity", "").lower()
            if severity in ["critical", "high"]:
                # Check if validation step already exists
                has_validation = any(
                    s.phase == ScanPhase.VALIDATION and s.status == StepStatus.PENDING
                    for s in plan.steps
                )
                if not has_validation:
                    from strix.core.tci import TCIResult, ComplexityLevel, SecurityPosture

                    mock_tci = TCIResult(
                        score=plan.tci_score,
                        complexity_level=ComplexityLevel(plan.complexity_level),
                        security_posture=SecurityPosture.STANDARD,
                    )
                    validation_step = self._create_step(
                        module="validation",
                        priority=PlanPriority.CRITICAL,
                        phase=ScanPhase.VALIDATION,
                        safe_mode=plan.safe_mode,
                        tci_result=mock_tci,
                        dependencies=[step_id],
                        description=f"Validate {vuln_type} finding with PoC",
                    )
                    plan.steps.append(validation_step)
                    new_steps.append(validation_step)

        return new_steps


def create_plan_from_fingerprint(
    target: str,
    fingerprint: TargetFingerprint,
    config: ScanPlanConfig | None = None,
) -> ScanPlan:
    """Convenience function to create a plan from fingerprint.

    This function handles TCI calculation and plan generation in one call.

    Args:
        target: Target URL or identifier
        fingerprint: Target fingerprint data
        config: Optional planner configuration

    Returns:
        Complete ScanPlan

    Example:
        >>> from strix.core.tci import TargetFingerprint
        >>> fp = TargetFingerprint(
        ...     open_ports=[80, 443],
        ...     technologies=["django", "postgresql"],
        ...     auth_types=["jwt"],
        ... )
        >>> plan = create_plan_from_fingerprint("https://example.com", fp)
        >>> print(plan.to_json())
    """
    from strix.core.tci import compute_tci

    tci_result = compute_tci(fingerprint)
    planner = ScanPlanner(config)

    return planner.generate_plan(
        target=target,
        fingerprint=fingerprint,
        tci_result=tci_result,
    )
