"""Target Complexity Index (TCI) Module.

Calculates a complexity score (0-100) from target fingerprint data to enable
adaptive, context-aware vulnerability scanning. The TCI drives dynamic planning
by quantifying target attack surface characteristics.

Key Features:
- Configurable weights for different complexity factors
- Multi-dimensional fingerprint analysis
- Priority-based module recommendations
- Support for infrastructure, web, and API targets

Usage:
    from strix.core.tci import compute_tci, TargetFingerprint

    fingerprint = TargetFingerprint(
        open_ports=[22, 80, 443, 8080],
        technologies=["nginx", "python", "postgresql"],
        auth_types=["jwt", "oauth2"],
        api_endpoints=150,
        has_waf=True,
    )

    result = compute_tci(fingerprint)
    print(f"TCI Score: {result.score}")  # e.g., 78.3
    print(f"Priority Modules: {result.recommended_modules}")
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class TargetCategory(str, Enum):
    """Category of target being analyzed."""

    WEB_APPLICATION = "web_application"
    API = "api"
    INFRASTRUCTURE = "infrastructure"
    REPOSITORY = "repository"
    MOBILE = "mobile"
    IOT = "iot"
    CLOUD = "cloud"


class ComplexityLevel(str, Enum):
    """Overall complexity classification."""

    MINIMAL = "minimal"  # 0-20
    LOW = "low"  # 21-40
    MEDIUM = "medium"  # 41-60
    HIGH = "high"  # 61-80
    CRITICAL = "critical"  # 81-100


class SecurityPosture(str, Enum):
    """Detected security posture of target."""

    HARDENED = "hardened"
    STANDARD = "standard"
    PERMISSIVE = "permissive"
    UNKNOWN = "unknown"


class TCIConfig(BaseModel):
    """Configuration for TCI calculation weights.

    All weights should sum to approximately 1.0 for normalized scoring.
    Adjust weights based on engagement type and priorities.
    """

    # Port/Service complexity weights
    port_count_weight: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description="Weight for number of open ports",
    )
    service_diversity_weight: float = Field(
        default=0.08,
        ge=0.0,
        le=1.0,
        description="Weight for variety of services",
    )
    high_risk_ports_weight: float = Field(
        default=0.12,
        ge=0.0,
        le=1.0,
        description="Weight for high-risk ports (databases, admin panels, etc.)",
    )

    # Technology stack weights
    tech_stack_weight: float = Field(
        default=0.10,
        ge=0.0,
        le=1.0,
        description="Weight for technology stack complexity",
    )
    framework_count_weight: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Weight for number of frameworks",
    )

    # Authentication complexity
    auth_complexity_weight: float = Field(
        default=0.15,
        ge=0.0,
        le=1.0,
        description="Weight for authentication mechanism complexity",
    )

    # API surface weights
    api_surface_weight: float = Field(
        default=0.12,
        ge=0.0,
        le=1.0,
        description="Weight for API endpoint count/complexity",
    )
    graphql_weight: float = Field(
        default=0.05,
        ge=0.0,
        le=1.0,
        description="Weight for GraphQL presence (adds complexity)",
    )

    # Infrastructure weights
    waf_cdn_weight: float = Field(
        default=0.08,
        ge=0.0,
        le=1.0,
        description="Weight for WAF/CDN presence (adds evasion complexity)",
    )
    cloud_complexity_weight: float = Field(
        default=0.07,
        ge=0.0,
        le=1.0,
        description="Weight for cloud infrastructure complexity",
    )

    # Data sensitivity
    data_sensitivity_weight: float = Field(
        default=0.08,
        ge=0.0,
        le=1.0,
        description="Weight for data sensitivity indicators",
    )

    # Thresholds for port scoring
    port_count_low: int = Field(default=5, description="Low port count threshold")
    port_count_medium: int = Field(default=15, description="Medium port count threshold")
    port_count_high: int = Field(default=30, description="High port count threshold")

    # Thresholds for API scoring
    api_count_low: int = Field(default=20, description="Low API endpoint count")
    api_count_medium: int = Field(default=50, description="Medium API endpoint count")
    api_count_high: int = Field(default=100, description="High API endpoint count")

    @field_validator("*", mode="before")
    @classmethod
    def ensure_non_negative(cls, v: Any, info: Any) -> Any:
        """Ensure numeric values are non-negative."""
        if isinstance(v, int | float) and v < 0:
            raise ValueError(f"{info.field_name} must be non-negative")
        return v


# High-risk ports that indicate increased attack surface
HIGH_RISK_PORTS: set[int] = {
    21,  # FTP
    22,  # SSH
    23,  # Telnet
    25,  # SMTP
    53,  # DNS
    110,  # POP3
    135,  # RPC
    139,  # NetBIOS
    143,  # IMAP
    161,  # SNMP
    389,  # LDAP
    443,  # HTTPS (when exposed, indicates web surface)
    445,  # SMB
    512,  # rexec
    513,  # rlogin
    514,  # rsh
    1433,  # MSSQL
    1521,  # Oracle
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP Proxy/Alt
    8443,  # HTTPS Alt
    9200,  # Elasticsearch
    27017,  # MongoDB
    11211,  # Memcached
}

# Authentication types with complexity scores
AUTH_COMPLEXITY_SCORES: dict[str, float] = {
    "none": 0.0,
    "basic": 0.3,
    "api_key": 0.4,
    "bearer": 0.5,
    "jwt": 0.7,
    "oauth2": 0.85,
    "saml": 0.9,
    "mfa": 1.0,
    "custom": 0.6,
}

# Technology categories with vulnerability richness scores
TECH_VULNERABILITY_SCORES: dict[str, float] = {
    # Databases
    "postgresql": 0.6,
    "mysql": 0.7,
    "mongodb": 0.7,
    "redis": 0.5,
    "elasticsearch": 0.7,
    "mssql": 0.8,
    "oracle": 0.8,
    "sqlite": 0.3,
    # Web servers
    "nginx": 0.4,
    "apache": 0.5,
    "iis": 0.6,
    "tomcat": 0.7,
    # Frameworks
    "django": 0.5,
    "flask": 0.4,
    "fastapi": 0.4,
    "express": 0.5,
    "spring": 0.7,
    "rails": 0.6,
    "laravel": 0.6,
    "nextjs": 0.5,
    "react": 0.3,
    "vue": 0.3,
    "angular": 0.4,
    # Languages (when exposed)
    "php": 0.7,
    "java": 0.6,
    "python": 0.4,
    "nodejs": 0.5,
    "ruby": 0.5,
    "go": 0.3,
    "rust": 0.2,
    # Cloud/Infrastructure
    "kubernetes": 0.7,
    "docker": 0.5,
    "aws": 0.6,
    "azure": 0.6,
    "gcp": 0.6,
    # Auth providers
    "auth0": 0.4,
    "okta": 0.4,
    "firebase": 0.5,
    "supabase": 0.5,
    # Message queues
    "rabbitmq": 0.5,
    "kafka": 0.5,
    # GraphQL
    "graphql": 0.7,
    "apollo": 0.6,
    # CMS
    "wordpress": 0.8,
    "drupal": 0.7,
    "joomla": 0.8,
}

# Module recommendations based on fingerprint characteristics
MODULE_RECOMMENDATIONS: dict[str, list[str]] = {
    "has_jwt": ["authentication_jwt", "idor"],
    "has_oauth": ["oauth_testing", "authentication_jwt"],
    "has_graphql": ["graphql_security", "idor"],
    "has_websocket": ["websocket_testing"],
    "has_database": ["sql_injection"],
    "has_file_upload": ["file_upload", "xxe"],
    "has_api": ["api_security", "idor", "business_logic"],
    "has_xml": ["xxe"],
    "has_deserialization": ["deserialization"],
    "has_ssrf_surface": ["ssrf"],
    "has_rce_surface": ["rce"],
    "has_cloud": ["cloud_security"],
}


class TargetFingerprint(BaseModel):
    """Fingerprint data collected from target reconnaissance.

    This model captures all relevant characteristics of a target
    that influence scanning strategy and complexity assessment.
    """

    # Target identification
    target_id: str = Field(default="", description="Unique target identifier")
    target_url: str | None = Field(default=None, description="Primary target URL")
    target_host: str | None = Field(default=None, description="Target hostname/IP")
    category: TargetCategory = Field(
        default=TargetCategory.WEB_APPLICATION,
        description="Target category",
    )

    # Port and service data
    open_ports: list[int] = Field(
        default_factory=list,
        description="List of open ports discovered",
    )
    services: dict[int, str] = Field(
        default_factory=dict,
        description="Mapping of port to service name",
    )
    service_versions: dict[int, str] = Field(
        default_factory=dict,
        description="Mapping of port to service version",
    )

    # Technology stack
    technologies: list[str] = Field(
        default_factory=list,
        description="Detected technologies (normalized to lowercase)",
    )
    frameworks: list[str] = Field(
        default_factory=list,
        description="Detected frameworks",
    )
    programming_languages: list[str] = Field(
        default_factory=list,
        description="Detected programming languages",
    )
    databases: list[str] = Field(
        default_factory=list,
        description="Detected database systems",
    )

    # Web server info
    web_server: str | None = Field(default=None, description="Web server software")
    reverse_proxy: str | None = Field(default=None, description="Reverse proxy detected")
    cdn: str | None = Field(default=None, description="CDN provider detected")

    # Authentication
    auth_types: list[str] = Field(
        default_factory=list,
        description="Authentication mechanisms detected",
    )
    has_mfa: bool = Field(default=False, description="MFA detected")
    session_type: str | None = Field(default=None, description="Session management type")

    # API characteristics
    api_endpoints: int = Field(
        default=0,
        ge=0,
        description="Number of API endpoints discovered",
    )
    has_graphql: bool = Field(default=False, description="GraphQL endpoint present")
    has_websocket: bool = Field(default=False, description="WebSocket support detected")
    has_openapi_spec: bool = Field(default=False, description="OpenAPI spec available")
    has_graphql_introspection: bool = Field(
        default=False,
        description="GraphQL introspection enabled",
    )

    # Security controls
    has_waf: bool = Field(default=False, description="WAF detected")
    waf_type: str | None = Field(default=None, description="WAF vendor/type")
    has_rate_limiting: bool = Field(default=False, description="Rate limiting detected")
    has_csrf_protection: bool = Field(default=False, description="CSRF tokens detected")
    has_cors: bool = Field(default=False, description="CORS headers present")
    security_headers: list[str] = Field(
        default_factory=list,
        description="Security headers present",
    )

    # Content characteristics
    has_file_upload: bool = Field(default=False, description="File upload functionality")
    has_user_input: bool = Field(default=True, description="User input forms present")
    has_search: bool = Field(default=False, description="Search functionality")
    has_xml_processing: bool = Field(default=False, description="XML processing detected")
    has_json_api: bool = Field(default=True, description="JSON API present")

    # Cloud/Infrastructure
    cloud_provider: str | None = Field(default=None, description="Cloud provider")
    is_containerized: bool = Field(default=False, description="Running in containers")
    has_serverless: bool = Field(default=False, description="Serverless functions detected")

    # Sensitive data indicators
    handles_pii: bool = Field(default=False, description="PII handling detected")
    handles_payment: bool = Field(default=False, description="Payment processing")
    handles_healthcare: bool = Field(default=False, description="Healthcare data")
    data_sensitivity_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Overall data sensitivity score",
    )

    # Patch/Version posture
    outdated_components: list[str] = Field(
        default_factory=list,
        description="Components with known outdated versions",
    )
    known_vulnerabilities: list[str] = Field(
        default_factory=list,
        description="Known CVEs detected",
    )

    # Additional metadata
    scan_timestamp: str | None = Field(default=None, description="When fingerprint was captured")
    confidence_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in fingerprint accuracy",
    )
    notes: list[str] = Field(default_factory=list, description="Additional observations")

    @field_validator("technologies", "frameworks", "programming_languages", "databases", mode="after")
    @classmethod
    def normalize_to_lowercase(cls, v: list[str]) -> list[str]:
        """Normalize technology names to lowercase."""
        return [item.lower() for item in v]


@dataclass
class TCIResult:
    """Result of Target Complexity Index calculation."""

    # Overall score (0-100)
    score: float

    # Classification
    complexity_level: ComplexityLevel
    security_posture: SecurityPosture

    # Component scores (0-1 scale, pre-weighting)
    port_score: float = 0.0
    service_diversity_score: float = 0.0
    high_risk_ports_score: float = 0.0
    tech_stack_score: float = 0.0
    auth_complexity_score: float = 0.0
    api_surface_score: float = 0.0
    waf_complexity_score: float = 0.0
    data_sensitivity_score: float = 0.0
    cloud_complexity_score: float = 0.0

    # Recommendations
    recommended_modules: list[str] = field(default_factory=list)
    priority_vulnerabilities: list[str] = field(default_factory=list)

    # Scan hints
    suggested_timeout_multiplier: float = 1.0
    suggested_safe_mode: bool = True
    max_parallel_tests: int = 5

    # Metadata
    fingerprint_id: str = ""
    calculation_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "score": round(self.score, 2),
            "complexity_level": self.complexity_level.value,
            "security_posture": self.security_posture.value,
            "component_scores": {
                "port_score": round(self.port_score, 3),
                "service_diversity_score": round(self.service_diversity_score, 3),
                "high_risk_ports_score": round(self.high_risk_ports_score, 3),
                "tech_stack_score": round(self.tech_stack_score, 3),
                "auth_complexity_score": round(self.auth_complexity_score, 3),
                "api_surface_score": round(self.api_surface_score, 3),
                "waf_complexity_score": round(self.waf_complexity_score, 3),
                "data_sensitivity_score": round(self.data_sensitivity_score, 3),
                "cloud_complexity_score": round(self.cloud_complexity_score, 3),
            },
            "recommended_modules": self.recommended_modules,
            "priority_vulnerabilities": self.priority_vulnerabilities,
            "scan_hints": {
                "timeout_multiplier": self.suggested_timeout_multiplier,
                "safe_mode": self.suggested_safe_mode,
                "max_parallel_tests": self.max_parallel_tests,
            },
            "fingerprint_id": self.fingerprint_id,
            "calculation_notes": self.calculation_notes,
        }


class TargetComplexityIndex:
    """Calculator for Target Complexity Index.

    The TCI analyzes target fingerprint data and produces a complexity score
    that guides adaptive scanning decisions.
    """

    def __init__(self, config: TCIConfig | None = None):
        """Initialize TCI calculator.

        Args:
            config: Optional configuration for weight adjustments
        """
        self.config = config or TCIConfig()
        self._notes: list[str] = []

    def calculate(self, fingerprint: TargetFingerprint) -> TCIResult:
        """Calculate TCI score from fingerprint.

        Args:
            fingerprint: Target fingerprint data

        Returns:
            TCIResult with score and recommendations
        """
        self._notes = []

        # Calculate component scores
        port_score = self._calculate_port_score(fingerprint)
        service_score = self._calculate_service_diversity_score(fingerprint)
        high_risk_score = self._calculate_high_risk_ports_score(fingerprint)
        tech_score = self._calculate_tech_stack_score(fingerprint)
        auth_score = self._calculate_auth_complexity_score(fingerprint)
        api_score = self._calculate_api_surface_score(fingerprint)
        waf_score = self._calculate_waf_complexity_score(fingerprint)
        data_score = self._calculate_data_sensitivity_score(fingerprint)
        cloud_score = self._calculate_cloud_complexity_score(fingerprint)

        # Weighted sum
        weighted_score = (
            port_score * self.config.port_count_weight
            + service_score * self.config.service_diversity_weight
            + high_risk_score * self.config.high_risk_ports_weight
            + tech_score * self.config.tech_stack_weight
            + auth_score * self.config.auth_complexity_weight
            + api_score * self.config.api_surface_weight
            + waf_score * self.config.waf_cdn_weight
            + data_score * self.config.data_sensitivity_weight
            + cloud_score * self.config.cloud_complexity_weight
        )

        # Scale to 0-100
        total_weight = (
            self.config.port_count_weight
            + self.config.service_diversity_weight
            + self.config.high_risk_ports_weight
            + self.config.tech_stack_weight
            + self.config.auth_complexity_weight
            + self.config.api_surface_weight
            + self.config.waf_cdn_weight
            + self.config.data_sensitivity_weight
            + self.config.cloud_complexity_weight
        )

        # Normalize if weights don't sum to 1
        if total_weight > 0:
            normalized_score = (weighted_score / total_weight) * 100
        else:
            normalized_score = 50.0  # Default mid-range

        # Clamp to 0-100
        final_score = max(0.0, min(100.0, normalized_score))

        # Determine complexity level
        complexity_level = self._determine_complexity_level(final_score)

        # Determine security posture
        security_posture = self._determine_security_posture(fingerprint)

        # Generate recommendations
        recommended_modules = self._generate_module_recommendations(fingerprint)
        priority_vulns = self._generate_priority_vulnerabilities(fingerprint, final_score)

        # Calculate scan hints
        timeout_multiplier = self._calculate_timeout_multiplier(final_score, fingerprint)
        safe_mode = self._determine_safe_mode(fingerprint)
        max_parallel = self._calculate_max_parallel(final_score, fingerprint)

        return TCIResult(
            score=final_score,
            complexity_level=complexity_level,
            security_posture=security_posture,
            port_score=port_score,
            service_diversity_score=service_score,
            high_risk_ports_score=high_risk_score,
            tech_stack_score=tech_score,
            auth_complexity_score=auth_score,
            api_surface_score=api_score,
            waf_complexity_score=waf_score,
            data_sensitivity_score=data_score,
            cloud_complexity_score=cloud_score,
            recommended_modules=recommended_modules,
            priority_vulnerabilities=priority_vulns,
            suggested_timeout_multiplier=timeout_multiplier,
            suggested_safe_mode=safe_mode,
            max_parallel_tests=max_parallel,
            fingerprint_id=fingerprint.target_id,
            calculation_notes=self._notes,
        )

    def _calculate_port_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on port count."""
        port_count = len(fp.open_ports)

        if port_count == 0:
            return 0.0
        elif port_count <= self.config.port_count_low:
            score = port_count / self.config.port_count_low * 0.3
        elif port_count <= self.config.port_count_medium:
            score = 0.3 + (port_count - self.config.port_count_low) / (
                self.config.port_count_medium - self.config.port_count_low
            ) * 0.4
        elif port_count <= self.config.port_count_high:
            score = 0.7 + (port_count - self.config.port_count_medium) / (
                self.config.port_count_high - self.config.port_count_medium
            ) * 0.2
        else:
            score = 0.9 + min(0.1, (port_count - self.config.port_count_high) / 50 * 0.1)

        self._notes.append(f"Port count: {port_count} -> score: {score:.2f}")
        return min(1.0, score)

    def _calculate_service_diversity_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on service diversity."""
        unique_services = set(fp.services.values())
        service_count = len(unique_services)

        if service_count == 0:
            return 0.0

        # Logarithmic scaling for service diversity
        score = min(1.0, math.log2(service_count + 1) / 5)

        self._notes.append(f"Service diversity: {service_count} types -> score: {score:.2f}")
        return score

    def _calculate_high_risk_ports_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on high-risk ports present."""
        high_risk_found = [p for p in fp.open_ports if p in HIGH_RISK_PORTS]

        if not high_risk_found:
            return 0.0

        # Score based on number and type of high-risk ports
        base_score = min(1.0, len(high_risk_found) / 10)

        # Bonus for particularly dangerous ports
        dangerous_ports = {23, 3389, 445, 1433, 3306, 5432, 27017}  # Telnet, RDP, SMB, DBs
        has_dangerous = any(p in dangerous_ports for p in high_risk_found)

        if has_dangerous:
            base_score = min(1.0, base_score + 0.2)

        self._notes.append(f"High-risk ports: {high_risk_found} -> score: {base_score:.2f}")
        return base_score

    def _calculate_tech_stack_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on technology stack complexity."""
        all_tech = (
            fp.technologies + fp.frameworks + fp.programming_languages + fp.databases
        )

        if not all_tech:
            return 0.3  # Default baseline for unknown

        # Sum vulnerability scores for detected technologies
        vuln_scores = []
        for tech in all_tech:
            tech_lower = tech.lower()
            if tech_lower in TECH_VULNERABILITY_SCORES:
                vuln_scores.append(TECH_VULNERABILITY_SCORES[tech_lower])

        if not vuln_scores:
            return 0.3

        # Weighted average with count bonus
        avg_score = sum(vuln_scores) / len(vuln_scores)
        count_bonus = min(0.2, len(vuln_scores) / 20)

        final_score = min(1.0, avg_score + count_bonus)

        self._notes.append(f"Tech stack: {len(all_tech)} items -> score: {final_score:.2f}")
        return final_score

    def _calculate_auth_complexity_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on authentication complexity."""
        if not fp.auth_types:
            return 0.1  # No auth is low complexity but still testable

        auth_scores = []
        for auth_type in fp.auth_types:
            auth_lower = auth_type.lower()
            if auth_lower in AUTH_COMPLEXITY_SCORES:
                auth_scores.append(AUTH_COMPLEXITY_SCORES[auth_lower])
            else:
                auth_scores.append(0.5)  # Unknown auth type

        base_score = max(auth_scores) if auth_scores else 0.3

        # MFA bonus
        if fp.has_mfa:
            base_score = min(1.0, base_score + 0.2)

        # Multiple auth types bonus
        if len(fp.auth_types) > 1:
            base_score = min(1.0, base_score + 0.1)

        self._notes.append(f"Auth complexity: {fp.auth_types} -> score: {base_score:.2f}")
        return base_score

    def _calculate_api_surface_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on API surface area."""
        endpoint_count = fp.api_endpoints

        if endpoint_count == 0:
            base_score = 0.1
        elif endpoint_count <= self.config.api_count_low:
            base_score = endpoint_count / self.config.api_count_low * 0.3
        elif endpoint_count <= self.config.api_count_medium:
            base_score = 0.3 + (endpoint_count - self.config.api_count_low) / (
                self.config.api_count_medium - self.config.api_count_low
            ) * 0.3
        elif endpoint_count <= self.config.api_count_high:
            base_score = 0.6 + (endpoint_count - self.config.api_count_medium) / (
                self.config.api_count_high - self.config.api_count_medium
            ) * 0.2
        else:
            base_score = 0.8 + min(0.2, (endpoint_count - self.config.api_count_high) / 200 * 0.2)

        # GraphQL bonus (significantly increases attack surface)
        if fp.has_graphql:
            base_score = min(1.0, base_score + 0.25)
            if fp.has_graphql_introspection:
                base_score = min(1.0, base_score + 0.1)

        # WebSocket bonus
        if fp.has_websocket:
            base_score = min(1.0, base_score + 0.1)

        self._notes.append(f"API surface: {endpoint_count} endpoints -> score: {base_score:.2f}")
        return min(1.0, base_score)

    def _calculate_waf_complexity_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on WAF/CDN presence."""
        score = 0.0

        if fp.has_waf:
            score += 0.5
            # Some WAFs are harder to bypass
            hard_wafs = {"cloudflare", "akamai", "imperva", "f5", "fortinet"}
            if fp.waf_type and fp.waf_type.lower() in hard_wafs:
                score += 0.2

        if fp.cdn:
            score += 0.2

        if fp.has_rate_limiting:
            score += 0.1

        self._notes.append(f"WAF/CDN: waf={fp.has_waf}, cdn={fp.cdn} -> score: {score:.2f}")
        return min(1.0, score)

    def _calculate_data_sensitivity_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on data sensitivity indicators."""
        score = fp.data_sensitivity_score

        if fp.handles_pii:
            score = max(score, 0.7)
        if fp.handles_payment:
            score = max(score, 0.9)
        if fp.handles_healthcare:
            score = max(score, 0.95)

        self._notes.append(f"Data sensitivity: {score:.2f}")
        return min(1.0, score)

    def _calculate_cloud_complexity_score(self, fp: TargetFingerprint) -> float:
        """Calculate score based on cloud infrastructure complexity."""
        score = 0.0

        if fp.cloud_provider:
            score += 0.4

        if fp.is_containerized:
            score += 0.2

        if fp.has_serverless:
            score += 0.3

        # Check for cloud tech in technologies
        cloud_tech = {"kubernetes", "k8s", "docker", "aws", "azure", "gcp", "lambda"}
        found_cloud = [t for t in fp.technologies if t.lower() in cloud_tech]
        score += min(0.2, len(found_cloud) * 0.1)

        self._notes.append(f"Cloud complexity: provider={fp.cloud_provider} -> score: {score:.2f}")
        return min(1.0, score)

    def _determine_complexity_level(self, score: float) -> ComplexityLevel:
        """Determine complexity level from score."""
        if score <= 20:
            return ComplexityLevel.MINIMAL
        elif score <= 40:
            return ComplexityLevel.LOW
        elif score <= 60:
            return ComplexityLevel.MEDIUM
        elif score <= 80:
            return ComplexityLevel.HIGH
        else:
            return ComplexityLevel.CRITICAL

    def _determine_security_posture(self, fp: TargetFingerprint) -> SecurityPosture:
        """Determine security posture from fingerprint."""
        hardening_indicators = 0
        permissive_indicators = 0

        # Hardening indicators
        if fp.has_waf:
            hardening_indicators += 1
        if fp.has_rate_limiting:
            hardening_indicators += 1
        if fp.has_csrf_protection:
            hardening_indicators += 1
        if fp.has_mfa:
            hardening_indicators += 1
        if len(fp.security_headers) >= 4:
            hardening_indicators += 1

        # Permissive indicators
        if not fp.auth_types or "none" in [a.lower() for a in fp.auth_types]:
            permissive_indicators += 1
        if fp.has_graphql_introspection:
            permissive_indicators += 1
        if 23 in fp.open_ports or 21 in fp.open_ports:  # Telnet, FTP
            permissive_indicators += 1
        if len(fp.outdated_components) > 0:
            permissive_indicators += 1
        if len(fp.known_vulnerabilities) > 0:
            permissive_indicators += 2

        if hardening_indicators >= 3 and permissive_indicators == 0:
            return SecurityPosture.HARDENED
        elif permissive_indicators >= 2:
            return SecurityPosture.PERMISSIVE
        elif hardening_indicators > 0 or permissive_indicators > 0:
            return SecurityPosture.STANDARD
        else:
            return SecurityPosture.UNKNOWN

    def _generate_module_recommendations(self, fp: TargetFingerprint) -> list[str]:
        """Generate recommended prompt modules based on fingerprint."""
        modules: set[str] = set()

        # Check conditions for module recommendations
        if "jwt" in [a.lower() for a in fp.auth_types]:
            modules.update(MODULE_RECOMMENDATIONS.get("has_jwt", []))

        if "oauth2" in [a.lower() for a in fp.auth_types]:
            modules.update(MODULE_RECOMMENDATIONS.get("has_oauth", []))

        if fp.has_graphql:
            modules.update(MODULE_RECOMMENDATIONS.get("has_graphql", []))

        if fp.has_websocket:
            modules.update(MODULE_RECOMMENDATIONS.get("has_websocket", []))

        if fp.databases:
            modules.update(MODULE_RECOMMENDATIONS.get("has_database", []))

        if fp.has_file_upload:
            modules.update(MODULE_RECOMMENDATIONS.get("has_file_upload", []))

        if fp.api_endpoints > 0:
            modules.update(MODULE_RECOMMENDATIONS.get("has_api", []))

        if fp.has_xml_processing:
            modules.update(MODULE_RECOMMENDATIONS.get("has_xml", []))

        if fp.cloud_provider or fp.is_containerized:
            modules.update(MODULE_RECOMMENDATIONS.get("has_cloud", []))

        # Default modules if nothing specific detected
        if not modules:
            modules = {"reconnaissance", "business_logic", "idor"}

        # Limit to 5 modules
        return sorted(modules)[:5]

    def _generate_priority_vulnerabilities(
        self, fp: TargetFingerprint, score: float
    ) -> list[str]:
        """Generate priority vulnerability types to test."""
        vulns: list[str] = []

        # High-priority based on fingerprint
        if fp.databases:
            vulns.append("SQL Injection")

        if fp.has_graphql:
            vulns.extend(["GraphQL Injection", "IDOR via GraphQL"])

        if "jwt" in [a.lower() for a in fp.auth_types]:
            vulns.append("JWT Vulnerabilities")

        if fp.has_file_upload:
            vulns.append("Unrestricted File Upload")

        if fp.api_endpoints > 0:
            vulns.extend(["IDOR", "Broken Access Control"])

        if fp.has_xml_processing:
            vulns.append("XXE")

        if not fp.has_csrf_protection and fp.has_user_input:
            vulns.append("CSRF")

        # Add XSS if there's user input
        if fp.has_user_input or fp.has_search:
            vulns.append("XSS")

        # Add SSRF for high complexity targets
        if score >= 60 and (fp.cloud_provider or fp.has_json_api):
            vulns.append("SSRF")

        # Deduplicate and limit
        seen: set[str] = set()
        unique_vulns = []
        for v in vulns:
            if v not in seen:
                seen.add(v)
                unique_vulns.append(v)

        return unique_vulns[:8]

    def _calculate_timeout_multiplier(
        self, score: float, fp: TargetFingerprint
    ) -> float:
        """Calculate timeout multiplier based on complexity."""
        # Base multiplier from score
        base = 1.0 + (score / 100)

        # WAF increases timeout needs
        if fp.has_waf:
            base += 0.3

        # Rate limiting increases timeout needs
        if fp.has_rate_limiting:
            base += 0.2

        # Large API surface increases timeout
        if fp.api_endpoints > 100:
            base += 0.2

        return min(3.0, base)

    def _determine_safe_mode(self, fp: TargetFingerprint) -> bool:
        """Determine if safe mode should be suggested."""
        # Always suggest safe mode unless explicitly permissive indicators
        if fp.handles_payment or fp.handles_healthcare:
            return True

        if fp.has_waf or fp.has_rate_limiting:
            return True

        # Production indicators
        prod_indicators = ["prod", "production", "live"]
        if fp.target_url:
            url_lower = fp.target_url.lower()
            if any(ind in url_lower for ind in prod_indicators):
                return True

        return True  # Default to safe

    def _calculate_max_parallel(self, score: float, fp: TargetFingerprint) -> int:
        """Calculate maximum parallel test count."""
        # Start with base parallel count
        base = 10

        # Reduce for WAF/rate limiting
        if fp.has_waf:
            base = min(base, 5)
        if fp.has_rate_limiting:
            base = min(base, 3)

        # Reduce for high-sensitivity targets
        if fp.handles_payment or fp.handles_healthcare:
            base = min(base, 3)

        # Reduce for high complexity
        if score >= 80:
            base = min(base, 5)

        return max(1, base)


def compute_tci(
    fingerprint: TargetFingerprint,
    config: TCIConfig | None = None,
) -> TCIResult:
    """Convenience function to compute TCI from fingerprint.

    Args:
        fingerprint: Target fingerprint data
        config: Optional TCI configuration

    Returns:
        TCIResult with score and recommendations

    Example:
        >>> fp = TargetFingerprint(
        ...     open_ports=[80, 443, 8080],
        ...     technologies=["nginx", "python", "postgresql"],
        ...     auth_types=["jwt"],
        ... )
        >>> result = compute_tci(fp)
        >>> print(result.score)  # e.g., 65.4
    """
    calculator = TargetComplexityIndex(config)
    return calculator.calculate(fingerprint)
