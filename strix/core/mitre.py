"""MITRE ATT&CK Framework Integration.

Provides comprehensive mapping of security testing actions to MITRE ATT&CK
Tactics, Techniques, and Procedures (TTPs) for threat intelligence tagging.

Supports:
- Enterprise ATT&CK matrix (v14)
- Mobile ATT&CK matrix
- ICS ATT&CK matrix
- IoC (Indicators of Compromise) classification
- TTP-based engagement planning

Usage:
    from strix.core.mitre import (
        get_technique,
        get_techniques_for_tactic,
        map_action_to_ttps,
        MITRETactic,
        MITRETechnique,
    )

    # Get specific technique
    technique = get_technique("T1059.001")
    print(f"{technique.name}: {technique.description}")

    # Map action to TTPs
    ttps = map_action_to_ttps("powershell_execution")
    for ttp in ttps:
        print(f"[{ttp.technique_id}] {ttp.name}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class MITRETactic(str, Enum):
    """MITRE ATT&CK Tactics (Enterprise)."""

    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class MITREPlatform(str, Enum):
    """Target platforms for techniques."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD = "cloud"
    AZURE_AD = "azure_ad"
    OFFICE_365 = "office_365"
    SAAS = "saas"
    ICS = "ics"
    NETWORK = "network"
    CONTAINERS = "containers"
    PRE = "pre"  # Pre-compromise


class IoCSeverity(str, Enum):
    """Severity levels for Indicators of Compromise."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class IoCType(str, Enum):
    """Types of Indicators of Compromise."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    FILE_PATH = "file_path"
    PROCESS_NAME = "process_name"
    COMMAND_LINE = "command_line"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    MUTEX = "mutex"
    PIPE_NAME = "pipe_name"
    SERVICE_NAME = "service_name"


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK Technique."""

    technique_id: str  # e.g., "T1059.001"
    name: str
    description: str
    tactic: MITRETactic
    platforms: list[MITREPlatform] = field(default_factory=list)
    permissions_required: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    detection: str = ""
    mitigation: str = ""
    url: str = ""
    sub_techniques: list[str] = field(default_factory=list)
    is_sub_technique: bool = False
    parent_technique: str | None = None

    def __post_init__(self) -> None:
        """Set URL if not provided."""
        if not self.url:
            base_id = self.technique_id.split(".")[0]
            self.url = f"https://attack.mitre.org/techniques/{base_id}/"
            if "." in self.technique_id:
                sub_id = self.technique_id.split(".")[1]
                self.url = f"https://attack.mitre.org/techniques/{base_id}/{sub_id}/"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic.value,
            "tactic_name": self.tactic.name.replace("_", " ").title(),
            "platforms": [p.value for p in self.platforms],
            "permissions_required": self.permissions_required,
            "data_sources": self.data_sources,
            "detection": self.detection,
            "mitigation": self.mitigation,
            "url": self.url,
            "is_sub_technique": self.is_sub_technique,
            "parent_technique": self.parent_technique,
        }


@dataclass
class IoC:
    """Indicator of Compromise."""

    ioc_type: IoCType
    value: str
    severity: IoCSeverity
    description: str = ""
    related_techniques: list[str] = field(default_factory=list)
    confidence: float = 0.5  # 0.0 - 1.0
    tags: list[str] = field(default_factory=list)
    source: str = ""
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "severity": self.severity.value,
            "description": self.description,
            "related_techniques": self.related_techniques,
            "confidence": self.confidence,
            "tags": self.tags,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class TTPMapping:
    """Maps an action/behavior to TTPs."""

    action: str
    description: str
    techniques: list[MITRETechnique]
    iocs: list[IoC] = field(default_factory=list)
    detection_rules: list[str] = field(default_factory=list)
    risk_score: float = 0.5  # 0.0 - 1.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action": self.action,
            "description": self.description,
            "techniques": [t.to_dict() for t in self.techniques],
            "iocs": [i.to_dict() for i in self.iocs],
            "detection_rules": self.detection_rules,
            "risk_score": self.risk_score,
        }


# =============================================================================
# MITRE ATT&CK Technique Database
# =============================================================================

TECHNIQUES: dict[str, MITRETechnique] = {
    # Reconnaissance (TA0043)
    "T1595": MITRETechnique(
        technique_id="T1595",
        name="Active Scanning",
        description="Adversaries may execute active reconnaissance scans to gather information.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
        data_sources=["Network Traffic"],
        sub_techniques=["T1595.001", "T1595.002", "T1595.003"],
    ),
    "T1595.001": MITRETechnique(
        technique_id="T1595.001",
        name="Active Scanning: Scanning IP Blocks",
        description="Scan IP blocks to gather victim network information.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
        is_sub_technique=True,
        parent_technique="T1595",
    ),
    "T1595.002": MITRETechnique(
        technique_id="T1595.002",
        name="Active Scanning: Vulnerability Scanning",
        description="Scan victims for vulnerabilities that can be used during targeting.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
        is_sub_technique=True,
        parent_technique="T1595",
    ),
    "T1592": MITRETechnique(
        technique_id="T1592",
        name="Gather Victim Host Information",
        description="Gather information about the victim's hosts.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
    ),
    "T1589": MITRETechnique(
        technique_id="T1589",
        name="Gather Victim Identity Information",
        description="Gather information about the victim's identity.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
        sub_techniques=["T1589.001", "T1589.002", "T1589.003"],
    ),
    "T1590": MITRETechnique(
        technique_id="T1590",
        name="Gather Victim Network Information",
        description="Gather information about the victim's networks.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
    ),
    "T1593": MITRETechnique(
        technique_id="T1593",
        name="Search Open Websites/Domains",
        description="Search freely available websites and/or domains for victim information.",
        tactic=MITRETactic.RECONNAISSANCE,
        platforms=[MITREPlatform.PRE],
    ),

    # Initial Access (TA0001)
    "T1190": MITRETechnique(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        description="Adversaries may exploit vulnerabilities in internet-facing systems.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CONTAINERS],
        data_sources=["Application Log", "Network Traffic"],
        detection="Monitor application logs for abnormal behavior.",
    ),
    "T1133": MITRETechnique(
        technique_id="T1133",
        name="External Remote Services",
        description="Adversaries may leverage external-facing remote services to gain access.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1078": MITRETechnique(
        technique_id="T1078",
        name="Valid Accounts",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1078.001", "T1078.002", "T1078.003", "T1078.004"],
    ),
    "T1078.004": MITRETechnique(
        technique_id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        description="Adversaries may obtain and abuse credentials of cloud accounts.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.CLOUD, MITREPlatform.AZURE_AD, MITREPlatform.OFFICE_365, MITREPlatform.SAAS],
        is_sub_technique=True,
        parent_technique="T1078",
    ),
    "T1566": MITRETechnique(
        technique_id="T1566",
        name="Phishing",
        description="Adversaries may send phishing messages to gain access to victim systems.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.SAAS],
        sub_techniques=["T1566.001", "T1566.002", "T1566.003"],
    ),

    # Execution (TA0002)
    "T1059": MITRETechnique(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007"],
    ),
    "T1059.001": MITRETechnique(
        technique_id="T1059.001",
        name="Command and Scripting Interpreter: PowerShell",
        description="Adversaries may abuse PowerShell commands and scripts for execution.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.WINDOWS],
        data_sources=["Command", "Module", "Process", "Script"],
        detection="Monitor PowerShell execution, especially encoded commands and suspicious modules.",
        is_sub_technique=True,
        parent_technique="T1059",
    ),
    "T1059.003": MITRETechnique(
        technique_id="T1059.003",
        name="Command and Scripting Interpreter: Windows Command Shell",
        description="Adversaries may abuse the Windows command shell for execution.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.WINDOWS],
        is_sub_technique=True,
        parent_technique="T1059",
    ),
    "T1059.004": MITRETechnique(
        technique_id="T1059.004",
        name="Command and Scripting Interpreter: Unix Shell",
        description="Adversaries may abuse Unix shell commands and scripts for execution.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.LINUX, MITREPlatform.MACOS],
        is_sub_technique=True,
        parent_technique="T1059",
    ),
    "T1203": MITRETechnique(
        technique_id="T1203",
        name="Exploitation for Client Execution",
        description="Adversaries may exploit software vulnerabilities in client applications.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1047": MITRETechnique(
        technique_id="T1047",
        name="Windows Management Instrumentation",
        description="Adversaries may abuse WMI to execute malicious commands and payloads.",
        tactic=MITRETactic.EXECUTION,
        platforms=[MITREPlatform.WINDOWS],
    ),

    # Persistence (TA0003)
    "T1136": MITRETechnique(
        technique_id="T1136",
        name="Create Account",
        description="Adversaries may create an account to maintain access to victim systems.",
        tactic=MITRETactic.PERSISTENCE,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1136.001", "T1136.002", "T1136.003"],
    ),
    "T1098": MITRETechnique(
        technique_id="T1098",
        name="Account Manipulation",
        description="Adversaries may manipulate accounts to maintain access to victim systems.",
        tactic=MITRETactic.PERSISTENCE,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
    ),
    "T1505": MITRETechnique(
        technique_id="T1505",
        name="Server Software Component",
        description="Adversaries may abuse legitimate server software components to establish persistence.",
        tactic=MITRETactic.PERSISTENCE,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1505.001", "T1505.002", "T1505.003"],
    ),
    "T1505.003": MITRETechnique(
        technique_id="T1505.003",
        name="Server Software Component: Web Shell",
        description="Adversaries may backdoor web servers with web shells.",
        tactic=MITRETactic.PERSISTENCE,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        is_sub_technique=True,
        parent_technique="T1505",
    ),

    # Privilege Escalation (TA0004)
    "T1068": MITRETechnique(
        technique_id="T1068",
        name="Exploitation for Privilege Escalation",
        description="Adversaries may exploit software vulnerabilities to elevate privileges.",
        tactic=MITRETactic.PRIVILEGE_ESCALATION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CONTAINERS],
        permissions_required=["User"],
    ),
    "T1548": MITRETechnique(
        technique_id="T1548",
        name="Abuse Elevation Control Mechanism",
        description="Adversaries may circumvent mechanisms designed to control elevate privileges.",
        tactic=MITRETactic.PRIVILEGE_ESCALATION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1548.001", "T1548.002", "T1548.003"],
    ),
    "T1548.002": MITRETechnique(
        technique_id="T1548.002",
        name="Abuse Elevation Control Mechanism: Bypass User Account Control",
        description="Adversaries may bypass UAC mechanisms to elevate process privileges.",
        tactic=MITRETactic.PRIVILEGE_ESCALATION,
        platforms=[MITREPlatform.WINDOWS],
        is_sub_technique=True,
        parent_technique="T1548",
    ),
    "T1134": MITRETechnique(
        technique_id="T1134",
        name="Access Token Manipulation",
        description="Adversaries may modify access tokens to operate under different security contexts.",
        tactic=MITRETactic.PRIVILEGE_ESCALATION,
        platforms=[MITREPlatform.WINDOWS],
    ),

    # Defense Evasion (TA0005)
    "T1070": MITRETechnique(
        technique_id="T1070",
        name="Indicator Removal",
        description="Adversaries may delete or modify artifacts generated to remove evidence.",
        tactic=MITRETactic.DEFENSE_EVASION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1070.001", "T1070.002", "T1070.003", "T1070.004"],
    ),
    "T1562": MITRETechnique(
        technique_id="T1562",
        name="Impair Defenses",
        description="Adversaries may maliciously modify components to hinder or disable defenses.",
        tactic=MITRETactic.DEFENSE_EVASION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1562.001", "T1562.002", "T1562.004"],
    ),
    "T1027": MITRETechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        description="Adversaries may make payloads and files difficult to discover or analyze.",
        tactic=MITRETactic.DEFENSE_EVASION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),

    # Credential Access (TA0006)
    "T1110": MITRETechnique(
        technique_id="T1110",
        name="Brute Force",
        description="Adversaries may use brute force techniques to gain access to accounts.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
    ),
    "T1110.001": MITRETechnique(
        technique_id="T1110.001",
        name="Brute Force: Password Guessing",
        description="Adversaries may guess passwords to attempt access to accounts.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        is_sub_technique=True,
        parent_technique="T1110",
    ),
    "T1110.003": MITRETechnique(
        technique_id="T1110.003",
        name="Brute Force: Password Spraying",
        description="Adversaries may use a single or small list of passwords against many accounts.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        is_sub_technique=True,
        parent_technique="T1110",
    ),
    "T1555": MITRETechnique(
        technique_id="T1555",
        name="Credentials from Password Stores",
        description="Adversaries may search for common password storage locations.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1552": MITRETechnique(
        technique_id="T1552",
        name="Unsecured Credentials",
        description="Adversaries may search compromised systems for insecurely stored credentials.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1552.001", "T1552.002", "T1552.004", "T1552.005"],
    ),
    "T1539": MITRETechnique(
        technique_id="T1539",
        name="Steal Web Session Cookie",
        description="Adversaries may steal web application session cookies.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.SAAS],
    ),
    "T1528": MITRETechnique(
        technique_id="T1528",
        name="Steal Application Access Token",
        description="Adversaries may steal application access tokens.",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        platforms=[MITREPlatform.CLOUD, MITREPlatform.SAAS, MITREPlatform.OFFICE_365],
    ),

    # Discovery (TA0007)
    "T1087": MITRETechnique(
        technique_id="T1087",
        name="Account Discovery",
        description="Adversaries may attempt to get a listing of accounts on a system or domain.",
        tactic=MITRETactic.DISCOVERY,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
        sub_techniques=["T1087.001", "T1087.002", "T1087.003", "T1087.004"],
    ),
    "T1046": MITRETechnique(
        technique_id="T1046",
        name="Network Service Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
        tactic=MITRETactic.DISCOVERY,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
    ),
    "T1018": MITRETechnique(
        technique_id="T1018",
        name="Remote System Discovery",
        description="Adversaries may attempt to get a listing of other systems on a network.",
        tactic=MITRETactic.DISCOVERY,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),

    # Lateral Movement (TA0008)
    "T1021": MITRETechnique(
        technique_id="T1021",
        name="Remote Services",
        description="Adversaries may use valid accounts to log into remote services.",
        tactic=MITRETactic.LATERAL_MOVEMENT,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006"],
    ),
    "T1021.001": MITRETechnique(
        technique_id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        description="Adversaries may use RDP to connect to a remote system.",
        tactic=MITRETactic.LATERAL_MOVEMENT,
        platforms=[MITREPlatform.WINDOWS],
        is_sub_technique=True,
        parent_technique="T1021",
    ),
    "T1021.004": MITRETechnique(
        technique_id="T1021.004",
        name="Remote Services: SSH",
        description="Adversaries may use SSH to connect to remote systems.",
        tactic=MITRETactic.LATERAL_MOVEMENT,
        platforms=[MITREPlatform.LINUX, MITREPlatform.MACOS],
        is_sub_technique=True,
        parent_technique="T1021",
    ),
    "T1210": MITRETechnique(
        technique_id="T1210",
        name="Exploitation of Remote Services",
        description="Adversaries may exploit remote services to gain unauthorized access.",
        tactic=MITRETactic.LATERAL_MOVEMENT,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),

    # Collection (TA0009)
    "T1005": MITRETechnique(
        technique_id="T1005",
        name="Data from Local System",
        description="Adversaries may search local system sources to find files of interest.",
        tactic=MITRETactic.COLLECTION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1530": MITRETechnique(
        technique_id="T1530",
        name="Data from Cloud Storage",
        description="Adversaries may access data from improperly secured cloud storage.",
        tactic=MITRETactic.COLLECTION,
        platforms=[MITREPlatform.CLOUD, MITREPlatform.SAAS],
    ),
    "T1213": MITRETechnique(
        technique_id="T1213",
        name="Data from Information Repositories",
        description="Adversaries may leverage information repositories to mine valuable data.",
        tactic=MITRETactic.COLLECTION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.SAAS],
    ),

    # Command and Control (TA0011)
    "T1071": MITRETechnique(
        technique_id="T1071",
        name="Application Layer Protocol",
        description="Adversaries may communicate using OSI application layer protocols.",
        tactic=MITRETactic.COMMAND_AND_CONTROL,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        sub_techniques=["T1071.001", "T1071.002", "T1071.003", "T1071.004"],
    ),
    "T1071.001": MITRETechnique(
        technique_id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        description="Adversaries may communicate using HTTP/HTTPS protocols.",
        tactic=MITRETactic.COMMAND_AND_CONTROL,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
        is_sub_technique=True,
        parent_technique="T1071",
    ),
    "T1105": MITRETechnique(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        description="Adversaries may transfer tools or other files from an external system.",
        tactic=MITRETactic.COMMAND_AND_CONTROL,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),

    # Exfiltration (TA0010)
    "T1041": MITRETechnique(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        description="Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        tactic=MITRETactic.EXFILTRATION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1567": MITRETechnique(
        technique_id="T1567",
        name="Exfiltration Over Web Service",
        description="Adversaries may use existing web services to exfiltrate data.",
        tactic=MITRETactic.EXFILTRATION,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),

    # Impact (TA0040)
    "T1486": MITRETechnique(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        description="Adversaries may encrypt data on target systems to interrupt availability.",
        tactic=MITRETactic.IMPACT,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1565": MITRETechnique(
        technique_id="T1565",
        name="Data Manipulation",
        description="Adversaries may modify data to impact integrity or hide activity.",
        tactic=MITRETactic.IMPACT,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS],
    ),
    "T1498": MITRETechnique(
        technique_id="T1498",
        name="Network Denial of Service",
        description="Adversaries may perform Network DoS attacks to degrade availability.",
        tactic=MITRETactic.IMPACT,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX, MITREPlatform.MACOS, MITREPlatform.CLOUD],
    ),

    # Web-specific techniques
    "T1190.001": MITRETechnique(
        technique_id="T1190.001",
        name="SQL Injection",
        description="Adversaries may exploit SQL injection vulnerabilities in web applications.",
        tactic=MITRETactic.INITIAL_ACCESS,
        platforms=[MITREPlatform.WINDOWS, MITREPlatform.LINUX],
        is_sub_technique=True,
        parent_technique="T1190",
    ),
}


# =============================================================================
# Action to TTP Mappings
# =============================================================================

ACTION_TTP_MAPPINGS: dict[str, list[str]] = {
    # Reconnaissance actions
    "port_scanning": ["T1595.001", "T1046"],
    "vulnerability_scanning": ["T1595.002"],
    "service_enumeration": ["T1046", "T1592"],
    "directory_bruteforce": ["T1595", "T1087"],
    "subdomain_enumeration": ["T1590", "T1593"],
    "osint_gathering": ["T1589", "T1593"],
    "network_mapping": ["T1590", "T1018"],

    # Credential attacks
    "password_bruteforce": ["T1110.001"],
    "password_spraying": ["T1110.003"],
    "credential_stuffing": ["T1110.004"],
    "credential_harvesting": ["T1552", "T1555"],
    "session_hijacking": ["T1539", "T1528"],
    "token_theft": ["T1528"],
    "jwt_attack": ["T1528", "T1539"],

    # Web application attacks
    "sql_injection": ["T1190"],
    "xss_attack": ["T1059.007", "T1539"],
    "xxe_attack": ["T1190", "T1005"],
    "ssrf_attack": ["T1190", "T1046"],
    "csrf_attack": ["T1190"],
    "idor_attack": ["T1190", "T1087"],
    "file_upload_attack": ["T1190", "T1505.003"],
    "deserialization_attack": ["T1190", "T1059"],
    "graphql_injection": ["T1190"],
    "api_abuse": ["T1190", "T1078"],

    # Execution
    "powershell_execution": ["T1059.001"],
    "cmd_execution": ["T1059.003"],
    "bash_execution": ["T1059.004"],
    "python_execution": ["T1059.006"],
    "wmi_execution": ["T1047"],
    "remote_code_execution": ["T1203", "T1190"],

    # Privilege escalation
    "privilege_escalation": ["T1068", "T1548"],
    "uac_bypass": ["T1548.002"],
    "sudo_abuse": ["T1548.003"],
    "token_manipulation": ["T1134"],
    "kernel_exploit": ["T1068"],

    # Persistence
    "webshell_deployment": ["T1505.003"],
    "account_creation": ["T1136"],
    "backdoor_installation": ["T1505", "T1543"],
    "scheduled_task": ["T1053"],

    # Defense evasion
    "log_tampering": ["T1070"],
    "security_bypass": ["T1562"],
    "obfuscation": ["T1027"],

    # Lateral movement
    "rdp_access": ["T1021.001"],
    "ssh_access": ["T1021.004"],
    "pass_the_hash": ["T1550.002"],
    "service_exploitation": ["T1210"],

    # Collection & Exfiltration
    "data_collection": ["T1005", "T1213"],
    "cloud_data_access": ["T1530"],
    "data_exfiltration": ["T1041", "T1567"],
}


# =============================================================================
# Helper Functions
# =============================================================================


def get_technique(technique_id: str) -> MITRETechnique | None:
    """Get a technique by its ID.

    Args:
        technique_id: MITRE technique ID (e.g., "T1059.001")

    Returns:
        MITRETechnique if found, None otherwise
    """
    return TECHNIQUES.get(technique_id)


def get_all_techniques() -> dict[str, MITRETechnique]:
    """Get all registered techniques."""
    return TECHNIQUES.copy()


def get_techniques_for_tactic(tactic: MITRETactic) -> list[MITRETechnique]:
    """Get all techniques for a specific tactic.

    Args:
        tactic: MITRE tactic

    Returns:
        List of techniques under that tactic
    """
    return [t for t in TECHNIQUES.values() if t.tactic == tactic]


def get_techniques_for_platform(platform: MITREPlatform) -> list[MITRETechnique]:
    """Get all techniques applicable to a platform.

    Args:
        platform: Target platform

    Returns:
        List of applicable techniques
    """
    return [t for t in TECHNIQUES.values() if platform in t.platforms]


def map_action_to_ttps(action: str) -> list[MITRETechnique]:
    """Map a security testing action to relevant TTPs.

    Args:
        action: Action identifier (e.g., "sql_injection", "powershell_execution")

    Returns:
        List of relevant MITRETechnique objects
    """
    technique_ids = ACTION_TTP_MAPPINGS.get(action.lower(), [])
    techniques = []

    for tid in technique_ids:
        technique = TECHNIQUES.get(tid)
        if technique:
            techniques.append(technique)

    return techniques


def get_ttps_for_vulnerability(vuln_type: str) -> list[MITRETechnique]:
    """Get TTPs associated with a vulnerability type.

    Args:
        vuln_type: Vulnerability type (e.g., "SQL Injection", "XSS")

    Returns:
        List of relevant techniques
    """
    vuln_mapping: dict[str, list[str]] = {
        "sql injection": ["T1190"],
        "sqli": ["T1190"],
        "xss": ["T1059.007", "T1539"],
        "cross-site scripting": ["T1059.007", "T1539"],
        "xxe": ["T1190", "T1005"],
        "xml external entity": ["T1190", "T1005"],
        "ssrf": ["T1190", "T1046"],
        "server-side request forgery": ["T1190", "T1046"],
        "csrf": ["T1190"],
        "cross-site request forgery": ["T1190"],
        "idor": ["T1190", "T1087"],
        "insecure direct object reference": ["T1190", "T1087"],
        "rce": ["T1203", "T1190"],
        "remote code execution": ["T1203", "T1190"],
        "file upload": ["T1190", "T1505.003"],
        "deserialization": ["T1190", "T1059"],
        "authentication bypass": ["T1078", "T1190"],
        "broken access control": ["T1078", "T1087"],
        "jwt": ["T1528", "T1539"],
        "graphql": ["T1190"],
        "api security": ["T1190", "T1078"],
    }

    vuln_lower = vuln_type.lower()
    technique_ids: list[str] = []

    for key, tids in vuln_mapping.items():
        if key in vuln_lower or vuln_lower in key:
            technique_ids.extend(tids)

    # Deduplicate
    seen: set[str] = set()
    unique_ids = []
    for tid in technique_ids:
        if tid not in seen:
            seen.add(tid)
            unique_ids.append(tid)

    return [TECHNIQUES[tid] for tid in unique_ids if tid in TECHNIQUES]


def create_ioc(
    ioc_type: IoCType,
    value: str,
    severity: IoCSeverity = IoCSeverity.MEDIUM,
    description: str = "",
    related_actions: list[str] | None = None,
) -> IoC:
    """Create an IoC with automatic TTP mapping.

    Args:
        ioc_type: Type of indicator
        value: The indicator value
        severity: Severity level
        description: Description of the IoC
        related_actions: Actions that may generate this IoC

    Returns:
        IoC with populated technique mappings
    """
    related_techniques: list[str] = []

    if related_actions:
        for action in related_actions:
            ttps = map_action_to_ttps(action)
            for ttp in ttps:
                if ttp.technique_id not in related_techniques:
                    related_techniques.append(ttp.technique_id)

    return IoC(
        ioc_type=ioc_type,
        value=value,
        severity=severity,
        description=description,
        related_techniques=related_techniques,
    )


def create_ttp_mapping(
    action: str,
    description: str,
    additional_techniques: list[str] | None = None,
) -> TTPMapping:
    """Create a TTP mapping for an action.

    Args:
        action: Action identifier
        description: Human-readable description
        additional_techniques: Extra technique IDs to include

    Returns:
        TTPMapping with all relevant techniques
    """
    techniques = map_action_to_ttps(action)

    if additional_techniques:
        for tid in additional_techniques:
            technique = TECHNIQUES.get(tid)
            if technique and technique not in techniques:
                techniques.append(technique)

    # Calculate risk score based on tactics
    tactic_risks = {
        MITRETactic.INITIAL_ACCESS: 0.8,
        MITRETactic.EXECUTION: 0.9,
        MITRETactic.PRIVILEGE_ESCALATION: 0.9,
        MITRETactic.CREDENTIAL_ACCESS: 0.85,
        MITRETactic.LATERAL_MOVEMENT: 0.8,
        MITRETactic.EXFILTRATION: 0.9,
        MITRETactic.IMPACT: 1.0,
    }

    risk_score = 0.5
    if techniques:
        scores = [tactic_risks.get(t.tactic, 0.5) for t in techniques]
        risk_score = max(scores)

    return TTPMapping(
        action=action,
        description=description,
        techniques=techniques,
        risk_score=risk_score,
    )


def get_tactic_display_name(tactic: MITRETactic) -> str:
    """Get human-readable tactic name."""
    return tactic.name.replace("_", " ").title()


def get_attack_chain(actions: list[str]) -> list[tuple[MITRETactic, list[MITRETechnique]]]:
    """Build an attack chain from a sequence of actions.

    Args:
        actions: List of action identifiers

    Returns:
        List of (tactic, techniques) tuples representing the attack chain
    """
    chain: dict[MITRETactic, list[MITRETechnique]] = {}

    for action in actions:
        techniques = map_action_to_ttps(action)
        for technique in techniques:
            if technique.tactic not in chain:
                chain[technique.tactic] = []
            if technique not in chain[technique.tactic]:
                chain[technique.tactic].append(technique)

    # Sort by tactic order (kill chain order)
    tactic_order = [
        MITRETactic.RECONNAISSANCE,
        MITRETactic.RESOURCE_DEVELOPMENT,
        MITRETactic.INITIAL_ACCESS,
        MITRETactic.EXECUTION,
        MITRETactic.PERSISTENCE,
        MITRETactic.PRIVILEGE_ESCALATION,
        MITRETactic.DEFENSE_EVASION,
        MITRETactic.CREDENTIAL_ACCESS,
        MITRETactic.DISCOVERY,
        MITRETactic.LATERAL_MOVEMENT,
        MITRETactic.COLLECTION,
        MITRETactic.COMMAND_AND_CONTROL,
        MITRETactic.EXFILTRATION,
        MITRETactic.IMPACT,
    ]

    result = []
    for tactic in tactic_order:
        if tactic in chain:
            result.append((tactic, chain[tactic]))

    return result
