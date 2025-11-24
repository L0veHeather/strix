"""Strix Core Module.

Core components for target analysis and adaptive scanning:
- TCI (Target Complexity Index): Compute complexity scores from target fingerprints
- MITRE ATT&CK: TTP mapping and IoC classification
- OWASP: Top 10 reference appendices (Web, API, LLM)
- Models: Data structures for fingerprints, TCI results, and scan plans
"""

from strix.core.mitre import (
    IoC,
    IoCType,
    IoCSeverity,
    MITREPlatform,
    MITRETactic,
    MITRETechnique,
    TTPMapping,
    create_ioc,
    create_ttp_mapping,
    get_attack_chain,
    get_technique,
    get_techniques_for_tactic,
    get_ttps_for_vulnerability,
    map_action_to_ttps,
)
from strix.core.owasp import (
    OWASPCategory,
    OWASPMapping,
    OWASPStandard,
    Severity,
    generate_report_appendix,
    get_api_top10,
    get_llm_top10,
    get_web_top10,
    map_vulnerability_to_owasp,
)
from strix.core.tci import (
    TargetComplexityIndex,
    TCIConfig,
    TCIResult,
    TargetFingerprint,
    compute_tci,
)

__all__ = [
    # TCI
    "TargetComplexityIndex",
    "TCIConfig",
    "TCIResult",
    "TargetFingerprint",
    "compute_tci",
    # MITRE ATT&CK
    "IoC",
    "IoCType",
    "IoCSeverity",
    "MITREPlatform",
    "MITRETactic",
    "MITRETechnique",
    "TTPMapping",
    "create_ioc",
    "create_ttp_mapping",
    "get_attack_chain",
    "get_technique",
    "get_techniques_for_tactic",
    "get_ttps_for_vulnerability",
    "map_action_to_ttps",
    # OWASP
    "OWASPCategory",
    "OWASPMapping",
    "OWASPStandard",
    "Severity",
    "generate_report_appendix",
    "get_api_top10",
    "get_llm_top10",
    "get_web_top10",
    "map_vulnerability_to_owasp",
]
