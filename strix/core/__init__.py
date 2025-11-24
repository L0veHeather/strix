"""Strix Core Module.

Core components for target analysis and adaptive scanning:
- TCI (Target Complexity Index): Compute complexity scores from target fingerprints
- Models: Data structures for fingerprints, TCI results, and scan plans
"""

from strix.core.tci import (
    TargetComplexityIndex,
    TCIConfig,
    TCIResult,
    TargetFingerprint,
    compute_tci,
)

__all__ = [
    "TargetComplexityIndex",
    "TCIConfig",
    "TCIResult",
    "TargetFingerprint",
    "compute_tci",
]
