"""Trix Storage Layer.

SQLite-based storage for scans, findings, and plugin configurations.
"""

from trix.storage.database import Database, get_database
from trix.storage.models import (
    Scan,
    Vulnerability,
    PhaseResult,
    PluginConfig,
    ScanStatus,
    VulnerabilitySeverity,
)

__all__ = [
    "Database",
    "get_database",
    "Scan",
    "Vulnerability",
    "PhaseResult",
    "PluginConfig",
    "ScanStatus",
    "VulnerabilitySeverity",
]
