"""Scan Phase Definitions and Task Queue Structures.

This module defines the deterministic scanning phases and task queue
structures that ensure scanning is controlled by code, not LLM decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import uuid


class ScanPhase(str, Enum):
    """Deterministic scanning phases executed in strict order.
    
    The scanner MUST progress through these phases sequentially.
    LLM agents are NOT allowed to skip phases or decide phase transitions.
    """
    
    ENUMERATION = "enumeration"           # Discover URLs, endpoints, parameters
    PARAM_EXPANSION = "param_expansion"   # Guess hidden parameters
    VULNERABILITY_TEST = "vulnerability_test"  # Test for vulnerabilities
    LLM_VERIFICATION = "llm_verification"  # LLM generates PoC, code validates
    DEEP_ANALYSIS = "deep_analysis"       # Chain vulnerabilities, exploit validation
    SUMMARY = "summary"                   # Final reporting ONLY


@dataclass
class ScanTask:
    """A single atomic scanning task.
    
    Tasks are added to the queue during scanning and executed sequentially.
    Finding a vulnerability does NOT remove tasks from the queue.
    """
    
    url: str
    method: str = "GET"
    parameters: dict[str, Any] = field(default_factory=dict)
    
    # Phase this task belongs to
    phase: ScanPhase = ScanPhase.ENUMERATION
    
    # Metadata
    source: str = "initial"  # Where did this task come from
    task_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    
    # Tracking what's been tested on this task
    tested_vulnerabilities: set[str] = field(default_factory=set)
    
    def signature(self) -> str:
        """Generate unique signature for deduplication."""
        # Sort params for consistency
        param_str = "&".join(f"{k}={v}" for k, v in sorted(self.parameters.items()))
        # Include phase and source to allow different types of testing on the same URL
        return f"{self.phase.value}:{self.source}:{self.method}:{self.url}:{param_str}"
    
    def __hash__(self) -> int:
        return hash(self.signature())
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScanTask):
            return False
        return self.signature() == other.signature()
