"""Trix Scan Engine.

This module provides the core scanning engine that coordinates
plugins, manages scan phases, and collects results.
"""

from trix.engine.scan_engine import ScanEngine, ScanConfig
from trix.engine.phase_manager import PhaseManager, PhaseResult
from trix.engine.result_collector import ResultCollector
from trix.engine.event_bus import EventBus, EventHandler, EventType

__all__ = [
    "ScanEngine",
    "ScanConfig",
    "PhaseManager",
    "PhaseResult",
    "ResultCollector",
    "EventBus",
    "EventHandler",
    "EventType",
]

