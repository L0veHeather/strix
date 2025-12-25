"""Strix Scan Engine.

This module provides the core scanning engine that coordinates
plugins, manages scan phases, and collects results.
"""

from strix.engine.scan_engine import ScanEngine, ScanConfig
from strix.engine.phase_manager import PhaseManager, PhaseResult
from strix.engine.result_collector import ResultCollector
from strix.engine.event_bus import EventBus, EventHandler, EventType

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

