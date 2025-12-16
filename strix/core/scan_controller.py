"""Scan Controller - The single source of truth for scan state and flow.

This controller is the ONLY component allowed to:
1. Decide current scan phase
2. Decide when to transition phases
3. Decide when scanning is complete
4. Manage the task queue

LLM agents are NOT allowed to make these decisions.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

from strix.core.scan_phase import ScanPhase, ScanTask

logger = logging.getLogger(__name__)


class ScanController:
    """Controls scan execution flow deterministically.
    
    The controller enforces strict phase progression and manages
    the task queue. LLM agents only analyze results within their
    assigned phase - they cannot control the flow.
    """
    
    def __init__(self, initial_target: str, seed: int | None = None):
        self.initial_target = initial_target
        self.current_phase = ScanPhase.ENUMERATION
        
        # Seed for reproducibility
        self.seed = seed
        if seed is not None:
            import random
            random.seed(seed)
            logger.info(f"Scanner seeded with: {seed} for reproducible results")
        
        # HTTP methods to test (for method enumeration)
        self.http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        self.tested_methods: dict[str, set[str]] = {}  # url -> set of tested methods
        
        # Task Queue - FIFO execution
        self.task_queue: deque[ScanTask] = deque()
        
        # Deduplication tracking
        self.seen_task_signatures: set[str] = set()
        
        # Discovery tracking (for termination condition)
        self.discovered_urls: set[str] = {initial_target}
        self.discovered_params: set[str] = set()
        self.tested_vulnerability_types: set[str] = set()
        
        # Findings storage
        self.vulnerabilities: list[dict[str, Any]] = []
        self.suspected_vulnerabilities: list[dict[str, Any]] = []  # For LLM_VERIFICATION phase
        
        # Statistics
        self.tasks_executed = 0
        self.phase_tasks_executed: dict[ScanPhase, int] = {phase: 0 for phase in ScanPhase}
        
        # Initialize with first task
        initial_task = ScanTask(
            url=initial_target,
            method="GET",
            phase=ScanPhase.ENUMERATION,
            source="initial"
        )
        self.add_task(initial_task)
        
        logger.info(f"ScanController initialized for target: {initial_target}")
    
    def add_task(self, task: ScanTask) -> bool:
        """Add task to queue if not duplicate.
        
        Returns:
            True if task was added, False if duplicate
        """
        sig = task.signature()
        
        if sig in self.seen_task_signatures:
            logger.debug(f"Skipping duplicate task: {sig}")
            return False
        
        self.seen_task_signatures.add(sig)
        self.task_queue.append(task)
        logger.debug(f"Added task to queue: {task.method} {task.url} [phase={task.phase.value}]")
        return True
    
    def get_next_task(self) -> ScanTask | None:
        """Get next task from queue.
        
        Returns None if queue is empty.
        """
        if not self.task_queue:
            return None
        
        task = self.task_queue.popleft()
        self.tasks_executed += 1
        self.phase_tasks_executed[task.phase] += 1
        
        logger.info(f"Executing task {self.tasks_executed}: {task.method} {task.url} [phase={task.phase.value}]")
        return task
    
    def report_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Record a discovered vulnerability.
        
        IMPORTANT: Finding a vulnerability does NOT stop the scan.
        This only records the finding.
        """
        self.vulnerabilities.append(vuln)
        
        # Track vulnerability type for termination condition
        vuln_type = vuln.get("type", "unknown")
        self.tested_vulnerability_types.add(vuln_type)
        
        logger.warning(f"Vulnerability recorded: {vuln_type} at {vuln.get('url')}")
        logger.info(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        logger.info("Scan will continue until all tasks are completed.")
    
    def add_suspected_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Add a suspected vulnerability for LLM_VERIFICATION phase.
        
        These are vulnerabilities that need PoC validation.
        The LLM will generate PoC strategies, then code will validate.
        """
        self.suspected_vulnerabilities.append(vuln)
        logger.info(f"Suspected vulnerability queued for verification: {vuln.get('type')} at {vuln.get('url')}")
    
    def add_discovered_url(self, url: str) -> bool:
        """Track newly discovered URL.
        
        Returns:
            True if URL is new, False if already known
        """
        if url in self.discovered_urls:
            return False
        
        self.discovered_urls.add(url)
        logger.info(f"New URL discovered: {url} (total: {len(self.discovered_urls)})")
        return True
    
    def add_discovered_param(self, param: str) -> bool:
        """Track newly discovered parameter.
        
        Returns:
            True if parameter is new, False if already known
        """
        if param in self.discovered_params:
            return False
        
        self.discovered_params.add(param)
        logger.info(f"New parameter discovered: {param} (total: {len(self.discovered_params)})")
        return True
    
    def should_transition_phase(self) -> bool:
        """Check if current phase is complete and should transition.
        
        Phase transition occurs when:
        1. Task queue is empty
        2. No more work expected in current phase
        
        Returns:
            True if should transition to next phase
        """
        if self.task_queue:
            # Still have tasks, don't transition
            return False
        
        # Queue empty - check if we can move to next phase
        logger.info(f"Phase {self.current_phase.value} queue empty, checking for transition")
        return True
    
    def transition_to_next_phase(self) -> bool:
        """Transition to next phase in the sequence.
        
        Returns:
            True if transitioned, False if already in final phase
        """
        phase_order = [
            ScanPhase.ENUMERATION,
            ScanPhase.PARAM_EXPANSION,
            ScanPhase.VULNERABILITY_TEST,
            ScanPhase.LLM_VERIFICATION,  # NEW: PoC generation and validation
            ScanPhase.DEEP_ANALYSIS,
            ScanPhase.SUMMARY
        ]
        
        current_idx = phase_order.index(self.current_phase)
        
        if current_idx >= len(phase_order) - 1:
            # Already in SUMMARY phase
            return False
        
        next_phase = phase_order[current_idx + 1]
        
        logger.info(f"=== PHASE TRANSITION: {self.current_phase.value} -> {next_phase.value} ===")
        self.current_phase = next_phase
        
        # Initialize next phase tasks
        self._initialize_phase_tasks(next_phase)
        
        return True
    
    def _initialize_phase_tasks(self, phase: ScanPhase) -> None:
        """Generate initial tasks for a new phase."""
        if phase == ScanPhase.PARAM_EXPANSION:
            # Create param expansion tasks for each discovered URL
            for url in self.discovered_urls:
                task = ScanTask(
                    url=url,
                    method="GET",
                    phase=ScanPhase.PARAM_EXPANSION,
                    source="phase_init"
                )
                self.add_task(task)
            
            logger.info(f"Initialized {len(self.discovered_urls)} param expansion tasks")
        
        elif phase == ScanPhase.VULNERABILITY_TEST:
            # NEW: HTTP method enumeration - test different methods on URLs
            for url in self.discovered_urls:
                if url not in self.tested_methods:
                    self.tested_methods[url] = set()
                
                for method in self.http_methods:
                    if method not in self.tested_methods[url]:
                        # Create method test task
                        method_task = ScanTask(
                            url=url,
                            method=method,
                            phase=ScanPhase.VULNERABILITY_TEST,
                            source=f"method_enum:{method}"
                        )
                        self.add_task(method_task)
                        self.tested_methods[url].add(method)
            
            # Create vuln test tasks for URLs with discovered params
            vuln_types = ["xss", "sql_injection", "ssrf", "xxe", "rce"]
            
            for url in self.discovered_urls:
                for vuln_type in vuln_types:
                    task = ScanTask(
                        url=url,
                        method="GET",
                        phase=ScanPhase.VULNERABILITY_TEST,
                        source=f"vuln_test:{vuln_type}"
                    )
                    self.add_task(task)
            
            logger.info(f"Initialized {len(self.task_queue)} vulnerability test tasks")
        
        elif phase == ScanPhase.LLM_VERIFICATION:
            # NEW: Create verification tasks for suspected vulnerabilities
            # Only verify vulnerabilities that were flagged in VULNERABILITY_TEST
            # but need PoC validation
            
            if not hasattr(self, 'suspected_vulnerabilities'):
                self.suspected_vulnerabilities = []
            
            for vuln in self.suspected_vulnerabilities:
                task = ScanTask(
                    url=vuln.get("url", self.initial_target),
                    method=vuln.get("method", "GET"),
                    phase=ScanPhase.LLM_VERIFICATION,
                    source=f"verify:{vuln.get('type', 'unknown')}",
                    parameters=vuln.get("parameters", {})
                )
                # Store vulnerability data in task for context
                if not hasattr(task, 'verification_context'):
                    task.verification_context = vuln
                self.add_task(task)
            
            logger.info(f"Initialized {len(self.suspected_vulnerabilities)} verification tasks")
        
        elif phase == ScanPhase.DEEP_ANALYSIS:
            # Only if we found vulnerabilities
            if self.vulnerabilities:
                task = ScanTask(
                    url=self.initial_target,
                    method="ANALYSIS",
                    phase=ScanPhase.DEEP_ANALYSIS,
                    source="vuln_chaining"
                )
                self.add_task(task)
                logger.info("Initialized deep analysis task for vulnerability chaining")
        
        elif phase == ScanPhase.SUMMARY:
            # Summary task
            task = ScanTask(
                url=self.initial_target,
                method="REPORT",
                phase=ScanPhase.SUMMARY,
                source="final_report"
            )
            self.add_task(task)
            logger.info("Initialized summary report task")
    
    def is_scan_complete(self) -> bool:
        """Determine if scan is complete using HARD-CODED conditions.
        
        Scan is complete ONLY when:
        1. Task queue is empty
        2. Current phase is SUMMARY
        3. Summary task has been executed
        
        This is the ONLY function allowed to declare scan completion.
        LLM agents CANNOT make this decision.
        
        Returns:
            True if scan is complete
        """
        is_complete = (
            len(self.task_queue) == 0 and
            self.current_phase == ScanPhase.SUMMARY and
            self.phase_tasks_executed[ScanPhase.SUMMARY] > 0
        )
        
        if is_complete:
            logger.info("=" * 60)
            logger.info("SCAN COMPLETE - All phases executed, queue empty")
            logger.info(f"  Total tasks executed: {self.tasks_executed}")
            logger.info(f"  URLs discovered: {len(self.discovered_urls)}")
            logger.info(f"  Parameters discovered: {len(self.discovered_params)}")
            logger.info(f"  Vulnerabilities found: {len(self.vulnerabilities)}")
            logger.info("=" * 60)
        
        return is_complete
    
    def get_scan_summary(self) -> dict[str, Any]:
        """Get current scan state summary."""
        return {
            "current_phase": self.current_phase.value,
            "queue_size": len(self.task_queue),
            "tasks_executed": self.tasks_executed,
            "urls_discovered": len(self.discovered_urls),
            "params_discovered": len(self.discovered_params),
            "vulnerabilities_found": len(self.vulnerabilities),
            "is_complete": self.is_scan_complete(),
            "phase_breakdown": {
                phase.value: count 
                for phase, count in self.phase_tasks_executed.items()
            }
        }
