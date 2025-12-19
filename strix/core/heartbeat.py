"""Heartbeat monitoring for scan visibility during long operations.

This module provides a deterministic, concurrency-safe heartbeat mechanism
that outputs scan state every N seconds, even when no tasks complete.
"""

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from strix.core.scan_controller import ScanController

logger = logging.getLogger(__name__)


class HeartbeatMonitor:
    """Non-blocking heartbeat monitor for scan progress visibility.
    
    Runs in a separate asyncio task and periodically outputs system state
    without interfering with scan execution or blocking agent threads.
    """
    
    def __init__(
        self,
        scan_controller: "ScanController",
        interval_seconds: float = 5.0,
        scan_start_time: float | None = None
    ):
        """Initialize heartbeat monitor.
        
        Args:
            scan_controller: ScanController instance to read state from
            interval_seconds: Seconds between heartbeat outputs (default 5s)
            scan_start_time: Scan start timestamp (default: current time)
        """
        self.scan_controller = scan_controller
        self.interval_seconds = interval_seconds
        self.scan_start_time = scan_start_time or time.time()
        self._stop_flag = False
        self._running = False
    
    async def run(self) -> None:
        """Run heartbeat loop until stopped.
        
        This runs in a separate asyncio task and outputs heartbeat logs
        every interval_seconds. Safe to run concurrently with scan execution.
        """
        self._running = True
        logger.debug(f"Heartbeat monitor started (interval={self.interval_seconds}s)")
        
        # TEST HOOK: simulate async task failure after first heartbeat
        import os
        test_fail_counter = 0
        
        try:
            while not self._stop_flag:
                await asyncio.sleep(self.interval_seconds)
                
                # TEST HOOK: fail on second iteration
                if os.environ.get("STRIX_TEST_ASYNC_TASK_FAIL") == "1":
                    test_fail_counter += 1
                    if test_fail_counter >= 2:
                        raise RuntimeError("[TEST] Simulated async task failure in heartbeat")
                
                if self._stop_flag:
                    break
                
                if self._stop_flag:
                    break
                
                # Proactive cleanup of stuck tasks
                # This ensures that if a task hangs (e.g. unexpected async deadlock), it gets cleared
                try:
                    self.scan_controller.cleanup_stuck_tasks(timeout_seconds=300.0)
                except Exception as e:
                    logger.error(f"Error during stuck task cleanup: {e}")

                self._output_heartbeat()
        except asyncio.CancelledError:
            logger.debug("Heartbeat monitor cancelled")
        finally:
            self._running = False
            logger.debug("Heartbeat monitor stopped")
    
    def _output_heartbeat(self) -> None:
        """Output heartbeat log with current system state.
        
        Format: [Heartbeat] t=123s active_agents=1 pending_tasks=7 running_tasks=2 finished_tasks=5 llm_pending=1 last_progress=12s
        """
        # Calculate elapsed time
        elapsed = int(time.time() - self.scan_start_time)
        
        # Get state from ScanController (non-blocking read)
        state = self.scan_controller.get_heartbeat_state()
        
        # Get LLM pending count
        # Imported here to avoid circular import at module load time
        from strix.llm.llm import LLM
        llm_pending = LLM.get_pending_count()
        
        # Calculate time since last progress
        if state["last_progress_time"] is not None:
            last_progress = int(time.time() - state["last_progress_time"])
        else:
            last_progress = elapsed  # No progress yet
        
        # Get active tasks details
        active_tasks = self.scan_controller.active_tasks
        oldest_task_age = 0
        if active_tasks:
            oldest_start = min(active_tasks.values())
            oldest_task_age = int(time.time() - oldest_start)

        # Output heartbeat log
        logger.info(
            f"[Heartbeat] t={elapsed}s "
            f"active_agents=1 "
            f"pending={state['tasks_pending']} "
            f"running={state['tasks_running']} "
            f"finished={state['tasks_finished']} "
            f"llm_pending={llm_pending} "
            f"oldest_task={oldest_task_age}s "
            f"last_progress={last_progress}s"
        )
    
    def stop(self) -> None:
        """Signal heartbeat to stop gracefully."""
        self._stop_flag = True
    
    @property
    def is_running(self) -> bool:
        """Check if heartbeat is currently running."""
        return self._running
