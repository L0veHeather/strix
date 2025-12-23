"""Step Executor - Enforces Action-Execution Decoupling.

This module implements the core principle:
    LLM proposes INTENDED_ACTION → System executes → Results fed back to LLM

The LLM NEVER executes anything. This executor is the only component
that can perform actions.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Any, Callable, Awaitable, Optional

from strix.core.agent_philosophy import (
    IntendedAction,
    ActionType,
    StepStatus,
    StepOutput,
    HumanControlPoint,
    HumanDecision,
    StepProgressionGuard,
    TerminationController,
    PhilosophyValidator,
)

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of executing an IntendedAction.
    
    This result MUST be fed back to the LLM explicitly.
    The LLM cannot assume or hallucinate results.
    """
    
    action: IntendedAction
    success: bool
    output: Any = None
    error: str | None = None
    
    # Result metadata
    execution_time_ms: float = 0
    executed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    # Signal evaluation
    expected_signal_found: bool = False
    actual_signals: list[str] = field(default_factory=list)
    
    # New information flag (critical for progression)
    has_new_information: bool = False
    new_information_summary: str = ""
    
    def to_feedback_message(self) -> str:
        """Convert result to feedback message for LLM.
        
        This is how execution results are explicitly fed back.
        """
        parts = [
            f"[EXECUTION_RESULT]",
            f"action: {self.action.action_type.value}",
            f"tool: {self.action.name}",
            f"goal: {self.action.goal}",
            f"status: {'SUCCESS' if self.success else 'FAILED'}",
        ]
        
        if self.error:
            parts.append(f"error: {self.error}")
        
        if self.output:
            # Truncate output if too long
            output_str = str(self.output)
            if len(output_str) > 2000:
                output_str = output_str[:2000] + "... [truncated]"
            parts.append(f"\n[OUTPUT]\n{output_str}")
        
        parts.append(f"\n[SIGNAL_EVALUATION]")
        parts.append(f"expected: {self.action.expected_signal}")
        parts.append(f"found: {self.expected_signal_found}")
        
        if self.actual_signals:
            parts.append(f"actual_signals: {', '.join(self.actual_signals)}")
        
        parts.append(f"\n[NEW_INFORMATION]")
        parts.append(f"has_new_info: {self.has_new_information}")
        if self.new_information_summary:
            parts.append(f"summary: {self.new_information_summary}")
        
        return "\n".join(parts)


@dataclass
class StepRecord:
    """Complete record of a single step in the Agent lifecycle."""
    
    step_number: int
    proposed_action: IntendedAction
    control_point: HumanControlPoint
    execution_result: ExecutionResult | None = None
    
    # Timing
    proposed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    approved_at: datetime | None = None
    executed_at: datetime | None = None
    completed_at: datetime | None = None
    
    # Status
    final_status: StepStatus = StepStatus.PENDING


class StepExecutor:
    """Executes steps while enforcing Agent philosophy.
    
    Core responsibilities:
    1. Receive IntendedAction from LLM parser
    2. Present to human control point (if required)
    3. Execute action via appropriate handler
    4. Evaluate results against expected signals
    5. Format and return feedback for LLM
    
    The executor enforces:
    - Single action per step
    - Human approval flow
    - Result feedback requirement
    - Progression rules
    """
    
    def __init__(
        self,
        termination_controller: TerminationController,
        progression_guard: StepProgressionGuard | None = None,
        require_human_approval: bool = False,
        auto_approve_types: set[ActionType] | None = None,
    ):
        self.termination = termination_controller
        self.progression = progression_guard or StepProgressionGuard()
        self.require_human_approval = require_human_approval
        self.auto_approve_types = auto_approve_types or {ActionType.EXPLORE}
        
        # Step history
        self.step_history: list[StepRecord] = []
        self.current_step: int = 0
        
        # Action handlers
        self._handlers: dict[ActionType, Callable[[IntendedAction], Awaitable[Any]]] = {}
        
        # Human decision callback (to be set by runtime)
        self._human_decision_callback: Callable[[HumanControlPoint], Awaitable[HumanDecision]] | None = None
        
        # Event for pause/resume
        self._paused = asyncio.Event()
        self._paused.set()  # Start unpaused
    
    def register_handler(
        self,
        action_type: ActionType,
        handler: Callable[[IntendedAction], Awaitable[Any]]
    ) -> None:
        """Register a handler for an action type."""
        self._handlers[action_type] = handler
        logger.debug(f"Registered handler for {action_type.value}")
    
    def set_human_callback(
        self,
        callback: Callable[[HumanControlPoint], Awaitable[HumanDecision]]
    ) -> None:
        """Set the callback for human decisions."""
        self._human_decision_callback = callback
    
    async def execute_step(
        self,
        step_output: StepOutput,
        tracer: Optional[Any] = None,
    ) -> ExecutionResult:
        """Execute a single step from LLM output.
        
        This is the main entry point for step execution.
        
        Args:
            step_output: The parsed output from LLM
            tracer: Optional tracer for observability
            
        Returns:
            ExecutionResult that MUST be fed back to LLM
        """
        # Validate philosophy compliance
        errors = PhilosophyValidator.validate_step_output(step_output)
        if errors:
            logger.error(f"Philosophy violations: {errors}")
            return self._create_error_result(
                step_output.intended_action,
                f"Philosophy violations: {'; '.join(errors)}"
            )
        
        action = step_output.intended_action
        if not action:
            return self._create_error_result(
                None,
                "No INTENDED_ACTION in step output"
            )
        
        # Check termination
        should_term, reason = self.termination.should_terminate()
        if should_term:
            return self._create_error_result(
                action,
                f"Scan terminated: {reason.value if reason else 'unknown'}"
            )
        
        # Increment step
        self.current_step += 1
        self.termination.increment_step()
        action.step_number = self.current_step
        
        # Create control point
        control_point = HumanControlPoint(
            step_number=self.current_step,
            proposed_action=action,
            requires_approval=self._needs_approval(action),
        )
        
        # Create step record
        record = StepRecord(
            step_number=self.current_step,
            proposed_action=action,
            control_point=control_point,
        )
        self.step_history.append(record)
        
        # Log proposed action
        if tracer:
            self._log_proposed_action(tracer, action)
        
        # Wait if paused
        await self._paused.wait()
        
        # Human control point
        if control_point.requires_approval:
            decision = await self._get_human_decision(control_point)
            control_point.apply_decision(decision)
            
            if decision == HumanDecision.REJECT:
                action.status = StepStatus.REJECTED
                record.final_status = StepStatus.REJECTED
                return self._create_error_result(action, "Action rejected by human")
            
            elif decision == HumanDecision.STOP:
                self.termination.human_stop()
                return self._create_error_result(action, "Scan stopped by human")
            
            elif decision == HumanDecision.PAUSE:
                self._paused.clear()
                await self._paused.wait()  # Wait for resume
            
            elif decision == HumanDecision.MODIFY and control_point.modification:
                action = self._apply_modification(action, control_point.modification)
        
        record.approved_at = datetime.now(UTC)
        action.status = StepStatus.APPROVED
        
        # Execute the action
        action.status = StepStatus.EXECUTING
        record.executed_at = datetime.now(UTC)
        
        try:
            result = await self._execute_action(action)
            record.execution_result = result
            
            # Check progression
            can_progress, progress_msg = self.progression.can_progress(
                action, 
                result.has_new_information
            )
            
            if not can_progress:
                logger.warning(f"Progression blocked: {progress_msg}")
                result.error = f"Progression blocked: {progress_msg}"
            
            action.status = StepStatus.COMPLETED
            record.final_status = StepStatus.COMPLETED
            record.completed_at = datetime.now(UTC)
            
            # Log result
            if tracer:
                self._log_execution_result(tracer, result)
            
            return result
            
        except Exception as e:
            logger.exception(f"Action execution failed: {e}")
            action.status = StepStatus.FAILED
            record.final_status = StepStatus.FAILED
            return self._create_error_result(action, str(e))
    
    async def _execute_action(self, action: IntendedAction) -> ExecutionResult:
        """Execute the action using registered handler."""
        import time
        start_time = time.time()
        
        handler = self._handlers.get(action.action_type)
        if not handler:
            return ExecutionResult(
                action=action,
                success=False,
                error=f"No handler for action type: {action.action_type.value}"
            )
        
        try:
            output = await handler(action)
            execution_time = (time.time() - start_time) * 1000
            
            # Evaluate signals
            expected_found, actual_signals = self._evaluate_signals(
                action.expected_signal, 
                output
            )
            
            # Determine if new information
            has_new, new_summary = self._check_new_information(output)
            
            return ExecutionResult(
                action=action,
                success=True,
                output=output,
                execution_time_ms=execution_time,
                expected_signal_found=expected_found,
                actual_signals=actual_signals,
                has_new_information=has_new,
                new_information_summary=new_summary,
            )
            
        except Exception as e:
            return ExecutionResult(
                action=action,
                success=False,
                error=str(e),
                execution_time_ms=(time.time() - start_time) * 1000,
            )
    
    def _needs_approval(self, action: IntendedAction) -> bool:
        """Check if action needs human approval."""
        if not self.require_human_approval:
            return False
        return action.action_type not in self.auto_approve_types
    
    async def _get_human_decision(self, control_point: HumanControlPoint) -> HumanDecision:
        """Get human decision for a control point."""
        if self._human_decision_callback:
            return await self._human_decision_callback(control_point)
        
        # Default: auto-approve
        logger.info(f"Auto-approving step {control_point.step_number}")
        return HumanDecision.APPROVE
    
    def _apply_modification(
        self, 
        action: IntendedAction, 
        modification: dict[str, Any]
    ) -> IntendedAction:
        """Apply human modifications to an action."""
        if "goal" in modification:
            action.goal = modification["goal"]
        if "parameters" in modification:
            action.parameters.update(modification["parameters"])
        if "name" in modification:
            action.name = modification["name"]
        return action
    
    def _evaluate_signals(
        self, 
        expected: str, 
        output: Any
    ) -> tuple[bool, list[str]]:
        """Evaluate if expected signal was found in output."""
        actual_signals = []
        output_str = str(output).lower()
        expected_lower = expected.lower()
        
        # Simple keyword matching
        if expected_lower in output_str:
            actual_signals.append(expected)
            return True, actual_signals
        
        # Look for common indicators
        indicators = {
            "error": ["error", "exception", "failed", "invalid"],
            "success": ["success", "ok", "200", "found"],
            "vulnerability": ["vulnerable", "injection", "xss", "sqli"],
        }
        
        for category, keywords in indicators.items():
            for kw in keywords:
                if kw in output_str:
                    actual_signals.append(f"{category}:{kw}")
        
        return expected_lower in output_str, actual_signals
    
    def _check_new_information(self, output: Any) -> tuple[bool, str]:
        """Check if output contains new information."""
        if output is None:
            return False, ""
        
        output_str = str(output)
        
        # Empty or minimal output = no new info
        if len(output_str) < 10:
            return False, ""
        
        # Check for error-only responses
        if output_str.startswith("Error:") or output_str.startswith("Failed:"):
            return False, "Error response"
        
        # Has content = new info
        summary = output_str[:200] if len(output_str) > 200 else output_str
        return True, summary
    
    def _create_error_result(
        self, 
        action: IntendedAction | None, 
        error: str
    ) -> ExecutionResult:
        """Create an error result."""
        if action is None:
            action = IntendedAction(
                action_type=ActionType.WAIT,
                name="error",
                goal="Handle error",
                expected_signal="N/A"
            )
        
        return ExecutionResult(
            action=action,
            success=False,
            error=error,
            has_new_information=False,
        )
    
    def _log_proposed_action(self, tracer: Any, action: IntendedAction) -> None:
        """Log proposed action to tracer."""
        try:
            tracer.log_chat_message(
                content=f"[PROPOSED] Step {action.step_number}: {action.action_type.value} - {action.name}",
                role="system",
                agent_id=getattr(tracer, 'current_agent_id', None),
                metadata={
                    "type": "proposed_action",
                    "step": action.step_number,
                    "action_type": action.action_type.value,
                    "goal": action.goal,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to log proposed action: {e}")
    
    def _log_execution_result(self, tracer: Any, result: ExecutionResult) -> None:
        """Log execution result to tracer."""
        try:
            tracer.log_chat_message(
                content=result.to_feedback_message(),
                role="system",
                agent_id=getattr(tracer, 'current_agent_id', None),
                metadata={
                    "type": "execution_result",
                    "step": result.action.step_number,
                    "success": result.success,
                    "has_new_info": result.has_new_information,
                }
            )
        except Exception as e:
            logger.warning(f"Failed to log execution result: {e}")
    
    # ==========================================================================
    # Human Control Methods
    # ==========================================================================
    
    def pause(self) -> None:
        """Pause execution (human control)."""
        self._paused.clear()
        logger.info("Execution paused by human")
    
    def resume(self) -> None:
        """Resume execution (human control)."""
        self._paused.set()
        logger.info("Execution resumed by human")
    
    def stop(self) -> None:
        """Stop the scan (human control)."""
        self.termination.human_stop()
        self._paused.set()  # Unblock if paused
        logger.info("Scan stopped by human")
    
    def get_step_history(self) -> list[dict[str, Any]]:
        """Get step history for review."""
        return [
            {
                "step": r.step_number,
                "action_type": r.proposed_action.action_type.value,
                "action_name": r.proposed_action.name,
                "goal": r.proposed_action.goal,
                "status": r.final_status.value,
                "success": r.execution_result.success if r.execution_result else None,
                "has_new_info": r.execution_result.has_new_information if r.execution_result else None,
            }
            for r in self.step_history
        ]
