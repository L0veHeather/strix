"""Step-Based Agent Loop - Implements Agent Philosophy.

This module provides the main agent execution loop that enforces:
1. LLM proposes INTENDED_ACTION only
2. System executes and feeds results back
3. Human can interrupt at any step
4. Only external factors can terminate

This replaces autonomous agent loops with controlled step execution.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, UTC
from typing import Any, Optional

from strix.core.agent_philosophy import (
    ActionType,
    TerminationController,
    TerminationReason,
    StepProgressionGuard,
    HumanDecision,
    HumanControlPoint,
    PhilosophyValidator,
)
from strix.core.step_executor import StepExecutor, ExecutionResult
from strix.core.llm_response_parser import LLMResponseParser, ResponseValidator
from strix.agents.state import StepBasedState

logger = logging.getLogger(__name__)


class StepBasedAgentLoop:
    """Agent loop that enforces step-by-step execution with human control.
    
    Key differences from traditional agent loops:
    1. Each iteration is explicitly a "Step" with defined boundaries
    2. LLM output is parsed and validated before any action
    3. Actions are executed by StepExecutor, not by agent directly
    4. Results are explicitly fed back to LLM as feedback messages
    5. Human can interrupt, modify, or stop at any step
    6. Termination can only come from external sources
    """
    
    def __init__(
        self,
        state: StepBasedState,
        llm_client: Any,  # Your LLM client
        step_executor: StepExecutor,
        max_steps: int = 1000,
        require_human_approval: bool = False,
        tracer: Optional[Any] = None,
    ):
        self.state = state
        self.llm = llm_client
        self.executor = step_executor
        self.max_steps = max_steps
        self.require_human_approval = require_human_approval
        self.tracer = tracer
        
        # Parser for LLM responses
        self.parser = LLMResponseParser(strict_mode=True)
        
        # Termination controller
        self.termination = TerminationController(max_steps=max_steps)
        
        # Philosophy prompt (loaded from template)
        self._philosophy_prompt: str | None = None
        
        # Running flag
        self._running = False
        
        # Human callback
        self._on_step_proposed: Optional[callable] = None
        self._on_human_required: Optional[callable] = None
    
    def set_philosophy_prompt(self, prompt: str) -> None:
        """Set the philosophy prompt to prepend to all LLM calls."""
        self._philosophy_prompt = prompt
    
    def on_step_proposed(self, callback: callable) -> None:
        """Register callback when a step is proposed (for UI)."""
        self._on_step_proposed = callback
    
    def on_human_required(self, callback: callable) -> None:
        """Register callback when human intervention is needed."""
        self._on_human_required = callback
    
    async def run(self, initial_task: str) -> dict[str, Any]:
        """Run the step-based agent loop.
        
        Args:
            initial_task: The initial task description
            
        Returns:
            Final result dictionary
        """
        self._running = True
        
        logger.info("=" * 60)
        logger.info("🦉 Starting Step-Based Agent Loop")
        logger.info("=" * 60)
        logger.info(f"Max Steps: {self.max_steps}")
        logger.info(f"Require Human Approval: {self.require_human_approval}")
        
        # Add initial system message with philosophy
        if self._philosophy_prompt:
            self.state.add_message("system", self._philosophy_prompt)
        
        # Add initial task
        self.state.add_message("user", f"""
INITIAL TASK:
{initial_task}

Remember: You are an EXPLORER. Propose your first exploration action using the mandatory output format.
Do NOT try to analyze everything at once. Propose ONE specific action.
""")
        
        try:
            return await self._run_loop()
        finally:
            self._running = False
            logger.info("🏁 Agent loop terminated")
    
    async def _run_loop(self) -> dict[str, Any]:
        """Internal loop implementation."""
        consecutive_rejections = 0
        max_consecutive_rejections = 3
        
        while self._running:
            # Check termination conditions
            should_term, reason = self.termination.should_terminate()
            if should_term:
                return self._create_termination_result(reason)
            
            # Check if human intervention is needed
            if self.state.needs_human_intervention():
                await self._request_human_intervention(
                    f"No progress for {self.state.no_progress_count} steps"
                )
                # If still no progress after intervention, continue checking
                continue
            
            # Check if can continue
            can_continue, continue_reason = self.state.can_continue()
            if not can_continue:
                if "paused" in continue_reason.lower():
                    await self._wait_for_resume()
                    continue
                return self._create_termination_result(
                    TerminationReason.HUMAN_STOP,
                    continue_reason
                )
            
            # Increment step
            step_number = self.state.increment_step()
            self.termination.increment_step()
            
            logger.info(f"--- Step {step_number} ---")
            
            # Get LLM response
            try:
                llm_response = await self._get_llm_response()
            except Exception as e:
                logger.error(f"LLM request failed: {e}")
                self.state.add_message("system", f"LLM request failed: {e}")
                continue
            
            # Validate response against philosophy
            validation_errors = ResponseValidator.validate(llm_response)
            if validation_errors:
                logger.warning(f"Response validation failed: {validation_errors}")
                correction = ResponseValidator.create_correction_prompt(validation_errors)
                self.state.add_message("user", correction)
                consecutive_rejections += 1
                
                if consecutive_rejections >= max_consecutive_rejections:
                    await self._request_human_intervention(
                        f"LLM failed to comply after {consecutive_rejections} attempts"
                    )
                continue
            
            # Parse response
            parse_result = self.parser.parse(llm_response)
            
            if not parse_result.success:
                logger.warning(f"Parse failed: {parse_result.errors}")
                rejection_msg = self.parser.create_rejection_message(parse_result)
                self.state.add_message("user", rejection_msg)
                consecutive_rejections += 1
                
                if consecutive_rejections >= max_consecutive_rejections:
                    await self._request_human_intervention(
                        f"LLM failed to produce valid output after {consecutive_rejections} attempts"
                    )
                continue
            
            # Reset rejection counter on successful parse
            consecutive_rejections = 0
            
            # Store assistant message
            self.state.add_message("assistant", llm_response)
            
            # Notify UI of proposed step
            if self._on_step_proposed and parse_result.step_output:
                await self._notify_step_proposed(parse_result.step_output)
            
            # Check for duplicate action
            action = parse_result.step_output.intended_action
            if self.state.is_action_duplicate(
                action.action_type.value,
                action.name,
                action.goal
            ):
                logger.warning(f"Duplicate action detected: {action.name}")
                self.state.add_message("user", 
                    f"DUPLICATE ACTION REJECTED: You already proposed '{action.name}' with goal '{action.goal}'. "
                    f"Propose a DIFFERENT action or explain why the same action should be tried again."
                )
                continue
            
            # Execute the step
            result = await self.executor.execute_step(
                parse_result.step_output,
                tracer=self.tracer
            )
            
            # Record step
            self.state.record_step(
                step_number=step_number,
                action_type=action.action_type.value,
                action_name=action.name,
                goal=action.goal,
                status="completed" if result.success else "failed",
                has_new_info=result.has_new_information,
            )
            
            # Feed result back to LLM (CRITICAL: explicit feedback)
            feedback_message = result.to_feedback_message()
            self.state.add_message("user", f"""
{feedback_message}

Based on this result, what is your NEXT exploration action?
Remember: ONE action only, using the mandatory output format.
""")
            
            logger.info(f"Step {step_number} completed: success={result.success}, new_info={result.has_new_information}")
        
        return self._create_termination_result(TerminationReason.HUMAN_STOP)
    
    async def _get_llm_response(self) -> str:
        """Get response from LLM."""
        # This should be implemented to call your LLM
        # For now, we assume self.llm has a generate() method
        response = await self.llm.generate(
            self.state.get_conversation_history()
        )
        return response.content if hasattr(response, 'content') else str(response)
    
    async def _notify_step_proposed(self, step_output: Any) -> None:
        """Notify UI that a step was proposed."""
        if self._on_step_proposed:
            try:
                if asyncio.iscoroutinefunction(self._on_step_proposed):
                    await self._on_step_proposed(step_output)
                else:
                    self._on_step_proposed(step_output)
            except Exception as e:
                logger.warning(f"Failed to notify step proposed: {e}")
    
    async def _request_human_intervention(self, reason: str) -> None:
        """Request human intervention."""
        logger.warning(f"🚨 Human intervention required: {reason}")
        
        self.state.request_human_pause()
        
        if self._on_human_required:
            try:
                if asyncio.iscoroutinefunction(self._on_human_required):
                    await self._on_human_required(reason)
                else:
                    self._on_human_required(reason)
            except Exception as e:
                logger.warning(f"Failed to notify human required: {e}")
        
        # Wait for human to resume
        await self._wait_for_resume()
    
    async def _wait_for_resume(self) -> None:
        """Wait for human to resume execution."""
        logger.info("⏸️ Waiting for human to resume...")
        
        while self.state.human_paused and not self.state.human_stop_requested:
            await asyncio.sleep(0.5)
        
        logger.info("▶️ Execution resumed")
    
    def _create_termination_result(
        self,
        reason: TerminationReason | None,
        message: str = ""
    ) -> dict[str, Any]:
        """Create the final result when terminating."""
        return {
            "success": True,  # Termination itself is not a failure
            "terminated": True,
            "termination_reason": reason.value if reason else "unknown",
            "termination_message": message,
            "total_steps": self.state.current_step,
            "step_summary": self.state.get_step_summary(),
            "step_history": self.state.step_history,
        }
    
    # ==========================================================================
    # Human Control Interface
    # ==========================================================================
    
    def pause(self) -> None:
        """Pause execution (human control)."""
        self.state.request_human_pause()
        self.executor.pause()
        logger.info("⏸️ Agent paused by human")
    
    def resume(self) -> None:
        """Resume execution (human control)."""
        self.state.human_resume()
        self.executor.resume()
        logger.info("▶️ Agent resumed by human")
    
    def stop(self, reason: str = "human_requested") -> None:
        """Stop the scan (human control)."""
        self.state.human_stop(reason)
        self.termination.human_stop()
        self._running = False
        logger.info(f"🛑 Agent stopped by human: {reason}")
    
    def modify_direction(self, new_instruction: str) -> None:
        """Human modifies the exploration direction."""
        self.state.add_message("user", f"""
🔄 DIRECTION CHANGE (Human Override):

{new_instruction}

Please adjust your exploration strategy based on this new direction.
Propose your next action using the mandatory output format.
""")
        logger.info(f"🔄 Direction modified by human")
    
    def provide_feedback(self, feedback: str) -> None:
        """Human provides feedback to the agent."""
        self.state.add_message("user", f"""
💬 HUMAN FEEDBACK:

{feedback}

Please consider this feedback in your next action.
""")
        logger.info("💬 Human feedback provided")
    
    def get_status(self) -> dict[str, Any]:
        """Get current agent status for UI."""
        return {
            "running": self._running,
            "current_step": self.state.current_step,
            "paused": self.state.human_paused,
            "can_continue": self.state.can_continue(),
            "no_progress_count": self.state.no_progress_count,
            "step_summary": self.state.get_step_summary(),
            "termination_status": self.termination.should_terminate(),
        }


# =============================================================================
# Factory Function
# =============================================================================

def create_step_based_loop(
    state: StepBasedState,
    llm_client: Any,
    max_steps: int = 1000,
    require_human_approval: bool = False,
    tracer: Optional[Any] = None,
) -> StepBasedAgentLoop:
    """Create a configured step-based agent loop.
    
    Args:
        state: Agent state (must be StepBasedState)
        llm_client: LLM client for generating responses
        max_steps: Maximum number of steps before termination
        require_human_approval: If True, require human approval for each step
        tracer: Optional tracer for observability
        
    Returns:
        Configured StepBasedAgentLoop
    """
    from strix.core.step_executor import StepExecutor
    from strix.core.agent_philosophy import TerminationController, StepProgressionGuard
    
    # Create termination controller
    termination = TerminationController(max_steps=max_steps)
    
    # Create progression guard
    progression = StepProgressionGuard(max_no_progress_steps=5)
    
    # Create executor
    executor = StepExecutor(
        termination_controller=termination,
        progression_guard=progression,
        require_human_approval=require_human_approval,
    )
    
    # Create loop
    loop = StepBasedAgentLoop(
        state=state,
        llm_client=llm_client,
        step_executor=executor,
        max_steps=max_steps,
        require_human_approval=require_human_approval,
        tracer=tracer,
    )
    
    # Load philosophy prompt
    import os
    from pathlib import Path
    
    prompt_path = Path(__file__).parent.parent / "agents" / "StrixAgent" / "agent_philosophy_prompt.jinja2"
    if prompt_path.exists():
        with open(prompt_path) as f:
            # Remove Jinja comments for plain text
            content = f.read()
            # Simple cleanup of Jinja syntax
            content = content.replace("{#", "").replace("#}", "")
            loop.set_philosophy_prompt(content)
    
    return loop
