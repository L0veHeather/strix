import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AgentLifecycle(str, Enum):
    """Agent lifecycle states for observability."""

    CREATED = "created"    # __init__ completed, not yet started
    STARTED = "started"    # entered agent_loop / execute_scan
    RUNNING = "running"    # actively iterating (LLM / tool)
    WAITING = "waiting"    # waiting for user/sub-agent input
    FAILED = "failed"      # terminated with error
    FINISHED = "finished"  # completed successfully
    STOPPED = "stopped"    # terminated by user/system


def _generate_agent_id() -> str:
    return f"agent_{uuid.uuid4().hex[:8]}"


class AgentState(BaseModel):
    agent_id: str = Field(default_factory=_generate_agent_id)
    agent_name: str = "Trix Agent"
    parent_id: str | None = None
    sandbox_id: str | None = None
    sandbox_token: str | None = None
    sandbox_info: dict[str, Any] | None = None

    task: str = ""
    iteration: int = 0
    max_iterations: int = 300
    completed: bool = False
    stop_requested: bool = False
    waiting_for_input: bool = False
    llm_failed: bool = False
    waiting_start_time: datetime | None = None
    final_result: dict[str, Any] | None = None
    max_iterations_warning_sent: bool = False

    messages: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)

    start_time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_updated: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())

    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)

    errors: list[str] = Field(default_factory=list)

    def increment_iteration(self) -> None:
        self.iteration += 1
        self.last_updated = datetime.now(UTC).isoformat()

    def add_message(self, role: str, content: Any) -> None:
        self.messages.append({"role": role, "content": content})
        self.last_updated = datetime.now(UTC).isoformat()

    def add_action(self, action: dict[str, Any]) -> None:
        self.actions_taken.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "action": action,
            }
        )

    def add_observation(self, observation: dict[str, Any]) -> None:
        self.observations.append(
            {
                "iteration": self.iteration,
                "timestamp": datetime.now(UTC).isoformat(),
                "observation": observation,
            }
        )

    def add_error(self, error: str) -> None:
        self.errors.append(f"Iteration {self.iteration}: {error}")
        self.last_updated = datetime.now(UTC).isoformat()

    def update_context(self, key: str, value: Any) -> None:
        self.context[key] = value
        self.last_updated = datetime.now(UTC).isoformat()

    def set_completed(self, final_result: dict[str, Any] | None = None) -> None:
        self.completed = True
        self.final_result = final_result
        self.last_updated = datetime.now(UTC).isoformat()

    def request_stop(self) -> None:
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()

    def should_stop(self) -> bool:
        return self.stop_requested or self.completed or self.has_reached_max_iterations()

    def is_waiting_for_input(self) -> bool:
        return self.waiting_for_input

    def enter_waiting_state(self, llm_failed: bool = False) -> None:
        self.waiting_for_input = True
        self.waiting_start_time = datetime.now(UTC)
        self.llm_failed = llm_failed
        self.last_updated = datetime.now(UTC).isoformat()

    def resume_from_waiting(self, new_task: str | None = None) -> None:
        self.waiting_for_input = False
        self.waiting_start_time = None
        self.stop_requested = False
        self.completed = False
        self.llm_failed = False
        if new_task:
            self.task = new_task
        self.last_updated = datetime.now(UTC).isoformat()

    def has_reached_max_iterations(self) -> bool:
        return self.iteration >= self.max_iterations

    def is_approaching_max_iterations(self, threshold: float = 0.85) -> bool:
        return self.iteration >= int(self.max_iterations * threshold)

    def has_waiting_timeout(self) -> bool:
        if not self.waiting_for_input or not self.waiting_start_time:
            return False

        if (
            self.stop_requested
            or self.llm_failed
            or self.completed
            or self.has_reached_max_iterations()
        ):
            return False

        elapsed = (datetime.now(UTC) - self.waiting_start_time).total_seconds()
        return elapsed > 600

    def has_empty_last_messages(self, count: int = 3) -> bool:
        if len(self.messages) < count:
            return False

        last_messages = self.messages[-count:]

        for message in last_messages:
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return False

        return True

    def get_conversation_history(self) -> list[dict[str, Any]]:
        return self.messages

    def get_execution_summary(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "parent_id": self.parent_id,
            "sandbox_id": self.sandbox_id,
            "sandbox_info": self.sandbox_info,
            "task": self.task,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": self.completed,
            "final_result": self.final_result,
            "start_time": self.start_time,
            "last_updated": self.last_updated,
            "total_actions": len(self.actions_taken),
            "total_observations": len(self.observations),
            "total_errors": len(self.errors),
            "has_errors": len(self.errors) > 0,
            "max_iterations_reached": self.has_reached_max_iterations() and not self.completed,
        }


# =============================================================================
# Step-Based State (Agent Philosophy Compliant)
# =============================================================================

class StepBasedState(AgentState):
    """Extended state that tracks steps rather than just iterations.
    
    This state model supports the Agent Philosophy:
    - Each LLM call = one Step
    - Steps have explicit status tracking
    - Progression requires new information
    - Human can interrupt at any step
    """
    
    # Step tracking
    current_step: int = 0
    step_history: list[dict[str, Any]] = Field(default_factory=list)
    
    # Progression control
    no_progress_count: int = 0
    max_no_progress_steps: int = 5
    last_new_information_step: int = 0
    
    # Human control
    human_paused: bool = False
    human_stop_requested: bool = False
    pending_human_decision: str | None = None
    
    # Termination (only external)
    termination_reason: str | None = None
    
    # Recent actions for duplicate detection
    recent_action_signatures: list[str] = Field(default_factory=list)
    
    def increment_step(self) -> int:
        """Increment step counter and return new step number."""
        self.current_step += 1
        self.last_updated = datetime.now(UTC).isoformat()
        return self.current_step
    
    def record_step(
        self,
        step_number: int,
        action_type: str,
        action_name: str,
        goal: str,
        status: str,
        has_new_info: bool = False,
    ) -> None:
        """Record a step in history."""
        step_record = {
            "step": step_number,
            "action_type": action_type,
            "action_name": action_name,
            "goal": goal,
            "status": status,
            "has_new_info": has_new_info,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.step_history.append(step_record)
        
        # Track action signature for duplicate detection
        signature = f"{action_type}:{action_name}:{goal}"
        self.recent_action_signatures.append(signature)
        
        # Keep only last 10 signatures
        if len(self.recent_action_signatures) > 10:
            self.recent_action_signatures = self.recent_action_signatures[-10:]
        
        # Update progression tracking
        if has_new_info:
            self.no_progress_count = 0
            self.last_new_information_step = step_number
        else:
            self.no_progress_count += 1
        
        self.last_updated = datetime.now(UTC).isoformat()
    
    def is_action_duplicate(self, action_type: str, action_name: str, goal: str) -> bool:
        """Check if an action would be a duplicate of recent actions."""
        signature = f"{action_type}:{action_name}:{goal}"
        return signature in self.recent_action_signatures[-5:]
    
    def needs_human_intervention(self) -> bool:
        """Check if human intervention is needed due to no progress."""
        return self.no_progress_count >= self.max_no_progress_steps
    
    def request_human_pause(self) -> None:
        """Request human to pause execution."""
        self.human_paused = True
        self.pending_human_decision = "pause"
        self.last_updated = datetime.now(UTC).isoformat()
    
    def human_resume(self) -> None:
        """Human resumes execution."""
        self.human_paused = False
        self.pending_human_decision = None
        self.last_updated = datetime.now(UTC).isoformat()
    
    def human_stop(self, reason: str = "human_requested") -> None:
        """Human stops the scan."""
        self.human_stop_requested = True
        self.termination_reason = reason
        self.stop_requested = True
        self.last_updated = datetime.now(UTC).isoformat()
    
    def can_continue(self) -> tuple[bool, str]:
        """Check if agent can continue to next step.
        
        Returns:
            (can_continue, reason)
        """
        if self.human_stop_requested:
            return False, f"Human stopped: {self.termination_reason}"
        
        if self.human_paused:
            return False, "Paused by human"
        
        if self.has_reached_max_iterations():
            return False, "Max iterations reached"
        
        if self.needs_human_intervention():
            return False, f"No progress for {self.no_progress_count} steps"
        
        return True, "OK"
    
    def get_step_summary(self) -> dict[str, Any]:
        """Get summary of step-based execution."""
        return {
            "current_step": self.current_step,
            "total_steps": len(self.step_history),
            "no_progress_count": self.no_progress_count,
            "last_new_info_step": self.last_new_information_step,
            "human_paused": self.human_paused,
            "human_stop_requested": self.human_stop_requested,
            "termination_reason": self.termination_reason,
            "can_continue": self.can_continue()[0],
        }
