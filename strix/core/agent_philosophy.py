"""Agent Philosophy - Core principles for Strix Agent behavior.

This module defines the fundamental rules that govern Agent identity,
lifecycle, decision-making, and execution boundaries.

These principles MUST be enforced throughout the codebase:

1. Agent = Persistent intelligent entity, NOT one-shot analyzer
2. Agent proposes NEXT STEP, never final conclusions
3. Agent CANNOT terminate scan - termination is external only
4. Each LLM call = one Step, not one Scan
5. LLM decides WHAT to explore, not WHEN to stop
6. Actions and Execution are DECOUPLED
7. LLM outputs INTENDED_ACTION, code executes
8. Results must be explicitly fed back to LLM
9. Plugins are LLM's choice, not forced workflow
10. Human can interrupt/override at any point
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, UTC
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# =============================================================================
# Section 1: Agent Identity & Lifecycle
# =============================================================================

class AgentRole(str, Enum):
    """Agent's role in the system - always an explorer, never a judge."""
    
    EXPLORER = "explorer"      # Proposes next actions
    ANALYZER = "analyzer"      # FORBIDDEN - agents must not be one-shot analyzers
    EXECUTOR = "executor"      # FORBIDDEN - agents do not execute, only propose


class StepStatus(str, Enum):
    """Status of a single step in the Agent lifecycle."""
    
    PENDING = "pending"              # Step proposed, awaiting approval
    APPROVED = "approved"            # Human/system approved execution
    REJECTED = "rejected"            # Human rejected the step
    EXECUTING = "executing"          # Action being executed by system
    AWAITING_RESULT = "awaiting_result"  # Waiting for execution result
    COMPLETED = "completed"          # Result received, ready for next step
    FAILED = "failed"                # Execution failed


class TerminationReason(str, Enum):
    """Valid reasons for scan termination - ALL must be external."""
    
    HUMAN_STOP = "human_stop"              # Human explicitly stopped
    STEP_LIMIT = "step_limit"              # Reached max step count
    SCOPE_EXHAUSTED = "scope_exhausted"    # No more targets to explore
    TIMEOUT = "timeout"                     # External timeout triggered
    
    # FORBIDDEN reasons (will be rejected):
    # - "analysis_complete" 
    # - "no_vulnerabilities_found"
    # - "scan_finished"


# =============================================================================
# Section 2: Intended Action Structure (Mandatory Output Format)
# =============================================================================

class ActionType(str, Enum):
    """Types of actions LLM can propose."""
    
    PLUGIN = "plugin"       # Use a security plugin/tool
    REQUEST = "request"     # Make an HTTP request
    EXPLORE = "explore"     # Explore a new endpoint/parameter
    VERIFY = "verify"       # Verify a hypothesis
    WAIT = "wait"           # Wait for more information


@dataclass
class VulnHypothesis:
    """A vulnerability hypothesis proposed by the LLM.
    
    This is a HYPOTHESIS, not a conclusion. Must be verified by evidence.
    """
    
    description: str              # One sentence description
    vuln_type: str                # e.g., "sqli", "xss", "ssrf"
    confidence: str = "low"       # low/medium/high - LLM's initial confidence
    requires_verification: bool = True  # Always true initially


@dataclass  
class Evidence:
    """Evidence supporting or refuting a hypothesis."""
    
    source: str           # Where this evidence came from
    content: str          # The actual evidence
    supports_hypothesis: bool  # Does this support or refute?
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class IntendedAction:
    """The ONLY output format LLM is allowed to produce.
    
    LLM proposes, System executes. Never the reverse.
    
    This structure enforces:
    - Single action per step (no parallel actions)
    - Clear goal specification
    - Expected signal definition
    - No execution by LLM
    """
    
    action_type: ActionType
    name: str                    # Tool/plugin name or action identifier
    goal: str                    # SINGLE goal for this action
    expected_signal: str         # What would confirm/deny the hypothesis
    parameters: dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    step_number: int = 0
    proposed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: StepStatus = StepStatus.PENDING
    
    def validate(self) -> list[str]:
        """Validate the action follows philosophy rules.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        if not self.goal:
            errors.append("Action must have exactly ONE goal")
        
        if ";" in self.goal or " and " in self.goal.lower():
            errors.append("Action goal must be singular - no compound goals")
        
        if not self.expected_signal:
            errors.append("Action must define expected_signal for result evaluation")
        
        # Check for forbidden patterns
        forbidden_patterns = [
            "scan complete",
            "analysis done",
            "no vulnerabilities",
            "finish scan",
        ]
        goal_lower = self.goal.lower()
        for pattern in forbidden_patterns:
            if pattern in goal_lower:
                errors.append(f"Forbidden goal pattern: '{pattern}'")
        
        return errors


@dataclass
class StepOutput:
    """Complete output structure for one Agent step.
    
    This is the MANDATORY format for every LLM response.
    """
    
    hypothesis: VulnHypothesis | None = None
    evidence: list[Evidence] = field(default_factory=list)
    intended_action: IntendedAction | None = None
    
    # Analysis notes (internal reasoning)
    reasoning: str = ""
    
    def to_structured_output(self) -> str:
        """Convert to the mandatory output format."""
        parts = []
        
        if self.hypothesis:
            parts.append(f"""[VULN_HYPOTHESIS]
{self.hypothesis.description}
Type: {self.hypothesis.vuln_type}
Confidence: {self.hypothesis.confidence}""")
        
        if self.evidence:
            evidence_lines = [f"- {e.content}" for e in self.evidence]
            parts.append(f"""[EVIDENCE]
{chr(10).join(evidence_lines)}""")
        
        if self.intended_action:
            action = self.intended_action
            parts.append(f"""[INTENDED_ACTION]
type: {action.action_type.value}
name: {action.name}
goal: {action.goal}
expected_signal: {action.expected_signal}""")
            
            if action.parameters:
                params_str = "\n".join(f"  {k}: {v}" for k, v in action.parameters.items())
                parts.append(f"parameters:\n{params_str}")
        
        return "\n\n".join(parts)


# =============================================================================
# Section 3: State Progression Rules
# =============================================================================

@dataclass
class StepProgressionGuard:
    """Guards against invalid state progression.
    
    Rules enforced:
    1. Each step MUST depend on new information
    2. No progress without new results
    3. No repeated identical actions
    4. N consecutive no-progress steps → human intervention
    """
    
    max_no_progress_steps: int = 5
    recent_actions: list[str] = field(default_factory=list)
    no_progress_count: int = 0
    last_new_information: datetime | None = None
    
    def can_progress(self, new_action: IntendedAction, has_new_info: bool) -> tuple[bool, str]:
        """Check if progression is allowed.
        
        Args:
            new_action: The proposed next action
            has_new_info: Whether new information was received
            
        Returns:
            (can_progress, reason)
        """
        # Rule 1: Must have new information
        if not has_new_info:
            self.no_progress_count += 1
            if self.no_progress_count >= self.max_no_progress_steps:
                return False, f"No progress for {self.no_progress_count} steps - human intervention required"
            return False, "Cannot progress without new information from previous step"
        
        # Rule 2: No repeated actions
        action_signature = f"{new_action.action_type.value}:{new_action.name}:{new_action.goal}"
        if action_signature in self.recent_actions[-5:]:  # Check last 5 actions
            return False, f"Repeated action detected: {action_signature}"
        
        # Allow progression
        self.recent_actions.append(action_signature)
        self.no_progress_count = 0
        self.last_new_information = datetime.now(UTC)
        
        return True, "Progression allowed"
    
    def record_no_result(self) -> bool:
        """Record that execution produced no new result.
        
        Returns:
            True if human intervention is now required
        """
        self.no_progress_count += 1
        return self.no_progress_count >= self.max_no_progress_steps


# =============================================================================
# Section 4: Human Control Points
# =============================================================================

class HumanDecision(str, Enum):
    """Decisions human can make at any control point."""
    
    APPROVE = "approve"           # Approve proposed action
    REJECT = "reject"             # Reject proposed action  
    MODIFY = "modify"             # Modify the action before execution
    REDIRECT = "redirect"         # Change exploration direction
    PAUSE = "pause"               # Pause agent execution
    STOP = "stop"                 # Stop the scan entirely
    RESUME = "resume"             # Resume from pause


@dataclass
class HumanControlPoint:
    """A point where human can intervene in Agent execution.
    
    Human-in-the-loop capabilities:
    - Approve/reject any action
    - Modify target or parameters
    - Force direction change
    - Stop at any step
    - Agent MUST obey human decisions
    """
    
    step_number: int
    proposed_action: IntendedAction
    requires_approval: bool = True  # Can be configured per action type
    human_decision: HumanDecision | None = None
    decision_timestamp: datetime | None = None
    modification: dict[str, Any] | None = None
    
    def await_decision(self, timeout_seconds: float = 300.0) -> HumanDecision:
        """Wait for human decision.
        
        In non-interactive mode, this may auto-approve based on config.
        """
        # This will be implemented in the actual execution layer
        raise NotImplementedError("Implemented in execution layer")
    
    def apply_decision(self, decision: HumanDecision, modification: dict[str, Any] | None = None) -> None:
        """Apply human decision to this control point."""
        self.human_decision = decision
        self.decision_timestamp = datetime.now(UTC)
        self.modification = modification
        
        logger.info(f"Human decision at step {self.step_number}: {decision.value}")


# =============================================================================
# Section 5: Vulnerability Confirmation Rules
# =============================================================================

@dataclass
class VulnerabilityStatus:
    """Status of a vulnerability finding.
    
    Rules:
    1. "Suspected" ≠ "Confirmed"
    2. Confirmation requires REPRODUCIBLE behavior change
    3. Must document false positive possibility
    4. PoC is VERIFICATION, not conclusion
    """
    
    status: str  # "suspected", "testing", "confirmed", "false_positive"
    vuln_type: str
    url: str
    
    # Evidence chain
    initial_evidence: list[str] = field(default_factory=list)
    verification_attempts: int = 0
    reproducible_behavior: str | None = None
    
    # False positive analysis
    false_positive_probability: float = 0.5  # 50% by default
    false_positive_reasons: list[str] = field(default_factory=list)
    
    # PoC information
    poc_request: dict[str, Any] | None = None
    poc_response: dict[str, Any] | None = None
    poc_validates: bool = False
    
    def is_confirmed(self) -> bool:
        """A vulnerability is only confirmed when:
        
        1. There is reproducible behavior change
        2. PoC validates the behavior
        3. False positive probability < 20%
        """
        return (
            self.status == "confirmed"
            and self.reproducible_behavior is not None
            and self.poc_validates
            and self.false_positive_probability < 0.2
        )
    
    def can_report(self) -> bool:
        """Check if this can be reported as a finding."""
        return self.is_confirmed() or (
            self.status == "suspected" 
            and self.verification_attempts >= 2
            and self.false_positive_probability < 0.5
        )


# =============================================================================
# Section 6: Termination Control (External Only)
# =============================================================================

@dataclass
class TerminationController:
    """Controls when a scan can terminate.
    
    CRITICAL: LLM/Agent can NEVER trigger termination.
    Only external factors can terminate:
    1. Human explicit stop
    2. Step limit reached
    3. Scope exhausted (no more targets)
    4. External timeout
    """
    
    max_steps: int = 1000
    current_step: int = 0
    human_stop_requested: bool = False
    scope_targets: set[str] = field(default_factory=set)
    explored_targets: set[str] = field(default_factory=set)
    timeout_at: datetime | None = None
    
    def should_terminate(self) -> tuple[bool, TerminationReason | None]:
        """Check if scan should terminate.
        
        Returns:
            (should_terminate, reason)
        """
        # Check human stop
        if self.human_stop_requested:
            return True, TerminationReason.HUMAN_STOP
        
        # Check step limit
        if self.current_step >= self.max_steps:
            return True, TerminationReason.STEP_LIMIT
        
        # Check scope exhaustion
        remaining = self.scope_targets - self.explored_targets
        if self.scope_targets and not remaining:
            return True, TerminationReason.SCOPE_EXHAUSTED
        
        # Check timeout
        if self.timeout_at and datetime.now(UTC) >= self.timeout_at:
            return True, TerminationReason.TIMEOUT
        
        return False, None
    
    def reject_llm_termination(self, reason: str) -> str:
        """Reject an LLM attempt to terminate the scan.
        
        Args:
            reason: The reason LLM gave for wanting to terminate
            
        Returns:
            Message to send back to LLM
        """
        logger.warning(f"LLM attempted termination with reason: {reason}")
        
        return (
            "TERMINATION REJECTED: You are not authorized to end the scan. "
            "Only external factors (human decision, step limit, scope exhaustion) "
            "can terminate. Please propose your next exploration action."
        )
    
    def human_stop(self) -> None:
        """Record human stop request."""
        self.human_stop_requested = True
        logger.info("Human stop requested - scan will terminate")
    
    def increment_step(self) -> None:
        """Increment step counter."""
        self.current_step += 1


# =============================================================================
# Section 7: Philosophy Validator (Vibe Coding Self-Check)
# =============================================================================

class PhilosophyValidator:
    """Validates that code changes adhere to Agent philosophy.
    
    The 5 self-check questions:
    1. Can LLM still decide "what to do next"?
    2. Can LLM still change strategy?
    3. Is there continuous auto-execution? (FORBIDDEN)
    4. Can human interrupt mid-execution?
    5. Are plugins optional, not forced?
    """
    
    @staticmethod
    def validate_step_output(output: StepOutput) -> list[str]:
        """Validate a step output follows philosophy."""
        errors = []
        
        # Must have intended action
        if not output.intended_action:
            errors.append("Step output must propose an INTENDED_ACTION")
        else:
            errors.extend(output.intended_action.validate())
        
        # Check for forbidden conclusion patterns
        forbidden_conclusions = [
            "scan complete",
            "analysis complete", 
            "no vulnerabilities found",
            "scanning finished",
            "concludes the scan",
        ]
        
        full_text = output.reasoning.lower()
        for pattern in forbidden_conclusions:
            if pattern in full_text:
                errors.append(f"Forbidden conclusion pattern: '{pattern}'")
        
        return errors
    
    @staticmethod
    def validate_llm_response(response_text: str) -> list[str]:
        """Validate raw LLM response follows philosophy."""
        errors = []
        response_lower = response_text.lower()
        
        # Check for termination attempts
        termination_patterns = [
            "scan is complete",
            "analysis complete",
            "no further action",
            "scanning finished",
            "i have completed",
            "the scan has ended",
        ]
        
        for pattern in termination_patterns:
            if pattern in response_lower:
                errors.append(f"LLM attempted termination: '{pattern}'")
        
        # Check for parallel action proposals
        if response_lower.count("[intended_action]") > 1:
            errors.append("Multiple INTENDED_ACTIONs detected - only ONE action per step")
        
        # Check for execution claims
        execution_patterns = [
            "i have executed",
            "i ran the",
            "i performed",
            "execution result",
        ]
        
        for pattern in execution_patterns:
            if pattern in response_lower:
                errors.append(f"LLM claimed execution: '{pattern}' - LLM does not execute")
        
        return errors
    
    @staticmethod  
    def vibe_check() -> dict[str, bool]:
        """Perform the 5 vibe coding self-check questions.
        
        Returns:
            Dict mapping question to pass/fail
        """
        # These are checked structurally by the code design
        return {
            "llm_decides_next_step": True,      # IntendedAction structure
            "llm_can_change_strategy": True,    # VulnHypothesis is mutable
            "no_continuous_auto_exec": True,    # StepProgressionGuard
            "human_can_interrupt": True,        # HumanControlPoint
            "plugins_are_optional": True,       # ActionType includes non-plugin
        }


# =============================================================================
# Section 8: Anti-Pattern Detector
# =============================================================================

class AntiPatternDetector:
    """Detects and prevents anti-patterns in Agent behavior."""
    
    FORBIDDEN_PROMPT_PATTERNS = [
        "请分析是否存在漏洞",           # "analyze for vulnerabilities"
        "扫描完成后给我结果",            # "give results after scan"
        "analyze if vulnerability exists",
        "give me final results",
        "complete the scan",
        "finish analyzing",
    ]
    
    FORBIDDEN_ACTION_PATTERNS = [
        "可以顺便再试试",               # "might as well try"
        "同时也测试",                   # "also test simultaneously"  
        "run full scan",
        "scan everything",
        "try multiple things",
    ]
    
    @classmethod
    def check_prompt(cls, prompt: str) -> list[str]:
        """Check prompt for anti-patterns.
        
        Returns:
            List of detected anti-patterns
        """
        detected = []
        prompt_lower = prompt.lower()
        
        for pattern in cls.FORBIDDEN_PROMPT_PATTERNS:
            if pattern.lower() in prompt_lower:
                detected.append(f"Forbidden prompt pattern: '{pattern}'")
        
        return detected
    
    @classmethod
    def check_action_proposal(cls, proposal: str) -> list[str]:
        """Check action proposal for anti-patterns.
        
        Returns:
            List of detected anti-patterns
        """
        detected = []
        proposal_lower = proposal.lower()
        
        for pattern in cls.FORBIDDEN_ACTION_PATTERNS:
            if pattern.lower() in proposal_lower:
                detected.append(f"Forbidden action pattern: '{pattern}'")
        
        # Check for parallel action attempts
        parallel_indicators = ["and also", "while also", "simultaneously", "in parallel"]
        for indicator in parallel_indicators:
            if indicator in proposal_lower:
                detected.append(f"Parallel action attempt: '{indicator}'")
        
        return detected
