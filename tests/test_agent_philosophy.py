"""Tests for Agent Philosophy Implementation.

These tests verify that the Agent Philosophy principles are correctly enforced.
"""

import pytest
from datetime import datetime, UTC

from trix.core.agent_philosophy import (
    IntendedAction,
    ActionType,
    VulnHypothesis,
    Evidence,
    StepOutput,
    StepProgressionGuard,
    TerminationController,
    TerminationReason,
    HumanDecision,
    HumanControlPoint,
    PhilosophyValidator,
    AntiPatternDetector,
)


class TestIntendedAction:
    """Test IntendedAction validation."""
    
    def test_valid_action(self):
        """Valid action should pass validation."""
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="sqli_test",
            goal="Test login endpoint for SQL injection",
            expected_signal="SQL syntax error in response",
        )
        
        errors = action.validate()
        assert len(errors) == 0
    
    def test_missing_goal(self):
        """Action without goal should fail."""
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="",  # Empty goal
            expected_signal="something",
        )
        
        errors = action.validate()
        assert "Action must have exactly ONE goal" in errors
    
    def test_compound_goal(self):
        """Compound goal should fail."""
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test for SQL injection and also check for XSS",  # Compound
            expected_signal="errors",
        )
        
        errors = action.validate()
        assert any("compound" in e.lower() for e in errors)
    
    def test_missing_expected_signal(self):
        """Action without expected_signal should fail."""
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test something",
            expected_signal="",  # Empty
        )
        
        errors = action.validate()
        assert "expected_signal" in str(errors).lower()
    
    def test_forbidden_goal_patterns(self):
        """Forbidden patterns in goal should fail."""
        forbidden_goals = [
            "Complete the scan and report findings",
            "Scan complete, no vulnerabilities found",
            "Finish scan now",
        ]
        
        for goal in forbidden_goals:
            action = IntendedAction(
                action_type=ActionType.REQUEST,
                name="test",
                goal=goal,
                expected_signal="something",
            )
            errors = action.validate()
            assert len(errors) > 0, f"Expected error for goal: {goal}"


class TestStepProgressionGuard:
    """Test state progression rules."""
    
    def test_progress_with_new_info(self):
        """Should allow progress with new information."""
        guard = StepProgressionGuard()
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test something",
            expected_signal="response",
        )
        
        can_progress, reason = guard.can_progress(action, has_new_info=True)
        assert can_progress is True
    
    def test_no_progress_without_new_info(self):
        """Should block progress without new information."""
        guard = StepProgressionGuard()
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test something",
            expected_signal="response",
        )
        
        can_progress, reason = guard.can_progress(action, has_new_info=False)
        assert can_progress is False
        assert "new information" in reason.lower()
    
    def test_duplicate_action_detection(self):
        """Should detect and reject duplicate actions."""
        guard = StepProgressionGuard()
        
        action1 = IntendedAction(
            action_type=ActionType.REQUEST,
            name="sqli_test",
            goal="Test for SQL injection",
            expected_signal="error",
        )
        
        # First time should work
        can_progress, _ = guard.can_progress(action1, has_new_info=True)
        assert can_progress is True
        
        # Same action again should fail
        can_progress, reason = guard.can_progress(action1, has_new_info=True)
        assert can_progress is False
        assert "repeated" in reason.lower()
    
    def test_human_intervention_after_no_progress(self):
        """Should require human intervention after N no-progress steps."""
        guard = StepProgressionGuard(max_no_progress_steps=3)
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test",
            expected_signal="x",
        )
        
        # Simulate no progress
        for i in range(3):
            guard.can_progress(action, has_new_info=False)
        
        can_progress, reason = guard.can_progress(action, has_new_info=False)
        assert can_progress is False
        assert "human intervention" in reason.lower()


class TestTerminationController:
    """Test termination control."""
    
    def test_no_premature_termination(self):
        """Should not terminate without external trigger."""
        controller = TerminationController(max_steps=100)
        
        should_term, reason = controller.should_terminate()
        assert should_term is False
        assert reason is None
    
    def test_human_stop(self):
        """Should terminate on human stop."""
        controller = TerminationController(max_steps=100)
        
        controller.human_stop()
        
        should_term, reason = controller.should_terminate()
        assert should_term is True
        assert reason == TerminationReason.HUMAN_STOP
    
    def test_step_limit(self):
        """Should terminate when step limit reached."""
        controller = TerminationController(max_steps=5)
        
        for _ in range(5):
            controller.increment_step()
        
        should_term, reason = controller.should_terminate()
        assert should_term is True
        assert reason == TerminationReason.STEP_LIMIT
    
    def test_scope_exhausted(self):
        """Should terminate when scope exhausted."""
        controller = TerminationController(max_steps=100)
        controller.scope_targets = {"target1", "target2"}
        controller.explored_targets = {"target1", "target2"}
        
        should_term, reason = controller.should_terminate()
        assert should_term is True
        assert reason == TerminationReason.SCOPE_EXHAUSTED
    
    def test_reject_llm_termination(self):
        """Should reject LLM termination attempts."""
        controller = TerminationController()
        
        message = controller.reject_llm_termination("Scan complete, no vulnerabilities")
        
        assert "TERMINATION REJECTED" in message
        assert "not authorized" in message.lower()


class TestPhilosophyValidator:
    """Test philosophy validation."""
    
    def test_valid_step_output(self):
        """Valid step output should pass."""
        output = StepOutput(
            hypothesis=VulnHypothesis(
                description="Potential SQL injection",
                vuln_type="sqli",
            ),
            evidence=[
                Evidence(source="response", content="SQL error", supports_hypothesis=True)
            ],
            intended_action=IntendedAction(
                action_type=ActionType.VERIFY,
                name="sqli_verify",
                goal="Verify SQL injection",
                expected_signal="Different response",
            ),
        )
        
        errors = PhilosophyValidator.validate_step_output(output)
        assert len(errors) == 0
    
    def test_detect_conclusion_patterns(self):
        """Should detect forbidden conclusion patterns."""
        output = StepOutput(
            intended_action=IntendedAction(
                action_type=ActionType.WAIT,
                name="finish",
                goal="Wait",
                expected_signal="nothing",
            ),
            reasoning="Based on my analysis, scan complete and no vulnerabilities found.",
        )
        
        errors = PhilosophyValidator.validate_step_output(output)
        assert any("forbidden" in e.lower() for e in errors)
    
    def test_validate_llm_response_termination(self):
        """Should detect termination attempts in LLM response."""
        response = """
        Based on my comprehensive analysis, the scan is complete.
        I have tested all endpoints and no vulnerabilities were found.
        """
        
        errors = PhilosophyValidator.validate_llm_response(response)
        assert len(errors) > 0
        assert any("termination" in e.lower() for e in errors)
    
    def test_validate_llm_response_execution_claim(self):
        """Should detect execution claims in LLM response."""
        response = """
        I have executed the SQL injection test and the result was successful.
        The injection worked and I ran additional tests.
        """
        
        errors = PhilosophyValidator.validate_llm_response(response)
        assert len(errors) > 0
        assert any("execution" in e.lower() for e in errors)
    
    def test_validate_llm_response_multiple_actions(self):
        """Should detect multiple INTENDED_ACTION sections."""
        response = """
        [INTENDED_ACTION]
        type: request
        name: test1
        goal: Test one thing
        expected_signal: something

        [INTENDED_ACTION]
        type: plugin
        name: nuclei
        goal: Full scan
        expected_signal: vulns
        """
        
        errors = PhilosophyValidator.validate_llm_response(response)
        assert any("multiple" in e.lower() for e in errors)
    
    def test_vibe_check(self):
        """Vibe check should pass with correct structure."""
        result = PhilosophyValidator.vibe_check()
        
        assert result["llm_decides_next_step"] is True
        assert result["llm_can_change_strategy"] is True
        assert result["no_continuous_auto_exec"] is True
        assert result["human_can_interrupt"] is True
        assert result["plugins_are_optional"] is True


class TestAntiPatternDetector:
    """Test anti-pattern detection."""
    
    def test_detect_forbidden_prompt(self):
        """Should detect forbidden prompt patterns."""
        prompts = [
            "请分析是否存在漏洞",
            "扫描完成后给我结果",
            "Analyze if vulnerability exists and give final results",
        ]
        
        for prompt in prompts:
            detected = AntiPatternDetector.check_prompt(prompt)
            assert len(detected) > 0, f"Should detect anti-pattern in: {prompt}"
    
    def test_detect_forbidden_action(self):
        """Should detect forbidden action patterns."""
        proposals = [
            "Run a full nuclei scan and also try sqlmap",
            "可以顺便再试试其他注入方式",
            "Let's test multiple things simultaneously",
        ]
        
        for proposal in proposals:
            detected = AntiPatternDetector.check_action_proposal(proposal)
            assert len(detected) > 0, f"Should detect anti-pattern in: {proposal}"
    
    def test_detect_parallel_actions(self):
        """Should detect parallel action attempts."""
        proposals = [
            "Test for XSS and also check for SSRF at the same time",
            "While also testing for injection vulnerabilities",
            "Run these scans in parallel",
        ]
        
        for proposal in proposals:
            detected = AntiPatternDetector.check_action_proposal(proposal)
            assert any("parallel" in d.lower() for d in detected), \
                f"Should detect parallel pattern in: {proposal}"


class TestHumanControlPoint:
    """Test human control functionality."""
    
    def test_control_point_creation(self):
        """Should create control point for human review."""
        action = IntendedAction(
            action_type=ActionType.PLUGIN,
            name="sqlmap",
            goal="Test for SQL injection",
            expected_signal="Injection successful",
        )
        
        control_point = HumanControlPoint(
            step_number=1,
            proposed_action=action,
            requires_approval=True,
        )
        
        assert control_point.step_number == 1
        assert control_point.requires_approval is True
        assert control_point.human_decision is None
    
    def test_apply_decision(self):
        """Should apply human decision."""
        action = IntendedAction(
            action_type=ActionType.PLUGIN,
            name="test",
            goal="Test",
            expected_signal="x",
        )
        
        control_point = HumanControlPoint(
            step_number=1,
            proposed_action=action,
        )
        
        control_point.apply_decision(HumanDecision.APPROVE)
        
        assert control_point.human_decision == HumanDecision.APPROVE
        assert control_point.decision_timestamp is not None
    
    def test_apply_modification(self):
        """Should record modifications."""
        action = IntendedAction(
            action_type=ActionType.REQUEST,
            name="test",
            goal="Test endpoint",
            expected_signal="response",
        )
        
        control_point = HumanControlPoint(
            step_number=1,
            proposed_action=action,
        )
        
        modification = {"goal": "Test different endpoint", "parameters": {"url": "new_url"}}
        control_point.apply_decision(HumanDecision.MODIFY, modification)
        
        assert control_point.human_decision == HumanDecision.MODIFY
        assert control_point.modification == modification


class TestVulnerabilityStatus:
    """Test vulnerability confirmation rules."""
    
    def test_not_confirmed_by_default(self):
        """Vulnerability should not be confirmed by default."""
        from trix.core.agent_philosophy import VulnerabilityStatus
        
        vuln = VulnerabilityStatus(
            status="suspected",
            vuln_type="sqli",
            url="http://test.com/login",
        )
        
        assert vuln.is_confirmed() is False
    
    def test_confirmation_requirements(self):
        """Should require all conditions for confirmation."""
        from trix.core.agent_philosophy import VulnerabilityStatus
        
        vuln = VulnerabilityStatus(
            status="confirmed",
            vuln_type="sqli",
            url="http://test.com/login",
            reproducible_behavior="Different response with payload",
            poc_validates=True,
            false_positive_probability=0.1,  # 10%
        )
        
        assert vuln.is_confirmed() is True
    
    def test_high_false_positive_blocks_confirmation(self):
        """High false positive probability should block confirmation."""
        from trix.core.agent_philosophy import VulnerabilityStatus
        
        vuln = VulnerabilityStatus(
            status="confirmed",
            vuln_type="sqli",
            url="http://test.com/login",
            reproducible_behavior="Something",
            poc_validates=True,
            false_positive_probability=0.5,  # 50% - too high
        )
        
        assert vuln.is_confirmed() is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
