"""Unit tests for Adaptive Scan Planner module."""

import json
import pytest

from strix.agents.planner import (
    MODULE_DESCRIPTIONS,
    MODULE_PHASES,
    MODULE_TIMEOUTS,
    PlanPriority,
    ResourceQuota,
    ScanPhase,
    ScanPlan,
    ScanPlanConfig,
    ScanPlanner,
    ScanStep,
    StepStatus,
    create_plan_from_fingerprint,
)
from strix.core.tci import (
    ComplexityLevel,
    SecurityPosture,
    TargetFingerprint,
    TCIResult,
    compute_tci,
)


class TestScanStep:
    """Tests for ScanStep data class."""

    def test_step_creation(self) -> None:
        """Test creating a scan step."""
        step = ScanStep(
            step_id="step-001",
            step_number=1,
            module="sql_injection",
            description="Test for SQL injection",
            priority=PlanPriority.HIGH,
            phase=ScanPhase.VULNERABILITY_SCAN,
        )
        assert step.step_id == "step-001"
        assert step.module == "sql_injection"
        assert step.priority == PlanPriority.HIGH
        assert step.safe_mode is True  # Default
        assert step.status == StepStatus.PENDING

    def test_step_to_dict(self) -> None:
        """Test converting step to dictionary."""
        step = ScanStep(
            step_id="step-001",
            step_number=1,
            module="xss",
            description="Test for XSS",
            priority=PlanPriority.MEDIUM,
            phase=ScanPhase.VULNERABILITY_SCAN,
            timeout_seconds=300,
            quota=50,
        )
        step_dict = step.to_dict()

        assert step_dict["step"] == 1
        assert step_dict["module"] == "xss"
        assert step_dict["priority"] == "medium"
        assert step_dict["phase"] == "vulnerability_scan"
        assert step_dict["timeout_seconds"] == 300
        assert step_dict["quota"] == 50


class TestResourceQuota:
    """Tests for ResourceQuota data class."""

    def test_default_quota(self) -> None:
        """Test default quota values."""
        quota = ResourceQuota()
        assert quota.max_requests == 1000
        assert quota.max_duration_minutes == 60
        assert quota.max_parallel_tests == 5
        assert quota.rate_limit_rps == 10.0

    def test_custom_quota(self) -> None:
        """Test custom quota values."""
        quota = ResourceQuota(
            max_requests=500,
            max_duration_minutes=30,
            rate_limit_rps=5.0,
        )
        assert quota.max_requests == 500
        assert quota.max_duration_minutes == 30
        assert quota.rate_limit_rps == 5.0


class TestScanPlanConfig:
    """Tests for ScanPlanConfig model."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = ScanPlanConfig()
        assert config.enable_safe_mode is True
        assert config.include_reconnaissance is True
        assert config.include_validation is True
        assert config.max_steps == 20
        assert config.max_modules == 5
        assert config.low_complexity_threshold == 30.0
        assert config.high_complexity_threshold == 70.0

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = ScanPlanConfig(
            enable_safe_mode=False,
            max_steps=10,
            high_complexity_threshold=80.0,
        )
        assert config.enable_safe_mode is False
        assert config.max_steps == 10
        assert config.high_complexity_threshold == 80.0

    def test_critical_vulns_config(self) -> None:
        """Test critical vulnerability list."""
        config = ScanPlanConfig()
        assert "SQL Injection" in config.critical_vulns
        assert "RCE" in config.critical_vulns
        assert "SSRF" in config.critical_vulns


class TestScanPlan:
    """Tests for ScanPlan data class."""

    def create_sample_plan(self) -> ScanPlan:
        """Helper to create a sample plan."""
        steps = [
            ScanStep(
                step_id="step-001",
                step_number=1,
                module="reconnaissance",
                description="Perform reconnaissance",
                priority=PlanPriority.HIGH,
                phase=ScanPhase.RECONNAISSANCE,
            ),
            ScanStep(
                step_id="step-002",
                step_number=2,
                module="sql_injection",
                description="Test SQL injection",
                priority=PlanPriority.HIGH,
                phase=ScanPhase.VULNERABILITY_SCAN,
                dependencies=["step-001"],
            ),
            ScanStep(
                step_id="step-003",
                step_number=3,
                module="xss",
                description="Test XSS",
                priority=PlanPriority.MEDIUM,
                phase=ScanPhase.VULNERABILITY_SCAN,
                dependencies=["step-001"],
            ),
        ]
        return ScanPlan(
            plan_id="plan-test-001",
            target="https://example.com",
            tci_score=65.0,
            complexity_level="high",
            created_at="2024-01-01T00:00:00Z",
            fingerprint_summary={"category": "web_application"},
            steps=steps,
            modules=["reconnaissance", "sql_injection", "xss"],
            quotas=ResourceQuota(),
            safe_mode=True,
            estimated_duration_minutes=30,
        )

    def test_plan_to_dict(self) -> None:
        """Test converting plan to dictionary."""
        plan = self.create_sample_plan()
        plan_dict = plan.to_dict()

        assert plan_dict["plan_id"] == "plan-test-001"
        assert plan_dict["target"] == "https://example.com"
        assert plan_dict["tci_score"] == 65.0
        assert len(plan_dict["plan"]) == 3
        assert plan_dict["safe_mode"] is True

    def test_plan_to_json(self) -> None:
        """Test converting plan to JSON."""
        plan = self.create_sample_plan()
        json_str = plan.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["plan_id"] == "plan-test-001"

    def test_get_steps_by_phase(self) -> None:
        """Test filtering steps by phase."""
        plan = self.create_sample_plan()

        recon_steps = plan.get_steps_by_phase(ScanPhase.RECONNAISSANCE)
        assert len(recon_steps) == 1
        assert recon_steps[0].module == "reconnaissance"

        vuln_steps = plan.get_steps_by_phase(ScanPhase.VULNERABILITY_SCAN)
        assert len(vuln_steps) == 2

    def test_get_steps_by_priority(self) -> None:
        """Test filtering steps by priority."""
        plan = self.create_sample_plan()

        high_priority = plan.get_steps_by_priority(PlanPriority.HIGH)
        assert len(high_priority) == 2

        medium_priority = plan.get_steps_by_priority(PlanPriority.MEDIUM)
        assert len(medium_priority) == 1

    def test_get_pending_steps(self) -> None:
        """Test getting pending steps."""
        plan = self.create_sample_plan()
        pending = plan.get_pending_steps()
        assert len(pending) == 3

        # Complete one step
        plan.mark_step_completed("step-001")
        pending = plan.get_pending_steps()
        assert len(pending) == 2

    def test_get_next_step(self) -> None:
        """Test getting next executable step."""
        plan = self.create_sample_plan()

        # First step should be recon (no dependencies)
        next_step = plan.get_next_step()
        assert next_step is not None
        assert next_step.step_id == "step-001"

        # After completing recon, other steps become available
        plan.mark_step_completed("step-001")
        next_step = plan.get_next_step()
        assert next_step is not None
        assert next_step.step_id in ["step-002", "step-003"]

    def test_mark_step_completed(self) -> None:
        """Test marking step as completed."""
        plan = self.create_sample_plan()

        result = plan.mark_step_completed("step-001", {"findings": []})
        assert result is True
        assert plan.steps[0].status == StepStatus.COMPLETED
        assert plan.steps[0].result == {"findings": []}

    def test_mark_step_failed(self) -> None:
        """Test marking step as failed."""
        plan = self.create_sample_plan()

        result = plan.mark_step_failed("step-002", "Connection timeout")
        assert result is True
        assert plan.steps[1].status == StepStatus.FAILED
        assert plan.steps[1].notes == "Connection timeout"


class TestScanPlanner:
    """Tests for ScanPlanner class."""

    def test_planner_creation(self) -> None:
        """Test creating a planner."""
        planner = ScanPlanner()
        assert planner.config is not None
        assert planner.config.enable_safe_mode is True

    def test_planner_with_config(self) -> None:
        """Test creating planner with custom config."""
        config = ScanPlanConfig(
            max_steps=10,
            enable_safe_mode=False,
        )
        planner = ScanPlanner(config)
        assert planner.config.max_steps == 10
        assert planner.config.enable_safe_mode is False

    def test_generate_plan_basic(self) -> None:
        """Test basic plan generation."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            technologies=["nginx", "python"],
            auth_types=["basic"],
        )
        tci_result = compute_tci(fp)

        planner = ScanPlanner()
        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        assert plan.plan_id.startswith("plan-")
        assert plan.target == "https://example.com"
        assert plan.tci_score == tci_result.score
        assert len(plan.steps) > 0
        assert plan.safe_mode is True

    def test_generate_plan_includes_phases(self) -> None:
        """Test that plan includes expected phases."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            databases=["postgresql"],
        )
        tci_result = compute_tci(fp)

        planner = ScanPlanner()
        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        phases = {step.phase for step in plan.steps}
        assert ScanPhase.RECONNAISSANCE in phases or ScanPhase.ENUMERATION in phases

    def test_generate_plan_respects_max_steps(self) -> None:
        """Test that plan respects max steps config."""
        config = ScanPlanConfig(max_steps=5)
        planner = ScanPlanner(config)

        fp = TargetFingerprint(
            open_ports=[80, 443, 8080],
            technologies=["django", "postgresql", "redis"],
            auth_types=["jwt", "oauth2"],
            has_graphql=True,
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        assert len(plan.steps) <= 5

    def test_generate_plan_respects_max_modules(self) -> None:
        """Test that plan respects max modules config."""
        config = ScanPlanConfig(max_modules=3)
        planner = ScanPlanner(config)

        fp = TargetFingerprint(
            open_ports=[80, 443],
            databases=["postgresql"],
            auth_types=["jwt"],
            has_graphql=True,
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        assert len(plan.modules) <= 3

    def test_generate_plan_safe_mode_override(self) -> None:
        """Test safe mode override."""
        planner = ScanPlanner()

        fp = TargetFingerprint(open_ports=[80])
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
            override_safe_mode=False,
        )

        assert plan.safe_mode is False

    def test_generate_plan_additional_modules(self) -> None:
        """Test adding additional modules to plan."""
        planner = ScanPlanner()

        fp = TargetFingerprint(open_ports=[80])
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
            additional_modules=["custom_module"],
        )

        assert "custom_module" in plan.modules

    def test_quotas_scale_with_complexity(self) -> None:
        """Test that quotas scale with target complexity."""
        planner = ScanPlanner()

        # Low complexity target
        fp_low = TargetFingerprint(open_ports=[80])
        tci_low = compute_tci(fp_low)
        plan_low = planner.generate_plan(
            target="https://simple.com",
            fingerprint=fp_low,
            tci_result=tci_low,
        )

        # High complexity target
        fp_high = TargetFingerprint(
            open_ports=[80, 443, 8080, 3306, 5432],
            technologies=["java", "spring", "postgresql"],
            auth_types=["oauth2", "jwt"],
            has_graphql=True,
            has_waf=True,
        )
        tci_high = compute_tci(fp_high)
        plan_high = planner.generate_plan(
            target="https://complex.com",
            fingerprint=fp_high,
            tci_result=tci_high,
        )

        # High complexity should have different quotas
        # More time but slower rate
        assert plan_high.quotas.max_duration_minutes >= plan_low.quotas.max_duration_minutes

    def test_step_dependencies(self) -> None:
        """Test that steps have proper dependencies."""
        planner = ScanPlanner()

        fp = TargetFingerprint(
            open_ports=[80, 443],
            databases=["postgresql"],
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        # Vulnerability scan steps should depend on enumeration
        enum_step = next(
            (s for s in plan.steps if s.phase == ScanPhase.ENUMERATION),
            None
        )
        if enum_step:
            vuln_steps = [s for s in plan.steps if s.phase == ScanPhase.VULNERABILITY_SCAN]
            for step in vuln_steps:
                assert enum_step.step_id in step.dependencies

    def test_priority_assignment(self) -> None:
        """Test that priorities are assigned based on vulnerability type."""
        planner = ScanPlanner()

        fp = TargetFingerprint(
            databases=["postgresql"],  # Should trigger SQL injection
            auth_types=["jwt"],  # Should trigger JWT testing
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        # Find SQL injection step if present
        sql_step = next(
            (s for s in plan.steps if "sql" in s.module.lower()),
            None
        )
        if sql_step:
            # SQL injection should be high or critical priority
            assert sql_step.priority in [PlanPriority.CRITICAL, PlanPriority.HIGH]

    def test_timeout_scaling(self) -> None:
        """Test that timeouts scale with TCI multiplier."""
        planner = ScanPlanner()

        # Low complexity - lower multiplier
        fp_low = TargetFingerprint(open_ports=[80])
        tci_low = compute_tci(fp_low)
        plan_low = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp_low,
            tci_result=tci_low,
        )

        # High complexity with WAF - higher multiplier
        fp_high = TargetFingerprint(
            open_ports=[80, 443],
            has_waf=True,
            has_rate_limiting=True,
        )
        tci_high = compute_tci(fp_high)
        plan_high = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp_high,
            tci_result=tci_high,
        )

        # Find similar steps and compare timeouts
        low_enum = next((s for s in plan_low.steps if s.module == "enumeration"), None)
        high_enum = next((s for s in plan_high.steps if s.module == "enumeration"), None)

        if low_enum and high_enum:
            assert high_enum.timeout_seconds >= low_enum.timeout_seconds

    def test_fingerprint_summary_generation(self) -> None:
        """Test that fingerprint summary is generated."""
        planner = ScanPlanner()

        fp = TargetFingerprint(
            category=TargetCategory.API,
            open_ports=[443, 8080],
            technologies=["fastapi", "postgresql"],
            auth_types=["jwt"],
            has_waf=True,
            api_endpoints=100,
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://api.example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        assert "category" in plan.fingerprint_summary
        assert plan.fingerprint_summary["category"] == "api"
        assert plan.fingerprint_summary["has_waf"] is True
        assert plan.fingerprint_summary["api_endpoints"] == 100

    def test_plan_notes_generation(self) -> None:
        """Test that plan notes are generated."""
        planner = ScanPlanner()

        fp = TargetFingerprint(
            has_graphql=True,
            has_waf=True,
            waf_type="cloudflare",
            handles_payment=True,
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        assert len(plan.notes) > 0
        # Should have notes about GraphQL, WAF, payment
        notes_text = " ".join(plan.notes).lower()
        assert "graphql" in notes_text or "waf" in notes_text or "payment" in notes_text


class TestCreatePlanFromFingerprint:
    """Tests for create_plan_from_fingerprint convenience function."""

    def test_basic_creation(self) -> None:
        """Test basic plan creation from fingerprint."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            technologies=["nginx"],
        )

        plan = create_plan_from_fingerprint("https://example.com", fp)

        assert isinstance(plan, ScanPlan)
        assert plan.target == "https://example.com"
        assert len(plan.steps) > 0

    def test_with_custom_config(self) -> None:
        """Test plan creation with custom config."""
        fp = TargetFingerprint(open_ports=[80])
        config = ScanPlanConfig(max_steps=5, enable_safe_mode=False)

        plan = create_plan_from_fingerprint("https://example.com", fp, config)

        assert len(plan.steps) <= 5
        assert plan.safe_mode is False


class TestModuleConstants:
    """Tests for module-related constants."""

    def test_module_phases(self) -> None:
        """Test module to phase mapping."""
        assert MODULE_PHASES["reconnaissance"] == ScanPhase.RECONNAISSANCE
        assert MODULE_PHASES["sql_injection"] == ScanPhase.VULNERABILITY_SCAN
        assert MODULE_PHASES["idor"] == ScanPhase.VULNERABILITY_SCAN

    def test_module_descriptions(self) -> None:
        """Test module descriptions exist."""
        assert "reconnaissance" in MODULE_DESCRIPTIONS
        assert "sql_injection" in MODULE_DESCRIPTIONS
        assert len(MODULE_DESCRIPTIONS["reconnaissance"]) > 0

    def test_module_timeouts(self) -> None:
        """Test module timeout defaults."""
        assert MODULE_TIMEOUTS["reconnaissance"] > 0
        assert MODULE_TIMEOUTS["sql_injection"] > 0
        # Reconnaissance should have higher timeout
        assert MODULE_TIMEOUTS["reconnaissance"] >= MODULE_TIMEOUTS["csrf"]


class TestPlanExecution:
    """Tests for plan execution helpers."""

    def test_step_status_transitions(self) -> None:
        """Test step status transitions."""
        step = ScanStep(
            step_id="step-001",
            step_number=1,
            module="test",
            description="Test step",
            priority=PlanPriority.MEDIUM,
            phase=ScanPhase.VULNERABILITY_SCAN,
        )

        assert step.status == StepStatus.PENDING

        step.status = StepStatus.IN_PROGRESS
        assert step.status == StepStatus.IN_PROGRESS

        step.status = StepStatus.COMPLETED
        assert step.status == StepStatus.COMPLETED

    def test_plan_estimated_duration(self) -> None:
        """Test plan duration estimation."""
        planner = ScanPlanner()

        fp = TargetFingerprint(
            open_ports=[80, 443],
            databases=["postgresql"],
        )
        tci_result = compute_tci(fp)

        plan = planner.generate_plan(
            target="https://example.com",
            fingerprint=fp,
            tci_result=tci_result,
        )

        # Duration should be sum of step timeouts (approximately)
        total_step_time = sum(s.timeout_seconds for s in plan.steps)
        # Estimated duration should be reasonable
        assert plan.estimated_duration_minutes > 0
        # Should be less than total step time (some parallelization expected)
        assert plan.estimated_duration_minutes <= total_step_time / 60 * 1.5


# Import for type hints
from strix.core.tci import TargetCategory
