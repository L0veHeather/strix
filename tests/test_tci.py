"""Unit tests for Target Complexity Index (TCI) module."""

import pytest

from strix.core.tci import (
    AUTH_COMPLEXITY_SCORES,
    HIGH_RISK_PORTS,
    ComplexityLevel,
    SecurityPosture,
    TargetCategory,
    TargetComplexityIndex,
    TargetFingerprint,
    TCIConfig,
    TCIResult,
    compute_tci,
)


class TestTargetFingerprint:
    """Tests for TargetFingerprint model."""

    def test_default_fingerprint(self) -> None:
        """Test creating fingerprint with defaults."""
        fp = TargetFingerprint()
        assert fp.target_id == ""
        assert fp.category == TargetCategory.WEB_APPLICATION
        assert fp.open_ports == []
        assert fp.technologies == []
        assert fp.auth_types == []
        assert fp.api_endpoints == 0
        assert fp.has_waf is False
        assert fp.confidence_score == 0.5

    def test_fingerprint_with_values(self) -> None:
        """Test creating fingerprint with custom values."""
        fp = TargetFingerprint(
            target_id="test-001",
            target_url="https://api.example.com",
            category=TargetCategory.API,
            open_ports=[80, 443, 8080],
            technologies=["Django", "PostgreSQL"],
            auth_types=["jwt", "oauth2"],
            api_endpoints=150,
            has_waf=True,
            waf_type="cloudflare",
        )
        assert fp.target_id == "test-001"
        assert fp.category == TargetCategory.API
        assert len(fp.open_ports) == 3
        assert "django" in fp.technologies  # Should be normalized to lowercase
        assert fp.has_waf is True

    def test_technology_normalization(self) -> None:
        """Test that technologies are normalized to lowercase."""
        fp = TargetFingerprint(
            technologies=["NGINX", "Python", "PostgreSQL"],
            frameworks=["FastAPI", "React"],
            databases=["MySQL", "Redis"],
        )
        assert all(t.islower() for t in fp.technologies)
        assert all(f.islower() for f in fp.frameworks)
        assert all(d.islower() for d in fp.databases)


class TestTCIConfig:
    """Tests for TCI configuration."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = TCIConfig()
        assert config.port_count_weight == 0.10
        assert config.auth_complexity_weight == 0.15
        assert config.api_surface_weight == 0.12
        assert config.port_count_low == 5
        assert config.api_count_high == 100

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = TCIConfig(
            port_count_weight=0.20,
            auth_complexity_weight=0.25,
            port_count_low=10,
        )
        assert config.port_count_weight == 0.20
        assert config.auth_complexity_weight == 0.25
        assert config.port_count_low == 10

    def test_config_validation(self) -> None:
        """Test that config validates weight bounds."""
        with pytest.raises(ValueError):
            TCIConfig(port_count_weight=1.5)  # > 1.0

        with pytest.raises(ValueError):
            TCIConfig(auth_complexity_weight=-0.1)  # < 0.0


class TestTCIResult:
    """Tests for TCI result data class."""

    def test_result_to_dict(self) -> None:
        """Test converting result to dictionary."""
        result = TCIResult(
            score=75.5,
            complexity_level=ComplexityLevel.HIGH,
            security_posture=SecurityPosture.STANDARD,
            port_score=0.6,
            auth_complexity_score=0.8,
            recommended_modules=["sql_injection", "idor"],
            priority_vulnerabilities=["SQL Injection", "IDOR"],
        )

        result_dict = result.to_dict()
        assert result_dict["score"] == 75.5
        assert result_dict["complexity_level"] == "high"
        assert result_dict["security_posture"] == "standard"
        assert "sql_injection" in result_dict["recommended_modules"]


class TestTargetComplexityIndex:
    """Tests for TCI calculator."""

    def test_minimal_complexity_target(self) -> None:
        """Test TCI calculation for minimal complexity target."""
        fp = TargetFingerprint(
            open_ports=[80],
            technologies=["nginx"],
        )
        result = compute_tci(fp)

        assert result.score < 30
        assert result.complexity_level == ComplexityLevel.MINIMAL

    def test_low_complexity_target(self) -> None:
        """Test TCI calculation for low complexity target."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            technologies=["nginx", "python"],
            auth_types=["basic"],
            api_endpoints=10,
        )
        result = compute_tci(fp)

        assert result.score < 50
        assert result.complexity_level in [ComplexityLevel.MINIMAL, ComplexityLevel.LOW]

    def test_medium_complexity_target(self) -> None:
        """Test TCI calculation for medium complexity target."""
        fp = TargetFingerprint(
            open_ports=[22, 80, 443, 8080],
            technologies=["django", "postgresql", "redis"],
            auth_types=["jwt"],
            api_endpoints=50,
            has_waf=False,
        )
        result = compute_tci(fp)

        assert 30 <= result.score <= 70
        assert result.complexity_level in [ComplexityLevel.LOW, ComplexityLevel.MEDIUM]

    def test_high_complexity_target(self) -> None:
        """Test TCI calculation for high complexity target."""
        fp = TargetFingerprint(
            open_ports=[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200],
            technologies=["java", "spring", "postgresql", "redis", "elasticsearch"],
            frameworks=["spring"],
            databases=["postgresql", "redis", "elasticsearch"],
            auth_types=["oauth2", "jwt"],
            api_endpoints=200,
            has_graphql=True,
            has_graphql_introspection=True,
            has_waf=True,
            waf_type="cloudflare",
            cloud_provider="aws",
            handles_pii=True,
        )
        result = compute_tci(fp)

        assert result.score >= 60
        assert result.complexity_level in [ComplexityLevel.HIGH, ComplexityLevel.CRITICAL]

    def test_high_risk_ports_detection(self) -> None:
        """Test that high-risk ports increase complexity."""
        # Without high-risk ports
        fp_low = TargetFingerprint(open_ports=[8000, 9000])
        result_low = compute_tci(fp_low)

        # With high-risk ports (database, RDP)
        fp_high = TargetFingerprint(open_ports=[3306, 5432, 3389])
        result_high = compute_tci(fp_high)

        assert result_high.high_risk_ports_score > result_low.high_risk_ports_score
        assert result_high.score > result_low.score

    def test_auth_complexity_scoring(self) -> None:
        """Test that auth types affect complexity."""
        # No auth
        fp_none = TargetFingerprint(auth_types=["none"])
        result_none = compute_tci(fp_none)

        # OAuth2 (high complexity)
        fp_oauth = TargetFingerprint(auth_types=["oauth2"])
        result_oauth = compute_tci(fp_oauth)

        assert result_oauth.auth_complexity_score > result_none.auth_complexity_score

    def test_api_surface_scoring(self) -> None:
        """Test that API endpoints affect complexity."""
        # Few endpoints
        fp_few = TargetFingerprint(api_endpoints=5)
        result_few = compute_tci(fp_few)

        # Many endpoints
        fp_many = TargetFingerprint(api_endpoints=200)
        result_many = compute_tci(fp_many)

        assert result_many.api_surface_score > result_few.api_surface_score

    def test_graphql_increases_complexity(self) -> None:
        """Test that GraphQL presence increases complexity."""
        fp_rest = TargetFingerprint(api_endpoints=50)
        result_rest = compute_tci(fp_rest)

        fp_graphql = TargetFingerprint(
            api_endpoints=50,
            has_graphql=True,
            has_graphql_introspection=True,
        )
        result_graphql = compute_tci(fp_graphql)

        assert result_graphql.api_surface_score > result_rest.api_surface_score
        assert result_graphql.score > result_rest.score

    def test_waf_increases_complexity(self) -> None:
        """Test that WAF presence increases complexity score."""
        fp_no_waf = TargetFingerprint(open_ports=[80, 443])
        result_no_waf = compute_tci(fp_no_waf)

        fp_with_waf = TargetFingerprint(
            open_ports=[80, 443],
            has_waf=True,
            waf_type="cloudflare",
        )
        result_with_waf = compute_tci(fp_with_waf)

        assert result_with_waf.waf_complexity_score > result_no_waf.waf_complexity_score

    def test_module_recommendations_jwt(self) -> None:
        """Test that JWT auth triggers JWT module recommendation."""
        fp = TargetFingerprint(auth_types=["jwt"])
        result = compute_tci(fp)

        assert "authentication_jwt" in result.recommended_modules

    def test_module_recommendations_graphql(self) -> None:
        """Test that GraphQL triggers graphql module recommendation."""
        fp = TargetFingerprint(has_graphql=True)
        result = compute_tci(fp)

        assert "graphql_security" in result.recommended_modules

    def test_module_recommendations_database(self) -> None:
        """Test that databases trigger SQL injection module."""
        fp = TargetFingerprint(databases=["postgresql", "mysql"])
        result = compute_tci(fp)

        assert "sql_injection" in result.recommended_modules

    def test_priority_vulnerabilities(self) -> None:
        """Test that priority vulnerabilities are generated."""
        fp = TargetFingerprint(
            databases=["postgresql"],
            has_graphql=True,
            auth_types=["jwt"],
            has_file_upload=True,
        )
        result = compute_tci(fp)

        assert len(result.priority_vulnerabilities) > 0
        assert "SQL Injection" in result.priority_vulnerabilities

    def test_security_posture_hardened(self) -> None:
        """Test hardened security posture detection."""
        fp = TargetFingerprint(
            has_waf=True,
            has_rate_limiting=True,
            has_csrf_protection=True,
            has_mfa=True,
            security_headers=["CSP", "HSTS", "X-Frame-Options", "X-XSS-Protection"],
            auth_types=["oauth2"],
        )
        result = compute_tci(fp)

        assert result.security_posture == SecurityPosture.HARDENED

    def test_security_posture_permissive(self) -> None:
        """Test permissive security posture detection."""
        fp = TargetFingerprint(
            open_ports=[21, 23],  # FTP, Telnet
            auth_types=["none"],
            has_graphql_introspection=True,
            known_vulnerabilities=["CVE-2021-12345"],
        )
        result = compute_tci(fp)

        assert result.security_posture == SecurityPosture.PERMISSIVE

    def test_timeout_multiplier(self) -> None:
        """Test that timeout multiplier scales with complexity."""
        fp_simple = TargetFingerprint(open_ports=[80])
        result_simple = compute_tci(fp_simple)

        fp_complex = TargetFingerprint(
            open_ports=[80, 443, 8080],
            has_waf=True,
            has_rate_limiting=True,
            api_endpoints=150,
        )
        result_complex = compute_tci(fp_complex)

        assert result_complex.suggested_timeout_multiplier >= result_simple.suggested_timeout_multiplier

    def test_max_parallel_tests(self) -> None:
        """Test that max parallel tests decreases for sensitive targets."""
        fp_normal = TargetFingerprint(open_ports=[80, 443])
        result_normal = compute_tci(fp_normal)

        fp_sensitive = TargetFingerprint(
            open_ports=[80, 443],
            has_waf=True,
            has_rate_limiting=True,
            handles_payment=True,
        )
        result_sensitive = compute_tci(fp_sensitive)

        assert result_sensitive.max_parallel_tests <= result_normal.max_parallel_tests

    def test_safe_mode_suggestion(self) -> None:
        """Test that safe mode is suggested appropriately."""
        # Payment processing should always suggest safe mode
        fp_payment = TargetFingerprint(handles_payment=True)
        result_payment = compute_tci(fp_payment)
        assert result_payment.suggested_safe_mode is True

        # WAF should suggest safe mode
        fp_waf = TargetFingerprint(has_waf=True)
        result_waf = compute_tci(fp_waf)
        assert result_waf.suggested_safe_mode is True

    def test_custom_config_affects_scores(self) -> None:
        """Test that custom config weights affect final scores."""
        fp = TargetFingerprint(
            open_ports=[80, 443, 8080, 3306, 5432],
            auth_types=["oauth2"],
        )

        # Default weights
        result_default = compute_tci(fp)

        # Custom config emphasizing auth complexity
        config = TCIConfig(
            auth_complexity_weight=0.5,
            port_count_weight=0.05,
        )
        result_custom = compute_tci(fp, config)

        # Scores should differ based on weights
        assert result_default.score != result_custom.score

    def test_score_bounds(self) -> None:
        """Test that scores are always within 0-100 bounds."""
        # Minimal target
        fp_minimal = TargetFingerprint()
        result_minimal = compute_tci(fp_minimal)
        assert 0 <= result_minimal.score <= 100

        # Maximal target
        fp_maximal = TargetFingerprint(
            open_ports=list(range(1, 100)),
            technologies=["java", "python", "nodejs", "php", "ruby"],
            frameworks=["spring", "django", "express", "laravel"],
            databases=["postgresql", "mysql", "mongodb", "redis"],
            auth_types=["oauth2", "jwt", "saml", "mfa"],
            api_endpoints=500,
            has_graphql=True,
            has_graphql_introspection=True,
            has_websocket=True,
            has_waf=True,
            waf_type="cloudflare",
            has_rate_limiting=True,
            cloud_provider="aws",
            is_containerized=True,
            has_serverless=True,
            handles_pii=True,
            handles_payment=True,
        )
        result_maximal = compute_tci(fp_maximal)
        assert 0 <= result_maximal.score <= 100

    def test_calculation_notes(self) -> None:
        """Test that calculation notes are populated."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            technologies=["nginx", "python"],
        )
        result = compute_tci(fp)

        assert len(result.calculation_notes) > 0
        # Should have notes about port count, tech stack, etc.
        assert any("Port count" in note for note in result.calculation_notes)


class TestConstants:
    """Tests for TCI constants."""

    def test_high_risk_ports(self) -> None:
        """Test high-risk ports set."""
        # Database ports should be high-risk
        assert 3306 in HIGH_RISK_PORTS  # MySQL
        assert 5432 in HIGH_RISK_PORTS  # PostgreSQL
        assert 27017 in HIGH_RISK_PORTS  # MongoDB

        # Remote access ports should be high-risk
        assert 22 in HIGH_RISK_PORTS  # SSH
        assert 3389 in HIGH_RISK_PORTS  # RDP
        assert 23 in HIGH_RISK_PORTS  # Telnet

    def test_auth_complexity_scores(self) -> None:
        """Test auth complexity score ordering."""
        assert AUTH_COMPLEXITY_SCORES["none"] < AUTH_COMPLEXITY_SCORES["basic"]
        assert AUTH_COMPLEXITY_SCORES["basic"] < AUTH_COMPLEXITY_SCORES["jwt"]
        assert AUTH_COMPLEXITY_SCORES["jwt"] < AUTH_COMPLEXITY_SCORES["oauth2"]
        assert AUTH_COMPLEXITY_SCORES["oauth2"] < AUTH_COMPLEXITY_SCORES["mfa"]


class TestComputeTCIFunction:
    """Tests for the compute_tci convenience function."""

    def test_basic_computation(self) -> None:
        """Test basic TCI computation."""
        fp = TargetFingerprint(
            open_ports=[80, 443],
            technologies=["nginx"],
        )
        result = compute_tci(fp)

        assert isinstance(result, TCIResult)
        assert 0 <= result.score <= 100
        assert result.complexity_level in ComplexityLevel
        assert result.security_posture in SecurityPosture

    def test_computation_with_config(self) -> None:
        """Test TCI computation with custom config."""
        fp = TargetFingerprint(open_ports=[80])
        config = TCIConfig(port_count_weight=0.5)

        result = compute_tci(fp, config)
        assert isinstance(result, TCIResult)
