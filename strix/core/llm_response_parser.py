"""LLM Response Parser - Enforces Mandatory Output Structure.

This module parses LLM responses and enforces the mandatory output format:

[VULN_HYPOTHESIS]
<one sentence description>

[EVIDENCE]
- evidence 1
- evidence 2

[INTENDED_ACTION]
type: plugin | request
name: <tool name>
goal: <single goal>
expected_signal: <signal to look for>

Any response not conforming to this structure is REJECTED.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from strix.core.agent_philosophy import (
    IntendedAction,
    ActionType,
    VulnHypothesis,
    Evidence,
    StepOutput,
    PhilosophyValidator,
    AntiPatternDetector,
)

logger = logging.getLogger(__name__)


@dataclass
class ParseResult:
    """Result of parsing an LLM response."""
    
    success: bool
    step_output: StepOutput | None = None
    errors: list[str] = field(default_factory=list)
    raw_response: str = ""



class LLMResponseParser:
    """Parses LLM responses and enforces the mandatory output format.
    
    This parser ensures:
    1. Response contains INTENDED_ACTION (mandatory)
    2. Only ONE action per response
    3. No termination attempts
    4. No execution claims
    5. No parallel action proposals
    """
    
    # Section markers
    HYPOTHESIS_MARKER = "[VULN_HYPOTHESIS]"
    EVIDENCE_MARKER = "[EVIDENCE]"
    ACTION_MARKER = "[INTENDED_ACTION]"
    
    # Regex patterns
    ACTION_TYPE_PATTERN = re.compile(r"type:\s*(plugin|request|explore|verify|wait)", re.IGNORECASE)
    ACTION_NAME_PATTERN = re.compile(r"name:\s*(.+?)(?:\n|$)", re.IGNORECASE)
    ACTION_GOAL_PATTERN = re.compile(r"goal:\s*(.+?)(?:\n|$)", re.IGNORECASE)
    ACTION_SIGNAL_PATTERN = re.compile(r"expected_signal:\s*(.+?)(?:\n|$)", re.IGNORECASE)
    
    def __init__(self, strict_mode: bool = True):
        """Initialize parser.
        
        Args:
            strict_mode: If True, reject any non-conforming response.
                        If False, try to extract what we can.
        """
        self.strict_mode = strict_mode
    
    def parse(self, response: str) -> ParseResult:
        """Parse an LLM response into structured output.
        
        Args:
            response: Raw LLM response text
            
        Returns:
            ParseResult with success status and parsed output
        """
        errors = []
        
        # Check for anti-patterns first
        anti_patterns = AntiPatternDetector.check_action_proposal(response)
        if anti_patterns:
            errors.extend(anti_patterns)
        
        # Check for philosophy violations
        philosophy_errors = PhilosophyValidator.validate_llm_response(response)
        if philosophy_errors:
            errors.extend(philosophy_errors)
        
        # If strict mode and errors found, reject immediately
        if self.strict_mode and errors:
            return ParseResult(
                success=False,
                errors=errors,
                raw_response=response,
            )
        
        # Parse sections
        hypothesis = self._parse_hypothesis(response)
        evidence = self._parse_evidence(response)
        intended_action = self._parse_intended_action(response)
        
        # INTENDED_ACTION is mandatory
        if not intended_action:
            errors.append("Missing mandatory [INTENDED_ACTION] section")
            
            if self.strict_mode:
                return ParseResult(
                    success=False,
                    errors=errors,
                    raw_response=response,
                )
        
        # Validate the action if present
        if intended_action:
            action_errors = intended_action.validate()
            if action_errors:
                errors.extend(action_errors)
                
                if self.strict_mode:
                    return ParseResult(
                        success=False,
                        errors=errors,
                        raw_response=response,
                    )
        
        # Build output
        step_output = StepOutput(
            hypothesis=hypothesis,
            evidence=evidence,
            intended_action=intended_action,
            reasoning=self._extract_reasoning(response),
        )
        
        return ParseResult(
            success=len(errors) == 0 or not self.strict_mode,
            step_output=step_output,
            errors=errors,
            raw_response=response,
        )
    
    def _parse_hypothesis(self, response: str) -> VulnHypothesis | None:
        """Parse the VULN_HYPOTHESIS section."""
        if self.HYPOTHESIS_MARKER not in response:
            return None
        
        # Find section content
        start = response.find(self.HYPOTHESIS_MARKER) + len(self.HYPOTHESIS_MARKER)
        
        # Find end (next marker or end of string)
        end = len(response)
        for marker in [self.EVIDENCE_MARKER, self.ACTION_MARKER]:
            pos = response.find(marker, start)
            if pos != -1 and pos < end:
                end = pos
        
        section = response[start:end].strip()
        
        if not section:
            return None
        
        # Parse fields
        lines = section.split("\n")
        description = lines[0].strip() if lines else ""
        
        vuln_type = "unknown"
        confidence = "low"
        
        for line in lines[1:]:
            line = line.strip()
            if line.lower().startswith("type:"):
                vuln_type = line.split(":", 1)[1].strip()
            elif line.lower().startswith("confidence:"):
                confidence = line.split(":", 1)[1].strip().lower()
        
        return VulnHypothesis(
            description=description,
            vuln_type=vuln_type,
            confidence=confidence,
        )
    
    def _parse_evidence(self, response: str) -> list[Evidence]:
        """Parse the EVIDENCE section."""
        if self.EVIDENCE_MARKER not in response:
            return []
        
        start = response.find(self.EVIDENCE_MARKER) + len(self.EVIDENCE_MARKER)
        
        # Find end
        end = len(response)
        for marker in [self.HYPOTHESIS_MARKER, self.ACTION_MARKER]:
            pos = response.find(marker, start)
            if pos != -1 and pos < end:
                end = pos
        
        section = response[start:end].strip()
        
        evidence_list = []
        for line in section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                content = line[1:].strip()
                if content:
                    evidence_list.append(Evidence(
                        source="llm_analysis",
                        content=content,
                        supports_hypothesis=True,
                    ))
        
        return evidence_list
    
    def _parse_intended_action(self, response: str) -> IntendedAction | None:
        """Parse the INTENDED_ACTION section."""
        if self.ACTION_MARKER not in response:
            return None
        
        # Check for multiple action markers (forbidden)
        if response.count(self.ACTION_MARKER) > 1:
            logger.warning("Multiple INTENDED_ACTION sections detected - using first only")
        
        start = response.find(self.ACTION_MARKER) + len(self.ACTION_MARKER)
        
        # Find end
        end = len(response)
        for marker in [self.HYPOTHESIS_MARKER, self.EVIDENCE_MARKER]:
            pos = response.find(marker, start)
            if pos != -1 and pos < end:
                end = pos
        
        section = response[start:end].strip()
        
        # Extract fields using regex
        action_type_match = self.ACTION_TYPE_PATTERN.search(section)
        name_match = self.ACTION_NAME_PATTERN.search(section)
        goal_match = self.ACTION_GOAL_PATTERN.search(section)
        signal_match = self.ACTION_SIGNAL_PATTERN.search(section)
        
        if not all([action_type_match, name_match, goal_match, signal_match]):
            logger.warning("Incomplete INTENDED_ACTION section")
            return None
        
        # Map action type
        action_type_str = action_type_match.group(1).lower()
        action_type_map = {
            "plugin": ActionType.PLUGIN,
            "request": ActionType.REQUEST,
            "explore": ActionType.EXPLORE,
            "verify": ActionType.VERIFY,
            "wait": ActionType.WAIT,
        }
        action_type = action_type_map.get(action_type_str, ActionType.EXPLORE)
        
        # Parse parameters if present
        parameters = self._parse_parameters(section)
        
        return IntendedAction(
            action_type=action_type,
            name=name_match.group(1).strip(),
            goal=goal_match.group(1).strip(),
            expected_signal=signal_match.group(1).strip(),
            parameters=parameters,
        )
    
    def _parse_parameters(self, section: str) -> dict[str, Any]:
        """Parse parameters from action section."""
        parameters = {}
        
        # Look for parameters: block
        params_match = re.search(
            r"parameters:\s*\n((?:\s+\w+:\s*.+\n?)+)", 
            section, 
            re.IGNORECASE
        )
        
        if params_match:
            params_text = params_match.group(1)
            for line in params_text.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    parameters[key.strip()] = value.strip()
        
        return parameters
    
    def _extract_reasoning(self, response: str) -> str:
        """Extract reasoning/analysis from response."""
        # Get text before any markers
        earliest_marker = len(response)
        for marker in [self.HYPOTHESIS_MARKER, self.EVIDENCE_MARKER, self.ACTION_MARKER]:
            pos = response.find(marker)
            if pos != -1 and pos < earliest_marker:
                earliest_marker = pos
        
        if earliest_marker > 0:
            return response[:earliest_marker].strip()
        
        return ""
    
    def create_rejection_message(self, parse_result: ParseResult) -> str:
        """Create a message to send back to LLM when response is rejected.
        
        This guides the LLM to correct its output format.
        """
        parts = [
            "YOUR RESPONSE WAS REJECTED. Errors:",
        ]
        
        for error in parse_result.errors:
            parts.append(f"  - {error}")
        
        parts.append("")
        parts.append("You MUST respond using EXACTLY this format:")
        parts.append("")
        parts.append("[VULN_HYPOTHESIS]")
        parts.append("<one sentence description of your current hypothesis>")
        parts.append("Type: <vulnerability type>")
        parts.append("Confidence: low|medium|high")
        parts.append("")
        parts.append("[EVIDENCE]")
        parts.append("- evidence item 1")
        parts.append("- evidence item 2")
        parts.append("")
        parts.append("[INTENDED_ACTION]")
        parts.append("type: plugin | request | explore | verify | wait")
        parts.append("name: <tool or action name>")
        parts.append("goal: <EXACTLY ONE goal - no compound goals>")
        parts.append("expected_signal: <what to look for in results>")
        parts.append("")
        parts.append("CRITICAL RULES:")
        parts.append("1. You CANNOT end the scan - only propose next actions")
        parts.append("2. You CANNOT execute actions - only propose them")
        parts.append("3. You CANNOT propose multiple actions - only ONE per response")
        parts.append("4. You MUST wait for execution results before reasoning further")
        
        return "\n".join(parts)


class ResponseValidator:
    """Additional validation for LLM responses."""
    
    # Forbidden phrases that indicate analyzer behavior
    FORBIDDEN_CONCLUSIONS = [
        "scan complete",
        "analysis complete",
        "no vulnerabilities found",
        "scanning finished",
        "i have completed",
        "the scan has ended",
        "based on my analysis, there are no",
        "i conclude that",
        "final report",
        "summary of findings",
    ]
    
    # Forbidden execution claims
    FORBIDDEN_EXECUTIONS = [
        "i have executed",
        "i ran the",
        "i performed",
        "the result was",
        "executing the",
        "i tested",
        "i scanned",
    ]
    
    # Forbidden parallel action indicators
    FORBIDDEN_PARALLEL = [
        "and also",
        "while also",
        "simultaneously",
        "in parallel",
        "at the same time",
        "can also try",
        "might as well",
        "顺便",  # Chinese: "while we're at it"
        "同时",  # Chinese: "simultaneously"
    ]
    
    @classmethod
    def validate(cls, response: str) -> list[str]:
        """Validate response against all forbidden patterns.
        
        Returns:
            List of validation errors
        """
        errors = []
        response_lower = response.lower()
        
        # Check conclusions
        for phrase in cls.FORBIDDEN_CONCLUSIONS:
            if phrase in response_lower:
                errors.append(f"Forbidden conclusion: '{phrase}'")
        
        # Check execution claims
        for phrase in cls.FORBIDDEN_EXECUTIONS:
            if phrase in response_lower:
                errors.append(f"Forbidden execution claim: '{phrase}'")
        
        # Check parallel actions
        for phrase in cls.FORBIDDEN_PARALLEL:
            if phrase.lower() in response_lower:
                errors.append(f"Forbidden parallel action: '{phrase}'")
        
        return errors
    
    @classmethod
    def create_correction_prompt(cls, errors: list[str]) -> str:
        """Create a prompt to correct the LLM's behavior."""
        parts = [
            "⚠️ BEHAVIOR CORRECTION REQUIRED ⚠️",
            "",
            "You violated the following rules:",
        ]
        
        for error in errors:
            parts.append(f"  ❌ {error}")
        
        parts.extend([
            "",
            "REMEMBER YOUR IDENTITY:",
            "• You are an EXPLORER, not a judge",
            "• You PROPOSE actions, you do NOT execute them",
            "• You NEVER conclude or end scans",
            "• You provide ONE action per response",
            "",
            "Now, please reformulate your response with ONLY:",
            "1. Your current hypothesis (if any)",
            "2. Evidence you've observed",
            "3. Your SINGLE proposed next action",
        ])
        
        return "\n".join(parts)
