from typing import Any, Optional

from strix.agents.base_agent import BaseAgent
from strix.core.scan_controller import ScanController
from strix.core.scan_phase import ScanPhase, ScanTask
from strix.llm.config import LLMConfig
from strix.telemetry.tracer import Tracer


class StrixAgent(BaseAgent):
    max_iterations = 300

    def __init__(self, config: dict[str, Any]):
        default_modules = []

        state = config.get("state")
        if state is None or (hasattr(state, "parent_id") and state.parent_id is None):
            default_modules = ["root_agent"]

        self.default_llm_config = LLMConfig(prompt_modules=default_modules)

        super().__init__(config)
        
        # Controller manages all flow decisions
        self.scan_controller: ScanController | None = None

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:
        """Execute a scan based on the scan configuration with deterministic flow control."""
        import logging
        logger = logging.getLogger(__name__)
        
        # 添加详细的启动日志
        logger.info("=" * 80)
        logger.info("🦉 Strix Scan Starting with Deterministic Architecture")
        logger.info("=" * 80)
        
        targets = scan_config.get("targets", [])
        user_instructions = scan_config.get("user_instructions", "")

        logger.info(f"📋 Scan Configuration:")
        logger.info(f"   - Scan ID: {scan_config.get('scan_id', 'unknown')}")
        logger.info(f"   - Targets: {len(targets)}")
        logger.info(f"   - User Instructions: {user_instructions[:100] if user_instructions else 'None'}")

        # Extract target information
        urls = []
        repositories = []
        local_code = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]

            if target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "repository":
                repositories.append(details.get("target_repo", "unknown"))
            elif target_type == "local_code":
                local_code.append(details.get("target_path", "unknown"))

        # Determine primary target
        primary_target = urls[0] if urls else "http://localhost:8080"
        logger.info(f"🎯 Primary Target: {primary_target}")
        
        # Extract seed for reproducibility
        seed = scan_config.get("seed")
        if seed is not None:
            logger.info(f"🎲 Scan Seed: {seed} (reproducible mode)")
        
        # Initialize ScanController - this is now the flow control authority
        try:
            logger.info("⚙️  Initializing ScanController...")
            self.scan_controller = ScanController(initial_target=primary_target, seed=seed)
            logger.info(f"✅ ScanController initialized successfully")
            logger.info(f"   - Current Phase: {self.scan_controller.current_phase.value}")
            logger.info(f"   - Initial Task Queue: {len(self.scan_controller.task_queue)} tasks")
            logger.info(f"   - HTTP Methods to Test: {', '.join(self.scan_controller.http_methods)}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize ScanController: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        if seed is not None:
            logger.info(f"Scan initialized with seed {seed} for reproducible results")
        
        # Build initial context for the agent
        task_description_parts = [
            "You are a vulnerability scanning agent working under a ScanController.",
            "",
            "CRITICAL RULES:",
            "1. You do NOT decide when scanning is complete",
            "2. You do NOT decide which phase to execute", 
            "3. You do NOT decide to stop after finding a vulnerability",
            "4. You MUST analyze the specific task given to you and return structured results",
            "",
            f"Primary Target: {primary_target}",
        ]
        
        if urls:
            task_description_parts.append(f"\nWeb Applications: {', '.join(urls)}")
        if repositories:
            task_description_parts.append(f"\nRepositories: {', '.join(repositories)}")
        if local_code:
            task_description_parts.append(f"\nLocal Code: {', '.join(local_code)}")
        
        if user_instructions:
            task_description_parts.append(f"\nUser Instructions: {user_instructions}")
        
        task_description = "\n".join(task_description_parts)
        
        logger.info("🚀 Starting controlled scan loop...")
        # Start the controlled scan loop
        return await self._controlled_scan_loop(task_description)
    
    async def _controlled_scan_loop(self, initial_context: str) -> dict[str, Any]:
        """Execute scan under ScanController's authority.
        
        This replaces the autonomous agent_loop with controller-driven execution.
        """
        from strix.telemetry.tracer import get_global_tracer
        from strix.core.concurrent_executor import ConcurrentExecutor
        import logging
        
        logger = logging.getLogger(__name__)
        tracer = get_global_tracer()
        
        # Add initial context
        self.state.add_message("user", initial_context)
        logger.info("📝 Initial context added to agent state")
        
        iteration = 0
        max_scan_iterations = 1000  # Safety limit
        
        logger.info("🔄 Entering main scan loop")
        logger.info(f"   - Max iterations: {max_scan_iterations}")
        
        # Initialize concurrent executor for performance
        try:
            logger.info("🚀 Initializing ConcurrentExecutor...")
            async with ConcurrentExecutor(max_concurrent=10) as executor:
                self.concurrent_executor = executor
                logger.info("✅ ConcurrentExecutor initialized (10 concurrent requests)")
                
                while iteration < max_scan_iterations:
                    iteration += 1
                    
                    # 每10次迭代输出一次进度
                    if iteration % 10 == 1 or iteration <= 5:
                        logger.info(f"📊 Iteration {iteration}/{max_scan_iterations}")
                        logger.info(f"   - Current Phase: {self.scan_controller.current_phase.value}")
                        logger.info(f"   - Queue Size: {len(self.scan_controller.task_queue)}")
                        logger.info(f"   - Vulnerabilities Found: {len(self.scan_controller.vulnerabilities)}")
                    
                    # Check if scan is complete (ONLY controller decides this)
                    if self.scan_controller.is_scan_complete():
                        logger.info("✅ Scan completed (controller determined)")
                        break
                    
                    # Check for phase transition (controller decides)
                    if self.scan_controller.should_transition_phase():
                        old_phase = self.scan_controller.current_phase
                        if not self.scan_controller.transition_to_next_phase():
                            # No more phases, scan complete
                            logger.info("✅ No more phases, scan complete")
                            break
                        new_phase = self.scan_controller.current_phase
                        logger.info(f"🔄 Phase Transition: {old_phase.value} → {new_phase.value}")
                    
                    # Get next task from controller
                    task = self.scan_controller.get_next_task()
                    
                    if task is None:
                        logger.warning(f"⚠️  No tasks available at iteration {iteration}")
                        logger.warning(f"   - Phase: {self.scan_controller.current_phase.value}")
                        logger.warning(f"   - Queue: {len(self.scan_controller.task_queue)}")
                        logger.warning(f"   - Is Complete: {self.scan_controller.is_scan_complete()}")
                        # No tasks available but scan not complete - wait/error
                        break
                    
                    # 输出任务信息
                    if iteration <= 5 or iteration % 10 == 0:
                        logger.info(f"🔧 Executing Task #{iteration}")
                        logger.info(f"   - URL: {task.url}")
                        logger.info(f"   - Method: {task.method}")
                        logger.info(f"   - Phase: {task.phase.value}")
                    
                    # Execute task based on current phase
                    try:
                        await self._execute_controlled_task(task, tracer)
                    except Exception as e:
                        logger.error(f"❌ Task execution failed at iteration {iteration}: {e}")
                        import traceback
                        traceback.print_exc()
                        # Continue with next task instead of crashing
                        continue
                        
        except Exception as e:
            logger.error(f"❌ ConcurrentExecutor failed: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        # Cleanup
        self.concurrent_executor = None
        logger.info("🧹 ConcurrentExecutor cleaned up")
        
        # Generate final summary
        logger.info("📊 Generating final summary...")
        summary = self.scan_controller.get_scan_summary()
        
        logger.info("=" * 80)
        logger.info("🎉 Scan Complete!")
        logger.info("=" * 80)
        logger.info(f"   - Total Iterations: {iteration}")
        logger.info(f"   - Vulnerabilities Found: {len(self.scan_controller.vulnerabilities)}")
        logger.info(f"   - Final Phase: {self.scan_controller.current_phase.value}")
        
        return {
            "success": True,
            "scan_completed": True,
            "iterations": iteration,
            "summary": summary,
            "vulnerabilities": self.scan_controller.vulnerabilities
        }
    
    async def _execute_controlled_task(self, task: ScanTask, tracer: Optional[Tracer]) -> None:
        """Execute a single task under controller supervision.
        
        The LLM analyzes the task but does NOT decide flow control.
        """
        import httpx
        import json
        import logging
        
        logger = logging.getLogger(__name__)
        
        # Build phase-specific prompt
        phase_prompt = self._build_phase_prompt(task)
        
        # Execute HTTP request if needed (not for ANALYSIS/REPORT tasks)
        http_result = None
        if task.method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            logger.debug(f"🌐 Executing HTTP request: {task.method} {task.url}")
            # Use concurrent executor if available (performance optimization)
            if hasattr(self, 'concurrent_executor') and self.concurrent_executor:
                http_result = await self.concurrent_executor.execute_request(task)
            else:
                http_result = await self._execute_http_request(task)
            
            if http_result:
                status = http_result.get('status_code', 0)
                logger.debug(f"   Response: {status}")
        
        # Add task context to conversation
        task_context = f"""
CURRENT SCAN PHASE: {task.phase.value.upper()}
TASK: {task.method} {task.url}
TASK ID: {task.task_id}

{phase_prompt}
"""
        
        if http_result:
            task_context += f"\n\nHTTP RESPONSE:\nStatus: {http_result.get('status_code')}\nBody (snippet): {http_result.get('body', '')[:500]}"
        
        self.state.add_message("user", task_context)
        
        # Get LLM analysis
        try:
            logger.debug(f"🤖 Calling LLM for phase: {task.phase.value}")
            response = await self.llm.generate(self.state.get_conversation_history())
            logger.debug(f"✅ LLM response received ({len(response.content)} chars)")
            self.state.add_message("assistant", response.content)
            
            # Parse LLM response based on phase (now async)
            await self._process_llm_response(task, response.content, tracer)
            
        except Exception as e:
            import logging
            logging.error(f"❌ Task execution failed: {e}")
            import traceback
            traceback.print_exc()
    
    def _build_phase_prompt(self, task: ScanTask) -> str:
        """Build phase-specific prompt for the LLM."""
        phase = task.phase
        
        if phase == ScanPhase.ENUMERATION:
            return """Analyze the HTTP response for:
1. New URLs/endpoints (links, forms, API endpoints)
2. New parameters (query params, form fields, JSON keys)
3. Technologies detected (frameworks, servers, libraries)

Respond in JSON format:
{
    "new_urls": ["url1", "url2"],
    "new_params": ["param1", "param2"],
    "technologies": ["tech1", "tech2"]
}"""
        
        elif phase == ScanPhase.PARAM_EXPANSION:
            return f"""Suggest hidden parameters for: {task.url}

Known parameters: {list(self.scan_controller.discovered_params)}

Respond in JSON format:
{{
    "suggested_params": ["param1", "param2"],
    "reasoning": "why these params"
}}"""
        
        elif phase == ScanPhase.VULNERABILITY_TEST:
            vuln_type = task.source.split(":")[-1] if ":" in task.source else "generic"
            return f"""Test for {vuln_type} vulnerability.

Analyze the response for indicators of {vuln_type}.

Respond in JSON format:
{{
    "vulnerable": true/false,
    "vulnerability_type": "{vuln_type}",
    "confidence": "high/medium/low",
    "evidence": "description",
    "severity": "critical/high/medium/low"
}}"""
        
        elif phase == ScanPhase.LLM_VERIFICATION:
            # NEW: Generate PoC requests for validation
            vuln_type = task.source.split(":")[-1] if ":" in task.source else "unknown"
            verification_context = getattr(task, 'verification_context', {})
            
            return f"""CRITICAL: Generate PoC (Proof of Concept) request for validation.

Vulnerability Type: {vuln_type}
Target URL: {task.url}
Method: {task.method}
Parameters: {task.parameters}
Initial Evidence: {verification_context.get('evidence', 'None')}

YOU MUST:
1. Generate 1-3 testable PoC requests
2. Specify exact payloads and where to inject them
3. Define indicators to look for in responses
4. Output ONLY JSON format

YOU MUST NOT:
1. Determine if vulnerability is confirmed
2. Output "vulnerability confirmed" or similar conclusions
3. Make final determinations

Respond in JSON format:
{{
    "poc_requests": [
        {{
            "poc_name": "Test Name",
            "method": "GET",
            "url": "{task.url}",
            "parameters": {{"param": "payload"}},
            "headers": {{"header": "value"}},
            "expected_indicators": ["indicator1", "indicator2"],
            "validation_strategy": "pattern_matching",
            "reasoning": "why this will work"
        }}
    ],
    "attack_vectors": ["vector description"],
    "validation_notes": "context"
}}"""
        
        elif phase == ScanPhase.DEEP_ANALYSIS:
            vulns = len(self.scan_controller.vulnerabilities)
            return f"""Analyze {vulns} discovered vulnerabilities for:
1. Vulnerability chaining possibilities
2. Exploitation paths
3. Impact assessment

Respond in JSON format:
{{
    "chains": ["description of chains"],
    "recommendations": ["rec1", "rec2"]
}}"""
        
        else:  # SUMMARY
            return """Generate final vulnerability report summary.

DO NOT decide if scan is complete - that's handled by the controller.

Provide a concise summary of findings."""
    
    async def _execute_http_request(self, task: ScanTask) -> dict[str, Any]:
        """Execute HTTP request for a task."""
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                if task.method == "GET":
                    response = await client.get(task.url, params=task.parameters)
                elif task.method == "POST":
                    response = await client.post(task.url, data=task.parameters)
                else:
                    response = await client.request(task.method, task.url, params=task.parameters)
                
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:2000]  # Limit response size
                }
        except Exception as e:
            import logging
            logging.error(f"HTTP request failed: {e}")
            return {"status_code": 0, "error": str(e)}
    
    async def _process_llm_response(self, task: ScanTask, content: str, tracer: Optional[Tracer]) -> None:
        """Process LLM response and update controller state with schema validation."""
        import json
        import re
        import logging
        from pydantic import ValidationError
        from strix.core.phase_schemas import (
            EnumerationOutput,
            ParamExpansionOutput,
            VulnerabilityTestOutput,
            LLMVerificationOutput,
            DeepAnalysisOutput
        )
        
        logger = logging.getLogger(__name__)
        
        # Extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', content)
        if not json_match:
            logger.warning(f"No JSON found in LLM response for phase {task.phase.value}")
            return
        
        try:
            raw_result = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON from LLM: {e}")
            return
        
        # Validate        # Process based on phase with schema validation
        if task.phase == ScanPhase.ENUMERATION:
            try:
                result = EnumerationOutput.model_validate(raw_result)
            except ValidationError as e:
                logger.error(f"Schema validation failed for ENUMERATION: {e}")
                return
            
            # Add discovered URLs
            for url in result.new_urls:
                if self.scan_controller.add_discovered_url(url):
                    # Add enumeration task for new URL
                    new_task = ScanTask(
                        url=url,
                        method="GET",
                        phase=ScanPhase.ENUMERATION,
                        source="discovered"
                    )
                    self.scan_controller.add_task(new_task)
            
            # Add discovered params
            for param in result.new_params:
                self.scan_controller.add_discovered_param(param)
        
        elif task.phase == ScanPhase.PARAM_EXPANSION:
            try:
                result = ParamExpansionOutput.model_validate(raw_result)
            except ValidationError as e:
                logger.error(f"Schema validation failed for PARAM_EXPANSION: {e}")
                return
            
            # CRITICAL FIX: Create test tasks for new parameters
            for param in result.suggested_params:
                if self.scan_controller.add_discovered_param(param):
                    # Create test tasks for this param on all known URLs
                    for url in self.scan_controller.discovered_urls:
                        # Create a test task with this parameter
                        test_task = ScanTask(
                            url=url,
                            method="GET",
                            parameters={param: "FUZZ"},  # Placeholder value
                            phase=ScanPhase.PARAM_EXPANSION,
                            source=f"param_test:{param}"
                        )
                        self.scan_controller.add_task(test_task)
                    
                    logger.info(f"Created {len(self.scan_controller.discovered_urls)} test tasks for param: {param}")
        
        elif task.phase == ScanPhase.VULNERABILITY_TEST:
            try:
                result = VulnerabilityTestOutput.model_validate(raw_result)
            except ValidationError as e:
                logger.error(f"Schema validation failed for VULNERABILITY_TEST: {e}")
                return
            
            # Check if vulnerability found
            if result.vulnerable:
                # Mark as suspected - needs verification
                suspected_vuln = {
                    "type": result.vulnerability_type,
                    "url": task.url,
                    "method": task.method,
                    "severity": result.severity,
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                    "parameters": task.parameters
                }
                self.scan_controller.add_suspected_vulnerability(suspected_vuln)
        
        elif task.phase == ScanPhase.LLM_VERIFICATION:
            # NEW: Process PoC requests and validate
            from strix.core.poc_validator import PoCValidator, PoCRequest
            
            try:
                result = LLMVerificationOutput.model_validate(raw_result)
            except ValidationError as e:
                logger.error(f"Schema validation failed for LLM_VERIFICATION: {e}")
                return
            
            if not result.poc_requests:
                logger.warning(f"No PoC requests generated for {task.url}")
                return
            
            validator = PoCValidator()
            
            # Execute each PoC and validate
            for poc_schema in result.poc_requests:
                poc = PoCRequest(
                    method=poc_schema.method,
                    url=poc_schema.url,
                    parameters=poc_schema.parameters,
                    headers=poc_schema.headers,
                    expected_indicators=poc_schema.expected_indicators,
                    vulnerability_type=task.source.split(":")[-1] if ":" in task.source else "unknown"
                )
                
                # Validate PoC (proper async/await - no nesting)
                try:
                    validation_result = await validator.validate_poc(poc)
                    
                    # CODE makes final determination
                    if validation_result.is_vulnerable:
                        vuln_data = {
                            "type": poc.vulnerability_type,
                            "url": task.url,
                            "severity": getattr(task, 'verification_context', {}).get("severity", "medium"),
                            "confidence": validation_result.confidence,
                            "evidence": validation_result.evidence,
                            "parameters": task.parameters,
                            "validation_method": validation_result.validation_method,
                            "verified": True  # CODE verified it
                        }
                        self.scan_controller.report_vulnerability(vuln_data)
                        
                        # Report to tracer
                        if tracer:
                            tracer.add_vulnerability_report(
                                vuln_type=vuln_data["type"],
                                title=f"[VERIFIED] {vuln_data['type']} at {task.url}",
                                description=f"Validation: {validation_result.validation_method}\nEvidence: {', '.join(validation_result.evidence)}",
                                severity=vuln_data["severity"],
                                location=task.url
                            )
                        
                        logger.info(f"✓ Verified vulnerability: {poc.vulnerability_type} at {task.url}")
                    else:
                        logger.info(f"✗ Vulnerability not confirmed: {poc.vulnerability_type} at {task.url}")
                        logger.debug(f"Validation failed: {', '.join(validation_result.evidence)}")
                    
                except Exception as e:
                    logger.error(f"PoC validation error: {e}")
                    # Continue with other tasks - don't stop scanning

