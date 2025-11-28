from typing import Any, Optional

from strix.agents.base_agent import BaseAgent
from strix.agents.planner import ScanPlanner, ScanPlan
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
        
        self.planner = ScanPlanner()
        self.current_plan: ScanPlan | None = None
        self._processed_findings: set[str] = set()

    async def execute_scan(self, scan_config: dict[str, Any]) -> dict[str, Any]:  # noqa: PLR0912
        user_instructions = scan_config.get("user_instructions", "")
        targets = scan_config.get("targets", [])

        repositories = []
        local_code = []
        urls = []
        ip_addresses = []

        for target in targets:
            target_type = target["type"]
            details = target["details"]
            workspace_subdir = details.get("workspace_subdir")
            workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

            if target_type == "repository":
                repo_url = details["target_repo"]
                cloned_path = details.get("cloned_repo_path")
                repositories.append(
                    {
                        "url": repo_url,
                        "workspace_path": workspace_path if cloned_path else None,
                    }
                )

            elif target_type == "local_code":
                original_path = details.get("target_path", "unknown")
                local_code.append(
                    {
                        "path": original_path,
                        "workspace_path": workspace_path,
                    }
                )

            elif target_type == "web_application":
                urls.append(details["target_url"])
            elif target_type == "ip_address":
                ip_addresses.append(details["target_ip"])

        task_parts = []

        if repositories:
            task_parts.append("\n\nRepositories:")
            for repo in repositories:
                if repo["workspace_path"]:
                    task_parts.append(f"- {repo['url']} (available at: {repo['workspace_path']})")
                else:
                    task_parts.append(f"- {repo['url']}")

        if local_code:
            task_parts.append("\n\nLocal Codebases:")
            task_parts.extend(
                f"- {code['path']} (available at: {code['workspace_path']})" for code in local_code
            )

        if urls:
            task_parts.append("\n\nURLs:")
            task_parts.extend(f"- {url}" for url in urls)

        if ip_addresses:
            task_parts.append("\n\nIP Addresses:")
            task_parts.extend(f"- {ip}" for ip in ip_addresses)

        task_description = " ".join(task_parts)

        if user_instructions:
            task_description += f"\n\nSpecial instructions: {user_instructions}"

        return await self.agent_loop(task=task_description)

    async def _process_iteration(self, tracer: Optional[Tracer]) -> bool:
        # Call parent method to execute normal agent logic
        should_finish = await super()._process_iteration(tracer)
        
        if should_finish:
            return True
            
        # Check for new critical findings and trigger re-planning
        if tracer and tracer.vulnerability_reports:
            new_findings = []
            for report in tracer.vulnerability_reports:
                # Use a unique key for the finding to avoid processing duplicates
                finding_id = f"{report.get('type')}:{report.get('location')}"
                if finding_id not in self._processed_findings:
                    self._processed_findings.add(finding_id)
                    new_findings.append(report)
            
            if new_findings and self.current_plan:
                # We have a plan and new findings, check if we need to replan
                updated_plan = self.planner.replan(self.current_plan, new_findings)
                
                # If steps were added (simple check by length or content)
                # Ideally replan returns a new object or modifies in place. 
                # Our replan modifies in place and returns it.
                
                # We can check if the plan has pending steps that are CRITICAL and were just added
                # But for now, let's just notify the agent if we found critical stuff
                
                critical_findings = [
                    f for f in new_findings 
                    if f.get("severity", "").lower() in ["critical", "high"]
                ]
                
                if critical_findings:
                    notification = (
                        f"SYSTEM ALERT: {len(critical_findings)} new critical/high severity findings detected. "
                        "The scan plan has been updated to include exploitation steps. "
                        "Please prioritize these new steps."
                    )
                    self.state.add_message("user", notification)
                    
        return False
