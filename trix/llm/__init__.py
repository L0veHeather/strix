"""Trix LLM - Language model integration layer.

This package provides:
- LLM wrapper with LiteLLM backend (100+ providers)
- Role-based multi-model routing
- Cost optimization and token tracking
- Memory compression for long conversations

Usage:
    from trix.llm import LLM, LLMConfig

    # Simple usage
    config = LLMConfig()  # Uses STRIX_LLM env var
    llm = LLM(config, agent_name="MyAgent")

    # Role-based configuration
    from trix.llm.roles import LLMRole
    config = LLMConfig.for_role(LLMRole.THINKING)

    # Task-based routing
    from trix.llm.roles import TaskType
    config = LLMConfig.for_task(TaskType.PLANNING)
"""

import litellm

from trix.llm.config import LLMConfig
from trix.llm.llm import LLM, LLMRequestFailedError
from trix.llm.roles import (
    CostConfig,
    LLMRole,
    LLMRolesConfig,
    RoleConfig,
    TaskType,
    get_model_for_role,
    get_model_for_task,
    get_roles_config,
    set_roles_config,
)


__all__ = [
    # Core LLM
    "LLM",
    "LLMConfig",
    "LLMRequestFailedError",
    # Roles
    "CostConfig",
    "LLMRole",
    "LLMRolesConfig",
    "RoleConfig",
    "TaskType",
    "get_model_for_role",
    "get_model_for_task",
    "get_roles_config",
    "set_roles_config",
]

litellm._logging._disable_debugging()

litellm.drop_params = True
