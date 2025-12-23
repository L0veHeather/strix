"""Settings API Routes.

Provides API endpoints for managing application settings including LLM configuration.
"""

from __future__ import annotations

import os
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from strix.storage import get_database

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/settings", tags=["settings"])


# Models
class LLMConfig(BaseModel):
    """LLM configuration model."""
    
    model: str = Field(
        default="openai/gpt-4o",
        description="LLM model identifier (e.g., openai/gpt-4o, anthropic/claude-3-sonnet)"
    )
    api_key: str | None = Field(
        default=None,
        description="API key for the LLM provider (stored securely)"
    )
    api_base: str | None = Field(
        default=None,
        description="Custom API base URL (for local LLMs or proxies)"
    )
    timeout: int = Field(
        default=600,
        description="Request timeout in seconds"
    )
    enable_caching: bool = Field(
        default=True,
        description="Enable prompt caching (Anthropic)"
    )
    max_tokens: int | None = Field(
        default=None,
        description="Max tokens for completion"
    )


class SettingValue(BaseModel):
    """Generic setting value."""
    value: Any


class AllSettings(BaseModel):
    """All application settings."""
    
    llm: LLMConfig = Field(default_factory=LLMConfig)
    telemetry_enabled: bool = Field(default=False)
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    perplexity_api_key: str | None = None


# Sensitive keys that should be masked in responses
SENSITIVE_KEYS = ["api_key", "langfuse_secret_key", "perplexity_api_key"]

# LLM provider options
LLM_PROVIDERS = [
    {
        "id": "openai",
        "name": "OpenAI",
        "models": [
            {"id": "openai/gpt-4o", "name": "GPT-4o", "description": "Most capable model"},
            {"id": "openai/gpt-4o-mini", "name": "GPT-4o Mini", "description": "Fast and efficient"},
            {"id": "openai/gpt-4-turbo", "name": "GPT-4 Turbo", "description": "High performance"},
            {"id": "openai/o1-preview", "name": "o1 Preview", "description": "Reasoning model"},
        ],
        "requires_key": True,
        "key_env": "OPENAI_API_KEY",
    },
    {
        "id": "anthropic",
        "name": "Anthropic",
        "models": [
            {"id": "anthropic/claude-sonnet-4-20250514", "name": "Claude Sonnet 4", "description": "Latest Sonnet"},
            {"id": "anthropic/claude-3-5-sonnet-20241022", "name": "Claude 3.5 Sonnet", "description": "Balanced"},
            {"id": "anthropic/claude-3-opus-20240229", "name": "Claude 3 Opus", "description": "Most capable"},
        ],
        "requires_key": True,
        "key_env": "ANTHROPIC_API_KEY",
    },
    {
        "id": "ollama",
        "name": "Ollama (Local)",
        "models": [
            {"id": "ollama/llama3.3:70b", "name": "Llama 3.3 70B", "description": "Large local model"},
            {"id": "ollama/llama3.2:latest", "name": "Llama 3.2", "description": "Fast local model"},
            {"id": "ollama/qwen2.5:32b", "name": "Qwen 2.5 32B", "description": "Chinese + English"},
            {"id": "ollama/deepseek-coder-v2:16b", "name": "DeepSeek Coder V2", "description": "Coding focused"},
        ],
        "requires_key": False,
        "default_base": "http://localhost:11434",
    },
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "models": [
            {"id": "deepseek/deepseek-chat", "name": "DeepSeek Chat", "description": "General purpose"},
            {"id": "deepseek/deepseek-coder", "name": "DeepSeek Coder", "description": "Coding focused"},
        ],
        "requires_key": True,
        "key_env": "DEEPSEEK_API_KEY",
    },
    {
        "id": "custom",
        "name": "Custom / OpenAI Compatible",
        "models": [],
        "requires_key": True,
        "supports_custom_base": True,
    },
]


def mask_sensitive_value(value: str | None) -> str | None:
    """Mask a sensitive value for display."""
    if not value:
        return None
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def get_setting(key: str, default: Any = None) -> Any:
    """Get a setting from database or environment."""
    db = get_database()
    
    # Try database first
    with db.get_session() as session:
        from strix.storage.models import Setting
        setting = session.query(Setting).filter_by(key=key).first()
        if setting and setting.value is not None:
            return setting.value
    
    # Fall back to environment variable
    env_key = key.upper().replace(".", "_")
    env_val = os.environ.get(env_key)
    if env_val is not None:
        return env_val
    
    return default


def set_setting(key: str, value: Any) -> None:
    """Save a setting to database."""
    db = get_database()
    
    with db.get_session() as session:
        from strix.storage.models import Setting
        setting = session.query(Setting).filter_by(key=key).first()
        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            session.add(setting)
        session.commit()


@router.get("/providers")
async def get_llm_providers():
    """Get available LLM providers and their models."""
    return {"providers": LLM_PROVIDERS}


@router.get("/llm")
async def get_llm_config():
    """Get current LLM configuration."""
    config = LLMConfig(
        model=get_setting("llm.model", os.environ.get("STRIX_LLM", "openai/gpt-4o")),
        api_key=mask_sensitive_value(get_setting("llm.api_key", os.environ.get("LLM_API_KEY"))),
        api_base=get_setting("llm.api_base", os.environ.get("LLM_API_BASE")),
        timeout=int(get_setting("llm.timeout", os.environ.get("LLM_TIMEOUT", 600))),
        enable_caching=get_setting("llm.enable_caching", True),
        max_tokens=get_setting("llm.max_tokens"),
    )
    
    # Check if keys are configured (from env or db)
    has_openai = bool(os.environ.get("OPENAI_API_KEY") or get_setting("llm.openai_api_key"))
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY") or get_setting("llm.anthropic_api_key"))
    has_deepseek = bool(os.environ.get("DEEPSEEK_API_KEY") or get_setting("llm.deepseek_api_key"))
    
    return {
        "config": config.model_dump(),
        "configured_providers": {
            "openai": has_openai,
            "anthropic": has_anthropic,
            "deepseek": has_deepseek,
            "ollama": True,  # Always available if running locally
        },
    }


@router.put("/llm")
async def update_llm_config(config: LLMConfig):
    """Update LLM configuration."""
    try:
        # Save model selection
        set_setting("llm.model", config.model)
        
        # Save API key if provided (not masked)
        if config.api_key and not config.api_key.startswith("****") and "..." not in config.api_key:
            # Determine which provider key to save based on model
            provider = config.model.split("/")[0] if "/" in config.model else "openai"
            set_setting(f"llm.{provider}_api_key", config.api_key)
            
            # Also set as environment variable for immediate use
            if provider == "openai":
                os.environ["OPENAI_API_KEY"] = config.api_key
            elif provider == "anthropic":
                os.environ["ANTHROPIC_API_KEY"] = config.api_key
            elif provider == "deepseek":
                os.environ["DEEPSEEK_API_KEY"] = config.api_key
            
            os.environ["LLM_API_KEY"] = config.api_key
        
        # Save other settings
        if config.api_base:
            set_setting("llm.api_base", config.api_base)
            os.environ["LLM_API_BASE"] = config.api_base
        
        set_setting("llm.timeout", config.timeout)
        set_setting("llm.enable_caching", config.enable_caching)
        
        if config.max_tokens:
            set_setting("llm.max_tokens", config.max_tokens)
        
        # Update environment variable for model
        os.environ["STRIX_LLM"] = config.model
        
        logger.info(f"LLM configuration updated: model={config.model}")
        
        return {"status": "success", "message": "LLM configuration updated"}
    
    except Exception as e:
        logger.error(f"Failed to update LLM config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def get_all_settings():
    """Get all application settings."""
    return {
        "llm": {
            "model": get_setting("llm.model", os.environ.get("STRIX_LLM", "openai/gpt-4o")),
            "timeout": get_setting("llm.timeout", 600),
            "enable_caching": get_setting("llm.enable_caching", True),
        },
        "telemetry": {
            "enabled": get_setting("telemetry.enabled", False),
            "langfuse_configured": bool(
                os.environ.get("LANGFUSE_PUBLIC_KEY") or 
                get_setting("telemetry.langfuse_public_key")
            ),
        },
        "research": {
            "perplexity_configured": bool(
                os.environ.get("PERPLEXITY_API_KEY") or 
                get_setting("research.perplexity_api_key")
            ),
        },
    }


@router.put("/{key}")
async def update_setting(key: str, data: SettingValue):
    """Update a specific setting."""
    try:
        set_setting(key, data.value)
        return {"status": "success", "key": key}
    except Exception as e:
        logger.error(f"Failed to update setting {key}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-llm")
async def test_llm_connection():
    """Test the current LLM configuration."""
    try:
        from strix.llm.config import LLMConfig as StrixLLMConfig
        from strix.llm.llm import LLM
        
        # Get current config
        model = get_setting("llm.model", os.environ.get("STRIX_LLM", "openai/gpt-4o"))
        timeout = int(get_setting("llm.timeout", 600))
        
        config = StrixLLMConfig(
            model_name=model,
            timeout=min(timeout, 30),  # Use shorter timeout for test
        )
        
        llm = LLM(config)
        
        # Simple test prompt
        response = await llm.generate("Say 'Hello from Strix!' in exactly those words.")
        
        return {
            "status": "success",
            "model": model,
            "response": response[:100] if response else None,
        }
    
    except ImportError:
        return {
            "status": "warning",
            "message": "LLM module not fully initialized, but configuration saved",
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
        }
