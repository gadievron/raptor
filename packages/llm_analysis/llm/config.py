#!/usr/bin/env python3
"""
LLM Configuration Management

Handles configuration for multiple LLM providers with support for:
- API-based models (Claude, GPT-4, Gemini)
- Local models (Ollama, vLLM)
- Automatic fallback between models
- Cost optimization and rate limiting
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import json
import requests
import yaml

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def _get_litellm_models() -> List[Dict]:
    """
    Get all models from LiteLLM config.

    Returns list of model configurations with capabilities.
    Falls back to empty list if config not found.

    Config path resolution:
    1. LITELLM_CONFIG_PATH environment variable
    2. ~/.config/litellm/config.yaml (XDG standard)
    3. ~/Documents/ClaudeCode/litellm/config.yaml (dev default)
    4. /etc/litellm/config.yaml (Linux/macOS only)

    Note: Windows compatibility - /etc path will be skipped on Windows systems.
    """
    try:
        # Try environment variable first
        litellm_config_path = os.getenv('LITELLM_CONFIG_PATH')
        if litellm_config_path:
            # Resolve to absolute path to prevent path traversal attacks
            litellm_config_path = Path(litellm_config_path).resolve()
            if not litellm_config_path.exists():
                logger.debug(f"LITELLM_CONFIG_PATH set but file not found: {litellm_config_path}")
                return []
        else:
            # Try standard locations
            possible_paths = [
                Path.home() / ".config/litellm/config.yaml",              # XDG standard (Linux/macOS)
                Path.home() / "Documents/ClaudeCode/litellm/config.yaml", # Dev default
                Path("/etc/litellm/config.yaml"),                         # System-wide (Linux/macOS only)
            ]
            litellm_config_path = None
            for path in possible_paths:
                if path.exists():
                    litellm_config_path = path
                    logger.debug(f"Found LiteLLM config at: {litellm_config_path}")
                    break

            if not litellm_config_path:
                logger.debug("LiteLLM config not found in standard locations")
                return []

        with open(litellm_config_path) as f:
            config = yaml.safe_load(f)

        # Handle empty YAML file (yaml.safe_load returns None for empty files)
        if config is None:
            logger.debug("LiteLLM config file is empty or contains only comments")
            return []

        # Validate model_list is actually a list (not int, bool, string, etc.)
        model_list = config.get('model_list', [])
        if not isinstance(model_list, list):
            logger.debug(f"LiteLLM config has non-list model_list (type: {type(model_list).__name__})")
            return []

        return model_list
    except Exception as e:
        logger.debug(f"Could not read LiteLLM config: {e}")
        return []


def _get_best_thinking_model() -> Optional['ModelConfig']:
    """
    Automatically select the best thinking/reasoning model from LiteLLM config.

    Priority:
    1. Models with explicit reasoning support (gpt-5.2-thinking, gemini-3-deep-think)
    2. Most capable models (Opus > Sonnet > others)
    3. Latest versions

    Returns ModelConfig for best available thinking model, or None if none found.
    """
    models = _get_litellm_models()
    if not models:
        return None

    # Define priority order for thinking models (best first)
    # Format: (exact_underlying_model, model_alias, base_priority_score)
    # Note: Models with supports_reasoning=true get +10 bonus
    thinking_model_patterns = [
        # Tier 1: Most capable models (Opus is preferred for deep reasoning)
        ("anthropic/claude-opus-4.5", "claude-opus-4.5", 110),          # Most capable overall (preferred)
        ("openai/gpt-5.2-thinking", "gpt-5.2-thinking", 95),            # GPT-5.2 with thinking (gets +10 = 105 total)
        ("gemini/gemini-3-deep-think", "gemini-3-deep-think", 90),      # Gemini reasoning (gets +10 = 100 total)

        # Tier 2: Strong models
        ("anthropic/claude-opus-4", "claude-opus-4", 85),               # Previous Opus
        ("openai/gpt-5.2", "gpt-5.2", 80),                              # Latest GPT (exact match only)

        # Tier 3: Latest capable models (fallback)
        ("anthropic/claude-sonnet-4.5", "claude-sonnet-4.5", 70),       # Latest Sonnet
        ("gemini/gemini-3-pro", "gemini-3-pro", 65),                    # Latest Gemini
    ]

    # Find best matching model
    best_model = None
    best_score = -1

    for model_entry in models:
        # SAFETY: Validate model_entry is a dict (Issue #3: malformed YAML entries)
        if not isinstance(model_entry, dict):
            logger.debug(f"Skipping malformed model entry (not a dict): {type(model_entry)}")
            continue

        try:
            # Handle explicit null values (Issue: dict.get() default only used for missing keys, not null)
            model_name = model_entry.get('model_name', '')
            if model_name is None:
                model_name = ''

            litellm_params = model_entry.get('litellm_params', {})
            if litellm_params is None:
                litellm_params = {}

            underlying_model = litellm_params.get('model', '')
            if underlying_model is None:
                underlying_model = ''

            model_info = model_entry.get('model_info', {})
            if model_info is None:
                model_info = {}

            # Check if model has reasoning support OR matches our thinking patterns
            has_reasoning = model_info.get('supports_reasoning', False)

            # Score this model (Issue #1: Use exact match instead of startswith to prevent overlap)
            for exact_model, pattern_name, score in thinking_model_patterns:
                if underlying_model == exact_model or pattern_name in model_name:
                    # Boost score if has explicit reasoning flag
                    if has_reasoning:
                        score += 10

                    if score > best_score:
                        best_score = score

                        # Determine which model string to use for provider/cost extraction
                        # If underlying_model is empty or invalid, fall back to pattern's exact_model
                        model_for_metadata = underlying_model if underlying_model and '/' in underlying_model else exact_model

                        # Extract provider and API key
                        provider = model_for_metadata.split('/')[0] if '/' in model_for_metadata else 'unknown'

                        # Handle both os.environ/VAR format and literal API keys
                        # Handle explicit null: dict.get() returns None, not default, if key exists with null value
                        api_key_value = litellm_params.get('api_key', '')
                        if api_key_value is None:
                            api_key_value = ''

                        if api_key_value.startswith('os.environ/'):
                            # Extract env var name and get value from environment
                            api_key_env = api_key_value.replace('os.environ/', '')
                            api_key = os.getenv(api_key_env)
                        elif api_key_value:
                            # Use literal API key from config
                            api_key = api_key_value
                        else:
                            api_key = None

                        # Use the underlying model name for direct API calls
                        # Extract actual model ID from "provider/model-id" format
                        actual_model_name = underlying_model.split('/')[-1] if '/' in underlying_model else model_name

                        # Determine cost based on actual model tier
                        # Use model_for_metadata (not alias) to ensure correct cost even when matched by alias
                        is_opus = 'opus' in model_for_metadata.lower()
                        cost_per_1k = 0.015 if is_opus else 0.005

                        best_model = ModelConfig(
                            provider=provider,
                            model_name=actual_model_name,  # Use actual API model name
                            api_key=api_key,
                            max_tokens=model_info.get('max_output_tokens', 64000),
                            temperature=0.7,
                            cost_per_1k_tokens=cost_per_1k,
                        )
                    break

        except Exception as e:
            logger.debug(f"Error processing model entry {model_entry.get('model_name', 'unknown')}: {e}")
            continue

    if best_model:
        logger.info(f"Auto-selected thinking model: {best_model.provider}/{best_model.model_name} (score: {best_score})")

    return best_model


def _validate_ollama_url(url: str) -> str:
    """
    Validate and normalize Ollama URL.

    Args:
        url: Ollama server URL

    Returns:
        Normalized URL

    Raises:
        ValueError: If URL format is invalid
    """
    url = url.rstrip('/')
    if not url.startswith(('http://', 'https://')):
        raise ValueError(f"Invalid Ollama URL (must start with http:// or https://): {url}")
    return url


def _get_available_ollama_models() -> List[str]:
    """Get list of available Ollama models."""
    try:
        ollama_url = _validate_ollama_url(RaptorConfig.OLLAMA_HOST)
        response = requests.get(f"{ollama_url}/api/tags", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
    except Exception as e:
        # Mask remote Ollama URLs for privacy
        ollama_display = RaptorConfig.OLLAMA_HOST if 'localhost' in RaptorConfig.OLLAMA_HOST or '127.0.0.1' in RaptorConfig.OLLAMA_HOST else '[REMOTE-OLLAMA]'
        logger.debug(f"Could not connect to Ollama at {ollama_display}: {e}")
    return []


def _get_default_primary_model() -> 'ModelConfig':
    """
    Get default primary model based on available providers.

    Strategy:
    1. Try automatic thinking model selection (reads LiteLLM config)
    2. Fall back to API key detection with manual config
    3. Fall back to Ollama if no cloud providers available
    """
    # Try automatic thinking model selection first
    thinking_model = _get_best_thinking_model()
    if thinking_model and thinking_model.api_key:
        logger.info(f"Using automatic thinking model: {thinking_model.provider}/{thinking_model.model_name}")
        return thinking_model

    # Fallback: Check for API keys manually (if auto-detection failed)
    if os.getenv("ANTHROPIC_API_KEY"):
        return ModelConfig(
            provider="anthropic",
            model_name="claude-sonnet-4.5",  # Use LiteLLM alias
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=64000,
            temperature=0.7,
            cost_per_1k_tokens=0.003,
        )

    if os.getenv("OPENAI_API_KEY"):
        return ModelConfig(
            provider="openai",
            model_name="gpt-5.2",  # Latest GPT model
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=128000,
            temperature=0.7,
            cost_per_1k_tokens=0.005,
        )

    if os.getenv("GEMINI_API_KEY"):
        return ModelConfig(
            provider="gemini",
            model_name="gemini-3-pro",  # Use LiteLLM alias (not gemini-3.0-pro-latest!)
            api_key=os.getenv("GEMINI_API_KEY"),
            max_tokens=8192,
            temperature=0.7,
            cost_per_1k_tokens=0.0001,
        )

    # Otherwise use Ollama with first available model
    ollama_models = _get_available_ollama_models()
    if ollama_models:
        # Prefer general reasoning models for security analysis
        preferred = ['mistral', 'qwen', 'codellama', 'llama', 'gemma', 'deepseek-coder', 'deepseek']
        selected_model = ollama_models[0]  # Default to first

        for pref in preferred:
            for model in ollama_models:
                if pref in model.lower():
                    selected_model = model
                    break
            if selected_model != ollama_models[0]:
                break

        return ModelConfig(
            provider="ollama",
            model_name=selected_model,
            api_base=RaptorConfig.OLLAMA_HOST,
            max_tokens=4096,
            temperature=0.7,
            cost_per_1k_tokens=0.0,
        )

    # Fallback to Claude (will fail if no API key, but that's expected)
    return ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4.5",  # Use LiteLLM alias (consistent with other models)
        api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        max_tokens=8192,
        temperature=0.7,
        cost_per_1k_tokens=0.015,  # Opus is more expensive than Sonnet
    )


def _get_default_fallback_models() -> List['ModelConfig']:
    """
    Get default fallback models based on primary model tier.

    Fallback stays within same tier (local→local, cloud→cloud).
    Never cross tiers - if local fails, fix local infrastructure, don't silently switch to cloud.

    This function returns ALL available models (both cloud and local).
    The client.py logic filters to same tier as primary model.

    Uses LiteLLM aliases (not underlying model IDs) to ensure compatibility.
    """
    fallbacks = []

    # Add all available cloud models using LiteLLM aliases
    if os.getenv("ANTHROPIC_API_KEY"):
        # Add both Opus (thinking) and Sonnet (balanced)
        fallbacks.append(ModelConfig(
            provider="anthropic",
            model_name="claude-opus-4.5",  # LiteLLM alias for thinking model
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=64000,
            temperature=0.7,
            cost_per_1k_tokens=0.015,  # Opus is more expensive
        ))
        fallbacks.append(ModelConfig(
            provider="anthropic",
            model_name="claude-sonnet-4.5",  # LiteLLM alias
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=64000,
            temperature=0.7,
            cost_per_1k_tokens=0.003,
        ))

    if os.getenv("OPENAI_API_KEY"):
        # Add latest GPT models
        fallbacks.append(ModelConfig(
            provider="openai",
            model_name="gpt-5.2",  # Latest GPT
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=128000,
            temperature=0.7,
            cost_per_1k_tokens=0.005,
        ))
        fallbacks.append(ModelConfig(
            provider="openai",
            model_name="gpt-5.2-thinking",  # GPT-5.2 with thinking
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=128000,
            temperature=0.7,
            cost_per_1k_tokens=0.006,
        ))

    if os.getenv("GEMINI_API_KEY"):
        # Add reasoning model + latest Gemini
        fallbacks.append(ModelConfig(
            provider="gemini",
            model_name="gemini-3-deep-think",  # LiteLLM alias for reasoning
            api_key=os.getenv("GEMINI_API_KEY"),
            max_tokens=8192,
            temperature=0.7,
            cost_per_1k_tokens=0.0002,
        ))
        fallbacks.append(ModelConfig(
            provider="gemini",
            model_name="gemini-3-pro",  # LiteLLM alias (NOT gemini-3.0-pro-latest!)
            api_key=os.getenv("GEMINI_API_KEY"),
            max_tokens=8192,
            temperature=0.7,
            cost_per_1k_tokens=0.0001,
        ))

    # Add all available local models
    ollama_models = _get_available_ollama_models()
    for model in ollama_models[:3]:  # Add first 3 local models
        fallbacks.append(ModelConfig(
            provider="ollama",
            model_name=model,
            api_base=RaptorConfig.OLLAMA_HOST,
            max_tokens=4096,
            temperature=0.7,
            cost_per_1k_tokens=0.0,
        ))

    return fallbacks


@dataclass
class ModelConfig:
    """Configuration for a specific model."""
    provider: str  # "anthropic", "openai", "ollama", "google"
    model_name: str  # "claude-sonnet-4", "gpt-4", "llama3:70b", etc.
    api_key: Optional[str] = None
    api_base: Optional[str] = None  # For Ollama: http://localhost:11434
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: int = 120
    cost_per_1k_tokens: float = 0.0  # For cost tracking
    enabled: bool = True


@dataclass
class LLMConfig:
    """Main LLM configuration for RAPTOR."""

    # Primary model (fastest/most capable)
    primary_model: ModelConfig = field(default_factory=_get_default_primary_model)

    # Fallback models (in priority order)
    fallback_models: List[ModelConfig] = field(default_factory=_get_default_fallback_models)

    # Analysis-specific models (for different task types)
    # Will be auto-populated if not set
    specialized_models: Dict[str, ModelConfig] = field(default_factory=dict)

    # Global settings
    enable_fallback: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0  # Default for local servers
    retry_delay_remote: float = 5.0  # Longer delay for remote servers
    enable_caching: bool = True
    cache_dir: Path = Path("out/llm_cache")
    enable_cost_tracking: bool = True
    max_cost_per_scan: float = 10.0  # USD

    def to_file(self, config_path: Path) -> None:
        """Save configuration to JSON file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        # TODO: Implement proper serialization
        with open(config_path, 'w') as f:
            json.dump({
                "primary_model": {
                    "provider": self.primary_model.provider,
                    "model_name": self.primary_model.model_name,
                },
                "fallback_enabled": self.enable_fallback,
            }, f, indent=2)

    def get_model_for_task(self, task_type: str) -> ModelConfig:
        """Get the appropriate model for a specific task type."""
        if task_type in self.specialized_models:
            model = self.specialized_models[task_type]
            if model.enabled:
                return model
        return self.primary_model

    def get_available_models(self) -> List[ModelConfig]:
        """Get list of all available models (primary + fallbacks)."""
        models = [self.primary_model]
        if self.enable_fallback:
            models.extend(self.fallback_models)
        return [m for m in models if m.enabled]

    def get_retry_delay(self, api_base: Optional[str] = None) -> float:
        """
        Get appropriate retry delay based on server location.

        Args:
            api_base: API base URL to check if remote

        Returns:
            Retry delay in seconds
        """
        if api_base and ("localhost" not in api_base and "127.0.0.1" not in api_base):
            return self.retry_delay_remote
        return self.retry_delay


# Default configuration
DEFAULT_LLM_CONFIG = LLMConfig()
