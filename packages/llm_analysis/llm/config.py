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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import json
import requests


def _get_available_ollama_models() -> List[str]:
    """Get list of available Ollama models."""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return [model['name'] for model in data.get('models', [])]
    except:
        pass
    return []


def _get_default_primary_model() -> 'ModelConfig':
    """Get default primary model based on available providers."""
    # Check for API keys first
    if os.getenv("ANTHROPIC_API_KEY"):
        return ModelConfig(
            provider="anthropic",
            model_name="claude-sonnet-4-20250514",
            api_key=os.getenv("ANTHROPIC_API_KEY"),
            max_tokens=8192,
            temperature=0.7,
            cost_per_1k_tokens=0.003,
        )

    if os.getenv("OPENAI_API_KEY"):
        return ModelConfig(
            provider="openai",
            model_name="gpt-4-turbo-preview",
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=4096,
            temperature=0.7,
            cost_per_1k_tokens=0.01,
        )

    # Otherwise use Ollama with first available model
    ollama_models = _get_available_ollama_models()
    if ollama_models:
        # Prefer coding models
        preferred = ['deepseek-coder', 'qwen', 'codellama', 'deepseek', 'gemma', 'llama']
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
            api_base="http://localhost:11434",
            max_tokens=4096,
            temperature=0.7,
            cost_per_1k_tokens=0.0,
        )

    # Fallback to Claude (will fail if no API key, but that's expected)
    return ModelConfig(
        provider="anthropic",
        model_name="claude-sonnet-4-20250514",
        api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        max_tokens=8192,
        temperature=0.7,
        cost_per_1k_tokens=0.003,
    )


def _get_default_fallback_models() -> List['ModelConfig']:
    """Get default fallback models."""
    fallbacks = []

    # Add API-based models if keys available
    if os.getenv("OPENAI_API_KEY"):
        fallbacks.append(ModelConfig(
            provider="openai",
            model_name="gpt-4-turbo-preview",
            api_key=os.getenv("OPENAI_API_KEY"),
            max_tokens=4096,
            temperature=0.7,
            cost_per_1k_tokens=0.01,
        ))

    # Add Ollama models
    ollama_models = _get_available_ollama_models()
    for model in ollama_models[:2]:  # Add first 2 as fallbacks
        fallbacks.append(ModelConfig(
            provider="ollama",
            model_name=model,
            api_base="http://localhost:11434",
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
    primary_model: ModelConfig = field(default_factory=lambda: _get_default_primary_model())

    # Fallback models (in priority order)
    fallback_models: List[ModelConfig] = field(default_factory=lambda: _get_default_fallback_models())

    # Analysis-specific models (for different task types)
    # Will be auto-populated if not set
    specialized_models: Dict[str, ModelConfig] = field(default_factory=dict)

    # Global settings
    enable_fallback: bool = True
    max_retries: int = 3
    retry_delay: float = 2.0
    enable_caching: bool = True
    cache_dir: Path = Path("out/llm_cache")
    enable_cost_tracking: bool = True
    max_cost_per_scan: float = 10.0  # USD

    @classmethod
    def from_file(cls, config_path: Path) -> 'LLMConfig':
        """Load configuration from JSON file."""
        with open(config_path) as f:
            data = json.load(f)
        # TODO: Implement proper deserialization
        return cls()

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


# Default configuration
DEFAULT_LLM_CONFIG = LLMConfig()
