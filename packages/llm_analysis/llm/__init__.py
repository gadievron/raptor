#!/usr/bin/env python3
"""
RAPTOR LLM Integration Module

Provides unified interface for multiple LLM providers:
- Frontier models: Claude (Anthropic), GPT (OpenAI), Gemini (Google)
- Local models: Ollama (Llama, Mistral, DeepSeek, Qwen, etc.)

Uses OpenAI SDK for OpenAI-compatible providers and Anthropic SDK
for native Anthropic support. Instructor provides structured output
with Pydantic validation fallback for universal compatibility.
"""

from .providers import (
    LLMProvider,
    OpenAICompatibleProvider,
    AnthropicProvider,
    ClaudeCodeProvider,
    ClaudeProvider,
    OpenAIProvider,
    OllamaProvider,
)
from .client import LLMClient
from .config import LLMConfig, ModelConfig
from .detection import LLMAvailability, detect_llm_availability

__all__ = [
    'LLMProvider',
    'OpenAICompatibleProvider',
    'AnthropicProvider',
    'ClaudeProvider',
    'OpenAIProvider',
    'OllamaProvider',
    'ClaudeCodeProvider',
    'LLMClient',
    'LLMConfig',
    'ModelConfig',
    'LLMAvailability',
    'detect_llm_availability',
]
