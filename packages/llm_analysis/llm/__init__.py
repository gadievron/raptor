#!/usr/bin/env python3
"""
RAPTOR LLM Integration Module

Provides unified interface for multiple LLM providers:
- Frontier models: Claude (Anthropic), GPT-4 (OpenAI), Gemini (Google)
- Local models: Ollama (Llama, Mistral, DeepSeek, Qwen, etc.)
- Future: vLLM, LocalAI, LM Studio

This enables true agentic behaviour with intelligent, context-aware analysis.
"""

from .providers import LLMProvider, ClaudeProvider, OpenAIProvider, OllamaProvider
from .client import LLMClient
from .config import LLMConfig

__all__ = [
    'LLMProvider',
    'ClaudeProvider',
    'OpenAIProvider',
    'OllamaProvider',
    'LLMClient',
    'LLMConfig',
]
