#!/usr/bin/env python3
"""
RAPTOR LLM Integration Module

Provides unified interface for multiple LLM providers:
- Frontier models: Claude (Anthropic), GPT-4 (OpenAI), Gemini (Google)
- Local models: Ollama (Llama, Mistral, DeepSeek, Qwen, etc.)
- Future: vLLM, LocalAI, LM Studio

This enables true agentic behaviour with intelligent, context-aware analysis.
"""

from .providers import LLMProvider, ClaudeProvider, OpenAIProvider, OllamaProvider, ClaudeCodeProvider
from .client import LLMClient, check_dependency_integrity
from .config import LLMConfig, LLMAvailability, detect_llm_availability

__all__ = [
    'LLMProvider',
    'ClaudeProvider',
    'OpenAIProvider',
    'OllamaProvider',
    'ClaudeCodeProvider',
    'LLMClient',
    'LLMConfig',
    'LLMAvailability',
    'detect_llm_availability',
    'check_dependency_integrity',
]
