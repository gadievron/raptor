"""core.llm — LLM transport layer.

Unified interface for sending prompts to any LLM provider (Anthropic,
OpenAI, Gemini, Ollama) and receiving structured or free-form responses.

This package owns *how* to talk to an LLM. *What* to say (prompt
templates, schemas, task definitions) stays with each consumer package.
"""

from .providers import (
    LLMProvider,
    LLMResponse,
    StructuredResponse,
    OpenAICompatibleProvider,
    AnthropicProvider,
    GeminiProvider,
    ClaudeCodeProvider,
    ClaudeCodeLLMProvider,
    ClaudeProvider,
    OpenAIProvider,
    OllamaProvider,
    create_provider,
)
from .cc_adapter import (
    CCDispatchConfig,
    build_cc_command,
    strip_json_fences,
    system_prompt_file_for,
    extract_envelope_metadata,
    parse_cc_structured,
    parse_cc_freeform,
)
from .client import LLMClient
from .config import LLMConfig, ModelConfig, ConfigError
from .detection import LLMAvailability, detect_llm_availability

__all__ = [
    "AnthropicProvider",
    "CCDispatchConfig",
    "ClaudeCodeLLMProvider",
    "ClaudeCodeProvider",
    "ClaudeProvider",
    "ConfigError",
    "GeminiProvider",
    "LLMAvailability",
    "LLMClient",
    "LLMConfig",
    "LLMProvider",
    "LLMResponse",
    "ModelConfig",
    "OllamaProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "StructuredResponse",
    "build_cc_command",
    "create_provider",
    "detect_llm_availability",
    "extract_envelope_metadata",
    "parse_cc_freeform",
    "parse_cc_structured",
    "strip_json_fences",
    "system_prompt_file_for",
]
