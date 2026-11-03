"""core.llm — LLM transport layer.

Unified interface for sending prompts to any LLM provider (Anthropic,
OpenAI, Gemini, Ollama) and receiving structured or free-form responses.

This package owns *how* to talk to an LLM. *What* to say (prompt
templates, schemas, task definitions) stays with each consumer package.
"""

from typing import Any

# Resolve public exports on demand so leaf imports (broker metadata, wire
# types) do not initialise SDKs or recurse into core.config.
_LAZY_EXPORTS = {
    "LLMProvider": ("core.llm.providers", "LLMProvider"),
    "LLMResponse": ("core.llm.providers", "LLMResponse"),
    "StructuredResponse": ("core.llm.providers", "StructuredResponse"),
    "OpenAICompatibleProvider": ("core.llm.providers", "OpenAICompatibleProvider"),
    "AnthropicProvider": ("core.llm.providers", "AnthropicProvider"),
    "GeminiProvider": ("core.llm.providers", "GeminiProvider"),
    "ClaudeCodeProvider": ("core.llm.providers", "ClaudeCodeProvider"),
    "ClaudeCodeLLMProvider": ("core.llm.providers", "ClaudeCodeLLMProvider"),
    "ClaudeProvider": ("core.llm.providers", "ClaudeProvider"),
    "OpenAIProvider": ("core.llm.providers", "OpenAIProvider"),
    "OllamaProvider": ("core.llm.providers", "OllamaProvider"),
    "create_provider": ("core.llm.providers", "create_provider"),
    "CCDispatchConfig": ("core.llm.cc_adapter", "CCDispatchConfig"),
    "build_cc_command": ("core.llm.cc_adapter", "build_cc_command"),
    "strip_json_fences": ("core.llm.cc_adapter", "strip_json_fences"),
    "system_prompt_file_for": ("core.llm.cc_adapter", "system_prompt_file_for"),
    "extract_envelope_metadata": ("core.llm.cc_adapter", "extract_envelope_metadata"),
    "parse_cc_structured": ("core.llm.cc_adapter", "parse_cc_structured"),
    "parse_cc_freeform": ("core.llm.cc_adapter", "parse_cc_freeform"),
    "LLMClient": ("core.llm.client", "LLMClient"),
    "LLMConfig": ("core.llm.config", "LLMConfig"),
    "ModelConfig": ("core.llm.config", "ModelConfig"),
    "ConfigError": ("core.llm.config", "ConfigError"),
    "LLMAvailability": ("core.llm.detection", "LLMAvailability"),
    "detect_llm_availability": ("core.llm.detection", "detect_llm_availability"),
}


def __getattr__(name: str) -> Any:
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib
    module_name, attribute = spec
    # Python-owned export map; never derived from registry data.
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))

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
