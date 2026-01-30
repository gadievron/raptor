#!/usr/bin/env python3
"""
LLM Provider Implementations with LiteLLM

Unified interface using LiteLLM for multi-provider support.
Replaces individual provider implementations with a single LiteLLMProvider.
"""

import json
import sys
from abc import ABC, abstractmethod
from inspect import isclass
from typing import Dict, Optional, Any, Tuple, Type, Union
from dataclasses import dataclass
from pathlib import Path

# Add parent directories to path for core imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from core.logging import get_logger
from .config import ModelConfig

logger = get_logger()


@dataclass
class LLMResponse:
    """Standardised LLM response."""
    content: str
    model: str
    provider: str
    tokens_used: int
    cost: float
    finish_reason: str
    raw_response: Optional[Dict[str, Any]] = None


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ModelConfig):
        self.config = config
        self.total_tokens = 0
        self.total_cost = 0.0

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion from the model."""
        pass

    @abstractmethod
    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured output matching the provided schema."""
        pass

    def track_usage(self, tokens: int, cost: float) -> None:
        """Track token usage and cost."""
        self.total_tokens += tokens
        self.total_cost += (cost or 0.0)  # Handle None costs from Ollama
        logger.debug(f"LLM usage: {tokens} tokens, ${(cost or 0.0):.4f} (total: {self.total_tokens} tokens, ${self.total_cost:.4f})")


def _dict_schema_to_pydantic(schema: Union[Dict[str, Any], Type['BaseModel']]):
    """
    Convert dict schema or Pydantic model to Pydantic model class.

    Supports hybrid approach:
    - If already Pydantic model class: return as-is
    - If dict: convert to dynamic Pydantic model

    Supports TWO dict formats:
    1. Simple format: {"field_name": "type description"}
       Example: {"is_exploitable": "boolean", "score": "float (0.0-1.0)"}

    2. JSON Schema format: {"properties": {...}, "required": [...]}
       Example: {"properties": {"is_exploitable": {"type": "boolean"}}, "required": ["is_exploitable"]}

    Args:
        schema: Either simple dict, JSON Schema dictionary, or Pydantic BaseModel class

    Returns:
        Pydantic BaseModel class

    Raises:
        ValueError: If schema is invalid or empty
    """
    from pydantic import BaseModel, Field, create_model
    from typing import get_type_hints

    # Check if already a Pydantic model class
    if isclass(schema) and issubclass(schema, BaseModel):
        return schema  # Already Pydantic, return as-is

    # Validate it's a dict if not Pydantic
    if not isinstance(schema, dict):
        raise ValueError(
            f"Schema must be dict or Pydantic BaseModel class, "
            f"got {type(schema).__name__}"
        )

    # AUTO-WRAP: Convert simple format to JSON Schema if needed
    if "properties" not in schema:
        # Simple format detected: {"field": "type description"}
        # Convert to JSON Schema: {"properties": {"field": {"type": "type"}}, "required": [...]}

        # Type aliases: map common Python types to JSON Schema types
        type_aliases = {
            "bool": "boolean",
            "str": "string",
            "int": "integer",
            "float": "number",
            "list": "array",
            "dict": "object",
        }

        properties = {}
        for field_name, field_desc in schema.items():
            if isinstance(field_desc, str):
                # Parse description like "boolean" or "float (0.0-1.0)" or "string - description"
                # Extract type (first word/token before space or parenthesis)
                field_type = field_desc.split()[0].strip()

                # Normalize type using aliases
                field_type = type_aliases.get(field_type, field_type)

                # Map to JSON Schema type
                properties[field_name] = {"type": field_type}

                # Add description if present (anything after " - " or in parentheses)
                if " - " in field_desc:
                    desc = field_desc.split(" - ", 1)[1].strip()
                    properties[field_name]["description"] = desc
                elif "(" in field_desc:
                    desc = field_desc[field_desc.find("("):].strip()
                    properties[field_name]["description"] = desc
            elif isinstance(field_desc, dict):
                # Already in property format (partial JSON Schema)
                properties[field_name] = field_desc
            else:
                raise ValueError(f"Invalid field description for '{field_name}': {field_desc}")

        # Wrap into JSON Schema format with all fields required by default
        schema = {"properties": properties, "required": list(schema.keys())}

    properties = schema.get("properties", {})
    required_fields = schema.get("required", [])
    has_required_key = "required" in schema

    # Type mapping from JSON Schema to Python types
    type_map = {
        "string": str,
        "integer": int,
        "number": float,
        "boolean": bool,
        "array": list,
        "object": dict,
        "null": type(None)
    }

    # Build field definitions for create_model
    field_definitions = {}

    for field_name, field_spec in properties.items():
        field_type = field_spec.get("type", "string")
        python_type = type_map.get(field_type, str)

        # Get default value if present
        default_value = field_spec.get("default", ...)

        # Determine if field is required:
        # - If schema has "required" key: only those fields are required
        # - If no "required" key: all fields are required (default JSON Schema behavior)
        is_required = (not has_required_key) or (field_name in required_fields)

        # If field is not required and has no default, make it Optional
        if not is_required and default_value is ...:
            from typing import Optional as Opt
            python_type = Opt[python_type]
            default_value = None

        # Create field definition
        if default_value is ...:
            field_definitions[field_name] = (python_type, ...)
        else:
            field_definitions[field_name] = (python_type, default_value)

    # Create and return Pydantic model
    model = create_model('DynamicSchema', **field_definitions)
    return model


class LiteLLMProvider(LLMProvider):
    """
    Unified LLM provider using LiteLLM.

    Supports multiple providers (OpenAI, Anthropic, Gemini, Ollama, etc.)
    through a single interface using LiteLLM + Instructor.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        try:
            import litellm
            import instructor
            self.litellm = litellm
            self.instructor = instructor
        except ImportError as e:
            raise ImportError(
                f"Required packages not installed: {e}. "
                "Run: pip install litellm instructor pydantic"
            )

        # Build model identifier for LiteLLM
        # Format: provider/model-name (e.g., "openai/gpt-4o-mini", "ollama/deepseek-coder:latest")
        if config.provider.lower() == "ollama":
            self.model_id = f"{config.provider.lower()}/{config.model_name}"
        else:
            self.model_id = f"{config.provider.lower()}/{config.model_name}"

        logger.debug(f"Initialized LiteLLMProvider: {self.model_id}")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """
        Generate completion using LiteLLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            **kwargs: Additional parameters (temperature, max_tokens, format, etc.)

        Returns:
            LLMResponse object
        """
        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Prepare litellm parameters
        litellm_params = {
            "model": self.model_id,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        # Add api_base if configured (e.g., for custom Ollama hosts)
        if self.config.api_base:
            litellm_params["api_base"] = self.config.api_base

        # Add api_key if configured (Bug #13 fix)
        # For Ollama, we use "ollama" as a placeholder to avoid LiteLLM None handling issues
        if self.config.api_key:
            litellm_params["api_key"] = self.config.api_key
        elif self.config.provider.lower() == "ollama":
            litellm_params["api_key"] = "ollama"

        # Handle Ollama-specific format parameter (CRITICAL for GBNF)
        if "format" in kwargs and self.config.provider.lower() == "ollama":
            litellm_params["format"] = kwargs["format"]

        # Make API call
        try:
            response = self.litellm.completion(**litellm_params)

            # Extract response data
            content = response.choices[0].message.content
            tokens_used = response.usage.total_tokens if (hasattr(response, 'usage') and response.usage is not None) else 0

            # Calculate cost (LiteLLM may provide this, or we calculate)
            cost = 0.0
            if hasattr(response, '_hidden_params') and 'response_cost' in response._hidden_params:
                cost = response._hidden_params['response_cost'] or 0.0  # Handle None from Ollama
            else:
                # Fallback: use config cost
                cost = (tokens_used / 1000) * self.config.cost_per_1k_tokens

            # Track usage
            self.track_usage(tokens_used, cost)

            # Build response
            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider=self.config.provider.lower(),
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=response.choices[0].finish_reason if hasattr(response.choices[0], 'finish_reason') else "complete",
                raw_response=response.dict() if hasattr(response, 'dict') else None
            )

        except Exception as e:
            logger.error(f"LiteLLM completion failed: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """
        Generate structured output using Instructor + Pydantic.

        Args:
            prompt: User prompt
            schema: JSON Schema dictionary
            system_prompt: System prompt (optional)

        Returns:
            Tuple of (parsed dict, full response content)
        """
        # Convert dict schema to Pydantic model
        pydantic_model = _dict_schema_to_pydantic(schema)

        # Build messages
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Create Instructor client from LiteLLM
        try:
            from litellm import completion as litellm_completion

            # CRITICAL: Force JSON mode for Ollama to prevent array wrapping issues
            # Ollama has known bugs with structured outputs (ollama/ollama#8000, #8063)
            # Using explicit Mode.JSON ensures arrays return as [...] not {"items": [...]}
            # This prevents Pydantic validation errors even though Instructor 1.13.0
            # auto-detection works correctly (defense-in-depth: explicit > implicit)
            if self.config.provider.lower() == "ollama":
                client = self.instructor.from_litellm(
                    litellm_completion,
                    mode=self.instructor.Mode.JSON
                )
            else:
                client = self.instructor.from_litellm(litellm_completion)

            # Make structured API call
            # Build kwargs for the call
            create_kwargs = {
                "model": self.model_id,
                "response_model": pydantic_model,
                "messages": messages,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
            }

            # Add api_base if configured (e.g., for custom Ollama hosts)
            if self.config.api_base:
                create_kwargs["api_base"] = self.config.api_base

            # Add api_key if configured (Bug #13 fix)
            # For Ollama, we use "ollama" as a placeholder to avoid LiteLLM None handling issues
            if self.config.api_key:
                create_kwargs["api_key"] = self.config.api_key
            elif self.config.provider.lower() == "ollama":
                create_kwargs["api_key"] = "ollama"

            response = client.chat.completions.create(**create_kwargs)

            # Convert Pydantic model to dict
            result_dict = response.model_dump()

            # Generate full response content (JSON string)
            full_response = json.dumps(result_dict, indent=2)

            # Track usage (estimate based on prompt+response length)
            # Note: Instructor doesn't always expose token counts
            estimated_tokens = (len(prompt) + len(full_response)) // 4  # Rough estimate
            estimated_cost = (estimated_tokens / 1000) * (self.config.cost_per_1k_tokens or 0.0)
            self.track_usage(estimated_tokens, estimated_cost)

            return result_dict, full_response

        except Exception as e:
            logger.error(f"Structured generation failed: {e}")
            raise


def create_provider(config: ModelConfig) -> LLMProvider:
    """
    Factory function to create appropriate provider.

    Now uses LiteLLMProvider for all providers (unified interface).

    Args:
        config: ModelConfig specifying provider and model

    Returns:
        LiteLLMProvider instance
    """
    # All providers now use LiteLLMProvider (unified via LiteLLM)
    return LiteLLMProvider(config)


# Backward compatibility aliases
ClaudeProvider = LiteLLMProvider
OpenAIProvider = LiteLLMProvider
OllamaProvider = LiteLLMProvider
