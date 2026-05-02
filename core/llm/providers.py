#!/usr/bin/env python3
"""
LLM Provider Implementations — OpenAI SDK + Anthropic SDK + Gemini SDK + Instructor

Native SDKs where available: Anthropic SDK for Anthropic, google-genai
for Gemini (with OpenAI shim fallback), and OpenAI SDK for everything else.
Instructor is used for structured output when available, with a universal
JSON-in-prompt fallback for providers that lack native structured support.
"""

import json
import sys
import time
from abc import ABC, abstractmethod
from inspect import isclass
from typing import Dict, Optional, Any, Tuple, Type, Union
from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger
from .config import ModelConfig

logger = get_logger()

# SDK availability flags (canonical source is detection.py)
from .detection import OPENAI_SDK_AVAILABLE, ANTHROPIC_SDK_AVAILABLE, GENAI_SDK_AVAILABLE

# Re-import the actual modules where available (config.py only sets flags)
if OPENAI_SDK_AVAILABLE:
    from openai import OpenAI
if ANTHROPIC_SDK_AVAILABLE:
    import anthropic
if GENAI_SDK_AVAILABLE:
    from google import genai as _genai_module

try:
    import instructor
    INSTRUCTOR_AVAILABLE = True
except ImportError:
    INSTRUCTOR_AVAILABLE = False


@dataclass
class LLMResponse:
    """Standardised LLM response."""
    content: str
    model: str
    provider: str
    tokens_used: int
    cost: float
    finish_reason: str
    input_tokens: int = 0
    output_tokens: int = 0
    thinking_tokens: int = 0
    duration: float = 0.0


@dataclass
class StructuredResponse:
    """Response from generate_structured() with metadata.

    Iterable for backwards compatibility: result, raw = response
    """
    result: Dict[str, Any]
    raw: str
    cost: float = 0.0
    tokens_used: int = 0
    model: str = ""
    provider: str = ""
    duration: float = 0.0
    cached: bool = False  # Not yet wired: generate_structured() has no cache path.
    # generate() caches via _get_cached_response but returns LLMResponse, not this.
    # To enable: add cache check in generate_structured() before provider call,
    # return StructuredResponse(cached=True) on hit. Cache key must include schema.
    # Inventory checksums (core/inventory) could feed cache invalidation.

    def __iter__(self):
        """Allow unpacking as 2-tuple for backwards compatibility."""
        return iter((self.result, self.raw))


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: ModelConfig):
        import threading
        self.config = config
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0
        self.total_duration = 0.0
        self._usage_lock = threading.Lock()

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

    def track_usage(self, tokens: int, cost: float,
                    input_tokens: int = 0, output_tokens: int = 0,
                    duration: float = 0.0) -> None:
        """Track token usage, cost, and call duration (thread-safe)."""
        with self._usage_lock:
            self.total_tokens += tokens
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            self.total_cost += (cost or 0.0)
            self.call_count += 1
            self.total_duration += duration
        logger.debug(f"LLM usage: {tokens} tokens, ${(cost or 0.0):.4f} (total: {self.total_tokens} tokens, ${self.total_cost:.4f})")

    def _calculate_cost_split(self, input_tokens: int, output_tokens: int,
                              thinking_tokens: int = 0) -> float:
        """Calculate cost using split input/output pricing.

        Thinking/reasoning tokens are billed at the output rate on all
        providers (OpenAI, Google, Anthropic).
        """
        from .model_data import MODEL_COSTS
        rates = MODEL_COSTS.get(self.config.model_name)
        if not rates:
            rate = self.config.cost_per_1k_tokens or 0.0
            return ((input_tokens + output_tokens + thinking_tokens) / 1000) * rate
        return (
            (input_tokens / 1000) * rates["input"]
            + ((output_tokens + thinking_tokens) / 1000) * rates["output"]
        )

    def _structured_fallback(self, prompt: str, schema: Dict[str, Any],
                             pydantic_model, system_prompt: Optional[str] = None
                             ) -> Tuple[Dict[str, Any], str]:
        """
        Universal fallback: ask for JSON in the prompt, validate
        with Pydantic. Works with any LLM that can produce JSON.
        Usage is tracked by self.generate() — no double counting.
        """
        schema_json = json.dumps(schema, indent=2)
        augmented_prompt = (
            f"{prompt}\n\n"
            f"Respond with JSON matching this schema:\n"
            f"```json\n{schema_json}\n```\n"
            f"Return ONLY valid JSON, no other text."
        )
        response = self.generate(augmented_prompt, system_prompt)
        try:
            content = response.content.strip()
            # Strip markdown fences: ```json\n...\n``` or ```\n...\n```
            if content.startswith("```") and content.endswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
                content = content.rsplit("```", 1)[0]
            elif content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
            content = content.strip()
            parsed = json.loads(content)
            parsed = _coerce_to_schema(parsed, schema)
            validated = pydantic_model.model_validate(parsed)
            result_dict = validated.model_dump()
            return result_dict, json.dumps(result_dict, indent=2)
        except Exception as e:
            logger.error(f"Structured fallback failed (JSON parse or validation): {e}")
            raise


def _coerce_to_schema(data: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce LLM output values to match schema types before Pydantic validation.

    LLMs (especially via JSON-in-prompt fallback) often return wrong types:
    - "not_a_bool" or "true" instead of true for booleans
    - "0.85" instead of 0.85 for numbers
    - null instead of "" for strings

    This coercion step fixes common mismatches so Pydantic validation succeeds.
    """
    properties = schema.get("properties", {})
    if not properties:
        return data

    coerced = dict(data)
    for field_name, field_spec in properties.items():
        if field_name not in coerced:
            continue

        value = coerced[field_name]
        field_type = field_spec.get("type", "string")

        # Handle nullable types: ["string", "null"] or ["boolean", "null"]
        if isinstance(field_type, list):
            if value is None and "null" in field_type:
                continue  # null is valid
            # Use the non-null type for coercion
            field_type = next((t for t in field_type if t != "null"), "string")

        if field_type == "boolean" and not isinstance(value, bool):
            if isinstance(value, str):
                coerced[field_name] = value.lower() in ("true", "yes", "1")
            elif isinstance(value, (int, float)):
                coerced[field_name] = bool(value)
            else:
                coerced[field_name] = False

        elif field_type == "number" and not isinstance(value, (int, float)):
            try:
                coerced[field_name] = float(value)
            except (ValueError, TypeError):
                coerced[field_name] = 0.0

        elif field_type == "integer" and not isinstance(value, int):
            try:
                coerced[field_name] = int(value)
            except (ValueError, TypeError):
                coerced[field_name] = 0

        elif field_type == "string" and value is None:
            coerced[field_name] = ""

    return coerced


def _normalize_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize simple format schema to JSON Schema format.

    Simple format: {"field": "type description"}
    JSON Schema format: {"properties": {...}, "required": [...]}

    Returns the schema unchanged if already in JSON Schema format.
    """
    if "properties" in schema:
        return schema  # Already JSON Schema

    type_aliases = {
        "bool": "boolean", "str": "string", "int": "integer",
        "float": "number", "list": "array", "dict": "object",
    }

    properties = {}
    for field_name, field_desc in schema.items():
        if isinstance(field_desc, dict):
            properties[field_name] = field_desc
            continue

        field_desc_str = str(field_desc)
        field_type = field_desc_str.split()[0].strip()
        field_type = type_aliases.get(field_type, field_type)

        # Detect nullable: "string or null", "float or null"
        if " or null" in field_desc_str.lower():
            prop = {"type": [field_type, "null"]}
        else:
            prop = {"type": field_type}

        # Arrays need an items definition for Gemini
        if field_type == "array":
            prop["items"] = {"type": "string"}

        # Extract description
        if " - " in field_desc_str:
            prop["description"] = field_desc_str.split(" - ", 1)[1].strip()
        elif "(" in field_desc_str:
            prop["description"] = field_desc_str[field_desc_str.find("("):].strip()

        properties[field_name] = prop

    return {"properties": properties, "required": list(schema.keys())}


def _schema_to_gemini(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Convert JSON Schema to Gemini-compatible schema.

    The google-genai SDK rejects nullable union types like ["string", "null"].
    Gemini expects single type strings ("STRING") with a separate "nullable" flag.
    """
    TYPE_MAP = {
        "string": "STRING", "number": "NUMBER", "integer": "INTEGER",
        "boolean": "BOOLEAN", "array": "ARRAY", "object": "OBJECT", "null": "NULL",
    }

    def convert_property(prop: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        prop_type = prop.get("type")
        if isinstance(prop_type, list):
            # ["string", "null"] → type="STRING", nullable=True
            non_null = [t for t in prop_type if t != "null"]
            out["type"] = TYPE_MAP.get(non_null[0], non_null[0]) if non_null else "STRING"
            if "null" in prop_type:
                out["nullable"] = True
        elif prop_type:
            out["type"] = TYPE_MAP.get(prop_type, prop_type)

        if "description" in prop:
            out["description"] = prop["description"]
        if "enum" in prop:
            out["enum"] = prop["enum"]
        if "items" in prop:
            out["items"] = convert_property(prop["items"])
        if "properties" in prop:
            out["properties"] = {k: convert_property(v) for k, v in prop["properties"].items()}
            if "required" in prop:
                out["required"] = prop["required"]
        return out

    result = {"type": "OBJECT"}
    if "properties" in schema:
        result["properties"] = {k: convert_property(v) for k, v in schema["properties"].items()}
    if "required" in schema:
        result["required"] = schema["required"]
    return result


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

    # Normalize simple format to JSON Schema
    schema = _normalize_schema(schema)

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

        # Handle nullable types: ["string", "null"] → Optional[str]
        nullable = False
        if isinstance(field_type, list):
            nullable = "null" in field_type
            non_null = [t for t in field_type if t != "null"]
            field_type = non_null[0] if non_null else "string"

        python_type = type_map.get(field_type, str)
        if nullable:
            from typing import Optional as Opt
            python_type = Opt[python_type]

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

        # Nullable fields should default to None even if required in the schema —
        # LLMs frequently omit nullable fields rather than explicitly returning null
        if nullable and default_value is ...:
            default_value = None

        # Create field definition
        if default_value is ...:
            field_definitions[field_name] = (python_type, ...)
        else:
            field_definitions[field_name] = (python_type, default_value)

    # Create and return Pydantic model
    model = create_model('DynamicSchema', **field_definitions)
    return model


class OpenAICompatibleProvider(LLMProvider):
    """
    LLM provider using the OpenAI SDK.

    Works with any OpenAI-compatible API: OpenAI, Ollama, vLLM, LM Studio,
    Gemini (via OpenAI compat), Mistral, etc.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not OPENAI_SDK_AVAILABLE:
            raise ImportError(
                "OpenAI SDK not installed. Run: pip install openai"
            )

        self.client = OpenAI(
            api_key=config.api_key or "unused",
            base_url=config.api_base,
            timeout=config.timeout,
        )

        self.instructor_client = None
        self._instructor_warned = False
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_openai(self.client)
        else:
            logger.warning(
                "Instructor not installed — structured output will use JSON-in-prompt fallback. "
                "For more reliable structured output: pip install instructor"
            )

        logger.debug(f"Initialized OpenAICompatibleProvider: {config.model_name} (base_url={config.api_base})")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the OpenAI SDK."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            t_start = time.monotonic()
            response = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                temperature=kwargs.get("temperature", self.config.temperature),
                max_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            )
            duration = time.monotonic() - t_start

            if not response.choices:
                raise RuntimeError("OpenAI returned empty choices")
            message = response.choices[0].message
            content = message.content or ""
            # Ollama thinking models (qwen3, etc.) put responses in reasoning_content
            if not content:
                content = getattr(message, 'reasoning_content', '') or ""
            finish_reason = response.choices[0].finish_reason or "complete"

            # Detect content filter blocks and model refusals
            refusal = getattr(message, 'refusal', None)
            if refusal:
                raise RuntimeError(
                    f"Model refused request: {refusal}"
                )
            if finish_reason == "content_filter":
                if not content:
                    raise RuntimeError(
                        "Response blocked by content filter. "
                        "This typically happens with exploit code or attack scenario prompts."
                    )
                logger.warning("Response truncated by content filter")

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage:
                input_tokens = response.usage.prompt_tokens or 0
                output_tokens = response.usage.completion_tokens or 0
                # Extract thinking/reasoning tokens (o3, o4-mini, etc.)
                details = getattr(response.usage, 'completion_tokens_details', None)
                if details:
                    thinking_tokens = getattr(details, 'reasoning_tokens', 0) or 0
                    # Reasoning tokens are included in completion_tokens — subtract
                    # to get actual output tokens for display, but bill both as output
                    output_tokens = output_tokens - thinking_tokens

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)
            logger.debug(f"[OpenAI] model={self.config.model_name}, tokens={tokens_used}, cost=${cost:.4f}, duration={duration:.2f}s"
                         + (f", thinking={thinking_tokens}" if thinking_tokens else ""))

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider=self.config.provider.lower(),
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
            )

        except Exception as e:
            logger.error(f"OpenAI completion failed: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Instructor (or JSON fallback)."""
        pydantic_model = _dict_schema_to_pydantic(schema)

        # Try Instructor first (skip for Anthropic via OpenAI-compat — response_format is ignored)
        is_anthropic_compat = self.config.provider.lower() == "anthropic"
        if self.instructor_client is not None and not is_anthropic_compat:
            try:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                messages.append({"role": "user", "content": prompt})

                t_start = time.monotonic()
                result, completion = self.instructor_client.chat.completions.create_with_completion(
                    model=self.config.model_name,
                    response_model=pydantic_model,
                    messages=messages,
                    temperature=self.config.temperature,
                    max_tokens=self.config.max_tokens,
                )
                duration = time.monotonic() - t_start

                result_dict = result.model_dump()
                full_response = json.dumps(result_dict, indent=2)

                input_tokens = 0
                output_tokens = 0
                thinking_tokens = 0
                if completion.usage:
                    input_tokens = completion.usage.prompt_tokens or 0
                    output_tokens = completion.usage.completion_tokens or 0
                    details = getattr(completion.usage, 'completion_tokens_details', None)
                    if details:
                        thinking_tokens = getattr(details, 'reasoning_tokens', 0) or 0
                        output_tokens = output_tokens - thinking_tokens

                tokens_used = input_tokens + output_tokens + thinking_tokens
                cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)
                self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)

                return result_dict, full_response

            except Exception as e:
                if not self._instructor_warned:
                    logger.warning(f"Instructor structured generation failed for {self.config.provider}/{self.config.model_name} — disabling for this provider, using JSON fallback")
                    self._instructor_warned = True
                else:
                    logger.debug(f"Instructor fallback (repeat): {e}")
                # Disable Instructor for this provider — same error will repeat
                self.instructor_client = None

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)


class AnthropicProvider(LLMProvider):
    """
    LLM provider using the Anthropic SDK.

    Native support for Claude models with proper system message handling
    and token counting.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not ANTHROPIC_SDK_AVAILABLE:
            raise ImportError(
                "Anthropic SDK not installed. Run: pip install anthropic"
            )

        self.client = anthropic.Anthropic(
            api_key=config.api_key,
            timeout=config.timeout,
        )

        self.instructor_client = None
        self._instructor_warned = False
        if INSTRUCTOR_AVAILABLE:
            self.instructor_client = instructor.from_anthropic(self.client)
        else:
            logger.warning(
                "Instructor not installed — structured output will use JSON-in-prompt fallback. "
                "For more reliable structured output: pip install instructor"
            )

        logger.debug(f"Initialized AnthropicProvider: {config.model_name}")

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the Anthropic SDK."""
        messages = [{"role": "user", "content": prompt}]

        create_kwargs = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        if system_prompt:
            create_kwargs["system"] = system_prompt

        try:
            t_start = time.monotonic()
            response = self.client.messages.create(**create_kwargs)
            duration = time.monotonic() - t_start

            # Extract text from response (guard against empty/non-text content)
            if not response.content:
                raise RuntimeError("Anthropic returned empty content")
            first_block = response.content[0]
            if not hasattr(first_block, 'text'):
                raise RuntimeError(f"Anthropic returned non-text content block: {first_block.type}")
            content = first_block.text
            finish_reason = response.stop_reason or "complete"

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage:
                input_tokens = response.usage.input_tokens or 0
                output_tokens = response.usage.output_tokens or 0
                # Anthropic extended thinking (when available)
                thinking_tokens = getattr(response.usage, 'thinking_tokens', 0) or 0
            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)
            logger.debug(f"[Anthropic] model={self.config.model_name}, tokens={tokens_used}, cost=${cost:.4f}, duration={duration:.2f}s")

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider=self.config.provider.lower(),
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
            )

        except Exception as e:
            logger.error(f"Anthropic completion failed: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Instructor (or JSON fallback)."""
        pydantic_model = _dict_schema_to_pydantic(schema)

        # Try Instructor first
        if self.instructor_client is not None:
            try:
                messages = [{"role": "user", "content": prompt}]

                create_kwargs = {
                    "model": self.config.model_name,
                    "response_model": pydantic_model,
                    "messages": messages,
                    "temperature": self.config.temperature,
                    "max_tokens": self.config.max_tokens,
                }
                if system_prompt:
                    create_kwargs["system"] = system_prompt

                t_start = time.monotonic()
                result, completion = self.instructor_client.messages.create_with_completion(
                    **create_kwargs,
                )
                duration = time.monotonic() - t_start

                result_dict = result.model_dump()
                full_response = json.dumps(result_dict, indent=2)

                input_tokens = 0
                output_tokens = 0
                thinking_tokens = 0
                if completion.usage:
                    input_tokens = completion.usage.input_tokens or 0
                    output_tokens = completion.usage.output_tokens or 0
                    thinking_tokens = getattr(completion.usage, 'thinking_tokens', 0) or 0
                tokens_used = input_tokens + output_tokens + thinking_tokens
                cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)
                self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)

                return result_dict, full_response

            except Exception as e:
                if not self._instructor_warned:
                    logger.warning(f"Instructor structured generation failed for {self.config.provider}/{self.config.model_name} — disabling for this provider, using JSON fallback")
                    self._instructor_warned = True
                else:
                    logger.debug(f"Instructor fallback (repeat): {e}")
                # Disable Instructor for this provider — same error will repeat
                self.instructor_client = None

        # Fallback: JSON-in-prompt
        return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)


class GeminiProvider(LLMProvider):
    """Native Google Gemini provider using the google-genai SDK.

    Advantages over the OpenAI-compatible shim:
    - Exposes thoughts_token_count for accurate cost tracking
    - Native schema-constrained JSON output (server-side grammar enforcement)
    - No dependency on Google's OpenAI compatibility layer

    Falls back to OpenAICompatibleProvider if google-genai is not installed.
    """

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        if not GENAI_SDK_AVAILABLE:
            raise RuntimeError("google-genai SDK not installed: pip install google-genai")

        import threading
        self._local = threading.local()
        logger.debug(f"Initialized GeminiProvider: {config.model_name}")

    @property
    def client(self):
        """Per-thread client — google-genai is not guaranteed thread-safe."""
        if not hasattr(self._local, 'client'):
            self._local.client = _genai_module.Client(api_key=self.config.api_key)
        return self._local.client

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs) -> LLMResponse:
        """Generate completion using the native Gemini SDK."""
        config_kwargs = {
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_output_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        generate_kwargs = {
            "model": self.config.model_name,
            "contents": contents,
            "config": config_kwargs,
        }
        if system_prompt:
            generate_kwargs["config"]["system_instruction"] = system_prompt

        try:
            t_start = time.monotonic()
            response = self.client.models.generate_content(**generate_kwargs)
            duration = time.monotonic() - t_start

            if not response.text and not response.candidates:
                raise RuntimeError("Gemini returned empty response")

            content = response.text or ""
            finish_reason = "complete"
            if response.candidates and response.candidates[0].finish_reason:
                fr = response.candidates[0].finish_reason
                finish_reason = getattr(fr, 'name', str(fr)).lower()

            # Gemini safety filters block exploit/attack content — detect and raise
            # so the caller sees a clear error rather than empty content
            if not content and finish_reason in ('safety', 'recitation', 'blocked', 'other'):
                raise RuntimeError(
                    f"Gemini blocked response (finish_reason={finish_reason}). "
                    f"This typically happens with exploit code or attack scenario prompts."
                )

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage_metadata:
                input_tokens = response.usage_metadata.prompt_token_count or 0
                output_tokens = response.usage_metadata.candidates_token_count or 0
                thinking_tokens = getattr(response.usage_metadata, 'thoughts_token_count', 0) or 0

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)

            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)
            logger.debug(f"[Gemini] model={self.config.model_name}, tokens={tokens_used}, cost=${cost:.4f}, "
                         f"duration={duration:.2f}s, thinking={thinking_tokens}")

            return LLMResponse(
                content=content,
                model=self.config.model_name,
                provider="gemini",
                tokens_used=tokens_used,
                cost=cost,
                finish_reason=finish_reason,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                thinking_tokens=thinking_tokens,
                duration=duration,
            )

        except Exception as e:
            logger.error(f"Gemini completion failed: {e}")
            raise

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None) -> Tuple[Dict[str, Any], str]:
        """Generate structured output using Gemini's native JSON mode."""
        # Normalize simple schema to JSON Schema format so both pydantic and
        # Gemini schema conversion see the same structure
        normalized = _normalize_schema(schema)
        pydantic_model = _dict_schema_to_pydantic(normalized)

        config_kwargs = {
            "temperature": self.config.temperature,
            "max_output_tokens": self.config.max_tokens,
            "response_mime_type": "application/json",
            "response_schema": _schema_to_gemini(normalized),
        }

        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        generate_kwargs = {
            "model": self.config.model_name,
            "contents": contents,
            "config": config_kwargs,
        }
        if system_prompt:
            generate_kwargs["config"]["system_instruction"] = system_prompt

        try:
            t_start = time.monotonic()
            response = self.client.models.generate_content(**generate_kwargs)
            duration = time.monotonic() - t_start

            content = response.text or ""
            parsed = json.loads(content)
            if not parsed:
                # Gemini sometimes returns {} in structured mode — fall back to text
                raise ValueError("Gemini returned empty object in structured mode")
            parsed = _coerce_to_schema(parsed, schema)
            validated = pydantic_model.model_validate(parsed)
            result_dict = validated.model_dump()
            full_response = json.dumps(result_dict, indent=2)

            input_tokens = 0
            output_tokens = 0
            thinking_tokens = 0
            if response.usage_metadata:
                input_tokens = response.usage_metadata.prompt_token_count or 0
                output_tokens = response.usage_metadata.candidates_token_count or 0
                thinking_tokens = getattr(response.usage_metadata, 'thoughts_token_count', 0) or 0

            tokens_used = input_tokens + output_tokens + thinking_tokens
            cost = self._calculate_cost_split(input_tokens, output_tokens, thinking_tokens)
            self.track_usage(tokens_used, cost, input_tokens, output_tokens, duration)

            logger.debug(f"[Gemini] structured model={self.config.model_name}, tokens={tokens_used}, "
                         f"cost=${cost:.4f}, duration={duration:.2f}s, thinking={thinking_tokens}")

            return result_dict, full_response

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Schema/parsing error — native mode incompatible, fall back to JSON-in-prompt
            logger.warning(f"Gemini native structured generation failed (falling back): {e}")
            return self._structured_fallback(prompt, schema, pydantic_model, system_prompt)
        except Exception:
            # Auth, network, quota — don't waste a second call
            raise


class ClaudeCodeProvider:
    """
    LLM provider stub that signals 'Claude Code will handle this.'

    Returns None from all generation methods. When the agentic pipeline
    runs inside Claude Code with no external LLM configured, this provider
    is used instead of LLMClient. The Python pipeline does mechanical prep
    work (SARIF parsing, code extraction, dataflow analysis) and returns
    structured findings for Claude Code to reason over.

    Callers handle None returns gracefully — the same code path used when
    an external LLM call fails.

    Not a subclass of LLMProvider (returns None instead of LLMResponse),
    but provides the same tracking attributes for stats compatibility.
    Use `is_stub_provider()` to distinguish from real providers.
    """

    is_stub = True  # Distinguishes from real providers

    def __init__(self):
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cost = 0.0
        self.call_count = 0
        self.total_duration = 0.0

    def generate(self, prompt: str, system_prompt: Optional[str] = None,
                 **kwargs):
        """Returns None — Claude Code will do the reasoning."""
        return None

    def generate_structured(self, prompt: str, schema: Dict[str, Any],
                           system_prompt: Optional[str] = None):
        """Returns (None, None) — Claude Code will do the reasoning."""
        return None, None

    def get_stats(self) -> Dict[str, Any]:
        """Return zero stats."""
        return {
            "total_requests": 0,
            "total_cost": 0.0,
            "budget_remaining": 0.0,
            "providers": {},
        }


def create_provider(config: ModelConfig) -> LLMProvider:
    """
    Factory function to create appropriate provider.

    Uses native SDKs where available: AnthropicProvider for Anthropic,
    GeminiProvider for Gemini (with OpenAI shim fallback), and
    OpenAICompatibleProvider for everything else.

    Args:
        config: ModelConfig specifying provider and model

    Returns:
        LLMProvider instance
    """
    provider = config.provider.lower()
    if provider == "anthropic":
        if ANTHROPIC_SDK_AVAILABLE:
            return AnthropicProvider(config)
        elif OPENAI_SDK_AVAILABLE:
            logger.warning(
                "Anthropic SDK not installed — using OpenAI-compatible endpoint. "
                "Structured output will use Pydantic fallback (response_format is ignored by Anthropic). "
                "For best results: pip install anthropic"
            )
            from dataclasses import replace
            compat_config = replace(config, api_base="https://api.anthropic.com/v1")
            return OpenAICompatibleProvider(compat_config)
        else:
            raise RuntimeError(
                "Anthropic provider requires: pip install anthropic (or) pip install openai"
            )
    if provider == "gemini":
        if GENAI_SDK_AVAILABLE:
            return GeminiProvider(config)
        elif OPENAI_SDK_AVAILABLE:
            logger.info("google-genai SDK not installed — using OpenAI-compatible endpoint for Gemini. "
                        "For accurate thinking token tracking: pip install google-genai")
            return OpenAICompatibleProvider(config)
        else:
            raise RuntimeError(
                "Gemini provider requires: pip install google-genai (or) pip install openai"
            )
    if OPENAI_SDK_AVAILABLE:
        return OpenAICompatibleProvider(config)
    raise RuntimeError(
        f"Provider '{provider}' requires: pip install openai"
    )


# Backward compatibility
ClaudeProvider = AnthropicProvider if ANTHROPIC_SDK_AVAILABLE else type('ClaudeProvider', (), {})
OpenAIProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OpenAIProvider', (), {})
OllamaProvider = OpenAICompatibleProvider if OPENAI_SDK_AVAILABLE else type('OllamaProvider', (), {})
