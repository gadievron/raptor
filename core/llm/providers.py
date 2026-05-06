#!/usr/bin/env python3
"""
LLM Provider Implementations — OpenAI SDK + Anthropic SDK + Gemini SDK + Instructor

Native SDKs where available: Anthropic SDK for Anthropic, google-genai
for Gemini (with OpenAI shim fallback), and OpenAI SDK for everything else.
Instructor is used for structured output when available, with a universal
JSON-in-prompt fallback for providers that lack native structured support.
"""

import json
import logging
import sys
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from inspect import isclass
from typing import Dict, Optional, Any, Tuple, Type, Union
from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger
from .config import ModelConfig
# Wire-shape types for tool-use turn primitive. These live in
# ``core.llm.tool_use.types`` (zero dependencies on this module);
# importing them here doesn't create a cycle.
from .tool_use.types import (
    CacheControl,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
    TurnResponse,
)

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
    cached: bool = False

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

    # ------------------------------------------------------------------
    # Tool-use primitives — opt-in per provider.
    # ------------------------------------------------------------------
    #
    # Single-turn round-trip used by the agentic ``ToolUseLoop``
    # runner in :mod:`core.llm.tool_use.loop`. Providers that natively
    # support tool / function calling override :meth:`turn` and flip
    # :meth:`supports_tool_use` to ``True``. Providers that can't
    # (e.g., :class:`ClaudeCodeProvider`'s subprocess dispatcher) keep
    # the defaults — calling :meth:`turn` raises ``NotImplementedError``.
    #
    # This is the same shape the now-retired ``ToolUseProvider``
    # Protocol had; absorbing it onto :class:`LLMProvider` removes the
    # parallel hierarchy + duplicate Anthropic SDK wiring that
    # ``AnthropicToolUseProvider`` introduced.

    def supports_tool_use(self) -> bool:
        """``True`` when the bound model accepts tool/function-call
        schemas in requests AND emits structured calls in responses.
        Default ``False``; concrete providers override."""
        return False

    def supports_prompt_caching(self) -> bool:
        """``True`` for providers with a per-region cache breakpoint
        mechanism (Anthropic). The :class:`ToolUseLoop` only forwards
        :class:`CacheControl` when this returns True; other providers
        receive the struct but ignore it."""
        return False

    def supports_parallel_tools(self) -> bool:
        """``True`` when the provider can return multiple
        :class:`ToolCall` blocks in one assistant turn AND the loop
        can dispatch them in parallel. The loop dispatches
        sequentially today regardless — informational flag for v1."""
        return False

    def context_window(self) -> int:
        """Total tokens the model accepts. Drives the loop's context-
        policy enforcement. Sourced from :mod:`core.llm.model_data`
        by default; raises ``KeyError`` on unknown models so
        misconfiguration surfaces immediately."""
        from .model_data import context_window_for
        return context_window_for(self.config.model_name)

    def estimate_tokens(self, text: str) -> int:
        """Cheap pre-flight token estimator. Default heuristic
        (4 chars/token) is good enough for the loop's context-policy
        gate; providers with a real tokenizer can override for
        accuracy."""
        return max(len(text) // 4, 1)

    def price_per_million(self) -> tuple[float, float]:
        """``(input_per_million_usd, output_per_million_usd)`` for the
        bound model. Cache-read / cache-write multipliers — when
        relevant — are applied inside :meth:`compute_cost`, not here."""
        from .model_data import price_for
        return price_for(self.config.model_name, default=(0.0, 0.0))

    def compute_cost(self, response: TurnResponse) -> float:
        """USD cost of ``response`` given the bound model's pricing.

        If ``response.cost_usd`` is already populated (some providers
        — e.g., Claude Code via the synthesis fallback — surface the
        exact envelope cost), that value is returned directly so the
        loop's budget tracking matches the provider's own ledger.
        Otherwise: standard input/output tokens at the model's per-M
        rates, ignoring cache fields. Anthropic overrides to add the
        documented 1.25× cache-write and 0.1× cache-read multipliers.
        """
        if response.cost_usd is not None:
            return response.cost_usd
        in_per_m, out_per_m = self.price_per_million()
        return (
            response.input_tokens * in_per_m
            + response.output_tokens * out_per_m
        ) / 1_000_000.0

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Send one round-trip with tool/function-call schemas.

        Default implementation raises ``NotImplementedError`` —
        providers that can do tool-use override this method. Callers
        that need to gate behaviour use :meth:`supports_tool_use`.
        """
        raise NotImplementedError(
            f"{type(self).__name__} does not support tool-use; "
            f"check ``supports_tool_use()`` before calling ``turn()``"
        )

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

    # ------------------------------------------------------------------
    # Tool-use fallback — JSON-in-prompt protocol over plain generate().
    # ------------------------------------------------------------------
    #
    # Synthesises a single tool-use turn for providers that can produce
    # text but lack native tool/function calling (e.g., the Claude Code
    # subprocess transport). Subclasses opt in by overriding ``turn`` to
    # delegate here and flipping ``supports_tool_use`` to True.
    #
    # Limitations vs. native:
    #   * one tool call per turn (parallel calls aren't reliably
    #     synthesisable — the prompt asks for one at a time)
    #   * ``CacheControl`` is ignored
    #   * token counts come from the underlying ``generate()`` response;
    #     cost flows through whatever ``track_usage`` records
    # The loop itself is unchanged — it sees the same ``TurnResponse``
    # shape native ``turn`` impls produce.

    def _tool_use_fallback(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Synthesise one tool-use round-trip via plain ``generate()``."""
        del cache_control, provider_specific  # unused by fallback
        tool_protocol = self._render_tool_protocol(tools) if tools else ""
        sys_combined = "\n\n".join(s for s in (system, tool_protocol) if s) or None
        rendered_prompt = self._render_messages_as_prompt(messages)

        response = self.generate(
            rendered_prompt,
            system_prompt=sys_combined,
            max_tokens=max_tokens,
        )

        text = response.content if response and response.content else ""
        block, stop_reason = self._parse_fallback_response(text, tools)

        # Surface the underlying generate() cost on the TurnResponse so
        # loop-side budget tracking reflects the actual provider charge,
        # not a token-derived estimate that may be 0 (e.g., when the CC
        # subprocess uses a model name absent from MODEL_COSTS).
        cost = getattr(response, "cost", None)
        return TurnResponse(
            content=[block],
            stop_reason=stop_reason,
            input_tokens=getattr(response, "input_tokens", 0) or 0,
            output_tokens=getattr(response, "output_tokens", 0) or 0,
            cost_usd=float(cost) if cost is not None else None,
        )

    @staticmethod
    def _render_tool_protocol(tools: Sequence[ToolDef]) -> str:
        """Render tool defs as a JSON-call protocol the model is asked
        to follow. The model is told to emit one JSON object per call;
        the parser tolerates ```json fences and surrounding whitespace
        but not interleaved prose."""
        lines = [
            "You have access to the following tools. To call a tool,",
            "respond with ONLY a JSON object in this exact shape:",
            "```json",
            '{"tool": "<tool_name>", "input": {...}}',
            "```",
            "Call only one tool per response. If you don't need a tool,",
            "respond with normal text and no JSON.",
            "",
            "Available tools:",
        ]
        for t in tools:
            schema_json = json.dumps(t.input_schema, indent=2)
            lines.append(f"- name: {t.name}")
            lines.append(f"  description: {t.description}")
            lines.append(f"  input_schema: {schema_json}")
        return "\n".join(lines)

    @staticmethod
    def _render_messages_as_prompt(messages: Sequence[Message]) -> str:
        """Flatten conversation history into a single prompt string.

        Tool calls/results are rendered as tagged sections so the model
        can follow the protocol on subsequent turns. The role labels
        match what we ask for in :meth:`_render_tool_protocol`."""
        parts: list[str] = []
        for msg in messages:
            for block in msg.content:
                if isinstance(block, TextBlock):
                    parts.append(f"{msg.role}: {block.text}")
                elif isinstance(block, ToolCall):
                    parts.append(
                        f"assistant called tool {block.name!r} "
                        f"with input {json.dumps(block.input)}"
                    )
                elif isinstance(block, ToolResult):
                    err = " [ERROR]" if block.is_error else ""
                    parts.append(
                        f"tool_result{err} for {block.tool_use_id}: "
                        f"{block.content}"
                    )
        return "\n\n".join(parts)

    @staticmethod
    def _parse_fallback_response(
        text: str, tools: Sequence[ToolDef],
    ) -> tuple[Union[TextBlock, ToolCall], StopReason]:
        """Extract a tool call (if any) or fall back to a text block.

        Uses :func:`core.llm.cc_adapter.strip_json_fences` to find a
        JSON payload inside ```json fences anywhere in the response —
        not just at the start — so a model that adds short prose
        before/after the fenced JSON still has its call recognised.
        """
        if not text or not tools:
            return TextBlock(text=text or ""), StopReason.COMPLETE

        from .cc_adapter import strip_json_fences
        candidate = strip_json_fences(text).strip()
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return TextBlock(text=text), StopReason.COMPLETE

        if not isinstance(parsed, dict):
            return TextBlock(text=text), StopReason.COMPLETE

        name = parsed.get("tool")
        inp = parsed.get("input")
        if not isinstance(name, str) or not isinstance(inp, dict):
            return TextBlock(text=text), StopReason.COMPLETE

        if not any(t.name == name for t in tools):
            # Model hallucinated a tool name — surface the raw text so
            # the loop can see what happened rather than dispatching a
            # bogus call.
            return TextBlock(text=text), StopReason.COMPLETE

        import uuid as _uuid
        call_id = f"call_{_uuid.uuid4().hex[:12]}"
        return ToolCall(id=call_id, name=name, input=inp), StopReason.NEEDS_TOOL_CALL


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

        # Flips on first detection that this provider's bound model
        # rejects function-calling (older Ollama models, smaller
        # Mistrals, custom finetunes, vLLM-served models without
        # tool support, etc.). Subsequent ``turn()`` calls then go
        # straight to the JSON-protocol synthesis fallback rather
        # than wasting another round-trip. Per-instance, not
        # persisted — a fresh process re-detects on first turn.
        self._tool_use_unsupported = False

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

    # ------------------------------------------------------------------
    # Tool-use turn primitive — OpenAI function-calling shape.
    # ------------------------------------------------------------------
    #
    # Covers OpenAI / Gemini (via /openai compat) / Ollama / Mistral
    # via the same SDK + base_url override that ``generate()`` uses.
    # Function-calling shape: ``tools=[{type:"function", function:{...}}]``,
    # response carries ``message.tool_calls = [{id, function:{name,arguments}}]``.
    # No prompt caching (capability flag returns False); ``CacheControl``
    # is silently ignored. Parallel tool calls are supported by OpenAI
    # but not exploited by the loop today.

    def supports_tool_use(self) -> bool:
        # Flips after a runtime-detected tool-rejection from the
        # bound model — see ``turn()``.
        return not self._tool_use_unsupported
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return True

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        **_unused: Any,
    ) -> TurnResponse:
        """Send one round-trip via OpenAI-compatible function calling.

        ``cache_control`` is accepted but ignored — OpenAI-compat
        endpoints don't expose a per-region cache mechanism. Caching
        on the actual OpenAI endpoint is automatic (server-side) and
        not driven by request fields.

        Auto-detects tool-use rejection: if the bound model returns a
        4xx error referencing tools/functions on the first attempt,
        flips :attr:`_tool_use_unsupported` and routes through
        :meth:`_tool_use_fallback` for this and all subsequent turns
        (per-instance state). Models that natively support function
        calling never hit this path.
        """
        if _unused:
            logger.debug(
                f"OpenAICompatibleProvider.turn: ignoring unrecognised "
                f"kwargs: {sorted(_unused)}"
            )

        # Already detected this provider rejects tool/function calling.
        # Synthesise via the ABC's JSON-protocol fallback rather than
        # paying another wasted round-trip.
        if self._tool_use_unsupported and tools:
            return self._tool_use_fallback(
                messages, tools,
                system=system, max_tokens=max_tokens,
                cache_control=cache_control,
            )

        # ---- tools (function-calling shape) --------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

        # ---- messages (OpenAI flat list with role markers) ----------
        wire_messages: list[Dict[str, Any]] = []
        if system:
            wire_messages.append({"role": "system", "content": system})
        for m in messages:
            wire_messages.extend(_message_to_openai_wire(m))

        # ---- dispatch (with retry on transient errors) ---------------
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
        }
        if tool_schemas:
            kwargs["tools"] = tool_schemas

        from openai import (                                # type: ignore[import-not-found]
            APIConnectionError,
            APIStatusError,
        )
        t_start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                resp = self.client.chat.completions.create(**kwargs)
                break
            except (APIConnectionError, APIStatusError) as exc:
                # Bound model doesn't support tool/function calling?
                # Flip the per-instance flag and synthesise via the
                # JSON-protocol fallback rather than retrying or
                # giving up. Skips noise on the rest of the run.
                if (
                    tools
                    and isinstance(exc, APIStatusError)
                    and _is_tool_use_unsupported_error(exc)
                ):
                    logger.warning(
                        f"OpenAICompatibleProvider.turn: model "
                        f"{self.config.model_name!r} rejected tools — "
                        f"falling back to JSON-protocol synthesis for "
                        f"this provider instance: {exc}"
                    )
                    self._tool_use_unsupported = True
                    return self._tool_use_fallback(
                        messages, tools,
                        system=system, max_tokens=max_tokens,
                        cache_control=cache_control,
                    )
                if not _is_transient_openai(exc) or attempt >= max_retries:
                    kind = "transient" if _is_transient_openai(exc) else "permanent"
                    err_msg = f"{kind} error after {attempt + 1} attempt(s): {exc}"
                    logger.warning(f"OpenAICompatibleProvider.turn: {err_msg}")
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = backoff_factor ** attempt
                logger.info(
                    f"OpenAICompatibleProvider.turn: transient error attempt "
                    f"{attempt + 1}, retrying in {delay:.1f}s: {exc}"
                )
                time.sleep(delay)
        else:
            return TurnResponse(
                content=[], stop_reason=StopReason.ERROR,
                input_tokens=0, output_tokens=0,
                error_message="exhausted retries",
            )
        duration = time.monotonic() - t_start

        # ---- normalise response --------------------------------------
        if not resp.choices:
            return TurnResponse(
                content=[], stop_reason=StopReason.ERROR,
                input_tokens=0, output_tokens=0,
                error_message="empty choices in response",
            )
        choice = resp.choices[0]
        msg = choice.message
        stop = _OPENAI_FINISH_REASON_MAP.get(
            choice.finish_reason or "", StopReason.ERROR,
        )

        out_blocks: list = []
        if msg.content:
            out_blocks.append(TextBlock(text=msg.content))
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments)
            except (TypeError, ValueError):
                args = {}
            out_blocks.append(ToolCall(
                id=tc.id, name=tc.function.name, input=args,
            ))

        usage = resp.usage
        turn_response = TurnResponse(
            content=out_blocks,
            stop_reason=stop,
            input_tokens=(getattr(usage, "prompt_tokens", 0) or 0) if usage else 0,
            output_tokens=(getattr(usage, "completion_tokens", 0) or 0) if usage else 0,
            # OpenAI-compat doesn't surface per-region cache tokens.
            cache_read_tokens=0,
            cache_write_tokens=0,
        )
        # Track usage so multi-turn loop spend rolls into provider
        # stats. Symmetric with ``generate()`` and the Anthropic
        # ``turn()`` impl. Without this, ``LLMClient.get_stats()``
        # reports 0 cost / 0 tokens for tool-use no matter how many
        # turns the loop ran for.
        cost = self.compute_cost(turn_response)
        self.track_usage(
            tokens=turn_response.input_tokens + turn_response.output_tokens,
            cost=cost,
            input_tokens=turn_response.input_tokens,
            output_tokens=turn_response.output_tokens,
            duration=duration,
        )
        return turn_response


# ---------------------------------------------------------------------------
# OpenAI tool-use helpers
# ---------------------------------------------------------------------------

# OpenAI's native finish_reason → our enum.
_OPENAI_FINISH_REASON_MAP = {
    "stop": StopReason.COMPLETE,
    "tool_calls": StopReason.NEEDS_TOOL_CALL,
    "length": StopReason.MAX_TOKENS,
    "content_filter": StopReason.REFUSED,
    "function_call": StopReason.NEEDS_TOOL_CALL,            # legacy alias
}


def _is_transient_openai(exc: BaseException) -> bool:
    """Same shape as the Anthropic helper. 429 + 5xx retryable;
    permanent 4xx fails fast."""
    from openai import APIConnectionError, APIStatusError    # type: ignore[import-not-found]
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False


def _is_tool_use_unsupported_error(exc: BaseException) -> bool:
    """Heuristic: does ``exc`` look like a 4xx rejection from the
    bound model saying it doesn't support tool / function calling?

    Conservative by design — false positives make us synthesise when
    native would have worked (cheaper outcome — synthesis still
    produces correct results, just slower per turn). False negatives
    keep the existing fail-fast behaviour, which is what users see
    without this detection at all.

    Detects 4xx (not 429) responses whose error body mentions a
    tool/function keyword alongside an unsupported/not-supported
    phrase. Covers Ollama (``model 'X' does not support tools``),
    Mistral, vLLM, and similar shims. OpenAI and Anthropic models
    never produce this error class — every current model on those
    providers supports tool-use natively.
    """
    from openai import APIStatusError                        # type: ignore[import-not-found]
    if not isinstance(exc, APIStatusError):
        return False
    status = getattr(exc, "status_code", None)
    if status is None or status >= 500 or status == 429:
        return False                                         # transient or server-side

    text = str(exc).lower()
    body = getattr(exc, "body", None)
    if isinstance(body, dict):
        err = body.get("error", body)
        if isinstance(err, dict):
            text += " " + str(err.get("message", "")).lower()
        elif isinstance(err, str):
            text += " " + err.lower()

    has_keyword = "tool" in text or "function call" in text or "function-call" in text
    has_negation = (
        "not support" in text
        or "unsupported" in text
        or "does not" in text
        or "no support" in text
    )
    return has_keyword and has_negation


def _message_to_openai_wire(m: Message) -> list[Dict[str, Any]]:
    """One :class:`Message` → 1+ OpenAI wire dicts.

    OpenAI splits user messages with multiple :class:`ToolResult`\\ s
    into N separate ``role:"tool"`` messages (each carrying its own
    ``tool_call_id``), unlike Anthropic which packs them in one user
    message's content array.

    Empty assistant turns (``content=[]``, which the loop can produce
    on ``StopReason.ERROR``) emit ``{"role": "assistant",
    "content": ""}`` — most OpenAI-compatible backends reject an
    assistant message with neither ``content`` nor ``tool_calls``,
    so the empty-string is the safe wire form. Empty user turns are
    skipped (the message has nothing to convey).

    User turns carrying both text and tool_results emit the tool
    messages first, then a trailing ``role:"user"`` text message —
    OpenAI requires tool messages to immediately follow the prior
    assistant's ``tool_calls`` (text in between breaks the link).
    """
    if m.role == "assistant":
        text_parts: list[str] = []
        tool_calls: list[Dict[str, Any]] = []
        for b in m.content:
            if isinstance(b, TextBlock):
                text_parts.append(b.text)
            elif isinstance(b, ToolCall):
                tool_calls.append({
                    "id": b.id,
                    "type": "function",
                    "function": {
                        "name": b.name,
                        "arguments": json.dumps(b.input),
                    },
                })
        out: Dict[str, Any] = {"role": "assistant"}
        if text_parts:
            out["content"] = "".join(text_parts)
        if tool_calls:
            out["tool_calls"] = tool_calls
        if not text_parts and not tool_calls:
            out["content"] = ""
        return [out]
    # user role
    out_msgs: list[Dict[str, Any]] = []
    text_parts = []
    for b in m.content:
        if isinstance(b, TextBlock):
            text_parts.append(b.text)
        elif isinstance(b, ToolResult):
            out_msgs.append({
                "role": "tool",
                "tool_call_id": b.tool_use_id,
                "content": b.content,
            })
    if text_parts:
        out_msgs.append({"role": "user", "content": "".join(text_parts)})
    return out_msgs


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

        # Per-instance flag: have we warned about silent cache-failure
        # for this model? Warns once per provider instance to avoid
        # spam, since the silent-failure is a model-level property
        # (claude-opus-4-5 and claude-opus-4-6 verified non-caching as
        # of 2026-05-04 — Anthropic accepts the cache_control marker
        # but doesn't honor it). See ``_maybe_warn_silent_cache_failure``.
        self._caching_warning_emitted = False

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

    # ------------------------------------------------------------------
    # Tool-use turn primitive — Anthropic-native.
    # ------------------------------------------------------------------
    #
    # Honours all three Anthropic cache regions (system / tools /
    # history-through-index) via ``cache_control: {"type": "ephemeral"}``
    # markers. Cost computation accounts for ``cache_read`` (0.1x input
    # rate) and ``cache_creation`` (1.25x input rate) per Anthropic's
    # documented multipliers. Beta task-budget endpoint via
    # ``provider_specific={"anthropic_task_budget_beta": True,
    # "anthropic_task_budget_tokens": N}``.

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return True
    def supports_parallel_tools(self) -> bool: return True

    def compute_cost(self, response: TurnResponse) -> float:
        """Anthropic cost: standard input/output + cache_write (1.25x
        input) + cache_read (0.1x input) per Anthropic's pricing.

        ``response.cost_usd``, when set, takes precedence — same
        rationale as the ABC default.
        """
        if response.cost_usd is not None:
            return response.cost_usd
        from .model_data import (
            ANTHROPIC_CACHE_READ_MULTIPLIER,
            ANTHROPIC_CACHE_WRITE_MULTIPLIER,
        )
        in_per_m, out_per_m = self.price_per_million()
        return (
            response.input_tokens * in_per_m
            + response.output_tokens * out_per_m
            + response.cache_write_tokens * in_per_m * ANTHROPIC_CACHE_WRITE_MULTIPLIER
            + response.cache_read_tokens * in_per_m * ANTHROPIC_CACHE_READ_MULTIPLIER
        ) / 1_000_000.0

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        anthropic_task_budget_beta: bool = False,
        anthropic_task_budget_tokens: Optional[int] = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
        **_unused: Any,
    ) -> TurnResponse:
        """Send one round-trip to Anthropic.

        Provider-specific kwargs:
          * ``anthropic_task_budget_beta``: route via
            ``client.beta.messages.create`` (cost-cap beta endpoint).
            Activating the beta requires both this flag (sets the
            ``betas=["task-budgets-..."]`` header) AND
            ``anthropic_task_budget_tokens`` (sets the
            ``output_config.task_budget`` request body).
          * ``anthropic_task_budget_tokens``: total token budget
            communicated to the model via
            ``output_config: {task_budget: {type: "tokens", total: N}}``.
            Required when ``anthropic_task_budget_beta=True``.
          * ``max_retries`` / ``backoff_factor``: retry on transient
            errors (connection / 429 / 5xx). Permanent 4xx fails
            fast.
        """
        if anthropic_task_budget_beta and anthropic_task_budget_tokens is None:
            raise ValueError(
                "anthropic_task_budget_beta=True requires "
                "anthropic_task_budget_tokens=N (total token budget the "
                "model self-regulates against). Without it the beta "
                "endpoint accepts the request but no budget is enforced."
            )
        if _unused:
            logger.debug(
                f"AnthropicProvider.turn: ignoring unrecognised "
                f"kwargs: {sorted(_unused)}"
            )

        # ---- system block --------------------------------------------
        # Anthropic accepts a string OR a content list. Use the list
        # form when caching the system prompt so the cache_control
        # marker can attach to it; otherwise the simpler string form.
        system_arg: Optional[Union[str, list]]
        if system:
            if cache_control.system:
                system_arg = [{
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }]
            else:
                system_arg = system
        else:
            system_arg = None

        # ---- tools ---------------------------------------------------
        tool_schemas: list[Dict[str, Any]] = [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in tools
        ]
        if cache_control.tools and tool_schemas:
            last = dict(tool_schemas[-1])
            last["cache_control"] = {"type": "ephemeral"}
            tool_schemas[-1] = last

        # ---- messages ------------------------------------------------
        wire_messages = [_message_to_anthropic_wire(m) for m in messages]
        if (
            cache_control.history_through_index is not None
            and 0 <= cache_control.history_through_index < len(wire_messages)
        ):
            _attach_anthropic_cache_marker(
                wire_messages[cache_control.history_through_index],
            )

        # ---- dispatch (with retry on transient errors) ---------------
        # Routing to ``client.beta.messages.create`` is necessary but
        # not sufficient — the beta only activates when the beta name
        # appears in the ``betas=[...]`` request parameter.
        create_fn = (
            self.client.beta.messages.create
            if anthropic_task_budget_beta
            else self.client.messages.create
        )
        kwargs: Dict[str, Any] = {
            "model": self.config.model_name,
            "max_tokens": max_tokens,
            "messages": wire_messages,
            "tools": tool_schemas if tool_schemas else None,
        }
        if anthropic_task_budget_beta:
            kwargs["betas"] = [_ANTHROPIC_TASK_BUDGET_BETA]
            kwargs["output_config"] = {
                "task_budget": {
                    "type": "tokens",
                    "total": anthropic_task_budget_tokens,
                },
            }
        if system_arg is not None:
            kwargs["system"] = system_arg
        send_kwargs = {k: v for k, v in kwargs.items() if v is not None}

        from anthropic import (                              # type: ignore[import-not-found]
            APIConnectionError,
            APIError,
            APIStatusError,
        )
        t_start = time.monotonic()
        for attempt in range(max_retries + 1):
            try:
                resp = create_fn(**send_kwargs)
                break
            except (APIConnectionError, APIStatusError, APIError) as exc:
                if not _is_transient_anthropic(exc) or attempt >= max_retries:
                    kind = "transient" if _is_transient_anthropic(exc) else "permanent"
                    err_msg = f"{kind} error after {attempt + 1} attempt(s): {exc}"
                    logger.warning(f"AnthropicProvider.turn: {err_msg}")
                    return TurnResponse(
                        content=[],
                        stop_reason=StopReason.ERROR,
                        input_tokens=0,
                        output_tokens=0,
                        error_message=err_msg,
                    )
                delay = backoff_factor ** attempt
                logger.info(
                    f"AnthropicProvider.turn: transient error attempt "
                    f"{attempt + 1}, retrying in {delay:.1f}s: {exc}"
                )
                time.sleep(delay)
        else:
            return TurnResponse(
                content=[], stop_reason=StopReason.ERROR,
                input_tokens=0, output_tokens=0,
                error_message="exhausted retries",
            )
        duration = time.monotonic() - t_start

        # ---- normalise response --------------------------------------
        stop = _ANTHROPIC_STOP_REASON_MAP.get(
            resp.stop_reason or "", StopReason.ERROR,
        )
        out_blocks: list = []
        for block in resp.content:
            block_type = getattr(block, "type", None)
            if block_type == "text":
                out_blocks.append(TextBlock(text=block.text))
            elif block_type == "tool_use":
                out_blocks.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    input=dict(block.input) if block.input else {},
                ))

        usage = resp.usage
        turn_response = TurnResponse(
            content=out_blocks,
            stop_reason=stop,
            input_tokens=(getattr(usage, "input_tokens", 0) or 0) if usage else 0,
            output_tokens=(getattr(usage, "output_tokens", 0) or 0) if usage else 0,
            cache_read_tokens=(
                getattr(usage, "cache_read_input_tokens", 0) or 0
            ) if usage else 0,
            cache_write_tokens=(
                getattr(usage, "cache_creation_input_tokens", 0) or 0
            ) if usage else 0,
        )
        # Track usage so multi-turn loop spend shows up alongside
        # generate() in provider stats. Without this, ``LLMClient.
        # get_stats()`` reports 0 cost / 0 tokens for tool-use even
        # when the loop ran for many turns. Cost via ``compute_cost``
        # so cache multipliers (1.25x write, 0.1x read) apply.
        cost = self.compute_cost(turn_response)
        self.track_usage(
            tokens=turn_response.input_tokens + turn_response.output_tokens,
            cost=cost,
            input_tokens=turn_response.input_tokens,
            output_tokens=turn_response.output_tokens,
            duration=duration,
        )
        self._maybe_warn_silent_cache_failure(turn_response, cache_control)
        return turn_response

    def _maybe_warn_silent_cache_failure(
        self,
        response: TurnResponse,
        cache_control: CacheControl,
    ) -> None:
        """Detect when ``cache_control`` markers are silently no-op'd.

        Anthropic's published cacheable-region minimum is 1024 tokens
        (Opus / Sonnet) or 2048 (Haiku 3.5). Empirically (2026-05-04)
        some model versions enforce a higher de-facto minimum and
        return ``cache_creation_input_tokens=0,
        cache_read_input_tokens=0`` for cache_control opt-ins below
        that minimum, with no error — silent no-op. Consumers planning
        cost budgets around cache savings (cve-diff is the headline
        case) won't see the savings, with no signal until the bill
        comes in.

        Warn once per provider instance when all conditions hold:
          * ``cache_control`` was opt-in (caller asked for caching)
          * ``input_tokens >= 8192`` — well above any observed model's
            de-facto minimum, so a zero-cache outcome is a real signal,
            not a "your request was too small" false positive
          * ``cache_creation_input_tokens == 0`` AND
            ``cache_read_input_tokens == 0``

        The 8192 floor trades sensitivity for specificity: smaller
        cacheable regions that legitimately fall below a model's
        minimum won't trigger spurious warnings, but real silent-
        no-op cases on production-sized prompts (cve-diff: 5K+ tokens
        of system + tools) still surface.

        Scope: per-provider-instance. Each ``LLMClient`` builds its
        own provider via ``_get_provider``, and a fresh agentic run
        typically constructs a fresh client. Operators running the
        same setup repeatedly will see the warning once per run —
        loud enough to act on, not so loud as to hide in noise. A
        cross-process / cross-run dedup would need module-level
        state and isn't worth the complexity for a one-time signal.
        """
        if self._caching_warning_emitted:
            return
        requested = (
            cache_control.system
            or cache_control.tools
            or cache_control.history_through_index is not None
        )
        if not requested:
            return
        if response.input_tokens < 8192:
            return                                          # below threshold
        if response.cache_read_tokens > 0 or response.cache_write_tokens > 0:
            return                                          # caching is working
        logger.warning(
            f"AnthropicProvider: model {self.config.model_name!r} did not "
            f"populate cache fields on a turn with cache_control opt-in "
            f"and {response.input_tokens} input tokens — cache savings "
            f"won't apply for requests this size. Common causes: (1) "
            f"this model's de-facto cacheable-region minimum is higher "
            f"than the documented 1024 tokens; (2) the cacheable subset "
            f"(system + tools when those are opted in) is below the "
            f"model's minimum even though total input is above 8192. "
            f"Try a different model (claude-opus-4-7, "
            f"claude-sonnet-4-5-20250929) or increase the cacheable "
            f"region size. This warning fires once per provider instance."
        )
        self._caching_warning_emitted = True


# ---------------------------------------------------------------------------
# Anthropic tool-use helpers (module-level — used by
# ``AnthropicProvider.turn``)
# ---------------------------------------------------------------------------

# Beta header name for Anthropic's task-budget endpoint. Activated by
# the ``anthropic_task_budget_beta=True`` provider-specific kwarg —
# routing to ``client.beta.messages.create`` is necessary BUT NOT
# SUFFICIENT; the ``betas=[...]`` parameter must also be passed for
# the server to actually honour the beta.
_ANTHROPIC_TASK_BUDGET_BETA = "task-budgets-2026-03-13"

# Anthropic's native stop_reason → our enum.
_ANTHROPIC_STOP_REASON_MAP = {
    "end_turn": StopReason.COMPLETE,
    "stop_sequence": StopReason.COMPLETE,
    "tool_use": StopReason.NEEDS_TOOL_CALL,
    "pause_turn": StopReason.PAUSE_TURN,
    "max_tokens": StopReason.MAX_TOKENS,
    "refusal": StopReason.REFUSED,
}


def _is_transient_anthropic(exc: BaseException) -> bool:
    """``True`` when ``exc`` is a connection / 429 / 5xx error worth
    retrying. Permanent 4xx (auth, schema, not-found) are False so
    callers fail fast instead of burning budget on hopeless retries."""
    from anthropic import APIConnectionError, APIStatusError    # type: ignore[import-not-found]
    if isinstance(exc, APIConnectionError):
        return True
    if isinstance(exc, APIStatusError):
        status = getattr(exc, "status_code", None)
        return status == 429 or (status is not None and 500 <= status < 600)
    return False


def _message_to_anthropic_wire(m: Message) -> Dict[str, Any]:
    """Our :class:`Message` → Anthropic wire dict.

    Anthropic accepts mixed content lists per turn — text, tool_use,
    and tool_result blocks all live in the same ``content`` array;
    role determines which subset is valid (assistant: text + tool_use;
    user: text + tool_result).

    Empty :class:`Message`\\ s (``content=[]``) — which the loop can
    produce when a turn returns ``StopReason.ERROR`` with no blocks —
    are emitted as ``[{"type": "text", "text": ""}]`` so the wire
    shape stays valid if a caller resumes from a failed run.
    """
    out_content: list[Dict[str, Any]] = []
    for block in m.content:
        if isinstance(block, TextBlock):
            out_content.append({"type": "text", "text": block.text})
        elif isinstance(block, ToolCall):                  # assistant role only
            out_content.append({
                "type": "tool_use",
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })
        elif isinstance(block, ToolResult):                # user role only
            out_content.append({
                "type": "tool_result",
                "tool_use_id": block.tool_use_id,
                "content": block.content,
                "is_error": block.is_error,
            })
    if not out_content:
        out_content.append({"type": "text", "text": ""})
    return {"role": m.role, "content": out_content}


def _attach_anthropic_cache_marker(message: Dict[str, Any]) -> None:
    """Mutate ``message["content"][-1]`` in-place to carry a
    cache_control marker. Anthropic places the marker on the LAST
    block of a region to cache everything preceding it within that
    message."""
    if not message["content"]:
        return
    last = dict(message["content"][-1])
    last["cache_control"] = {"type": "ephemeral"}
    message["content"][-1] = last


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

            content = (response.text or "").strip()
            if content.startswith("```") and content.endswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
                content = content.rsplit("```", 1)[0].strip()
            elif content.startswith("```"):
                content = content.split("\n", 1)[1] if "\n" in content else content[3:]
                content = content.strip()
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

    # ------------------------------------------------------------------
    # Tool-use via JSON-protocol synthesis.
    # ------------------------------------------------------------------
    #
    # The native google-genai SDK exposes Gemini's function-calling but
    # this provider doesn't wire that up — operators wanting native
    # function-calling install ``openai`` alongside ``google-genai`` and
    # the factory routes through :class:`OpenAICompatibleProvider`
    # against Gemini's OpenAI-compat endpoint.
    #
    # For users who installed ONLY the google-genai SDK (chosen for
    # accurate ``thoughts_token_count`` cost tracking, server-side
    # schema-constrained JSON), the synthesis fallback gives them
    # tool-use without forcing an additional SDK install. Same pattern
    # as :class:`ClaudeCodeLLMProvider`.

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return False

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Tool-use via the ABC's JSON-protocol fallback."""
        return self._tool_use_fallback(
            messages, tools,
            system=system, max_tokens=max_tokens,
            cache_control=cache_control, **provider_specific,
        )


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


def _safe_subprocess_stderr(stderr: Optional[str], *, limit: int = 500) -> str:
    """Sanitise subprocess stderr for inclusion in operator-facing
    ``RuntimeError`` messages.

    Per ``project_log_sanitisation_adoption.md`` (threats A + B):
    redact credentials that the child process may have echoed
    (``ANTHROPIC_API_KEY``, bearer tokens, ``user:pass@`` URLs) and
    escape non-printable bytes (ANSI / BIDI / control bytes) so the
    error message can't corrupt operator terminals or be reshared
    with secrets intact.

    Truncation happens *after* sanitisation so the limit applies to
    the rendered length, not the raw byte count.
    """
    if not stderr:
        return ""
    from core.security.log_sanitisation import escape_nonprintable
    from core.security.redaction import redact_secrets
    return escape_nonprintable(redact_secrets(stderr))[:limit]


class ClaudeCodeLLMProvider(LLMProvider):
    """Claude Code subprocess transport as a real :class:`LLMProvider`.

    Wraps ``claude -p`` (via :mod:`core.llm.cc_adapter`) so consumers
    that hold a :class:`ModelConfig` can transparently use the Claude
    Code CLI when no SDK API key is configured. Supports tool-use via
    the ABC's :meth:`_tool_use_fallback` (JSON-in-prompt protocol over
    plain ``generate()``) — slower than native tool/function calling
    and one tool call per turn, but functional on any backend that
    just emits text.

    Distinct from the :class:`ClaudeCodeProvider` stub above: this is
    a real provider that does generation; the stub returns ``None`` to
    signal "the surrounding orchestrator handles reasoning" and is
    used by :mod:`packages.llm_analysis.agent` for prep-only mode.
    """

    is_stub = False

    def __init__(
        self,
        config: ModelConfig,
        *,
        claude_bin: Optional[str] = None,
        budget_usd: str = "1.00",
        timeout_s: Optional[int] = None,
    ) -> None:
        super().__init__(config)
        self._claude_bin = claude_bin or "claude"
        self._budget_usd = budget_usd
        # Per-call timeout: prefer explicit kwarg, then ModelConfig.timeout,
        # then a generous default (Claude Code subprocess + tool-use can
        # take several minutes on real workloads).
        self._timeout_s = timeout_s or (config.timeout if config.timeout else 600)

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Dispatch a prompt to ``claude -p`` and parse the JSON envelope."""
        from .cc_adapter import (
            CCDispatchConfig, build_cc_command, parse_cc_freeform,
        )
        import subprocess
        import time as _time

        full_prompt = (
            f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        )
        cc_config = CCDispatchConfig(
            claude_bin=self._claude_bin,
            # Used as a pure-LLM substrate: disable CC's internal tools
            # (Read/Grep/Glob default) so the subprocess can't scan cwd
            # before answering. Tool-use happens at the loop layer above
            # us via _tool_use_fallback's JSON-protocol synthesis.
            tools="",
            budget_usd=self._budget_usd,
            timeout_s=self._timeout_s,
            capture_json_envelope=True,
        )
        cmd = build_cc_command(cc_config)

        start = _time.time()
        try:
            proc = subprocess.run(
                cmd,
                input=full_prompt,
                text=True,
                capture_output=True,
                timeout=self._timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"claude -p timed out after {self._timeout_s}s"
            ) from e
        duration = _time.time() - start

        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p exited with status {proc.returncode}: "
                f"{_safe_subprocess_stderr(proc.stderr)}"
            )

        parsed = parse_cc_freeform(proc.stdout, proc.stderr)
        content = parsed.get("content", "") or ""
        cost = float(parsed.get("cost_usd", 0.0) or 0.0)
        tokens = int(parsed.get("_tokens", 0) or 0)

        # Best-effort token split: cc_adapter only surfaces total tokens;
        # if the envelope had separate input/output we'd carry them, but
        # parse_cc_freeform sums them. Attribute everything to output to
        # avoid silently zeroing the counter.
        self.track_usage(
            tokens=tokens, cost=cost,
            input_tokens=0, output_tokens=tokens,
            duration=duration,
        )

        return LLMResponse(
            content=content,
            model=parsed.get("analysed_by", self.config.model_name),
            provider="claudecode",
            tokens_used=tokens,
            cost=cost,
            finish_reason="stop",
            input_tokens=0,
            output_tokens=tokens,
            duration=duration,
        )

    def generate_structured(
        self,
        prompt: str,
        schema: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str]:
        """Dispatch with ``--json-schema`` for structured output."""
        from .cc_adapter import (
            CCDispatchConfig, build_cc_command, parse_cc_structured,
        )
        import subprocess
        import time as _time

        full_prompt = (
            f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        )
        cc_config = CCDispatchConfig(
            claude_bin=self._claude_bin,
            tools="",                                # see generate() comment
            budget_usd=self._budget_usd,
            timeout_s=self._timeout_s,
            json_schema=schema,
            capture_json_envelope=True,
        )
        cmd = build_cc_command(cc_config)

        start = _time.time()
        try:
            proc = subprocess.run(
                cmd,
                input=full_prompt,
                text=True,
                capture_output=True,
                timeout=self._timeout_s,
            )
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(
                f"claude -p timed out after {self._timeout_s}s"
            ) from e
        duration = _time.time() - start

        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p exited with status {proc.returncode}: "
                f"{_safe_subprocess_stderr(proc.stderr)}"
            )

        result = parse_cc_structured(proc.stdout, proc.stderr)
        if "error" in result and result["error"]:
            raise RuntimeError(f"claude -p structured parse failed: {result['error']}")

        # Track usage so structured calls show up alongside generate() in
        # provider stats. cost/_tokens are set by extract_envelope_metadata
        # inside parse_cc_structured when the envelope carries them.
        cost = float(result.pop("cost_usd", 0.0) or 0.0)
        tokens = int(result.pop("_tokens", 0) or 0)
        result.pop("duration_seconds", None)
        result.pop("analysed_by", None)
        # parse_cc_structured injects ``finding_id`` (default "unknown")
        # via setdefault — a CVE-aware behaviour leaking from
        # cc_adapter's other consumers. Strip it so the consumer's
        # schema isn't polluted with a field they didn't ask for.
        result.pop("finding_id", None)
        self.track_usage(
            tokens=tokens, cost=cost,
            input_tokens=0, output_tokens=tokens,
            duration=duration,
        )

        # Return ``StructuredResponse`` so callers (notably ``turn()``)
        # can read per-call cost / tokens directly without racing on
        # shared instance state. ``__iter__`` keeps the existing
        # ``result, raw = client.generate_structured(...)`` tuple-
        # unpack pattern working.
        return StructuredResponse(
            result=result,
            raw=json.dumps(result, indent=2),
            cost=cost,
            tokens_used=tokens,
            model=self.config.model_name,
            provider="claudecode",
            duration=duration,
        )

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return False
    def supports_parallel_tools(self) -> bool: return False

    # ------------------------------------------------------------------
    # Tool-use via ``--json-schema`` structured output.
    # ------------------------------------------------------------------
    #
    # The ABC's JSON-in-prompt synthesis (``_tool_use_fallback``) does
    # *not* work for Claude Code. CC has anti-prompt-injection training
    # that refuses to roleplay as a different agent system when a system
    # prompt says "you have these tools, emit JSON to call them" — that
    # framing is indistinguishable from an attacker injecting a fake
    # tool schema, and CC correctly refuses.
    #
    # The fix: reframe the task as *structured output* via CC's
    # ``--json-schema`` flag. Anti-injection guards roleplay, not
    # form-filling. We give CC a discriminated-union schema (either
    # ``tool_call`` or ``complete``) plus the tool catalog as
    # reference material, and CC fills in the form. Verified
    # empirically: CC honours the schema and produces valid tool
    # calls or final answers for typical agent flows.

    def turn(
        self,
        messages: Sequence[Message],
        tools: Sequence[ToolDef],
        *,
        system: Optional[str] = None,
        max_tokens: int = 4096,
        cache_control: CacheControl = CacheControl(),
        **provider_specific: Any,
    ) -> TurnResponse:
        """Tool-use via ``generate_structured`` with a discriminated
        schema. Each turn, CC chooses either to call a tool (returning
        name + input) or to finalise (returning text)."""
        del cache_control, provider_specific            # unused by CC

        # No tools → plain text generation. Skip the schema overhead.
        if not tools:
            rendered = LLMProvider._render_messages_as_prompt(messages)
            response = self.generate(
                rendered, system_prompt=system, max_tokens=max_tokens,
            )
            cost = getattr(response, "cost", None)
            return TurnResponse(
                content=[TextBlock(text=(response.content if response else "") or "")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=getattr(response, "input_tokens", 0) or 0,
                output_tokens=getattr(response, "output_tokens", 0) or 0,
                cost_usd=float(cost) if cost is not None else None,
            )

        schema = self._build_turn_schema(tools)
        sys_combined = self._build_turn_system_prompt(tools, extra=system)
        rendered_history = self._render_history_for_cc(messages)

        try:
            response = self.generate_structured(
                prompt=rendered_history,
                schema=schema,
                system_prompt=sys_combined,
            )
        except RuntimeError as exc:
            err_msg = f"subprocess error: {exc}"
            logger.warning(f"ClaudeCodeLLMProvider.turn: {err_msg}")
            return TurnResponse(
                content=[],
                stop_reason=StopReason.ERROR,
                input_tokens=0, output_tokens=0,
                error_message=err_msg,
            )

        # Per-call cost / tokens come from the response directly so
        # concurrent loops on the same provider don't race on shared
        # ``self.total_cost`` state. ``StructuredResponse`` carries
        # the values; the legacy ``(result, raw)`` tuple-unpack still
        # works via ``__iter__``.
        if isinstance(response, StructuredResponse):
            result = response.result
            cost_usd = response.cost
            tokens = response.tokens_used
        else:
            # Defensive: a future provider might still return a tuple.
            result, _ = response
            cost_usd = 0.0
            tokens = 0

        return self._parse_turn_structured_result(
            result, tools,
            cost_usd=cost_usd,
            # ``tokens_used`` from cc_adapter's envelope is already the
            # input+output sum; we don't have a clean split, so attribute
            # everything to output (consistent with ``generate()``'s
            # behaviour for CC — see ``ClaudeCodeLLMProvider.generate``).
            input_tokens=0,
            output_tokens=tokens,
        )

    # ------------------------------------------------------------------
    # turn() helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_turn_schema(tools: Sequence[ToolDef]) -> Dict[str, Any]:
        """Discriminated-union schema CC fills in for one turn.

        ``tool_name`` is constrained to the registered tool set so CC
        can't hallucinate a name. ``tool_input`` is left as a generic
        object — per-tool input validation happens at dispatch time
        in :class:`ToolUseLoop`."""
        return {
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["tool_call", "complete"],
                    "description": (
                        "tool_call to invoke a tool; complete to "
                        "deliver the final answer."
                    ),
                },
                "tool_name": {
                    "type": "string",
                    "enum": [t.name for t in tools],
                    "description": (
                        "Name of the tool to invoke (only when "
                        "type=tool_call)."
                    ),
                },
                "tool_input": {
                    "type": "object",
                    "description": (
                        "Arguments object for the tool, matching its "
                        "input_schema (only when type=tool_call)."
                    ),
                },
                "final_text": {
                    "type": "string",
                    "description": (
                        "Final answer text (only when type=complete)."
                    ),
                },
            },
            "required": ["type"],
        }

    @staticmethod
    def _build_turn_system_prompt(
        tools: Sequence[ToolDef],
        *,
        extra: Optional[str] = None,
    ) -> str:
        # The "do not invent values" instruction is critical and
        # substrate-level (not consumer-specific): without it, the
        # model sometimes calls verification tools (e.g.
        # ``gh_commit_detail(slug=..., sha=...)``) with hallucinated
        # arguments before the discovery tool that produces those
        # values has been called. The mitigation costs nothing and
        # generalises across consumers; per-consumer guardrails
        # (cve-diff's verified-SHA gate, etc.) remain the
        # belt-and-braces second line.
        lines = [
            "Decide the next action for an agentic tool-use loop. "
            "Either invoke a tool to gather more information or "
            "deliver a final answer. Output JSON matching the "
            "provided schema.",
            "",
            "RULES:",
            "1. When invoking a tool, the values you put in tool_input "
            "MUST come from either the conversation history or the "
            "user's request. Do not guess, invent, or recall from "
            "training data — even values that look plausible (slugs, "
            "SHAs, URLs, IDs, package names).",
            "2. If you don't have a value the next tool needs, call "
            "a discovery tool first to obtain it.",
            "3. Call only one tool per response.",
            "",
            "TOOL CATALOG:",
        ]
        for t in tools:
            lines.append(f"- {t.name}: {t.description}")
            lines.append(
                f"  input_schema: {json.dumps(t.input_schema)}"
            )
        if extra:
            lines.extend(["", extra])
        return "\n".join(lines)

    @staticmethod
    def _render_history_for_cc(messages: Sequence[Message]) -> str:
        """Flatten conversation history into a prompt CC reads as
        reference material. Roles labelled; tool-call/result blocks
        rendered as descriptive text."""
        parts: list[str] = ["CONVERSATION HISTORY:"]
        for msg in messages:
            for block in msg.content:
                if isinstance(block, TextBlock):
                    parts.append(f"{msg.role}: {block.text}")
                elif isinstance(block, ToolCall):
                    parts.append(
                        f"assistant called tool {block.name!r} with "
                        f"input {json.dumps(block.input)}"
                    )
                elif isinstance(block, ToolResult):
                    err = " [error]" if block.is_error else ""
                    parts.append(
                        f"tool_result{err} for {block.tool_use_id}: "
                        f"{block.content}"
                    )
        return "\n\n".join(parts)

    def _parse_turn_structured_result(
        self,
        result: Dict[str, Any],
        tools: Sequence[ToolDef],
        *,
        cost_usd: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> TurnResponse:
        """Translate CC's structured response into a
        :class:`TurnResponse`. Defensive against malformed output —
        falls back to a text block if the result doesn't fit either
        branch of the discriminated schema."""
        usd: Optional[float] = float(cost_usd) if cost_usd else None
        rtype = result.get("type")
        if rtype == "tool_call":
            name = result.get("tool_name")
            inp = result.get("tool_input")
            if (
                isinstance(name, str)
                and isinstance(inp, dict)
                and any(t.name == name for t in tools)
            ):
                import uuid as _uuid
                call_id = f"call_{_uuid.uuid4().hex[:12]}"
                return TurnResponse(
                    content=[ToolCall(id=call_id, name=name, input=inp)],
                    stop_reason=StopReason.NEEDS_TOOL_CALL,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=usd,
                )
            # Malformed tool_call — surface the raw result as text so
            # callers can see what went wrong rather than silently
            # dropping it.
            return TurnResponse(
                content=[TextBlock(text=json.dumps(result))],
                stop_reason=StopReason.COMPLETE,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=usd,
            )
        # Default to "complete" for type="complete" and any other
        # unexpected discriminator value.
        text = result.get("final_text") or ""
        return TurnResponse(
            content=[TextBlock(text=text)],
            stop_reason=StopReason.COMPLETE,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=usd,
        )


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
    if provider in ("claudecode", "claude_code", "claude-code"):
        return ClaudeCodeLLMProvider(config)
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
