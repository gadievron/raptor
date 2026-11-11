"""Admission quotes for supported, fully buffered text generation requests.

The input bound uses the existing dispatcher assumption that BPE input tokens
consume at least one byte of the complete request. Unsupported server work and
remote input references are refused. An upstream violating its output or usage
contract is outside this accounting bound; a quote is not proof of live billing.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from typing import Any

from .budget_errors import LLMCallAdmissionRefused


@dataclass(frozen=True)
class PreparedQuote:
    reservation_usd: float
    reservation_tokens: int


_CHAT_PATHS = frozenset({"/chat/completions", "/v1/chat/completions",
                         "/openai/v1/chat/completions"})
_MESSAGE_PATHS = frozenset({"/messages", "/v1/messages", "/anthropic/v1/messages"})
_FIELDS = frozenset({
    "model", "messages", "system", "max_tokens", "max_completion_tokens", "temperature",
    "top_p", "top_k", "stop", "stop_sequences", "tools", "tool_choice", "response_format",
    "parallel_tool_calls", "thinking", "metadata", "output_config", "betas", "stream",
    "seed", "user", "logprobs", "top_logprobs", "n",
})


def _unavailable(reason: str) -> None:
    raise LLMCallAdmissionRefused("prepared request unavailable: " + reason)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite_json(_value):
    raise ValueError("non-finite JSON value")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("non-finite JSON value")
    return result


def _cache_control(value) -> None:
    if (not isinstance(value, dict) or set(value) - {"type", "ttl"}
            or value.get("type") != "ephemeral" or value.get("ttl", "5m") != "5m"):
        _unavailable("unsupported cache policy")


def _text_content(value) -> None:
    if isinstance(value, str):
        return
    if not isinstance(value, list) or not value:
        _unavailable("non-text content")
    for block in value:
        if (not isinstance(block, dict) or set(block) - {"type", "text", "cache_control"}
                or block.get("type") != "text" or not isinstance(block.get("text"), str)):
            _unavailable("non-text content")
        if "cache_control" in block:
            _cache_control(block["cache_control"])


def _local_schema_references(value) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            for key, item in current.items():
                if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (
                        not isinstance(item, str) or not item.startswith("#")):
                    _unavailable("external schema reference")
                pending.append(item)
        elif isinstance(current, list):
            pending.extend(current)


def _tool_choice(value) -> None:
    if isinstance(value, str) and value in {"auto", "none", "required", "any"}:
        return
    if not isinstance(value, dict):
        _unavailable("unsupported tool choice")
    kind = value.get("type")
    if kind not in ("auto", "none", "any", "tool", "function"):
        _unavailable("unsupported tool choice")
    allowed = {"type", "disable_parallel_tool_use"}
    if kind == "tool":
        allowed.add("name")
    elif kind == "function":
        allowed = {"type", "function"}
    if set(value) - allowed:
        _unavailable("unsupported tool choice")
    if "disable_parallel_tool_use" in value and type(value["disable_parallel_tool_use"]) is not bool:
        _unavailable("unsupported tool choice")
    if kind == "function" and (not isinstance(value.get("function"), dict)
                                or set(value["function"]) != {"name"}
                                or not isinstance(value["function"]["name"], str)):
        _unavailable("unsupported tool choice")
    if kind == "tool" and not isinstance(value.get("name"), str):
        _unavailable("unsupported tool choice")


def _response_format(value) -> None:
    if not isinstance(value, dict):
        _unavailable("unsupported response format")
    kind = value.get("type")
    if kind in ("text", "json_object") and set(value) == {"type"}:
        return
    schema = value.get("json_schema")
    if (kind != "json_schema" or set(value) != {"type", "json_schema"}
            or not isinstance(schema, dict)
            or set(schema) - {"name", "description", "schema", "strict"}
            or not isinstance(schema.get("name"), str)
            or not isinstance(schema.get("schema"), dict)):
        _unavailable("unsupported response format")
    _local_schema_references(schema)


def _output_config(value) -> None:
    if not isinstance(value, dict) or set(value) - {"effort", "format"}:
        _unavailable("unsupported output configuration")
    if "effort" in value and value["effort"] not in ("low", "medium", "high", "max"):
        _unavailable("unsupported output configuration")
    if "format" in value:
        form = value["format"]
        if (not isinstance(form, dict) or set(form) != {"type", "schema"}
                or form.get("type") != "json_schema" or not isinstance(form.get("schema"), dict)):
            _unavailable("unsupported output configuration")
        _local_schema_references(form["schema"])


def _tools(value) -> None:
    if not isinstance(value, list):
        _unavailable("unsupported tools")
    for tool in value:
        if not isinstance(tool, dict):
            _unavailable("unsupported tools")
        kind = tool.get("type", "custom")
        if kind == "function":
            function = tool.get("function")
            if (set(tool) - {"type", "function"} or not isinstance(function, dict)
                    or set(function) - {"name", "description", "parameters", "strict"}
                    or not isinstance(function.get("name"), str)
                    or not isinstance(function.get("parameters"), dict)):
                _unavailable("unsupported function tool")
        elif kind == "custom":
            if (set(tool) - {"type", "name", "description", "input_schema", "cache_control", "strict"}
                    or not isinstance(tool.get("name"), str)
                    or not isinstance(tool.get("input_schema"), dict)):
                _unavailable("unsupported custom tool")
            if "cache_control" in tool:
                _cache_control(tool["cache_control"])
        else:
            _unavailable("server tool")
        _local_schema_references(tool)


def _payload(request, provider) -> tuple[dict[str, Any], int, int]:
    try:
        body = request.content
        path = request.url.path
        method, query, fragment = request.method, request.url.query, request.url.fragment
    except (AttributeError, RuntimeError, TypeError) as error:
        raise LLMCallAdmissionRefused("prepared request unavailable: unbuffered request") from error
    if method != "POST" or path not in _CHAT_PATHS | _MESSAGE_PATHS or query or fragment:
        _unavailable("unsupported route")
    if not isinstance(body, bytes):
        _unavailable("unbuffered request")
    try:
        payload = json.loads(body, object_pairs_hook=_unique_object,
                             parse_constant=_nonfinite_json, parse_float=_finite_float)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise LLMCallAdmissionRefused("prepared request unavailable: invalid JSON") from error
    if not isinstance(payload, dict) or set(payload) - _FIELDS:
        _unavailable("unsupported envelope fields")
    if (not isinstance(payload.get("model"), str)
            or payload["model"] != provider.config.model_name):
        _unavailable("model mismatch")
    if (payload.get("stream") is not None and payload["stream"] is not False
            or type(payload.get("n", 1)) is not int or payload.get("n", 1) != 1):
        _unavailable("streaming or multiple completions")
    keys = ("max_tokens",) if path in _MESSAGE_PATHS else ("max_tokens", "max_completion_tokens")
    ceilings = [payload[key] for key in keys if key in payload]
    if not ceilings or any(type(value) is not int or value <= 0 for value in ceilings):
        _unavailable("output ceiling missing")
    output = max(ceilings)
    if path in _MESSAGE_PATHS and "max_completion_tokens" in payload:
        _unavailable("unsupported messages ceiling")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages:
        _unavailable("messages missing")
    for message in messages:
        if (not isinstance(message, dict) or set(message) - {"role", "content", "name"}
                or message.get("role") not in ("user", "assistant", "system", "developer")):
            _unavailable("unsupported message")
        _text_content(message.get("content"))
    if "system" in payload:
        _text_content(payload["system"])
    if "tools" in payload:
        _tools(payload["tools"])
    if "tool_choice" in payload:
        _tool_choice(payload["tool_choice"])
    if "response_format" in payload:
        _response_format(payload["response_format"])
    if "output_config" in payload:
        _output_config(payload["output_config"])
    if "thinking" in payload:
        thinking = payload["thinking"]
        if (not isinstance(thinking, dict) or set(thinking) - {"type", "budget_tokens", "display"}
                or thinking.get("type") not in ("enabled", "disabled", "adaptive")):
            _unavailable("unsupported thinking policy")
        budget = thinking.get("budget_tokens")
        if budget is not None and (type(budget) is not int or budget <= 0 or budget > output):
            _unavailable("thinking exceeds output ceiling")
    return payload, len(body), output


def quote_prepared_request(request, provider, *, track_cost: bool = True) -> PreparedQuote:
    """Quote existing price arithmetic for a supported actual wire envelope."""
    _, body_len, output = _payload(request, provider)
    if not track_cost:
        return PreparedQuote(0.0, body_len + output)
    from .model_data import resolve_model_costs
    rates = resolve_model_costs(provider.config.model_name)
    fallback = provider.config.cost_per_1k_tokens
    if rates is None and (isinstance(fallback, bool) or not isinstance(fallback, (int, float))
                          or not math.isfinite(fallback) or fallback <= 0):
        _unavailable("model pricing missing")
    try:
        components = [provider._calculate_cost_split(body_len, 0),
                      provider._calculate_cost_split(0, 0, cache_write_tokens=body_len),
                      provider._calculate_cost_split(0, output)]
        if any(isinstance(value, bool) or not math.isfinite(value) or value < 0 for value in components):
            _unavailable("model pricing invalid")
        cost = max(components[0], components[1]) + components[2]
        if not math.isfinite(cost):
            _unavailable("model pricing invalid")
    except (ArithmeticError, TypeError, ValueError) as error:
        raise LLMCallAdmissionRefused("prepared request unavailable: model pricing invalid") from error
    return PreparedQuote(float(cost), body_len + output)
