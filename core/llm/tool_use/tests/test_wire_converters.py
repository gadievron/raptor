"""Tests for the per-provider wire-format converters that translate
:class:`Message` to native Anthropic / OpenAI request shapes, plus
``compute_cost``'s respect for the ``TurnResponse.cost_usd`` override.

These are unit tests of the module-level helpers in
:mod:`core.llm.providers`; they don't construct providers or hit any
SDK. The provider-level integration tests
(``test_anthropic.py``, ``test_openai_compat.py``) cover the same
shapes end-to-end via fake clients.
"""

from __future__ import annotations

import json

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import (
    _message_to_anthropic_wire,
    _message_to_openai_wire,
)
from core.llm.tool_use import (
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolResult,
    TurnResponse,
)


# ---------------------------------------------------------------------------
# Anthropic wire converter — empty-content defensive fallback
# ---------------------------------------------------------------------------


def test_anthropic_wire_empty_assistant_emits_empty_textblock() -> None:
    """When ``turn()`` returns ``StopReason.ERROR`` with no content
    blocks, the loop appends ``Message(role='assistant', content=[])``
    to history. If a caller later resumes via ``run_with_history``,
    Anthropic rejects an assistant message with an empty content
    array. The converter inserts an empty text block so the wire
    shape stays valid."""
    msg = Message(role="assistant", content=[])
    out = _message_to_anthropic_wire(msg)
    assert out == {
        "role": "assistant",
        "content": [{"type": "text", "text": ""}],
    }


def test_anthropic_wire_empty_user_also_handled() -> None:
    """Same defensive behaviour for empty user messages — symmetry
    matters because the loop's truncation logic could leave one in
    rare edge cases."""
    msg = Message(role="user", content=[])
    out = _message_to_anthropic_wire(msg)
    assert out["content"] == [{"type": "text", "text": ""}]


def test_anthropic_wire_normal_text_unaffected() -> None:
    """The empty-content fallback only fires when content is empty."""
    msg = Message(role="user", content=[TextBlock(text="hi")])
    out = _message_to_anthropic_wire(msg)
    assert out["content"] == [{"type": "text", "text": "hi"}]


def test_anthropic_wire_assistant_text_plus_tool_call() -> None:
    """Mixed content survives the converter unchanged."""
    msg = Message(role="assistant", content=[
        TextBlock(text="thinking"),
        ToolCall(id="t1", name="search", input={"q": "x"}),
    ])
    out = _message_to_anthropic_wire(msg)
    assert len(out["content"]) == 2
    assert out["content"][0]["type"] == "text"
    assert out["content"][1]["type"] == "tool_use"


# ---------------------------------------------------------------------------
# OpenAI wire converter — empty-content defensive fallback
# ---------------------------------------------------------------------------


def test_openai_wire_empty_assistant_emits_empty_string_content() -> None:
    """OpenAI-compatible backends reject an assistant message with
    neither ``content`` nor ``tool_calls``. The converter emits
    ``content=""`` for fully-empty assistant turns so the wire shape
    is accepted on resume from a failed run."""
    msg = Message(role="assistant", content=[])
    out = _message_to_openai_wire(msg)
    assert out == [{"role": "assistant", "content": ""}]


def test_openai_wire_assistant_with_tool_calls_only_omits_content() -> None:
    """When an assistant turn has tool_calls but no text, OpenAI
    accepts the message without ``content``. Don't add an empty
    string in this case — it might confuse some shims."""
    msg = Message(role="assistant", content=[
        ToolCall(id="t1", name="search", input={"q": "x"}),
    ])
    out = _message_to_openai_wire(msg)
    assert len(out) == 1
    assert "content" not in out[0]
    assert out[0]["tool_calls"][0]["function"]["name"] == "search"


def test_openai_wire_empty_user_emits_empty_content() -> None:
    """Empty user turns emit ``{"role": "user", "content": ""}`` —
    symmetric with the assistant-empty branch which has always done
    this. Pre-fix returned `[]`, which produced a malformed
    conversation (the next assistant turn followed an absent user
    turn) and most OpenAI-compat backends rejected the request
    outright."""
    msg = Message(role="user", content=[])
    out = _message_to_openai_wire(msg)
    assert out == [{"role": "user", "content": ""}]


def test_openai_wire_user_with_tool_results_only() -> None:
    """User turn carrying just tool_results splits into N tool
    messages (existing behaviour, no change)."""
    msg = Message(role="user", content=[
        ToolResult(tool_use_id="t1", content="42"),
        ToolResult(tool_use_id="t2", content="43"),
    ])
    out = _message_to_openai_wire(msg)
    assert len(out) == 2
    assert all(m["role"] == "tool" for m in out)
    assert out[0]["tool_call_id"] == "t1"
    assert out[1]["tool_call_id"] == "t2"


def test_openai_wire_user_text_plus_tool_results_emits_text_last() -> None:
    """OpenAI's strict ordering: tool messages must immediately follow
    the prior assistant's tool_calls. A user-text message sandwiched
    between assistant.tool_calls and the matching tool messages would
    break the link and many shims reject the request. The converter
    therefore emits tool messages first, then trailing user text —
    so the chain remains: assistant.tool_calls → tool → tool → user."""
    msg = Message(role="user", content=[
        TextBlock(text="extra context"),
        ToolResult(tool_use_id="t1", content="42"),
        ToolResult(tool_use_id="t2", content="43"),
    ])
    out = _message_to_openai_wire(msg)
    assert len(out) == 3
    assert out[0]["role"] == "tool"
    assert out[0]["tool_call_id"] == "t1"
    assert out[1]["role"] == "tool"
    assert out[1]["tool_call_id"] == "t2"
    assert out[2] == {"role": "user", "content": "extra context"}


def test_openai_wire_assistant_text_only_carries_content() -> None:
    """Plain text assistant — no tool_calls, content set."""
    msg = Message(role="assistant", content=[TextBlock(text="answer")])
    out = _message_to_openai_wire(msg)
    assert out == [{"role": "assistant", "content": "answer"}]


# ---------------------------------------------------------------------------
# TurnResponse.cost_usd — propagates through compute_cost
# ---------------------------------------------------------------------------


def _llm_provider_with_known_pricing():
    """A minimal LLMProvider subclass for testing compute_cost.
    Uses the ABC default ``compute_cost`` and a model with known
    per-million pricing (claude-opus-4-6 → $5 in / $25 out)."""
    from core.llm.providers import LLMProvider

    class _Stub(LLMProvider):
        def generate(self, prompt, system_prompt=None, **kwargs):    # noqa: ARG002
            raise NotImplementedError

        def generate_structured(self, prompt, schema, system_prompt=None):  # noqa: ARG002
            raise NotImplementedError

    return _Stub(ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="ignored",
        timeout=1,
    ))


def test_compute_cost_uses_token_formula_when_cost_usd_unset() -> None:
    """Default path: token-based formula when cost_usd is None."""
    p = _llm_provider_with_known_pricing()
    resp = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=1000,
        output_tokens=500,
    )
    expected = (1000 * 5 + 500 * 25) / 1_000_000.0
    assert abs(p.compute_cost(resp) - expected) < 1e-9


def test_compute_cost_returns_cost_usd_when_set() -> None:
    """Override path: when the provider already knows the exact
    cost (e.g., from CC's envelope), compute_cost returns it
    verbatim and skips the token formula entirely."""
    p = _llm_provider_with_known_pricing()
    resp = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=1_000_000,                 # would compute huge
        output_tokens=1_000_000,
        cost_usd=0.0123,                        # but we trust this
    )
    assert p.compute_cost(resp) == 0.0123


def test_compute_cost_zero_cost_usd_treated_as_known() -> None:
    """``cost_usd=0.0`` is a *known* zero (e.g., Ollama local), not
    a missing value. Distinct from ``None``. Returns 0 directly
    rather than falling back to the token formula."""
    p = _llm_provider_with_known_pricing()
    resp = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=10_000,                    # token formula > 0
        output_tokens=10_000,
        cost_usd=0.0,
    )
    assert p.compute_cost(resp) == 0.0


# ---------------------------------------------------------------------------
# AnthropicProvider.compute_cost — also respects cost_usd
# ---------------------------------------------------------------------------


def test_anthropic_compute_cost_respects_cost_usd_override() -> None:
    """Anthropic's compute_cost overrides the ABC to add cache
    multipliers, but should still honour an explicit cost_usd —
    otherwise the loop's budget tracking diverges from any
    out-of-band cost ledger the caller maintains."""
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider

    p = AnthropicProvider(ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="test-key",
        timeout=1,
    ))
    resp = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=1000,
        output_tokens=500,
        cache_read_tokens=10_000,
        cache_write_tokens=5_000,
        cost_usd=0.42,
    )
    assert p.compute_cost(resp) == 0.42


def test_anthropic_compute_cost_uses_cache_formula_when_cost_usd_unset() -> None:
    """Default path on Anthropic — full cache-aware formula."""
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider

    p = AnthropicProvider(ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="test-key",
        timeout=1,
    ))
    resp = TurnResponse(
        content=[],
        stop_reason=StopReason.COMPLETE,
        input_tokens=1000,
        output_tokens=500,
        cache_read_tokens=10_000,
        cache_write_tokens=2_000,
    )
    expected = (
        1000 * 5
        + 500 * 25
        + 10_000 * 5 * 0.1                       # cache read
        + 2_000 * 5 * 1.25                       # cache write
    ) / 1_000_000
    assert abs(p.compute_cost(resp) - expected) < 1e-9
