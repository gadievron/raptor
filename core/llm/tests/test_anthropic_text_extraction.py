"""AnthropicProvider.generate() response-shape contract.

Two families of shape hazard, both observed live on the Bedrock
dispatcher route with a reasoning-tier model:

* Block ordering — reasoning models prepend thinking blocks, so
  content[0] is not reliably text.  A response shaped
  [thinking, text("OK")] failed with "non-text content block:
  thinking" before the first-text-block fix.

* Empty / no-text responses — the API can end a turn with ZERO
  content blocks (hard refusal via stop_reason="refusal"; output
  budget exhausted mid-thinking via stop_reason="max_tokens").
  Dropping the stop_reason turned a diagnosable model boundary into
  an opaque "Anthropic returned empty content" — observed live as an
  entire call class (summary / spec_inference) failing while sibling
  classes succeeded on the same route, with no way to tell refusal
  from truncation from the run artifacts.

The matrix below pins: text-only, thinking+text, thinking-only,
tool_use-only, and empty content under every stop_reason variant —
plus the error-taxonomy ripple (refusals classify 'blocked', nothing
here is retryable).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest


def _response(*blocks, stop_reason="end_turn"):
    return SimpleNamespace(
        content=list(blocks),
        stop_reason=stop_reason,
        usage=SimpleNamespace(
            input_tokens=5, output_tokens=3,
            cache_creation_input_tokens=0, cache_read_input_tokens=0,
        ),
        model="claude-sonnet-5",
    )


def _generate_with(response):
    # Hermetic provider (core.testing): the SDK client is fully faked,
    # so construction must not require the optional anthropic SDK —
    # these are RAPTOR response-shape/taxonomy tests, and they run
    # unchanged on bare CI where the SDK is absent.
    from core.testing import make_anthropic_provider

    provider = make_anthropic_provider(SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: response),
    ))
    return provider.generate("ping")


# ── Text extraction ───────────────────────────────────────────────────


def test_thinking_block_before_text_is_skipped():
    thinking = SimpleNamespace(type="thinking", thinking="…")
    text = SimpleNamespace(type="text", text="OK")
    out = _generate_with(_response(thinking, text))
    assert out.content == "OK"


def test_plain_text_first_still_works():
    text = SimpleNamespace(type="text", text="hello")
    out = _generate_with(_response(text))
    assert out.content == "hello"


# ── No text block: error lists block types AND stop_reason ───────────


def test_no_text_block_raises_with_block_types():
    thinking = SimpleNamespace(type="thinking", thinking="…")
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(thinking))
    assert "thinking" in str(e.value)
    assert "stop_reason=end_turn" in str(e.value)


def test_thinking_only_end_turn_carries_no_truncation_marker():
    thinking = SimpleNamespace(type="thinking", thinking="…")
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(thinking))
    assert not getattr(e.value, "llm_truncation", False)


def test_thinking_only_max_tokens_carries_truncation_marker():
    """Thinking-only content ended by the output cap is the same
    condition as empty-content max_tokens — reasoning consumed the
    whole shared budget before the first text block — and must carry
    the same typed marker so consumers classify it as deterministic
    truncation (split / abort), never as retryable provider noise."""
    thinking = SimpleNamespace(type="thinking", thinking="…")
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(thinking, stop_reason="max_tokens"))
    assert getattr(e.value, "llm_truncation", False) is True
    assert "no text content block" in str(e.value)


def test_thinking_only_max_tokens_is_not_retryable():
    from core.llm.client import _is_retryable_error

    thinking = SimpleNamespace(type="thinking", thinking="…")
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(thinking, stop_reason="max_tokens"))
    assert not _is_retryable_error(e.value)


# ── Rejected responses still book their spend ─────────────────────────


def _provider_and_error(response):
    from core.testing import make_anthropic_provider

    provider = make_anthropic_provider(SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: response),
    ))
    with pytest.raises(RuntimeError) as e:
        provider.generate("ping")
    return provider, e.value


@pytest.mark.parametrize(
    "blocks,stop_reason",
    [
        ((), "max_tokens"),
        ((), "refusal"),
        ((SimpleNamespace(type="thinking", thinking="…"),), "max_tokens"),
        ((SimpleNamespace(type="thinking", thinking="…"),), "end_turn"),
    ],
)
def test_shape_guard_failures_book_provider_ledger(blocks, stop_reason):
    """A response the shape guards reject is still a completed, BILLED
    generation. The provider ledger is the budget-enforcement floor
    (max(total_cost, provider_spend_usd)) — leaving guard failures off
    it let a class-wide deterministic failure burn full-price calls
    invisible to the spend cap."""
    provider, err = _provider_and_error(
        _response(*blocks, stop_reason=stop_reason),
    )
    assert provider.total_cost > 0
    assert provider.total_input_tokens == 5
    assert provider.total_output_tokens == 3


@pytest.mark.parametrize(
    "blocks,stop_reason",
    [
        ((), "max_tokens"),
        ((SimpleNamespace(type="thinking", thinking="…"),), "max_tokens"),
    ],
)
def test_shape_guard_failures_stamp_billed_attribution(blocks, stop_reason):
    """The exception carries the paid usage so the client's telemetry
    row can attribute the burn to its call class (the ledger booking
    is aggregate-only and cannot)."""
    _, err = _provider_and_error(
        _response(*blocks, stop_reason=stop_reason),
    )
    assert getattr(err, "billed_cost_usd", 0.0) > 0
    assert getattr(err, "billed_tokens_in", 0) == 5
    assert getattr(err, "billed_tokens_out", 0) == 3


# ── Thinking-shares-output-budget capability gate ─────────────────────


@pytest.mark.parametrize("model", [
    "claude-fable-5",
    "anthropic.claude-fable-5",
    "us.anthropic.claude-opus-4-7",
    "claude-opus-4-7-20260301",
    "claude-opus-4-8",
    "claude-sonnet-5",
])
def test_thinking_shares_output_budget_reasoning_tier(model):
    from core.llm.providers import thinking_shares_output_budget

    assert thinking_shares_output_budget(model) is True


@pytest.mark.parametrize("model", [
    "claude-opus-4-6",
    "claude-sonnet-4-5",
    "claude-haiku-4-5",
    "gpt-5.6-sol",
    "",
])
def test_thinking_shares_output_budget_older_or_foreign(model):
    from core.llm.providers import thinking_shares_output_budget

    assert thinking_shares_output_budget(model) is False


def test_tool_use_only_raises_with_block_type_and_stop_reason():
    tool_use = SimpleNamespace(
        type="tool_use", id="t1", name="emit", input={},
    )
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(tool_use, stop_reason="tool_use"))
    assert "tool_use" in str(e.value)
    assert "stop_reason=tool_use" in str(e.value)


def test_mixed_tool_use_and_text_extracts_text():
    tool_use = SimpleNamespace(
        type="tool_use", id="t1", name="emit", input={},
    )
    text = SimpleNamespace(type="text", text="alongside")
    out = _generate_with(_response(tool_use, text, stop_reason="tool_use"))
    assert out.content == "alongside"


# ── Empty content: stop_reason variants ───────────────────────────────


def test_empty_content_refusal_surfaces_model_boundary():
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="refusal"))
    msg = str(e.value)
    assert "refused" in msg
    assert "stop_reason=refusal" in msg


def test_empty_content_refusal_classifies_blocked():
    """The refusal wording must ride the existing error taxonomy:
    classify_error_text → 'blocked', telemetry disposition →
    'blocked' — that is what makes the degradation honest instead of
    the failure looking like transport noise."""
    from core.llm.client import _failure_disposition
    from core.llm.structured_call import classify_error_text

    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="refusal"))
    assert classify_error_text(str(e.value)) == "blocked"
    assert _failure_disposition(e.value) == "blocked"


def test_empty_content_max_tokens_names_budget_exhaustion():
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="max_tokens"))
    assert "stop_reason=max_tokens" in str(e.value)


def test_empty_content_max_tokens_carries_truncation_marker():
    """This guard's message contains NEITHER "truncated" NOR "output
    token limit", so phrase-matching consumers (study split-retry,
    audit _classify_error) can only classify it via the typed
    ``llm_truncation`` marker every truncation guard stamps."""
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="max_tokens"))
    assert getattr(e.value, "llm_truncation", False) is True


def test_empty_content_refusal_carries_no_truncation_marker():
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="refusal"))
    assert not getattr(e.value, "llm_truncation", False)


def test_empty_content_end_turn_carries_stop_reason():
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason="end_turn"))
    assert "stop_reason=end_turn" in str(e.value)


def test_empty_content_none_stop_reason_reads_unknown():
    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason=None))
    assert "stop_reason=unknown" in str(e.value)


@pytest.mark.parametrize(
    "stop_reason", ["refusal", "max_tokens", "end_turn", None],
)
def test_empty_content_errors_are_not_retryable(stop_reason):
    """An identical retry cannot fix a refusal or an exhausted output
    budget — every empty-content variant must stay non-retryable so
    the client fails through to the call class's own degradation
    (mechanical fallback / skip) instead of re-buying the failure."""
    from core.llm.client import _is_retryable_error

    with pytest.raises(RuntimeError) as e:
        _generate_with(_response(stop_reason=stop_reason))
    assert not _is_retryable_error(e.value)
