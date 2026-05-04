"""Tests for llm_family: family detection + cross-family checker selection."""

from __future__ import annotations

from core.security.llm_family import (
    family_of,
    same_family,
    select_cross_family_checker,
)


# --- family_of ---

def test_anthropic_models_resolve_to_anthropic():
    assert family_of("claude-opus-4-7") == "anthropic"
    assert family_of("claude-sonnet-4-6") == "anthropic"
    assert family_of("anthropic/claude-haiku-4-5") == "anthropic"


def test_openai_models_resolve_to_openai():
    assert family_of("gpt-5") == "openai"
    assert family_of("gpt-4o") == "openai"
    assert family_of("o1-preview") == "openai"
    assert family_of("o3-mini") == "openai"
    assert family_of("openai/gpt-5") == "openai"


def test_google_models_resolve_to_google():
    assert family_of("gemini-2.5-pro") == "google"
    assert family_of("gemini/gemini-2.5-flash") == "google"
    assert family_of("google/gemini-2.5-pro") == "google"


def test_meta_models_resolve_to_meta():
    assert family_of("llama-3.1-70b") == "meta"
    assert family_of("meta-llama/Llama-3.1-8B") == "meta"


def test_ollama_resolves_to_ollama():
    assert family_of("ollama/llama3-8b") == "ollama"
    assert family_of("ollama/qwen2.5-7b") == "ollama"
    assert family_of("ollama/llama-3.1-8b") == "ollama"  # not meta


def test_mistral_family():
    assert family_of("mistral-7b") == "mistral"
    assert family_of("mistral-small-latest") == "mistral"
    assert family_of("mistral/mistral-large") == "mistral"


def test_unknown_models_resolve_to_unknown():
    assert family_of("custom-model-xyz") == "unknown"
    assert family_of("") == "unknown"


def test_family_detection_is_case_insensitive():
    assert family_of("CLAUDE-OPUS-4-7") == "anthropic"
    assert family_of("OpenAI/GPT-4o") == "openai"


# --- same_family ---

def test_same_family_for_two_anthropic_models():
    assert same_family("claude-opus-4-7", "anthropic/claude-haiku-4-5") is True


def test_different_families_are_not_same():
    assert same_family("claude-opus-4-7", "gpt-5") is False
    assert same_family("gemini-2.5-pro", "claude-opus-4-7") is False
    assert same_family("gpt-5", "ollama/llama3-8b") is False


def test_unknown_is_never_same_family():
    """Two unknown identifiers must NOT be treated as same family —
    we can't prove shared lineage and treating them as related would
    weaken the cross-family invariant downstream."""
    assert same_family("custom-model-a", "custom-model-b") is False
    assert same_family("custom-model-a", "claude-opus-4-7") is False


def test_same_family_handles_provider_prefix_variations():
    # Both anthropic, just different identifier shapes.
    assert same_family("claude-opus-4-7", "anthropic/claude-sonnet-4-6") is True
    # Both openai (bare and prefixed).
    assert same_family("gpt-5", "openai/gpt-4o") is True


# --- select_cross_family_checker ---

def test_select_returns_first_different_family_candidate():
    pick = select_cross_family_checker(
        "claude-opus-4-7",
        ["claude-haiku-4-5", "gpt-5", "gemini-2.5-pro"],
    )
    assert pick == "gpt-5"


def test_select_skips_same_family_candidates():
    pick = select_cross_family_checker(
        "claude-opus-4-7",
        ["claude-haiku-4-5", "anthropic/claude-sonnet-4-6", "gemini-2.5-pro"],
    )
    assert pick == "gemini-2.5-pro"


def test_select_skips_unknown_family_candidates():
    """Unknown-family candidates cannot be proven cross-family, so they
    must not be selected even if everything else is same-family."""
    pick = select_cross_family_checker(
        "claude-opus-4-7",
        ["custom-model-xyz", "gemini-2.5-pro"],
    )
    assert pick == "gemini-2.5-pro"


def test_select_returns_none_when_no_cross_family_candidate():
    assert select_cross_family_checker(
        "claude-opus-4-7",
        ["claude-haiku-4-5", "anthropic/claude-sonnet-4-6"],
    ) is None


def test_select_returns_none_for_empty_candidate_list():
    assert select_cross_family_checker("claude-opus-4-7", []) is None


def test_select_returns_none_when_only_unknown_candidates():
    assert select_cross_family_checker(
        "claude-opus-4-7",
        ["custom-model-a", "custom-model-b"],
    ) is None


def test_select_preserves_caller_ordering():
    """Caller may pass a preference order (cheap-first, fast-first); the
    first cross-family match should be returned, not e.g. an alphabetical
    pick."""
    pick = select_cross_family_checker(
        "claude-opus-4-7",
        ["openai/o3-mini", "gemini-2.5-flash", "gpt-4o"],
    )
    assert pick == "openai/o3-mini"


def test_select_works_when_producer_is_unknown_family():
    """If the producer is unknown-family, any known-family candidate is
    cross-family by our same_family() rule."""
    pick = select_cross_family_checker(
        "custom-model-xyz",
        ["claude-opus-4-7"],
    )
    assert pick == "claude-opus-4-7"


def test_select_skips_unknown_producer_against_unknown_candidate():
    """Unknown producer + unknown candidate is still not a usable pair —
    we cannot prove they're independent."""
    assert select_cross_family_checker(
        "custom-model-a",
        ["custom-model-b"],
    ) is None


# --- Integration with validate_response (composition pattern) ---

def test_composes_with_validate_response_via_llm_call_callback():
    """Pin the intended composition pattern: caller picks a cross-family
    checker, wraps a dispatch in a closure, passes it as llm_call to
    validate_response. validate_response itself stays unchanged."""
    from typing import Optional
    from pydantic import BaseModel

    from core.security.llm_response_schema import validate_response

    class Verdict(BaseModel):
        exploitable: bool
        reasoning: Optional[str] = None

    producer_model = "claude-opus-4-7"
    available_checkers = ["claude-haiku-4-5", "gpt-5", "gemini-2.5-pro"]

    # Simulated dispatcher that returns valid JSON only for the cross-family pick
    dispatched_with: list[str] = []

    def dispatch_fn(model_id: str) -> str:
        dispatched_with.append(model_id)
        if model_id == "gpt-5":
            return '{"exploitable": true, "reasoning": "cross-family checker resolved it"}'
        return "still invalid"

    checker = select_cross_family_checker(producer_model, available_checkers)
    assert checker == "gpt-5"
    result = validate_response(
        '{malformed',
        Verdict,
        llm_call=lambda: dispatch_fn(checker),
    )
    assert result is not None
    assert result.exploitable is True
    assert dispatched_with == ["gpt-5"]


def test_no_cross_family_checker_means_no_retry():
    """If candidates only contain same-family models, the caller passes
    llm_call=None and validate_response returns None on first failure.
    Pinning this so a future regression doesn't accidentally retry against
    a same-family checker (which would defeat the point)."""
    from typing import Optional
    from pydantic import BaseModel

    from core.security.llm_response_schema import validate_response

    class Verdict(BaseModel):
        exploitable: bool

    producer_model = "claude-opus-4-7"
    same_family_only = ["claude-haiku-4-5", "anthropic/claude-sonnet-4-6"]

    checker = select_cross_family_checker(producer_model, same_family_only)
    assert checker is None
    result = validate_response('{malformed', Verdict, llm_call=None)
    assert result is None
