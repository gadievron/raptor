"""Tests for llm_family: family detection + cross-family checker selection."""

from __future__ import annotations

from core.security.llm_family import (
    bare_model_id,
    family_of,
    same_family,
    select_cross_family_checker,
)


def test_bare_model_id_passes_through_bare_names():
    assert bare_model_id("claude-haiku-4-5") == "claude-haiku-4-5"
    assert bare_model_id("gpt-5") == "gpt-5"
    assert bare_model_id("gemini-2.5-pro") == "gemini-2.5-pro"


def test_bare_model_id_peels_provider_prefix():
    assert bare_model_id("anthropic/claude-haiku-4-5") == "claude-haiku-4-5"
    assert bare_model_id("openai/gpt-5") == "gpt-5"
    assert bare_model_id("gemini/gemini-2.5-pro") == "gemini-2.5-pro"


def test_bare_model_id_peels_aggregator_then_provider():
    # ``together/anthropic/claude-haiku-4-5`` — aggregator + provider
    # both peel; the lookup in models.json sees just ``claude-haiku-4-5``.
    assert bare_model_id("together/anthropic/claude-haiku-4-5") == "claude-haiku-4-5"
    assert bare_model_id("openrouter/openai/gpt-5") == "gpt-5"


def test_bare_model_id_leaves_unknown_prefixes_alone():
    # ``foo/`` is not a known provider — preserve as-is so an
    # operator typo doesn't silently collapse to an unintended match.
    assert bare_model_id("foo/bar-1") == "foo/bar-1"


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


# ---------------------------------------------------------------------------
# Bedrock regional + provider prefixes — family_of must strip both
# ---------------------------------------------------------------------------

def test_bedrock_us_anthropic_resolves_to_anthropic():
    """The bug the test in PR #696 hid via ``in {"anthropic", "unknown"}``:
    ``us.anthropic.claude-opus-4-7`` must resolve to ``anthropic``, not
    ``unknown``.  Without this, the cross-family validator silently
    treats a Bedrock-Claude producer and a direct-API-Claude checker
    as ``different families`` and pairs them — the exact failure the
    Attacker-Moves-Second paper warns against."""
    assert family_of("us.anthropic.claude-opus-4-7") == "anthropic"
    assert family_of("eu.anthropic.claude-sonnet-4-6") == "anthropic"
    assert family_of("au.anthropic.claude-haiku-4-5") == "anthropic"
    assert family_of("apac.anthropic.claude-opus-4-5") == "anthropic"
    assert family_of("global.anthropic.claude-opus-4-7") == "anthropic"


def test_bedrock_unprefixed_provider_still_resolves():
    """Even without a regional prefix, ``anthropic.claude-...`` is a
    Bedrock catalog name (non-callable for on-demand on Claude 4.x,
    but family detection still needs to map it correctly when it
    appears in non-call contexts like logs or model selection)."""
    assert family_of("anthropic.claude-opus-4-7") == "anthropic"


def test_bedrock_meta_mistral_cohere_resolve_correctly():
    """Other Bedrock provider segments map to their respective families."""
    assert family_of("us.meta.llama-3-2-90b-instruct") == "meta"
    assert family_of("eu.mistral.mistral-large-2407") == "mistral"
    assert family_of("us.cohere.command-r-plus") == "cohere"


def test_bedrock_amazon_titan_remains_unknown():
    """``amazon.`` (Titan / Nova) has no Family-literal mapping yet.
    Documented limitation; would require extending the Family literal."""
    assert family_of("us.amazon.titan-text-express") == "unknown"


def test_same_family_bedrock_claude_and_direct_claude():
    """The cross-family check that PR #696's review identified as
    broken — Bedrock-Claude and direct-API Claude must compare equal."""
    assert same_family(
        "us.anthropic.claude-opus-4-7", "claude-opus-4-7",
    ) is True
    assert same_family(
        "global.anthropic.claude-opus-4-7",
        "anthropic/claude-haiku-4-5",
    ) is True


def test_bedrock_cross_family_does_not_match():
    """A Bedrock-Claude producer + GPT checker IS cross-family."""
    assert same_family(
        "us.anthropic.claude-opus-4-7", "gpt-5",
    ) is False


def test_bare_model_id_peels_bedrock_regional_and_provider():
    """``--model us.anthropic.claude-opus-4-7`` must match the
    canonical ``claude-opus-4-7`` entry in models.json."""
    from core.security.llm_family import bare_model_id
    assert bare_model_id("us.anthropic.claude-opus-4-7") \
        == "claude-opus-4-7"
    assert bare_model_id("global.anthropic.claude-haiku-4-5") \
        == "claude-haiku-4-5"
    assert bare_model_id("eu.mistral.mistral-large-2407") \
        == "mistral-large-2407"


def test_bare_model_id_preserves_case():
    """Bedrock IDs are case-sensitive at AWS; ``bare_model_id``
    must NOT lowercase the result even though it lowercases for
    matching purposes."""
    from core.security.llm_family import bare_model_id
    # Hypothetical mixed-case input — bare result preserves case.
    result = bare_model_id("us.anthropic.Claude-Opus-4-7")
    assert result == "Claude-Opus-4-7"


# ---------------------------------------------------------------------------
# provider_of vs family_of decoupling — routing distinct from lineage
# (issue D/N from the adversarial review).  Co-authored with owen10380
# whose PR #696 first surfaced the routing-vs-family tension.
# ---------------------------------------------------------------------------

def test_provider_of_returns_bedrock_for_bedrock_shaped_ids():
    """The ROUTING provider for ``us.anthropic.claude-opus-4-7`` is
    ``bedrock`` (so config-file lookups + auth selection pick the
    Bedrock path).  Distinct from family_of which returns
    ``anthropic`` (so cross-family validation correctly refuses
    Bedrock-Claude ↔ direct-Claude pairing)."""
    from core.security.llm_family import provider_of
    assert provider_of("us.anthropic.claude-opus-4-7") == "bedrock"
    assert provider_of("eu.anthropic.claude-sonnet-4-6") == "bedrock"
    assert provider_of("global.anthropic.claude-haiku-4-5") == "bedrock"
    assert provider_of("apac.anthropic.claude-opus-4-7") == "bedrock"
    assert provider_of("au.anthropic.claude-opus-4-7") == "bedrock"


def test_provider_of_bedrock_works_for_other_provider_segments():
    """Bedrock routes Meta / Mistral / Cohere too — all route via
    Bedrock regardless of underlying family."""
    from core.security.llm_family import provider_of
    assert provider_of("us.meta.llama-3-70b") == "bedrock"
    assert provider_of("eu.mistral.mistral-large-2407") == "bedrock"
    assert provider_of("us.cohere.command-r-plus") == "bedrock"


def test_provider_of_falls_back_to_family_for_direct_api():
    """Direct-API model IDs use the family-based provider mapping
    (existing behaviour preserved)."""
    from core.security.llm_family import provider_of
    assert provider_of("claude-opus-4-7") == "anthropic"
    assert provider_of("anthropic/claude-opus-4-7") == "anthropic"
    assert provider_of("gpt-5") == "openai"


def test_family_and_provider_diverge_for_bedrock():
    """The key safety invariant: family stays ``anthropic`` for the
    cross-family validator while routing changes to ``bedrock``.
    Pre-decoupling, the two were coupled via ``provider_of`` calling
    ``family_of`` — owen10380's PR #696 patched ``provider_of`` to
    return ``bedrock`` but accidentally left ``family_of`` broken,
    silently weakening Attacker-Moves-Second.  This decoupling
    preserves both invariants."""
    from core.security.llm_family import family_of, provider_of, same_family
    model = "us.anthropic.claude-opus-4-7"
    assert family_of(model) == "anthropic"  # security
    assert provider_of(model) == "bedrock"  # routing
    # Cross-family checker still treats Bedrock-Claude + direct-Claude
    # as the SAME family — must NOT be paired as independent checkers.
    assert same_family(model, "claude-opus-4-7") is True


# ---------------------------------------------------------------------------
# Aggregator + Bedrock combination (Issue A from the adversarial review).
# Iterated peel handles chained shapes like
# ``together/us.anthropic.claude-opus-4-7``.  Co-authored with owen10380.
# ---------------------------------------------------------------------------

def test_aggregator_plus_bedrock_resolves_to_anthropic():
    """``together/us.anthropic.claude-...`` must resolve to anthropic
    family.  Pre-fix the family_of returned "unknown" because the
    aggregator peel ran after the Bedrock peel and the second pass
    of Bedrock peel never happened."""
    from core.security.llm_family import family_of
    assert family_of("together/us.anthropic.claude-opus-4-7") == "anthropic"
    assert family_of("groq/eu.anthropic.claude-sonnet-4-6") == "anthropic"
    assert family_of(
        "openrouter/global.anthropic.claude-haiku-4-5",
    ) == "anthropic"


def test_aggregator_plus_bedrock_routes_via_bedrock():
    """ROUTING goes via Bedrock even when an aggregator prefix is
    nominally present — the Bedrock-shape signal dominates."""
    from core.security.llm_family import provider_of
    assert provider_of(
        "together/us.anthropic.claude-opus-4-7",
    ) == "bedrock"


def test_aggregator_chain_plus_bedrock():
    """Chained aggregators + Bedrock — peel converges within bound."""
    from core.security.llm_family import family_of
    assert family_of(
        "openrouter/together/us.anthropic.claude-opus-4-7",
    ) == "anthropic"
