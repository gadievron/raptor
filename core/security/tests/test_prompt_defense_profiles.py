"""Tests for the profile registry: lookup behaviour and design invariants."""

from __future__ import annotations

import pytest

from core.security.prompt_defense_profiles import (
    _BY_PREFIX,
    ANTHROPIC_CLAUDE,
    CONSERVATIVE,
    GOOGLE_GEMINI,
    META_LLAMA,
    OLLAMA_SMALL,
    OPENAI_GPT,
    get_profile_for,
)


def test_anthropic_models_get_anthropic_profile():
    assert get_profile_for("claude-opus-4-7") is ANTHROPIC_CLAUDE
    assert get_profile_for("claude-sonnet-4-6") is ANTHROPIC_CLAUDE
    assert get_profile_for("anthropic/claude-haiku-4-5") is ANTHROPIC_CLAUDE


def test_openai_models_get_openai_profile():
    assert get_profile_for("gpt-5") is OPENAI_GPT
    assert get_profile_for("openai/gpt-4o") is OPENAI_GPT
    assert get_profile_for("o1-preview") is OPENAI_GPT
    assert get_profile_for("o3-mini") is OPENAI_GPT


def test_gemini_models_get_gemini_profile():
    assert get_profile_for("gemini-2.5-pro") is GOOGLE_GEMINI
    assert get_profile_for("gemini/gemini-2.5-flash") is GOOGLE_GEMINI
    assert get_profile_for("google/gemini-2.5-pro") is GOOGLE_GEMINI


def test_llama_models_get_meta_profile():
    assert get_profile_for("llama-3.1-70b") is META_LLAMA
    assert get_profile_for("meta-llama/Llama-3.1-8B") is META_LLAMA


def test_ollama_models_get_ollama_profile():
    assert get_profile_for("ollama/llama3-8b") is OLLAMA_SMALL
    assert get_profile_for("ollama/qwen2.5-7b") is OLLAMA_SMALL


def test_unknown_model_falls_back_to_conservative():
    assert get_profile_for("unknown-model-xyz") is CONSERVATIVE
    assert get_profile_for("") is CONSERVATIVE


def test_lookup_is_case_insensitive():
    assert get_profile_for("CLAUDE-OPUS-4-7") is ANTHROPIC_CLAUDE
    assert get_profile_for("OpenAI/GPT-4o") is OPENAI_GPT


def test_conservative_profile_is_safe_default():
    assert CONSERVATIVE.envelope_xml is True
    assert CONSERVATIVE.datamarking is False
    assert CONSERVATIVE.base64_code is False
    assert CONSERVATIVE.role_placement == "user-only"


def test_ollama_profile_disables_decode_dependent_layers():
    assert OLLAMA_SMALL.base64_code is False
    assert OLLAMA_SMALL.datamarking is False


def test_anthropic_profile_uses_document_tag_style():
    assert ANTHROPIC_CLAUDE.tag_style == "nonce-only"


def test_openai_profile_uses_untrusted_text_tag_style():
    assert OPENAI_GPT.tag_style == "openai-untrusted-text"


def test_meta_profile_uses_nonce_only():
    assert META_LLAMA.tag_style == "nonce-only"


# --- Invariant tests (prevent regressions as the registry grows) ---

ALL_PROFILES = (
    CONSERVATIVE,
    ANTHROPIC_CLAUDE,
    OPENAI_GPT,
    GOOGLE_GEMINI,
    META_LLAMA,
    OLLAMA_SMALL,
)


def test_all_profile_names_are_distinct():
    names = [p.name for p in ALL_PROFILES]
    assert len(names) == len(set(names)), f"duplicate profile names: {names}"


def test_prefix_table_has_no_substring_collisions():
    prefixes = [p for p, _ in _BY_PREFIX]
    for i, a in enumerate(prefixes):
        for j, b in enumerate(prefixes):
            if i != j and a != b and b.startswith(a):
                pytest.fail(
                    f"prefix collision: {a!r} (idx {i}) is a strict prefix of {b!r} (idx {j}); "
                    f"{b!r} would never match because {a!r} matches first"
                )


def test_every_referenced_profile_in_prefix_table_is_in_all_profiles():
    referenced = {profile for _, profile in _BY_PREFIX}
    missing = referenced - set(ALL_PROFILES)
    assert not missing, f"profiles in _BY_PREFIX not in ALL_PROFILES: {missing}"


def test_every_profile_uses_a_known_tag_style():
    known_styles = {
        "nonce-only",
        "anthropic-document",
        "openai-untrusted-text",
        "secalign",
        "begin-end-marker",
    }
    for p in ALL_PROFILES:
        assert p.tag_style in known_styles, f"{p.name}: {p.tag_style!r}"
