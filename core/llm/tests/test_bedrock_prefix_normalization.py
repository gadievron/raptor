"""Tests for surface-keyed Bedrock model-id normalization.

Mantle accepts only bare ``<provider>.<model>`` ids (regional routing
is in the hostname); runtime accepts prefixed inference-profile ids,
versioned ids and ARNs verbatim.  The normalizer applies lossless
fixes for Mantle and flags clear geography/region contradictions for
runtime — it never guesses.
"""

from __future__ import annotations

import pytest

from core.llm.bedrock_prefixes import (
    mantle_model_id,
    prefix_region_mismatch,
    regional_prefix_of,
)


# ---------------------------------------------------------------------------
# regional_prefix_of
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("model_id,expected", [
    ("us.anthropic.claude-opus-4-7", "us."),
    ("global.anthropic.claude-sonnet-5", "global."),
    ("eu.meta.llama3-70b-instruct-v1:0", "eu."),
    ("anthropic.claude-sonnet-5", None),
    ("claude-sonnet-5", None),
    ("arn:aws:bedrock:us-east-1:123456789012:inference-profile/x", None),
])
def test_regional_prefix_of(model_id, expected):
    assert regional_prefix_of(model_id) == expected


# ---------------------------------------------------------------------------
# mantle_model_id
# ---------------------------------------------------------------------------

def test_mantle_peels_regional_prefix():
    assert (mantle_model_id("us.anthropic.claude-opus-4-7")
            == "anthropic.claude-opus-4-7")
    assert (mantle_model_id("global.anthropic.claude-sonnet-5")
            == "anthropic.claude-sonnet-5")


def test_mantle_bare_id_passes_through():
    assert (mantle_model_id("anthropic.claude-sonnet-5")
            == "anthropic.claude-sonnet-5")


def test_mantle_prepends_provider_segment_for_catalog_name():
    """A bare catalog name whose family implies a provider segment
    gets it prepended — ``claude-x`` → ``anthropic.claude-x``."""
    assert mantle_model_id("claude-sonnet-5") == "anthropic.claude-sonnet-5"


def test_mantle_leaves_unrecognisable_ids_verbatim():
    arn = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/x"
    assert mantle_model_id(arn) == arn


# ---------------------------------------------------------------------------
# prefix_region_mismatch
# ---------------------------------------------------------------------------

def test_us_profile_from_eu_region_flagged():
    msg = prefix_region_mismatch("us.anthropic.claude-opus-4-7", "eu-west-1")
    assert msg is not None
    assert "us." in msg and "eu-west-1" in msg


def test_eu_profile_from_us_region_flagged():
    assert prefix_region_mismatch(
        "eu.anthropic.claude-sonnet-5", "us-east-1",
    ) is not None


def test_matching_geography_not_flagged():
    assert prefix_region_mismatch(
        "us.anthropic.claude-opus-4-7", "us-west-2",
    ) is None
    assert prefix_region_mismatch(
        "apac.anthropic.claude-sonnet-5", "ap-northeast-1",
    ) is None


def test_global_profile_never_flagged():
    assert prefix_region_mismatch(
        "global.anthropic.claude-sonnet-5", "eu-west-1",
    ) is None


def test_bare_id_and_empty_region_never_flagged():
    assert prefix_region_mismatch("anthropic.claude-sonnet-5",
                                  "us-east-1") is None
    assert prefix_region_mismatch("us.anthropic.claude-opus-4-7", "") is None


# ---------------------------------------------------------------------------
# Config-layer wiring
# ---------------------------------------------------------------------------

def test_entry_on_mantle_normalizes_prefixed_id(monkeypatch, tmp_path):
    """A models.json entry with a prefixed id on the mantle surface is
    normalized to the bare shape at parse time."""
    for var in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_MANTLE",
                "RAPTOR_BEDROCK_API", "RAPTOR_BEDROCK_REGION"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("RAPTOR_CC_PROBE_CACHE", str(tmp_path / "p.json"))
    from core.llm.config import _model_config_from_entry
    mc = _model_config_from_entry({
        "provider": "bedrock",
        "model": "us.anthropic.claude-opus-4-7",
        "bedrock_api": "mantle",
    })
    assert mc.model_name == "anthropic.claude-opus-4-7"


def test_entry_on_runtime_keeps_id_verbatim(monkeypatch, tmp_path):
    """Runtime ids pass verbatim — prefixed, versioned and ARN forms
    are all legal on InvokeModel."""
    for var in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_MANTLE",
                "RAPTOR_BEDROCK_API", "RAPTOR_BEDROCK_REGION"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("RAPTOR_CC_PROBE_CACHE", str(tmp_path / "p.json"))
    from core.llm.config import _model_config_from_entry
    mc = _model_config_from_entry({
        "provider": "bedrock",
        "model": "us.anthropic.claude-opus-4-7",
        "bedrock_api": "runtime",
        "region": "us-east-1",
    })
    assert mc.model_name == "us.anthropic.claude-opus-4-7"
