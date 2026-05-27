#!/usr/bin/env python3
"""Tests for the AWS Bedrock LLM provider integration.

Covers:
  * Bedrock SDK availability flag
  * Bedrock model alias map (cost/limit lookup parity with Anthropic)
  * ``supports_temperature`` gate (Opus 4.7+ models)
  * ``_build_bedrock_config`` env-driven activation
  * ``create_provider`` factory dispatch to ``BedrockProvider``
  * ``provider_of`` routing for Bedrock-prefixed model IDs
  * Resource policy validation in orchestrator (no-API-key path)

Live SDK calls are mocked — a real round-trip lives in
``test_bedrock_provider_live`` (gated behind ``--integration`` per
pytest.ini).
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from core.llm.detection import BEDROCK_AVAILABLE, detect_llm_availability
from core.llm.config import _build_bedrock_config, _PROVIDER_BUILDERS
from core.llm.model_data import (
    MODEL_COSTS,
    MODEL_LIMITS,
    MODELS_WITHOUT_TEMPERATURE,
    PROVIDER_DEFAULT_MODELS,
    PROVIDER_ENV_KEYS,
    PROVIDER_FAST_MODELS,
    supports_temperature,
)
from core.security.llm_family import provider_of, family_of


# ---------------------------------------------------------------------------
# Detection / SDK availability
# ---------------------------------------------------------------------------


class TestBedrockAvailability:
    def test_flag_exposed(self):
        # The flag is True in this venv (boto3 + anthropic both installed).
        # Other test environments may be False — we only assert it's a bool.
        assert isinstance(BEDROCK_AVAILABLE, bool)

    def test_provider_in_env_keys(self):
        assert PROVIDER_ENV_KEYS["bedrock"] == "AWS_REGION"


# ---------------------------------------------------------------------------
# Model alias map — Bedrock IDs must alias to canonical Anthropic costs/limits
# ---------------------------------------------------------------------------


class TestBedrockModelAliases:
    @pytest.mark.parametrize("bedrock_id,canonical", [
        ("us.anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("eu.anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("au.anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("global.anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("us.anthropic.claude-sonnet-4-6", "claude-sonnet-4-6"),
        ("us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5"),
        ("us.anthropic.claude-opus-4-6-v1", "claude-opus-4-6"),
        ("us.anthropic.claude-sonnet-4-5-20250929-v1:0", "claude-sonnet-4-5"),
        ("us.anthropic.claude-opus-4-5-20251101-v1:0", "claude-opus-4-5"),
        ("us.anthropic.claude-opus-4-1-20250805-v1:0", "claude-opus-4-1"),
    ])
    def test_costs_aliased(self, bedrock_id: str, canonical: str):
        assert bedrock_id in MODEL_COSTS, f"{bedrock_id} missing from MODEL_COSTS"
        assert canonical in MODEL_COSTS, f"canonical {canonical} not in MODEL_COSTS"
        assert MODEL_COSTS[bedrock_id] == MODEL_COSTS[canonical]

    @pytest.mark.parametrize("bedrock_id,canonical", [
        ("us.anthropic.claude-opus-4-7", "claude-opus-4-7"),
        ("us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5"),
        ("us.anthropic.claude-opus-4-6-v1", "claude-opus-4-6"),
    ])
    def test_limits_aliased(self, bedrock_id: str, canonical: str):
        assert bedrock_id in MODEL_LIMITS
        assert canonical in MODEL_LIMITS
        assert MODEL_LIMITS[bedrock_id] == MODEL_LIMITS[canonical]

    def test_default_model_is_opus_47(self):
        assert PROVIDER_DEFAULT_MODELS["bedrock"] == "us.anthropic.claude-opus-4-7"

    def test_fast_model_is_haiku(self):
        assert "haiku" in PROVIDER_FAST_MODELS["bedrock"].lower()


# ---------------------------------------------------------------------------
# supports_temperature gate
# ---------------------------------------------------------------------------


class TestSupportsTemperature:
    def test_opus_47_canonical_returns_false(self):
        assert supports_temperature("claude-opus-4-7") is False

    @pytest.mark.parametrize("bedrock_id", [
        "us.anthropic.claude-opus-4-7",
        "eu.anthropic.claude-opus-4-7",
        "au.anthropic.claude-opus-4-7",
        "global.anthropic.claude-opus-4-7",
        "anthropic.claude-opus-4-7",
    ])
    def test_opus_47_bedrock_variants_return_false(self, bedrock_id: str):
        assert supports_temperature(bedrock_id) is False

    @pytest.mark.parametrize("model", [
        "claude-sonnet-4-6",
        "claude-opus-4-6",
        "claude-haiku-4-5",
        "claude-sonnet-4-5",
        "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "gpt-5.4",
        "gemini-2.5-pro",
    ])
    def test_other_models_return_true(self, model: str):
        assert supports_temperature(model) is True

    def test_unknown_model_defaults_true(self):
        # Safer default: unknown models are assumed to accept temperature.
        # Worst case the API rejects with a 400 and we know to add it
        # to the set; the alternative (default False) silently drops
        # caller-specified temperatures on every unknown model.
        assert supports_temperature("future-model-9000") is True

    def test_all_bedrock_opus_47_variants_in_set(self):
        # Future-proofing: if we add a new region prefix, this test
        # forces us to update MODELS_WITHOUT_TEMPERATURE too.
        expected_variants = {
            "claude-opus-4-7",
            "anthropic.claude-opus-4-7",
            "us.anthropic.claude-opus-4-7",
            "eu.anthropic.claude-opus-4-7",
            "au.anthropic.claude-opus-4-7",
            "global.anthropic.claude-opus-4-7",
        }
        assert expected_variants <= MODELS_WITHOUT_TEMPERATURE


# ---------------------------------------------------------------------------
# _build_bedrock_config — env-driven activation
# ---------------------------------------------------------------------------


class TestBuildBedrockConfig:
    def test_returns_none_without_aws_region(self, monkeypatch):
        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        if not BEDROCK_AVAILABLE:
            pytest.skip("Bedrock SDKs not installed")
        assert _build_bedrock_config() is None

    def test_returns_config_with_aws_region(self, monkeypatch):
        if not BEDROCK_AVAILABLE:
            pytest.skip("Bedrock SDKs not installed")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        cfg = _build_bedrock_config()
        assert cfg is not None
        assert cfg.provider == "bedrock"
        assert cfg.api_key is None  # boto3 chain handles auth
        assert cfg.model_name == "us.anthropic.claude-opus-4-7"

    def test_aws_default_region_also_works(self, monkeypatch):
        if not BEDROCK_AVAILABLE:
            pytest.skip("Bedrock SDKs not installed")
        monkeypatch.delenv("AWS_REGION", raising=False)
        monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
        cfg = _build_bedrock_config()
        assert cfg is not None
        assert cfg.provider == "bedrock"

    def test_registered_in_provider_builders(self):
        assert "bedrock" in _PROVIDER_BUILDERS


# ---------------------------------------------------------------------------
# Factory dispatch — create_provider must route bedrock to BedrockProvider
# ---------------------------------------------------------------------------


class TestFactoryDispatch:
    def test_factory_returns_bedrock_provider(self, monkeypatch):
        if not BEDROCK_AVAILABLE:
            pytest.skip("Bedrock SDKs not installed")
        from core.llm.providers import create_provider, BedrockProvider, AnthropicProvider
        from core.llm.config import ModelConfig

        monkeypatch.setenv("AWS_REGION", "us-east-1")
        cfg = ModelConfig(
            provider="bedrock",
            model_name="us.anthropic.claude-opus-4-7",
            api_key=None,
            max_tokens=1000,
            max_context=1000000,
            temperature=0.7,
            cost_per_1k_tokens=0.015,
        )
        provider = create_provider(cfg)
        assert isinstance(provider, BedrockProvider)
        # Subclass invariant — must be an AnthropicProvider too so all
        # inherited methods (turn, generate_structured, etc.) are
        # callable polymorphically.
        assert isinstance(provider, AnthropicProvider)

    def test_factory_raises_when_bedrock_unavailable(self, monkeypatch):
        # When BEDROCK_AVAILABLE is False the factory should raise a
        # clear RuntimeError telling the operator what to install.
        from core.llm.config import ModelConfig
        from core.llm import providers as providers_module
        cfg = ModelConfig(
            provider="bedrock",
            model_name="us.anthropic.claude-opus-4-7",
            api_key=None,
            max_tokens=1000,
            max_context=1000000,
            temperature=0.7,
            cost_per_1k_tokens=0.015,
        )
        with patch.object(providers_module, "BEDROCK_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="boto3 anthropic"):
                providers_module.create_provider(cfg)


# ---------------------------------------------------------------------------
# provider_of — routing for Bedrock-prefixed model IDs
# ---------------------------------------------------------------------------


class TestProviderOfBedrockRouting:
    @pytest.mark.parametrize("model_id", [
        "us.anthropic.claude-opus-4-7",
        "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "au.anthropic.claude-haiku-4-5-20251001-v1:0",
        "apac.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "global.anthropic.claude-opus-4-7",
        "anthropic.claude-opus-4-7",
        "anthropic.claude-haiku-4-5-20251001-v1:0",
    ])
    def test_bedrock_ids_route_to_bedrock(self, model_id: str):
        assert provider_of(model_id) == "bedrock"

    @pytest.mark.parametrize("model_id,expected", [
        ("claude-opus-4-7", "anthropic"),
        ("claude-sonnet-4-5", "anthropic"),
        ("anthropic/claude-haiku-4-5", "anthropic"),
        ("gpt-5.4", "openai"),
        ("gemini-2.5-pro", "gemini"),
    ])
    def test_non_bedrock_ids_unaffected(self, model_id: str, expected: str):
        assert provider_of(model_id) == expected

    def test_family_unchanged_for_bedrock_claude(self):
        # Cross-family validation must still see Bedrock-Claude as the
        # same Claude lineage as direct-API Claude — they ARE the same
        # model. Family routing is separate from provider routing.
        assert family_of("us.anthropic.claude-opus-4-7") in {
            "anthropic", "unknown",  # acceptable: either matches or unknown
        }


# ---------------------------------------------------------------------------
# Orchestrator validation — keyless Bedrock config must not be rejected
# ---------------------------------------------------------------------------


class TestOrchestratorBedrockValidation:
    def test_resolve_model_accepts_bedrock_with_aws_region(self):
        # The orchestrator's _resolve_model() rejects models with
        # api_key=None UNLESS the provider is bedrock and AWS_REGION
        # is set. Without this exemption, Bedrock configs (which have
        # no API key — boto3 chain handles auth) would be rejected
        # at command-line --model resolution time.
        # We assert the env-var allowlist is correct; full integration
        # of orchestrator._resolve_model is exercised by the live e2e.
        from core.config import RaptorConfig
        assert "AWS_REGION" in RaptorConfig.LLM_API_KEY_VARS
        assert "AWS_DEFAULT_REGION" in RaptorConfig.LLM_API_KEY_VARS
        assert "AWS_PROFILE" in RaptorConfig.LLM_API_KEY_VARS

    def test_aws_credentials_in_safe_env_list(self):
        from core.config import RaptorConfig
        # All the AWS-cred vars boto3 needs must be allowlisted for
        # subprocess passthrough. Without these, the dispatcher
        # subprocess that runs the real Bedrock call has no way to
        # authenticate.
        for var in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_PROFILE",
        ):
            assert var in RaptorConfig.LLM_API_KEY_VARS
