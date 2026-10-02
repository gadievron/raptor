"""Tests for model role resolution and validation."""

import sys
from pathlib import Path

import pytest

# packages/llm_analysis/tests/test_model_roles.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.llm.config import (
    ModelConfig, ConfigError, resolve_model_roles, VALID_ROLES,
)


class TestRoleResolution:
    def test_no_roles_defaults(self):
        """No roles specified: first model = analysis+code, rest = fallback."""
        m1 = ModelConfig(provider="anthropic", model_name="claude-opus-4-6")
        m2 = ModelConfig(provider="openai", model_name="gpt-5.2")
        r = resolve_model_roles(m1, [m2])

        assert r["analysis_model"].model_name == "claude-opus-4-6"
        assert r["code_model"].model_name == "claude-opus-4-6"
        assert r["consensus_models"] == []
        assert len(r["fallback_models"]) == 1
        assert r["fallback_models"][0].model_name == "gpt-5.2"

    def test_explicit_analysis(self):
        m1 = ModelConfig(provider="anthropic", model_name="claude-opus-4-6", role="analysis")
        r = resolve_model_roles(m1)

        assert r["analysis_model"].model_name == "claude-opus-4-6"
        assert r["code_model"].model_name == "claude-opus-4-6"

    def test_analysis_plus_consensus(self):
        m1 = ModelConfig(provider="anthropic", model_name="claude-opus-4-6", role="analysis")
        m2 = ModelConfig(provider="gemini", model_name="gemini-2.5-pro", role="consensus")
        r = resolve_model_roles(m1, [m2])

        assert r["analysis_model"].model_name == "claude-opus-4-6"
        assert len(r["consensus_models"]) == 1
        assert r["consensus_models"][0].model_name == "gemini-2.5-pro"

    def test_specialist_code_model(self):
        m1 = ModelConfig(provider="anthropic", model_name="claude-opus-4-6", role="analysis")
        m2 = ModelConfig(provider="ollama", model_name="deepseek-coder-v3", role="code")
        r = resolve_model_roles(m1, [m2])

        assert r["analysis_model"].model_name == "claude-opus-4-6"
        assert r["code_model"].model_name == "deepseek-coder-v3"

    def test_full_config(self):
        m1 = ModelConfig(provider="anthropic", model_name="claude-opus-4-6", role="analysis")
        m2 = ModelConfig(provider="gemini", model_name="gemini-2.5-pro", role="consensus")
        m3 = ModelConfig(provider="ollama", model_name="deepseek-coder-v3", role="code")
        m4 = ModelConfig(provider="anthropic", model_name="claude-haiku-4-5", role="fallback")
        r = resolve_model_roles(m1, [m2, m3, m4])

        assert r["analysis_model"].model_name == "claude-opus-4-6"
        assert r["code_model"].model_name == "deepseek-coder-v3"
        assert len(r["consensus_models"]) == 1
        assert len(r["fallback_models"]) == 1

    def test_no_models(self):
        r = resolve_model_roles(None, None)
        assert r["analysis_model"] is None
        assert r["code_model"] is None
        assert r["consensus_models"] == []


class TestRoleValidation:
    def test_consensus_without_analysis_raises(self):
        m = ModelConfig(provider="gemini", model_name="gemini-2.5-pro", role="consensus")
        with pytest.raises(ConfigError, match="without an analysis model"):
            resolve_model_roles(None, [m])

    def test_code_without_analysis_raises(self):
        m = ModelConfig(provider="ollama", model_name="deepseek", role="code")
        with pytest.raises(ConfigError, match="without an analysis model"):
            resolve_model_roles(None, [m])

    def test_multiple_analysis_allowed(self):
        m1 = ModelConfig(provider="anthropic", model_name="opus", role="analysis")
        m2 = ModelConfig(provider="openai", model_name="gpt-5", role="analysis")
        result = resolve_model_roles(m1, [m2])
        assert len(result["analysis_models"]) == 2
        assert result["analysis_model"] == m1

    def test_fallback_only_raises(self):
        m = ModelConfig(provider="anthropic", model_name="opus", role="fallback")
        with pytest.raises(ConfigError, match="All models are configured as fallback"):
            resolve_model_roles(None, [m])

    def test_roleless_primary_with_fallback_entry_allowed(self):
        """A role-less entry is an implicit analysis model — one
        role:fallback sibling must not trip the all-fallback refusal."""
        primary = ModelConfig(provider="anthropic", model_name="opus")
        fb = ModelConfig(provider="openai", model_name="gpt-5.2", role="fallback")
        r = resolve_model_roles(primary, [fb])
        assert r["analysis_model"] is primary
        assert fb in r["fallback_models"]

    def test_all_explicit_fallback_still_raises(self):
        # Two-direction guard: with NO role-less entry present, an
        # all-fallback configuration keeps refusing.
        m1 = ModelConfig(provider="anthropic", model_name="opus", role="fallback")
        m2 = ModelConfig(provider="openai", model_name="gpt-5.2", role="fallback")
        with pytest.raises(ConfigError, match="All models are configured as fallback"):
            resolve_model_roles(m1, [m2])

    def test_roleless_primary_with_judge_allowed(self):
        """A role-less primary is an implicit analysis model, so pairing it
        with a judge must not trip 'Judge models configured without an
        analysis model'. This is the common local lineup: a role-less
        primary plus a bigger model held back as judge."""
        primary = ModelConfig(provider="ollama", model_name="local-primary")
        judge = ModelConfig(provider="ollama", model_name="local-big", role="judge")
        r = resolve_model_roles(primary, [judge])
        assert r["analysis_model"] is primary
        assert judge in r["judge_models"]

    def test_roleless_primary_with_consensus_allowed(self):
        primary = ModelConfig(provider="ollama", model_name="local-primary")
        cons = ModelConfig(provider="ollama", model_name="local-peer", role="consensus")
        r = resolve_model_roles(primary, [cons])
        assert r["analysis_model"] is primary
        assert cons in r["consensus_models"]

    def test_roleless_primary_with_aggregate_allowed(self):
        primary = ModelConfig(provider="ollama", model_name="local-primary")
        agg = ModelConfig(provider="ollama", model_name="local-agg", role="aggregate")
        r = resolve_model_roles(primary, [agg])
        assert r["analysis_model"] is primary
        assert agg in r["aggregate_models"]

    def test_roleless_primary_with_code_allowed(self):
        primary = ModelConfig(provider="ollama", model_name="local-primary")
        code = ModelConfig(provider="ollama", model_name="local-coder", role="code")
        r = resolve_model_roles(primary, [code])
        assert r["analysis_model"] is primary
        assert r["code_model"] is code

    def test_judge_without_any_analysis_still_raises(self):
        # Two-direction guard: with NO role-less entry and NO explicit
        # analysis role, a judge-only configuration keeps refusing.
        judge = ModelConfig(provider="ollama", model_name="local-big", role="judge")
        with pytest.raises(ConfigError, match="Judge models configured without an analysis model"):
            resolve_model_roles(None, [judge])

    def test_multiple_code_raises(self):
        m1 = ModelConfig(provider="anthropic", model_name="opus", role="analysis")
        m2 = ModelConfig(provider="ollama", model_name="deepseek", role="code")
        m3 = ModelConfig(provider="openai", model_name="codex", role="code")
        with pytest.raises(ConfigError, match="Multiple models with role 'code'"):
            resolve_model_roles(m1, [m2, m3])

    def test_invalid_role_name_raises(self):
        m1 = ModelConfig(provider="anthropic", model_name="opus", role="analysis")
        m2 = ModelConfig(provider="openai", model_name="gpt", role="wizard")
        with pytest.raises(ConfigError, match="Invalid role"):
            resolve_model_roles(m1, [m2])

    def test_same_model_two_roles_raises(self):
        m1 = ModelConfig(provider="anthropic", model_name="opus", role="analysis")
        m2 = ModelConfig(provider="anthropic", model_name="opus", role="consensus")
        with pytest.raises(ConfigError, match="conflicting roles"):
            resolve_model_roles(m1, [m2])


class TestValidRoles:
    def test_valid_roles_set(self):
        assert "analysis" in VALID_ROLES
        assert "code" in VALID_ROLES
        assert "consensus" in VALID_ROLES
        assert "fallback" in VALID_ROLES
        assert "wizard" not in VALID_ROLES
