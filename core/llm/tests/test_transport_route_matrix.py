"""Three-route resolution contract: claudecode / direct API / Bedrock.

The transport-routing env family now flows into every LLM child env
(``get_llm_env``), and the misroute guard polices cross-shaped ids.
These tests pin the contract that neither change may disturb:

1. claudecode fallback ORDER preserved — when no Bedrock entry is
   configured, resolution behaves exactly as before (claude CLI last
   resort, ``session-default`` sentinel), even with the full routing
   family ambient in the environment.
2. Direct Anthropic API resolution is unchanged — ``ANTHROPIC_MODEL``
   never steers it (its only functional reader is the CC-topology
   backfill, gated on ``CLAUDE_CODE_USE_BEDROCK``), and the
   ANTHROPIC_API_KEY family keeps selecting it.
3. Bedrock selection stays explicit — the carried family (AWS_PROFILE,
   AWS_REGION, ANTHROPIC_MODEL, even CLAUDE_CODE_USE_BEDROCK) is
   backfill/auth input, never a provider-selection signal by itself.
"""

from __future__ import annotations

import json

import pytest


@pytest.fixture(autouse=True)
def _hermetic_resolution(monkeypatch, tmp_path):
    """No inherited keys, no operator config, cold caches."""
    from core.config import RaptorConfig
    for var in RaptorConfig.LLM_API_KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    for var in RaptorConfig.LLM_ROUTING_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    for var in (
        "RAPTOR_BEDROCK_API", "RAPTOR_BEDROCK_MODEL",
        "RAPTOR_BEDROCK_PROFILE", "RAPTOR_BEDROCK_REGION",
        "RAPTOR_CC_MODEL", "RAPTOR_LLM_SOCKET", "RAPTOR_LLM_TOKEN_FD",
    ):
        monkeypatch.delenv(var, raising=False)
    empty = tmp_path / "models.json"
    empty.write_text(json.dumps({"models": []}))
    monkeypatch.setenv("RAPTOR_CONFIG", str(empty))
    monkeypatch.setenv(
        "RAPTOR_CC_PROBE_CACHE", str(tmp_path / "cc-probe.json"),
    )
    import core.llm.config as cfg
    import core.llm.detection as det
    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False
    monkeypatch.setattr(cfg, "_operator_primary_override", None)
    yield
    det._cached_llm_availability = None
    cfg._cached_thinking_model = None
    cfg._thinking_model_checked = False


def _claude_on_path(monkeypatch):
    import shutil
    real_which = shutil.which

    def fake_which(cmd, *a, **k):
        if cmd == "claude":
            return "/usr/local/bin/claude"
        return real_which(cmd, *a, **k)

    monkeypatch.setattr(shutil, "which", fake_which)


class TestClaudecodeRoutePreserved:

    def test_no_bedrock_entry_resolves_claudecode_session_default(
        self, monkeypatch,
    ):
        """Route 1 baseline: nothing configured, claude CLI on PATH →
        claudecode/session-default, exactly today's behaviour."""
        _claude_on_path(monkeypatch)
        from core.llm.config import (
            CLAUDECODE_SESSION_MODEL,
            _get_default_primary_model,
        )
        mc = _get_default_primary_model()
        assert mc is not None
        assert mc.provider == "claudecode"
        assert mc.model_name == CLAUDECODE_SESSION_MODEL

    def test_ambient_routing_family_does_not_change_the_fallback(
        self, monkeypatch,
    ):
        """The env family that get_llm_env now carries into children
        must not flip selection: with no Bedrock entry / bearer /
        RAPTOR_BEDROCK_* signal, resolution is byte-identical to the
        family-free environment."""
        _claude_on_path(monkeypatch)
        monkeypatch.setenv("AWS_PROFILE", "some-profile")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("ANTHROPIC_MODEL",
                           "us.anthropic.claude-opus-4-8-v1:0")
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
        from core.llm.config import (
            CLAUDECODE_SESSION_MODEL,
            _get_default_primary_model,
        )
        mc = _get_default_primary_model()
        assert mc is not None
        assert mc.provider == "claudecode"
        assert mc.model_name == CLAUDECODE_SESSION_MODEL

    def test_session_default_provider_constructs_with_family_present(
        self, monkeypatch,
    ):
        """The misroute guard must be invisible to the legitimate
        fallback: session-default on a Bedrock-backed CLI constructs
        (and would omit --model)."""
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        from core.llm.config import CLAUDECODE_SESSION_MODEL, ModelConfig
        from core.llm.providers import create_provider
        p = create_provider(ModelConfig(
            provider="claudecode",
            model_name=CLAUDECODE_SESSION_MODEL,
            api_key=None, max_tokens=1024, max_context=32000,
        ))
        assert p._cli_model() is None


class TestDirectApiRouteUnchanged:

    def test_anthropic_key_entry_still_selects_direct_api(
        self, monkeypatch, tmp_path,
    ):
        """Route 2: an ANTHROPIC_API_KEY-backed entry resolves to the
        direct API with the entry's own model — the ambient
        ANTHROPIC_MODEL (Bedrock-shaped, carried by the family) must
        not shadow or misroute it."""
        config = tmp_path / "models-direct.json"
        config.write_text(json.dumps({
            "models": [
                {
                    # A name the thinking-model scorer's pattern table
                    # matches exactly — selection must go to THIS
                    # entry, not the claudecode fallback.
                    "provider": "anthropic",
                    "model": "claude-opus-4-6",
                    "api_key": "sk-ant-test",
                    "role": "thinking",
                },
            ],
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))
        monkeypatch.setenv("ANTHROPIC_MODEL",
                           "us.anthropic.claude-opus-4-8-v1:0")
        monkeypatch.setenv("AWS_PROFILE", "some-profile")
        # Hermetic: the anthropic entry is alias-validated against the
        # live /v1/models inventory — seed it instead of the network.
        from core.llm.model_resolution import (
            _reset_cache_for_tests,
            _seed_cache_for_tests,
        )
        _seed_cache_for_tests(["claude-opus-4-6"])
        import core.llm.config as cfg
        cfg._cached_thinking_model = None
        cfg._thinking_model_checked = False
        try:
            mc = cfg._get_default_primary_model()
        finally:
            _reset_cache_for_tests()
        assert mc is not None
        assert mc.provider == "anthropic"
        assert mc.model_name == "claude-opus-4-6"

    def test_cc_topology_backfill_gated_on_bedrock_flag(self, monkeypatch):
        """ANTHROPIC_MODEL's only functional reader is the CC-topology
        backfill, and it returns nothing on a direct-API install —
        carrying the var into children cannot re-route them."""
        monkeypatch.setenv("ANTHROPIC_MODEL",
                           "us.anthropic.claude-opus-4-8-v1:0")
        monkeypatch.delenv("CLAUDE_CODE_USE_BEDROCK", raising=False)
        from core.llm.config import _cc_bedrock_topology
        assert _cc_bedrock_topology() == (None, None)
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
        surface, model = _cc_bedrock_topology()
        assert surface == "mantle"
        assert model == "us.anthropic.claude-opus-4-8-v1:0"


class TestBedrockSelectionStaysExplicit:

    def test_family_alone_never_selects_bedrock(self, monkeypatch):
        """Ambient AWS names + CC flags without an explicit statement
        (config entry / RAPTOR_BEDROCK_* / bearer) must not build a
        Bedrock config — the family is backfill input, not a
        selection signal."""
        monkeypatch.setenv("AWS_PROFILE", "some-profile")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        monkeypatch.setenv("ANTHROPIC_MODEL",
                           "us.anthropic.claude-opus-4-8-v1:0")
        from core.llm.config import _build_bedrock_config
        assert _build_bedrock_config() is None

    def test_raptor_bedrock_env_still_selects(self, monkeypatch):
        """The explicit RAPTOR_BEDROCK_* opt-in keeps working when the
        family rides along."""
        monkeypatch.setenv("RAPTOR_BEDROCK_PROFILE", "signing-profile")
        monkeypatch.setenv("RAPTOR_BEDROCK_MODEL",
                           "anthropic.claude-opus-4-8")
        mc = None
        from core.llm.config import _build_bedrock_config
        mc = _build_bedrock_config()
        assert mc is not None
        assert mc.provider == "bedrock"
        assert mc.aws_profile == "signing-profile"
