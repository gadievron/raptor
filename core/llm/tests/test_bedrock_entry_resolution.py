"""Tests for Bedrock models.json entry resolution: surface + model
backfill from a Bedrock-backed Claude Code install, the per-model
``aws_profile`` / ``region`` fields, and primary-selection eligibility
for role-less Bedrock entries.

Selection stays explicit throughout: the config entry (or a
RAPTOR_BEDROCK_* env var) is the opt-in; Claude Code's environment
only fills fields the operator left blank, and only when Claude Code
is itself on Bedrock.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch, tmp_path):
    """Neutral CC/AWS env per test: no inherited backend selection, a
    cold cc-probe cache, and cleared selection caches."""
    for var in (
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_MANTLE",
        "ANTHROPIC_MODEL",
        "AWS_BEARER_TOKEN_BEDROCK",
        "RAPTOR_BEDROCK_API",
        "RAPTOR_BEDROCK_MODEL",
        "RAPTOR_BEDROCK_PROFILE",
        "RAPTOR_BEDROCK_REGION",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
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


def _entry_config(entry):
    from core.llm.config import _model_config_from_entry
    return _model_config_from_entry(entry)


# ---------------------------------------------------------------------------
# Surface + model backfill
# ---------------------------------------------------------------------------

def test_minimal_entry_inherits_cc_mantle_topology(monkeypatch):
    """{"provider": "bedrock"} on a box where Claude Code runs against
    Bedrock Mantle inherits both the surface and the model id."""
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-sonnet-5")
    mc = _entry_config({"provider": "bedrock"})
    assert mc.provider == "bedrock"
    assert mc.bedrock_api == "mantle"
    assert mc.model_name == "anthropic.claude-sonnet-5"


def test_minimal_entry_cc_without_mantle_is_runtime(monkeypatch):
    """CC on plain Bedrock (no Mantle) → the inherited surface is the
    runtime/InvokeModel one."""
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "us.anthropic.claude-opus-4-7")
    mc = _entry_config({"provider": "bedrock"})
    assert mc.bedrock_api == "runtime"
    assert mc.model_name == "us.anthropic.claude-opus-4-7"


def test_probe_cache_beats_anthropic_model_env(monkeypatch):
    """When the cc-probe cache is warm, its backend-resolved model
    outranks the ANTHROPIC_MODEL env pin."""
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-opus-4-8")
    with patch("core.llm.cc_probe.cached_cc_session_model",
               return_value="anthropic.claude-sonnet-5"):
        mc = _entry_config({"provider": "bedrock"})
    assert mc.model_name == "anthropic.claude-sonnet-5"


def test_cross_surface_inherit_refused(monkeypatch):
    """Entry pins the runtime surface while CC uses Mantle: the CC
    model id must NOT be inherited (bare vs prefixed shapes are
    surface-specific) — the entry falls back to the static default."""
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-sonnet-5")
    mc = _entry_config({"provider": "bedrock", "bedrock_api": "runtime"})
    assert mc.bedrock_api == "runtime"
    assert mc.model_name != "anthropic.claude-sonnet-5"
    assert mc.model_name.startswith("anthropic.")


def test_minimal_entry_without_cc_bedrock_ignores_cc_model(monkeypatch):
    """CC on the direct Anthropic API: its model id is the wrong shape
    for Bedrock and must never be inherited."""
    monkeypatch.setenv("ANTHROPIC_MODEL", "claude-sonnet-5")
    mc = _entry_config({"provider": "bedrock"})
    assert mc.model_name != "claude-sonnet-5"
    assert mc.model_name.startswith("anthropic.")
    assert mc.bedrock_api == "mantle"


def test_explicit_entry_fields_win_over_cc(monkeypatch):
    """A fully-specified entry ignores CC's topology entirely."""
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-opus-4-8")
    mc = _entry_config({
        "provider": "bedrock",
        "model": "anthropic.claude-sonnet-5",
        "bedrock_api": "mantle",
    })
    assert mc.model_name == "anthropic.claude-sonnet-5"


# ---------------------------------------------------------------------------
# aws_profile / region fields
# ---------------------------------------------------------------------------

def test_entry_carries_profile_and_region():
    mc = _entry_config({
        "provider": "bedrock",
        "model": "anthropic.claude-sonnet-5",
        "aws_profile": "bedrock-access",
        "region": "eu-west-1",
    })
    assert mc.aws_profile == "bedrock-access"
    assert mc.aws_region == "eu-west-1"


def test_region_env_fallback(monkeypatch):
    """Entry without ``region`` picks up RAPTOR_BEDROCK_REGION."""
    monkeypatch.setenv("RAPTOR_BEDROCK_REGION", "eu-central-1")
    mc = _entry_config({
        "provider": "bedrock", "model": "anthropic.claude-sonnet-5",
    })
    assert mc.aws_region == "eu-central-1"


def test_entry_region_beats_env(monkeypatch):
    monkeypatch.setenv("RAPTOR_BEDROCK_REGION", "eu-central-1")
    mc = _entry_config({
        "provider": "bedrock",
        "model": "anthropic.claude-sonnet-5",
        "region": "us-west-2",
    })
    assert mc.aws_region == "us-west-2"


def test_non_bedrock_entries_have_no_aws_fields():
    mc = _entry_config({
        "provider": "openai", "model": "gpt-5.2", "api_key": "sk-x",
    })
    assert mc.aws_profile is None
    assert mc.aws_region is None


def test_bare_bedrock_id_resolves_catalog_limits():
    """``anthropic.<model>`` ids peel to the catalog row instead of
    landing on the generic fallback limits."""
    from core.llm.model_data import MODEL_LIMITS
    mc = _entry_config({
        "provider": "bedrock", "model": "anthropic.claude-sonnet-5",
    })
    expected = MODEL_LIMITS["claude-sonnet-5"]["max_output"]
    assert mc.max_tokens == expected


# ---------------------------------------------------------------------------
# Builder inheritance (env opt-in path)
# ---------------------------------------------------------------------------

def test_builder_inherits_cc_topology_on_profile_opt_in(monkeypatch):
    """RAPTOR_BEDROCK_PROFILE opt-in on a CC/Mantle box inherits the
    working surface and model."""
    monkeypatch.setenv("RAPTOR_BEDROCK_PROFILE", "bedrock-access")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    monkeypatch.setenv("ANTHROPIC_MODEL", "anthropic.claude-sonnet-5")
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None
    assert cfg.model_name == "anthropic.claude-sonnet-5"
    assert cfg.bedrock_api == "mantle"
    assert cfg.aws_profile == "bedrock-access"


def test_builder_surface_env_beats_cc(monkeypatch):
    monkeypatch.setenv("RAPTOR_BEDROCK_PROFILE", "bedrock-access")
    monkeypatch.setenv("RAPTOR_BEDROCK_API", "runtime")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("CLAUDE_CODE_USE_MANTLE", "1")
    from core.llm.config import _build_bedrock_config
    cfg = _build_bedrock_config()
    assert cfg is not None
    assert cfg.bedrock_api == "runtime"


# ---------------------------------------------------------------------------
# Primary selection
# ---------------------------------------------------------------------------

def _primary_with_entries(monkeypatch, entries):
    import core.llm.config as cfg
    monkeypatch.setattr(cfg, "_get_configured_models", lambda: entries)
    monkeypatch.setattr(cfg, "_get_best_thinking_model", lambda: None)
    from core.llm.config import _get_default_primary_model
    return _get_default_primary_model()


def test_roleless_bedrock_entry_becomes_primary(monkeypatch):
    """A role-less Bedrock entry is the operator's declared default
    for API work — it wins primary selection."""
    monkeypatch.setenv("AWS_PROFILE", "bedrock-access")
    primary = _primary_with_entries(monkeypatch, [
        {"provider": "bedrock", "model": "anthropic.claude-sonnet-5"},
    ])
    assert primary is not None
    assert primary.provider == "bedrock"
    assert primary.model_name == "anthropic.claude-sonnet-5"


def test_fallback_role_bedrock_entry_not_primary(monkeypatch, tmp_path):
    """role: fallback keeps primary selection on today's behavior —
    the Bedrock entry stays an auxiliary."""
    monkeypatch.setenv("AWS_PROFILE", "bedrock-access")
    primary = _primary_with_entries(monkeypatch, [
        {"provider": "bedrock", "model": "anthropic.claude-sonnet-5",
         "role": "fallback"},
    ])
    assert primary is None or primary.provider != "bedrock"


def test_bedrock_entry_without_credentials_not_primary(
    monkeypatch, tmp_path,
):
    """No credential signal anywhere → the entry can't authenticate
    and must not be selected."""
    monkeypatch.setenv("HOME", str(tmp_path))
    primary = _primary_with_entries(monkeypatch, [
        {"provider": "bedrock", "model": "anthropic.claude-sonnet-5"},
    ])
    assert primary is None or primary.provider != "bedrock"


# ---------------------------------------------------------------------------
# claudecode entries as explicit fallbacks
# ---------------------------------------------------------------------------

def test_claudecode_entry_auth_resolvable_via_binary(monkeypatch):
    """A keyless claudecode entry authenticates through the installed
    CLI — resolvable exactly when the binary exists."""
    from core.llm.config import ModelConfig, _entry_auth_resolvable
    mc = ModelConfig(provider="claudecode", model_name="session-default")
    with patch("shutil.which", return_value="/usr/bin/claude"):
        assert _entry_auth_resolvable(mc) is True
    with patch("shutil.which", return_value=None):
        assert _entry_auth_resolvable(mc) is False


def test_claudecode_entry_backfills_model():
    from core.llm.config import _model_config_from_entry
    mc = _model_config_from_entry({"provider": "claudecode",
                                   "role": "fallback"})
    assert mc.provider == "claudecode"
    assert mc.model_name
    assert mc.role == "fallback"


def test_claudecode_fallback_behind_bedrock_primary(monkeypatch):
    """The declared safety net: Bedrock primary + claudecode fallback
    both resolve from one models.json."""
    import core.llm.config as cfg
    monkeypatch.setenv("AWS_PROFILE", "bedrock-access")
    entries = [
        {"provider": "bedrock", "model": "anthropic.claude-sonnet-5"},
        {"provider": "claudecode", "role": "fallback"},
    ]
    monkeypatch.setattr(cfg, "_get_configured_models", lambda: entries)
    monkeypatch.setattr(cfg, "_get_best_thinking_model", lambda: None)
    primary = cfg._get_default_primary_model()
    assert primary is not None and primary.provider == "bedrock"
    with patch("shutil.which", return_value="/usr/bin/claude"), \
         patch.object(cfg, "detect_llm_availability") as av, \
         patch.object(cfg, "_get_available_ollama_models",
                      return_value=[]):
        av.return_value = type("A", (), {"external_llm": True})()
        fallbacks = cfg._get_default_fallback_models()
    providers = [m.provider for m in fallbacks]
    assert "claudecode" in providers
